import pytest

import attack_path_pruner as ap


def pruner(**kwargs):
    return ap.AttackPathPruner(**kwargs)


def triple(engine):
    engine.add_edge("entry-a", "t1", cost=10, technique="T1078")
    engine.add_edge("entry-b", "t1", cost=4, technique="T1190")
    engine.add_edge("entry-c", "t1", cost=7, technique="T1210")
    return engine


def test_add_edge_builds_nodes_and_edge_list():
    engine = pruner()
    engine.add_edge("asset-a", "asset-b", cost=3, technique="T1078")
    engine.add_edge("asset-b", "asset-c", cost=4)
    assert engine.nodes() == ["asset-a", "asset-b", "asset-c"]
    assert engine.edges() == [
        {"src": "asset-a", "dst": "asset-b", "cost": 3, "technique": "T1078"},
        {"src": "asset-b", "dst": "asset-c", "cost": 4, "technique": ""},
    ]
    stats = engine.stats()
    assert stats["edges"] == 2
    assert stats["nodes"] == 3
    assert stats["edge_additions"] == 2


def test_add_edge_rejects_bad_nodes_cost_and_self_loop():
    engine = pruner()
    for src, dst in (("", "b"), ("a", "  ")):
        with pytest.raises(ap.PrunerError) as exc:
            engine.add_edge(src, dst, cost=1)
        assert exc.value.code == "PRUNER_BAD_NODE"
    for cost in (0, -3, "5"):
        with pytest.raises(ap.PrunerError) as exc:
            engine.add_edge("a", "b", cost=cost)
        assert exc.value.code == "PRUNER_BAD_COST"
    with pytest.raises(ap.PrunerError) as exc:
        engine.add_edge("a", "a", cost=1)
    assert exc.value.code == "PRUNER_SELF_LOOP"
    assert engine.nodes() == []
    assert engine.edges() == []


def test_add_edge_rejects_duplicate_edge():
    engine = pruner()
    engine.add_edge("a", "b", cost=2, technique="T1078")
    with pytest.raises(ap.PrunerError) as exc:
        engine.add_edge("a", "b", cost=9, technique="T1190")
    assert exc.value.code == "PRUNER_DUPLICATE_EDGE"
    assert engine.edges() == [
        {"src": "a", "dst": "b", "cost": 2, "technique": "T1078"},
    ]
    assert engine.stats()["edge_additions"] == 1


def test_edge_limit_is_enforced():
    engine = pruner(max_edges=2)
    engine.add_edge("a", "b", cost=1)
    engine.add_edge("b", "c", cost=1)
    with pytest.raises(ap.PrunerError) as exc:
        engine.add_edge("c", "d", cost=1)
    assert exc.value.code == "PRUNER_EDGE_LIMIT"
    assert len(engine.edges()) == 2
    assert engine.nodes() == ["a", "b", "c"]
    assert engine.stats()["edge_additions"] == 2


def test_shortest_to_returns_cheapest_path_with_techniques():
    engine = pruner()
    engine.add_edge("entry-a", "hop", cost=2, technique="T1078")
    engine.add_edge("hop", "t1", cost=5, technique="T1210")
    paths = engine.shortest_to("t1")
    assert len(paths) == 1
    path = paths[0]
    assert isinstance(path, ap.Path)
    assert path.nodes == ("entry-a", "hop", "t1")
    assert path.cost == 7
    assert path.techniques == ("T1078", "T1210")


def test_shortest_to_returns_paths_ordered_by_cost():
    engine = triple(pruner())
    paths = engine.shortest_to("t1", k=3)
    assert [path.cost for path in paths] == [4, 7, 10]
    assert [path.nodes for path in paths] == [
        ("entry-b", "t1"),
        ("entry-c", "t1"),
        ("entry-a", "t1"),
    ]


def test_shortest_to_returns_fewer_paths_than_requested():
    engine = triple(pruner())
    assert len(engine.shortest_to("t1", k=5)) == 3
    lonely = pruner()
    lonely.add_edge("entry", "only", cost=1)
    assert len(lonely.shortest_to("only", k=5)) == 1


def test_cheapest_path_wins_even_with_more_hops():
    engine = pruner()
    engine.add_edge("entry", "far", cost=3)
    engine.add_edge("far", "target", cost=3)
    engine.add_edge("entry", "target", cost=50)
    paths = engine.shortest_to("target", k=2)
    assert [path.cost for path in paths] == [6, 50]
    assert paths[0].nodes == ("entry", "far", "target")
    assert paths[1].nodes == ("entry", "target")


def test_shortest_to_rejects_bad_limit():
    engine = triple(pruner())
    for limit in (0, -1, 11):
        with pytest.raises(ap.PrunerError) as exc:
            engine.shortest_to("t1", k=limit)
        assert exc.value.code == "PRUNER_BAD_LIMIT"


def test_shortest_to_unknown_target_raises():
    engine = triple(pruner())
    with pytest.raises(ap.PrunerError) as exc:
        engine.shortest_to("t-404")
    assert exc.value.code == "PRUNER_UNKNOWN_NODE"


def test_cache_hit_and_miss_counters():
    engine = pruner()
    engine.add_edge("entry", "t1", cost=5)
    assert engine.cache_info() == {
        "entries": 0, "hits": 0, "misses": 0, "invalidations": 0,
    }
    engine.shortest_to("t1")
    assert engine.cache_info()["misses"] == 1
    assert engine.cache_info()["entries"] == 1
    engine.shortest_to("t1")
    info = engine.cache_info()
    assert info["hits"] == 1
    assert info["misses"] == 1
    assert info["entries"] == 1
    assert engine.stats()["queries"] == 2


def test_invalidate_drops_only_affected_entries():
    engine = pruner()
    engine.add_edge("entry-a", "mid", cost=1)
    engine.add_edge("mid", "t1", cost=1)
    engine.add_edge("entry-b", "t2", cost=1)
    engine.shortest_to("t1")
    engine.shortest_to("t2")
    assert engine.cache_info()["entries"] == 2
    assert engine.invalidate(node="mid") == 1
    assert engine.cache_info()["entries"] == 1
    assert engine.invalidate(node="entry-b") == 1
    assert engine.cache_info()["entries"] == 0
    engine.shortest_to("t1")
    assert engine.invalidate() == 1
    assert engine.cache_info()["entries"] == 0
    assert engine.cache_info()["invalidations"] == 3


def test_remove_node_drops_incident_edges_and_invalidates_cache():
    engine = pruner()
    engine.add_edge("entry-a", "mid", cost=1)
    engine.add_edge("mid", "t1", cost=1)
    engine.add_edge("entry-b", "t2", cost=1)
    engine.shortest_to("t1")
    assert engine.cache_info()["entries"] == 1
    assert engine.remove_node("mid") == 2
    assert engine.cache_info()["entries"] == 0
    assert engine.shortest_to("t1") == []
    assert engine.nodes() == ["entry-a", "entry-b", "t1", "t2"]
    assert [edge["dst"] for edge in engine.edges()] == ["t2"]
    assert engine.stats()["node_removals"] == 1
    with pytest.raises(ap.PrunerError) as exc:
        engine.remove_node("mid")
    assert exc.value.code == "PRUNER_UNKNOWN_NODE"


def test_remove_edge_updates_graph_and_cache():
    engine = pruner()
    engine.add_edge("entry-a", "t1", cost=5, technique="T1078")
    engine.add_edge("entry-b", "t1", cost=9)
    assert [path.cost for path in engine.shortest_to("t1")] == [5, 9]
    assert engine.remove_edge("entry-a", "t1") == 1
    assert [path.cost for path in engine.shortest_to("t1")] == [9]
    assert engine.nodes() == ["entry-a", "entry-b", "t1"]
    with pytest.raises(ap.PrunerError) as exc:
        engine.remove_edge("entry-a", "t1")
    assert exc.value.code == "PRUNER_UNKNOWN_EDGE"
    assert engine.stats()["edge_removals"] == 1


def test_snapshot_roundtrip_and_malformed_restore():
    engine = triple(pruner())
    engine.shortest_to("t1")
    state = engine.snapshot()
    clone = pruner()
    clone.restore(state)
    assert clone.nodes() == engine.nodes()
    assert clone.edges() == engine.edges()
    assert clone.stats() == engine.stats()
    assert [path.cost for path in clone.shortest_to("t1", k=3)] == [4, 7, 10]
    assert clone.cache_info()["entries"] == 1
    missing = dict(state)
    missing.pop("edges")
    wrong_type = dict(state)
    wrong_type["nodes"] = "entry-a"
    for bad in (None, {}, {"version": 99}, missing, wrong_type):
        with pytest.raises(ap.PrunerError) as exc:
            engine.restore(bad)
        assert exc.value.code == "PRUNER_SNAPSHOT_INVALID"
    assert len(engine.edges()) == 3
