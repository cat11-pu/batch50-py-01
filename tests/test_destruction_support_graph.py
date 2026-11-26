import copy
import threading

import pytest

import destruction_support_graph as dsg


def graph(**kwargs):
    return dsg.DestructionSupportGraph(**kwargs)


def chain(ids, *, material="wood", durability=100):
    components = [
        {"component": cid, "x": index, "y": 0, "durability": durability,
         "material": material, "grounded": index == 0}
        for index, cid in enumerate(ids)
    ]
    edges = [(ids[index], ids[index + 1]) for index in range(len(ids) - 1)]
    return components, edges


def test_register_structure_records_components_and_edges():
    g = graph()
    out = g.register_structure("tower", *chain(["G", "A", "B", "C"]),
                               region="north")
    assert out == {"structure": "tower", "components": 4, "edges": 3,
                   "region": "north"}
    assert g.structures() == ["tower"]
    assert g.component_of("tower", "G") == {
        "component": "G", "x": 0, "y": 0, "durability": 100,
        "max_durability": 100, "material": "wood", "grounded": True,
        "destroyed": False}
    assert g.durability_of("tower", "B") == 100
    assert g.stats() == {"registered": 1, "damaged": 0, "collapsed": 0,
                         "destroyed": 0, "repaired": 0, "loot": 0,
                         "resets": 0}


def test_register_structure_rejects_invalid_graphs():
    g = graph()
    g.register_structure("tower", *chain(["G", "A"]))
    with pytest.raises(dsg.GraphError) as exc:
        g.register_structure("tower", *chain(["G2", "A2"]))
    assert exc.value.code == "GRAPH_STRUCTURE_EXISTS"
    with pytest.raises(dsg.GraphError) as exc:
        g.register_structure("empty", [], [])
    assert exc.value.code == "GRAPH_INVALID_REQUEST"
    with pytest.raises(dsg.GraphError) as exc:
        g.register_structure("", *chain(["G", "A"]))
    assert exc.value.code == "GRAPH_INVALID_REQUEST"
    duplicated = [{"component": "G", "grounded": True},
                  {"component": "G"}]
    with pytest.raises(dsg.GraphError) as exc:
        g.register_structure("dup", duplicated, [("G", "G")])
    assert exc.value.code == "GRAPH_INVALID_REQUEST"
    floating = [{"component": "A", "durability": 100},
                {"component": "B", "durability": 100}]
    with pytest.raises(dsg.GraphError) as exc:
        g.register_structure("floating", floating, [("A", "B")])
    assert exc.value.code == "GRAPH_INVALID_REQUEST"
    brittle = [{"component": "G", "grounded": True, "durability": 0},
               {"component": "A", "durability": 100}]
    with pytest.raises(dsg.GraphError) as exc:
        g.register_structure("brittle", brittle, [("G", "A")])
    assert exc.value.code == "GRAPH_INVALID_REQUEST"
    components, _ = chain(["G", "A"])
    with pytest.raises(dsg.GraphError) as exc:
        g.register_structure("dangling", components, [("G", "Z")])
    assert exc.value.code == "GRAPH_INVALID_REQUEST"
    assert g.structures() == ["tower"]


def test_component_capacity_is_enforced():
    g = graph(max_components=3)
    with pytest.raises(dsg.GraphError) as exc:
        g.register_structure("tower", *chain(["G", "A", "B", "C"]))
    assert exc.value.code == "GRAPH_CAPACITY_EXCEEDED"
    assert g.structures() == []
    assert g.stats()["registered"] == 0


def test_apply_damage_reduces_then_destroys_a_component():
    g = graph()
    g.register_structure("tower", *chain(["G", "A", "B"]))
    first = g.apply_damage("tower", "A", 60)
    assert first == {"structure": "tower", "component": "A", "durability": 40,
                     "destroyed": False}
    second = g.apply_damage("tower", "A", 60)
    assert second["durability"] == 0
    assert second["destroyed"] is True
    info = g.component_of("tower", "A")
    assert info["destroyed"] is True
    assert info["durability"] == 0
    with pytest.raises(dsg.GraphError) as exc:
        g.apply_damage("tower", "A", 10)
    assert exc.value.code == "GRAPH_COMPONENT_GONE"
    assert g.stats() == {"registered": 1, "damaged": 2, "collapsed": 0,
                         "destroyed": 1, "repaired": 0, "loot": 0,
                         "resets": 0}


def test_apply_damage_rejects_unknown_targets_and_bad_amounts():
    g = graph()
    g.register_structure("tower", *chain(["G", "A"]))
    with pytest.raises(dsg.GraphError) as exc:
        g.apply_damage("nope", "G", 10)
    assert exc.value.code == "GRAPH_STRUCTURE_UNKNOWN"
    with pytest.raises(dsg.GraphError) as exc:
        g.apply_damage("tower", "Z", 10)
    assert exc.value.code == "GRAPH_COMPONENT_UNKNOWN"
    for bad in (0, -5, 1.5, "10"):
        with pytest.raises(dsg.GraphError) as exc:
            g.apply_damage("tower", "G", bad)
        assert exc.value.code == "GRAPH_INVALID_REQUEST"
    assert g.durability_of("tower", "G") == 100
    assert g.stats()["damaged"] == 0


def test_evaluate_support_finds_components_cut_off_from_ground():
    g = graph()
    g.register_structure("tower", *chain(["G", "A", "B"]))
    assert g.evaluate_support("tower") == []
    g.apply_damage("tower", "A", 100)
    assert g.evaluate_support("tower") == ["B"]
    assert g.evaluate_support("tower") == ["B"]
    with pytest.raises(dsg.GraphError) as exc:
        g.evaluate_support("nope")
    assert exc.value.code == "GRAPH_STRUCTURE_UNKNOWN"


def test_collapse_region_takes_target_and_unstable_subtree():
    g = graph()
    g.register_structure("tower", *chain(["G", "A", "B"], material="wood"))
    out = g.collapse_region("tower", "A")
    assert out["structure"] == "tower"
    assert out["collapsed"] == ["A", "B"]
    assert out["pending"] == 0
    assert out["secondary_destroyed"] == []
    assert out["damaged"]["G"] == 85
    assert out["loot"] == [
        {"item": "wood-rubble", "material": "wood", "quantity": 1,
         "from": "A"},
        {"item": "wood-rubble", "material": "wood", "quantity": 1,
         "from": "B"},
    ]
    assert g.stats()["collapsed"] == 2
    assert g.stats()["loot"] == 2


def test_settle_loot_drains_the_pending_queue():
    g = graph()
    g.register_structure("tower", *chain(["G", "A", "B"]))
    g.collapse_region("tower", "A")
    pending = g.pending_loot("tower")
    assert [row["from"] for row in pending] == ["A", "B"]
    assert g.settle_loot("tower") == pending
    assert g.pending_loot("tower") == []
    assert g.settle_loot("tower") == []
    with pytest.raises(dsg.GraphError) as exc:
        g.settle_loot("nope")
    assert exc.value.code == "GRAPH_STRUCTURE_UNKNOWN"


def test_collapse_deals_secondary_damage_to_neighbours():
    g = graph(secondary_damage=15)
    components = [
        {"component": "G", "grounded": True, "durability": 100,
         "material": "stone"},
        {"component": "A", "durability": 100, "material": "wood"},
        {"component": "C", "durability": 100, "material": "stone"},
    ]
    edges = [("G", "A"), ("G", "C"), ("A", "C")]
    g.register_structure("hall", components, edges)
    out = g.collapse_region("hall", "A")
    assert out["collapsed"] == ["A"]
    assert out["damaged"]["C"] == 85
    assert out["secondary_destroyed"] == []
    assert g.durability_of("hall", "C") == 85
    assert g.evaluate_support("hall") == []


def test_repair_restores_a_living_component_only():
    g = graph()
    g.register_structure("tower", *chain(["G", "A", "B"]))
    g.apply_damage("tower", "A", 60)
    out = g.repair("tower", "A")
    assert out == {"structure": "tower", "component": "A", "durability": 100}
    assert g.durability_of("tower", "A") == 100
    g.apply_damage("tower", "B", 100)
    with pytest.raises(dsg.GraphError) as exc:
        g.repair("tower", "B")
    assert exc.value.code == "GRAPH_COMPONENT_GONE"
    with pytest.raises(dsg.GraphError) as exc:
        g.repair("tower", "Z")
    assert exc.value.code == "GRAPH_COMPONENT_UNKNOWN"
    assert g.stats()["repaired"] == 1


def test_reset_rebuilds_the_whole_structure():
    g = graph()
    g.register_structure("tower", *chain(["G", "A", "B"], material="wood"))
    g.collapse_region("tower", "A")
    assert g.pending_loot("tower") != []
    assert g.reset("tower") == 3
    assert g.durability_of("tower", "A") == 100
    assert g.component_of("tower", "A")["destroyed"] is False
    assert g.evaluate_support("tower") == []
    assert g.pending_loot("tower") == []
    assert g.stats()["resets"] == 1


def test_collapse_respects_max_collapse_and_reports_pending():
    g = graph(max_collapse=2)
    g.register_structure("bridge", *chain(["G", "A", "B", "C", "D", "E"]))
    out = g.collapse_region("bridge", "A")
    assert out["collapsed"] == ["A", "B"]
    assert out["pending"] == 3
    assert g.evaluate_support("bridge") == ["C", "D", "E"]


def test_snapshot_is_detached_from_the_live_structure():
    g = graph()
    g.register_structure("tower", *chain(["G", "A", "B"]))
    g.collapse_region("tower", "A")
    state = g.snapshot()
    assert set(state) == {"version", "structures", "stats"}
    assert state["version"] == 1
    state["structures"].clear()
    state["stats"]["collapsed"] = 99
    assert g.stats()["collapsed"] == 2
    assert g.component_of("tower", "A")["destroyed"] is True
    assert len(g.pending_loot("tower")) == 2


def test_restore_roundtrips_destroyed_state_and_loot():
    source = graph()
    source.register_structure("tower", *chain(["G", "A", "B"]))
    source.apply_damage("tower", "B", 100)
    source.collapse_region("tower", "A")
    loot = source.pending_loot("tower")
    state = source.snapshot()
    pristine = copy.deepcopy(state)

    clone = graph()
    clone.restore(pristine)
    assert clone.stats() == source.stats()
    assert clone.structures() == ["tower"]
    assert clone.component_of("tower", "B")["destroyed"] is True
    assert clone.evaluate_support("tower") == []
    assert clone.pending_loot("tower") == loot
    assert clone.settle_loot("tower") == loot
    assert clone.pending_loot("tower") == []

    bad_states = [
        None,
        {},
        {key: value for key, value in pristine.items() if key != "structures"},
        {**pristine, "version": 2},
        {**pristine, "structures": []},
        {**pristine, "stats": {"collapsed": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(dsg.GraphError) as exc:
            clone.restore(bad)
        assert exc.value.code == "GRAPH_SNAPSHOT_INVALID"
    assert clone.stats()["collapsed"] == 2


def test_concurrent_damage_merges_and_destroys_once():
    g = graph()
    g.register_structure("tower", *chain(["G", "A"]))
    errors = []
    barrier = threading.Barrier(10)

    def worker():
        try:
            barrier.wait(timeout=5)
            g.apply_damage("tower", "A", 10)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert g.durability_of("tower", "A") == 0
    assert g.component_of("tower", "A")["destroyed"] is True
    assert g.stats()["damaged"] == 10
    assert g.stats()["destroyed"] == 1
