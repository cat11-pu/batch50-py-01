import copy

import pytest

import scene_graph_dirty_sync as sg


def make(**kwargs):
    return sg.SceneGraphDirtySync(**kwargs)


def test_attach_builds_tree_and_rejects_duplicates_and_bad_input():
    obj = make()
    root = obj.attach("root")
    assert root["node_id"] == "root"
    assert root["parent"] is None
    assert root["local"] == (0.0, 0.0, 0.0)
    assert root["attached"] is True

    child = obj.attach("a", parent="root", local=(1, 2, 3))
    assert child["parent"] == "root"
    assert child["local"] == (1.0, 2.0, 3.0)

    with pytest.raises(sg.SceneGraphError) as exc:
        obj.attach("a", parent="root")
    assert exc.value.code == "SG_DUPLICATE"
    with pytest.raises(sg.SceneGraphError) as exc:
        obj.attach("orphan", parent="missing")
    assert exc.value.code == "SG_UNKNOWN"

    for kwargs in (dict(local=(1, 2)), dict(local=("a", 0, 0))):
        with pytest.raises(sg.SceneGraphError) as exc:
            obj.attach("bad", **kwargs)
        assert exc.value.code == "SG_INVALID_ARGUMENT"
    with pytest.raises(sg.SceneGraphError) as exc:
        obj.attach("")
    assert exc.value.code == "SG_INVALID_ARGUMENT"


def test_attach_respects_max_nodes_and_frees_slots_on_detach():
    obj = make(max_nodes=2)
    obj.attach("a")
    obj.attach("b")
    with pytest.raises(sg.SceneGraphError) as exc:
        obj.attach("c")
    assert exc.value.code == "SG_CAPACITY_EXCEEDED"
    assert obj.stats()["nodes"] == 2

    obj.detach("b")
    obj.attach("c")
    assert obj.stats()["nodes"] == 2


def test_set_local_marks_subtree_and_validates_input():
    obj = make()
    obj.attach("root")
    obj.attach("child", parent="root", local=(1, 0, 0))
    obj.update_world()
    obj.commit()

    out = obj.set_local("child", local=(0, 2, 0))
    assert out["node_id"] == "child"
    assert out["local"] == (0.0, 2.0, 0.0)
    assert out["dirty"] == 1
    assert obj.set_local("child", local=(0, 2, 0))["dirty"] == 0
    assert obj.set_local("root", local=(5, 0, 0))["dirty"] == 1

    assert obj.update_world() == {"recomputed": 2, "remaining": 0}
    obj.commit()
    assert obj.query_world("root") == (5.0, 0.0, 0.0)
    assert obj.query_world("child") == (5.0, 2.0, 0.0)

    with pytest.raises(sg.SceneGraphError) as exc:
        obj.set_local("missing", local=(1, 1, 1))
    assert exc.value.code == "SG_UNKNOWN"
    with pytest.raises(sg.SceneGraphError) as exc:
        obj.set_local("root", local=(1, 1))
    assert exc.value.code == "SG_INVALID_ARGUMENT"


def test_update_world_composes_translations_parent_first():
    obj = make()
    obj.attach("root", local=(1, 2, 3))
    obj.attach("a", parent="root", local=(10, 0, 0))
    obj.attach("b", parent="a", local=(0, 1, 0))

    assert obj.update_world() == {"recomputed": 3, "remaining": 0}
    obj.commit()
    assert obj.query_world("root") == (1.0, 2.0, 3.0)
    assert obj.query_world("a") == (11.0, 2.0, 3.0)
    assert obj.query_world("b") == (11.0, 3.0, 3.0)


def test_query_before_commit_and_unknown_node():
    obj = make()
    obj.attach("root", local=(4, 5, 6))
    with pytest.raises(sg.SceneGraphError) as exc:
        obj.query_world("root")
    assert exc.value.code == "SG_NO_COMMIT"

    obj.update_world()
    obj.commit()
    with pytest.raises(sg.SceneGraphError) as exc:
        obj.query_world("missing")
    assert exc.value.code == "SG_UNKNOWN"


def test_query_returns_committed_world_until_next_commit():
    obj = make()
    obj.attach("root", local=(1, 0, 0))
    obj.attach("child", parent="root", local=(1, 0, 0))
    obj.update_world()
    assert obj.commit()["generation"] == 1
    assert obj.query_world("child") == (2.0, 0.0, 0.0)

    obj.set_local("root", local=(10, 0, 0))
    obj.update_world()
    assert obj.query_world("root") == (1.0, 0.0, 0.0)
    assert obj.query_world("child") == (2.0, 0.0, 0.0)

    assert obj.commit()["generation"] == 2
    assert obj.query_world("root") == (10.0, 0.0, 0.0)
    assert obj.query_world("child") == (11.0, 0.0, 0.0)


def test_mark_dirty_propagates_and_counts_only_new_nodes():
    obj = make()
    obj.attach("root")
    obj.attach("a", parent="root")
    obj.attach("b", parent="root")
    obj.attach("c", parent="a")
    assert obj.update_world()["recomputed"] == 4

    assert obj.mark_dirty("a") == 2
    assert obj.mark_dirty("a") == 0
    assert obj.mark_dirty("root") == 2
    assert obj.update_world() == {"recomputed": 4, "remaining": 0}

    with pytest.raises(sg.SceneGraphError) as exc:
        obj.mark_dirty("missing")
    assert exc.value.code == "SG_UNKNOWN"


def test_update_world_returns_zero_when_clean():
    obj = make()
    obj.attach("root")
    assert obj.update_world() == {"recomputed": 1, "remaining": 0}
    assert obj.update_world() == {"recomputed": 0, "remaining": 0}


def test_commit_is_blocked_while_nodes_are_dirty():
    obj = make()
    obj.attach("root")
    with pytest.raises(sg.SceneGraphError) as exc:
        obj.commit()
    assert exc.value.code == "SG_DIRTY_PENDING"

    obj.update_world()
    assert obj.commit()["generation"] == 1
    obj.set_local("root", local=(2, 0, 0))
    with pytest.raises(sg.SceneGraphError) as exc:
        obj.commit()
    assert exc.value.code == "SG_DIRTY_PENDING"

    obj.update_world()
    assert obj.commit()["generation"] == 2


def test_commit_reports_node_count_and_bumps_generation():
    obj = make()
    obj.attach("root")
    obj.attach("a", parent="root")
    obj.update_world()
    assert obj.commit() == {"generation": 1, "nodes": 2}
    assert obj.commit() == {"generation": 2, "nodes": 2}


def test_detach_returns_postorder_subtree_and_rejects_unknown():
    obj = make()
    obj.attach("root")
    obj.attach("a", parent="root")
    obj.attach("b", parent="a")
    obj.attach("c", parent="root")
    obj.update_world()
    obj.commit()

    assert obj.detach("a") == ["b", "a"]
    with pytest.raises(sg.SceneGraphError) as exc:
        obj.detach("a")
    assert exc.value.code == "SG_UNKNOWN"
    assert obj.detach("root") == ["c", "root"]
    with pytest.raises(sg.SceneGraphError) as exc:
        obj.detach("missing")
    assert exc.value.code == "SG_UNKNOWN"


def test_rollback_restores_last_committed_world_and_generation():
    obj = make()
    with pytest.raises(sg.SceneGraphError) as exc:
        obj.rollback()
    assert exc.value.code == "SG_NO_ROLLBACK"

    obj.attach("root", local=(1, 0, 0))
    obj.update_world()
    obj.commit()
    obj.set_local("root", local=(4, 0, 0))
    obj.update_world()

    assert obj.rollback() == {"generation": 1, "restored": 1, "removed": 0}
    assert obj.query_world("root") == (1.0, 0.0, 0.0)
    with pytest.raises(sg.SceneGraphError) as exc:
        obj.rollback()
    assert exc.value.code == "SG_NO_ROLLBACK"


def test_snapshot_is_detached_and_restore_continues_from_pending_state():
    obj = make()
    obj.attach("root", local=(1, 0, 0))
    obj.attach("a", parent="root", local=(1, 0, 0))
    obj.update_world()
    obj.commit()
    obj.attach("b", parent="root", local=(0, 1, 0))
    obj.set_local("root", local=(2, 0, 0))
    obj.update_world()

    state = obj.snapshot()
    assert state["version"] == 1
    snapshot_copy = copy.deepcopy(state)
    state["nodes"].clear()
    state["stats"]["commits"] = 99
    assert obj.stats()["commits"] == 1
    assert obj.stats()["nodes"] == 3

    clone = make()
    clone.restore(snapshot_copy)
    assert clone.stats() == obj.stats()
    assert clone.query_world("a") == (2.0, 0.0, 0.0)
    assert clone.commit()["generation"] == 2
    assert clone.query_world("a") == (3.0, 0.0, 0.0)
    assert obj.query_world("a") == (2.0, 0.0, 0.0)


def test_restore_rejects_malformed_state_without_touching_live_data():
    obj = make()
    obj.attach("root", local=(1, 0, 0))
    obj.update_world()
    obj.commit()
    before = obj.stats()

    bad_states = [
        None,
        {},
        {"version": 2, "generation": 1, "nodes": [], "pending": {},
         "committed": {}, "dirty": [], "modified": [], "stats": {}},
        {"version": 1, "generation": -1, "nodes": [], "pending": {},
         "committed": {}, "dirty": [], "modified": [], "stats": {}},
        {"version": 1, "generation": 1, "nodes": "nope", "pending": {},
         "committed": {}, "dirty": [], "modified": [], "stats": {}},
        {"version": 1, "generation": 1, "nodes": [], "pending": {},
         "committed": {}, "dirty": [], "modified": [],
         "stats": {"commits": -1}},
    ]
    for bad in bad_states:
        with pytest.raises(sg.SceneGraphError) as exc:
            obj.restore(bad)
        assert exc.value.code == "SG_SNAPSHOT_INVALID"

    assert obj.stats() == before
    assert obj.query_world("root") == (1.0, 0.0, 0.0)


def test_stats_track_dirty_marks_commits_and_detach():
    obj = make()
    obj.attach("root")
    obj.attach("a", parent="root")
    obj.attach("b", parent="root")
    obj.update_world()
    obj.commit()
    obj.set_local("a", local=(1, 0, 0))
    obj.update_world()
    obj.mark_dirty("b")
    obj.mark_dirty("b")
    obj.detach("b")

    assert obj.stats() == {"nodes": 2, "attached": 3, "detached": 1,
                           "dirty_marks": 2, "recomputed": 4,
                           "commits": 1, "rollbacks": 0}
