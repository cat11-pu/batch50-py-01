import copy
import threading

import pytest

import fog_of_war_explorer as fog


def explorer(**kwargs):
    return fog.FogOfWarExplorer(**kwargs)


def circle(cx, cy, radius):
    return {
        (x, y)
        for x in range(cx - radius, cx + radius + 1)
        for y in range(cy - radius, cy + radius + 1)
        if (x - cx) ** 2 + (y - cy) ** 2 <= radius * radius
    }


def test_add_viewer_reveals_circle_with_default_radius():
    exp = explorer()
    out = exp.add_viewer("scout-1", "red", 5, 5)
    assert out["viewer_id"] == "scout-1"
    assert out["team"] == "red"
    assert (out["x"], out["y"], out["radius"]) == (5, 5, 2)
    assert out["visible"] == 13
    assert set(exp.visible_cells("red")) == circle(5, 5, 2)
    assert set(exp.explored_cells("red")) == circle(5, 5, 2)
    assert exp.stats() == {"viewers": 1, "teams": 1, "reveals": 1, "moves": 0,
                           "removed": 0, "explored_cells": 13,
                           "visible_cells": 13}


def test_add_viewer_rejects_bad_arguments_and_duplicates():
    exp = explorer(max_radius=6)
    bad_calls = [
        dict(viewer_id="", team="red", x=5, y=5),
        dict(viewer_id="   ", team="red", x=5, y=5),
        dict(viewer_id="v1", team="  ", x=5, y=5),
        dict(viewer_id="v1", team="red", x=5, y=5, radius=0),
        dict(viewer_id="v1", team="red", x=5, y=5, radius=7),
        dict(viewer_id="v1", team="red", x="5", y=5),
    ]
    for kwargs in bad_calls:
        with pytest.raises(fog.FogError) as exc:
            exp.add_viewer(**kwargs)
        assert exc.value.code == "FOG_INVALID_REQUEST"
    for x, y in ((-1, 3), (32, 3), (3, 40)):
        with pytest.raises(fog.FogError) as exc:
            exp.add_viewer("v1", "red", x, y)
        assert exc.value.code == "FOG_OUT_OF_BOUNDS"
    assert exp.stats()["viewers"] == 0
    exp.add_viewer("v1", "red", 5, 5, radius=1)
    with pytest.raises(fog.FogError) as exc:
        exp.add_viewer("v1", "blue", 8, 8, radius=1)
    assert exc.value.code == "FOG_VIEWER_EXISTS"
    assert exp.stats()["viewers"] == 1
    assert set(exp.visible_cells("red")) == circle(5, 5, 1)
    assert exp.visible_cells("blue") == []


def test_constructor_bounds_and_viewer_capacity():
    for kwargs in ({"width": 0}, {"height": -4}, {"max_radius": 0},
                   {"max_radius": 4, "default_radius": 9}, {"max_viewers": 0}):
        with pytest.raises(fog.FogError) as exc:
            explorer(**kwargs)
        assert exc.value.code == "FOG_INVALID_REQUEST"
    exp = explorer(max_viewers=2)
    exp.add_viewer("a", "red", 2, 2, radius=1)
    exp.add_viewer("b", "red", 20, 20, radius=1)
    with pytest.raises(fog.FogError) as exc:
        exp.add_viewer("c", "red", 10, 10, radius=1)
    assert exc.value.code == "FOG_CAPACITY_EXCEEDED"
    assert exp.stats()["viewers"] == 2
    with pytest.raises(fog.FogError) as exc:
        exp.remove_viewer("c")
    assert exc.value.code == "FOG_UNKNOWN_VIEWER"


def test_move_viewer_reports_gained_and_lost_cells():
    exp = explorer()
    exp.add_viewer("scout", "red", 5, 5, radius=2)
    out = exp.move_viewer("scout", 6, 5)
    old = circle(5, 5, 2)
    new = circle(6, 5, 2)
    assert out["viewer_id"] == "scout"
    assert (out["x"], out["y"]) == (6, 5)
    assert out["gained"] == len(new - old) == 5
    assert out["lost"] == len(old - new) == 5
    assert set(exp.visible_cells("red")) == new
    assert set(exp.explored_cells("red")) == old | new
    assert len(old | new) == 18
    assert exp.visibility_at("red", 3, 5) == "explored"
    assert exp.cell_info("red", 3, 5)["visible"] == 0
    assert exp.stats()["moves"] == 1
    still = exp.move_viewer("scout", 6, 5)
    assert (still["gained"], still["lost"]) == (0, 0)
    assert exp.stats()["moves"] == 2


def test_move_viewer_rejects_unknown_viewer_and_bad_target():
    exp = explorer()
    exp.add_viewer("scout", "red", 5, 5, radius=1)
    with pytest.raises(fog.FogError) as exc:
        exp.move_viewer("ghost", 5, 5)
    assert exc.value.code == "FOG_UNKNOWN_VIEWER"
    with pytest.raises(fog.FogError) as exc:
        exp.move_viewer("scout", 99, 5)
    assert exc.value.code == "FOG_OUT_OF_BOUNDS"
    with pytest.raises(fog.FogError) as exc:
        exp.move_viewer("scout", 5.5, 5)
    assert exc.value.code == "FOG_INVALID_REQUEST"
    assert (exp.visible_cells("red")) == sorted(circle(5, 5, 1))
    assert exp.stats()["moves"] == 0


def test_remove_viewer_releases_visibility_but_keeps_exploration():
    exp = explorer()
    exp.add_viewer("scout", "red", 5, 5, radius=2)
    out = exp.remove_viewer("scout")
    assert out == {"viewer_id": "scout", "released": 13}
    assert exp.visible_cells("red") == []
    assert set(exp.explored_cells("red")) == circle(5, 5, 2)
    assert exp.visibility_at("red", 5, 5) == "explored"
    assert exp.stats() == {"viewers": 0, "teams": 1, "reveals": 1, "moves": 0,
                           "removed": 1, "explored_cells": 13,
                           "visible_cells": 0}
    with pytest.raises(fog.FogError) as exc:
        exp.remove_viewer("scout")
    assert exc.value.code == "FOG_UNKNOWN_VIEWER"


def test_visibility_at_and_cell_info_report_three_states():
    exp = explorer()
    exp.add_viewer("scout", "red", 5, 5, radius=1)
    assert exp.visibility_at("red", 5, 5) == "visible"
    assert exp.visibility_at("red", 5, 3) == "explored"
    assert exp.visibility_at("red", 30, 30) == "hidden"
    assert exp.visibility_at("ghost", 5, 5) == "hidden"
    info = exp.cell_info("red", 5, 5)
    assert info == {"x": 5, "y": 5, "visible": 1, "seen_gen": 1,
                    "status": "visible"}
    blank = exp.cell_info("red", 30, 30)
    assert blank == {"x": 30, "y": 30, "visible": 0, "seen_gen": 0,
                     "status": "hidden"}
    with pytest.raises(fog.FogError) as exc:
        exp.visibility_at("red", -1, 5)
    assert exc.value.code == "FOG_OUT_OF_BOUNDS"
    with pytest.raises(fog.FogError) as exc:
        exp.cell_info("red", 5, 32)
    assert exc.value.code == "FOG_OUT_OF_BOUNDS"
    with pytest.raises(fog.FogError) as exc:
        exp.visibility_at("   ", 5, 5)
    assert exc.value.code == "FOG_INVALID_REQUEST"


def test_reveal_circle_counts_only_first_time_cells():
    exp = explorer()
    assert exp.reveal_circle("blue", 10, 10, 1) == 5
    assert exp.reveal_circle("blue", 10, 10, 1) == 0
    assert exp.visibility_at("blue", 10, 10) == "explored"
    assert exp.reveal_circle("blue", 11, 10, 1) == 3
    assert set(exp.explored_cells("blue")) == circle(10, 10, 1) | circle(11, 10, 1)
    assert exp.stats()["reveals"] == 3
    assert exp.stats()["viewers"] == 0
    with pytest.raises(fog.FogError) as exc:
        exp.reveal_circle("blue", 10, 10, 0)
    assert exc.value.code == "FOG_INVALID_REQUEST"
    with pytest.raises(fog.FogError) as exc:
        exp.reveal_circle("blue", 10, 33, 1)
    assert exc.value.code == "FOG_OUT_OF_BOUNDS"


def test_visible_and_explored_lists_are_sorted_and_team_scoped():
    exp = explorer()
    exp.add_viewer("r1", "red", 3, 3, radius=1)
    exp.add_viewer("b1", "blue", 9, 9, radius=1)
    assert exp.visible_cells("red") == [(2, 3), (3, 2), (3, 3), (3, 4), (4, 3)]
    assert exp.explored_cells("red") == exp.visible_cells("red")
    assert exp.visibility_at("blue", 3, 3) == "hidden"
    assert exp.visibility_at("red", 9, 9) == "hidden"
    assert exp.visible_cells("blue") == [(8, 9), (9, 8), (9, 9), (9, 10), (10, 9)]


def test_viewer_stats_tracks_personal_visibility_and_history():
    exp = explorer()
    exp.add_viewer("scout", "red", 5, 5, radius=2)
    exp.move_viewer("scout", 6, 5)
    assert exp.viewer_stats("scout") == {"viewer_id": "scout", "team": "red",
                                         "radius": 2, "visible": 13,
                                         "seen": 18}
    with pytest.raises(fog.FogError) as exc:
        exp.viewer_stats("nobody")
    assert exc.value.code == "FOG_UNKNOWN_VIEWER"


def test_team_snapshot_lists_members_and_counts():
    exp = explorer()
    exp.add_viewer("beta", "red", 20, 20, radius=2)
    exp.add_viewer("alpha", "red", 4, 4, radius=2)
    snap = exp.team_snapshot("red")
    assert snap["team"] == "red"
    assert snap["members"] == ["alpha", "beta"]
    assert snap["counts"] == {"members": 2, "visible": 26, "explored": 26}
    assert snap["visible"] == sorted(circle(4, 4, 2) | circle(20, 20, 2))
    assert snap["explored"] == snap["visible"]
    assert exp.team_snapshot("blue") == {"team": "blue", "members": [],
                                         "visible": [], "explored": [],
                                         "counts": {"members": 0, "visible": 0,
                                                    "explored": 0}}


def test_snapshot_is_detached_from_live_state():
    exp = explorer()
    exp.add_viewer("scout", "red", 5, 5, radius=2)
    exp.move_viewer("scout", 6, 5)
    state = exp.snapshot()
    assert set(state) == {"version", "gen", "grids", "viewers", "stats"}
    assert state["version"] == 1
    state["viewers"].clear()
    state["grids"].clear()
    state["stats"]["moves"] = 99
    assert exp.stats()["moves"] == 1
    assert exp.stats()["viewers"] == 1
    assert set(exp.visible_cells("red")) == circle(6, 5, 2)


def test_restore_roundtrips_grid_history_and_counters():
    source = explorer()
    source.add_viewer("scout", "red", 5, 5, radius=2)
    source.move_viewer("scout", 6, 5)
    source.reveal_circle("blue", 12, 12, 1)
    state = source.snapshot()

    clone = explorer()
    clone.restore(data := copy.deepcopy(state))
    assert data == state
    assert clone.stats() == source.stats()
    assert clone.viewer_stats("scout") == source.viewer_stats("scout")
    assert set(clone.explored_cells("red")) == circle(5, 5, 2) | circle(6, 5, 2)
    moved = clone.move_viewer("scout", 7, 5)
    assert moved["gained"] == len(circle(7, 5, 2) - circle(6, 5, 2))
    assert exp_union(clone) == circle(5, 5, 2) | circle(6, 5, 2) | circle(7, 5, 2)
    assert clone.visibility_at("blue", 12, 12) == "explored"


def exp_union(exp):
    return set(exp.explored_cells("red")) | set(exp.explored_cells("blue"))


def test_restore_rejects_malformed_state_without_touching_live_data():
    exp = explorer()
    exp.add_viewer("scout", "red", 5, 5, radius=1)
    good = exp.snapshot()
    bad_states = [
        None,
        {},
        {key: value for key, value in good.items() if key != "grids"},
        {**good, "version": 2},
        {**good, "grids": []},
        {**good, "viewers": []},
        {**good, "stats": {"viewers": 1}},
        {**good, "gen": "1"},
    ]
    for bad in bad_states:
        with pytest.raises(fog.FogError) as exc:
            exp.restore(bad)
        assert exc.value.code == "FOG_SNAPSHOT_INVALID"
    assert exp.stats()["viewers"] == 1
    assert set(exp.visible_cells("red")) == circle(5, 5, 1)


def test_concurrent_moves_keep_every_viewer_and_counter():
    exp = explorer(width=64, height=64, max_viewers=16)
    targets = {}
    for index in range(8):
        team = f"team-{index}"
        exp.add_viewer(f"v{index}", team, 5 + index, 5, radius=1)
        targets[f"v{index}"] = (40 + index, 40)

    errors = []
    barrier = threading.Barrier(len(targets))

    def worker(viewer_id, x, y):
        try:
            barrier.wait(timeout=5)
            for _ in range(5):
                exp.move_viewer(viewer_id, x, y)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(viewer, *pos))
               for viewer, pos in targets.items()]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert exp.stats()["moves"] == 40
    assert exp.stats()["viewers"] == 8
    for viewer_id, (x, y) in targets.items():
        stats = exp.viewer_stats(viewer_id)
        assert stats["visible"] == 5
        assert stats["seen"] == 10
        assert (x, y) in exp.visible_cells(stats["team"])
