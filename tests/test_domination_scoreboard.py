import copy
import threading

import pytest

import domination_scoreboard as ds


def board(**kwargs):
    params = dict(mercy_gap=1000, tick_points=10, round_seconds=60,
                  overtime_seconds=5, lock_ticks=3)
    params.update(kwargs)
    return ds.DominationScoreboard(**params)


def capture(score, point_id, team, amount=100):
    return score.capture_tick(point_id, team, amount)


def test_register_point_and_unknown_lookup():
    score = board()
    state = score.register_point("p1")
    assert state == {"point_id": "p1", "controller": None, "progress": 0, "locked": 0}
    assert score.point_state("p1") == state
    assert score.stats() == {"points": 1, "captures": 0, "flips": 0,
                             "ignored": 0, "ticks": 0, "mercies": 0,
                             "finalized": 0}
    for bad in ("", "   "):
        with pytest.raises(ds.DominationError) as exc:
            score.register_point(bad)
        assert exc.value.code == "DOMINATION_INVALID_REQUEST"
    with pytest.raises(ds.DominationError) as exc:
        score.register_point("p1")
    assert exc.value.code == "DOMINATION_INVALID_REQUEST"
    with pytest.raises(ds.DominationError) as exc:
        score.point_state("missing")
    assert exc.value.code == "DOMINATION_UNKNOWN_POINT"


def test_capture_accumulates_then_flips_and_locks():
    score = board(lock_ticks=3)
    score.register_point("p1")
    assert capture(score, "p1", "red", 40)["progress"] == 40
    assert capture(score, "p1", "red", 40)["progress"] == 80
    flipped = capture(score, "p1", "red", 40)
    assert flipped == {"point_id": "p1", "controller": "red", "progress": 0, "locked": 3}
    assert score.stats()["captures"] == 3
    assert score.stats()["flips"] == 1


def test_opposing_push_moves_one_signed_meter():
    score = board(lock_ticks=0)
    score.register_point("p1")
    capture(score, "p1", "red", 40)
    pushed = capture(score, "p1", "blue", 60)
    assert pushed["progress"] == -20
    assert pushed["controller"] is None
    taken = capture(score, "p1", "blue", 80)
    assert taken["progress"] == 0
    assert taken["controller"] == "blue"
    assert score.stats()["flips"] == 1


def test_capture_rejects_bad_input():
    score = board()
    score.register_point("p1")
    with pytest.raises(ds.DominationError) as exc:
        capture(score, "p1", "green", 10)
    assert exc.value.code == "DOMINATION_INVALID_REQUEST"
    with pytest.raises(ds.DominationError) as exc:
        capture(score, "nope", "red", 10)
    assert exc.value.code == "DOMINATION_UNKNOWN_POINT"
    for bad_amount in (0, -5, "10"):
        with pytest.raises(ds.DominationError) as exc:
            capture(score, "p1", "red", bad_amount)
        assert exc.value.code == "DOMINATION_INVALID_REQUEST"
    assert score.point_state("p1")["progress"] == 0
    assert score.stats()["captures"] == 0


def test_locked_point_ignores_progress_until_settle_unlocks():
    score = board(lock_ticks=2, round_seconds=10)
    score.register_point("p1")
    capture(score, "p1", "red", 100)
    ignored = capture(score, "p1", "blue", 50)
    assert ignored["progress"] == 0
    assert ignored["locked"] == 2
    assert score.stats()["ignored"] == 1
    score.settle()
    assert score.point_state("p1")["locked"] == 1
    score.settle()
    assert score.point_state("p1")["locked"] == 0
    assert capture(score, "p1", "blue", 50)["progress"] == -50


def test_settle_awards_points_for_held_points():
    score = board(tick_points=10, round_seconds=10, lock_ticks=0)
    score.register_point("p1")
    score.register_point("p2")
    capture(score, "p1", "red", 100)
    capture(score, "p2", "red", 100)
    first = score.settle()
    assert first["ticks"] == 1
    assert first["awarded"] == {"red": 20, "blue": 0}
    assert first["clock"] == 9
    assert first["overtime"] == {"active": False, "remaining": 0, "trailing": None}
    second = score.settle(2)
    assert second["awarded"] == {"red": 40, "blue": 0}
    assert second["clock"] == 7
    assert score.score_of("red") == 60
    assert score.score_of("blue") == 0
    assert score.stats()["ticks"] == 3


def test_clock_exhaustion_starts_overtime_with_trailing_team():
    score = board(round_seconds=2, overtime_seconds=5, lock_ticks=0)
    score.register_point("p1")
    capture(score, "p1", "red", 100)
    first = score.settle()
    assert first["clock"] == 1
    assert first["overtime"]["active"] is False
    second = score.settle()
    assert second["clock"] == 0
    assert second["overtime"] == {"active": True, "remaining": 5, "trailing": "blue"}
    assert score.overtime() == {"active": True, "remaining": 5, "trailing": "blue"}
    assert score.score_of("red") == 20


def test_overtime_clock_advances_only_on_trailing_capture():
    score = board(round_seconds=1, overtime_seconds=3, tick_points=10, lock_ticks=0)
    score.register_point("p1")
    score.register_point("p2")
    capture(score, "p1", "red", 100)
    capture(score, "p2", "red", 100)
    entered = score.settle()
    assert entered["overtime"] == {"active": True, "remaining": 3, "trailing": "blue"}
    capture(score, "p1", "red", 100)
    leader_tick = score.settle()
    assert leader_tick["overtime"]["remaining"] == 3
    capture(score, "p1", "blue", 100)
    trailing_tick = score.settle()
    assert trailing_tick["overtime"]["remaining"] == 2
    assert score.score_of("red") == 50
    assert score.score_of("blue") == 10


def test_overtime_exhaustion_ends_round():
    score = board(round_seconds=1, overtime_seconds=2, tick_points=10, lock_ticks=0)
    score.register_point("p1")
    score.register_point("p2")
    score.register_point("p3")
    capture(score, "p1", "red", 100)
    capture(score, "p2", "red", 100)
    capture(score, "p3", "red", 100)
    score.settle()
    capture(score, "p1", "blue", 100)
    score.settle()
    assert score.overtime()["remaining"] == 1
    score.settle()
    assert score.overtime()["remaining"] == 1
    capture(score, "p2", "blue", 100)
    final = score.settle()
    assert score.overtime()["remaining"] == 0
    assert final["overtime"]["active"] is False
    result = score.finalize()
    assert result["winner"] == "red"
    assert result["reason"] == "overtime"
    assert result["scores"] == {"red": 80, "blue": 40}
    assert score.stats()["finalized"] == 1


def test_mercy_gap_triggers_on_settlement():
    score = board(mercy_gap=50, tick_points=60, round_seconds=10, lock_ticks=0)
    score.register_point("p1")
    capture(score, "p1", "red", 100)
    settled = score.settle()
    assert settled["awarded"] == {"red": 60, "blue": 0}
    assert score.mercy_check() == {"triggered": True, "gap": 60, "leader": "red"}
    result = score.finalize()
    assert result["winner"] == "red"
    assert result["reason"] == "mercy"
    assert score.stats()["mercies"] == 1


def test_finalize_before_round_end_is_refused():
    score = board(mercy_gap=1000)
    score.register_point("p1")
    capture(score, "p1", "red", 100)
    with pytest.raises(ds.DominationError) as exc:
        score.finalize()
    assert exc.value.code == "DOMINATION_ROUND_ACTIVE"
    assert score.stats()["finalized"] == 0


def test_points_held_counts_controlled_points_only():
    score = board(lock_ticks=0)
    for point_id in ("p1", "p2", "p3"):
        score.register_point(point_id)
    capture(score, "p1", "red", 100)
    capture(score, "p2", "red", 100)
    capture(score, "p3", "blue", 100)
    assert score.points_held("red") == 2
    assert score.points_held("blue") == 1
    assert score.score_of("red") == 0
    with pytest.raises(ds.DominationError) as exc:
        score.score_of("green")
    assert exc.value.code == "DOMINATION_INVALID_REQUEST"


def test_snapshot_is_detached_and_restore_roundtrips():
    score = board(round_seconds=2, overtime_seconds=4, lock_ticks=0)
    score.register_point("p1")
    capture(score, "p1", "red", 100)
    score.settle()
    state = score.snapshot()
    assert set(state) == {"version", "points", "scores", "clock", "overtime",
                          "mercy", "stats"}
    pristine = copy.deepcopy(state)
    state["points"].clear()
    state["scores"]["red"] = 999
    assert score.score_of("red") == 10
    assert score.point_state("p1")["controller"] == "red"

    clone = board(round_seconds=2, overtime_seconds=4, lock_ticks=0)
    clone.restore(pristine)
    assert clone.score_of("red") == 10
    assert clone.point_state("p1")["controller"] == "red"
    assert clone.stats()["ticks"] == 1
    after = clone.settle()
    assert after["clock"] == 0
    assert after["overtime"] == {"active": True, "remaining": 4, "trailing": "blue"}


def test_restore_rejects_malformed_state_without_touching_live_data():
    score = board(lock_ticks=0)
    score.register_point("p1")
    capture(score, "p1", "red", 100)
    score.settle()
    good = score.snapshot()
    bad_states = [
        None,
        {},
        {**good, "version": 2},
        {key: value for key, value in good.items() if key != "mercy"},
        {**good, "points": []},
        {**good, "scores": []},
        {**good, "overtime": []},
        {**good, "stats": {"points": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(ds.DominationError) as exc:
            score.restore(bad)
        assert exc.value.code == "DOMINATION_SNAPSHOT_INVALID"
    assert score.score_of("red") == 10
    assert score.point_state("p1")["controller"] == "red"
    assert score.stats()["ticks"] == 1


def test_concurrent_captures_keep_progress_bounded():
    score = board(lock_ticks=0, mercy_gap=1000)
    score.register_point("p1")
    errors = []
    barrier = threading.Barrier(12)

    def worker():
        try:
            barrier.wait(timeout=5)
            score.capture_tick("p1", "red", 10)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    state = score.point_state("p1")
    assert state["controller"] == "red"
    assert state["progress"] == 20
    assert -100 <= state["progress"] <= 100
    assert score.stats()["captures"] == 12
    assert score.stats()["flips"] == 1
