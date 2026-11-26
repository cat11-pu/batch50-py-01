import copy
import threading

import pytest

import takeover_supervisor as ts


def supervisor(**kwargs):
    params = dict(grace_ticks=3, frame_budget=3, max_pending=8)
    params.update(kwargs)
    return ts.TakeoverSupervisor(**params)


def make_supervised(control, character="c1"):
    control.mark_offline(character)
    control.advance_frame(control.grace_ticks)
    return control.takeover(character)


def test_register_character_and_initial_state():
    control = supervisor()
    state = control.register_character("c1")
    assert state == {"character": "c1", "status": "online", "controller": "player",
                     "grace_left": 0, "frozen_ticks": 0, "budget_left": 3}
    assert control.stats() == {"registered": 1, "offline": 0, "takeovers": 0,
                               "handbacks": 0, "executed": 0, "queued": 0,
                               "denied": 0, "refused": 0}
    with pytest.raises(ts.TakeoverError) as exc:
        control.register_character("   ")
    assert exc.value.code == "TAKEOVER_INVALID_REQUEST"
    with pytest.raises(ts.TakeoverError) as exc:
        control.register_character("c1")
    assert exc.value.code == "TAKEOVER_INVALID_REQUEST"


def test_grace_window_and_early_takeover_refused():
    control = supervisor(grace_ticks=3)
    control.register_character("c1")
    grace = control.mark_offline("c1")
    assert grace == {"character": "c1", "status": "grace", "controller": "player",
                     "grace_left": 3, "frozen_ticks": 0, "budget_left": 3}
    control.advance_frame(2)
    assert control.state_of("c1")["grace_left"] == 1
    with pytest.raises(ts.TakeoverError) as exc:
        control.takeover("c1")
    assert exc.value.code == "TAKEOVER_GRACE_ACTIVE"
    control.heartbeat("c1")
    assert control.state_of("c1")["status"] == "online"
    with pytest.raises(ts.TakeoverError) as exc:
        control.takeover("c1")
    assert exc.value.code == "TAKEOVER_NOT_OFFLINE"


def test_takeover_after_grace_changes_controller():
    control = supervisor(grace_ticks=2)
    control.register_character("c1")
    control.mark_offline("c1")
    control.advance_frame(2)
    state = control.takeover("c1")
    assert state == {"character": "c1", "status": "supervised",
                     "controller": "supervisor", "grace_left": 0,
                     "frozen_ticks": 0, "budget_left": 3}
    assert control.stats()["takeovers"] == 1
    assert control.stats()["offline"] == 1


def test_second_takeover_is_refused():
    control = supervisor()
    control.register_character("c1")
    make_supervised(control)
    with pytest.raises(ts.TakeoverError) as exc:
        control.takeover("c1")
    assert exc.value.code == "TAKEOVER_ALREADY_SUPERVISED"
    assert control.stats()["takeovers"] == 1


def test_execute_consumes_frame_budget():
    control = supervisor(frame_budget=3)
    control.register_character("c1")
    make_supervised(control)
    first = control.execute("c1", "move")
    assert first["status"] == "executed"
    assert first["budget_left"] == 2
    assert first["pending"] == 0
    second = control.execute("c1", "dodge")
    assert second["status"] == "executed"
    assert second["budget_left"] == 1
    assert control.stats()["executed"] == 2
    other = supervisor()
    other.register_character("c2")
    with pytest.raises(ts.TakeoverError) as exc:
        other.execute("c2", "move")
    assert exc.value.code == "TAKEOVER_NOT_SUPERVISED"


def test_execute_denies_action_outside_restricted_set():
    control = supervisor()
    control.register_character("c1")
    make_supervised(control)
    with pytest.raises(ts.TakeoverError) as exc:
        control.execute("c1", "meteor")
    assert exc.value.code == "TAKEOVER_ACTION_DENIED"
    state = control.state_of("c1")
    assert state["budget_left"] == 3
    assert control.pending_actions("c1") == []
    assert control.stats()["denied"] == 1
    assert control.stats()["executed"] == 0


def test_budget_exhaustion_queues_until_limit():
    control = supervisor(frame_budget=2, max_pending=2)
    control.register_character("c1")
    make_supervised(control)
    control.execute("c1", "move")
    control.execute("c1", "move")
    queued_one = control.execute("c1", "dodge")
    assert queued_one["status"] == "queued"
    assert queued_one["pending"] == 1
    assert queued_one["budget_left"] == 0
    control.execute("c1", "guard")
    assert control.pending_actions("c1") == ["dodge", "guard"]
    with pytest.raises(ts.TakeoverError) as exc:
        control.execute("c1", "move")
    assert exc.value.code == "TAKEOVER_QUEUE_FULL"
    assert control.stats()["queued"] == 2
    control.advance_frame(1)
    after = control.execute("c1", "move")
    assert after["status"] == "executed"
    assert after["budget_left"] == 1
    assert control.pending_actions("c1") == ["dodge", "guard"]


def test_handback_freezes_one_frame_then_returns_control():
    control = supervisor()
    control.register_character("c1")
    make_supervised(control)
    state = control.handback("c1")
    assert state == {"character": "c1", "status": "returning",
                     "controller": "frozen", "grace_left": 0,
                     "frozen_ticks": 1, "budget_left": 3}
    with pytest.raises(ts.TakeoverError) as exc:
        control.submit_input("c1", "move")
    assert exc.value.code == "TAKEOVER_CONTROL_FROZEN"
    with pytest.raises(ts.TakeoverError) as exc:
        control.execute("c1", "move")
    assert exc.value.code == "TAKEOVER_CONTROL_FROZEN"
    summary = control.advance_frame(1)
    assert summary["returned"] == ["c1"]
    assert control.state_of("c1") == {"character": "c1", "status": "online",
                                      "controller": "player", "grace_left": 0,
                                      "frozen_ticks": 0, "budget_left": 3}
    accepted = control.submit_input("c1", "move")
    assert accepted["character"] == "c1"
    assert accepted["accepted"] is True
    assert control.stats()["handbacks"] == 1
    with pytest.raises(ts.TakeoverError) as exc:
        control.handback("c1")
    assert exc.value.code == "TAKEOVER_NOT_SUPERVISED"


def test_heartbeat_does_not_lift_active_takeover():
    control = supervisor()
    control.register_character("c1")
    make_supervised(control)
    state = control.heartbeat("c1")
    assert state["status"] == "supervised"
    assert state["controller"] == "supervisor"
    result = control.execute("c1", "move")
    assert result["status"] == "executed"


def test_pending_actions_lifecycle_and_unknown_character():
    control = supervisor()
    control.register_character("c1")
    assert control.pending_actions("c1") == []
    with pytest.raises(ts.TakeoverError) as exc:
        control.pending_actions("ghost")
    assert exc.value.code == "TAKEOVER_UNKNOWN_CHARACTER"
    with pytest.raises(ts.TakeoverError) as exc:
        control.state_of("ghost")
    assert exc.value.code == "TAKEOVER_UNKNOWN_CHARACTER"


def test_advance_frame_reports_grace_and_return_events():
    control = supervisor(grace_ticks=2)
    control.register_character("a")
    control.register_character("b")
    control.mark_offline("a")
    first = control.advance_frame(2)
    assert first == {"frame": 2, "grace_expired": ["a"], "returned": []}
    control.takeover("a")
    control.handback("a")
    second = control.advance_frame(1)
    assert second == {"frame": 3, "grace_expired": [], "returned": ["a"]}
    with pytest.raises(ts.TakeoverError) as exc:
        control.advance_frame(0)
    assert exc.value.code == "TAKEOVER_INVALID_REQUEST"


def test_snapshot_is_detached_and_restore_roundtrips():
    control = supervisor(grace_ticks=2, frame_budget=3)
    control.register_character("c1")
    make_supervised(control)
    for _ in range(3):
        control.execute("c1", "move")
    control.execute("c1", "move")
    control.execute("c1", "dodge")
    assert control.pending_actions("c1") == ["move", "dodge"]
    state = control.snapshot()
    assert set(state) == {"version", "frame", "characters", "stats"}
    pristine = copy.deepcopy(state)
    state["characters"].clear()
    state["stats"]["takeovers"] = 99
    assert control.state_of("c1")["status"] == "supervised"
    assert control.stats()["takeovers"] == 1

    clone = supervisor(grace_ticks=2, frame_budget=3)
    clone.restore(pristine)
    assert clone.state_of("c1")["controller"] == "supervisor"
    assert clone.state_of("c1")["budget_left"] == 0
    assert clone.pending_actions("c1") == ["move", "dodge"]
    assert clone.stats()["takeovers"] == 1
    clone.advance_frame(1)
    assert clone.state_of("c1")["budget_left"] == 3
    assert clone.execute("c1", "guard")["status"] == "executed"


def test_restore_rejects_malformed_state_without_touching_live_data():
    control = supervisor()
    control.register_character("c1")
    make_supervised(control)
    control.execute("c1", "move")
    good = control.snapshot()
    bad_states = [
        None,
        {},
        {**good, "version": 2},
        {key: value for key, value in good.items() if key != "stats"},
        {**good, "characters": []},
        {**good, "characters": {"c1": "supervised"}},
        {**good, "stats": []},
        {**good, "stats": {"registered": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(ts.TakeoverError) as exc:
            control.restore(bad)
        assert exc.value.code == "TAKEOVER_SNAPSHOT_INVALID"
    assert control.state_of("c1")["status"] == "supervised"
    assert control.state_of("c1")["budget_left"] == 2
    assert control.stats()["takeovers"] == 1


def test_concurrent_takeover_allows_only_one_controller():
    control = supervisor(grace_ticks=1)
    control.register_character("c1")
    control.mark_offline("c1")
    control.advance_frame(1)
    outcomes = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            control.takeover("c1")
            outcomes.append("ok")
        except ts.TakeoverError as exc:
            outcomes.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert outcomes.count("ok") == 1
    assert outcomes.count("TAKEOVER_ALREADY_SUPERVISED") == 7
    assert control.stats()["takeovers"] == 1
    assert control.state_of("c1")["controller"] == "supervisor"


def test_stats_track_mixed_supervision_sequence():
    control = supervisor(grace_ticks=1, frame_budget=2)
    control.register_character("c1")
    control.mark_offline("c1")
    control.advance_frame(1)
    control.takeover("c1")
    control.execute("c1", "move")
    control.execute("c1", "dodge")
    queued = control.execute("c1", "move")
    assert queued["status"] == "queued"
    control.handback("c1")
    control.advance_frame(1)
    assert control.stats() == {"registered": 1, "offline": 1, "takeovers": 1,
                               "handbacks": 1, "executed": 2, "queued": 1,
                               "denied": 0, "refused": 0}
