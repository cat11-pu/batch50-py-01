import threading

import pytest

import simulation_safety_interlock as si

SCOPE = ["10.1.0.0/16", "192.168.5.0/24"]


def interlock(**kwargs):
    return si.SimulationSafetyInterlock(**kwargs)


def prepared(**kwargs):
    app = interlock(**kwargs)
    app.register_scope("lab", cidrs=SCOPE)
    app.arm("sim-1", scope_id="lab", now=1000)
    return app


def test_register_scope_and_arm_marks_run_armed():
    app = interlock()
    scope = app.register_scope("lab", cidrs=SCOPE)
    assert scope == {"scope_id": "lab", "cidrs": tuple(SCOPE)}
    run = app.arm("sim-1", scope_id="lab", now=1000)
    assert run == {"run_id": "sim-1", "scope_id": "lab", "state": si.RUN_ARMED,
                   "armed_at": 1000}
    status = app.status(now=1000)
    assert status["state"] == si.STATE_ARMED
    assert status["armed_runs"] == 1
    assert status["in_flight"] == 0


def test_register_scope_validates_ids_and_cidrs():
    app = interlock()
    with pytest.raises(si.InterlockError) as exc:
        app.register_scope("", cidrs=SCOPE)
    assert exc.value.code == "INTERLOCK_INVALID_REQUEST"
    for cidrs in ([], ["10.0.0.0/33"], ["not-a-network"]):
        with pytest.raises(si.InterlockError) as exc:
            app.register_scope("lab", cidrs=cidrs)
        assert exc.value.code == "INTERLOCK_BAD_SCOPE"
    app.register_scope("lab", cidrs=SCOPE)
    with pytest.raises(si.InterlockError) as exc:
        app.register_scope("lab", cidrs=["10.9.0.0/16"])
    assert exc.value.code == "INTERLOCK_SCOPE_EXISTS"
    with pytest.raises(si.InterlockError) as exc:
        app.arm("sim-1", scope_id="lab-b", now=1000)
    assert exc.value.code == "INTERLOCK_SCOPE_UNKNOWN"


def test_arm_rejects_unknown_scope_duplicate_run_and_blank_id():
    app = interlock()
    app.register_scope("lab", cidrs=SCOPE)
    with pytest.raises(si.InterlockError) as exc:
        app.arm("sim-1", scope_id="other", now=1000)
    assert exc.value.code == "INTERLOCK_SCOPE_UNKNOWN"
    with pytest.raises(si.InterlockError) as exc:
        app.arm("  ", scope_id="lab", now=1000)
    assert exc.value.code == "INTERLOCK_INVALID_REQUEST"

    app.arm("sim-1", scope_id="lab", now=1000)
    with pytest.raises(si.InterlockError) as exc:
        app.arm("sim-1", scope_id="lab", now=1001)
    assert exc.value.code == "INTERLOCK_RUN_EXISTS"
    assert app.status(now=1001)["armed_runs"] == 1


def test_check_action_requires_target_inside_authorized_scope():
    app = prepared()
    permit = app.check_action("sim-1", action_id="a-1", target="10.1.7.9",
                              now=1001)
    assert permit["permit_id"] == "P-0001"
    assert permit["run_id"] == "sim-1"
    assert permit["action_id"] == "a-1"
    assert permit["target"] == "10.1.7.9"
    assert permit["state"] == si.PERMIT_IN_FLIGHT
    assert permit["granted_at"] == 1001
    assert app.check_action("sim-1", action_id="a-2", target="192.168.5.200",
                            now=1002)["state"] == si.PERMIT_IN_FLIGHT

    with pytest.raises(si.InterlockError) as exc:
        app.check_action("sim-1", action_id="a-3", target="10.2.0.1", now=1003)
    assert exc.value.code == "SCOPE_TARGET_DENIED"
    with pytest.raises(si.InterlockError) as exc:
        app.check_action("sim-1", action_id="a-4", target="10.1.0.0/16", now=1004)
    assert exc.value.code == "INTERLOCK_BAD_TARGET"
    with pytest.raises(si.InterlockError) as exc:
        app.check_action("sim-1", action_id="", target="10.1.7.9", now=1005)
    assert exc.value.code == "INTERLOCK_INVALID_REQUEST"


def test_per_target_budget_resets_in_the_next_window():
    app = prepared(per_target_rate=2, global_rate=50, window_seconds=10)
    assert app.check_action("sim-1", action_id="a-1", target="10.1.0.5",
                            now=1000)["state"] == si.PERMIT_IN_FLIGHT
    assert app.check_action("sim-1", action_id="a-2", target="10.1.0.5",
                            now=1001)["state"] == si.PERMIT_IN_FLIGHT
    with pytest.raises(si.InterlockError) as exc:
        app.check_action("sim-1", action_id="a-3", target="10.1.0.5", now=1002)
    assert exc.value.code == "RATE_TARGET_EXCEEDED"
    assert app.check_action("sim-1", action_id="a-4", target="10.1.0.6",
                            now=1002)["state"] == si.PERMIT_IN_FLIGHT
    assert app.check_action("sim-1", action_id="a-5", target="10.1.0.5",
                            now=1010)["state"] == si.PERMIT_IN_FLIGHT


def test_global_budget_spans_targets_and_resets_per_window():
    app = prepared(global_rate=3, per_target_rate=5, window_seconds=10)
    targets = ["10.1.0.1", "10.1.0.2", "10.1.0.3"]
    for index, target in enumerate(targets):
        assert app.check_action("sim-1", action_id=f"a-{index}", target=target,
                                now=1000)["state"] == si.PERMIT_IN_FLIGHT
    with pytest.raises(si.InterlockError) as exc:
        app.check_action("sim-1", action_id="a-9", target="10.1.0.4", now=1001)
    assert exc.value.code == "RATE_GLOBAL_EXCEEDED"
    assert app.check_action("sim-1", action_id="a-10", target="10.1.0.4",
                            now=1010)["state"] == si.PERMIT_IN_FLIGHT


def test_action_ids_are_unique_per_run_only():
    app = prepared()
    app.arm("sim-2", scope_id="lab", now=1000)
    app.check_action("sim-1", action_id="recon-1", target="10.1.0.5", now=1001)
    with pytest.raises(si.InterlockError) as exc:
        app.check_action("sim-1", action_id="recon-1", target="10.1.0.6",
                         now=1002)
    assert exc.value.code == "INTERLOCK_DUPLICATE_ACTION"
    assert app.check_action("sim-2", action_id="recon-1", target="10.1.0.6",
                            now=1003)["run_id"] == "sim-2"


def test_finish_action_settles_a_permit_once():
    app = prepared()
    permit = app.check_action("sim-1", action_id="a-1", target="10.1.0.5",
                              now=1001)
    with pytest.raises(si.InterlockError) as exc:
        app.finish_action("P-9999", outcome="ok", now=1002)
    assert exc.value.code == "INTERLOCK_PERMIT_UNKNOWN"
    with pytest.raises(si.InterlockError) as exc:
        app.finish_action(permit["permit_id"], outcome="maybe", now=1002)
    assert exc.value.code == "INTERLOCK_INVALID_REQUEST"

    done = app.finish_action(permit["permit_id"], outcome="ok", now=1003)
    assert done["state"] == si.PERMIT_COMPLETED
    assert done["settled_at"] == 1003
    with pytest.raises(si.InterlockError) as exc:
        app.finish_action(permit["permit_id"], outcome="ok", now=1004)
    assert exc.value.code == "INTERLOCK_PERMIT_SETTLED"

    second = app.check_action("sim-1", action_id="a-2", target="10.1.0.6",
                              now=1005)
    assert app.finish_action(second["permit_id"], outcome="failed",
                             now=1006)["state"] == si.PERMIT_FAILED


def test_check_action_and_disarm_require_an_armed_run():
    app = prepared()
    with pytest.raises(si.InterlockError) as exc:
        app.check_action("missing", action_id="a-1", target="10.1.0.5", now=1001)
    assert exc.value.code == "INTERLOCK_RUN_UNKNOWN"

    disarmed = app.disarm("sim-1", now=1002)
    assert disarmed == {"run_id": "sim-1", "state": si.RUN_DISARMED,
                        "disarmed_at": 1002}
    with pytest.raises(si.InterlockError) as exc:
        app.check_action("sim-1", action_id="a-1", target="10.1.0.5", now=1003)
    assert exc.value.code == "INTERLOCK_RUN_STATE"
    with pytest.raises(si.InterlockError) as exc:
        app.disarm("sim-1", now=1004)
    assert exc.value.code == "INTERLOCK_RUN_STATE"
    with pytest.raises(si.InterlockError) as exc:
        app.disarm("missing", now=1005)
    assert exc.value.code == "INTERLOCK_RUN_UNKNOWN"


def test_trip_freezes_every_run_and_blocks_new_actions():
    app = prepared()
    app.arm("sim-2", scope_id="lab", now=1000)
    app.check_action("sim-1", action_id="a-1", target="10.1.0.5", now=1001)
    app.check_action("sim-2", action_id="a-2", target="10.1.0.6", now=1002)
    out = app.trip(reason="target_escape", now=1003)
    assert out["tripped_runs"] == 2
    assert out["frozen_permits"] == 2
    assert out["reason"] == "target_escape"
    assert app.status()["state"] == si.STATE_TRIPPED
    for run_id in ("sim-1", "sim-2"):
        with pytest.raises(si.InterlockError) as exc:
            app.check_action(run_id, action_id="a-9", target="10.1.0.7",
                             now=1004)
        assert exc.value.code == "INTERLOCK_TRIPPED"
    with pytest.raises(si.InterlockError) as exc:
        app.arm("sim-3", scope_id="lab", now=1004)
    assert exc.value.code == "INTERLOCK_TRIPPED"


def test_reset_cools_down_before_new_runs_are_armed():
    app = prepared(cooldown_seconds=60)
    app.trip(reason="runaway_scan", now=1000)
    out = app.reset(now=1005)
    assert out["state"] == si.STATE_COOLING
    assert out["reset_at"] == 1005
    assert out["cooling_until"] == 1060
    assert app.status(now=1025)["cooling_remaining"] == 35
    assert app.arm("sim-2", scope_id="lab", now=1060)["state"] == si.RUN_ARMED
    with pytest.raises(si.InterlockError) as exc:
        app.reset(now=1061)
    assert exc.value.code == "INTERLOCK_NOT_TRIPPED"


def test_concurrent_action_checks_all_get_permits():
    app = prepared(global_rate=100, per_target_rate=100, window_seconds=10)
    errors = []
    barrier = threading.Barrier(20)

    def worker(index):
        try:
            barrier.wait(timeout=10)
            app.check_action("sim-1", action_id=f"a-{index}",
                             target="10.1.0.5", now=1000)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(20)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(app.permits()) == 20
    assert app.report()["in_flight"] == 20
    assert app.stats()["permits"] == 20


def test_snapshot_is_detached_and_restore_roundtrips():
    app = prepared()
    first = app.check_action("sim-1", action_id="a-1", target="10.1.0.5",
                             now=1001)
    second = app.check_action("sim-1", action_id="a-2", target="10.1.0.6",
                              now=1002)
    app.finish_action(first["permit_id"], outcome="ok", now=1003)
    app.finish_action(second["permit_id"], outcome="failed", now=1004)

    state = app.snapshot()
    assert set(state) == {"format", "scopes", "runs", "permits", "switch",
                          "counters"}
    state["permits"].clear()
    state["runs"].clear()
    assert len(app.permits()) == 2
    assert app.report()["completed"] == 1
    assert app.status()["armed_runs"] == 1

    clone = interlock()
    clone.restore(app.snapshot())
    assert clone.status()["armed_runs"] == 1
    assert clone.report() == {"actions": 2, "in_flight": 0, "completed": 1,
                              "failed": 1, "voided": 0}
    assert [row["permit_id"] for row in clone.permits(run_id="sim-1")] == \
        ["P-0001", "P-0002"]
    assert clone.stats() == {"scopes": 1, "runs": 1, "permits": 2, "trips": 0,
                             "resets": 0}


def test_restore_rejects_malformed_state_without_touching_live_data():
    app = prepared()
    app.check_action("sim-1", action_id="a-1", target="10.1.0.5", now=1001)
    good = app.snapshot()
    bad_states = [
        None,
        {},
        dict(good, format="other"),
        dict(good, permits=[]),
        dict(good, scopes="nope"),
        dict(good, switch="nope"),
    ]
    for bad in bad_states:
        with pytest.raises(si.InterlockError) as exc:
            app.restore(bad)
        assert exc.value.code == "INTERLOCK_SNAPSHOT_INVALID"

    assert app.status()["armed_runs"] == 1
    assert len(app.permits()) == 1


def test_permits_are_listed_by_id_and_counters_are_exact():
    app = prepared()
    first = app.check_action("sim-1", action_id="a-1", target="10.1.0.5",
                             now=1001)
    second = app.check_action("sim-1", action_id="a-2", target="10.1.0.6",
                              now=1002)
    app.finish_action(first["permit_id"], outcome="ok", now=1003)
    app.finish_action(second["permit_id"], outcome="failed", now=1004)

    rows = app.permits()
    assert [row["permit_id"] for row in rows] == ["P-0001", "P-0002"]
    assert [row["state"] for row in rows] == [si.PERMIT_COMPLETED,
                                              si.PERMIT_FAILED]
    assert app.stats() == {"scopes": 1, "runs": 1, "permits": 2, "trips": 0,
                           "resets": 0}
    with pytest.raises(si.InterlockError) as exc:
        app.trip(reason="  ", now=1005)
    assert exc.value.code == "INTERLOCK_INVALID_REQUEST"
