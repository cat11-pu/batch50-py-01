import threading

import pytest

import trap_trigger_orchestrator as to


def orchestrator(**kwargs):
    return to.TrapTriggerOrchestrator(**kwargs)


def with_players(*names):
    instance = orchestrator()
    for name in names:
        instance.register_player(name)
    return instance


def test_register_trap_creates_unarmed_trap():
    instance = orchestrator()
    trap = instance.register_trap("spike", charges=3, radius=2,
                                  cooldown_frames=4)
    assert trap.trap_id == "spike"
    assert trap.charges == 3
    assert trap.initial_charges == 3
    assert trap.radius == 2
    assert trap.cooldown_frames == 4
    assert trap.one_shot is False
    assert trap.reset_on_wipe is True
    assert trap.armed is False
    assert trap.spent is False
    assert instance.charges_of("spike") == 3
    with pytest.raises(to.TrapError) as exc:
        instance.register_trap("spike", charges=1, radius=1)
    assert exc.value.code == "TRAP_DUPLICATE_TRAP"
    for charges, radius, cooldown in ((0, 1, 0), (1, 0, 0), (1, 1, -1)):
        with pytest.raises(to.TrapError) as exc:
            instance.register_trap(f"bad-{charges}-{radius}-{cooldown}",
                                   charges=charges, radius=radius,
                                   cooldown_frames=cooldown)
        assert exc.value.code == "TRAP_INVALID_REQUEST"


def test_register_player_and_unknown_player():
    instance = with_players("p1")
    with pytest.raises(to.TrapError) as exc:
        instance.register_player("p1")
    assert exc.value.code == "TRAP_DUPLICATE_PLAYER"
    instance.register_trap("spike", charges=2, radius=2)
    instance.arm("spike")
    with pytest.raises(to.TrapError) as exc:
        instance.trigger("spike", ["ghost"])
    assert exc.value.code == "TRAP_UNKNOWN_PLAYER"


def test_arm_and_disarm_control_triggering():
    instance = with_players("p1")
    instance.register_trap("spike", charges=2, radius=1)
    armed = instance.arm("spike")
    assert armed.armed is True
    with pytest.raises(to.TrapError) as exc:
        instance.arm("spike")
    assert exc.value.code == "TRAP_ALREADY_ARMED"
    disarmed = instance.disarm("spike")
    assert disarmed.armed is False
    with pytest.raises(to.TrapError) as exc:
        instance.trigger("spike", ["p1"])
    assert exc.value.code == "TRAP_NOT_ARMED"


def test_trigger_consumes_charge_per_player_in_arrival_order():
    instance = with_players("p1", "p2", "p3")
    instance.register_trap("spike", charges=5, radius=3)
    instance.arm("spike")
    outcomes = instance.trigger("spike", ["p3", "p1", "p2"])
    assert tuple(item.player for item in outcomes) == ("p3", "p1", "p2")
    assert tuple(item.status for item in outcomes) == (
        "triggered", "triggered", "triggered")
    assert all(item.frame == 1 for item in outcomes)
    assert instance.charges_of("spike") == 2
    assert instance.stats()["triggered"] == 3


def test_burst_marks_depleted_after_last_charge():
    instance = with_players("p1", "p2", "p3")
    instance.register_trap("spike", charges=1, radius=3)
    instance.arm("spike")
    outcomes = instance.trigger("spike", ["p1", "p2", "p3"])
    assert tuple(item.status for item in outcomes) == (
        "triggered", "depleted", "depleted")
    assert instance.charges_of("spike") == 0
    assert instance.trap_state("spike").armed is False
    assert instance.stats()["depleted"] == 2
    with pytest.raises(to.TrapError) as exc:
        instance.trigger("spike", ["p1"])
    assert exc.value.code == "TRAP_NOT_ARMED"


def test_player_cooldown_blocks_repeat_trigger():
    instance = with_players("p1", "p2")
    instance.register_trap("spike", charges=6, radius=2, cooldown_frames=3)
    instance.arm("spike")
    instance.trigger("spike", ["p1"])
    assert instance.cooldown_of("spike", "p1") == 3
    second = instance.trigger("spike", ["p1"])
    assert second[0].status == "cooldown"
    assert instance.cooldown_of("spike", "p1") == 2
    instance.trigger("spike", ["p2"])
    assert instance.cooldown_of("spike", "p1") == 1
    instance.trigger("spike", ["p2"])
    assert instance.cooldown_of("spike", "p1") == 0
    third = instance.trigger("spike", ["p1"])
    assert third[0].status == "triggered"


def test_one_shot_trap_is_permanently_spent():
    instance = with_players("p1")
    instance.register_trap("glyph", charges=2, radius=1, one_shot=True)
    instance.arm("glyph")
    outcomes = instance.trigger("glyph", ["p1"])
    assert outcomes[0].status == "triggered"
    assert instance.charges_of("glyph") == 0
    state = instance.trap_state("glyph")
    assert state.spent is True
    assert state.armed is False
    assert instance.rearmable("glyph") is False
    with pytest.raises(to.TrapError) as exc:
        instance.arm("glyph")
    assert exc.value.code == "TRAP_PERMANENTLY_SPENT"


def test_radius_caps_players_per_frame():
    instance = with_players("p1", "p2", "p3")
    instance.register_trap("spike", charges=3, radius=1)
    instance.arm("spike")
    outcomes = instance.trigger("spike", ["p1", "p2", "p3"])
    assert tuple(item.status for item in outcomes) == (
        "triggered", "overflow", "overflow")
    assert instance.charges_of("spike") == 2
    assert instance.stats()["overflow"] == 2


def test_unknown_trap_operations_are_rejected():
    instance = orchestrator()
    calls = [
        lambda: instance.charges_of("ghost"),
        lambda: instance.cooldown_of("ghost", "p1"),
        lambda: instance.trap_state("ghost"),
        lambda: instance.arm("ghost"),
    ]
    for call in calls:
        with pytest.raises(to.TrapError) as exc:
            call()
        assert exc.value.code == "TRAP_UNKNOWN_TRAP"


def test_reset_instance_rearms_resettable_traps():
    instance = with_players("p1")
    instance.register_trap("spike", charges=4, radius=1, cooldown_frames=2)
    instance.arm("spike")
    instance.trigger("spike", ["p1"])
    assert instance.charges_of("spike") == 3
    assert instance.cooldown_of("spike", "p1") == 2
    result = instance.reset_instance()
    assert result["restored"] == 1
    assert result["left_alone"] == 0
    assert instance.charges_of("spike") == 4
    assert instance.cooldown_of("spike", "p1") == 0
    assert instance.trap_state("spike").armed is True
    assert instance.stats()["resets"] == 1


def test_rearmable_reports_configuration():
    instance = orchestrator()
    instance.register_trap("normal", charges=2, radius=1)
    instance.register_trap("glyph", charges=2, radius=1, one_shot=True)
    instance.register_trap("anchor", charges=2, radius=1, reset_on_wipe=False)
    assert instance.rearmable("normal") is True
    assert instance.rearmable("glyph") is False
    assert instance.rearmable("anchor") is False


def test_stats_track_frames_and_rejections():
    instance = with_players("p1", "p2")
    instance.register_trap("spike", charges=2, radius=2, cooldown_frames=2)
    instance.arm("spike")
    first = instance.trigger("spike", ["p1", "p1"])
    assert tuple(item.status for item in first) == ("triggered", "cooldown")
    instance.trigger("spike", ["p2"])
    counters = instance.stats()
    assert counters["frames"] == 2
    assert counters["triggered"] == 2
    assert counters["cooldown_rejected"] == 1
    assert counters["depleted"] == 0
    assert counters["overflow"] == 0


def test_snapshot_preserves_charges_and_player_cooldowns():
    instance = with_players("p1", "p2")
    instance.register_trap("spike", charges=5, radius=1, cooldown_frames=3)
    instance.arm("spike")
    instance.trigger("spike", ["p1"])
    snap = instance.snapshot()
    fresh = orchestrator()
    fresh.restore(snap)
    assert fresh.charges_of("spike") == 4
    assert fresh.cooldown_of("spike", "p1") == 3
    assert fresh.trap_state("spike").armed is True
    fresh.trigger("spike", ["p2"])
    assert fresh.cooldown_of("spike", "p1") == 2
    instance.disarm("spike")
    assert fresh.trap_state("spike").armed is True


def test_restore_rejects_malformed_state():
    instance = with_players("p1")
    instance.register_trap("spike", charges=3, radius=1)
    instance.arm("spike")
    before = instance.trap_state("spike")
    with pytest.raises(to.TrapError) as exc:
        instance.restore({"traps": []})
    assert exc.value.code == "TRAP_SNAPSHOT_INVALID"
    assert instance.trap_state("spike") == before
    with pytest.raises(to.TrapError) as exc:
        instance.restore({"traps": {}, "players": [], "frame": -1})
    assert exc.value.code == "TRAP_SNAPSHOT_INVALID"


def test_concurrent_triggers_do_not_overspend_charges():
    instance = with_players(*[f"p{i}" for i in range(8)])
    instance.register_trap("spike", charges=2, radius=1)
    instance.arm("spike")
    barrier = threading.Barrier(8)
    outcomes = []
    refused = []
    errors = []
    lock = threading.Lock()

    def worker(player):
        try:
            barrier.wait(timeout=5)
            result = instance.trigger("spike", [player])
            with lock:
                outcomes.extend(result)
        except to.TrapError as exc:
            with lock:
                refused.append(exc.code)
        except BaseException as exc:  # noqa: BLE001 - collected for assert
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(f"p{i}",))
               for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == []
    triggered = [item for item in outcomes if item.status == "triggered"]
    assert len(triggered) == 2
    assert instance.charges_of("spike") == 0
