import copy
import threading

import pytest

import wipe_recovery_ledger as wrl


def make(**kwargs):
    return wrl.WipeRecoveryLedger(**kwargs)


def test_enter_records_checkpoint_and_rejects_double_entry():
    ledger = make()
    progress = ledger.enter_combat("boss-a", hp_max=1200, phase=1)
    assert progress.status == "engaged"
    assert (progress.hp, progress.hp_max, progress.phase) == (1200, 1200, 1)
    assert (progress.checkpoint_hp, progress.checkpoint_phase) == (1200, 1)
    assert progress.attempts_left == 3
    assert progress.consecutive_wipes == 0
    assert progress.buffs == ()
    assert progress.summons == ()
    with pytest.raises(wrl.RecoveryError) as exc:
        ledger.enter_combat("boss-a")
    assert exc.value.code == "RECOVERY_ALREADY_ENGAGED"


def test_advance_phase_moves_checkpoint_and_rejects_regression():
    ledger = make()
    ledger.enter_combat("boss-a", hp_max=1000)
    progress = ledger.advance_phase("boss-a", phase=2, hp=780)
    assert progress.phase == 2
    assert progress.hp == 780
    assert (progress.checkpoint_hp, progress.checkpoint_phase) == (780, 2)
    with pytest.raises(wrl.RecoveryError) as exc:
        ledger.advance_phase("boss-a", phase=2, hp=700)
    assert exc.value.code == "RECOVERY_PHASE_REGRESSION"
    with pytest.raises(wrl.RecoveryError) as exc:
        ledger.advance_phase("boss-a", phase=1, hp=700)
    assert exc.value.code == "RECOVERY_PHASE_REGRESSION"


def test_wipe_moves_to_recovery_and_spends_attempt():
    ledger = make()
    ledger.enter_combat("boss-a", hp_max=1000)
    progress = ledger.wipe("boss-a")
    assert progress.status == "recovering"
    assert progress.consecutive_wipes == 1
    assert progress.total_wipes == 1
    assert progress.attempts_left == 2


def test_duplicate_wipe_report_counts_once():
    ledger = make()
    ledger.enter_combat("boss-a", hp_max=1000)
    ledger.wipe("boss-a")
    progress = ledger.wipe("boss-a")
    assert progress.status == "recovering"
    assert progress.consecutive_wipes == 1
    assert progress.total_wipes == 1
    assert progress.attempts_left == 2
    assert ledger.stats()["wipes"] == 1


def test_recover_restores_checkpoint_and_clears_effects():
    ledger = make()
    ledger.enter_combat("boss-a", hp_max=1000)
    ledger.advance_phase("boss-a", phase=2, hp=640)
    ledger.add_effect("boss-a", "buff", "frenzy")
    ledger.add_effect("boss-a", "summon", "add-1")
    ledger.wipe("boss-a")
    outcome = ledger.recover("boss-a")
    assert outcome.restored_hp == 640
    assert outcome.restored_phase == 2
    assert outcome.cleared_buffs == ("frenzy",)
    assert outcome.cleared_summons == ("add-1",)
    assert outcome.ejected is False
    assert outcome.attempts_left == 2
    progress = ledger.progress_of("boss-a")
    assert progress.status == "engaged"
    assert (progress.hp, progress.phase) == (640, 2)
    assert progress.buffs == ()
    assert progress.summons == ()


def test_recover_requires_recovering_state():
    ledger = make()
    ledger.enter_combat("boss-a", hp_max=1000)
    with pytest.raises(wrl.RecoveryError) as exc:
        ledger.recover("boss-a")
    assert exc.value.code == "RECOVERY_NOT_RECOVERING"


def test_exhausted_attempts_eject_the_raid():
    ledger = make(attempts_per_lockout=1)
    ledger.enter_combat("boss-a", hp_max=1000)
    progress = ledger.wipe("boss-a")
    assert progress.status == "ejected"
    assert progress.attempts_left == 0
    with pytest.raises(wrl.RecoveryError) as exc:
        ledger.recover("boss-a")
    assert exc.value.code == "RECOVERY_EJECTED"


def test_enter_after_eject_needs_instance_reset():
    ledger = make(attempts_per_lockout=1)
    ledger.enter_combat("boss-a", hp_max=1000)
    ledger.wipe("boss-a")
    with pytest.raises(wrl.RecoveryError) as exc:
        ledger.enter_combat("boss-a")
    assert exc.value.code == "RECOVERY_EJECTED"
    result = ledger.reset_instance()
    assert result["bosses"] == 1
    assert result["wipes_cleared"] == 1
    progress = ledger.enter_combat("boss-a", hp_max=1000)
    assert progress.status == "engaged"
    assert progress.attempts_left == 1
    assert progress.consecutive_wipes == 0


def test_mark_clear_finishes_the_encounter():
    ledger = make()
    ledger.enter_combat("boss-a", hp_max=1000)
    progress = ledger.mark_clear("boss-a")
    assert progress.status == "cleared"
    assert ledger.attempts_left("boss-a") == 0
    assert ledger.progress_of("boss-a").status == "cleared"
    assert ledger.stats()["clears"] == 1


def test_unknown_boss_operations_raise():
    ledger = make()
    calls = (
        lambda: ledger.progress_of("ghost"),
        lambda: ledger.attempts_left("ghost"),
        lambda: ledger.wipe("ghost"),
        lambda: ledger.recover("ghost"),
    )
    for call in calls:
        with pytest.raises(wrl.RecoveryError) as exc:
            call()
        assert exc.value.code == "RECOVERY_BOSS_UNKNOWN"


def test_concurrent_wipe_reports_count_once():
    ledger = make()
    ledger.enter_combat("boss-a", hp_max=1000)
    received = []
    errors = []
    barrier = threading.Barrier(10)

    def worker():
        try:
            barrier.wait(timeout=5)
            received.append(ledger.wipe("boss-a").consecutive_wipes)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(getattr(exc, "code", repr(exc)))

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert received == [1] * 10
    progress = ledger.progress_of("boss-a")
    assert progress.consecutive_wipes == 1
    assert progress.attempts_left == 2
    assert ledger.stats()["wipes"] == 1


def test_snapshot_is_detached_from_live_state():
    ledger = make()
    ledger.enter_combat("boss-a", hp_max=1000)
    ledger.wipe("boss-a")
    state = ledger.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "bosses", "counters"}
    state["bosses"].clear()
    state["counters"]["wipes"] = 99
    assert ledger.progress_of("boss-a").consecutive_wipes == 1
    assert ledger.stats()["wipes"] == 1
    assert len(pristine["bosses"]) == 1


def test_restore_roundtrip_preserves_encounter_state():
    ledger = make()
    ledger.enter_combat("boss-a", hp_max=1500)
    ledger.advance_phase("boss-a", phase=3, hp=900)
    ledger.wipe("boss-a")
    ledger.recover("boss-a")
    state = ledger.snapshot()
    clone = make()
    clone.restore(state)
    assert clone.stats() == ledger.stats()
    progress = clone.progress_of("boss-a")
    assert progress.status == "engaged"
    assert (progress.hp, progress.phase) == (900, 3)
    assert (progress.checkpoint_hp, progress.checkpoint_phase) == (900, 3)
    assert progress.attempts_left == 2


def test_restore_rejects_malformed_state_without_touching_live_data():
    ledger = make()
    ledger.enter_combat("boss-a", hp_max=1000)
    bad_states = [
        None,
        {},
        {"version": 2, "bosses": {}, "counters": {}},
        {"version": 1, "bosses": [], "counters": {}},
        {"version": 1, "bosses": {}, "counters": []},
        {"version": 1, "bosses": {}, "counters": {"wipes": 0}},
    ]
    for bad in bad_states:
        with pytest.raises(wrl.RecoveryError) as exc:
            ledger.restore(bad)
        assert exc.value.code == "RECOVERY_SNAPSHOT_INVALID"
    assert ledger.progress_of("boss-a").status == "engaged"
    assert ledger.stats()["bosses"] == 1


def test_stats_track_encounter_counters():
    ledger = make()
    ledger.enter_combat("boss-a", hp_max=1000)
    ledger.wipe("boss-a")
    ledger.recover("boss-a")
    assert ledger.stats() == {"bosses": 1, "engaged": 1, "recovering": 0,
                              "cleared": 0, "ejected": 0, "wipes": 1,
                              "recovers": 1, "clears": 0, "resets": 0}
