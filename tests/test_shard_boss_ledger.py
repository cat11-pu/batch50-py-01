import copy
import threading

import pytest

import shard_boss_ledger as sb


def ledger(**kwargs):
    params = dict(max_hp=1000, phase2_at=0.5)
    params.update(kwargs)
    return sb.ShardBossLedger(**params)


def test_register_shard_and_initial_ledger():
    led = ledger()
    report = led.register_shard("s1")
    assert report == {"shard_id": "s1", "segments": 0, "damage": 0, "max_seq": 0}
    assert led.shard_report("s1") == report
    assert led.boss_state() == {"hp": 1000, "max_hp": 1000, "phase": "phase-1",
                                "status": "active", "killer": None,
                                "segments": 0, "damage": 0}
    assert led.frozen_shards() == []
    assert led.stats() == {"registered": 1, "segments": 0, "duplicates": 0,
                           "damage": 0, "overkill": 0, "freezes": 0, "merged": 0}
    for bad in ("", "   "):
        with pytest.raises(sb.ShardError) as exc:
            led.register_shard(bad)
        assert exc.value.code == "SHARD_INVALID_REQUEST"
    with pytest.raises(sb.ShardError) as exc:
        led.register_shard("s1")
    assert exc.value.code == "SHARD_INVALID_REQUEST"
    with pytest.raises(sb.ShardError) as exc:
        led.shard_report("ghost")
    assert exc.value.code == "SHARD_UNKNOWN_SHARD"


def test_apply_damage_reduces_shared_hp():
    led = ledger()
    led.register_shard("s1")
    result = led.apply_damage("s1", 1, 300, actor="mage")
    assert result == {"shard_id": "s1", "segment_seq": 1, "accepted": True,
                      "damage": 300, "hp": 700, "phase": "phase-1",
                      "status": "active"}
    assert led.stats()["segments"] == 1
    assert led.stats()["damage"] == 300
    assert led.shard_report("s1") == {"shard_id": "s1", "segments": 1,
                                      "damage": 300, "max_seq": 1}


def test_duplicate_segment_is_rejected_per_shard():
    led = ledger()
    led.register_shard("s1")
    led.register_shard("s2")
    led.apply_damage("s1", 1, 100)
    led.apply_damage("s2", 1, 200)
    with pytest.raises(sb.ShardError) as exc:
        led.apply_damage("s1", 1, 50)
    assert exc.value.code == "SHARD_DUPLICATE_SEGMENT"
    assert led.boss_state()["hp"] == 700
    assert led.stats()["segments"] == 2
    assert led.stats()["duplicates"] == 1
    assert led.stats()["damage"] == 300


def test_apply_damage_validates_segment_and_amount():
    led = ledger()
    led.register_shard("s1")
    for bad_seq in (0, -2, "3"):
        with pytest.raises(sb.ShardError) as exc:
            led.apply_damage("s1", bad_seq, 10)
        assert exc.value.code == "SHARD_INVALID_REQUEST"
    for bad_damage in (0, -10, "5"):
        with pytest.raises(sb.ShardError) as exc:
            led.apply_damage("s1", 1, bad_damage)
        assert exc.value.code == "SHARD_INVALID_REQUEST"
    with pytest.raises(sb.ShardError) as exc:
        led.apply_damage("ghost", 1, 10)
    assert exc.value.code == "SHARD_UNKNOWN_SHARD"
    assert led.boss_state()["hp"] == 1000
    assert led.stats()["segments"] == 0


def test_lethal_segment_freezes_every_shard_and_records_killer():
    led = ledger()
    led.register_shard("s1")
    led.register_shard("s2")
    led.apply_damage("s1", 1, 600, actor="tank")
    final = led.apply_damage("s1", 2, 500, actor="tank")
    assert final["hp"] == 0
    assert final["phase"] == "settlement"
    assert final["status"] == "settlement"
    state = led.boss_state()
    assert state["hp"] == 0
    assert state["killer"] == "tank"
    assert state["damage"] == 1100
    assert state["segments"] == 2
    assert led.stats()["overkill"] == 100
    assert led.stats()["freezes"] == 1
    assert led.frozen_shards() == ["s1", "s2"]


def test_phase_changes_at_half_hp():
    led = ledger()
    led.register_shard("s1")
    assert led.apply_damage("s1", 1, 499)["phase"] == "phase-1"
    middle = led.apply_damage("s1", 2, 1)
    assert middle["hp"] == 500
    assert middle["phase"] == "phase-2"
    assert middle["status"] == "active"
    assert led.apply_damage("s1", 3, 400)["phase"] == "phase-2"


def test_out_of_order_segments_still_aggregate():
    led = ledger(max_hp=100000)
    led.register_shard("a")
    led.register_shard("b")
    led.apply_damage("a", 5, 100)
    led.apply_damage("a", 3, 200)
    led.apply_damage("b", 4, 300)
    assert led.boss_state()["hp"] == 99400
    assert led.boss_state()["segments"] == 3
    assert led.boss_state()["damage"] == 600
    assert led.shard_report("a") == {"shard_id": "a", "segments": 2,
                                     "damage": 300, "max_seq": 5}
    assert led.shard_report("b") == {"shard_id": "b", "segments": 1,
                                     "damage": 300, "max_seq": 4}


def test_manual_freeze_enters_settlement_without_killer():
    led = ledger()
    led.register_shard("s1")
    led.register_shard("s2")
    out = led.freeze("maintenance")
    assert out == {"status": "settlement", "phase": "settlement",
                   "frozen_shards": ["s1", "s2"]}
    state = led.boss_state()
    assert state["status"] == "settlement"
    assert state["phase"] == "settlement"
    assert state["hp"] == 1000
    assert state["killer"] is None
    assert led.stats()["freezes"] == 1


def test_repeated_freeze_is_idempotent():
    led = ledger()
    led.register_shard("s1")
    first = led.freeze()
    second = led.freeze()
    assert first == second
    assert led.stats()["freezes"] == 1


def test_merge_shards_moves_segments_without_reapplying_damage():
    led = ledger()
    led.register_shard("a")
    led.register_shard("b")
    led.apply_damage("a", 1, 100)
    led.apply_damage("a", 2, 200)
    led.apply_damage("b", 3, 150)
    out = led.merge_shards("a", "b")
    assert out == {"source": "a", "target": "b", "moved": 2, "skipped": 0}
    assert led.shard_report("b") == {"shard_id": "b", "segments": 3,
                                     "damage": 450, "max_seq": 3}
    assert led.boss_state()["hp"] == 550
    assert led.boss_state()["damage"] == 450
    assert led.boss_state()["segments"] == 3
    with pytest.raises(sb.ShardError) as exc:
        led.shard_report("a")
    assert exc.value.code == "SHARD_UNKNOWN_SHARD"
    assert led.stats()["merged"] == 1


def test_merge_rejects_invalid_and_frozen_ledger():
    led = ledger()
    led.register_shard("a")
    led.register_shard("b")
    with pytest.raises(sb.ShardError) as exc:
        led.merge_shards("a", "a")
    assert exc.value.code == "SHARD_INVALID_REQUEST"
    with pytest.raises(sb.ShardError) as exc:
        led.merge_shards("ghost", "a")
    assert exc.value.code == "SHARD_UNKNOWN_SHARD"
    led.freeze()
    with pytest.raises(sb.ShardError) as exc:
        led.merge_shards("a", "b")
    assert exc.value.code == "SHARD_BOSS_FROZEN"
    assert led.stats()["merged"] == 0


def test_reports_and_boss_totals_stay_consistent():
    led = ledger(max_hp=5000)
    for shard_id in ("alpha", "beta", "gamma"):
        led.register_shard(shard_id)
    led.apply_damage("alpha", 2, 111)
    led.apply_damage("alpha", 10, 222)
    led.apply_damage("beta", 1, 333)
    led.apply_damage("gamma", 4, 444)
    assert led.boss_state() == {"hp": 3890, "max_hp": 5000, "phase": "phase-1",
                                "status": "active", "killer": None,
                                "segments": 4, "damage": 1110}
    assert led.shard_report("alpha") == {"shard_id": "alpha", "segments": 2,
                                         "damage": 333, "max_seq": 10}
    assert led.shard_report("beta") == {"shard_id": "beta", "segments": 1,
                                        "damage": 333, "max_seq": 1}
    assert led.shard_report("gamma") == {"shard_id": "gamma", "segments": 1,
                                         "damage": 444, "max_seq": 4}


def test_snapshot_is_detached_and_restore_roundtrips():
    led = ledger()
    led.register_shard("s1")
    led.register_shard("s2")
    led.apply_damage("s1", 1, 300, actor="mage")
    led.apply_damage("s2", 2, 200, actor="rogue")
    state = led.snapshot()
    assert set(state) == {"version", "boss", "shards", "frozen", "stats"}
    pristine = copy.deepcopy(state)
    state["boss"]["hp"] = 1
    state["shards"].clear()
    state["stats"]["segments"] = 99
    assert led.boss_state()["hp"] == 500
    assert led.shard_report("s1")["damage"] == 300

    clone = ledger()
    clone.restore(pristine)
    assert clone.boss_state()["hp"] == 500
    assert clone.boss_state()["phase"] == "phase-2"
    assert clone.boss_state()["segments"] == 2
    assert clone.shard_report("s1") == {"shard_id": "s1", "segments": 1,
                                        "damage": 300, "max_seq": 1}
    assert clone.stats()["segments"] == 2
    final = clone.apply_damage("s1", 3, 600, actor="mage")
    assert final["hp"] == 0
    assert final["status"] == "settlement"
    assert clone.boss_state()["killer"] == "mage"


def test_restore_rejects_malformed_state_without_touching_live_data():
    led = ledger()
    led.register_shard("s1")
    led.apply_damage("s1", 1, 300)
    good = led.snapshot()
    bad_states = [
        None,
        {},
        {**good, "version": 2},
        {key: value for key, value in good.items() if key != "frozen"},
        {**good, "boss": []},
        {**good, "shards": []},
        {**good, "frozen": {}},
        {**good, "stats": {"registered": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(sb.ShardError) as exc:
            led.restore(bad)
        assert exc.value.code == "SHARD_SNAPSHOT_INVALID"
    assert led.boss_state()["hp"] == 700
    assert led.stats()["segments"] == 1
    assert led.shard_report("s1")["damage"] == 300


def test_concurrent_segments_apply_once():
    led = ledger(max_hp=100000)
    led.register_shard("s1")
    errors = []
    barrier = threading.Barrier(12)

    def worker(seq):
        try:
            barrier.wait(timeout=5)
            led.apply_damage("s1", seq, 100)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index + 1,))
               for index in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert led.boss_state()["hp"] == 98800
    assert led.stats()["segments"] == 12
    assert led.stats()["damage"] == 1200

    duplicate_errors = []
    barrier = threading.Barrier(12)

    def duplicate_worker():
        try:
            barrier.wait(timeout=5)
            led.apply_damage("s1", 99, 100)
        except sb.ShardError as exc:
            duplicate_errors.append(exc.code)

    threads = [threading.Thread(target=duplicate_worker) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert duplicate_errors.count("SHARD_DUPLICATE_SEGMENT") == 11
    assert led.boss_state()["hp"] == 98700
    assert led.stats()["duplicates"] == 11
    assert led.stats()["segments"] == 13
