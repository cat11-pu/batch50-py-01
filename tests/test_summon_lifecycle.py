import copy
import threading

import pytest

import summon_lifecycle as sl

NOW = "2026-11-20T10:00:00+00:00"
LATER = "2026-11-20T10:05:00+00:00"


def ledger(**kwargs):
    return sl.SummonLifecycle(**kwargs)


def test_summon_defaults_and_sequence():
    life = ledger()
    first = life.summon("necro", "skeleton", now=NOW)
    assert first["summon_id"] == "s0001"
    assert first["seq"] == 1
    assert first["owner"] == "necro"
    assert first["kind"] == "skeleton"
    assert first["remaining"] == 60
    assert first["inherit"] == 1.0
    assert first["created_at"] == NOW
    second = life.summon("necro", "wraith", ttl=30, inherit=0.5, now=NOW)
    assert second["summon_id"] == "s0002"
    assert second["seq"] == 2
    assert second["remaining"] == 30
    assert second["inherit"] == 0.5
    assert life.stats() == {"summoned": 2, "dismissed": 0, "expired": 0,
                            "transferred": 0, "reaped": 0, "evicted": 0,
                            "refused": 0}


def test_summon_rejects_invalid_parameters():
    life = ledger()
    bad_calls = [
        dict(owner="", kind="skeleton"),
        dict(owner="   ", kind="skeleton"),
        dict(owner="necro", kind=""),
        dict(owner="necro", kind="skeleton", ttl=0),
        dict(owner="necro", kind="skeleton", ttl=-3),
        dict(owner="necro", kind="skeleton", inherit=0),
        dict(owner="necro", kind="skeleton", inherit=1.5),
    ]
    for kwargs in bad_calls:
        with pytest.raises(sl.SummonError) as exc:
            life.summon(now=NOW, **kwargs)
        assert exc.value.code == "SUMMON_INVALID_REQUEST"
    assert life.stats()["summoned"] == 0
    assert life.list_of("necro") == []


def test_cooldown_is_per_kind_and_advances_with_tick():
    life = ledger(default_cooldown=10)
    life.summon("necro", "skeleton", now=NOW)
    with pytest.raises(sl.SummonError) as exc:
        life.summon("necro", "skeleton", now=NOW)
    assert exc.value.code == "SUMMON_COOLDOWN_ACTIVE"
    life.summon("necro", "wraith", now=NOW)
    assert life.cooldown_of("necro", "skeleton") == 10
    assert life.cooldown_of("necro", "wraith") == 10
    life.tick(4)
    assert life.cooldown_of("necro", "skeleton") == 6
    life.tick(6)
    assert life.cooldown_of("necro", "skeleton") == 0
    again = life.summon("necro", "skeleton", now=LATER)
    assert again["seq"] == 3
    assert again["summon_id"] == "s0003"


def test_owner_cap_evicts_least_remaining_summon():
    life = ledger(per_owner_cap=3, default_cooldown=0)
    life.summon("necro", "a", ttl=30, now=NOW)
    shortest = life.summon("necro", "b", ttl=10, now=NOW)
    life.summon("necro", "c", ttl=20, now=NOW)
    life.summon("necro", "d", ttl=40, now=NOW)
    rows = life.list_of("necro")
    assert [row["summon_id"] for row in rows] == ["s0001", "s0003", "s0004"]
    assert [row["remaining"] for row in rows] == [30, 20, 40]
    assert life.stats()["summoned"] == 4
    assert life.stats()["evicted"] == 1
    with pytest.raises(sl.SummonError) as exc:
        life.remaining_of(shortest["summon_id"])
    assert exc.value.code == "SUMMON_UNKNOWN_SUMMON"


def test_dismiss_removes_only_own_summon():
    life = ledger(default_cooldown=0)
    first = life.summon("necro", "skeleton", now=NOW)
    second = life.summon("necro", "wraith", now=NOW)
    assert life.dismiss("necro", first["summon_id"]) is True
    assert [row["summon_id"] for row in life.list_of("necro")] == ["s0002"]
    assert life.stats()["dismissed"] == 1
    with pytest.raises(sl.SummonError) as exc:
        life.dismiss("necro", first["summon_id"])
    assert exc.value.code == "SUMMON_UNKNOWN_SUMMON"
    with pytest.raises(sl.SummonError) as exc:
        life.dismiss("lich", second["summon_id"])
    assert exc.value.code == "SUMMON_OWNER_MISMATCH"
    assert [row["summon_id"] for row in life.list_of("necro")] == ["s0002"]


def test_tick_expires_summon_and_reports_sorted_ids():
    life = ledger(default_cooldown=0)
    life.summon("necro", "a", ttl=5, now=NOW)
    life.summon("necro", "b", ttl=9, now=NOW)
    assert life.tick(4) == []
    assert life.remaining_of("s0001") == 1
    assert life.tick(2) == ["s0001"]
    assert [row["summon_id"] for row in life.list_of("necro")] == ["s0002"]
    assert life.remaining_of("s0002") == 3
    assert life.stats()["expired"] == 1
    for bad in (0, -1):
        with pytest.raises(sl.SummonError) as exc:
            life.tick(bad)
        assert exc.value.code == "SUMMON_INVALID_REQUEST"


def test_transfer_owner_preserves_remaining_and_sequence():
    life = ledger(default_cooldown=0)
    record = life.summon("necro", "skeleton", ttl=25, now=NOW)
    life.tick(5)
    moved = life.transfer_owner(record["summon_id"], "lich")
    assert moved["owner"] == "lich"
    assert moved["remaining"] == 20
    assert moved["seq"] == 1
    assert moved["summon_id"] == "s0001"
    assert life.list_of("necro") == []
    assert [row["summon_id"] for row in life.list_of("lich")] == ["s0001"]
    assert life.stats()["transferred"] == 1
    with pytest.raises(sl.SummonError) as exc:
        life.transfer_owner("s9999", "lich")
    assert exc.value.code == "SUMMON_UNKNOWN_SUMMON"
    with pytest.raises(sl.SummonError) as exc:
        life.transfer_owner("s0001", "   ")
    assert exc.value.code == "SUMMON_INVALID_REQUEST"


def test_transfer_into_full_owner_evicts_their_weakest():
    life = ledger(per_owner_cap=2, default_cooldown=0)
    incoming = life.summon("necro", "skeleton", ttl=50, now=NOW)
    life.summon("lich", "a", ttl=40, now=NOW)
    life.summon("lich", "b", ttl=15, now=NOW)
    life.transfer_owner(incoming["summon_id"], "lich")
    rows = life.list_of("lich")
    assert [row["summon_id"] for row in rows] == ["s0002", "s0001"]
    assert [row["remaining"] for row in rows] == [40, 50]
    assert life.stats()["evicted"] == 1
    assert life.stats()["transferred"] == 1


def test_list_of_is_owner_scoped_and_sequence_ordered():
    life = ledger(default_cooldown=0)
    life.summon("necro", "a", ttl=10, now=NOW)
    life.summon("lich", "b", ttl=20, now=NOW)
    life.summon("necro", "c", ttl=30, now=NOW)
    rows = life.list_of("necro")
    assert [row["kind"] for row in rows] == ["a", "c"]
    assert [row["seq"] for row in rows] == [1, 3]
    assert life.remaining_of("s0003") == 30
    assert life.list_of("ghost") == []
    with pytest.raises(sl.SummonError) as exc:
        life.remaining_of("s0404")
    assert exc.value.code == "SUMMON_UNKNOWN_SUMMON"


def test_offline_before_grace_keeps_summons_and_first_timestamp():
    life = ledger(offline_grace=30)
    life.summon("necro", "a", now=NOW)
    assert life.owner_offline("necro", now=NOW) == {"owner": "necro", "offline_at": NOW}
    repeated = life.owner_offline("necro", now="2026-11-20T10:01:00+00:00")
    assert repeated["offline_at"] == NOW
    assert life.reap_owner("necro", now="2026-11-20T10:00:29+00:00") == 0
    assert [row["kind"] for row in life.list_of("necro")] == ["a"]


def test_reap_after_grace_dissipates_all_summons():
    life = ledger(offline_grace=30, default_cooldown=0)
    life.summon("necro", "a", now=NOW)
    life.summon("necro", "b", now=NOW)
    life.owner_offline("necro", now=NOW)
    assert life.reap_owner("necro", now="2026-11-20T10:00:31+00:00") == 2
    assert life.list_of("necro") == []
    assert life.stats()["reaped"] == 2
    assert life.reap_owner("necro", now="2026-11-20T10:00:45+00:00") == 0


def test_owner_online_clears_offline_marker():
    life = ledger(offline_grace=30)
    life.summon("necro", "a", now=NOW)
    life.owner_offline("necro", now=NOW)
    life.owner_online("necro", now=LATER)
    assert life.reap_owner("necro", now="2026-11-20T11:00:00+00:00") == 0
    assert len(life.list_of("necro")) == 1
    life.owner_offline("necro", now="2026-11-20T11:00:00+00:00")
    assert life.reap_owner("necro", now="2026-11-20T11:00:31+00:00") == 1
    assert life.stats()["reaped"] == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    life = ledger(per_owner_cap=2, offline_grace=30, default_cooldown=10)
    life.summon("necro", "skeleton", ttl=40, now=NOW)
    life.summon("necro", "wraith", ttl=20, now=NOW)
    life.tick(5)
    life.owner_offline("lich", now=NOW)
    state = life.snapshot()
    assert set(state) == {"version", "seq", "summons", "owners", "cooldowns", "stats"}
    pristine = copy.deepcopy(state)
    state["summons"].clear()
    state["stats"]["summoned"] = 99
    assert len(life.list_of("necro")) == 2
    assert life.stats()["summoned"] == 2

    clone = ledger(per_owner_cap=2, offline_grace=30, default_cooldown=10)
    clone.restore(pristine)
    assert clone.stats()["summoned"] == 2
    rows = clone.list_of("necro")
    assert [(row["kind"], row["remaining"]) for row in rows] == [
        ("skeleton", 35), ("wraith", 15)]
    assert clone.cooldown_of("necro", "skeleton") == 5
    again = clone.owner_offline("lich", now=LATER)
    assert again["offline_at"] == NOW


def test_restore_rejects_malformed_state_without_touching_live_data():
    life = ledger()
    life.summon("necro", "skeleton", now=NOW)
    good = life.snapshot()
    bad_states = [
        None,
        {},
        {**good, "version": 2},
        {key: value for key, value in good.items() if key != "owners"},
        {**good, "summons": {"s0001": {}}},
        {**good, "owners": []},
        {**good, "cooldowns": []},
        {**good, "stats": {"summoned": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(sl.SummonError) as exc:
            life.restore(bad)
        assert exc.value.code == "SUMMON_SNAPSHOT_INVALID"
    assert life.stats()["summoned"] == 1
    assert [row["summon_id"] for row in life.list_of("necro")] == ["s0001"]


def test_concurrent_summons_respect_cap_and_sequence():
    life = ledger(per_owner_cap=5, default_cooldown=0)
    kinds = [f"kind-{index:02d}" for index in range(12)]
    errors = []
    barrier = threading.Barrier(len(kinds))

    def worker(kind, ttl):
        try:
            barrier.wait(timeout=5)
            life.summon("necro", kind, ttl=ttl, now=NOW)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(kind, 50 + index))
               for index, kind in enumerate(kinds)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    rows = life.list_of("necro")
    assert len(rows) == 5
    assert life.stats()["summoned"] == 12
    assert life.stats()["evicted"] == 7
    assert len({row["seq"] for row in rows}) == 5
