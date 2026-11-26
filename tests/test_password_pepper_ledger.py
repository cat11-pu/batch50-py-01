import copy
import threading

import pytest

import password_pepper_ledger as pl

NOW = "2026-11-26T09:00:00+00:00"
SOON = "2026-11-26T09:10:00+00:00"
LATER = "2026-11-26T09:20:00+00:00"


def ledger(**kwargs):
    kwargs.setdefault("iterations", 1000)
    return pl.PasswordPepperLedger(**kwargs)


def ready(**kwargs):
    b = ledger(**kwargs)
    b.register_version(1, pepper="pepper-one", now=NOW)
    return b


def test_register_version_is_monotonic():
    b = ledger()
    assert b.register_version(1, pepper="pepper-one", now=NOW) == 1
    assert b.register_version(2, pepper="pepper-two", now=SOON) == 2
    assert b.current_version() == 2
    assert b.version_enabled(1) is True
    assert b.version_enabled(2) is True
    assert b.version_enabled(3) is False
    with pytest.raises(pl.PepperError) as exc:
        b.register_version(2, pepper="again", now=SOON)
    assert exc.value.code == "PEPPER_VERSION_REGRESSION"
    with pytest.raises(pl.PepperError) as exc:
        b.register_version(0, pepper="zero", now=SOON)
    assert exc.value.code == "PEPPER_INVALID_REQUEST"
    with pytest.raises(pl.PepperError) as exc:
        b.register_version(3, pepper="   ", now=SOON)
    assert exc.value.code == "PEPPER_INVALID_REQUEST"
    assert b.stats()["versions"] == 2


def test_hash_record_stores_current_version_metadata():
    b = ready()
    record = b.hash_record("alice", "correct-horse", now=NOW)
    assert record.account_id == "alice"
    assert record.version == 1
    assert record.algorithm == "pbkdf2_sha256"
    assert record.iterations == 1000
    assert len(record.salt_hex) >= 16
    assert len(record.digest_hex) >= 32
    assert record.updated_at == NOW
    assert b.record_for("alice") == record
    assert [row.account_id for row in b.records()] == ["alice"]
    assert b.record_for("nobody") is None
    assert b.stats()["hashed"] == 1


def test_hash_record_rejects_bad_input_and_disabled_version():
    b = ready()
    with pytest.raises(pl.PepperError) as exc:
        b.hash_record("", "pw", now=NOW)
    assert exc.value.code == "PEPPER_INVALID_REQUEST"
    with pytest.raises(pl.PepperError) as exc:
        b.hash_record("alice", "", now=NOW)
    assert exc.value.code == "PEPPER_INVALID_REQUEST"

    empty = ledger()
    with pytest.raises(pl.PepperError) as exc:
        empty.hash_record("alice", "pw", now=NOW)
    assert exc.value.code == "PEPPER_NO_VERSION"

    c = ready()
    c.disable_version(1, now=SOON)
    with pytest.raises(pl.PepperError) as exc:
        c.hash_record("alice", "pw", now=SOON)
    assert exc.value.code == "PEPPER_VERSION_DISABLED"


def test_verify_accepts_current_version_and_rejects_wrong_password():
    b = ready()
    b.hash_record("alice", "correct-horse", now=NOW)
    accepted = b.verify("alice", "correct-horse", now=SOON)
    assert accepted.account_id == "alice"
    assert accepted.status == "ok"
    assert accepted.version == 1
    assert accepted.rehash_queued is False
    rejected = b.verify("alice", "wrong-horse", now=SOON)
    assert rejected.status == "invalid"
    assert rejected.version == 1
    assert rejected.rehash_queued is False
    assert b.stats()["verified"] == 1
    assert b.stats()["invalid"] == 1


def test_verify_unknown_account_and_outside_window():
    b = ready()
    missing = b.verify("nobody", "whatever", now=SOON)
    assert missing.status == "unknown"
    assert missing.version is None
    assert b.stats()["unknown"] == 1

    b.hash_record("alice", "pw-one", now=NOW)
    b.register_version(2, pepper="pepper-two", now=SOON)
    b.register_version(3, pepper="pepper-three", now=SOON)
    result = b.verify("alice", "pw-one", now=SOON)
    assert result.status == "reset_required"
    assert result.version == 1
    assert b.stats()["reset_required"] == 1


def test_verify_on_previous_version_queues_single_rehash():
    b = ready()
    b.hash_record("alice", "pw-one", now=NOW)
    b.register_version(2, pepper="pepper-two", now=SOON)
    first = b.verify("alice", "pw-one", now=SOON)
    assert first.status == "ok"
    assert first.version == 1
    assert first.rehash_queued is True
    assert b.pending_count() == 1
    second = b.verify("alice", "pw-one", now=SOON)
    assert second.status == "ok"
    assert second.rehash_queued is False
    assert b.pending_count() == 1
    assert b.stats()["rehash_queued"] == 1
    assert b.record_for("alice").version == 1


def test_rehash_pending_upgrades_and_is_idempotent():
    b = ready()
    b.hash_record("alice", "pw-one", now=NOW)
    b.register_version(2, pepper="pepper-two", now=SOON)
    b.verify("alice", "pw-one", now=SOON)
    assert b.rehash_pending(now=LATER) == 1
    assert b.pending_count() == 0
    record = b.record_for("alice")
    assert record.version == 2
    assert record.updated_at == LATER
    assert b.rehash_pending(now=LATER) == 0
    assert b.stats()["rehashed"] == 1
    again = b.verify("alice", "pw-one", now=LATER)
    assert again.status == "ok"
    assert again.rehash_queued is False


def test_rehash_pending_respects_limit_and_queue_cap():
    b = ledger(max_pending=2)
    b.register_version(1, pepper="pepper-one", now=NOW)
    for name in ("a", "b", "c"):
        b.hash_record(name, f"pw-{name}", now=NOW)
    b.register_version(2, pepper="pepper-two", now=SOON)
    for name in ("a", "b", "c"):
        assert b.verify(name, f"pw-{name}", now=SOON).status == "ok"
    assert b.pending_count() == 2
    assert b.stats()["rehash_deferred"] == 1
    assert b.rehash_pending(limit=1, now=LATER) == 1
    assert b.pending_count() == 1
    assert b.rehash_pending(now=LATER) == 1
    assert b.record_for("c").version == 1
    assert b.record_for("a").version == 2
    assert b.record_for("b").version == 2


def test_disable_version_counts_records_and_blocks_new_hashes():
    b = ready()
    b.hash_record("alice", "pw-a", now=NOW)
    b.hash_record("bob", "pw-b", now=NOW)
    b.register_version(2, pepper="pepper-two", now=SOON)
    assert b.disable_version(1, now=SOON) == 2
    assert b.version_enabled(1) is False
    assert b.current_version() == 2
    fresh = b.hash_record("carol", "pw-c", now=SOON)
    assert fresh.version == 2
    assert b.disable_version(1, now=SOON) == 0
    with pytest.raises(pl.PepperError) as exc:
        b.disable_version(7, now=SOON)
    assert exc.value.code == "PEPPER_UNKNOWN_VERSION"
    assert b.stats()["disabled_versions"] == 1


def test_rehash_pending_ignores_records_already_current():
    b = ready()
    b.hash_record("alice", "pw-one", now=NOW)
    b.register_version(2, pepper="pepper-two", now=SOON)
    b.verify("alice", "pw-one", now=SOON)
    b.hash_record("alice", "pw-one", now=SOON)
    assert b.record_for("alice").version == 2
    assert b.rehash_pending(now=LATER) == 0
    assert b.pending_count() == 0
    assert b.stats()["rehashed"] == 0


def test_concurrent_rehash_handles_each_account_once():
    b = ledger(max_pending=16)
    b.register_version(1, pepper="pepper-one", now=NOW)
    names = [f"user-{index}" for index in range(4)]
    for name in names:
        b.hash_record(name, f"pw-{name}", now=NOW)
    b.register_version(2, pepper="pepper-two", now=SOON)
    for name in names:
        assert b.verify(name, f"pw-{name}", now=SOON).rehash_queued is True
    assert b.pending_count() == 4

    totals = []
    failures = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            totals.append(b.rehash_pending(now=LATER))
        except Exception as exc:  # noqa: BLE001 - reported through failures
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert sum(totals) == 4
    assert b.pending_count() == 0
    assert sorted(row.account_id for row in b.records()) == names
    assert {row.version for row in b.records()} == {2}
    assert b.stats()["rehashed"] == 4


def test_snapshot_roundtrip_restores_queue_and_peppers():
    b = ready()
    b.hash_record("alice", "pw-one", now=NOW)
    b.register_version(2, pepper="pepper-two", now=SOON)
    b.verify("alice", "pw-one", now=SOON)
    state = b.snapshot()
    assert set(state) == {"version", "versions", "records", "pending",
                          "force_reset", "stats"}
    pristine = copy.deepcopy(state)
    state["records"].clear()
    state["pending"].clear()
    state["stats"]["hashed"] = 99
    assert b.stats()["hashed"] == 1
    assert b.pending_count() == 1

    clone = ledger()
    clone.restore(pristine)
    assert clone.current_version() == 2
    assert clone.pending_count() == 1
    assert clone.record_for("alice").version == 1
    assert clone.rehash_pending(now=LATER) == 1
    assert clone.record_for("alice").version == 2
    assert clone.verify("alice", "pw-one", now=LATER).status == "ok"
    assert clone.stats()["hashed"] == 1


def test_restore_rejects_malformed_snapshot():
    b = ready()
    b.hash_record("alice", "pw-one", now=NOW)
    bad_snapshots = [
        None,
        {},
        {"version": 4, "versions": [], "records": [], "pending": [],
         "force_reset": [], "stats": {}},
        {"version": 1, "versions": {}, "records": [], "pending": [],
         "force_reset": [], "stats": {}},
        {"version": 1, "versions": [], "records": "no", "pending": [],
         "force_reset": [], "stats": {}},
        {"version": 1, "versions": [], "records": [], "pending": [],
         "force_reset": [], "stats": []},
    ]
    for snapshot in bad_snapshots:
        with pytest.raises(pl.PepperError) as exc:
            b.restore(snapshot)
        assert exc.value.code == "PEPPER_SNAPSHOT_INVALID"
    assert b.record_for("alice").version == 1
    assert b.stats()["hashed"] == 1


def test_stats_track_each_operation():
    b = ready()
    b.hash_record("alice", "pw-a", now=NOW)
    b.hash_record("bob", "pw-b", now=NOW)
    b.register_version(2, pepper="pepper-two", now=SOON)
    b.verify("alice", "pw-a", now=SOON)
    b.verify("bob", "wrong", now=SOON)
    b.verify("carol", "whatever", now=SOON)
    assert b.rehash_pending(now=LATER) == 1
    stats = b.stats()
    assert stats["versions"] == 2
    assert stats["hashed"] == 2
    assert stats["verified"] == 1
    assert stats["invalid"] == 1
    assert stats["unknown"] == 1
    assert stats["reset_required"] == 0
    assert stats["rehash_queued"] == 1
    assert stats["rehashed"] == 1


def test_hash_record_uses_random_salt_per_record():
    b = ready()
    first = b.hash_record("alice", "same-password", now=NOW)
    second = b.hash_record("bob", "same-password", now=NOW)
    assert first.salt_hex != second.salt_hex
    assert first.digest_hex != second.digest_hex
    assert b.verify("alice", "same-password", now=SOON).status == "ok"
    assert b.verify("bob", "same-password", now=SOON).status == "ok"
    assert b.stats()["verified"] == 2
