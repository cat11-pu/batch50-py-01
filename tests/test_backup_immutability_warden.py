import pytest

import backup_immutability_warden as bw

T0 = "2026-11-26T00:00:00+00:00"
CANARY = "/srv/backup/canary.txt"
DIGEST = "sha256:9f2c" + "0" * 60


def warden(**kwargs):
    return bw.BackupImmutabilityWarden(**kwargs)


def locked(w=None, name="rp-1126", *, size_gb=10, days=30, now=T0):
    engine = w or warden()
    engine.lock(name, size_gb=size_gb, min_retention_days=days, now=now)
    return engine


def test_lock_creates_immutable_record_with_expiry():
    w = locked()
    rec = w.locks()[0]
    assert isinstance(rec, bw.LockRecord)
    assert rec.restore_point == "rp-1126"
    assert rec.status == "locked"
    assert rec.locked_at == T0
    assert rec.expires_at == "2026-12-26T00:00:00+00:00"
    assert rec.size_gb == 10
    assert rec.min_retention_days == 30
    assert rec.extensions == 0
    assert w.stats()["locked"] == 1


def test_lock_rejects_duplicate_and_invalid_parameters():
    w = locked()
    with pytest.raises(bw.WardenError) as exc:
        w.lock("rp-1126", size_gb=5, min_retention_days=7, now=T0)
    assert exc.value.code == "WARDEN_ALREADY_LOCKED"
    for days in (0, -3, 3651):
        with pytest.raises(bw.WardenError) as exc:
            w.lock("rp-{0}".format(days), size_gb=5, min_retention_days=days, now=T0)
        assert exc.value.code == "WARDEN_BAD_RETENTION"
    for size in (0, -2):
        with pytest.raises(bw.WardenError) as exc:
            w.lock("rp-size-{0}".format(size), size_gb=size, min_retention_days=7, now=T0)
        assert exc.value.code == "WARDEN_BAD_SIZE"
    assert len(w.locks()) == 1
    assert w.stats()["locked"] == 1


def test_lock_rejects_when_quota_would_be_exceeded():
    w = warden(quota_gb=50)
    w.lock("rp-a", size_gb=30, min_retention_days=7, now=T0)
    with pytest.raises(bw.WardenError) as exc:
        w.lock("rp-b", size_gb=25, min_retention_days=7, now=T0)
    assert exc.value.code == "WARDEN_QUOTA_EXCEEDED"
    assert [rec.restore_point for rec in w.locks()] == ["rp-a"]
    assert w.stats()["locked"] == 1


def test_extend_is_monotonic_and_accumulates():
    w = locked()
    first = w.extend("rp-1126", extra_days=10, now=T0)
    assert first.expires_at == "2027-01-05T00:00:00+00:00"
    assert first.extensions == 1
    second = w.extend("rp-1126", extra_days=5, now=T0)
    assert second.expires_at == "2027-01-10T00:00:00+00:00"
    assert second.extensions == 2
    with pytest.raises(bw.WardenError) as exc:
        w.extend("rp-1126", extra_days=0, now=T0)
    assert exc.value.code == "WARDEN_BAD_RETENTION"
    assert w.stats()["extended"] == 2


def test_extend_unknown_restore_point_is_refused():
    w = warden()
    with pytest.raises(bw.WardenError) as exc:
        w.extend("rp-missing", extra_days=1, now=T0)
    assert exc.value.code == "WARDEN_NOT_LOCKED"
    assert w.stats()["extended"] == 0


def test_release_during_retention_is_refused():
    w = locked()
    with pytest.raises(bw.WardenError) as exc:
        w.release("rp-1126", actor="ops-1", now="2026-12-01T00:00:00+00:00")
    assert exc.value.code == "WARDEN_LOCK_HELD"
    assert w.locks()[0].status == "locked"
    assert w.stats()["released"] == 0


def test_release_after_expiry_succeeds_exactly_once():
    w = locked()
    receipt = w.release("rp-1126", actor="ops-1", now="2027-01-01T00:00:00+00:00")
    assert receipt["status"] == "released"
    assert receipt["actor"] == "ops-1"
    assert receipt["restore_point"] == "rp-1126"
    assert w.locks()[0].status == "released"
    with pytest.raises(bw.WardenError) as exc:
        w.release("rp-1126", actor="ops-2", now="2027-01-02T00:00:00+00:00")
    assert exc.value.code == "WARDEN_ALREADY_RELEASED"
    assert w.stats()["released"] == 1


def test_retention_reports_remaining_days():
    w = locked()
    info = w.retention("rp-1126", now="2026-12-16T00:00:00+00:00")
    assert info["expires_at"] == "2026-12-26T00:00:00+00:00"
    assert info["remaining_days"] == 10
    late = w.retention("rp-1126", now="2027-01-05T00:00:00+00:00")
    assert late["remaining_days"] == -10


def test_canary_registration_and_match():
    w = warden()
    w.register_canary(CANARY, DIGEST)
    out = w.check_canary(CANARY, observed_digest=DIGEST, now=T0)
    assert out == {"path": CANARY, "ok": True, "frozen": False}
    assert w.can_backup() is True
    assert w.stats()["frozen"] == 0


def test_canary_mismatch_freezes_repository():
    w = locked()
    w.register_canary(CANARY, DIGEST)
    out = w.check_canary(CANARY, observed_digest="sha256:drifted", now=T0)
    assert out["ok"] is False
    assert out["frozen"] is True
    assert w.can_backup() is False
    with pytest.raises(bw.WardenError) as exc:
        w.lock("rp-later", size_gb=5, min_retention_days=7, now=T1)
    assert exc.value.code == "WARDEN_REPO_FROZEN"
    assert w.stats()["frozen"] == 1


def test_canary_unknown_path_is_refused():
    w = warden()
    with pytest.raises(bw.WardenError) as exc:
        w.check_canary("/srv/backup/missing.txt", observed_digest=DIGEST, now=T0)
    assert exc.value.code == "WARDEN_CANARY_UNKNOWN"
    assert w.can_backup() is True


def test_verify_restore_marks_unusable_on_missing_chunks():
    w = locked()
    good = w.verify_restore("rp-1126", total_chunks=8, ok_chunks=8, now=T0)
    assert (good.status, good.usable) == ("verified", True)
    assert (good.total_chunks, good.ok_chunks) == (8, 8)
    assert w.restore_allowed("rp-1126") is True
    bad = w.verify_restore("rp-1126", total_chunks=8, ok_chunks=7, now=T0)
    assert (bad.status, bad.usable) == ("unusable", False)
    assert w.restore_allowed("rp-1126") is False
    assert w.stats()["integrity_failed"] == 1


def test_verify_restore_rejects_invalid_chunk_counts():
    w = locked()
    for total, ok in ((0, 0), (5, 6), (-1, 0)):
        with pytest.raises(bw.WardenError) as exc:
            w.verify_restore("rp-1126", total_chunks=total, ok_chunks=ok, now=T0)
        assert exc.value.code == "WARDEN_BAD_REQUEST"
    assert w.restore_allowed("rp-1126") is True


def test_snapshot_roundtrip_preserves_expiry_and_remaining_time():
    w = locked()
    w.extend("rp-1126", extra_days=10, now=T0)
    w.register_canary(CANARY, DIGEST)
    state = w.snapshot()

    clone = warden()
    clone.restore(state)
    assert [rec.expires_at for rec in clone.locks()] == [
        rec.expires_at for rec in w.locks()]
    assert clone.retention("rp-1126", now="2026-12-31T00:00:00+00:00")["remaining_days"] == 5
    assert clone.stats() == w.stats()
    with pytest.raises(bw.WardenError) as exc:
        clone.release("rp-1126", actor="ops-9", now="2026-12-25T00:00:00+00:00")
    assert exc.value.code == "WARDEN_LOCK_HELD"

    state["locks"] = {}
    assert w.locks()[0].expires_at == "2027-01-05T00:00:00+00:00"


def test_restore_rejects_malformed_snapshot():
    w = locked()
    w.register_canary(CANARY, DIGEST)
    good = w.snapshot()
    broken = [None, {},
              {"version": 5, "quota_gb": 10.0, "locks": {}, "released": {},
               "canaries": {}, "frozen": "", "verdicts": {}, "audit": [],
               "counters": {}, "stats": {}}]
    partial = dict(good)
    partial.pop("canaries")
    broken.append(partial)
    wrong_type = dict(good)
    wrong_type["locks"] = ["rp"]
    broken.append(wrong_type)
    for bad in broken:
        with pytest.raises(bw.WardenError) as exc:
            w.restore(bad)
        assert exc.value.code == "WARDEN_SNAPSHOT_INVALID"
    assert [rec.expires_at for rec in w.locks()] == ["2026-12-26T00:00:00+00:00"]
    assert w.can_backup() is True
