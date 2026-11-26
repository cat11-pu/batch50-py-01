import copy
import threading

import pytest

import quota_freeze_arbiter as q

T0 = "2026-11-26T00:00:00+00:00"
T0_PLUS_GRACE = "2026-11-26T00:10:00+00:00"


def arbiter(**kwargs):
    params = dict(soft_limit=1000, hard_limit=2000, grace_seconds=600,
                  max_write_bytes=4096)
    params.update(kwargs)
    return q.QuotaFreezeArbiter(**params)


def fresh_arbiter(**kwargs):
    arb = arbiter(**kwargs)
    arb.register_volume("vol-a")
    return arb


def test_set_quota_validates_limits_and_rejects_duplicate():
    arb = fresh_arbiter()
    policy = arb.set_quota("t1", "vol-a", soft_limit=500, hard_limit=900)
    assert (policy.tenant, policy.volume, policy.soft_limit, policy.hard_limit) == (
        "t1", "vol-a", 500, 900)
    with pytest.raises(q.QuotaError) as exc:
        arb.set_quota("t1", "vol-a", soft_limit=500, hard_limit=900)
    assert exc.value.code == "QUOTA_POLICY_EXISTS"

    for soft, hard in ((0, 100), (100, 100), (200, 100), (-1, 10)):
        with pytest.raises(q.QuotaError) as exc:
            arb.set_quota("t2", "vol-a", soft_limit=soft, hard_limit=hard)
        assert exc.value.code == "QUOTA_POLICY_INVALID"

    assert arb.quota_policy("t1", "vol-a") == policy
    assert arb.quota_policy("t9", "vol-a") is None


def test_volume_registration_and_invalid_write_requests():
    arb = arbiter()
    with pytest.raises(q.QuotaError) as exc:
        arb.admit_write("t1", "vol-x", "a.log", 10)
    assert exc.value.code == "QUOTA_UNKNOWN_VOLUME"

    arb.register_volume("vol-a")
    assert arb.volumes() == ("vol-a",)
    with pytest.raises(q.QuotaError) as exc:
        arb.admit_write("t1", "vol-x", "a.log", 10)
    assert exc.value.code == "QUOTA_UNKNOWN_VOLUME"

    for size in (0, -1, 1.5):
        with pytest.raises(q.QuotaError) as exc:
            arb.admit_write("t1", "vol-a", "a.log", size)
        assert exc.value.code == "QUOTA_INVALID_REQUEST"
    with pytest.raises(q.QuotaError) as exc:
        arb.admit_write("t1", "vol-a", "", 10)
    assert exc.value.code == "QUOTA_INVALID_REQUEST"
    with pytest.raises(q.QuotaError) as exc:
        arb.admit_write("t1", "vol-a", "a.log", 5000)
    assert exc.value.code == "QUOTA_WRITE_TOO_LARGE"
    assert arb.usage("t1") == 0


def test_allowed_write_updates_usage_and_remaining():
    arb = fresh_arbiter()
    decision = arb.admit_write("t1", "vol-a", "a.log", 300, now=T0)
    assert decision.outcome == "allowed"
    assert decision.state == "ok"
    assert decision.code is None
    assert decision.usage == 300
    assert decision.remaining == 1700
    assert decision.grace_deadline is None
    assert arb.usage("t1") == 300
    assert arb.tenant_state("t1", now=T0) == "ok"


def test_soft_limit_enters_grace_with_deadline():
    arb = fresh_arbiter()
    arb.admit_write("t1", "vol-a", "a.log", 800, now=T0)
    decision = arb.admit_write("t1", "vol-a", "b.log", 300, now=T0)
    assert decision.outcome == "grace"
    assert decision.state == "grace"
    assert decision.usage == 1100
    assert decision.grace_deadline == T0_PLUS_GRACE
    assert arb.tenant_state("t1", now=T0) == "grace"
    assert arb.usage("t1") == 1100


def test_hard_limit_denial_keeps_usage_and_freezes():
    arb = fresh_arbiter()
    arb.admit_write("t1", "vol-a", "a.log", 2000, now=T0)
    decision = arb.admit_write("t1", "vol-a", "b.log", 1, now=T0)
    assert decision.outcome == "denied"
    assert decision.code == "QUOTA_HARD_LIMIT"
    assert decision.state == "frozen"
    assert decision.usage == 2000
    assert decision.remaining == 0
    assert arb.usage("t1") == 2000
    assert arb.tenant_state("t1", now=T0) == "frozen"


def test_grace_expiry_denies_write_and_freezes():
    arb = fresh_arbiter(soft_limit=1000, hard_limit=5000)
    arb.admit_write("t1", "vol-a", "a.log", 1200, now=T0)
    assert arb.tenant_state("t1", now=T0) == "grace"
    decision = arb.admit_write("t1", "vol-a", "b.log", 100, now=T0_PLUS_GRACE)
    assert decision.outcome == "denied"
    assert decision.code == "QUOTA_GRACE_EXPIRED"
    assert decision.state == "frozen"
    assert arb.usage("t1") == 1200


def test_delete_reclaims_and_repeat_delete_returns_zero():
    arb = fresh_arbiter(soft_limit=1000, hard_limit=5000, max_write_bytes=10000)
    arb.admit_write("t1", "vol-a", "a.log", 400, now=T0)
    arb.admit_write("t1", "vol-a", "b.log", 200, now=T0)

    first = arb.delete_object("t1", "vol-a", "a.log", now=T0)
    assert first.reclaimed == 400
    assert first.usage == 200
    second = arb.delete_object("t1", "vol-a", "a.log", now=T0)
    assert second.reclaimed == 0
    assert second.usage == 200
    unknown = arb.delete_object("t1", "vol-a", "missing.log", now=T0)
    assert unknown.reclaimed == 0
    assert arb.usage("t1") == 200

    shrink = arb.truncate_object("t1", "vol-a", "b.log", 50, now=T0)
    assert shrink.action == "reclaim"
    assert shrink.reclaimed == 150
    assert shrink.usage == 50
    grow = arb.truncate_object("t1", "vol-a", "b.log", 6000, now=T0)
    assert grow.action == "admit"
    assert grow.decision.outcome == "denied"
    assert grow.decision.code == "QUOTA_HARD_LIMIT"
    assert arb.usage("t1") == 50


def test_tenant_aggregate_limit_freezes_across_volumes():
    arb = arbiter(soft_limit=100000, hard_limit=100000)
    arb.register_volume("vol-a")
    arb.register_volume("vol-b")
    arb.set_tenant_limit("t1", 1500)
    arb.admit_write("t1", "vol-a", "a.log", 1000, now=T0)
    decision = arb.admit_write("t1", "vol-b", "b.log", 600, now=T0)
    assert decision.outcome == "denied"
    assert decision.code == "QUOTA_TENANT_LIMIT"
    assert arb.usage("t1") == 1000
    assert arb.tenant_state("t1", now=T0) == "frozen"


def test_lift_freeze_refusals():
    arb = fresh_arbiter()
    with pytest.raises(q.QuotaError) as exc:
        arb.lift_freeze("t1", now=T0)
    assert exc.value.code == "QUOTA_NOT_FROZEN"

    arb.admit_write("t1", "vol-a", "a.log", 2000, now=T0)
    assert arb.tenant_state("t1", now=T0) == "frozen"
    with pytest.raises(q.QuotaError) as exc:
        arb.lift_freeze("t1", now=T0)
    assert exc.value.code == "QUOTA_RELEASE_REFUSED"
    assert arb.tenant_state("t1", now=T0) == "frozen"


def test_admin_freeze_is_idempotent_and_blocks_writes():
    arb = fresh_arbiter()
    assert arb.freeze_tenant("t1", "incident", now=T0) == "frozen"
    assert arb.freeze_tenant("t1", "incident again", now=T0) == "frozen"
    assert arb.stats()["frozen"] == 1

    decision = arb.admit_write("t1", "vol-a", "a.log", 10, now=T0)
    assert decision.outcome == "denied"
    assert decision.code == "QUOTA_TENANT_FROZEN"
    assert arb.usage("t1") == 0
    assert arb.tenant_state("t1", now=T0) == "frozen"


def test_stats_and_audit_track_each_decision():
    arb = fresh_arbiter()
    arb.admit_write("t1", "vol-a", "a.log", 500, now=T0)
    arb.admit_write("t1", "vol-a", "b.log", 600, now=T0)
    arb.delete_object("t1", "vol-a", "a.log", now=T0)
    arb.admit_write("t1", "vol-a", "c.log", 100, now=T0)

    assert arb.stats() == {
        "admitted": 2,
        "grace_admitted": 1,
        "denied": 0,
        "written_bytes": 1200,
        "reclaimed_bytes": 500,
        "grace_entered": 1,
        "frozen": 0,
        "released": 0,
        "audit_writes": 4,
    }
    entries = arb.audit_entries()
    assert [entry.seq for entry in entries] == [1, 2, 3, 4]
    assert [entry.action for entry in entries] == ["admit", "admit", "delete", "admit"]
    assert [entry.outcome for entry in entries] == [
        "allowed", "grace", "reclaimed", "allowed"]
    assert entries[1].code is None
    assert entries[0].usage_after == 500
    assert entries[1].usage_after == 1100


def test_snapshot_restore_roundtrip():
    arb = fresh_arbiter()
    arb.admit_write("t1", "vol-a", "a.log", 400, now=T0)
    snap = arb.snapshot()
    assert set(snap) == {"version", "volumes", "policies", "tenant_limits",
                         "objects", "states", "audit", "stats"}
    pristine = copy.deepcopy(snap)

    snap["stats"]["admitted"] = 99
    snap["objects"].clear()
    assert arb.stats()["admitted"] == 1
    assert arb.usage("t1") == 400

    clone = arbiter()
    clone.restore(pristine)
    assert clone.usage("t1") == 400
    assert clone.stats() == arb.stats()
    assert clone.tenant_state("t1", now=T0) == arb.tenant_state("t1", now=T0)
    before = len(clone.audit_entries())
    decision = clone.admit_write("t1", "vol-a", "b.log", 100, now=T0)
    assert decision.outcome == "allowed"
    assert clone.audit_entries()[-1].seq == before + 1
    assert clone.usage("t1") == 500


def test_restore_rejects_malformed_snapshot():
    arb = fresh_arbiter()
    arb.admit_write("t1", "vol-a", "a.log", 400, now=T0)
    snap = arb.snapshot()

    missing_stats = copy.deepcopy(snap)
    missing_stats.pop("stats")
    bad_objects = copy.deepcopy(snap)
    bad_objects["objects"] = "nope"
    bad_policies = copy.deepcopy(snap)
    bad_policies["policies"] = "nope"
    bad_states = [None, {}, missing_stats, bad_objects, bad_policies]

    for bad in bad_states:
        with pytest.raises(q.QuotaError) as exc:
            arb.restore(bad)
        assert exc.value.code == "QUOTA_SNAPSHOT_INVALID"

    assert arb.usage("t1") == 400
    assert arb.stats()["admitted"] == 1


def test_concurrent_admission_never_oversells_hard_limit():
    arb = fresh_arbiter(soft_limit=800, hard_limit=1000, max_write_bytes=256)
    workers = 20
    results = []
    errors = []
    barrier = threading.Barrier(workers)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            decision = arb.admit_write("t1", "vol-a", f"f{index:02d}", 100, now=T0)
            results.append(decision)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert arb.usage("t1") == 1000
    allowed = [item for item in results if item.outcome in ("allowed", "grace")]
    denied = [item for item in results if item.outcome == "denied"]
    assert len(allowed) == 10
    assert len(denied) == 10
    assert {item.code for item in denied} == {"QUOTA_HARD_LIMIT"}
    assert arb.stats()["admitted"] + arb.stats()["grace_admitted"] == 10
    assert arb.stats()["denied"] == 10


def test_usage_aggregates_across_volumes():
    arb = arbiter(soft_limit=5000, hard_limit=9000)
    arb.register_volume("vol-a")
    arb.register_volume("vol-b")
    arb.admit_write("t1", "vol-a", "a1", 300, inode=11, now=T0)
    arb.admit_write("t1", "vol-b", "b1", 450, inode=12, now=T0)
    arb.admit_write("t2", "vol-a", "c1", 100, inode=13, now=T0)

    assert arb.usage("t1") == 750
    assert arb.usage_by_volume("t1") == {"vol-a": 300, "vol-b": 450}
    assert arb.usage("t2") == 100
    assert arb.usage_by_volume("t2") == {"vol-a": 100, "vol-b": 0}
