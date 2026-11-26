import pytest

import shm_quota_warden as shm

NOW = "2026-11-26T09:00:00+00:00"
T15 = "2026-11-26T09:00:15+00:00"
T40 = "2026-11-26T09:00:40+00:00"


def warden(**kwargs):
    return shm.ShmQuotaWarden(**kwargs)


def one(**kwargs):
    keeper = warden(**kwargs)
    keeper.create("alpha", 1, owner="svc-a", size=600, now=NOW)
    return keeper


def test_create_records_segment_and_quota_watermarks():
    keeper = warden()
    record = keeper.create("alpha", 1, owner="svc-a", size=600, now=NOW)
    assert record.namespace == "alpha"
    assert record.key == 1
    assert record.owner == "svc-a"
    assert record.size == 600
    assert record.segment_id == "shm-1"
    assert record.state == "live"
    assert record.refcount == 0
    assert record.created_at == NOW
    assert [(item.namespace, item.key) for item in keeper.segments()] == [("alpha", 1)]
    assert keeper.stats()["quota_bytes"] == 600
    assert keeper.stats()["quota_segments"] == 1


def test_create_argument_validation():
    keeper = warden()
    with pytest.raises(shm.ShmError) as err:
        keeper.create("alpha", 1, owner="svc-a", size=0, now=NOW)
    assert err.value.code == "SHM_BAD_SIZE"
    with pytest.raises(shm.ShmError) as err:
        keeper.create("alpha", 1, owner="svc-a", size=-5, now=NOW)
    assert err.value.code == "SHM_BAD_SIZE"
    with pytest.raises(shm.ShmError) as err:
        keeper.create("alpha", 1, owner="", size=10, now=NOW)
    assert err.value.code == "SHM_BAD_OWNER"
    with pytest.raises(shm.ShmError) as err:
        keeper.create("alpha", -1, owner="svc-a", size=10, now=NOW)
    assert err.value.code == "SHM_BAD_KEY"
    with pytest.raises(shm.ShmError) as err:
        keeper.create("", 1, owner="svc-a", size=10, now=NOW)
    assert err.value.code == "SHM_BAD_NAMESPACE"
    assert keeper.stats()["denied"] == 5
    assert keeper.stats()["quota_segments"] == 0


def test_duplicate_keys_are_scoped_by_owner_and_namespace():
    keeper = warden()
    first = keeper.create("alpha", 1, owner="svc-a", size=600, now=NOW)
    again = keeper.create("alpha", 1, owner="svc-a", size=900, now=NOW)
    assert again.segment_id == first.segment_id
    assert keeper.stats()["quota_bytes"] == 600
    with pytest.raises(shm.ShmError) as err:
        keeper.create("alpha", 1, owner="svc-b", size=10, now=NOW)
    assert err.value.code == "SHM_KEY_OWNED"
    other = keeper.create("beta", 1, owner="svc-b", size=10, now=NOW)
    assert other.segment_id != first.segment_id
    assert [(item.namespace, item.key) for item in keeper.segments()] == [
        ("alpha", 1), ("beta", 1)]


def test_user_byte_quota_is_pre_charged():
    keeper = warden(user_bytes=1000)
    keeper.create("alpha", 1, owner="svc-a", size=600, now=NOW)
    with pytest.raises(shm.ShmError) as err:
        keeper.create("alpha", 2, owner="svc-a", size=500, now=NOW)
    assert err.value.code == "SHM_USER_QUOTA"
    assert keeper.stats()["quota_bytes"] == 600
    assert keeper.stats()["quota_segments"] == 1


def test_namespace_segment_quota_is_enforced():
    keeper = warden(ns_segments=2)
    keeper.create("alpha", 1, owner="svc-a", size=10, now=NOW)
    keeper.create("alpha", 2, owner="svc-b", size=10, now=NOW)
    with pytest.raises(shm.ShmError) as err:
        keeper.create("alpha", 3, owner="svc-c", size=10, now=NOW)
    assert err.value.code == "SHM_NS_SEGMENTS"
    other = keeper.create("beta", 1, owner="svc-c", size=10, now=NOW)
    assert other.segment_id == "shm-3"


def test_attach_tracks_references_and_pids():
    keeper = one()
    assert keeper.attach("alpha", 1, pid=1001, now=NOW) == 1
    assert keeper.attach("alpha", 1, pid=1002, now=T15) == 2
    status = keeper.status("alpha", 1)
    assert status["refcount"] == 2
    assert status["attached_pids"] == (1001, 1002)
    assert status["last_attach_at"] == T15
    assert keeper.stats()["attached"] == 2


def test_attach_errors_for_missing_pending_and_bad_pid():
    keeper = one()
    with pytest.raises(shm.ShmError) as err:
        keeper.attach("alpha", 99, pid=1, now=NOW)
    assert err.value.code == "SHM_NOT_FOUND"
    with pytest.raises(shm.ShmError) as err:
        keeper.attach("alpha", 1, pid=0, now=NOW)
    assert err.value.code == "SHM_BAD_PID"
    keeper.attach("alpha", 1, pid=1001, now=NOW)
    keeper.remove("alpha", 1, now=NOW)
    with pytest.raises(shm.ShmError) as err:
        keeper.attach("alpha", 1, pid=1002, now=T15)
    assert err.value.code == "SHM_PENDING_DELETE"


def test_detach_decrements_and_rejects_unknown_pid():
    keeper = one()
    keeper.attach("alpha", 1, pid=1001, now=NOW)
    keeper.attach("alpha", 1, pid=1002, now=NOW)
    assert keeper.detach("alpha", 1, pid=1001, now=T15) == 1
    with pytest.raises(shm.ShmError) as err:
        keeper.detach("alpha", 1, pid=1001, now=T15)
    assert err.value.code == "SHM_NOT_ATTACHED"
    assert keeper.status("alpha", 1)["refcount"] == 1
    with pytest.raises(shm.ShmError) as err:
        keeper.detach("alpha", 9, pid=1001, now=T15)
    assert err.value.code == "SHM_NOT_FOUND"


def test_zero_references_do_not_delete_the_segment():
    keeper = one()
    keeper.attach("alpha", 1, pid=1001, now=NOW)
    assert keeper.detach("alpha", 1, pid=1001, now=T15) == 0
    status = keeper.status("alpha", 1)
    assert status["state"] == "live"
    assert status["refcount"] == 0
    assert keeper.stats()["segments"] == 1
    assert keeper.remove("alpha", 1, now=T15) == 0
    with pytest.raises(shm.ShmError) as err:
        keeper.status("alpha", 1)
    assert err.value.code == "SHM_NOT_FOUND"
    assert keeper.stats()["quota_bytes"] == 0


def test_remove_is_idempotent_while_references_remain():
    keeper = one()
    keeper.attach("alpha", 1, pid=1001, now=NOW)
    assert keeper.remove("alpha", 1, now=NOW) == 1
    assert keeper.remove("alpha", 1, now=NOW) == 1
    assert keeper.status("alpha", 1)["state"] == "pending_delete"
    assert keeper.detach("alpha", 1, pid=1001, now=T15) == 0
    with pytest.raises(shm.ShmError) as err:
        keeper.remove("alpha", 1, now=T15)
    assert err.value.code == "SHM_NOT_FOUND"


def test_sweep_removes_stale_unattached_segments_and_honours_whitelist():
    keeper = warden()
    keeper.create("alpha", 1, owner="svc-a", size=100, now=NOW)
    keeper.create("alpha", 2, owner="svc-b", size=100, now=NOW)
    keeper.attach("alpha", 2, pid=7, now=T15)
    keeper.detach("alpha", 2, pid=7, now=T15)
    keeper.create("alpha", 3, owner="ops", size=100, now=NOW)
    removed = keeper.sweep(stale_after=10, now=T40, whitelist=("ops",))
    assert removed == [("alpha", 1), ("alpha", 2)]
    assert [(item.namespace, item.key) for item in keeper.segments()] == [("alpha", 3)]
    assert keeper.stats()["swept"] == 2
    assert keeper.stats()["quota_bytes"] == 100


def test_reap_releases_every_reference_of_a_dead_pid():
    keeper = warden()
    keeper.create("alpha", 1, owner="svc-a", size=100, now=NOW)
    keeper.create("alpha", 2, owner="svc-a", size=100, now=NOW)
    keeper.attach("alpha", 1, pid=9, now=NOW)
    keeper.attach("alpha", 2, pid=9, now=NOW)
    assert keeper.reap(9, now=T15) == 2
    assert keeper.status("alpha", 1)["refcount"] == 0
    assert keeper.status("alpha", 2)["refcount"] == 0
    assert keeper.stats()["segments"] == 2
    assert keeper.reap(9, now=T15) == 0


def test_snapshot_preserves_pending_delete_state():
    keeper = one()
    keeper.attach("alpha", 1, pid=1001, now=NOW)
    keeper.attach("alpha", 1, pid=1002, now=NOW)
    keeper.remove("alpha", 1, now=NOW)
    snap = keeper.snapshot()
    fresh = warden()
    fresh.restore(snap)
    status = fresh.status("alpha", 1)
    assert status["state"] == "pending_delete"
    assert status["refcount"] == 2
    with pytest.raises(shm.ShmError) as err:
        fresh.attach("alpha", 1, pid=1003, now=T15)
    assert err.value.code == "SHM_PENDING_DELETE"
    assert fresh.detach("alpha", 1, pid=1001, now=T15) == 1
    assert fresh.detach("alpha", 1, pid=1002, now=T15) == 0
    with pytest.raises(shm.ShmError) as err:
        fresh.status("alpha", 1)
    assert err.value.code == "SHM_NOT_FOUND"


def test_invalid_snapshot_keeps_segment_table():
    keeper = one()
    with pytest.raises(shm.ShmError) as err:
        keeper.restore({"segments": 3})
    assert err.value.code == "SHM_SNAPSHOT_INVALID"
    assert keeper.stats()["segments"] == 1
    assert keeper.status("alpha", 1)["size"] == 600


def test_stats_count_each_lifecycle_event():
    keeper = warden()
    keeper.create("alpha", 1, owner="svc-a", size=100, now=NOW)
    keeper.create("alpha", 2, owner="svc-a", size=100, now=NOW)
    keeper.create("alpha", 3, owner="svc-a", size=100, now=NOW)
    keeper.attach("alpha", 1, pid=5, now=NOW)
    keeper.detach("alpha", 1, pid=5, now=T15)
    keeper.remove("alpha", 3, now=T15)
    removed = keeper.sweep(stale_after=1, now=T40)
    assert removed == [("alpha", 1), ("alpha", 2)]
    stats = keeper.stats()
    assert stats["created"] == 3
    assert stats["attached"] == 1
    assert stats["detached"] == 1
    assert stats["removed"] == 1
    assert stats["swept"] == 2
    assert stats["quota_segments"] == 0
    assert stats["quota_bytes"] == 0
