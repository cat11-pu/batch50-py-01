import copy
import threading

import pytest

import wipe_job_scheduler as wj


def scheduler(**kwargs):
    return wj.WipeJobScheduler(**kwargs)


def test_register_device_validates_and_unknown_online():
    s = scheduler()
    s.register_device("nvme0", blocks=20)
    cases = [
        (lambda: s.register_device("nvme0", blocks=20), "WIPE_DUPLICATE_DEVICE"),
        (lambda: s.register_device("nvme1", blocks=0), "WIPE_INVALID_REQUEST"),
        (lambda: s.register_device("nvme1", blocks=-4), "WIPE_INVALID_REQUEST"),
        (lambda: s.register_device("  ", blocks=4), "WIPE_INVALID_REQUEST"),
        (lambda: s.set_device_online("ghost", online=False), "WIPE_UNKNOWN_DEVICE"),
        (lambda: s.submit(device="ghost", start=0, end=1, shard_blocks=1),
         "WIPE_UNKNOWN_DEVICE"),
    ]
    for call, code in cases:
        with pytest.raises(wj.WipeError) as exc:
            call()
        assert exc.value.code == code
    assert s.stats() == {"submitted": 0, "claimed": 0, "completed": 0,
                         "cancelled": 0, "requeued": 0, "offline_drops": 0,
                         "leases_expired": 0}


def test_submit_validates_range_and_shard_size():
    s = scheduler()
    s.register_device("nvme0", blocks=10)
    cases = [
        (dict(device="nvme0", start=4, end=4, shard_blocks=2), "WIPE_INVALID_REQUEST"),
        (dict(device="nvme0", start=6, end=4, shard_blocks=2), "WIPE_INVALID_REQUEST"),
        (dict(device="nvme0", start=-1, end=4, shard_blocks=2), "WIPE_INVALID_REQUEST"),
        (dict(device="nvme0", start=0, end=11, shard_blocks=2), "WIPE_INVALID_REQUEST"),
        (dict(device="nvme0", start=0, end=4, shard_blocks=0), "WIPE_INVALID_REQUEST"),
    ]
    for kwargs, code in cases:
        with pytest.raises(wj.WipeError) as exc:
            s.submit(**kwargs)
        assert exc.value.code == code
    assert s.stats()["submitted"] == 0


def test_submit_splits_range_into_shards_and_reports_status():
    s = scheduler()
    s.register_device("nvme0", blocks=20)
    job = s.submit(device="nvme0", start=0, end=10, shard_blocks=4)
    assert job == "job-1"
    view = s.status(job)
    assert (view.job_id, view.device, view.start, view.end) == ("job-1", "nvme0", 0, 10)
    assert (view.total_blocks, view.done_blocks, view.state) == (10, 0, "active")
    assert (view.shard_count, view.pending, view.leased, view.done) == (3, 3, 0, 0)
    rows = s.shards(job)
    assert [(row.index, row.start, row.end, row.state, row.done_blocks)
            for row in rows] == [
        (0, 0, 4, "pending", 0),
        (1, 4, 8, "pending", 0),
        (2, 8, 10, "pending", 0),
    ]
    assert s.stats()["submitted"] == 1


def test_overlapping_ranges_conflict_but_adjacent_are_allowed():
    s = scheduler()
    s.register_device("nvme0", blocks=20)
    s.submit(device="nvme0", start=0, end=10, shard_blocks=5)
    for start, end in ((5, 15), (0, 20)):
        with pytest.raises(wj.WipeError) as exc:
            s.submit(device="nvme0", start=start, end=end, shard_blocks=5)
        assert exc.value.code == "WIPE_RANGE_CONFLICT"
    assert s.submit(device="nvme0", start=10, end=20, shard_blocks=5) == "job-2"
    s.register_device("nvme1", blocks=10)
    assert s.submit(device="nvme1", start=0, end=10, shard_blocks=10) == "job-3"


def test_claim_picks_lowest_job_then_lowest_pending_shard():
    s = scheduler()
    s.register_device("nvme0", blocks=20)
    first = s.submit(device="nvme0", start=0, end=10, shard_blocks=5)
    s.submit(device="nvme0", start=10, end=20, shard_blocks=10)
    lease = s.claim("w1", now=1000)
    assert (lease.lease_id, lease.job_id, lease.shard_index) == ("lease-1", first, 0)
    assert (lease.start, lease.end, lease.expires_at) == (0, 5, 31000)
    assert s.leases() == {"w1": lease}
    second = s.claim("w2", now=1010)
    assert (second.job_id, second.shard_index) == (first, 1)
    view = s.status(first)
    assert (view.pending, view.leased) == (0, 2)
    assert s.stats()["claimed"] == 2


def test_claim_rejects_active_lease_and_returns_none_when_idle():
    s = scheduler()
    s.register_device("nvme0", blocks=8)
    job = s.submit(device="nvme0", start=0, end=4, shard_blocks=4)
    lease = s.claim("w1", now=0)
    with pytest.raises(wj.WipeError) as exc:
        s.claim("w1", now=10)
    assert exc.value.code == "WIPE_LEASE_ACTIVE"
    s.report_progress(lease.lease_id, 4, now=20)
    assert s.status(job).state == "complete"
    assert s.claim("w2", now=30) is None


def test_progress_updates_accumulate_and_complete_shard():
    s = scheduler(lease_ms=500)
    s.register_device("nvme0", blocks=10)
    job = s.submit(device="nvme0", start=0, end=10, shard_blocks=4)
    lease = s.claim("w1", now=1000)
    assert s.report_progress(lease.lease_id, 2, now=1100) == {
        "completed": False, "done_blocks": 2, "remaining": 2}
    view = s.status(job)
    assert (view.done_blocks, view.leased) == (2, 1)
    with pytest.raises(wj.WipeError) as exc:
        s.report_progress(lease.lease_id, 1, now=1150)
    assert exc.value.code == "WIPE_PROGRESS_REGRESS"
    assert s.shards(job)[0].done_blocks == 2
    assert s.report_progress(lease.lease_id, 4, now=1200) == {
        "completed": True, "done_blocks": 4, "remaining": 0}
    assert s.shards(job)[0].state == "done"
    assert s.leases() == {}
    assert s.stats()["completed"] == 1
    assert s.claim("w1", now=1300).shard_index == 1


def test_job_completes_when_every_shard_is_done():
    s = scheduler(lease_ms=500)
    s.register_device("nvme0", blocks=8)
    job = s.submit(device="nvme0", start=0, end=8, shard_blocks=4)
    for now in (100, 200):
        lease = s.claim("w1", now=now)
        s.report_progress(lease.lease_id, 4, now=now + 10)
    view = s.status(job)
    assert (view.state, view.done_blocks) == ("complete", 8)
    assert (view.pending, view.leased, view.done) == (0, 0, 2)
    assert s.claim("w2", now=300) is None
    assert s.stats()["completed"] == 2


def test_expired_lease_is_reclaimed_and_stale_report_lost():
    s = scheduler(lease_ms=100)
    s.register_device("nvme0", blocks=8)
    job = s.submit(device="nvme0", start=0, end=8, shard_blocks=4)
    first = s.claim("w1", now=0)
    second = s.claim("w2", now=200)
    assert (second.shard_index, second.lease_id) == (0, "lease-2")
    with pytest.raises(wj.WipeError) as exc:
        s.report_progress(first.lease_id, 1, now=210)
    assert exc.value.code == "WIPE_LEASE_LOST"
    assert s.shards(job)[0].state == "leased"
    assert s.leases() == {"w2": second}
    assert s.stats()["leases_expired"] == 1


def test_resume_requeues_only_expired_incomplete_shards_with_progress():
    s = scheduler(lease_ms=100)
    s.register_device("nvme0", blocks=8)
    job = s.submit(device="nvme0", start=0, end=8, shard_blocks=4)
    lease = s.claim("w1", now=0)
    s.report_progress(lease.lease_id, 2, now=50)
    assert s.resume(job, now=100) == 0
    assert s.resume(job, now=200) == 1
    view = s.status(job)
    assert (view.pending, view.leased, view.done_blocks) == (2, 0, 2)
    row = s.shards(job)[0]
    assert (row.state, row.done_blocks) == ("pending", 2)
    assert s.stats()["requeued"] == 1
    second = s.claim("w2", now=210)
    assert (second.job_id, second.shard_index) == (job, 0)


def test_cancel_reclaims_incomplete_shards_and_invalidates_leases():
    s = scheduler(lease_ms=500)
    s.register_device("nvme0", blocks=16)
    job = s.submit(device="nvme0", start=0, end=8, shard_blocks=4)
    lease = s.claim("w1", now=0)
    s.report_progress(lease.lease_id, 4, now=10)
    second = s.claim("w1", now=20)
    assert (second.job_id, second.shard_index) == (job, 1)
    assert s.cancel(job) == 1
    view = s.status(job)
    assert (view.state, view.done, view.pending, view.leased) == (
        "cancelled", 1, 0, 0)
    assert s.leases() == {}
    with pytest.raises(wj.WipeError) as exc:
        s.report_progress(second.lease_id, 1, now=30)
    assert exc.value.code == "WIPE_LEASE_LOST"
    assert s.cancel(job) == 0

    done_job = s.submit(device="nvme0", start=8, end=12, shard_blocks=4)
    finished = s.claim("w1", now=40)
    assert (finished.job_id, finished.shard_index) == (done_job, 0)
    s.report_progress(finished.lease_id, 4, now=50)
    with pytest.raises(wj.WipeError) as exc:
        s.cancel(done_job)
    assert exc.value.code == "WIPE_JOB_COMPLETE"


def test_offline_device_releases_leases_and_blocks_claiming():
    s = scheduler(lease_ms=500)
    s.register_device("nvme0", blocks=8)
    job = s.submit(device="nvme0", start=0, end=8, shard_blocks=4)
    lease = s.claim("w1", now=0)
    assert s.set_device_online("nvme0", online=False) == 1
    view = s.status(job)
    assert (view.pending, view.leased) == (2, 0)
    assert s.shards(job)[0].done_blocks == 0
    assert s.claim("w2", now=10) is None
    with pytest.raises(wj.WipeError) as exc:
        s.report_progress(lease.lease_id, 1, now=10)
    assert exc.value.code == "WIPE_LEASE_LOST"
    assert s.set_device_online("nvme0", online=True) == 0
    again = s.claim("w2", now=20)
    assert (again.job_id, again.shard_index) == (job, 0)
    assert s.stats()["offline_drops"] == 1


def test_snapshot_restore_keeps_leases_and_progress():
    s = scheduler(lease_ms=1000)
    s.register_device("nvme0", blocks=8)
    job = s.submit(device="nvme0", start=0, end=8, shard_blocks=4)
    lease = s.claim("w1", now=100)
    s.report_progress(lease.lease_id, 3, now=200)
    state = s.snapshot()
    assert set(state) == {"version", "devices", "jobs", "shards", "leases",
                          "counters", "next_job", "next_lease"}
    pristine = copy.deepcopy(state)
    clone = wj.WipeJobScheduler(lease_ms=1000)
    clone.restore(pristine)
    assert clone.status(job) == s.status(job)
    assert clone.leases() == s.leases()
    out = clone.report_progress(lease.lease_id, 4, now=300)
    assert out == {"completed": True, "done_blocks": 4, "remaining": 0}
    assert s.status(job).done_blocks == 3
    state["jobs"].clear()
    assert s.status(job).done_blocks == 3
    assert job in pristine["jobs"]


def test_restore_rejects_malformed_snapshot():
    s = scheduler()
    s.register_device("nvme0", blocks=8)
    job = s.submit(device="nvme0", start=0, end=8, shard_blocks=4)
    bad_states = [
        None,
        {},
        {"version": 2, "devices": {}, "jobs": {}, "shards": {}, "leases": {},
         "counters": {}, "next_job": 1, "next_lease": 1},
        {"version": 1, "devices": [], "jobs": {}, "shards": {}, "leases": {},
         "counters": {}, "next_job": 1, "next_lease": 1},
        {"version": 1, "devices": {}, "jobs": [], "shards": {}, "leases": {},
         "counters": {}, "next_job": 1, "next_lease": 1},
        {"version": 1, "devices": {}, "jobs": {}, "shards": [], "leases": {},
         "counters": {}, "next_job": 1, "next_lease": 1},
        {"version": 1, "devices": {}, "jobs": {}, "shards": {}, "leases": [],
         "counters": {}, "next_job": 1, "next_lease": 1},
    ]
    for bad in bad_states:
        with pytest.raises(wj.WipeError) as exc:
            s.restore(bad)
        assert exc.value.code == "WIPE_SNAPSHOT_INVALID"
    assert s.status(job).state == "active"
    assert s.status(job).pending == 2


def test_concurrent_claims_give_distinct_shards():
    s = scheduler(lease_ms=1000)
    s.register_device("nvme0", blocks=5)
    job = s.submit(device="nvme0", start=0, end=5, shard_blocks=1)
    leases = []
    errors = []
    barrier = threading.Barrier(5)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            lease = s.claim(f"w{index}", now=100)
            if lease is not None:
                leases.append(lease)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(5)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(leases) == 5
    assert len({lease.shard_index for lease in leases}) == 5
    assert s.stats()["claimed"] == 5
    assert len(s.leases()) == 5
    assert s.status(job).leased == 5
