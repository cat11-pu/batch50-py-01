import copy
import threading

import pytest

import lightmap_bake_scheduler as lb


def scheduler(**kwargs):
    return lb.LightmapBakeScheduler(**kwargs)


def submit(sched, object_id, *, density=2, bounds=(16.0, 16.0), priority=0):
    return sched.submit_job(object_id, texel_density=density, bounds=bounds,
                            priority=priority)


def test_submit_job_reports_state_and_required_slots():
    sched = scheduler()
    first = submit(sched, "obj-a", density=2)
    second = submit(sched, "obj-b", density=4)
    assert (first, second) == ("job-0001", "job-0002")
    state = sched.job_state(first)
    assert state["object_id"] == "obj-a"
    assert state["status"] == "queued"
    assert state["priority"] == 0
    assert state["required_slots"] == 1
    assert state["page"] is None
    assert state["slots"] == ()
    assert state["worker"] is None
    assert state["version"] == 1
    assert state["attempts"] == 0
    assert sched.job_state(second)["required_slots"] == 2
    assert sched.stats()["submitted"] == 2


def test_submit_job_rejects_invalid_arguments():
    sched = scheduler()
    bad_calls = [
        lambda: sched.submit_job("", texel_density=2, bounds=(16.0, 16.0)),
        lambda: sched.submit_job("obj", texel_density=0, bounds=(16.0, 16.0)),
        lambda: sched.submit_job("obj", texel_density=2, bounds=(0.0, 16.0)),
        lambda: sched.submit_job("obj", texel_density=2, bounds=(16.0,)),
        lambda: sched.submit_job("obj", texel_density=2,
                                 bounds=(16.0, 16.0), priority=-1),
    ]
    for call in bad_calls:
        with pytest.raises(lb.LightmapError) as exc:
            call()
        assert exc.value.code == "LIGHTMAP_INVALID_REQUEST"
    assert sched.stats()["submitted"] == 0


def test_allocate_page_uses_first_fit_slots():
    sched = scheduler()
    job_a = submit(sched, "obj-a", density=4)
    job_b = submit(sched, "obj-b", density=4)
    job_c = submit(sched, "obj-c", density=2)
    alloc_a = sched.allocate_page(job_a)
    alloc_b = sched.allocate_page(job_b)
    alloc_c = sched.allocate_page(job_c)
    assert (alloc_a.page, alloc_a.slots) == (0, (0, 1))
    assert (alloc_b.page, alloc_b.slots) == (0, (2, 3))
    assert (alloc_c.page, alloc_c.slots) == (1, (0,))
    assert alloc_a.slot_texels == 512
    assert sched.pages_of("obj-c") == (alloc_c,)
    assert sched.job_state(job_a)["page"] == 0
    assert sched.job_state(job_a)["slots"] == (0, 1)
    assert sched.stats()["allocations"] == 3
    assert sched.stats()["pages_created"] == 2


def test_allocate_refuses_density_above_page_capacity():
    sched = scheduler(page_slots=2)
    job = submit(sched, "obj-a", density=8, bounds=(16.0, 16.0))
    assert sched.job_state(job)["required_slots"] == 4
    with pytest.raises(lb.LightmapError) as exc:
        sched.allocate_page(job)
    assert exc.value.code == "LIGHTMAP_DENSITY_TOO_HIGH"
    assert sched.pages_of("obj-a") == ()
    assert sched.stats()["refused_allocations"] == 1
    assert sched.stats()["pages_created"] == 0


def test_allocate_refuses_when_page_cap_reached():
    sched = scheduler(page_slots=2, max_pages=1)
    job_a = submit(sched, "obj-a")
    job_b = submit(sched, "obj-b")
    job_c = submit(sched, "obj-c")
    sched.allocate_page(job_a)
    sched.allocate_page(job_b)
    with pytest.raises(lb.LightmapError) as exc:
        sched.allocate_page(job_c)
    assert exc.value.code == "LIGHTMAP_PAGES_EXHAUSTED"
    assert sched.stats()["refused_allocations"] == 1
    assert sched.stats()["pages_created"] == 1
    assert sched.job_state(job_c)["status"] == "queued"


def test_dispatch_prefers_higher_priority():
    sched = scheduler()
    low = submit(sched, "obj-low", priority=1)
    high = submit(sched, "obj-high", priority=5)
    sched.allocate_page(low)
    sched.allocate_page(high)
    assert sched.dispatch("w1") == high
    assert sched.job_state(high)["status"] == "running"
    assert sched.job_state(high)["worker"] == "w1"
    assert sched.job_state(low)["status"] == "queued"
    assert sched.dispatch("w2") == low
    assert sched.pending_jobs() == ()
    assert sched.stats()["dispatches"] == 2


def test_start_job_requires_allocation_and_available_worker():
    sched = scheduler(max_workers=1)
    job_a = submit(sched, "obj-a")
    job_b = submit(sched, "obj-b")
    with pytest.raises(lb.LightmapError) as exc:
        sched.start_job(job_a, worker="w1")
    assert exc.value.code == "LIGHTMAP_JOB_NOT_ALLOCATED"

    sched.allocate_page(job_a)
    sched.allocate_page(job_b)
    sched.start_job(job_a, worker="w1")
    with pytest.raises(lb.LightmapError) as busy:
        sched.start_job(job_b, worker="w1")
    assert busy.value.code == "LIGHTMAP_WORKER_BUSY"
    with pytest.raises(lb.LightmapError) as limit:
        sched.start_job(job_b, worker="w2")
    assert limit.value.code == "LIGHTMAP_WORKER_LIMIT"

    sched.release_worker("w1")
    assert sched.job_state(job_a)["status"] == "queued"
    assert sched.job_state(job_a)["worker"] is None
    sched.start_job(job_b, worker="w2")
    assert sched.job_state(job_b)["worker"] == "w2"


def test_report_progress_completes_job_and_frees_worker():
    sched = scheduler()
    job = submit(sched, "obj-a", density=4)
    sched.allocate_page(job)
    sched.start_job(job, worker="w1")
    sched.report_progress(job, page_index=0, progress=0.5, digest="digest-0")
    sched.report_progress(job, page_index=0, progress=1.0, digest="digest-0-final")
    assert sched.job_state(job)["status"] == "running"
    sched.report_progress(job, page_index=1, progress=1.0, digest="digest-1-final")
    state = sched.job_state(job)
    assert state["status"] == "done"
    assert state["worker"] is None
    assert state["progress"] == (1.0, 1.0)
    assert state["digest"] == ("digest-0-final", "digest-1-final")
    assert sched.stats()["completed"] == 1
    assert sched.stats()["progress_reports"] == 3


def test_progress_and_unknown_job_are_rejected():
    sched = scheduler()
    job = submit(sched, "obj-a", density=4)
    sched.allocate_page(job)
    with pytest.raises(lb.LightmapError) as not_running:
        sched.report_progress(job, page_index=0, progress=0.5)
    assert not_running.value.code == "LIGHTMAP_JOB_NOT_RUNNING"

    sched.start_job(job, worker="w1")
    sched.report_progress(job, page_index=0, progress=0.5)
    for call in (
        lambda: sched.report_progress(job, page_index=0, progress=0.4),
        lambda: sched.report_progress(job, page_index=2, progress=0.6),
        lambda: sched.report_progress(job, page_index=1, progress=1.5),
    ):
        with pytest.raises(lb.LightmapError) as exc:
            call()
        assert exc.value.code == "LIGHTMAP_PROGRESS_INVALID"
    state = sched.job_state(job)
    assert state["progress"] == (0.5, 0.0)
    assert state["digest"] == (None, None)

    for call in (
        lambda: sched.job_state("job-9999"),
        lambda: sched.allocate_page("job-9999"),
        lambda: sched.cancel_job("job-9999"),
    ):
        with pytest.raises(lb.LightmapError) as exc:
            call()
        assert exc.value.code == "LIGHTMAP_UNKNOWN_JOB"


def test_cancel_releases_worker_and_resume_requeues():
    sched = scheduler()
    job = submit(sched, "obj-a", density=4)
    sched.allocate_page(job)
    sched.start_job(job, worker="w1")
    sched.report_progress(job, page_index=0, progress=0.5, digest="partial")
    assert sched.cancel_job(job) is True
    state = sched.job_state(job)
    assert state["status"] == "canceled"
    assert state["worker"] is None
    assert state["page"] == 0
    assert state["progress"] == (0.5, 0.0)
    assert sched.pending_jobs() == ()
    assert sched.stats()["canceled"] == 1

    sched.resume(job)
    state = sched.job_state(job)
    assert state["status"] == "queued"
    assert state["page"] == 0
    assert state["slots"] == (0, 1)
    assert state["progress"] == (0.5, 0.0)
    assert sched.stats()["resumed"] == 1
    sched.start_job(job, worker="w2")
    assert sched.job_state(job)["worker"] == "w2"


def test_resume_requires_canceled_job():
    sched = scheduler()
    job = submit(sched, "obj-a")
    with pytest.raises(lb.LightmapError) as queued:
        sched.resume(job)
    assert queued.value.code == "LIGHTMAP_NOT_CANCELED"

    sched.allocate_page(job)
    sched.start_job(job, worker="w1")
    with pytest.raises(lb.LightmapError) as running:
        sched.resume(job)
    assert running.value.code == "LIGHTMAP_NOT_CANCELED"
    assert sched.stats()["resumed"] == 0


def test_failed_job_releases_slots_and_can_be_reallocated():
    sched = scheduler()
    job = submit(sched, "obj-a", density=4)
    sched.allocate_page(job)
    sched.start_job(job, worker="w1")
    sched.report_progress(job, page_index=0, progress=0.25, digest="partial")
    sched.fail_job(job, reason="device lost")
    state = sched.job_state(job)
    assert state["status"] == "failed"
    assert state["worker"] is None
    assert state["attempts"] == 1
    assert sched.pages_of("obj-a") == ()
    assert sched.stats()["failed"] == 1

    again = sched.allocate_page(job)
    assert (again.page, again.slots) == (0, (0, 1))
    assert sched.job_state(job)["status"] == "queued"


def test_concurrent_submit_and_allocate_are_atomic():
    sched = scheduler()
    errors = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            job = sched.submit_job(f"obj-{index}", texel_density=2,
                                   bounds=(8.0, 8.0))
            sched.allocate_page(job)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert sched.stats()["submitted"] == 8
    assert sched.stats()["allocations"] == 8
    assert sched.stats()["pages_created"] == 2
    seen = set()
    for index in range(8):
        allocs = sched.pages_of(f"obj-{index}")
        assert len(allocs) == 1
        for slot in allocs[0].slots:
            key = (allocs[0].page, slot)
            assert key not in seen
            seen.add(key)
    assert len(seen) == 8


def test_snapshot_is_detached_and_restores_runtime():
    sched = scheduler()
    job = submit(sched, "obj-a", density=4)
    sched.allocate_page(job)
    sched.start_job(job, worker="w1")
    sched.report_progress(job, page_index=0, progress=0.5, digest="page-0")
    snap = sched.snapshot()
    assert set(snap) == {"schema", "jobs", "pages", "workers", "stats"}
    pristine = copy.deepcopy(snap)

    snap["jobs"].clear()
    snap["pages"].clear()
    snap["stats"]["completed"] = 99
    assert sched.job_state(job)["progress"] == (0.5, 0.0)
    assert sched.stats()["completed"] == 0

    clone = scheduler()
    clone.restore(pristine)
    state = clone.job_state(job)
    assert state["status"] == "running"
    assert state["worker"] == "w1"
    assert state["progress"] == (0.5, 0.0)
    assert state["digest"] == ("page-0", None)
    assert clone.pages_of("obj-a")[0].slots == (0, 1)
    assert clone.stats()["allocations"] == 1


def test_restore_rejects_malformed_state():
    sched = scheduler()
    job = submit(sched, "obj-a")
    sched.allocate_page(job)
    bad_states = [
        None,
        {},
        {"schema": 1, "jobs": [], "pages": [], "workers": {}},
        {"schema": 1, "jobs": "nope", "pages": [], "workers": {},
         "stats": {}},
        {"schema": 1, "jobs": [], "pages": [], "workers": [], "stats": {}},
        {"schema": 1, "jobs": [], "pages": [], "workers": {},
         "stats": {"completed": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(lb.LightmapError) as exc:
            sched.restore(bad)
        assert exc.value.code == "LIGHTMAP_SNAPSHOT_INVALID"
    assert sched.job_state(job)["page"] == 0
    assert sched.pages_of("obj-a")[0].slots == (0, 1)
