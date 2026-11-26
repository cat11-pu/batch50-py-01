import copy

import pytest

import lightmap_bake_queue as bake


def make(**kwargs):
    return bake.LightmapBakeQueue(**kwargs)


def finish(queue, worker="w1"):
    task = queue.claim(worker)
    return queue.complete(task["task_id"], digest="d-" + task["region"])


def test_submit_returns_task_and_dedups_active_region():
    queue = make()
    task = queue.submit("scene", "r1", priority=2, size=(128, 64))
    assert task["task_id"] == "bake-0001"
    assert task["status"] == "queued"
    assert task["scene"] == "scene"
    assert task["region"] == "r1"
    assert task["priority"] == 2
    assert task["size"] == (128, 64)

    again = queue.submit("scene", "r1", priority=9, size=(128, 64))
    assert again["task_id"] == task["task_id"]
    assert again["priority"] == 2
    assert queue.stats()["submitted"] == 1

    finish(queue)
    fresh = queue.submit("scene", "r1", priority=2, size=(128, 64))
    assert fresh["task_id"] == "bake-0002"
    assert queue.stats()["submitted"] == 2


def test_submit_validates_scene_region_priority_and_size():
    queue = make()
    bad_calls = [
        dict(scene="", region="r1", size=(64, 64)),
        dict(scene="scene", region="", size=(64, 64)),
        dict(scene="scene", region="r1", size=(0, 64)),
        dict(scene="scene", region="r1", size=(64, 0)),
        dict(scene="scene", region="r1", size=(2048, 64)),
        dict(scene="scene", region="r1", size=(64, 2048)),
        dict(scene="scene", region="r1", size=(64,)),
        dict(scene="scene", region="r1", size=(64, "64")),
    ]
    for kwargs in bad_calls:
        with pytest.raises(bake.BakeError) as exc:
            queue.submit(**kwargs)
        assert exc.value.code == "BAKE_INVALID_ARGUMENT"

    for priority in ("high", 1.5, None):
        with pytest.raises(bake.BakeError) as exc:
            queue.submit("scene", "r1", priority=priority, size=(64, 64))
        assert exc.value.code == "BAKE_INVALID_ARGUMENT"


def test_claim_takes_priority_then_fifo_order():
    queue = make()
    queue.submit("scene", "low", priority=1, size=(64, 64))
    queue.submit("scene", "high", priority=5, size=(64, 64))
    queue.submit("scene", "mid", priority=3, size=(64, 64))

    first = queue.claim("w1")
    assert first["region"] == "high"
    finish(queue, "w1")
    second = queue.claim("w2")
    assert second["region"] == "mid"
    finish(queue, "w2")
    third = queue.claim("w3")
    assert third["region"] == "low"

    queue = make()
    queue.submit("scene", "first", size=(64, 64))
    queue.submit("scene", "second", size=(64, 64))
    assert queue.claim("w1")["region"] == "first"
    assert queue.claim("w2")["region"] == "second"


def test_claim_empty_returns_none_and_worker_cannot_hold_two_tasks():
    queue = make()
    assert queue.claim("w1") is None

    queue.submit("scene", "r1", size=(64, 64))
    queue.submit("scene", "r2", size=(64, 64))
    task = queue.claim("w1")
    assert task["status"] == "running"
    assert task["worker"] == "w1"

    with pytest.raises(bake.BakeError) as exc:
        queue.claim("w1")
    assert exc.value.code == "BAKE_WORKER_BUSY"
    assert queue.claim("w2")["region"] == "r2"

    with pytest.raises(bake.BakeError) as exc:
        queue.claim("")
    assert exc.value.code == "BAKE_INVALID_ARGUMENT"


def test_complete_requires_running_task_and_stores_digest():
    queue = make()
    task = queue.submit("scene", "r1", size=(64, 64))
    with pytest.raises(bake.BakeError) as exc:
        queue.complete(task["task_id"], digest="d1")
    assert exc.value.code == "BAKE_NOT_RUNNING"

    claimed = queue.claim("w1")
    with pytest.raises(bake.BakeError) as exc:
        queue.complete(claimed["task_id"], digest="")
    assert exc.value.code == "BAKE_INVALID_ARGUMENT"

    done = queue.complete(claimed["task_id"], digest="sha-r1")
    assert done["status"] == "done"
    assert done["digest"] == "sha-r1"
    assert done["worker"] is None

    queue.submit("scene", "r2", size=(64, 64))
    assert queue.claim("w1")["region"] == "r2"


def test_complete_rejects_unknown_and_double_completion():
    queue = make()
    with pytest.raises(bake.BakeError) as exc:
        queue.complete("bake-9999", digest="d")
    assert exc.value.code == "BAKE_UNKNOWN"

    queue.submit("scene", "r1", size=(64, 64))
    finish(queue)
    with pytest.raises(bake.BakeError) as exc:
        queue.complete("bake-0001", digest="again")
    assert exc.value.code == "BAKE_NOT_RUNNING"


def test_cancel_queued_task_frees_slot_and_rejects_repeat():
    queue = make()
    first = queue.submit("scene", "r1", size=(64, 64))
    queue.submit("scene", "r2", size=(64, 64))

    cancelled = queue.cancel(first["task_id"])
    assert cancelled["status"] == "cancelled"
    assert queue.stats()["cancelled"] == 1
    assert queue.claim("w1")["region"] == "r2"

    with pytest.raises(bake.BakeError) as exc:
        queue.cancel(first["task_id"])
    assert exc.value.code == "BAKE_NOT_CANCELLABLE"
    with pytest.raises(bake.BakeError) as exc:
        queue.cancel("bake-9999")
    assert exc.value.code == "BAKE_UNKNOWN"


def test_cancel_completed_task_is_rejected():
    queue = make()
    task = queue.submit("scene", "r1", size=(64, 64))
    queue.claim("w1")
    queue.complete(task["task_id"], digest="d1")
    with pytest.raises(bake.BakeError) as exc:
        queue.cancel(task["task_id"])
    assert exc.value.code == "BAKE_NOT_CANCELLABLE"


def test_pack_atlas_shelves_regions_and_splits_pages():
    queue = make(page_size=(1024, 1024))
    specs = [("r1", (600, 600)), ("r2", (400, 400)), ("r3", (400, 400)),
             ("r4", (300, 300)), ("r5", (600, 600))]
    for region, size in specs:
        queue.submit("scene", region, size=size)
    for _ in specs:
        finish(queue)

    pages = queue.pack_atlas()
    assert [page["page"] for page in pages] == [0, 1]
    rects = {region: rect for page in pages for region, rect in page["regions"]}
    assert rects == {
        "r1": (0, 0, 600, 600),
        "r2": (600, 0, 400, 400),
        "r3": (0, 600, 400, 400),
        "r4": (400, 600, 300, 300),
        "r5": (0, 0, 600, 600),
    }
    assert [region for region, _ in pages[0]["regions"]] == ["r1", "r2", "r3", "r4"]
    assert [region for region, _ in pages[1]["regions"]] == ["r5"]
    assert queue.stats()["packed_regions"] == 5
    assert queue.stats()["pages"] == 2


def test_pack_atlas_never_packs_a_region_twice():
    queue = make(page_size=(1024, 1024))
    queue.submit("scene", "r1", size=(500, 500))
    finish(queue)

    pages = queue.pack_atlas()
    assert len(pages) == 1
    assert pages[0]["regions"] == [("r1", (0, 0, 500, 500))]
    assert queue.pack_atlas() == []
    assert queue.stats()["packed_regions"] == 1
    assert queue.stats()["pages"] == 1


def test_pack_atlas_never_drops_regions_when_pages_overflow():
    queue = make(page_size=(1024, 1024))
    regions = [f"big-{index}" for index in range(5)]
    for region in regions:
        queue.submit("scene", region, size=(600, 600))
    for _ in regions:
        finish(queue)

    pages = queue.pack_atlas()
    assert len(pages) == 5
    collected = [region for page in pages for region, _ in page["regions"]]
    assert sorted(collected) == sorted(regions)
    assert all(rect == (0, 0, 600, 600) for page in pages for _, rect in page["regions"])


def test_dirty_merge_joins_adjacent_rects_but_not_across_pages():
    queue = make(page_size=(1024, 1024))
    for region, size in (("r1", (600, 600)), ("r2", (400, 400)), ("r3", (600, 600))):
        queue.submit("scene", region, size=size)
    for _ in range(3):
        finish(queue)
    queue.pack_atlas()

    assert queue.dirty_mark("scene", "r1") == 1
    assert queue.dirty_mark("scene", "r1") == 1
    assert queue.dirty_mark("scene", "r2") == 2
    assert queue.dirty_mark("scene", "r3") == 3

    groups = queue.merge_dirty("scene")
    assert [(group["page"], group["regions"], group["bounds"]) for group in groups] == [
        (0, ("r1", "r2"), (0, 0, 1000, 600)),
        (1, ("r3",), (0, 0, 600, 600)),
    ]
    assert queue.merge_dirty("scene") == []


def test_snapshot_is_detached_and_restore_keeps_running_lease():
    queue = make()
    queue.submit("scene", "r1", size=(100, 100))
    queue.submit("scene", "r2", size=(100, 100), priority=2)
    queue.submit("scene", "r3", size=(100, 100))
    running = queue.claim("w1")

    state = queue.snapshot()
    assert state["version"] == 1
    snapshot_copy = copy.deepcopy(state)
    state["tasks"].clear()
    state["stats"]["submitted"] = 99
    assert queue.stats()["submitted"] == 3

    clone = make()
    clone.restore(snapshot_copy)
    assert clone.stats() == queue.stats()
    next_task = clone.claim("w2")
    assert next_task["region"] == "r1"
    done = clone.complete(running["task_id"], digest="d2")
    assert done["status"] == "done"
    assert done["region"] == "r2"


def test_restore_rejects_malformed_state_without_touching_live_data():
    queue = make()
    task = queue.submit("scene", "r1", size=(100, 100))
    before = queue.stats()

    bad_states = [
        None,
        {},
        {"version": 2, "page_size": [1024, 1024], "max_queued": 64,
         "tasks": [], "atlas": [], "dirty": {}, "stats": {}},
        {"version": 1, "page_size": [1024, 1024], "max_queued": 64,
         "tasks": "nope", "atlas": [], "dirty": {}, "stats": {}},
        {"version": 1, "page_size": [0, 1024], "max_queued": 64,
         "tasks": [], "atlas": [], "dirty": {}, "stats": {}},
        {"version": 1, "page_size": [1024, 1024], "max_queued": 64,
         "tasks": [], "atlas": [], "dirty": {}, "stats": {"submitted": -1}},
    ]
    for bad in bad_states:
        with pytest.raises(bake.BakeError) as exc:
            queue.restore(bad)
        assert exc.value.code == "BAKE_SNAPSHOT_INVALID"

    assert queue.stats() == before
    assert queue.claim("w1")["task_id"] == task["task_id"]


def test_stats_track_submit_claim_complete_and_cancel():
    queue = make()
    first = queue.submit("scene", "r1", size=(64, 64))
    second = queue.submit("scene", "r2", size=(64, 64))
    queue.claim("w1")
    queue.complete(first["task_id"], digest="d1")
    queue.cancel(second["task_id"])

    assert queue.stats() == {"submitted": 2, "claimed": 1, "completed": 1,
                             "cancelled": 1, "discarded": 0,
                             "packed_regions": 0, "pages": 0,
                             "reused_pages": 0}
