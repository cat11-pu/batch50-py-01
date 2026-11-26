import threading

import pytest

import svo_residency_manager as svo

VOL = "city"


def manager(**kwargs):
    return svo.SvoResidencyManager(**kwargs)


def with_volume(**kwargs):
    instance = manager(**kwargs)
    instance.declare_volume(VOL, depth=2)
    return instance


def test_declare_volume_creates_root_leaf():
    instance = manager()
    view = instance.declare_volume(VOL, depth=3, bytes_per_voxel=2)
    assert view.volume_id == VOL
    assert view.depth == 3
    assert view.bytes_per_voxel == 2
    assert view.root_morton == 0
    assert view.node_count == 1
    assert view.resident_bricks == 0
    root = instance.node_state(VOL, 0, 0)
    assert root.level == 0
    assert root.morton == 0
    assert root.is_leaf is True
    assert root.refcount == 0
    assert root.lod_refs == 0
    assert root.content_version == 0
    assert root.resident is False
    assert root.rev == 0


def test_duplicate_and_blank_volume_ids_are_refused():
    instance = manager()
    instance.declare_volume(VOL)
    with pytest.raises(svo.SvoError) as exc:
        instance.declare_volume(VOL, depth=2)
    assert exc.value.code == "SVO_VOLUME_EXISTS"
    for bad in ("", "   "):
        with pytest.raises(svo.SvoError) as exc:
            instance.declare_volume(bad)
        assert exc.value.code == "SVO_INVALID_REQUEST"
    with pytest.raises(svo.SvoError) as exc:
        instance.declare_volume("hollow", depth=0)
    assert exc.value.code == "SVO_INVALID_REQUEST"
    with pytest.raises(svo.SvoError) as exc:
        instance.declare_volume("hollow", depth=9)
    assert exc.value.code == "SVO_INVALID_REQUEST"
    with pytest.raises(svo.SvoError) as exc:
        instance.declare_volume("hollow", bytes_per_voxel=0)
    assert exc.value.code == "SVO_INVALID_REQUEST"


def test_unknown_volume_and_node_lookups_are_refused():
    instance = with_volume()
    for call in (
        lambda: instance.volume_view("nowhere"),
        lambda: instance.node_state("nowhere", 0, 0),
        lambda: instance.resident_keys("nowhere"),
        lambda: instance.request_node("nowhere", 0, 0),
    ):
        with pytest.raises(svo.SvoError) as exc:
            call()
        assert exc.value.code == "SVO_UNKNOWN_VOLUME"
    for morton, level in ((3, 1), (0, 1), (0, 2)):
        with pytest.raises(svo.SvoError) as exc:
            instance.node_state(VOL, morton, level)
        assert exc.value.code == "SVO_UNKNOWN_NODE"


def test_request_allocates_one_brick_and_counts():
    instance = with_volume(brick_pool_bytes=4096, brick_bytes=1024)
    node = instance.request_node(VOL, 0, 0)
    assert node.refcount == 1
    assert node.resident is True
    usage = instance.brick_usage()
    assert usage.used_bytes == 1024
    assert usage.limit_bytes == 4096
    assert usage.free_bytes == 3072
    assert usage.resident_bricks == 1
    assert usage.missing_bricks == 0
    again = instance.request_node(VOL, 0, 0)
    assert again.refcount == 2
    assert instance.brick_usage().used_bytes == 1024
    assert instance.resident_keys(VOL) == ((0, 0),)
    assert instance.stats()["requests"] == 2
    with pytest.raises(svo.SvoError) as exc:
        instance.request_node(VOL, 0, 2)
    assert exc.value.code == "SVO_UNKNOWN_NODE"


def test_release_decrements_and_underflow_is_refused():
    instance = with_volume(brick_pool_bytes=4096, brick_bytes=1024)
    instance.request_node(VOL, 0, 0)
    instance.request_node(VOL, 0, 0)
    first = instance.release_node(VOL, 0, 0)
    assert first.refcount == 1
    second = instance.release_node(VOL, 0, 0)
    assert second.refcount == 0
    assert instance.stats()["releases"] == 2
    with pytest.raises(svo.SvoError) as exc:
        instance.release_node(VOL, 0, 0)
    assert exc.value.code == "SVO_REF_UNDERFLOW"
    with pytest.raises(svo.SvoError) as exc:
        instance.release_node(VOL, 5, 1)
    assert exc.value.code == "SVO_UNKNOWN_NODE"


def test_split_creates_eight_children_in_index_order():
    instance = with_volume(depth=2)
    children = instance.split_node(VOL, 0, 0)
    assert len(children) == 8
    assert [child.morton for child in children] == list(range(8))
    assert all(child.level == 1 for child in children)
    assert all(child.is_leaf for child in children)
    assert all(child.refcount == 0 for child in children)
    assert instance.node_state(VOL, 0, 0).is_leaf is False
    assert instance.volume_view(VOL).node_count == 9
    grand = instance.split_node(VOL, 5, 1)
    assert [child.morton for child in grand] == list(range(40, 48))
    assert all(child.level == 2 for child in grand)
    assert instance.volume_view(VOL).node_count == 17
    assert instance.stats()["splits"] == 2


def test_split_refuses_non_leaf_and_depth_limit():
    instance = with_volume(depth=2)
    instance.split_node(VOL, 0, 0)
    with pytest.raises(svo.SvoError) as exc:
        instance.split_node(VOL, 0, 0)
    assert exc.value.code == "SVO_ALREADY_SPLIT"
    instance.split_node(VOL, 0, 1)
    with pytest.raises(svo.SvoError) as exc:
        instance.split_node(VOL, 0, 2)
    assert exc.value.code == "SVO_DEPTH_EXCEEDED"
    with pytest.raises(svo.SvoError) as exc:
        instance.split_node(VOL, 9, 1)
    assert exc.value.code == "SVO_UNKNOWN_NODE"


def test_split_respects_node_budget():
    instance = with_volume(max_nodes=5)
    with pytest.raises(svo.SvoError) as exc:
        instance.split_node(VOL, 0, 0)
    assert exc.value.code == "SVO_NODE_BUDGET"
    assert instance.volume_view(VOL).node_count == 1
    assert instance.node_state(VOL, 0, 0).is_leaf is True
    with pytest.raises(svo.SvoError) as exc:
        instance.node_state(VOL, 0, 1)
    assert exc.value.code == "SVO_UNKNOWN_NODE"
    assert instance.stats()["refusals"] == 1


def test_merge_refuses_missing_or_heterogeneous_children():
    instance = with_volume(depth=2)
    with pytest.raises(svo.SvoError) as exc:
        instance.merge_node(VOL, 0, 0)
    assert exc.value.code == "SVO_NOT_MERGEABLE"
    instance.split_node(VOL, 0, 0)
    instance.tag_node(VOL, 0, 1, 4)
    instance.tag_node(VOL, 1, 1, 4)
    with pytest.raises(svo.SvoError) as exc:
        instance.merge_node(VOL, 0, 0)
    assert exc.value.code == "SVO_NOT_MERGEABLE"
    assert instance.node_state(VOL, 0, 0).is_leaf is False
    assert instance.volume_view(VOL).node_count == 9


def test_merge_collapses_children_into_parent():
    instance = with_volume(depth=2)
    instance.split_node(VOL, 0, 0)
    for index in range(8):
        instance.tag_node(VOL, index, 1, index + 1)
    merged = instance.merge_node(VOL, 0, 0)
    assert merged.level == 0
    assert merged.morton == 0
    assert merged.is_leaf is True
    assert merged.content_version == 8
    assert merged.rev == 2
    assert instance.volume_view(VOL).node_count == 1
    for index in range(8):
        with pytest.raises(svo.SvoError) as exc:
            instance.node_state(VOL, index, 1)
        assert exc.value.code == "SVO_UNKNOWN_NODE"
    assert instance.stats()["merges"] == 1


def test_pool_evicts_least_recently_used_brick():
    instance = with_volume(brick_pool_bytes=2048, brick_bytes=1024)
    instance.split_node(VOL, 0, 0)
    for morton in (1, 2, 3):
        instance.request_node(VOL, morton, 1)
        instance.release_node(VOL, morton, 1)
    assert instance.resident_keys(VOL) == ((1, 2), (1, 3))
    assert instance.brick_usage(VOL).used_bytes == 2048
    assert instance.stats()["evictions"] >= 1
    instance.request_node(VOL, 2, 1)
    instance.request_node(VOL, 3, 1)
    with pytest.raises(svo.SvoError) as exc:
        instance.request_node(VOL, 1, 1)
    assert exc.value.code == "SVO_POOL_EXHAUSTED"
    assert instance.resident_keys(VOL) == ((1, 2), (1, 3))


def test_evict_meets_target_and_reports_shortfall():
    instance = with_volume(brick_pool_bytes=4096, brick_bytes=1024)
    instance.split_node(VOL, 0, 0)
    for morton in (1, 2, 3):
        instance.request_node(VOL, morton, 1)
        instance.release_node(VOL, morton, 1)
    evicted = instance.evict(VOL, needed_bytes=1024)
    assert evicted == ((1, 1),)
    assert instance.resident_keys(VOL) == ((1, 2), (1, 3))
    rest = instance.evict(VOL)
    assert rest == ((1, 2), (1, 3))
    assert instance.brick_usage(VOL).used_bytes == 0
    tight = with_volume(brick_pool_bytes=1024, brick_bytes=1024)
    tight.split_node(VOL, 0, 0)
    tight.request_node(VOL, 0, 1)
    with pytest.raises(svo.SvoError) as exc:
        tight.evict(VOL, needed_bytes=1024)
    assert exc.value.code == "SVO_POOL_EXHAUSTED"
    assert tight.brick_usage(VOL).used_bytes == 1024


def test_brick_usage_stats_and_lod_references():
    instance = manager(brick_pool_bytes=8192, brick_bytes=1024)
    instance.declare_volume("east", depth=2)
    instance.declare_volume("west", depth=2)
    instance.request_node("east", 0, 0)
    instance.request_node("west", 0, 0)
    total = instance.brick_usage()
    assert total.used_bytes == 2048
    assert total.limit_bytes == 8192
    assert total.resident_bricks == 2
    east = instance.brick_usage("east")
    assert east.used_bytes == 1024
    assert east.resident_bricks == 1
    keys = set(instance.stats())
    assert {"volumes", "requests", "releases", "splits", "merges",
            "evictions", "refusals"} <= keys
    instance.attach_lod("east", 2, 0, 0)
    attached = instance.attach_lod("east", 3, 0, 0)
    assert attached.lod_refs == 2
    assert instance.detach_lod("east", 2, 0, 0).lod_refs == 1
    assert instance.detach_lod("east", 3, 0, 0).lod_refs == 0
    with pytest.raises(svo.SvoError) as exc:
        instance.detach_lod("east", 2, 0, 0)
    assert exc.value.code == "SVO_INVALID_REQUEST"
    with pytest.raises(svo.SvoError) as exc:
        instance.attach_lod("east", 1, 4, 1)
    assert exc.value.code == "SVO_UNKNOWN_NODE"


def test_snapshot_roundtrip_and_invalid_restore():
    instance = with_volume(depth=2)
    instance.split_node(VOL, 0, 0)
    instance.request_node(VOL, 1, 1)
    instance.tag_node(VOL, 0, 0, 6)
    snap = instance.snapshot()
    assert set(snap) >= {"volumes", "stats"}
    snap["volumes"].clear()
    assert instance.node_state(VOL, 1, 1).refcount == 1
    fresh = with_volume(depth=2)
    fresh.restore(instance.snapshot())
    assert fresh.node_state(VOL, 1, 1).refcount == 1
    assert fresh.node_state(VOL, 0, 0).content_version == 6
    assert fresh.node_state(VOL, 0, 0).is_leaf is False
    assert fresh.resident_keys(VOL) == ((1, 1),)
    assert fresh.volume_view(VOL).node_count == 9
    before = fresh.snapshot()
    with pytest.raises(svo.SvoError) as exc:
        fresh.restore({"volumes": "not-a-mapping"})
    assert exc.value.code == "SVO_SNAPSHOT_INVALID"
    assert fresh.snapshot() == before


def test_concurrent_requests_on_one_node_keep_refcount():
    instance = with_volume(depth=2)
    instance.split_node(VOL, 0, 0)
    barrier = threading.Barrier(8)
    errors = []

    def worker():
        try:
            barrier.wait(timeout=5)
            instance.request_node(VOL, 3, 1)
        except BaseException as exc:  # noqa: BLE001 - collected for assert
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == []
    assert instance.node_state(VOL, 3, 1).refcount == 8
    assert instance.stats()["requests"] == 8
    assert instance.brick_usage().resident_bricks == 1
