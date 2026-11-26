import copy
import threading

import pytest

import hugepage_pool_warden as hp


def warden():
    return hp.HugepagePoolWarden()


def test_add_node_validates_and_reports_initial_layout():
    h = warden()
    h.add_node("n0", 8)
    assert h.node_view("n0") == hp.NodeView("n0", 8, 8, ((0, 8),), ())
    cases = [
        (lambda: h.add_node("n0", 4), "HP_DUPLICATE_NODE"),
        (lambda: h.add_node("n1", 0), "HP_INVALID_REQUEST"),
        (lambda: h.add_node("n1", -2), "HP_INVALID_REQUEST"),
        (lambda: h.add_node("  ", 4), "HP_INVALID_REQUEST"),
        (lambda: h.node_view("nope"), "HP_UNKNOWN_NODE"),
        (lambda: h.defrag("nope"), "HP_UNKNOWN_NODE"),
    ]
    for call, code in cases:
        with pytest.raises(hp.HugepageError) as exc:
            call()
        assert exc.value.code == code
    assert h.stats() == {"nodes": 1, "tenants": 0, "allocations": 0,
                         "releases": 0, "merges": 0}


def test_register_tenant_validates_quota():
    h = warden()
    h.register_tenant("t1", quota=10)
    h.register_tenant("t2", quota=0)
    cases = [
        (lambda: h.register_tenant("t1", quota=5), "HP_DUPLICATE_TENANT"),
        (lambda: h.register_tenant("t3", quota=-1), "HP_INVALID_REQUEST"),
        (lambda: h.register_tenant("  ", quota=5), "HP_INVALID_REQUEST"),
        (lambda: h.usage("ghost"), "HP_UNKNOWN_TENANT"),
        (lambda: h.set_quota("ghost", quota=5), "HP_UNKNOWN_TENANT"),
    ]
    for call, code in cases:
        with pytest.raises(hp.HugepageError) as exc:
            call()
        assert exc.value.code == code
    assert h.tenants() == {"t1": {"quota": 10, "used": 0},
                           "t2": {"quota": 0, "used": 0}}
    assert h.stats()["tenants"] == 2


def test_allocate_takes_lowest_contiguous_run_and_splits():
    h = warden()
    h.add_node("n0", 16)
    h.register_tenant("t1", quota=16)
    alloc = h.allocate("t1", 4, node="n0")
    assert alloc == hp.Allocation("alloc-1", "t1", "n0", 0, 4)
    assert h.node_view("n0") == hp.NodeView("n0", 16, 12, ((4, 12),),
                                            ((0, 4, "t1"),))
    assert h.usage("t1") == 4
    assert h.usage() == {"t1": 4}
    assert h.stats()["allocations"] == 1


def test_allocate_rejects_bad_requests():
    h = warden()
    h.add_node("n0", 4)
    h.register_tenant("t1", quota=4)
    cases = [
        (lambda: h.allocate("t1", 0, node="n0"), "HP_INVALID_REQUEST"),
        (lambda: h.allocate("t1", -1, node="n0"), "HP_INVALID_REQUEST"),
        (lambda: h.allocate("ghost", 1, node="n0"), "HP_UNKNOWN_TENANT"),
        (lambda: h.allocate("t1", 1, node="ghost"), "HP_UNKNOWN_NODE"),
    ]
    for call, code in cases:
        with pytest.raises(hp.HugepageError) as exc:
            call()
        assert exc.value.code == code
    assert h.usage("t1") == 0
    assert h.node_view("n0").free_pages == 4


def test_node_exhausted_when_total_free_is_too_small():
    h = warden()
    h.add_node("n0", 4)
    h.register_tenant("t1", quota=10)
    h.allocate("t1", 3, node="n0")
    with pytest.raises(hp.HugepageError) as exc:
        h.allocate("t1", 2, node="n0")
    assert exc.value.code == "HP_NODE_EXHAUSTED"
    assert h.usage("t1") == 3
    assert h.node_view("n0").free_pages == 1


def test_no_contiguous_run_when_free_pages_are_fragmented():
    h = warden()
    h.add_node("n0", 6)
    h.register_tenant("t1", quota=6)
    first = h.allocate("t1", 2, node="n0")
    second = h.allocate("t1", 2, node="n0")
    third = h.allocate("t1", 2, node="n0")
    assert (first.start, second.start, third.start) == (0, 2, 4)
    h.release(first.alloc_id, tenant="t1")
    h.release(third.alloc_id, tenant="t1")
    view = h.node_view("n0")
    assert (view.free_pages, view.fragments) == (4, ((0, 2), (4, 2)))
    with pytest.raises(hp.HugepageError) as exc:
        h.allocate("t1", 3, node="n0")
    assert exc.value.code == "HP_NO_CONTIGUOUS_RUN"
    assert h.usage("t1") == 2


def test_defrag_merges_adjacent_free_fragments_only():
    h = warden()
    h.add_node("n0", 8)
    h.register_tenant("t1", quota=8)
    first = h.allocate("t1", 2, node="n0")
    second = h.allocate("t1", 2, node="n0")
    h.allocate("t1", 2, node="n0")
    h.release(first.alloc_id, tenant="t1")
    h.release(second.alloc_id, tenant="t1")
    before = h.node_view("n0")
    assert before.fragments == ((0, 2), (2, 2), (6, 2))
    assert before.allocations == ((4, 2, "t1"),)
    assert h.defrag("n0") == 2
    after = h.node_view("n0")
    assert after.fragments == ((0, 4), (6, 2))
    assert after.allocations == ((4, 2, "t1"),)
    assert after.free_pages == 6
    assert h.stats()["merges"] == 2


def test_defrag_is_idempotent_and_scoped_to_one_node():
    h = warden()
    h.add_node("n0", 8)
    h.add_node("n1", 8)
    h.register_tenant("t1", quota=16)
    for node in ("n0", "n1"):
        first = h.allocate("t1", 2, node=node)
        second = h.allocate("t1", 2, node=node)
        h.release(first.alloc_id, tenant="t1")
        h.release(second.alloc_id, tenant="t1")
    assert h.node_view("n0").fragments == ((0, 2), (2, 2), (4, 4))
    assert h.defrag("n0") == 2
    assert h.node_view("n0").fragments == ((0, 8),)
    assert h.node_view("n1").fragments == ((0, 2), (2, 2), (4, 4))
    assert h.defrag("n0") == 0
    assert h.stats()["merges"] == 2


def test_release_requires_known_allocation_and_owner():
    h = warden()
    h.add_node("n0", 8)
    h.register_tenant("t1", quota=8)
    h.register_tenant("t2", quota=8)
    alloc = h.allocate("t1", 3, node="n0")
    with pytest.raises(hp.HugepageError) as exc:
        h.release(alloc.alloc_id, tenant="t2")
    assert exc.value.code == "HP_NOT_OWNER"
    with pytest.raises(hp.HugepageError) as exc:
        h.release("alloc-99", tenant="t1")
    assert exc.value.code == "HP_UNKNOWN_ALLOCATION"
    assert h.allocation_info(alloc.alloc_id) == alloc
    assert h.usage("t1") == 3
    assert h.release(alloc.alloc_id, tenant="t1") == 3
    assert h.usage("t1") == 0
    with pytest.raises(hp.HugepageError) as exc:
        h.release(alloc.alloc_id, tenant="t1")
    assert exc.value.code == "HP_UNKNOWN_ALLOCATION"
    assert h.stats()["releases"] == 1


def test_usage_summary_is_sorted_and_tenant_scoped():
    h = warden()
    h.add_node("n0", 16)
    h.register_tenant("beta", quota=10)
    h.register_tenant("alpha", quota=10)
    h.allocate("beta", 2, node="n0")
    h.allocate("alpha", 5, node="n0")
    assert h.usage() == {"alpha": 5, "beta": 2}
    assert list(h.usage()) == ["alpha", "beta"]
    assert h.usage("alpha") == 5
    assert h.usage("beta") == 2


def test_set_quota_rejects_shrinking_below_usage():
    h = warden()
    h.add_node("n0", 16)
    h.register_tenant("t1", quota=8)
    h.allocate("t1", 4, node="n0")
    with pytest.raises(hp.HugepageError) as exc:
        h.set_quota("t1", quota=3)
    assert exc.value.code == "HP_INVALID_REQUEST"
    assert h.tenants()["t1"]["quota"] == 8
    h.set_quota("t1", quota=12)
    assert h.tenants() == {"t1": {"quota": 12, "used": 4}}


def test_allocation_info_fields_and_unknown_id():
    h = warden()
    h.add_node("n0", 16)
    h.add_node("n1", 16)
    h.register_tenant("t1", quota=20)
    first = h.allocate("t1", 2, node="n0")
    second = h.allocate("t1", 3, node="n1")
    assert (first.alloc_id, first.start, first.count, first.node,
            first.tenant) == ("alloc-1", 0, 2, "n0", "t1")
    assert (second.alloc_id, second.start, second.count) == ("alloc-2", 0, 3)
    with pytest.raises(hp.HugepageError) as exc:
        h.allocation_info("alloc-99")
    assert exc.value.code == "HP_UNKNOWN_ALLOCATION"


def test_snapshot_restore_rebuilds_layout():
    h = warden()
    h.add_node("n0", 8)
    h.register_tenant("t1", quota=8)
    first = h.allocate("t1", 2, node="n0")
    second = h.allocate("t1", 2, node="n0")
    h.release(first.alloc_id, tenant="t1")
    state = h.snapshot()
    assert set(state) == {"version", "nodes", "tenants", "allocations",
                          "fragments", "counters", "next_alloc"}
    pristine = copy.deepcopy(state)
    clone = hp.HugepagePoolWarden()
    clone.restore(pristine)
    assert clone.node_view("n0") == h.node_view("n0")
    assert clone.usage() == {"t1": 2}
    assert clone.allocation_info(second.alloc_id) == second
    assert clone.tenants() == h.tenants()

    state["allocations"].clear()
    assert h.allocation_info(second.alloc_id) == second
    assert pristine["allocations"][second.alloc_id]["count"] == 2


def test_restore_rejects_malformed_snapshot():
    h = warden()
    h.add_node("n0", 8)
    h.register_tenant("t1", quota=8)
    h.allocate("t1", 2, node="n0")
    bad_states = [
        None,
        {},
        {"version": 2, "nodes": {}, "tenants": {}, "allocations": {},
         "fragments": {}, "counters": {}, "next_alloc": 1},
        {"version": 1, "nodes": [], "tenants": {}, "allocations": {},
         "fragments": {}, "counters": {}, "next_alloc": 1},
        {"version": 1, "nodes": {}, "tenants": [], "allocations": {},
         "fragments": {}, "counters": {}, "next_alloc": 1},
        {"version": 1, "nodes": {}, "tenants": {}, "allocations": {},
         "fragments": [], "counters": {}, "next_alloc": 1},
        {"version": 1, "nodes": {}, "tenants": {}, "allocations": {},
         "fragments": {}, "counters": [], "next_alloc": 1},
    ]
    for bad in bad_states:
        with pytest.raises(hp.HugepageError) as exc:
            h.restore(bad)
        assert exc.value.code == "HP_SNAPSHOT_INVALID"
    assert h.node_view("n0").allocations == ((0, 2, "t1"),)
    assert h.usage("t1") == 2


def test_concurrent_allocations_never_overlap():
    h = warden()
    h.add_node("n0", 40)
    h.register_tenant("t1", quota=20)
    results = []
    errors = []
    barrier = threading.Barrier(10)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(h.allocate("t1", 2, node="n0"))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 10
    assert len({alloc.alloc_id for alloc in results}) == 10
    spans = sorted((alloc.start, alloc.start + alloc.count) for alloc in results)
    for left, right in zip(spans, spans[1:]):
        assert left[1] <= right[0]
    assert h.usage("t1") == 20
    assert h.node_view("n0").free_pages == 20
    assert h.stats()["allocations"] == 10
