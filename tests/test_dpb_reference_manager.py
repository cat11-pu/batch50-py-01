import threading

import pytest

import dpb_reference_manager as dpb


def manager(**kwargs):
    return dpb.DpbReferenceManager(**kwargs)


def test_allocate_uses_lowest_free_slot_and_bumps_generation():
    d = manager(capacity=4)
    assert d.allocate(0, 100) == 0
    assert d.allocate(1, 101) == 1
    assert d.mark_output_done(100) is True
    assert d.flush() == 1
    assert d.allocate(2, 102) == 0
    table = d.slot_table()
    assert [(v.slot, v.pic_num) for v in table] == [(0, 102), (1, 101)]
    assert [v.generation for v in table] == [3, 2]


def test_allocate_rejects_duplicate_pic_num():
    d = manager(capacity=4)
    d.allocate(0, 100)
    with pytest.raises(dpb.DpbError) as exc:
        d.allocate(1, 100)
    assert exc.value.code == "DUPLICATE_PIC"
    assert d.stats()["allocated"] == 1
    assert len(d.slot_table()) == 1


def test_allocate_fails_when_all_slots_are_occupied():
    d = manager(capacity=2)
    d.allocate(0, 100)
    d.allocate(1, 101)
    with pytest.raises(dpb.DpbError) as exc:
        d.allocate(2, 102)
    assert exc.value.code == "DPB_FULL"
    assert d.stats()["allocated"] == 2
    assert [v.pic_num for v in d.slot_table()] == [100, 101]


def test_mark_reference_flags_short_term_slot():
    d = manager(capacity=4)
    slot = d.allocate(0, 100)
    assert d.mark_reference(100) == slot
    view = d.slot_table()[0]
    assert view.is_reference is True
    assert view.long_term is False
    assert view.long_term_index == -1
    assert d.stats()["refs"] == 1
    assert d.stats()["long_term_refs"] == 0


def test_mark_reference_rejects_unknown_picture():
    d = manager(capacity=4)
    d.allocate(0, 100)
    with pytest.raises(dpb.DpbError) as exc:
        d.mark_reference(999)
    assert exc.value.code == "UNKNOWN_PIC"
    assert d.stats()["refs"] == 0


def test_sliding_window_releases_oldest_short_term_reference():
    d = manager(capacity=4)
    d.allocate(0, 100)
    d.mark_reference(100)
    d.allocate(1, 101)
    d.mark_reference(101)
    assert d.sliding_window() == [100]
    assert d.get_ref(100) is None
    assert d.get_ref(101) == 1
    assert d.slot_table()[0].is_reference is False
    assert d.stats()["refs"] == 1


def test_sliding_window_keeps_long_term_references():
    d = manager(capacity=4)
    d.allocate(0, 100)
    d.mark_reference(100, long_term=True)
    d.allocate(1, 101)
    d.mark_reference(101)
    assert d.sliding_window() == [101]
    assert d.get_ref(100) == 0
    assert d.get_ref(101) is None
    assert d.stats()["long_term_refs"] == 1


def test_get_ref_returns_slot_with_long_term_index():
    d = manager(capacity=4)
    d.allocate(0, 100)
    d.mark_reference(100, long_term=True)
    assert d.get_ref(100) == 0
    view = d.slot_table()[0]
    assert view.long_term is True
    assert view.long_term_index == 0


def test_clear_refs_drops_marks_but_keeps_slots():
    d = manager(capacity=4)
    d.allocate(0, 100)
    d.mark_reference(100)
    d.allocate(1, 101)
    d.mark_reference(101)
    assert d.clear_refs() == 2
    assert d.get_ref(100) is None
    assert d.get_ref(101) is None
    assert len(d.slot_table()) == 2
    assert d.stats()["refs"] == 0


def test_flush_only_reclaims_output_done_slots():
    d = manager(capacity=4)
    d.allocate(0, 100)
    d.allocate(1, 101)
    assert d.mark_output_done(100) is True
    assert d.flush() == 1
    assert [v.pic_num for v in d.slot_table()] == [101]
    assert d.stats()["freed"] == 1


def test_long_term_reference_limit_is_enforced():
    d = manager(capacity=4, max_long_term=1)
    d.allocate(0, 100)
    d.mark_reference(100, long_term=True)
    d.allocate(1, 101)
    with pytest.raises(dpb.DpbError) as exc:
        d.mark_reference(101, long_term=True)
    assert exc.value.code == "LT_LIMIT"
    assert d.stats()["long_term_refs"] == 1


def test_snapshot_restore_keeps_slots_refs_and_counters():
    d = manager(capacity=4, max_long_term=2)
    d.allocate(0, 100)
    d.mark_reference(100, long_term=True)
    d.allocate(1, 101)
    d.mark_reference(101)
    d.allocate(2, 102)
    d.mark_output_done(102)
    snap = d.snapshot()
    clone = manager()
    clone.restore(snap)
    assert clone.stats() == d.stats()
    assert [(v.slot, v.pic_num, v.is_reference, v.long_term, v.long_term_index,
             v.output_done) for v in clone.slot_table()] == [
        (v.slot, v.pic_num, v.is_reference, v.long_term, v.long_term_index,
         v.output_done) for v in d.slot_table()
    ]
    assert clone.get_ref(100) == 0
    assert clone.allocate(3, 103) == 3


def test_restore_rejects_malformed_state_without_touching_slots():
    d = manager(capacity=4)
    d.allocate(0, 100)
    d.mark_reference(100)
    before = d.stats()
    bad_states = (None, {}, {"version": 1}, {"version": 1, "slots": "nope"})
    for bad in bad_states:
        with pytest.raises(dpb.DpbError) as exc:
            d.restore(bad)
        assert exc.value.code == "SNAPSHOT_INVALID"
    assert d.stats() == before
    assert d.get_ref(100) == 0


def test_concurrent_get_ref_and_output_marking_stay_consistent():
    d = manager(capacity=8)
    for index in range(6):
        d.allocate(index, 100 + index)
    for index in range(3):
        d.mark_reference(100 + index)
    errors = []
    barrier = threading.Barrier(6)

    def reader(index):
        try:
            barrier.wait(timeout=5)
            assert d.get_ref(100 + index) == index
            assert len(d.slot_table()) == 6
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    def writer(index):
        try:
            barrier.wait(timeout=5)
            assert d.mark_output_done(103 + index) is True
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=reader, args=(i,)) for i in range(3)]
    threads += [threading.Thread(target=writer, args=(i,)) for i in range(3)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert d.stats()["refs"] == 3
    done = {v.pic_num for v in d.slot_table() if v.output_done}
    assert done == {103, 104, 105}


def test_slot_table_is_sorted_and_stats_report_capacity():
    d = manager(capacity=5, max_long_term=3)
    d.allocate(0, 100)
    d.allocate(1, 101)
    d.mark_reference(100, long_term=True)
    stats = d.stats()
    assert stats["capacity"] == 5
    assert stats["refs"] == 1
    assert stats["long_term_refs"] == 1
    assert stats["gaps"] == 0
    assert [v.slot for v in d.slot_table()] == [0, 1]
