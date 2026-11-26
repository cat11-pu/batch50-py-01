import threading

import pytest

import feedback_suppressor as fs


def suppressor(**kwargs):
    return fs.FeedbackSuppressor(**kwargs)


def spectrum(peak_bin, bins=64, base=0.05, peak=0.9):
    values = [base] * bins
    values[peak_bin] = peak
    return values


def test_feed_spectrum_returns_frame_index():
    s = suppressor()
    assert s.feed_spectrum(spectrum(20)) == 0
    assert s.feed_spectrum(spectrum(20)) == 1
    assert s.stats()["frames"] == 2


def test_feed_spectrum_rejects_length_mismatch():
    s = suppressor()
    assert s.feed_spectrum(spectrum(20, bins=64)) == 0
    with pytest.raises(fs.FeedbackError) as exc:
        s.feed_spectrum([0.0] * 32)
    assert exc.value.code == "SPECTRUM_LENGTH"
    assert s.stats()["frames"] == 1


def test_detect_feedback_finds_narrow_peak_bin():
    s = suppressor()
    for _ in range(3):
        s.feed_spectrum(spectrum(20))
    peaks = s.detect_feedback()
    assert len(peaks) == 1
    assert peaks[0].bin_index == 20
    assert peaks[0].freq_hz == 7500.0
    assert peaks[0].confirmed is True


def test_detect_feedback_requires_three_frames():
    s = suppressor()
    s.feed_spectrum(spectrum(20))
    first = s.detect_feedback()
    assert len(first) == 1
    assert first[0].confirmed is False
    assert first[0].confidence == 0.33

    s.feed_spectrum(spectrum(20))
    assert s.detect_feedback()[0].confidence == 0.67

    s.feed_spectrum(spectrum(20))
    confirmed = s.detect_feedback()
    assert confirmed[0].confirmed is True
    assert confirmed[0].confidence == 1.0
    assert s.stats()["confirmed"] == 1


def test_detect_feedback_ignores_flat_spectrum():
    s = suppressor()
    for _ in range(4):
        s.feed_spectrum([0.1] * 64)
    assert s.detect_feedback() == []
    assert s.stats()["confirmed"] == 0


def test_allocate_notch_assigns_ids_and_default_depth():
    s = suppressor()
    assert s.allocate_notch(3000.0) == 1
    assert s.allocate_notch(1200.0) == 2
    table = {n.notch_id: n for n in s.notch_table()}
    assert table[1].freq_hz == 3000.0
    assert table[1].depth_db == -6.0
    assert table[1].remaining_ms == 500


def test_allocate_notch_respects_capacity():
    s = suppressor(notch_cap=2)
    s.allocate_notch(1000.0)
    s.allocate_notch(2000.0)
    with pytest.raises(fs.FeedbackError) as exc:
        s.allocate_notch(3000.0)
    assert exc.value.code == "NOTCH_CAPACITY"
    stats = s.stats()
    assert stats["allocated"] == 2
    assert stats["rejections"] == 1
    assert len(s.notch_table()) == 2


def test_release_notch_is_idempotent():
    s = suppressor()
    notch_id = s.allocate_notch(1500.0)
    assert s.release_notch(notch_id) is True
    assert s.release_notch(notch_id) is False
    assert s.notch_table() == []
    assert s.stats()["released"] == 1


def test_set_ceiling_validates_range():
    s = suppressor()
    assert s.set_ceiling(-12.0) == -12.0
    for bad in (1.5, 0.0, -25.0):
        with pytest.raises(fs.FeedbackError) as exc:
            s.set_ceiling(bad)
        assert exc.value.code == "INVALID_CEILING"
    assert s.stats()["ceiling_db"] == -12.0


def test_notch_table_is_sorted_by_frequency():
    s = suppressor()
    s.allocate_notch(2000.0)
    s.allocate_notch(1000.0)
    assert [(n.freq_hz, n.notch_id) for n in s.notch_table()] == [
        (1000.0, 2),
        (2000.0, 1),
    ]


def test_set_sample_rate_updates_bin_width():
    s = suppressor()
    assert s.set_sample_rate(24000) == 187.5
    assert s.stats()["sample_rate"] == 24000
    s.feed_spectrum(spectrum(20))
    peaks = s.detect_feedback()
    assert peaks[0].freq_hz == 3750.0
    assert peaks[0].confirmed is False


def test_advance_time_rejects_negative_milliseconds():
    s = suppressor()
    with pytest.raises(fs.FeedbackError) as exc:
        s.advance_time(-5)
    assert exc.value.code == "INVALID_TIME"
    assert s.advance_time(0) == 0


def test_snapshot_restore_keeps_notches_and_counters():
    s = suppressor(notch_cap=4)
    s.feed_spectrum(spectrum(20))
    s.allocate_notch(3000.0)
    s.allocate_notch(1200.0)
    snap = s.snapshot()
    clone = suppressor()
    clone.restore(snap)
    assert clone.stats() == s.stats()
    assert [(n.notch_id, n.freq_hz, n.depth_db, n.remaining_ms)
            for n in clone.notch_table()] == [
        (n.notch_id, n.freq_hz, n.depth_db, n.remaining_ms)
        for n in s.notch_table()
    ]
    assert clone.allocate_notch(2500.0) == 3


def test_restore_rejects_malformed_state_without_touching_table():
    s = suppressor()
    s.allocate_notch(1000.0)
    before = s.stats()
    bad_states = (None, {}, {"version": 1}, {"version": 1, "notches": "nope"})
    for bad in bad_states:
        with pytest.raises(fs.FeedbackError) as exc:
            s.restore(bad)
        assert exc.value.code == "SNAPSHOT_INVALID"
    assert s.stats() == before
    assert [n.notch_id for n in s.notch_table()] == [1]


def test_concurrent_allocate_does_not_exceed_capacity():
    s = suppressor(notch_cap=4)
    results = {}
    errors = []
    barrier = threading.Barrier(10)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            results[index] = s.allocate_notch(500.0 + index * 100)
        except fs.FeedbackError as exc:
            results[index] = exc.code
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    accepted = [value for value in results.values() if isinstance(value, int)]
    rejected = [value for value in results.values() if value == "NOTCH_CAPACITY"]
    assert len(accepted) == 4
    assert len(rejected) == 6
    assert len(s.notch_table()) == 4
    assert s.stats()["rejections"] == 6
