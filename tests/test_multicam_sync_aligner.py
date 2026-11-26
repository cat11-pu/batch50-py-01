import threading

import pytest

import multicam_sync_aligner as mc

RATE = 8000
WINDOW_MS = 10
WINDOW = 80


def aligner(**kwargs):
    return mc.MulticamSyncAligner(**kwargs)


def envelope(amplitudes):
    samples = []
    for value in amplitudes:
        samples.extend([value] * WINDOW)
    return samples


def noise_envelope(count, seed=12345):
    values = []
    state = seed
    for _ in range(count):
        state = (state * 1103515245 + 12345) % (2 ** 31)
        values.append(round((state % 1000) / 1000.0, 3))
    return values


def shifted(amplitudes, lag):
    if lag > 0:
        return [0.0] * lag + list(amplitudes[:len(amplitudes) - lag])
    if lag < 0:
        return list(amplitudes[-lag:]) + [0.0] * (-lag)
    return list(amplitudes)


def loaded(**kwargs):
    a = aligner(**kwargs)
    ref = noise_envelope(200)
    a.ingest_track("cam-a", envelope(ref), sample_rate=RATE)
    a.ingest_track("cam-b", envelope(shifted(ref, 2)), sample_rate=RATE)
    a.ingest_track("cam-c", envelope(shifted(ref, -1)), sample_rate=RATE)
    return a


def test_ingest_track_returns_index_and_fingerprint_count():
    a = aligner()
    ref = noise_envelope(200)
    assert a.ingest_track("cam-a", envelope(ref), sample_rate=RATE) == 0
    assert a.ingest_track("cam-b", envelope(shifted(ref, 2)), sample_rate=RATE) == 1
    assert a.fingerprint_count("cam-a") == 200
    assert a.fingerprint_count("cam-b") == 200
    assert a.track_info("cam-b").windows == 200


def test_ingest_rejects_empty_or_short_samples():
    a = aligner()
    with pytest.raises(mc.SyncError) as exc:
        a.ingest_track("cam-a", [], sample_rate=RATE)
    assert exc.value.code == "EMPTY_TRACK"
    with pytest.raises(mc.SyncError) as exc:
        a.ingest_track("cam-b", [0.0] * (WINDOW - 1), sample_rate=RATE)
    assert exc.value.code == "EMPTY_TRACK"
    assert a.track_stats()["tracks"] == 0


def test_ingest_rejects_duplicate_track_id():
    a = aligner()
    ref = noise_envelope(40)
    assert a.ingest_track("cam-a", envelope(ref), sample_rate=RATE) == 0
    with pytest.raises(mc.SyncError) as exc:
        a.ingest_track("cam-a", envelope(ref), sample_rate=RATE)
    assert exc.value.code == "DUPLICATE_TRACK"
    assert a.fingerprint_count("cam-a") == 40
    assert a.track_stats()["tracks"] == 1


def test_estimate_offset_recovers_fixed_lag():
    a = loaded()
    est = a.estimate_offset("cam-b", "cam-a")
    assert est.track_id == "cam-b"
    assert est.offset_ms == 20
    assert est.confidence > 0.0
    assert est.ambiguous is False


def test_estimate_and_align_reject_unknown_tracks():
    a = loaded()
    with pytest.raises(mc.SyncError) as exc:
        a.estimate_offset("nope", "cam-a")
    assert exc.value.code == "UNKNOWN_TRACK"
    with pytest.raises(mc.SyncError) as exc:
        a.estimate_offset("cam-b", "nope")
    assert exc.value.code == "UNKNOWN_REFERENCE"
    with pytest.raises(mc.SyncError) as exc:
        a.align("nope")
    assert exc.value.code == "UNKNOWN_REFERENCE"


def test_estimate_offset_is_antisymmetric_when_reference_swaps():
    a = loaded()
    forward = a.estimate_offset("cam-b", "cam-a")
    backward = a.estimate_offset("cam-a", "cam-b")
    assert forward.offset_ms == 20
    assert backward.offset_ms == -20


def test_align_maps_every_track_to_reference_timeline():
    a = loaded()
    mapping = a.align("cam-a")
    assert mapping == {"cam-a": 0, "cam-b": 20, "cam-c": -10}


def test_drift_report_splits_track_into_segments_with_zero_drift():
    a = loaded()
    segments = a.drift_report("cam-b", "cam-a")
    assert [(s.start_ms, s.end_ms) for s in segments] == [(0, 1000), (1000, 2000)]
    assert [s.drift_ppm for s in segments] == [0, 0]


def test_commit_freezes_offsets_and_records_version():
    a = loaded()
    before = a.align("cam-a")
    assert a.commit("v7") == "v7"
    stats = a.track_stats()
    assert stats["commits"] == 1
    assert stats["version"] == "v7"
    assert a.align("cam-a") == before


def test_track_capacity_is_enforced():
    a = aligner(max_tracks=2)
    ref = noise_envelope(50)
    a.ingest_track("t1", envelope(ref), sample_rate=RATE)
    a.ingest_track("t2", envelope(ref), sample_rate=RATE)
    with pytest.raises(mc.SyncError) as exc:
        a.ingest_track("t3", envelope(ref), sample_rate=RATE)
    assert exc.value.code == "TRACK_CAPACITY"
    assert a.fingerprint_count("t1") == 50
    assert a.track_stats()["tracks"] == 2


def test_track_info_reports_rate_windows_and_lock_state():
    a = loaded()
    info = a.track_info("cam-a")
    assert (info.track_id, info.sample_rate, info.windows, info.locked) == (
        "cam-a",
        RATE,
        200,
        False,
    )


def test_snapshot_restore_keeps_alignment_and_counters():
    a = loaded()
    a.align("cam-a")
    a.commit("v3")
    snap = a.snapshot()
    clone = aligner()
    clone.restore(snap)
    assert clone.track_stats() == a.track_stats()
    assert clone.align("cam-a") == a.align("cam-a")
    assert clone.fingerprint_count("cam-b") == 200
    assert clone.track_info("cam-c").windows == 200


def test_restore_rejects_malformed_state_without_touching_data():
    a = loaded()
    before = a.track_stats()
    bad_states = (None, {}, {"version": 1}, {"version": 1, "tracks": "nope"})
    for bad in bad_states:
        with pytest.raises(mc.SyncError) as exc:
            a.restore(bad)
        assert exc.value.code == "SNAPSHOT_INVALID"
    assert a.track_stats() == before
    assert a.align("cam-a") == {"cam-a": 0, "cam-b": 20, "cam-c": -10}


def test_concurrent_estimates_match_sequential_result():
    a = loaded()
    targets = ["cam-b", "cam-c"]
    results = {}
    errors = []
    barrier = threading.Barrier(6)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            results[index] = a.estimate_offset(targets[index % 2], "cam-a").offset_ms
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert [results[i] for i in range(6)] == [20, -10, 20, -10, 20, -10]


def test_track_stats_counts_ingests_and_estimates():
    a = aligner()
    ref = noise_envelope(50)
    a.ingest_track("cam-a", envelope(ref), sample_rate=RATE)
    a.ingest_track("cam-b", envelope(shifted(ref, 1)), sample_rate=RATE)
    a.estimate_offset("cam-b", "cam-a")
    stats = a.track_stats()
    assert stats["tracks"] == 2
    assert stats["ingests"] == 2
    assert stats["estimates"] == 1
    assert stats["commits"] == 0
    assert stats["version"] is None
