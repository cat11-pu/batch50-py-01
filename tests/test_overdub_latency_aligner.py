import pytest

import overdub_latency_aligner as oa


def aligner(**kwargs):
    kwargs.setdefault("max_latency", 48000)
    kwargs.setdefault("drift_limit", 500)
    kwargs.setdefault("max_tracks", 2)
    return oa.OverdubAligner(**kwargs)


def ready_take(instance, track="vox", take_id="take-1",
               start=1000, length=800):
    instance.place_take(track, take_id, start, length)
    instance.align_take(take_id)
    return take_id


def test_add_track_starts_with_zero_latency():
    instance = aligner()
    spec = instance.add_track("vox", 48000)
    assert spec.track_id == "vox"
    assert spec.sample_rate == 48000
    assert spec.latency_samples == 0
    assert spec.drift_samples == 0
    assert spec.max_latency == 48000


def test_add_track_rejects_duplicate():
    instance = aligner()
    instance.add_track("vox", 48000)
    with pytest.raises(oa.OverdubError) as exc:
        instance.add_track("vox", 44100)
    assert exc.value.code == "OVERDUB_DUPLICATE_TRACK"


def test_add_track_rejects_bad_sample_rate():
    instance = aligner()
    for sample_rate in (0, -48000):
        with pytest.raises(oa.OverdubError) as exc:
            instance.add_track(f"track-{sample_rate}", sample_rate)
        assert exc.value.code == "OVERDUB_INVALID_REQUEST"


def test_track_limit_is_hard_cap():
    instance = aligner(max_tracks=2)
    instance.add_track("vox", 48000)
    instance.add_track("gtr", 48000)
    with pytest.raises(oa.OverdubError) as exc:
        instance.add_track("bass", 48000)
    assert exc.value.code == "OVERDUB_TRACK_LIMIT"
    assert instance.stats()["tracks"] == 2


def test_calibrate_uses_median_measurement():
    instance = aligner()
    instance.add_track("vox", 48000)
    latency = instance.calibrate("vox", [100, 140, 120])
    assert latency == 120
    instance.place_take("vox", "take-1", 1000, 400)
    assert instance.align_take("take-1") == 880
    spec = instance.add_track("gtr", 48000)
    assert spec.latency_samples == 0
    assert instance.stats()["calibrations"] == 1


def test_calibrate_rejects_empty_measurements():
    instance = aligner()
    instance.add_track("vox", 48000)
    with pytest.raises(oa.OverdubError) as exc:
        instance.calibrate("vox", [])
    assert exc.value.code == "OVERDUB_INVALID_REQUEST"


def test_calibrate_flags_drift_beyond_limit():
    instance = aligner(drift_limit=500)
    instance.add_track("vox", 48000)
    with pytest.raises(oa.OverdubError) as exc:
        instance.calibrate("vox", [100, 1300])
    assert exc.value.code == "OVERDUB_DRIFT_EXCEEDED"
    instance.place_take("vox", "take-1", 1000, 400)
    assert instance.align_take("take-1") == 1000
    assert instance.stats()["calibrations"] == 0


def test_drift_estimate_reports_spread():
    instance = aligner()
    instance.add_track("vox", 48000)
    instance.calibrate("vox", [100, 140, 120])
    assert instance.drift_estimate("vox") == 20


def test_set_latency_rejects_over_max_and_negative():
    instance = aligner(max_latency=2000)
    instance.add_track("vox", 48000, max_latency=2000)
    with pytest.raises(oa.OverdubError) as exc:
        instance.set_latency("vox", 2001)
    assert exc.value.code == "OVERDUB_LATENCY_TOO_LARGE"
    with pytest.raises(oa.OverdubError) as exc:
        instance.set_latency("vox", -1)
    assert exc.value.code == "OVERDUB_INVALID_REQUEST"


def test_align_take_subtracts_latency():
    instance = aligner()
    instance.add_track("vox", 48000)
    instance.set_latency("vox", 120)
    take = ready_take(instance, start=1000, length=800)
    assert instance.align_take(take) == 880
    assert instance.take_of(take).aligned_start == 880


def test_place_take_rejects_duplicate_and_negative():
    instance = aligner()
    instance.add_track("vox", 48000)
    instance.place_take("vox", "take-1", 0, 400)
    with pytest.raises(oa.OverdubError) as exc:
        instance.place_take("vox", "take-1", 400, 400)
    assert exc.value.code == "OVERDUB_DUPLICATE_TAKE"
    with pytest.raises(oa.OverdubError) as exc:
        instance.place_take("vox", "take-2", -5, 400)
    assert exc.value.code == "OVERDUB_INVALID_REQUEST"


def test_punch_range_rejects_inverted_span():
    instance = aligner()
    instance.add_track("vox", 48000)
    instance.place_take("vox", "take-1", 0, 1000)
    with pytest.raises(oa.OverdubError) as exc:
        instance.punch_range("take-1", 600, 600)
    assert exc.value.code == "OVERDUB_INVALID_REQUEST"
    with pytest.raises(oa.OverdubError) as exc:
        instance.punch_range("take-1", 600, 1200)
    assert exc.value.code == "OVERDUB_INVALID_REQUEST"
    span = instance.punch_range("take-1", 200, 600)
    assert span.start_sample == 200
    assert span.end_sample == 600
    assert isinstance(span.fade_in, int)
    assert isinstance(span.fade_out, int)


def test_commit_replaces_overlapping_take():
    instance = aligner()
    instance.add_track("vox", 48000)
    first = ready_take(instance, take_id="take-1", start=0, length=1000)
    instance.commit(first)
    second = ready_take(instance, take_id="take-2", start=500, length=1000)
    result = instance.commit(second)
    assert result.replaced is True
    assert result.start_sample == 500
    assert result.end_sample == 1500
    assert result.spans == ((0, 1500),)
    assert instance.take_of(first).status == "replaced"
    assert instance.take_of(second).status == "committed"


def test_commit_merges_adjacent_spans():
    instance = aligner()
    instance.add_track("vox", 48000)
    first = ready_take(instance, take_id="take-1", start=0, length=500)
    instance.commit(first)
    second = ready_take(instance, take_id="take-2", start=500, length=500)
    result = instance.commit(second)
    assert result.replaced is False
    assert result.spans == ((0, 1000),)
    assert instance.committed_spans("vox") == ((0, 1000),)


def test_snapshot_restore_keeps_latency_and_spans():
    instance = aligner()
    instance.add_track("vox", 48000)
    instance.calibrate("vox", [100, 140, 120])
    take = ready_take(instance, start=1000, length=800)
    instance.commit(take)
    state = instance.snapshot()
    other = aligner()
    other.restore(state)
    assert other.committed_spans("vox") == ((1000, 1800),)
    assert other.drift_estimate("vox") == 20
    assert other.take_of(take).status == "committed"
    assert other.stats()["committed"] == 1
