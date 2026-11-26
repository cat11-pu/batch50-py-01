import pytest

import time_stretch_planner as ts


def planner(**kwargs):
    kwargs.setdefault("frame_size", 1024)
    kwargs.setdefault("max_search_window", 512)
    kwargs.setdefault("max_overlap", 256)
    kwargs.setdefault("max_clips", 3)
    return ts.TimeStretchPlanner(**kwargs)


def short_clip(instance, *, ratio=2.0, samples=2304, overlap=256):
    instance.register_clip("tail", 48000, 2, samples,
                           target_ratio=ratio, overlap=overlap)
    instance.plan_stretch("tail")
    return "tail"


def test_register_clip_records_spec():
    instance = planner()
    spec = instance.register_clip("bed-1", 48000, 2, 96000,
                                  target_ratio=1.25, search_window=128,
                                  overlap=64)
    assert spec.clip_id == "bed-1"
    assert spec.sample_rate == 48000
    assert spec.channels == 2
    assert spec.source_samples == 96000
    assert spec.target_ratio == 1.25
    assert spec.search_window == 128
    assert spec.overlap == 64
    assert instance.clip_of("bed-1") == spec


def test_register_rejects_duplicate_clip():
    instance = planner()
    instance.register_clip("bed-1", 48000, 2, 9600)
    with pytest.raises(ts.TimeStretchError) as exc:
        instance.register_clip("bed-1", 44100, 1, 9600)
    assert exc.value.code == "TIME_STRETCH_DUPLICATE_CLIP"


def test_register_rejects_non_positive_sizes():
    instance = planner()
    for sample_rate, channels, samples in ((0, 2, 9600), (48000, 0, 9600),
                                           (48000, 2, 0)):
        with pytest.raises(ts.TimeStretchError) as exc:
            instance.register_clip(f"bad-{sample_rate}-{channels}-{samples}",
                                   sample_rate, channels, samples)
        assert exc.value.code == "TIME_STRETCH_INVALID_REQUEST"


def test_register_rejects_ratio_outside_bounds():
    instance = planner()
    for ratio in (0.1, 4.5):
        with pytest.raises(ts.TimeStretchError) as exc:
            instance.register_clip(f"ratio-{ratio}", 48000, 2, 9600,
                                   target_ratio=ratio)
        assert exc.value.code == "TIME_STRETCH_INVALID_RATIO"


def test_register_rejects_oversized_window_and_overlap():
    instance = planner()
    with pytest.raises(ts.TimeStretchError) as exc:
        instance.register_clip("wide", 48000, 2, 9600, search_window=513)
    assert exc.value.code == "TIME_STRETCH_WINDOW_TOO_LARGE"
    with pytest.raises(ts.TimeStretchError) as exc:
        instance.register_clip("deep", 48000, 2, 9600, overlap=257)
    assert exc.value.code == "TIME_STRETCH_OVERLAP_TOO_LARGE"
    assert instance.stats()["clips"] == 0


def test_clip_limit_is_hard_cap():
    instance = planner(max_clips=3)
    for index in range(3):
        instance.register_clip(f"clip-{index}", 48000, 2, 9600)
    with pytest.raises(ts.TimeStretchError) as exc:
        instance.register_clip("clip-3", 48000, 2, 9600)
    assert exc.value.code == "TIME_STRETCH_CLIP_LIMIT"
    assert instance.stats()["clips"] == 3


def test_plan_stretch_derives_hops():
    instance = planner()
    instance.register_clip("bed", 48000, 2, 96000, target_ratio=1.5,
                           overlap=256)
    plan = instance.plan_stretch("bed")
    assert plan.clip_id == "bed"
    assert plan.ratio == 1.5
    assert plan.analysis_hop == 768
    assert plan.synthesis_hop == 1152
    assert plan.frame_count == 125
    assert plan.overlap == 256


def test_plan_stretch_ratio_override():
    instance = planner()
    instance.register_clip("bed", 48000, 2, 96000, target_ratio=1.5,
                           overlap=256)
    plan = instance.plan_stretch("bed", 0.5)
    assert plan.ratio == 0.5
    assert plan.analysis_hop == 768
    assert plan.synthesis_hop == 384
    assert plan.frame_count == 125
    assert instance.plan_stretch("bed").ratio == 1.5


def test_next_frame_advances_offsets_and_seams():
    instance = planner()
    short_clip(instance)
    first = instance.next_frame("tail")
    assert first.index == 0
    assert first.source_offset == 0
    assert first.output_offset == 0
    assert first.seam is False
    second = instance.next_frame("tail")
    assert second.index == 1
    assert second.source_offset == 768
    assert second.output_offset == 1536
    assert second.seam is True


def test_next_frame_exhausts_frame_count():
    instance = planner()
    short_clip(instance)
    for _ in range(3):
        instance.next_frame("tail")
    with pytest.raises(ts.TimeStretchError) as exc:
        instance.next_frame("tail")
    assert exc.value.code == "TIME_STRETCH_NO_FRAME"
    assert instance.pending("tail") == 0


def test_drain_respects_limit():
    instance = planner()
    short_clip(instance)
    batch = instance.drain("tail", 2)
    assert len(batch) == 2
    assert [frame.index for frame in batch] == [0, 1]
    assert instance.pending("tail") == 1
    with pytest.raises(ts.TimeStretchError) as exc:
        instance.drain("tail", 0)
    assert exc.value.code == "TIME_STRETCH_INVALID_REQUEST"


def test_cancel_stops_frame_production():
    instance = planner()
    short_clip(instance)
    instance.next_frame("tail")
    kept = instance.cancel("tail")
    assert isinstance(kept, int)
    assert kept >= 0
    with pytest.raises(ts.TimeStretchError) as exc:
        instance.next_frame("tail")
    assert exc.value.code == "TIME_STRETCH_CLIP_CANCELLED"
    assert instance.stats()["cancelled"] == 1


def test_snapshot_restore_resumes_progress():
    instance = planner()
    short_clip(instance)
    instance.next_frame("tail")
    instance.next_frame("tail")
    state = instance.snapshot()
    other = planner()
    other.restore(state)
    assert other.pending("tail") == 1
    frame = other.next_frame("tail")
    assert frame.index == 2
    assert frame.source_offset == 1536
    assert other.seam_count("tail") == 2


def test_restore_rejects_broken_snapshot_without_state_loss():
    instance = planner()
    short_clip(instance)
    instance.next_frame("tail")
    with pytest.raises(ts.TimeStretchError) as exc:
        instance.restore({})
    assert exc.value.code == "TIME_STRETCH_SNAPSHOT_INVALID"
    assert instance.pending("tail") == 2


def test_stats_counts_frames_and_seams():
    instance = planner()
    short_clip(instance)
    for _ in range(3):
        instance.next_frame("tail")
    counters = instance.stats()
    assert counters["clips"] == 1
    assert counters["planned"] == 1
    assert counters["frames"] == 3
    assert counters["seams"] == 2
    assert counters["cancelled"] == 0
