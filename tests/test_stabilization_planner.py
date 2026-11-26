import pytest

import stabilization_planner as sp


def planner(**kwargs):
    kwargs.setdefault("smooth_radius", 1)
    kwargs.setdefault("max_samples", 4096)
    kwargs.setdefault("min_confidence", 0.3)
    return sp.StabilizationPlanner(**kwargs)


SHAKE = [(0.0, 0.0, 1.0), (0.0, 0.0, 1.0), (0.0, 36.0, 1.0),
         (0.0, 0.0, 1.0), (0.0, 0.0, 1.0)]


def registered(instance, clip_id="handheld", width=1920, height=1080):
    instance.register_clip(clip_id, width, height)
    return clip_id


def smoothed(instance, clip_id="handheld"):
    registered(instance, clip_id)
    instance.ingest_motion(clip_id, SHAKE)
    instance.smooth_path(clip_id)
    return clip_id


def test_register_clip_records_dimensions():
    instance = planner()
    spec = instance.register_clip("handheld", 1920, 1080)
    assert spec.clip_id == "handheld"
    assert spec.width == 1920
    assert spec.height == 1080
    assert spec.fps == 60
    assert spec.smooth_radius == 1
    assert spec.sample_count == 0
    assert spec.rolling_shutter == 0
    assert instance.clip_of("handheld") == spec


def test_register_rejects_duplicate():
    instance = planner()
    instance.register_clip("handheld", 1920, 1080)
    with pytest.raises(sp.StabilizationError) as exc:
        instance.register_clip("handheld", 1280, 720)
    assert exc.value.code == "STAB_DUPLICATE_CLIP"


def test_register_rejects_non_positive_size():
    instance = planner()
    for width, height, fps in ((0, 1080, 60), (1920, -1, 60), (1920, 1080, 0)):
        with pytest.raises(sp.StabilizationError) as exc:
            instance.register_clip(f"bad-{width}-{height}-{fps}", width, height,
                                   fps=fps)
        assert exc.value.code == "STAB_INVALID_REQUEST"


def test_ingest_motion_returns_accepted_count():
    instance = planner()
    registered(instance)
    accepted = instance.ingest_motion("handheld", SHAKE)
    assert accepted == 5
    assert instance.clip_of("handheld").sample_count == 5


def test_ingest_motion_rejects_empty_and_bad_confidence():
    instance = planner()
    registered(instance)
    with pytest.raises(sp.StabilizationError) as exc:
        instance.ingest_motion("handheld", [])
    assert exc.value.code == "STAB_INVALID_REQUEST"
    for confidence in (1.4, -0.2):
        with pytest.raises(sp.StabilizationError) as exc:
            instance.ingest_motion("handheld", [(0.0, 0.0, confidence)])
        assert exc.value.code == "STAB_INVALID_SAMPLE"


def test_ingest_motion_respects_sample_limit():
    instance = planner(max_samples=3)
    registered(instance)
    instance.ingest_motion("handheld", SHAKE[:3])
    with pytest.raises(sp.StabilizationError) as exc:
        instance.ingest_motion("handheld", [(0.0, 0.0, 1.0)])
    assert exc.value.code == "STAB_SAMPLE_LIMIT"
    assert instance.clip_of("handheld").sample_count == 3


def test_smooth_path_averages_neighbours():
    instance = planner()
    clip = smoothed(instance)
    path = instance.smooth_path(clip)
    assert len(path) == 5
    assert path[0] == (0.0, 0.0)
    assert path[2] == (0.0, 12.0)
    assert path[3] == (0.0, 12.0)


def test_smooth_path_rejects_unknown_clip():
    instance = planner()
    with pytest.raises(sp.StabilizationError) as exc:
        instance.smooth_path("ghost")
    assert exc.value.code == "STAB_UNKNOWN_CLIP"


def test_smooth_requires_motion():
    instance = planner()
    registered(instance)
    with pytest.raises(sp.StabilizationError) as exc:
        instance.smooth_path("handheld")
    assert exc.value.code == "STAB_INVALID_REQUEST"


def test_plan_crop_returns_one_window_per_sample():
    instance = planner()
    clip = smoothed(instance)
    windows = instance.plan_crop(clip, 1280, 720)
    assert len(windows) == 5
    for window in windows:
        assert window.width == 1280
        assert window.height == 720
    assert instance.stats()["planned"] == 1


def test_plan_crop_requires_smoothing():
    instance = planner()
    registered(instance)
    instance.ingest_motion("handheld", SHAKE)
    with pytest.raises(sp.StabilizationError) as exc:
        instance.plan_crop("handheld", 1280, 720)
    assert exc.value.code == "STAB_NOT_SMOOTHED"


def test_keyframe_crop_takes_every_interval():
    instance = planner()
    clip = smoothed(instance)
    instance.plan_crop(clip, 1280, 720)
    keys = instance.keyframe_crop(clip, 2)
    assert [key.index for key in keys] == [0, 2, 4]
    assert all(key.crop.width == 1280 for key in keys)
    with pytest.raises(sp.StabilizationError) as exc:
        instance.keyframe_crop(clip, 0)
    assert exc.value.code == "STAB_INVALID_REQUEST"


def test_validate_bounds_detects_outside_window():
    instance = planner()
    clip = smoothed(instance)
    assert instance.validate_bounds(clip, sp.CropWindow(0, 0, 1280, 720)) is True
    assert instance.validate_bounds(clip, sp.CropWindow(-5, 0, 1280, 720)) is False
    assert instance.validate_bounds(clip, sp.CropWindow(700, 0, 1280, 720)) is False
    assert instance.validate_bounds(clip, sp.CropWindow(0, 400, 1280, 720)) is False


def test_commit_advances_and_rejects_backwards():
    instance = planner()
    clip = smoothed(instance)
    instance.plan_crop(clip, 1280, 720)
    instance.keyframe_crop(clip, 2)
    assert instance.commit(clip, 3) == 3
    assert instance.committed_keyframes(clip) == 2
    with pytest.raises(sp.StabilizationError) as exc:
        instance.commit(clip, 2)
    assert exc.value.code == "STAB_ORDER_VIOLATION"
    assert instance.commit(clip, 5) == 5
    assert instance.committed_keyframes(clip) == 3


def test_snapshot_restore_round_trip():
    instance = planner()
    clip = smoothed(instance)
    instance.plan_crop(clip, 1280, 720)
    instance.keyframe_crop(clip, 2)
    instance.commit(clip, 3)
    state = instance.snapshot()
    other = planner()
    other.restore(state)
    assert other.committed_keyframes(clip) == 2
    assert other.clip_of(clip).sample_count == 5
    assert [key.index for key in other.keyframe_crop(clip, 2)] == [0, 2, 4]
    assert other.stats()["samples"] == 5
