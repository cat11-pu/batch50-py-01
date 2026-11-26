import pytest

import pitch_correction_planner as pc


def planner(**kwargs):
    kwargs.setdefault("hop", 256)
    kwargs.setdefault("sample_rate", 48000)
    kwargs.setdefault("confidence_floor", 0.5)
    kwargs.setdefault("max_semitones_per_second", 1.5)
    return pc.PitchCorrectionPlanner(**kwargs)


def analyzed_take(instance, take_id="lead", frames=None):
    instance.register_take(take_id, 48000)
    if frames is None:
        frames = [(61.2, 0.9), (66.4, 0.9), (63.4, 0.9)]
    instance.analyze_pitch(take_id, frames)
    return take_id


def test_register_take_records_spec():
    instance = planner()
    spec = instance.register_take("lead", 48000)
    assert spec.take_id == "lead"
    assert spec.sample_rate == 48000
    assert spec.hop == 256
    assert spec.frame_count == 0
    assert spec.root == 0
    assert spec.mode == "major"
    assert spec.preserve_formant is True
    assert instance.take_of("lead") == spec


def test_register_rejects_duplicate():
    instance = planner()
    instance.register_take("lead", 48000)
    with pytest.raises(pc.PitchError) as exc:
        instance.register_take("lead", 44100)
    assert exc.value.code == "PITCH_DUPLICATE_TAKE"


def test_register_rejects_bad_sample_rate():
    instance = planner()
    for sample_rate in (0, -48000):
        with pytest.raises(pc.PitchError) as exc:
            instance.register_take(f"take-{sample_rate}", sample_rate)
        assert exc.value.code == "PITCH_INVALID_REQUEST"
    with pytest.raises(pc.PitchError) as exc:
        instance.register_take("zero-hop", 48000, hop=0)
    assert exc.value.code == "PITCH_INVALID_REQUEST"


def test_analyze_counts_voiced_frames():
    instance = planner()
    instance.register_take("lead", 48000)
    voiced = instance.analyze_pitch(
        "lead", [(60.0, 0.9), (0.0, 0.0), (62.0, 0.2), (64.0, 0.8)])
    assert voiced == 2
    assert instance.take_of("lead").frame_count == 4
    assert instance.confidence_at("lead", 2) == 0.2


def test_analyze_rejects_negative_pitch():
    instance = planner()
    instance.register_take("lead", 48000)
    with pytest.raises(pc.PitchError) as exc:
        instance.analyze_pitch("lead", [(-1.0, 0.9)])
    assert exc.value.code == "PITCH_INVALID_FRAME"


def test_analyze_rejects_bad_confidence():
    instance = planner()
    instance.register_take("lead", 48000)
    for confidence in (1.5, -0.1):
        with pytest.raises(pc.PitchError) as exc:
            instance.analyze_pitch("lead", [(60.0, confidence)])
        assert exc.value.code == "PITCH_INVALID_FRAME"


def test_set_scale_major_and_minor():
    instance = planner()
    instance.register_take("lead", 48000)
    assert instance.set_scale("lead", 0, "major") == (0, 2, 4, 5, 7, 9, 11)
    assert instance.set_scale("lead", 2, "minor") == (0, 2, 4, 5, 7, 9, 10)
    spec = instance.take_of("lead")
    assert spec.root == 2
    assert spec.mode == "minor"


def test_set_scale_rejects_unknown_mode():
    instance = planner()
    instance.register_take("lead", 48000)
    with pytest.raises(pc.PitchError) as exc:
        instance.set_scale("lead", 0, "dorian")
    assert exc.value.code == "PITCH_INVALID_MODE"
    with pytest.raises(pc.PitchError) as exc:
        instance.set_scale("lead", 12, "major")
    assert exc.value.code == "PITCH_INVALID_REQUEST"


def test_plan_correction_snaps_to_scale():
    instance = planner()
    instance.register_take("lead", 48000)
    instance.analyze_pitch("lead", [(61.2, 0.9)])
    plan = instance.plan_correction("lead")
    assert plan.take_id == "lead"
    assert plan.points == 1
    assert plan.scale == (0, 2, 4, 5, 7, 9, 11)
    point = instance.correction_curve("lead")[0]
    assert point.frame == 0
    assert point.source_pitch == 61.2
    assert point.target_pitch == 62.0
    assert point.shift == pytest.approx(0.8)


def test_stats_counts_voiced_and_planned():
    instance = planner()
    instance.register_take("lead", 48000)
    instance.analyze_pitch(
        "lead", [(60.0, 0.9), (0.0, 0.0), (62.0, 0.2), (64.0, 0.8)])
    instance.plan_correction("lead")
    counters = instance.stats()
    assert counters["takes"] == 1
    assert counters["analyzed"] == 1
    assert counters["voiced"] == 2
    assert counters["planned"] == 1
    assert counters["committed"] == 0


def test_correction_curve_is_ordered_and_on_scale():
    instance = planner()
    take = analyzed_take(instance)
    instance.set_scale(take, 0, "major")
    instance.plan_correction(take)
    curve = instance.correction_curve(take)
    frames = [point.frame for point in curve]
    assert frames == sorted(frames)
    scale = set(instance.set_scale(take, 0, "major"))
    for point in curve:
        assert round(point.target_pitch) % 12 in scale
        assert point.target_pitch - point.source_pitch == pytest.approx(
            point.shift)


def test_apply_segment_marks_committed_and_rejects_overlap():
    instance = planner()
    take = analyzed_take(instance)
    instance.plan_correction(take)
    assert instance.apply_segment(take, 0, 2) == 2
    assert instance.committed_frames(take) == 2
    with pytest.raises(pc.PitchError) as exc:
        instance.apply_segment(take, 1, 3)
    assert exc.value.code == "PITCH_ALREADY_COMMITTED"
    assert instance.apply_segment(take, 2, 3) == 1
    assert instance.committed_frames(take) == 3


def test_apply_segment_requires_analysis():
    instance = planner()
    example = instance.register_take("lead", 48000)
    with pytest.raises(pc.PitchError) as exc:
        instance.apply_segment(example.take_id, 0, 1)
    assert exc.value.code == "PITCH_NOT_ANALYZED"


def test_apply_segment_validates_range():
    instance = planner()
    take = analyzed_take(instance)
    instance.plan_correction(take)
    for start, end in ((-1, 2), (2, 2), (0, 99)):
        with pytest.raises(pc.PitchError) as exc:
            instance.apply_segment(take, start, end)
        assert exc.value.code == "PITCH_INVALID_REQUEST"


def test_snapshot_restore_round_trip():
    instance = planner()
    take = analyzed_take(instance)
    instance.set_scale(take, 2, "minor")
    instance.plan_correction(take)
    instance.apply_segment(take, 0, 1)
    state = instance.snapshot()
    other = planner()
    other.restore(state)
    assert other.committed_frames(take) == 1
    assert other.take_of(take).root == 2
    assert other.take_of(take).mode == "minor"
    assert len(other.correction_curve(take)) == 3
    assert other.stats()["voiced"] == 3
