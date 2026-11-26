import threading

import pytest

import animation_curve_compressor as acc

CLIP = "run-cycle"


def compressor(**kwargs):
    return acc.AnimationCurveCompressor(**kwargs)


def planned(**kwargs):
    instance = compressor(**kwargs)
    instance.register_clip(CLIP, track_count=3, key_budget=8, error_bound=0.5,
                           looping=False)
    return instance


def position_keys():
    return [
        (0, (0.0, 0.0, 0.0)),
        (10, (1.04, 0.0, 0.0)),
        (20, (2.0, 0.0, 0.0)),
    ]


def test_register_clip_stores_budget_and_version():
    instance = compressor()
    view = instance.register_clip(CLIP, track_count=4, key_budget=12,
                                  error_bound=0.25, looping=True)
    assert view.clip_id == CLIP
    assert view.track_count == 4
    assert view.key_budget == 12
    assert view.error_bound == 0.25
    assert view.looping is True
    assert view.version == 1
    assert view.committed_tracks == 0
    assert view.staged_tracks == 0
    defaults = instance.register_clip("idle", track_count=1)
    assert defaults.key_budget == 256
    assert defaults.error_bound == 0.001
    assert defaults.looping is False


def test_clip_registration_refuses_duplicates_and_bad_input():
    instance = compressor()
    instance.register_clip(CLIP, track_count=2)
    with pytest.raises(acc.CurveError) as exc:
        instance.register_clip(CLIP, track_count=2)
    assert exc.value.code == "CURVE_CLIP_EXISTS"
    for bad in ("", "  "):
        with pytest.raises(acc.CurveError) as exc:
            instance.register_clip(bad, track_count=1)
        assert exc.value.code == "CURVE_INVALID_REQUEST"
    with pytest.raises(acc.CurveError) as exc:
        instance.register_clip("jump", track_count=0)
    assert exc.value.code == "CURVE_INVALID_REQUEST"
    with pytest.raises(acc.CurveError) as exc:
        instance.register_clip("jump", track_count=1, key_budget=0)
    assert exc.value.code == "CURVE_INVALID_REQUEST"
    with pytest.raises(acc.CurveError) as exc:
        instance.register_clip("jump", track_count=1, error_bound=0.0)
    assert exc.value.code == "CURVE_INVALID_REQUEST"
    with pytest.raises(acc.CurveError) as exc:
        instance.clip_view("nowhere")
    assert exc.value.code == "CURVE_UNKNOWN_CLIP"


def test_plan_tracks_sorts_names_and_carries_budgets():
    instance = planned()
    plans = instance.plan_tracks(CLIP, [
        ("spine", "scale", [(0, (1.0, 1.0, 1.0)), (10, (1.0, 1.0, 1.0))]),
        ("hips", "position", position_keys()),
    ])
    assert [plan.track for plan in plans] == ["hips", "spine"]
    assert plans[0].kind == "position"
    assert plans[0].key_budget == 8
    assert plans[0].error_bound == 0.5
    assert plans[0].keys[0] == (0, (0.0, 0.0, 0.0))
    assert plans[1].kind == "scale"
    assert instance.stats()["plans"] == 1


def test_plan_tracks_refuses_unknown_kind_and_duplicate_names():
    instance = planned()
    with pytest.raises(acc.CurveError) as exc:
        instance.plan_tracks(CLIP, [("hips", "squash", [(0, (0.0, 0.0, 0.0)),
                                                        (5, (1.0, 0.0, 0.0))])])
    assert exc.value.code == "CURVE_UNKNOWN_KIND"
    with pytest.raises(acc.CurveError) as exc:
        instance.plan_tracks(CLIP, [
            ("hips", "position", [(0, (0.0, 0.0, 0.0)), (5, (1.0, 0.0, 0.0))]),
            ("hips", "position", [(0, (0.0, 0.0, 0.0)), (5, (2.0, 0.0, 0.0))]),
        ])
    assert exc.value.code == "CURVE_INVALID_REQUEST"
    with pytest.raises(acc.CurveError) as exc:
        instance.plan_tracks(CLIP, [("", "position", [(0, (0.0, 0.0, 0.0)),
                                                      (5, (1.0, 0.0, 0.0))])])
    assert exc.value.code == "CURVE_INVALID_REQUEST"
    with pytest.raises(acc.CurveError) as exc:
        instance.plan_tracks(CLIP, [
            ("a", "position", [(0, (0.0, 0.0, 0.0)), (1, (0.0, 0.0, 0.0))]),
            ("b", "position", [(0, (0.0, 0.0, 0.0)), (1, (0.0, 0.0, 0.0))]),
            ("c", "position", [(0, (0.0, 0.0, 0.0)), (1, (0.0, 0.0, 0.0))]),
            ("d", "position", [(0, (0.0, 0.0, 0.0)), (1, (0.0, 0.0, 0.0))]),
        ])
    assert exc.value.code == "CURVE_TRACK_BUDGET"


def test_plan_tracks_refuses_frame_order_and_value_arity():
    instance = planned()
    with pytest.raises(acc.CurveError) as exc:
        instance.plan_tracks(CLIP, [("hips", "position",
                                     [(0, (0.0, 0.0, 0.0)),
                                      (10, (1.0, 0.0, 0.0)),
                                      (10, (2.0, 0.0, 0.0))])])
    assert exc.value.code == "CURVE_FRAME_ORDER"
    with pytest.raises(acc.CurveError) as exc:
        instance.plan_tracks(CLIP, [("hips", "position",
                                     [(0, (0.0, 0.0)), (10, (1.0, 0.0))])])
    assert exc.value.code == "CURVE_INVALID_REQUEST"
    with pytest.raises(acc.CurveError) as exc:
        instance.plan_tracks(CLIP, [("spine", "rotation",
                                     [(0, (0.0, 0.0, 0.0)), (10, (1.0, 0.0, 0.0))])])
    assert exc.value.code == "CURVE_INVALID_REQUEST"
    with pytest.raises(acc.CurveError) as exc:
        instance.plan_tracks(CLIP, [("hips", "position", [(0, (0.0, 0.0, 0.0))])])
    assert exc.value.code == "CURVE_INVALID_REQUEST"


def test_compress_track_drops_collinear_keys():
    instance = planned()
    instance.plan_tracks(CLIP, [("hips", "position", position_keys())])
    report = instance.compress_track(CLIP, "hips")
    assert report.track == "hips"
    assert report.kind == "position"
    assert report.input_count == 3
    assert report.output_count == 2
    assert report.dropped_keys == 1
    assert report.status == "compressed"
    assert report.within_bound is True
    assert report.max_deviation <= 0.5
    assert [frame for frame, _ in report.keys] == [0, 20]
    assert instance.stats()["compressions"] == 1
    with pytest.raises(acc.CurveError) as exc:
        instance.compress_track(CLIP, "tail")
    assert exc.value.code == "CURVE_UNKNOWN_TRACK"


def test_compress_track_quantizes_onto_tolerance_grid():
    instance = planned()
    instance.plan_tracks(CLIP, [("hips", "position", [
        (0, (0.0, 1.03, 0.0)),
        (10, (1.04, 1.04, 0.0)),
        (20, (2.0, 2.02, 0.0)),
    ])])
    report = instance.compress_track(CLIP, "hips")
    assert report.tolerance == 0.5
    assert report.output_count == 2
    for _, values in report.keys:
        for component in values:
            steps = component / 0.5
            assert abs(steps - round(steps)) < 1e-9
    assert report.within_bound is True
    assert report.max_deviation <= 0.5


def test_compress_track_keeps_sharp_corner_keys():
    instance = planned()
    instance.plan_tracks(CLIP, [("hips", "position", [
        (0, (0.0, 0.0, 0.0)),
        (10, (5.0, 0.0, 0.0)),
        (20, (0.0, 0.0, 0.0)),
    ])])
    report = instance.compress_track(CLIP, "hips")
    assert report.input_count == 3
    assert report.output_count == 3
    assert report.dropped_keys == 0
    assert report.status == "kept"
    assert [frame for frame, _ in report.keys] == [0, 10, 20]


def test_compress_tolerance_cannot_exceed_clip_bound():
    instance = planned()
    instance.plan_tracks(CLIP, [("hips", "position", position_keys())])
    with pytest.raises(acc.CurveError) as exc:
        instance.compress_track(CLIP, "hips", tolerance=2.0)
    assert exc.value.code == "CURVE_TOLERANCE_TOO_LOOSE"
    for bad in (0.0, -0.5):
        with pytest.raises(acc.CurveError) as exc:
            instance.compress_track(CLIP, "hips", tolerance=bad)
        assert exc.value.code == "CURVE_INVALID_REQUEST"
    tight = instance.compress_track(CLIP, "hips", tolerance=0.25)
    assert tight.tolerance == 0.25
    assert tight.output_count == 2


def test_track_keys_keep_committed_version_before_commit():
    instance = planned()
    instance.plan_tracks(CLIP, [("hips", "position", position_keys())])
    instance.compress_track(CLIP, "hips")
    keys = instance.track_keys(CLIP, "hips")
    assert [frame for frame, _ in keys] == [0, 10, 20]
    assert instance.clip_view(CLIP).staged_tracks == 1
    assert instance.clip_view(CLIP).version == 1
    assert len(instance.report(CLIP)) == 1


def test_commit_promotes_every_staged_track():
    instance = planned()
    instance.plan_tracks(CLIP, [
        ("hips", "position", position_keys()),
        ("spine", "scale", [(0, (1.0, 1.0, 1.0)), (10, (1.0, 1.0, 1.0)),
                            (20, (3.0, 1.0, 1.0))]),
    ])
    instance.compress_track(CLIP, "hips")
    instance.compress_track(CLIP, "spine")
    view = instance.commit(CLIP)
    assert view.version == 2
    assert view.committed_tracks == 2
    assert view.staged_tracks == 0
    assert [frame for frame, _ in instance.track_keys(CLIP, "hips")] == [0, 20]
    assert instance.report(CLIP) == ()
    assert instance.stats()["commits"] == 1


def test_rollback_discards_staged_reports():
    instance = planned()
    instance.plan_tracks(CLIP, [("hips", "position", position_keys())])
    instance.compress_track(CLIP, "hips")
    view = instance.rollback(CLIP)
    assert view.version == 1
    assert view.staged_tracks == 0
    assert instance.report(CLIP) == ()
    assert [frame for frame, _ in instance.track_keys(CLIP, "hips")] == [0, 10, 20]
    assert instance.stats()["rollbacks"] == 1


def test_loop_validation_requires_looping_clip():
    instance = planned()
    instance.plan_tracks(CLIP, [("hips", "position", position_keys())])
    with pytest.raises(acc.CurveError) as exc:
        instance.validate_loop(CLIP, "hips")
    assert exc.value.code == "CURVE_NOT_LOOPING"
    looped = compressor()
    looped.register_clip("walk", track_count=1, key_budget=8, error_bound=0.5,
                         looping=True)
    looped.plan_tracks("walk", [("hips", "position", [
        (0, (0.0, 0.0, 0.0)),
        (10, (1.0, 0.0, 0.0)),
        (20, (0.0, 0.0, 0.0)),
    ])])
    report = looped.validate_loop("walk", "hips")
    assert report.track == "hips"
    assert report.closure_error == 0.0
    assert report.within_bound is True
    assert report.seam_frame == 20


def test_snapshot_roundtrip_and_invalid_restore():
    instance = planned()
    instance.plan_tracks(CLIP, [("hips", "position", position_keys())])
    instance.compress_track(CLIP, "hips")
    instance.commit(CLIP)
    snap = instance.snapshot()
    assert set(snap) >= {"clips", "stats"}
    snap["clips"].clear()
    assert instance.clip_view(CLIP).version == 2
    fresh = compressor()
    fresh.restore(instance.snapshot())
    assert fresh.clip_view(CLIP).version == 2
    assert [frame for frame, _ in fresh.track_keys(CLIP, "hips")] == [0, 20]
    before = fresh.snapshot()
    with pytest.raises(acc.CurveError) as exc:
        fresh.restore({"clips": "not-a-mapping"})
    assert exc.value.code == "CURVE_SNAPSHOT_INVALID"
    assert fresh.snapshot() == before


def test_concurrent_compression_of_one_track_serializes():
    instance = planned()
    instance.plan_tracks(CLIP, [("hips", "position", position_keys())])
    barrier = threading.Barrier(6)
    errors = []

    def worker():
        try:
            barrier.wait(timeout=5)
            instance.compress_track(CLIP, "hips")
        except BaseException as exc:  # noqa: BLE001 - collected for assert
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == []
    assert instance.stats()["compressions"] == 6
    assert instance.clip_view(CLIP).staged_tracks == 1
    assert len(instance.report(CLIP)) == 1
    assert instance.commit(CLIP).version == 2
