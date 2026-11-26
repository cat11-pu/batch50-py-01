import threading

import pytest

import vertex_animation_sampler as vas

CLIP = "flap"
MARKERS = [(0.0, 0.0, 0.0), (1.0, 0.0, 0.0), (2.0, 0.0, 0.0),
           (3.0, 0.0, 0.0), (4.0, 0.0, 0.0)]
BBOX = (-1.0, -1.0, -1.0, 1.0, 1.0, 1.0)


def sampler(**kwargs):
    return vas.VertexAnimationSampler(**kwargs)


def with_clip(**kwargs):
    instance = sampler(**kwargs)
    instance.register_clip(CLIP, frames=5, fps=10.0, bbox=BBOX,
                           marker_track=MARKERS)
    return instance


def test_register_clip_reports_metadata():
    instance = with_clip()
    view = instance.clip_view(CLIP)
    assert view.clip_id == CLIP
    assert view.frames == 5
    assert view.fps == 10.0
    assert view.duration == pytest.approx(0.4)
    assert view.bbox == BBOX
    assert view.has_normals is False
    assert view.version == 1
    assert view.instance_count == 0
    norms = instance.register_clip("sway", frames=3, fps=2.0, bbox=BBOX,
                                   marker_track=MARKERS[:3], has_normals=True)
    assert norms.has_normals is True
    assert norms.duration == pytest.approx(1.0)
    assert instance.stats()["clips"] == 2


def test_register_clip_refuses_bad_metadata():
    instance = sampler()
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.register_clip(CLIP, frames=1, fps=10.0, bbox=BBOX,
                               marker_track=MARKERS[:1])
    assert exc.value.code == "VERTANIM_INVALID_REQUEST"
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.register_clip(CLIP, frames=5, fps=0.0, bbox=BBOX,
                               marker_track=MARKERS)
    assert exc.value.code == "VERTANIM_INVALID_REQUEST"
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.register_clip(CLIP, frames=5, fps=10.0,
                               bbox=(1.0, -1.0, -1.0, 1.0, 1.0, 1.0),
                               marker_track=MARKERS)
    assert exc.value.code == "VERTANIM_INVALID_REQUEST"
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.register_clip(CLIP, frames=5, fps=10.0, bbox=BBOX,
                               marker_track=MARKERS[:3])
    assert exc.value.code == "VERTANIM_INVALID_REQUEST"
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.register_clip(CLIP, frames=5, fps=10.0, bbox=BBOX,
                               marker_track=[(0.0, 0.0)] * 5)
    assert exc.value.code == "VERTANIM_INVALID_REQUEST"
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.clip_view("nowhere")
    assert exc.value.code == "VERTANIM_UNKNOWN_CLIP"


def test_register_clip_refuses_duplicate_version():
    instance = with_clip()
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.register_clip(CLIP, frames=5, fps=10.0, bbox=BBOX,
                               marker_track=MARKERS)
    assert exc.value.code == "VERTANIM_CLIP_EXISTS"
    for bad in ("", "   "):
        with pytest.raises(vas.VertexAnimError) as exc:
            instance.register_clip(bad, frames=2, fps=1.0, bbox=BBOX,
                                   marker_track=MARKERS[:2])
        assert exc.value.code == "VERTANIM_INVALID_REQUEST"


def test_acquire_instance_defaults_and_validation():
    instance = with_clip()
    view = instance.acquire_instance("hero", CLIP)
    assert view.instance_id == "hero"
    assert view.clip_id == CLIP
    assert view.mode == "loop"
    assert view.phase == 0.0
    assert view.time == 0.0
    assert view.local_time == 0.0
    assert view.finished is False
    assert view.version == 1
    assert instance.clip_view(CLIP).instance_count == 1
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.acquire_instance("hero", CLIP)
    assert exc.value.code == "VERTANIM_INSTANCE_EXISTS"
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.acquire_instance("other", "nowhere")
    assert exc.value.code == "VERTANIM_UNKNOWN_CLIP"
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.acquire_instance("other", CLIP, mode="pingpong")
    assert exc.value.code == "VERTANIM_INVALID_REQUEST"
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.acquire_instance("other", CLIP, phase="half")
    assert exc.value.code == "VERTANIM_INVALID_REQUEST"
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.instance_view("ghost")
    assert exc.value.code == "VERTANIM_UNKNOWN_INSTANCE"


def test_instance_limit_and_release():
    instance = with_clip(max_instances=2)
    instance.acquire_instance("a", CLIP)
    instance.acquire_instance("b", CLIP)
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.acquire_instance("c", CLIP)
    assert exc.value.code == "VERTANIM_INSTANCE_LIMIT"
    freed = instance.release_instance("a")
    assert freed.instance_id == "a"
    assert instance.clip_view(CLIP).instance_count == 1
    instance.acquire_instance("c", CLIP)
    assert instance.clip_view(CLIP).instance_count == 2
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.release_instance("a")
    assert exc.value.code == "VERTANIM_UNKNOWN_INSTANCE"
    assert instance.stats()["releases"] == 1


def test_advance_accumulates_time():
    instance = with_clip()
    instance.acquire_instance("hero", CLIP)
    first = instance.advance("hero", 0.1)
    assert first.time == pytest.approx(0.1)
    assert first.local_time == pytest.approx(0.1)
    assert first.finished is False
    second = instance.advance("hero", 0.1)
    assert second.time == pytest.approx(0.2)
    third = instance.advance("hero", 0.0)
    assert third.time == pytest.approx(0.2)
    assert instance.stats()["advances"] == 3
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.advance("hero", -0.1)
    assert exc.value.code == "VERTANIM_INVALID_REQUEST"
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.advance("ghost", 0.1)
    assert exc.value.code == "VERTANIM_UNKNOWN_INSTANCE"


def test_sample_between_two_frames():
    instance = with_clip()
    instance.acquire_instance("hero", CLIP)
    instance.advance("hero", 0.15)
    sample = instance.sample_frame("hero")
    assert sample.frame == 1
    assert sample.next_frame == 2
    assert sample.alpha == pytest.approx(0.5)
    assert sample.local_time == pytest.approx(0.15)
    assert sample.mode == "loop"
    assert sample.finished is False
    assert instance.stats()["samples"] == 1


def test_sample_on_exact_frame_and_late_in_span():
    instance = with_clip()
    instance.acquire_instance("edge", CLIP)
    instance.acquire_instance("late", CLIP)
    instance.advance("edge", 0.3)
    boundary = instance.sample_frame("edge")
    assert boundary.frame == 3
    assert boundary.next_frame == 4
    assert boundary.alpha == pytest.approx(0.0, abs=1e-9)
    instance.advance("late", 0.35)
    late = instance.sample_frame("late")
    assert late.frame == 3
    assert late.next_frame == 4
    assert late.alpha == pytest.approx(0.5)


def test_sample_position_interpolates_probe_track():
    instance = with_clip()
    instance.acquire_instance("slow", CLIP)
    instance.acquire_instance("fast", CLIP)
    instance.advance("slow", 0.05)
    instance.advance("fast", 0.15)
    slow = instance.sample_position("slow")
    fast = instance.sample_position("fast")
    assert slow[0] == pytest.approx(0.5)
    assert slow[1] == pytest.approx(0.0)
    assert fast[0] == pytest.approx(1.5)
    assert fast[2] == pytest.approx(0.0)


def test_phase_offsets_the_sampling_window():
    instance = with_clip()
    view = instance.acquire_instance("hero", CLIP, phase=0.25)
    assert view.phase == 0.25
    sample = instance.sample_frame("hero")
    assert sample.phase == 0.25
    assert sample.frame == 1
    assert sample.next_frame == 2
    assert sample.alpha == pytest.approx(0.0, abs=1e-9)
    assert sample.local_time == pytest.approx(0.1)
    instance.set_phase("hero", 0.5)
    shifted = instance.sample_frame("hero")
    assert shifted.phase == 0.5
    assert shifted.frame == 2
    assert shifted.next_frame == 3
    with pytest.raises(vas.VertexAnimError) as exc:
        instance.set_phase("hero", "half")
    assert exc.value.code == "VERTANIM_INVALID_REQUEST"


def test_once_mode_samples_mid_clip():
    instance = with_clip()
    instance.acquire_instance("hero", CLIP, mode="once")
    view = instance.advance("hero", 0.2)
    assert view.mode == "once"
    assert view.finished is False
    sample = instance.sample_frame("hero")
    assert sample.mode == "once"
    assert sample.frame == 2
    assert sample.next_frame == 3
    assert sample.alpha == pytest.approx(0.0, abs=1e-9)
    assert sample.finished is False


def test_clamp_mode_samples_mid_clip():
    instance = with_clip()
    instance.acquire_instance("hero", CLIP, mode="clamp")
    view = instance.advance("hero", 0.25)
    assert view.mode == "clamp"
    assert view.finished is False
    sample = instance.sample_frame("hero")
    assert sample.frame == 2
    assert sample.next_frame == 3
    assert sample.alpha == pytest.approx(0.5)
    assert sample.finished is False


def test_state_cache_shares_slots_and_evicts():
    instance = with_clip(max_state_cache=2)
    for name in ("a", "b", "c"):
        instance.acquire_instance(name, CLIP)
    usage = instance.cache_usage()
    assert usage["entries"] == 1
    assert usage["limit"] == 2
    assert usage["misses"] == 1
    assert usage["hits"] == 2
    instance.acquire_instance("d", CLIP, phase=0.5)
    assert instance.cache_usage()["entries"] == 2
    instance.acquire_instance("e", CLIP, phase=0.25)
    grown = instance.cache_usage()
    assert grown["entries"] == 2
    assert grown["evictions"] == 1
    instance.sample_frame("a")
    rebuilt = instance.cache_usage()
    assert rebuilt["entries"] == 2
    assert rebuilt["misses"] == 4


def test_snapshot_roundtrip_and_invalid_restore():
    instance = with_clip()
    instance.acquire_instance("hero", CLIP, mode="once", phase=0.25)
    instance.advance("hero", 0.2)
    snap = instance.snapshot()
    assert set(snap) >= {"clips", "instances", "stats"}
    snap["instances"].clear()
    assert instance.instance_view("hero").time == pytest.approx(0.2)
    fresh = sampler()
    fresh.restore(instance.snapshot())
    assert fresh.clip_view(CLIP).frames == 5
    assert fresh.instance_view("hero").time == pytest.approx(0.2)
    assert fresh.instance_view("hero").mode == "once"
    assert fresh.sample_frame("hero").frame == 2
    before = fresh.snapshot()
    with pytest.raises(vas.VertexAnimError) as exc:
        fresh.restore({"clips": "not-a-mapping"})
    assert exc.value.code == "VERTANIM_SNAPSHOT_INVALID"
    assert fresh.snapshot() == before


def test_concurrent_advance_serializes_on_one_instance():
    instance = with_clip()
    instance.acquire_instance("hero", CLIP)
    barrier = threading.Barrier(6)
    errors = []

    def worker():
        try:
            barrier.wait(timeout=5)
            instance.advance("hero", 0.05)
        except BaseException as exc:  # noqa: BLE001 - collected for assert
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == []
    assert instance.instance_view("hero").time == pytest.approx(0.3)
    assert instance.stats()["advances"] == 6
