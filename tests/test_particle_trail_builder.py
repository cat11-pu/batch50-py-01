import copy
import threading

import pytest

import particle_trail_builder as pt


def builder(**kwargs):
    return pt.ParticleTrailBuilder(**kwargs)


def register(bld, emitter_id="e1", **kwargs):
    kwargs.setdefault("capacity", 8)
    kwargs.setdefault("max_age", 10.0)
    kwargs.setdefault("min_distance", 0.1)
    bld.register_emitter(emitter_id, **kwargs)


def push(bld, emitter_id, x, time, *, width=1.0):
    bld.push_sample(emitter_id, position=(float(x), 0.0), time=float(time),
                    width=width)


def test_register_emitter_reports_state_and_rejects_duplicates():
    bld = builder()
    register(bld, "e1", capacity=16, max_age=3.0, min_distance=0.5, priority=2)
    state = bld.emitter_state("e1")
    assert state["emitter_id"] == "e1"
    assert state["capacity"] == 16
    assert state["max_age"] == 3.0
    assert state["min_distance"] == 0.5
    assert state["priority"] == 2
    assert state["generation"] == 0
    assert state["segment_count"] == 0
    assert state["sample_count"] == 0
    assert state["samples"] == ()
    with pytest.raises(pt.ParticleError) as exc:
        register(bld, "e1")
    assert exc.value.code == "PARTICLE_EMITTER_EXISTS"
    assert bld.stats()["registered"] == 1


def test_register_emitter_rejects_invalid_arguments():
    bld = builder(max_emitters=1)
    bad_calls = [
        lambda: bld.register_emitter("", capacity=8),
        lambda: bld.register_emitter("e1", capacity=1),
        lambda: bld.register_emitter("e2", max_age=0.0),
        lambda: bld.register_emitter("e3", min_distance=-1.0),
    ]
    for call in bad_calls:
        with pytest.raises(pt.ParticleError) as exc:
            call()
        assert exc.value.code == "PARTICLE_INVALID_REQUEST"
    bld.register_emitter("e1", capacity=8)
    with pytest.raises(pt.ParticleError) as exc:
        bld.register_emitter("e2", capacity=8)
    assert exc.value.code == "PARTICLE_EMITTER_LIMIT"
    assert bld.stats()["registered"] == 1


def test_push_sample_keeps_ring_capacity_and_evicts_oldest():
    bld = builder()
    register(bld, "e1", capacity=3, max_age=100.0)
    for index in range(5):
        push(bld, "e1", index * 2, index)
    state = bld.emitter_state("e1")
    assert state["sample_count"] == 3
    assert [sample["position"] for sample in state["samples"]] == [
        (4.0, 0.0), (6.0, 0.0), (8.0, 0.0)]
    assert [sample["time"] for sample in state["samples"]] == [2.0, 3.0, 4.0]
    assert bld.stats()["samples"] == 5
    assert bld.stats()["dropped_capacity"] == 2


def test_push_sample_rejects_invalid_values():
    bld = builder()
    register(bld, "e1")
    push(bld, "e1", 0, 1)
    bad_calls = [
        lambda: bld.push_sample("e1", position=(0.0, 0.0, 0.0), time=2.0),
        lambda: bld.push_sample("e1", position=(0.0, 0.0), time=0.5),
        lambda: bld.push_sample("e1", position=(0.0, 0.0), time=2.0,
                                width=0.0),
        lambda: bld.push_sample("e1", position=(0.0, 0.0), time=2.0,
                                color=(1.0, 0.0, 0.0)),
        lambda: bld.push_sample("e1", position=("a", "b"), time=2.0),
    ]
    for call in bad_calls:
        with pytest.raises(pt.ParticleError) as exc:
            call()
        assert exc.value.code == "PARTICLE_INVALID_REQUEST"
    with pytest.raises(pt.ParticleError) as exc:
        push(bld, "ghost", 0, 0)
    assert exc.value.code == "PARTICLE_UNKNOWN_EMITTER"
    assert bld.emitter_state("e1")["sample_count"] == 1


def test_build_ribbon_emits_two_vertices_per_sample():
    bld = builder()
    register(bld, "e1", capacity=8, max_age=100.0)
    push(bld, "e1", 0, 0, width=2.0)
    push(bld, "e1", 10, 1, width=2.0)
    result = bld.build_ribbon("e1", budget=100)
    assert result["vertex_count"] == 4
    assert result["triangles"] == 2
    assert result["truncated"] is False
    assert [(seg["generation"], seg["sample_count"])
            for seg in result["segments"]] == [(0, 2)]
    flat = [component for vertex in result["vertices"]
            for component in vertex]
    assert flat == pytest.approx([0.0, 1.0, 0.0,
                                  0.0, -1.0, 1.0,
                                  10.0, 1.0, 0.0,
                                  10.0, -1.0, 1.0])
    assert bld.stats()["builds"] == 1


def test_build_ribbon_prunes_samples_older_than_max_age():
    bld = builder()
    register(bld, "e1", capacity=8, max_age=15.0)
    push(bld, "e1", 0, 0, width=2.0)
    push(bld, "e1", 10, 10, width=2.0)
    push(bld, "e1", 20, 20, width=2.0)
    result = bld.build_ribbon("e1")
    assert result["vertex_count"] == 4
    assert bld.emitter_state("e1")["sample_count"] == 2
    assert bld.stats()["expired_samples"] == 1


def test_break_trail_starts_new_segment():
    bld = builder()
    register(bld, "e1", capacity=8, max_age=100.0)
    push(bld, "e1", 0, 0)
    push(bld, "e1", 10, 1)
    assert bld.break_trail("e1", reason="effect reset") == 1
    push(bld, "e1", 20, 2)
    push(bld, "e1", 30, 3)
    segments = bld.segments("e1")
    assert [(seg["generation"], seg["sample_count"]) for seg in segments] == [
        (0, 2), (1, 2)]
    assert bld.emitter_state("e1")["generation"] == 1
    result = bld.build_ribbon("e1")
    assert result["vertex_count"] == 8
    assert result["triangles"] == 4
    assert bld.stats()["breaks"] == 1


def test_build_ribbon_handles_empty_and_single_sample_trails():
    bld = builder()
    register(bld, "e1", capacity=8, max_age=100.0)
    empty = bld.build_ribbon("e1")
    assert empty["vertices"] == ()
    assert empty["vertex_count"] == 0
    assert empty["triangles"] == 0
    assert empty["truncated"] is False
    push(bld, "e1", 0, 0)
    single = bld.build_ribbon("e1")
    assert single["vertices"] == ()
    assert single["vertex_count"] == 0
    assert single["triangles"] == 0
    assert [(seg["generation"], seg["sample_count"])
            for seg in single["segments"]] == [(0, 1)]


def test_emitters_are_listed_by_priority_then_id():
    bld = builder()
    register(bld, "e-low", priority=1)
    register(bld, "e-b", priority=5)
    register(bld, "e-c", priority=5)
    assert bld.emitters() == ("e-b", "e-c", "e-low")


def test_set_budget_and_remove_emitter():
    bld = builder()
    register(bld, "e1")
    bld.set_budget(128)
    for value in (0, -4):
        with pytest.raises(pt.ParticleError) as exc:
            bld.set_budget(value)
        assert exc.value.code == "PARTICLE_INVALID_REQUEST"
    bld.remove_emitter("e1")
    assert bld.emitters() == ()
    assert bld.stats()["removed"] == 1
    with pytest.raises(pt.ParticleError) as exc:
        bld.remove_emitter("e1")
    assert exc.value.code == "PARTICLE_UNKNOWN_EMITTER"


def test_unknown_emitter_is_rejected_across_operations():
    bld = builder()
    calls = [
        lambda: bld.emitter_state("ghost"),
        lambda: bld.push_sample("ghost", position=(0.0, 0.0), time=0.0),
        lambda: bld.build_ribbon("ghost"),
        lambda: bld.break_trail("ghost"),
        lambda: bld.segments("ghost"),
        lambda: bld.remove_emitter("ghost"),
    ]
    for call in calls:
        with pytest.raises(pt.ParticleError) as exc:
            call()
        assert exc.value.code == "PARTICLE_UNKNOWN_EMITTER"


def test_concurrent_push_samples_are_not_lost():
    bld = builder(teleport_distance=10000.0)
    register(bld, "e1", capacity=100, max_age=1000.0, min_distance=0.1)
    errors = []
    barrier = threading.Barrier(2)

    def worker(start):
        try:
            barrier.wait(timeout=5)
            for offset in range(20):
                bld.push_sample("e1", position=(float(start + offset), 0.0),
                                time=1.0)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(0,)),
               threading.Thread(target=worker, args=(100,))]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert bld.emitter_state("e1")["sample_count"] == 40
    assert bld.stats()["samples"] == 40


def test_snapshot_is_detached_and_restores_state():
    bld = builder()
    register(bld, "e1", capacity=8, max_age=100.0)
    push(bld, "e1", 0, 0, width=2.0)
    push(bld, "e1", 10, 1, width=2.0)
    push(bld, "e1", 20, 2, width=2.0)
    snap = bld.snapshot()
    assert set(snap) == {"schema", "emitters", "budget", "stats"}
    pristine = copy.deepcopy(snap)

    snap["emitters"]["e1"]["samples"].clear()
    snap["emitters"]["e1"]["capacity"] = 1
    snap["stats"]["samples"] = 900
    assert bld.emitter_state("e1")["sample_count"] == 3
    assert bld.emitter_state("e1")["capacity"] == 8
    assert bld.stats()["samples"] == 3

    clone = builder()
    clone.restore(pristine)
    state = clone.emitter_state("e1")
    assert state["capacity"] == 8
    assert state["sample_count"] == 3
    assert [sample["position"] for sample in state["samples"]] == [
        (0.0, 0.0), (10.0, 0.0), (20.0, 0.0)]
    assert clone.build_ribbon("e1")["vertex_count"] == 6


def test_restore_rejects_malformed_state():
    bld = builder()
    register(bld, "e1")
    push(bld, "e1", 0, 0)
    bad_states = [
        None,
        {},
        {"schema": 1, "emitters": {}, "budget": 4096},
        {"schema": 1, "emitters": [], "budget": 4096, "stats": {}},
        {"schema": 1, "emitters": {}, "budget": 0, "stats": {}},
        {"schema": 1, "emitters": {}, "budget": 4096, "stats": []},
    ]
    for bad in bad_states:
        with pytest.raises(pt.ParticleError) as exc:
            bld.restore(bad)
        assert exc.value.code == "PARTICLE_SNAPSHOT_INVALID"
    assert bld.emitter_state("e1")["sample_count"] == 1
    assert bld.stats()["samples"] == 1


def test_stats_track_each_operation():
    bld = builder()
    register(bld, "e1", capacity=8, max_age=100.0)
    register(bld, "e2", capacity=8, max_age=100.0)
    push(bld, "e1", 0, 0)
    push(bld, "e1", 10, 1)
    push(bld, "e1", 20, 2)
    bld.break_trail("e1")
    bld.set_budget(64)
    bld.build_ribbon("e1")
    assert bld.stats() == {
        "registered": 2,
        "removed": 0,
        "samples": 3,
        "dropped_capacity": 0,
        "expired_samples": 0,
        "breaks": 1,
        "builds": 1,
        "truncated_builds": 0,
    }
