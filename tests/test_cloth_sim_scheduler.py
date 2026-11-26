import copy

import pytest

import cloth_sim_scheduler as cloth


def make(**kwargs):
    return cloth.ClothSimScheduler(**kwargs)


def flat(positions):
    return [value for point in positions for value in point]


def test_register_assigns_tier_and_rejects_duplicates_and_bad_input():
    obj = make()
    near = obj.register("n", vertices=[[0, 0, 0]], distance=1.0)
    mid = obj.register("m", vertices=[[0, 0, 0]], distance=4.0)
    far = obj.register("f", vertices=[[0, 0, 0]], distance=7.0)
    assert (near["tier"], mid["tier"], far["tier"]) == ("near", "mid", "far")
    assert near["attached"] is True
    assert near["frame"] == 0

    with pytest.raises(cloth.ClothError) as exc:
        obj.register("n", vertices=[[0, 0, 0]])
    assert exc.value.code == "CLOTH_DUPLICATE"

    bad_kwargs = [
        dict(vertices=[]),
        dict(vertices=[[0, 0]]),
        dict(vertices=[[0, 0, 0]], pinned=(1,)),
        dict(vertices=[[0, 0, 0]], pinned=(0, 0)),
        dict(vertices=[[0, 0, 0]], rest=[[0, 0, 0], [1, 1, 1]]),
        dict(vertices=[[0, 0, 0]], distance=-1),
    ]
    for kwargs in bad_kwargs:
        with pytest.raises(cloth.ClothError) as exc:
            obj.register("bad", **kwargs)
        assert exc.value.code == "CLOTH_INVALID_ARGUMENT"

    with pytest.raises(cloth.ClothError) as exc:
        obj.register("", vertices=[[0, 0, 0]])
    assert exc.value.code == "CLOTH_INVALID_ARGUMENT"


def test_detach_marks_released_and_returns_vertex_count():
    obj = make()
    obj.register("cape", vertices=[[0, 0, 0], [1, 0, 0]])
    obj.step(0.02)

    out = obj.detach("cape")
    assert out["cloth_id"] == "cape"
    assert out["vertices"] == 2
    assert out["frame"] == 1
    assert out["release_order"] == 1
    state = obj.state_of("cape")
    assert state["attached"] is False
    assert len(state["positions"]) == 2


def test_unregister_requires_detach_and_removes_cloth():
    obj = make()
    obj.register("cape", vertices=[[0, 0, 0]])
    with pytest.raises(cloth.ClothError) as exc:
        obj.unregister("cape")
    assert exc.value.code == "CLOTH_STILL_ATTACHED"

    obj.detach("cape")
    removed = obj.unregister("cape")
    assert removed["cloth_id"] == "cape"
    assert removed["release_order"] == 1
    assert removed["removed"] is True

    with pytest.raises(cloth.ClothError) as exc:
        obj.unregister("cape")
    assert exc.value.code == "CLOTH_UNKNOWN"


def test_step_uses_fixed_timestep_and_carries_remainder():
    obj = make(fixed_step=0.01, substep_budget=8)
    obj.register("cloth", vertices=[[0, 0, 0]])

    first = obj.step(0.025)
    assert first["frame"] == 1
    assert first["requested"] == 2
    assert first["executed"] == 2
    assert first["throttled"] is False
    assert first["accumulator"] == pytest.approx(0.005, abs=1e-9)

    second = obj.step(0.005)
    assert second["frame"] == 2
    assert second["requested"] == 1
    assert second["executed"] == 1
    assert second["accumulator"] == pytest.approx(0.0, abs=1e-9)


def test_step_rejects_non_positive_dt():
    obj = make()
    obj.register("cloth", vertices=[[0, 0, 0]])
    for dt in (0, -0.01, "0.01", None):
        with pytest.raises(cloth.ClothError) as exc:
            obj.step(dt)
        assert exc.value.code == "CLOTH_INVALID_DT"


def test_state_of_unknown_and_pinned_vertices_hold():
    obj = make(fixed_step=0.01, substep_budget=8)
    obj.register("cloth", vertices=[[0, 0, 0], [1, 0, 0]],
                 rest=[[0, 0, 0], [5, 0, 0]], pinned=(0,))

    with pytest.raises(cloth.ClothError) as exc:
        obj.state_of("missing")
    assert exc.value.code == "CLOTH_UNKNOWN"

    obj.step(0.05)
    state = obj.state_of("cloth")
    assert state["frame"] == 1
    assert state["total_substeps"] == 5
    assert list(state["positions"][0]) == [0.0, 0.0, 0.0]
    free_x = state["positions"][1][0]
    assert 1.0 < free_x < 5.0


def test_hidden_cloth_receives_no_substeps():
    obj = make(fixed_step=0.01, substep_budget=4)
    obj.register("visible", vertices=[[0, 0, 0]])
    obj.register("hidden", vertices=[[0, 0, 0]], visible=False)

    report = obj.step(0.02)
    assert report["executed"] == 2
    assert obj.state_of("visible")["last_substeps"] == 2
    assert obj.state_of("hidden")["last_substeps"] == 0


def test_budget_caps_total_substeps_without_skipping_any_cloth():
    obj = make(fixed_step=0.01, substep_budget=4)
    obj.register("near", vertices=[[0, 0, 0]], distance=1.0)
    obj.register("mid", vertices=[[0, 0, 0]], distance=4.0)
    obj.register("far", vertices=[[0, 0, 0]], distance=9.0)

    report = obj.step(0.1)
    assert report["requested"] == 10
    assert report["executed"] == 4
    assert report["throttled"] is True
    counts = [obj.state_of(name)["last_substeps"] for name in ("near", "mid", "far")]
    assert min(counts) >= 1
    assert sum(counts) == 4


def test_budget_smaller_than_visible_cloth_count_rejects_before_update():
    obj = make(fixed_step=0.01, substep_budget=2)
    for name in ("a", "b", "c"):
        obj.register(name, vertices=[[0, 0, 0]])
    before = obj.state_of("a")["positions"]

    with pytest.raises(cloth.ClothError) as exc:
        obj.step(0.02)
    assert exc.value.code == "CLOTH_BUDGET_TOO_SMALL"
    assert obj.stats()["frames"] == 0
    assert obj.state_of("a")["positions"] == before


def test_collision_batch_merges_transitive_overlaps():
    obj = make()
    obj.register("a", vertices=[[0, 0, 0], [1, 0, 0]])
    obj.register("b", vertices=[[2, 0, 0], [3, 0, 0]])
    obj.register("c", vertices=[[0.5, 0, 0], [2.5, 0, 0]])
    obj.register("d", vertices=[[10, 0, 0]])
    obj.register("e", vertices=[[0.2, 0, 0]], visible=False)

    batches = obj.collision_batch()
    assert [(batch["cloths"]) for batch in batches] == [("a", "b", "c"), ("d",)]

    obj.detach("b")
    batches = obj.collision_batch()
    assert [batch["cloths"] for batch in batches] == [("a", "c"), ("d",)]


def test_snapshot_restore_continues_simulation_identically():
    obj = make(fixed_step=0.01, substep_budget=8)
    obj.register("cape", vertices=[[0, 0, 0], [1, 1, 0]],
                 rest=[[0, 2, 0], [3, 1, 0]], pinned=(1,), distance=1.0)
    for _ in range(3):
        obj.step(0.02)

    state = obj.snapshot()
    clone = make(fixed_step=0.01, substep_budget=8)
    clone.restore(copy.deepcopy(state))
    assert flat(clone.state_of("cape")["positions"]) == pytest.approx(
        flat(obj.state_of("cape")["positions"]), abs=1e-9)

    for _ in range(4):
        obj.step(0.02)
        clone.step(0.02)
    assert flat(clone.state_of("cape")["positions"]) == pytest.approx(
        flat(obj.state_of("cape")["positions"]), abs=1e-9)
    assert clone.state_of("cape")["total_substeps"] == obj.state_of("cape")["total_substeps"]
    assert clone.stats() == obj.stats()


def test_restore_rejects_malformed_state_without_touching_live_data():
    obj = make(fixed_step=0.01, substep_budget=8)
    obj.register("cape", vertices=[[0, 0, 0]], rest=[[1, 0, 0]])
    obj.step(0.02)
    before = obj.state_of("cape")["positions"]

    bad_states = [
        None,
        {},
        {"version": 2, "fixed_step": 0.01, "damping": 2.0, "budget": 8,
         "frame": 1, "accumulator": 0.0, "cloths": [], "stats": {}},
        {"version": 1, "fixed_step": 0.01, "damping": 2.0, "budget": 0,
         "frame": 1, "accumulator": 0.0, "cloths": [], "stats": {}},
        {"version": 1, "fixed_step": 0.01, "damping": 2.0, "budget": 8,
         "frame": 1, "accumulator": 0.0, "cloths": "nope", "stats": {}},
        {"version": 1, "fixed_step": 0.01, "damping": 2.0, "budget": 8,
         "frame": 1, "accumulator": 0.0, "cloths": [],
         "stats": {"frames": -1}},
    ]
    for bad in bad_states:
        with pytest.raises(cloth.ClothError) as exc:
            obj.restore(bad)
        assert exc.value.code == "CLOTH_SNAPSHOT_INVALID"

    assert obj.state_of("cape")["positions"] == before
    assert obj.step(0.01)["executed"] == 1


def test_stats_track_registration_steps_and_throttling():
    obj = make(fixed_step=0.01, substep_budget=4)
    obj.register("a", vertices=[[0, 0, 0]])
    obj.register("b", vertices=[[1, 0, 0]])
    obj.step(0.02)
    obj.set_budget(2)
    obj.step(0.05)
    obj.collision_batch()
    obj.detach("a")

    assert obj.stats() == {"frames": 2, "substeps": 4, "registrations": 2,
                           "detaches": 1, "collisions": 1,
                           "throttled_frames": 1}


def test_set_budget_validates_and_applies_immediately():
    obj = make(fixed_step=0.01, substep_budget=8)
    obj.register("cloth", vertices=[[0, 0, 0]])

    for bad in (0, 65, 3.5, "4"):
        with pytest.raises(cloth.ClothError) as exc:
            obj.set_budget(bad)
        assert exc.value.code == "CLOTH_INVALID_BUDGET"

    assert obj.set_budget(1) == 1
    report = obj.step(0.05)
    assert report["requested"] == 5
    assert report["executed"] == 1
    assert report["throttled"] is True


def test_detach_twice_and_unknown_are_rejected():
    obj = make()
    obj.register("cape", vertices=[[0, 0, 0]])
    obj.detach("cape")

    with pytest.raises(cloth.ClothError) as exc:
        obj.detach("cape")
    assert exc.value.code == "CLOTH_ALREADY_DETACHED"

    with pytest.raises(cloth.ClothError) as exc:
        obj.detach("missing")
    assert exc.value.code == "CLOTH_UNKNOWN"
