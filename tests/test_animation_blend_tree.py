import copy

import pytest

import animation_blend_tree as blend


def make(**kwargs):
    return blend.AnimationBlendTree(**kwargs)


def test_add_clip_returns_record_and_rejects_bad_input():
    tree = make()
    record = tree.add_clip("walk", layer=0, length=2.0, weight=0.75,
                           phase=0.25, bones={"root": (0, 10), "arm": (10, 30)})
    assert record["clip_id"] == "walk"
    assert record["layer"] == 0
    assert record["length"] == 2.0
    assert record["weight"] == 0.75
    assert record["phase"] == 0.25
    assert record["bones"] == ("arm", "root")

    with pytest.raises(blend.BlendError) as exc:
        tree.add_clip("walk", bones={"root": (0, 1)})
    assert exc.value.code == "BLEND_DUPLICATE"

    bad_calls = [
        dict(clip_id="", bones={"root": (0, 1)}),
        dict(clip_id="x", length=0, bones={"root": (0, 1)}),
        dict(clip_id="x", weight=-0.1, bones={"root": (0, 1)}),
        dict(clip_id="x", weight=1.1, bones={"root": (0, 1)}),
        dict(clip_id="x", phase=-1, bones={"root": (0, 1)}),
        dict(clip_id="x", layer=-1, bones={"root": (0, 1)}),
        dict(clip_id="x", bones={}),
        dict(clip_id="x", bones={"root": (0,)}),
        dict(clip_id="x", bones={"": (0, 1)}),
    ]
    for kwargs in bad_calls:
        with pytest.raises(blend.BlendError) as exc:
            tree.add_clip(**kwargs)
        assert exc.value.code == "BLEND_INVALID_ARGUMENT"


def test_remove_clip_updates_count_and_rejects_unknown():
    tree = make()
    tree.add_clip("walk", bones={"root": (0, 1)})
    tree.add_clip("run", bones={"root": (0, 2)})
    assert tree.stats()["clips"] == 2

    removed = tree.remove_clip("walk")
    assert removed["clip_id"] == "walk"
    assert tree.stats()["clips"] == 1
    with pytest.raises(blend.BlendError) as exc:
        tree.remove_clip("walk")
    assert exc.value.code == "BLEND_UNKNOWN"


def test_set_weight_validates_range_and_unknown_clip():
    tree = make()
    tree.add_clip("walk", bones={"root": (0, 1)})
    assert tree.set_weight("walk", 0.0) == 0.0
    assert tree.set_weight("walk", 0.5) == 0.5
    assert tree.set_weight("walk", 1.0) == 1.0

    for weight in (-0.01, 1.01, "1", None):
        with pytest.raises(blend.BlendError) as exc:
            tree.set_weight("walk", weight)
        assert exc.value.code == "BLEND_INVALID_ARGUMENT"
    with pytest.raises(blend.BlendError) as exc:
        tree.set_weight("missing", 0.5)
    assert exc.value.code == "BLEND_UNKNOWN"


def test_set_phase_validates_and_accepts_wrapping_values():
    tree = make()
    tree.add_clip("walk", bones={"root": (0, 1)})
    assert tree.set_phase("walk", 0.25) == 0.25
    assert tree.set_phase("walk", 3.0) == 3.0

    for phase in (-0.1, float("inf"), "0.5"):
        with pytest.raises(blend.BlendError) as exc:
            tree.set_phase("walk", phase)
        assert exc.value.code == "BLEND_INVALID_ARGUMENT"
    with pytest.raises(blend.BlendError) as exc:
        tree.set_phase("missing", 0.5)
    assert exc.value.code == "BLEND_UNKNOWN"


def test_pose_of_interpolates_each_bone_linearly():
    tree = make()
    tree.add_clip("walk", length=2.0,
                  bones={"root": (0, 10), "arm": (10, 30)})

    early = tree.pose_of("walk", 0.5)
    assert early["bones"]["root"] == pytest.approx(2.5, abs=1e-9)
    assert early["bones"]["arm"] == pytest.approx(15.0, abs=1e-9)

    late = tree.pose_of("walk", 1.5)
    assert late["bones"]["root"] == pytest.approx(7.5, abs=1e-9)
    assert late["bones"]["arm"] == pytest.approx(25.0, abs=1e-9)


def test_pose_of_wraps_phase_around_clip_length():
    tree = make()
    tree.add_clip("walk", length=1.0, phase=0.5, bones={"root": (0, 10)})

    first = tree.pose_of("walk", 0.25)
    assert first["effective"] == pytest.approx(0.75, abs=1e-9)
    assert first["bones"]["root"] == pytest.approx(7.5, abs=1e-9)

    second = tree.pose_of("walk", 0.75)
    assert second["effective"] == pytest.approx(0.25, abs=1e-9)
    assert second["bones"]["root"] == pytest.approx(2.5, abs=1e-9)

    third = tree.pose_of("walk", 1.25)
    assert third["effective"] == pytest.approx(0.75, abs=1e-9)


def test_evaluate_single_clip_matches_pose_of():
    tree = make()
    tree.add_clip("walk", length=1.0, bones={"root": (0, 10), "arm": (0, 20)})
    out = tree.evaluate(0.5)
    assert out["bones"] == pytest.approx(tree.pose_of("walk", 0.5)["bones"], abs=1e-9)
    assert out["fallback"] is False
    assert out["normalized"] is True

    for time in (-0.1, "0.5"):
        with pytest.raises(blend.BlendError) as exc:
            tree.evaluate(time)
        assert exc.value.code == "BLEND_INVALID_ARGUMENT"


def test_evaluate_normalizes_weights_per_bone():
    tree = make()
    tree.add_clip("walk", length=1.0, weight=1.0,
                  bones={"root": (0, 10), "arm": (0, 20)})
    tree.add_clip("run", length=1.0, weight=0.5, bones={"root": (0, 20)})

    out = tree.evaluate(0.5)
    assert out["bones"]["root"] == pytest.approx(10.0 / 1.5, abs=1e-9)
    assert out["bones"]["arm"] == pytest.approx(10.0, abs=1e-9)
    assert out["normalized"] is True


def test_evaluate_zero_weights_fall_back_to_default_pose():
    tree = make(default_pose={"root": 1.5})
    tree.add_clip("walk", length=1.0, weight=0.0, bones={"root": (0, 10)})
    tree.add_clip("run", length=1.0, weight=0.0, bones={"root": (0, 20)})

    out = tree.evaluate(0.5)
    assert out["bones"] == {"root": 1.5}
    assert out["fallback"] is True
    assert out["normalized"] is False

    tree.set_weight("run", 1.0)
    out = tree.evaluate(0.5)
    assert out["bones"] == pytest.approx({"root": 10.0}, abs=1e-9)
    assert out["fallback"] is False


def test_evaluate_is_deterministic_on_repeated_calls():
    tree = make()
    tree.add_clip("walk", length=2.0, weight=0.75, phase=0.1,
                  bones={"root": (0, 10), "arm": (10, 30)})
    tree.add_clip("run", length=2.0, weight=0.5, phase=0.2,
                  bones={"root": (0, 20)})

    first = tree.evaluate(0.5)
    second = tree.evaluate(0.5)
    assert sorted(first["bones"]) == sorted(second["bones"])
    assert first["bones"] == pytest.approx(second["bones"], abs=1e-9)


def test_set_layer_mask_deduplicates_and_validates():
    tree = make()
    tree.add_clip("walk", layer=1, bones={"root": (0, 1)})
    assert tree.set_layer_mask(1, ("root", "arm", "root")) == ("arm", "root")
    assert tree.set_layer_mask(2, ("tail",)) == ("tail",)

    bad_calls = [(-1, ("root",)), (1, ()), (1, ("",)), (1, (1,))]
    for layer, bones in bad_calls:
        with pytest.raises(blend.BlendError) as exc:
            tree.set_layer_mask(layer, bones)
        assert exc.value.code == "BLEND_INVALID_ARGUMENT"


def test_join_sync_group_checks_membership_conflicts_and_length():
    tree = make()
    tree.add_clip("a", length=1.0, bones={"root": (0, 1)})
    tree.add_clip("b", length=2.0, bones={"root": (0, 1)})
    tree.add_clip("c", length=1.0, bones={"root": (0, 1)})

    assert tree.join_sync_group("locomotion", "a") == ("a",)
    assert tree.join_sync_group("locomotion", "a") == ("a",)
    with pytest.raises(blend.BlendError) as exc:
        tree.join_sync_group("locomotion", "b")
    assert exc.value.code == "BLEND_SYNC_LENGTH"
    with pytest.raises(blend.BlendError) as exc:
        tree.join_sync_group("locomotion", "missing")
    assert exc.value.code == "BLEND_UNKNOWN"

    assert tree.join_sync_group("other", "c") == ("c",)
    with pytest.raises(blend.BlendError) as exc:
        tree.join_sync_group("locomotion", "c")
    assert exc.value.code == "BLEND_SYNC_CONFLICT"
    with pytest.raises(blend.BlendError) as exc:
        tree.join_sync_group("", "a")
    assert exc.value.code == "BLEND_INVALID_ARGUMENT"


def test_snapshot_is_detached_and_restore_keeps_pose_state():
    tree = make(default_pose={"root": 0.0})
    tree.add_clip("walk", length=2.0, weight=1.0, phase=0.25,
                  bones={"root": (0, 10), "arm": (10, 30)})
    tree.add_clip("run", length=2.0, weight=0.5, bones={"root": (0, 20)})
    tree.set_weight("run", 0.5)
    tree.set_phase("walk", 0.25)
    tree.join_sync_group("locomotion", "walk")
    tree.join_sync_group("locomotion", "run")
    tree.set_layer_mask(0, ("arm", "root"))
    before = tree.evaluate(0.5)

    state = tree.snapshot()
    assert state["version"] == 1
    snapshot_copy = copy.deepcopy(state)
    state["clips"].clear()
    state["stats"]["evaluations"] = 99
    assert tree.stats()["evaluations"] == 1
    assert tree.stats()["clips"] == 2

    clone = make(default_pose={"root": 0.0})
    clone.restore(snapshot_copy)
    assert clone.stats() == tree.stats()
    after = clone.evaluate(0.5)
    assert after["bones"] == pytest.approx(before["bones"], abs=1e-9)
    assert clone.set_layer_mask(0, ("root",)) == ("root",)


def test_restore_rejects_malformed_state_without_touching_live_data():
    tree = make(default_pose={"root": 0.0})
    tree.add_clip("walk", length=1.0, weight=0.0, bones={"root": (0, 10)})
    before = tree.stats()

    bad_states = [
        None,
        {},
        {"version": 2, "clips": [], "groups": {}, "masks": {},
         "default_pose": {}, "stats": {}},
        {"version": 1, "clips": "nope", "groups": {}, "masks": {},
         "default_pose": {}, "stats": {}},
        {"version": 1, "clips": [], "groups": {}, "masks": {},
         "default_pose": [], "stats": {}},
        {"version": 1, "clips": [], "groups": {}, "masks": {},
         "default_pose": {}, "stats": {"evaluations": -1}},
    ]
    for bad in bad_states:
        with pytest.raises(blend.BlendError) as exc:
            tree.restore(bad)
        assert exc.value.code == "BLEND_SNAPSHOT_INVALID"

    assert tree.stats() == before
    assert tree.evaluate(0.5)["fallback"] is True


def test_stats_track_evaluations_fallback_sync_and_masks():
    tree = make()
    tree.add_clip("walk", length=1.0, bones={"root": (0, 10)})
    tree.add_clip("run", length=1.0, bones={"root": (0, 20)})
    tree.evaluate(0.5)
    tree.set_weight("walk", 0.0)
    tree.set_weight("run", 0.0)
    tree.evaluate(0.5)
    tree.join_sync_group("g", "walk")
    tree.set_layer_mask(0, ("root",))

    assert tree.stats() == {"clips": 2, "evaluations": 2,
                            "fallback_evals": 1, "sync_joins": 1,
                            "mask_updates": 1}
