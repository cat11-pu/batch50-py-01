import copy
import math
import threading

import pytest

import pose_blend_stack as ps

IDENTITY = (0.0, 0.0, 0.0, 1.0)
TURN_HALF = (0.0, 0.0, 1.0, 0.0)


def stack(**kwargs):
    return ps.PoseBlendStack(**kwargs)


def angle_of(quaternion):
    w = min(1.0, abs(quaternion[3]))
    return math.degrees(2.0 * math.acos(w))


def test_add_layer_stores_order_and_rejects_duplicates():
    stack_ = stack()
    stack_.add_layer("base", weight=1.0)
    assert stack_.layers() == ("base",)
    state = stack_.layer_state("base")
    assert state["layer_id"] == "base"
    assert state["mode"] == "override"
    assert state["weight"] == 1.0
    assert state["pose"] == {}
    assert stack_.stats()["layers_added"] == 1
    with pytest.raises(ps.PoseError) as exc:
        stack_.add_layer("base")
    assert exc.value.code == "POSE_LAYER_EXISTS"


def test_add_layer_rejects_invalid_arguments_and_limits():
    stack_ = stack()
    bad_calls = [
        lambda: stack_.add_layer(""),
        lambda: stack_.add_layer("l1", mode="multiply"),
        lambda: stack_.add_layer("l2", weight=-0.1),
        lambda: stack_.add_layer("l3", mask="nope"),
        lambda: stack_.add_layer("l4", mask={"": 1.0}),
        lambda: stack_.add_layer("l5", mask={"root": 1.5}),
    ]
    for call in bad_calls:
        with pytest.raises(ps.PoseError) as exc:
            call()
        assert exc.value.code == "POSE_INVALID_REQUEST"

    layered = stack(max_layers=1)
    layered.add_layer("base")
    with pytest.raises(ps.PoseError) as exc:
        layered.add_layer("extra")
    assert exc.value.code == "POSE_LAYER_LIMIT"

    masked = stack(max_mask_bones=2)
    with pytest.raises(ps.PoseError) as exc:
        masked.add_layer("base", mask={"a": 1.0, "b": 1.0, "c": 1.0})
    assert exc.value.code == "POSE_MASK_LIMIT"


def test_push_pose_rejects_bad_quaternions_and_unknown_layers():
    stack_ = stack()
    stack_.add_layer("base")
    bad_calls = [
        lambda: stack_.push_pose("base", []),
        lambda: stack_.push_pose("base", {"": IDENTITY}),
        lambda: stack_.push_pose("base", {"root": (0.0, 0.0, 1.0)}),
        lambda: stack_.push_pose("base", {"root": (0.0, 0.0, 0.0, 0.0)}),
        lambda: stack_.push_pose("base", {"root": (0.0, 0.0, "x", 1.0)}),
    ]
    for call in bad_calls:
        with pytest.raises(ps.PoseError) as exc:
            call()
        assert exc.value.code in {"POSE_INVALID_REQUEST", "POSE_INVALID_POSE"}
    with pytest.raises(ps.PoseError) as exc:
        stack_.push_pose("ghost", {"root": IDENTITY})
    assert exc.value.code == "POSE_UNKNOWN_LAYER"
    assert stack_.layer_state("base")["pose"] == {}


def test_evaluate_single_identity_layer():
    stack_ = stack()
    stack_.add_layer("base")
    stack_.push_pose("base", {"root": IDENTITY})
    result = stack_.evaluate()
    assert result["revision"] == 1
    assert set(result["pose"]) == {"root"}
    assert result["pose"]["root"] == pytest.approx(IDENTITY)


def test_equal_weight_overlay_blends_halfway():
    stack_ = stack()
    stack_.add_layer("base")
    stack_.add_layer("turn")
    stack_.push_pose("base", {"root": IDENTITY})
    stack_.push_pose("turn", {"root": TURN_HALF})
    result = stack_.evaluate()
    assert angle_of(result["pose"]["root"]) == pytest.approx(90.0, abs=1e-6)


def test_overlay_weights_are_normalized():
    stack_ = stack()
    stack_.add_layer("base", weight=1.0)
    stack_.add_layer("turn", weight=3.0)
    stack_.push_pose("base", {"root": IDENTITY})
    stack_.push_pose("turn", {"root": TURN_HALF})
    result = stack_.evaluate()
    assert angle_of(result["pose"]["root"]) == pytest.approx(135.0, abs=1e-6)


def test_set_weight_changes_blend_and_validates():
    stack_ = stack()
    stack_.add_layer("base", weight=1.0)
    stack_.add_layer("turn", weight=0.0)
    stack_.push_pose("base", {"root": IDENTITY})
    stack_.push_pose("turn", {"root": TURN_HALF})
    assert angle_of(stack_.evaluate()["pose"]["root"]) == pytest.approx(0.0)
    stack_.set_weight("turn", 1.0)
    assert angle_of(stack_.evaluate()["pose"]["root"]) == pytest.approx(
        90.0, abs=1e-6)
    assert stack_.layer_state("turn")["weight"] == 1.0
    with pytest.raises(ps.PoseError) as exc:
        stack_.set_weight("turn", -1.0)
    assert exc.value.code == "POSE_INVALID_REQUEST"
    assert stack_.layer_state("turn")["weight"] == 1.0


def test_mask_weight_scales_one_bone():
    stack_ = stack()
    stack_.add_layer("base", weight=1.0)
    stack_.add_layer("turn", weight=1.0, mask={"hand": 0.5})
    stack_.push_pose("base", {"hand": IDENTITY})
    stack_.push_pose("turn", {"hand": TURN_HALF})
    result = stack_.evaluate()
    assert angle_of(result["pose"]["hand"]) == pytest.approx(60.0, abs=1e-6)


def test_set_mask_updates_layer_state_and_blend():
    stack_ = stack()
    stack_.add_layer("base", weight=1.0)
    stack_.add_layer("turn", weight=1.0)
    stack_.push_pose("base", {"hand": IDENTITY})
    stack_.push_pose("turn", {"hand": TURN_HALF})
    assert angle_of(stack_.evaluate()["pose"]["hand"]) == pytest.approx(
        90.0, abs=1e-6)
    stack_.set_mask("turn", {"hand": 1.0})
    assert stack_.layer_state("turn")["mask"] == {"hand": 1.0}
    assert angle_of(stack_.evaluate()["pose"]["hand"]) == pytest.approx(
        90.0, abs=1e-6)
    with pytest.raises(ps.PoseError) as exc:
        stack_.set_mask("turn", {"hand": 2.0})
    assert exc.value.code == "POSE_INVALID_REQUEST"
    assert stack_.layer_state("turn")["mask"] == {"hand": 1.0}


def test_remove_layer_updates_stack_and_stats():
    stack_ = stack()
    stack_.add_layer("base", weight=1.0)
    stack_.add_layer("turn", weight=3.0)
    stack_.push_pose("base", {"root": IDENTITY})
    stack_.push_pose("turn", {"root": TURN_HALF})
    assert angle_of(stack_.evaluate()["pose"]["root"]) == pytest.approx(
        135.0, abs=1e-6)
    stack_.remove_layer("turn")
    assert stack_.layers() == ("base",)
    assert angle_of(stack_.evaluate()["pose"]["root"]) == pytest.approx(0.0)
    assert stack_.stats()["layers_removed"] == 1
    with pytest.raises(ps.PoseError) as exc:
        stack_.layer_state("turn")
    assert exc.value.code == "POSE_UNKNOWN_LAYER"


def test_history_is_capped_to_max_history():
    stack_ = stack(max_history=3)
    stack_.add_layer("base")
    stack_.push_pose("base", {"root": IDENTITY})
    for _ in range(5):
        stack_.evaluate()
    rows = stack_.history()
    assert len(rows) == 3
    assert [row["revision"] for row in rows] == [3, 4, 5]
    assert all("pose" in row for row in rows)


def test_concurrent_evaluations_are_stable():
    stack_ = stack()
    stack_.add_layer("base", weight=1.0)
    stack_.add_layer("turn", weight=3.0)
    stack_.push_pose("base", {"root": IDENTITY})
    stack_.push_pose("turn", {"root": TURN_HALF})
    errors = []
    angles = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            for _ in range(5):
                angles.append(angle_of(stack_.evaluate()["pose"]["root"]))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(angles) == 40
    assert all(value == pytest.approx(135.0, abs=1e-6) for value in angles)
    assert stack_.stats()["evaluations"] == 40
    assert stack_.layers() == ("base", "turn")
    rows = stack_.history()
    assert len(rows) == 8
    assert rows[-1]["revision"] == 40


def test_snapshot_is_detached_from_live_layers():
    stack_ = stack()
    stack_.add_layer("base", weight=1.0)
    stack_.add_layer("turn", weight=3.0)
    stack_.push_pose("base", {"root": IDENTITY})
    stack_.push_pose("turn", {"root": TURN_HALF})
    stack_.evaluate()
    snap = stack_.snapshot()
    assert set(snap) == {"schema", "layers", "history", "stats"}
    pristine = copy.deepcopy(snap)

    snap["layers"].clear()
    snap["history"].clear()
    snap["stats"]["evaluations"] = 99
    assert stack_.layers() == ("base", "turn")
    assert stack_.layer_state("turn")["weight"] == 3.0
    assert angle_of(stack_.evaluate()["pose"]["root"]) == pytest.approx(
        135.0, abs=1e-6)
    assert stack_.stats()["evaluations"] == 2


def test_restore_rejects_malformed_state():
    stack_ = stack()
    stack_.add_layer("base")
    stack_.push_pose("base", {"root": IDENTITY})
    stack_.evaluate()
    bad_states = [
        None,
        {},
        {"schema": 1, "layers": [], "history": []},
        {"schema": 1, "layers": {}, "history": [], "stats": {}},
        {"schema": 1, "layers": [], "history": [], "stats": []},
        {"schema": 1, "layers": [{"layer_id": ""}], "history": [], "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(ps.PoseError) as exc:
            stack_.restore(bad)
        assert exc.value.code == "POSE_SNAPSHOT_INVALID"
    assert stack_.layers() == ("base",)
    assert stack_.history()[-1]["revision"] == 1


def test_stats_track_each_operation():
    stack_ = stack()
    stack_.add_layer("base", weight=1.0)
    stack_.add_layer("turn", weight=3.0)
    stack_.push_pose("base", {"root": IDENTITY})
    stack_.evaluate()
    stack_.set_weight("turn", 0.5)
    stack_.set_mask("turn", {"hand": 1.0})
    stack_.remove_layer("turn")
    assert stack_.stats() == {
        "layers_added": 2,
        "layers_removed": 1,
        "poses_pushed": 1,
        "evaluations": 1,
        "weight_updates": 1,
        "mask_updates": 1,
    }
