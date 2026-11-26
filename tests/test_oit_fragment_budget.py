import copy

import pytest

import oit_fragment_budget as oit


def make(**kwargs):
    return oit.OitFragmentBudget(**kwargs)


def started(**kwargs):
    obj = make(**kwargs)
    obj.begin_frame(1, width=4, height=3)
    return obj


def push(obj, depth, color=(10, 20, 30), alpha=1.0, x=0, y=0, seq=None):
    return obj.push_fragment(x=x, y=y, depth=depth, color=color, alpha=alpha, seq=seq)


def test_frame_lifecycle_rejects_pushes_and_bad_frame_ids():
    obj = make()
    with pytest.raises(oit.OitError) as exc:
        push(obj, 1)
    assert exc.value.code == "OIT_FRAME_NOT_STARTED"

    obj.begin_frame(5, width=2, height=2)
    with pytest.raises(oit.OitError) as exc:
        obj.begin_frame(5, width=2, height=2)
    assert exc.value.code == "OIT_FRAME_ORDER"
    with pytest.raises(oit.OitError) as exc:
        obj.begin_frame(4, width=2, height=2)
    assert exc.value.code == "OIT_FRAME_ORDER"


def test_push_rejects_bad_coordinates_and_depth():
    obj = started()
    for kwargs in (
        dict(x=-1, y=0, depth=1),
        dict(x=4, y=0, depth=1),
        dict(x=0, y=3, depth=1),
        dict(x=1.5, y=0, depth=1),
    ):
        with pytest.raises(oit.OitError) as exc:
            obj.push_fragment(color=(1, 2, 3), **kwargs)
        assert exc.value.code == "OIT_INVALID_PIXEL"

    for depth in (-1, 1 << 24, 3.5):
        with pytest.raises(oit.OitError) as exc:
            push(obj, depth)
        assert exc.value.code == "OIT_INVALID_FRAGMENT"


def test_push_rejects_bad_color_and_alpha():
    obj = started()
    for color in ((1, 2), (1, 2, 256), (0, 0, -1), (1.5, 0, 0)):
        with pytest.raises(oit.OitError) as exc:
            obj.push_fragment(x=0, y=0, depth=1, color=color)
        assert exc.value.code == "OIT_INVALID_FRAGMENT"

    for alpha in (0, 0.0, -0.5, 1.5, float("nan")):
        with pytest.raises(oit.OitError) as exc:
            obj.push_fragment(x=0, y=0, depth=1, color=(1, 2, 3), alpha=alpha)
        assert exc.value.code == "OIT_INVALID_FRAGMENT"

    assert obj.pending_count() == 0


def test_push_assigns_unique_sequence_and_rejects_duplicates():
    obj = started()
    first = push(obj, 5, x=0, y=0)
    second = push(obj, 6, x=1, y=0)
    assert (first, second) == (0, 1)
    assert push(obj, 7, x=2, y=0, seq=9) == 9

    with pytest.raises(oit.OitError) as exc:
        push(obj, 8, x=3, y=0, seq=9)
    assert exc.value.code == "OIT_SEQ_DUPLICATE"
    assert obj.pending_count() == 3


def test_resolve_sorts_by_depth_and_consumes_pixel():
    obj = started()
    push(obj, 3, color=(30, 0, 0))
    push(obj, 1, color=(10, 0, 0))
    push(obj, 2, color=(20, 0, 0))

    out = obj.resolve_pixel(x=0, y=0)
    assert [frag["depth"] for frag in out["fragments"]] == [1, 2, 3]
    assert out["color"] == (10, 0, 0)
    assert out["merged"] is False
    assert out["dropped"] == 0
    assert obj.pending_count(x=0, y=0) == 0

    again = obj.resolve_pixel(x=0, y=0, background=(7, 8, 9))
    assert again["fragments"] == ()
    assert again["color"] == (7, 8, 9)


def test_resolve_blends_far_to_near_with_exact_channels():
    obj = started()
    push(obj, 2, color=(100, 100, 100), alpha=0.5)
    push(obj, 1, color=(0, 200, 0), alpha=0.5)

    out = obj.resolve_pixel(x=0, y=0)
    assert out["color"] == (25, 125, 25)
    assert [frag["seq"] for frag in out["fragments"]] == [1, 0]


def test_resolve_rejects_pixel_outside_frame():
    obj = started()
    for x, y in ((-1, 0), (4, 0), (0, 3)):
        with pytest.raises(oit.OitError) as exc:
            obj.resolve_pixel(x=x, y=y)
        assert exc.value.code == "OIT_INVALID_PIXEL"


def test_new_frame_is_blocked_while_fragments_pending():
    obj = started()
    push(obj, 1)
    with pytest.raises(oit.OitError) as exc:
        obj.begin_frame(2, width=2, height=2)
    assert exc.value.code == "OIT_FRAME_PENDING"

    obj.resolve_pixel(x=0, y=0)
    obj.begin_frame(2, width=2, height=2)
    assert obj.stats()["frames"] == 2


def test_overflow_degrades_to_capacity_with_dropped_count():
    obj = make(capacity=4)
    obj.begin_frame(1, width=1, height=1)
    for depth in range(1, 6):
        push(obj, depth, color=(depth * 10, 0, 0))

    out = obj.resolve_pixel(x=0, y=0)
    depths = [frag["depth"] for frag in out["fragments"]]
    assert len(depths) == 4
    assert depths == sorted(depths)
    assert out["merged"] is True
    assert out["dropped"] == 2
    assert obj.overflow_stats() == {"pixels": 1, "dropped": 2, "merged": 2}


def test_capacity_change_is_locked_until_pixel_resolved():
    obj = make(capacity=4)
    obj.begin_frame(1, width=1, height=1)
    push(obj, 1)
    with pytest.raises(oit.OitError) as exc:
        obj.set_capacity(6)
    assert exc.value.code == "OIT_CAPACITY_LOCKED"

    obj.resolve_pixel(x=0, y=0)
    assert obj.set_capacity(6) == 6
    with pytest.raises(oit.OitError) as exc:
        obj.set_capacity(1)
    assert exc.value.code == "OIT_INVALID_CAPACITY"
    with pytest.raises(oit.OitError) as exc:
        obj.set_capacity(33)
    assert exc.value.code == "OIT_INVALID_CAPACITY"

    obj.begin_frame(2, width=1, height=1)
    for depth in range(1, 8):
        push(obj, depth)
    out = obj.resolve_pixel(x=0, y=0)
    assert len(out["fragments"]) == 6
    assert out["dropped"] == 2


def test_reset_clears_frame_pending_and_counters():
    obj = started()
    push(obj, 1)
    obj.reset()

    assert obj.pending_count() == 0
    with pytest.raises(oit.OitError) as exc:
        push(obj, 1)
    assert exc.value.code == "OIT_FRAME_NOT_STARTED"
    assert obj.stats() == {"frames": 0, "fragments": 0, "resolved": 0,
                           "dropped": 0, "merged": 0, "pixels_overflowed": 0}
    assert obj.overflow_stats() == {"pixels": 0, "dropped": 0, "merged": 0}


def test_stats_count_fragments_and_resolved_pixels_across_frames():
    obj = make()
    obj.begin_frame(1, width=2, height=1)
    push(obj, 1, x=0, y=0)
    push(obj, 2, x=1, y=0)
    obj.resolve_pixel(x=0, y=0)
    obj.resolve_pixel(x=1, y=0)

    obj.begin_frame(2, width=1, height=1)
    push(obj, 1, x=0, y=0)
    obj.resolve_pixel(x=0, y=0)

    assert obj.stats() == {"frames": 2, "fragments": 3, "resolved": 3,
                           "dropped": 0, "merged": 0, "pixels_overflowed": 0}


def test_snapshot_is_detached_and_restores_pending_fragments():
    obj = make(capacity=4)
    obj.begin_frame(3, width=2, height=1)
    push(obj, 2, color=(20, 0, 0))
    push(obj, 1, color=(10, 0, 0), x=1, y=0)

    state = obj.snapshot()
    assert state["version"] == 1
    assert state["capacity"] == 4
    assert state["merge_mode"] == "average"
    assert len(state["frame"]["pixels"]) == 2

    snapshot_copy = copy.deepcopy(state)
    state["stats"]["frames"] = 99
    state["capacity"] = 31
    state["frame"]["pixels"].clear()
    assert obj.stats()["frames"] == 1
    assert obj.pending_count() == 2

    clone = make(capacity=2)
    clone.restore(snapshot_copy)
    assert clone.pending_count() == 2
    out = clone.resolve_pixel(x=1, y=0)
    assert [frag["color"] for frag in out["fragments"]] == [(10, 0, 0)]
    assert clone.pending_count(x=0, y=0) == 1


def test_restore_rejects_malformed_snapshot_without_touching_state():
    obj = started()
    push(obj, 2)
    bad_states = [
        None,
        {},
        {"version": 2, "capacity": 4, "merge_mode": "average",
         "frame": None, "stats": {}},
        {"version": 1, "capacity": "4", "merge_mode": "average",
         "frame": None, "stats": {}},
        {"version": 1, "capacity": 4, "merge_mode": "average",
         "frame": {"frame_id": 1}, "stats": {}},
        {"version": 1, "capacity": 4, "merge_mode": "average",
         "frame": None, "stats": {"frames": -1}},
    ]
    for bad in bad_states:
        with pytest.raises(oit.OitError) as exc:
            obj.restore(bad)
        assert exc.value.code == "OIT_SNAPSHOT_INVALID"

    assert obj.pending_count() == 1
    assert obj.stats()["fragments"] == 1
    assert obj.resolve_pixel(x=0, y=0)["fragments"][0]["depth"] == 2


def test_overflow_stats_are_per_frame_while_totals_accumulate():
    obj = make(capacity=4)
    obj.begin_frame(1, width=1, height=1)
    for depth in range(1, 6):
        push(obj, depth)
    assert obj.overflow_stats() == {"pixels": 1, "dropped": 2, "merged": 2}

    obj.resolve_pixel(x=0, y=0)
    obj.begin_frame(2, width=1, height=1)
    push(obj, 1)
    assert obj.overflow_stats() == {"pixels": 0, "dropped": 0, "merged": 0}
    assert obj.stats()["dropped"] == 2
    assert obj.stats()["merged"] == 2
    assert obj.stats()["pixels_overflowed"] == 1
