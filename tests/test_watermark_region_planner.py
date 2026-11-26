import copy
import threading

import pytest

import watermark_region_planner as wrp


def planner(**kwargs):
    return wrp.WatermarkRegionPlanner(**kwargs)


def with_regions(*regions):
    instance = planner()
    instance.set_regions(regions)
    return instance


def test_set_regions_validates_and_locks_after_slots():
    instance = planner()
    assert instance.set_regions(("tl", "tr")) == ("tl", "tr")
    for bad in ((), ("tl", "tl"), ("tl", "")):
        with pytest.raises(wrp.WatermarkError) as exc:
            instance.set_regions(bad)
        assert exc.value.code == "WATERMARK_INVALID"
    instance.add_slot("w1", start=0, end=10, region="tl")
    with pytest.raises(wrp.WatermarkError) as exc:
        instance.set_regions(("tr",))
    assert exc.value.code == "WATERMARK_REGIONS_LOCKED"


def test_add_slot_validation_and_duplicates():
    instance = with_regions("tl", "tr")
    bad_calls = [
        dict(start=0, end=10, region="nowhere"),
        dict(start=-1, end=10, region="tl"),
        dict(start=0, end=0, region="tl"),
        dict(start=10, end=5, region="tl"),
        dict(start=0, end=10, region="tl", opacity=0),
        dict(start=0, end=10, region="tl", opacity=1.5),
        dict(start=0, end=10, region="tl", priority="high"),
        dict(start=0, end=10, region="tl", alternatives=("tr", "tr")),
        dict(start=0, end=10, region="tl", alternatives=("nowhere",)),
        dict(start=0, end=10, region="tl", alternatives=("tl",)),
    ]
    for kwargs in bad_calls:
        with pytest.raises(wrp.WatermarkError) as exc:
            instance.add_slot("w1", **kwargs)
        assert exc.value.code == "WATERMARK_INVALID"
    instance.add_slot("w1", start=0, end=10, region="tl")
    with pytest.raises(wrp.WatermarkError) as exc:
        instance.add_slot("w1", start=20, end=30, region="tr")
    assert exc.value.code == "WATERMARK_SLOT_EXISTS"


def test_add_segment_rejects_overlap_and_duplicates():
    instance = with_regions("tl")
    instance.add_segment("s1", start=0, end=50)
    instance.add_segment("s2", start=50, end=100)
    with pytest.raises(wrp.WatermarkError) as exc:
        instance.add_segment("s3", start=40, end=60)
    assert exc.value.code == "WATERMARK_INVALID"
    with pytest.raises(wrp.WatermarkError) as exc:
        instance.add_segment("s1", start=0, end=10)
    assert exc.value.code == "WATERMARK_SEGMENT_EXISTS"
    with pytest.raises(wrp.WatermarkError) as exc:
        instance.add_segment("s4", start=10, end=10)
    assert exc.value.code == "WATERMARK_INVALID"


def test_plan_assigns_preferred_region():
    instance = with_regions("tl", "tr")
    instance.add_segment("s1", start=0, end=100)
    instance.add_slot("w1", start=10, end=40, region="tr", priority=2)
    plan = instance.plan()
    assert plan.plan_id == "plan-0001"
    assert len(plan.assignments) == 1
    assignment = plan.assignments[0]
    assert assignment.slot_id == "w1"
    assert assignment.region == "tr"
    assert assignment.requested_region == "tr"
    assert assignment.start == 10
    assert assignment.end == 40
    assert assignment.segment_id == "s1"
    assert assignment.continued is False
    assert assignment.priority == 2
    assert instance.stats()["plans"] == 1
    assert instance.active_plan() is None


def test_plan_is_ordered_and_stable():
    instance = with_regions("tl", "tr")
    instance.add_segment("s1", start=0, end=100)
    instance.add_slot("w2", start=60, end=90, region="tr")
    instance.add_slot("w1", start=10, end=40, region="tl")
    first = instance.plan()
    second = instance.plan()
    assert [item.slot_id for item in first.assignments] == ["w1", "w2"]
    assert first.assignments == second.assignments
    assert first.plan_id == "plan-0001"
    assert second.plan_id == "plan-0002"
    assert instance.stats()["plans"] == 2


def test_at_time_requires_an_applied_plan():
    instance = with_regions("tl")
    instance.add_slot("w1", start=0, end=10, region="tl")
    instance.plan()
    with pytest.raises(wrp.WatermarkError) as exc:
        instance.at_time(5)
    assert exc.value.code == "WATERMARK_NO_PLAN"


def test_apply_activates_plan_and_at_time_uses_region_order():
    instance = with_regions("tl", "tr")
    instance.add_segment("s1", start=0, end=100)
    instance.add_slot("a", start=0, end=100, region="tl", priority=1)
    instance.add_slot("b", start=0, end=100, region="tr", priority=2)
    plan = instance.plan()
    assert instance.apply(plan.plan_id).plan_id == plan.plan_id
    assert instance.active_plan() == plan.plan_id
    active = instance.at_time(50)
    assert [item.slot_id for item in active] == ["a", "b"]
    assert [item.region for item in active] == ["tl", "tr"]
    assert instance.at_time(150) == ()
    assert instance.stats()["applied"] == 1
    with pytest.raises(wrp.WatermarkError) as exc:
        instance.apply("plan-9999")
    assert exc.value.code == "WATERMARK_UNKNOWN_PLAN"


def test_lower_priority_slot_moves_to_alternative():
    instance = with_regions("tl", "tr")
    instance.add_segment("s1", start=0, end=100)
    instance.add_slot("high", start=0, end=50, region="tl",
                      alternatives=("tr",), priority=5)
    instance.add_slot("low", start=10, end=40, region="tl",
                      alternatives=("tr",), priority=3)
    plan = instance.plan()
    placed = {item.slot_id: item for item in plan.assignments}
    assert placed["high"].region == "tl"
    assert placed["low"].region == "tr"
    assert placed["low"].requested_region == "tl"
    assert instance.stats()["relocations"] == 1
    assert instance.stats()["conflicts"] == 1


def test_conflicts_lists_overlapping_same_region_pairs():
    instance = with_regions("tl", "tr")
    instance.add_slot("a", start=0, end=50, region="tl")
    instance.add_slot("b", start=40, end=90, region="tl")
    instance.add_slot("c", start=0, end=20, region="tr")
    conflicts = instance.conflicts()
    assert len(conflicts) == 1
    conflict = conflicts[0]
    assert conflict.slot_id == "a"
    assert conflict.other_slot_id == "b"
    assert conflict.region == "tl"
    assert conflict.start == 40
    assert conflict.end == 50


def test_remove_slot_invalidates_active_plan():
    instance = with_regions("tl", "tr")
    instance.add_slot("a", start=0, end=50, region="tl")
    instance.add_slot("b", start=0, end=50, region="tr")
    instance.apply(instance.plan().plan_id)
    assert instance.remove_slot("a") is True
    assert instance.active_plan() is None
    with pytest.raises(wrp.WatermarkError) as exc:
        instance.at_time(10)
    assert exc.value.code == "WATERMARK_NO_PLAN"
    assert instance.remove_slot("a") is False
    assert [slot.slot_id for slot in instance.slots()] == ["b"]


def test_add_slot_invalidates_active_plan():
    instance = with_regions("tl", "tr")
    instance.add_slot("a", start=0, end=50, region="tl")
    instance.apply(instance.plan().plan_id)
    instance.add_slot("b", start=0, end=50, region="tr")
    with pytest.raises(wrp.WatermarkError) as exc:
        instance.at_time(10)
    assert exc.value.code == "WATERMARK_NO_PLAN"
    assert instance.active_plan() is None


def test_cross_segment_slot_is_flagged_as_continuation():
    instance = with_regions("tl")
    instance.add_segment("s1", start=0, end=50)
    instance.add_segment("s2", start=50, end=100)
    instance.add_slot("w1", start=20, end=80, region="tl")
    plan = instance.plan()
    assert [(item.segment_id, item.start, item.end, item.continued)
            for item in plan.assignments] == [
        ("s1", 20, 50, False), ("s2", 50, 80, True)]
    assert instance.stats()["continuations"] == 1


def test_opacity_fade_inside_one_segment():
    instance = with_regions("tl")
    instance.add_segment("s1", start=0, end=100)
    instance.add_slot("w1", start=10, end=40, region="tl", opacity=0.8,
                      fade_in=2)
    assignment = instance.plan().assignments[0]
    assert assignment.opacity == 0.8
    assert assignment.fade_in == 2
    assert assignment.fade_origin == 10
    assert assignment.opacity_at(10) == 0.4
    assert assignment.opacity_at(11) == 0.8
    assert assignment.opacity_at(39) == 0.8


def test_snapshot_roundtrip_and_invalid_restore():
    instance = with_regions("tl", "tr")
    instance.add_segment("s1", start=0, end=100)
    instance.add_slot("a", start=0, end=100, region="tl", priority=1)
    instance.add_slot("b", start=0, end=100, region="tr", priority=2)
    plan = instance.plan()
    instance.apply(plan.plan_id)
    state = instance.snapshot()
    pristine = copy.deepcopy(state)
    assert set(state) == {"version", "regions", "segments", "slots", "plans",
                          "active", "sequence", "stats"}
    state["slots"].clear()
    state["stats"]["applied"] = 99
    assert len(instance.slots()) == 2
    assert instance.stats()["applied"] == 1
    clone = planner()
    clone.restore(pristine)
    assert clone.active_plan() == plan.plan_id
    assert [item.slot_id for item in clone.at_time(10)] == ["a", "b"]
    assert len(clone.slots()) == 2
    assert clone.stats()["applied"] == 1
    bad_states = [
        None,
        {},
        {"version": 2, "regions": [], "segments": [], "slots": {},
         "plans": {}, "active": None, "sequence": 1, "stats": {}},
        {"version": 1, "regions": [], "segments": [], "slots": "nope",
         "plans": {}, "active": None, "sequence": 1, "stats": {}},
        {"version": 1, "regions": [], "segments": [], "slots": {},
         "plans": {}, "active": None, "sequence": 1, "stats": {"plans": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(wrp.WatermarkError) as exc:
            clone.restore(bad)
        assert exc.value.code == "WATERMARK_SNAPSHOT_INVALID"
    assert clone.active_plan() == plan.plan_id
    assert len(clone.slots()) == 2
    assert clone.stats()["applied"] == 1


def test_concurrent_slot_registration_keeps_all_slots():
    instance = with_regions("tl", "tr")
    instance.add_segment("s1", start=0, end=100)
    errors = []
    barrier = threading.Barrier(12)

    def worker(number):
        try:
            barrier.wait(timeout=5)
            instance.add_slot(f"w-{number:02d}", start=number, end=number + 5,
                              region="tl", priority=number % 3)
        except Exception as exc:  # pragma: no cover - reported via errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(number,))
               for number in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(instance.slots()) == 12
    assert [slot.slot_id for slot in instance.slots()] == [
        f"w-{number:02d}" for number in range(12)]
    assert instance.stats()["slots"] == 12
