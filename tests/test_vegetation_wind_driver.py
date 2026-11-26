import copy
import math
import threading

import pytest

import vegetation_wind_driver as vw

TWO_PI = 2.0 * math.pi


def driver(**kwargs):
    return vw.VegetationWindDriver(**kwargs)


def meadow():
    d = driver()
    d.register_field("meadow", wavelength=8.0, phase=0.0)
    return d


def expected_phase(name):
    checksum = sum((index + 1) * ord(char) for index, char in enumerate(name))
    return round(TWO_PI * (checksum % 1024) / 1024.0, 6)


def test_register_field_validates():
    d = driver()
    record = d.register_field("meadow", wavelength=8.0, phase=0.5)
    assert record.field_id == "meadow"
    assert record.wavelength == pytest.approx(8.0)
    assert record.phase == pytest.approx(0.5)
    with pytest.raises(vw.WindDriverError) as exc:
        d.register_field("meadow", wavelength=4.0)
    assert exc.value.code == "WIND_INVALID_INPUT"
    for kwargs in (dict(wavelength=0.0), dict(wavelength=-1.0),
                   dict(wavelength=float("nan")),
                   dict(wavelength=8.0, phase=float("inf"))):
        with pytest.raises(vw.WindDriverError) as exc:
            d.register_field("reed", **kwargs)
        assert exc.value.code == "WIND_INVALID_INPUT"
    with pytest.raises(vw.WindDriverError) as exc:
        d.register_field("   ", wavelength=1.0)
    assert exc.value.code == "WIND_INVALID_INPUT"
    assert d.stats()["fields"] == 1


def test_register_instance_derives_the_tier():
    d = meadow()
    near = d.register_instance("grass-1", position=(1.0, 2.0), stiffness=1.5,
                               field="meadow")
    assert near.instance_id == "grass-1"
    assert near.position == (1.0, 2.0)
    assert near.stiffness == pytest.approx(1.5)
    assert near.field == "meadow"
    assert near.tier == "near"
    assert near.phase == pytest.approx(expected_phase("grass-1"))
    far = d.register_instance("pine-9", position=(100.0, 0.0), field="meadow")
    assert far.tier == "far"
    with pytest.raises(vw.WindDriverError) as exc:
        d.register_instance("grass-1", position=(0.0, 0.0), field="meadow")
    assert exc.value.code == "WIND_INVALID_INPUT"
    with pytest.raises(vw.WindDriverError) as exc:
        d.register_instance("reed-1", position=(0.0, 0.0), field="ghost")
    assert exc.value.code == "WIND_UNKNOWN_FIELD"
    for kwargs in (dict(position=(1.0,)), dict(position=(1.0, 2.0), stiffness=0.0),
                   dict(position=(1.0, 2.0), stiffness=-2.0)):
        with pytest.raises(vw.WindDriverError) as exc:
            d.register_instance("bush-x", field="meadow", **kwargs)
        assert exc.value.code == "WIND_INVALID_INPUT"
    with pytest.raises(vw.WindDriverError) as exc:
        d.register_instance("", position=(0.0, 0.0), field="meadow")
    assert exc.value.code == "WIND_INVALID_INPUT"


def test_phase_of_is_stable_and_matches_the_checksum():
    d = meadow()
    for name in ("grass-1", "bush-7"):
        d.register_instance(name, position=(0.0, 0.0), field="meadow")
    for name in ("grass-1", "bush-7"):
        value = d.phase_of(name)
        assert value == pytest.approx(expected_phase(name), abs=1e-9)
        assert d.phase_of(name) == value
        assert 0.0 <= value < TWO_PI
    assert d.phase_of("grass-1") != d.phase_of("bush-7")
    with pytest.raises(vw.WindDriverError) as exc:
        d.phase_of("ghost")
    assert exc.value.code == "WIND_UNKNOWN_INSTANCE"


def test_set_wind_validates_and_records_state():
    d = meadow()
    result = d.set_wind(1.5, 45.0)
    assert result["strength"] == pytest.approx(1.5)
    assert result["direction"] == pytest.approx(45.0)
    assert result["transition"] == pytest.approx(0.0)
    stats = d.stats()
    assert stats["wind"]["strength"] == pytest.approx(1.5)
    assert stats["wind"]["direction"] == pytest.approx(45.0)
    for strength, direction, transition in ((-1.0, 0.0, 0.0),
                                            (float("nan"), 0.0, 0.0),
                                            (1.0, float("inf"), 0.0),
                                            (1.0, 0.0, -1.0)):
        with pytest.raises(vw.WindDriverError) as exc:
            d.set_wind(strength, direction, transition=transition)
        assert exc.value.code == "WIND_INVALID_WIND"
    assert d.set_wind(2.0, 370.0)["direction"] == pytest.approx(10.0)
    assert d.stats()["wind"]["strength"] == pytest.approx(2.0)


def test_update_requires_wind():
    d = meadow()
    d.register_instance("grass-1", position=(0.0, 0.0), field="meadow")
    with pytest.raises(vw.WindDriverError) as exc:
        d.update(0.0)
    assert exc.value.code == "WIND_NOT_SET"
    assert d.stats()["updates"] == 0
    assert d.stats()["updated"] == 0


def test_update_requires_monotonic_time():
    d = meadow()
    d.register_instance("grass-1", position=(0.0, 0.0), field="meadow")
    d.set_wind(1.0, 0.0)
    assert d.update(1.0)["updated"] == 1
    with pytest.raises(vw.WindDriverError) as exc:
        d.update(0.5)
    assert exc.value.code == "WIND_INVALID_TIME"
    with pytest.raises(vw.WindDriverError) as exc:
        d.update(float("nan"))
    assert exc.value.code == "WIND_INVALID_TIME"
    assert d.stats()["time"] == pytest.approx(1.0)
    assert d.stats()["updates"] == 1
    assert d.update(1.0)["updated"] == 1


def test_update_truncates_the_batch_by_distance():
    d = meadow()
    for index in range(1, 6):
        d.register_instance(f"bush-{index}", position=(float(index), 0.0),
                            field="meadow")
    d.set_wind(1.0, 0.0)
    assert d.set_lod_budget(2) == {"per_update": 2, "near_radius": 30.0,
                                   "far_stride": 3}
    first = d.update(0.0)
    assert first["due"] == 5
    assert first["updated"] == 2
    assert first["deferred"] == 3
    d.sample_instance("bush-1", 0.0)
    d.sample_instance("bush-2", 0.0)
    for name in ("bush-3", "bush-4", "bush-5"):
        with pytest.raises(vw.WindDriverError) as exc:
            d.sample_instance(name, 0.0)
        assert exc.value.code == "WIND_NO_SAMPLE"
    second = d.update(0.5)
    assert second["updated"] == 2
    assert second["deferred"] == 3
    assert d.set_lod_budget(5)["per_update"] == 5
    third = d.update(1.0)
    assert third["updated"] == 5
    assert third["deferred"] == 0
    for name in ("bush-3", "bush-4", "bush-5"):
        d.sample_instance(name, 1.0)
    for bad in ((0,), (-1,)):
        with pytest.raises(vw.WindDriverError) as exc:
            d.set_lod_budget(bad[0])
        assert exc.value.code == "WIND_INVALID_BUDGET"
    with pytest.raises(vw.WindDriverError) as exc:
        d.set_lod_budget(2, near_radius=0.0)
    assert exc.value.code == "WIND_INVALID_BUDGET"
    with pytest.raises(vw.WindDriverError) as exc:
        d.set_lod_budget(2, far_stride=0)
    assert exc.value.code == "WIND_INVALID_BUDGET"


def test_far_instances_update_on_a_stride():
    d = meadow()
    d.register_instance("grass-1", position=(1.0, 0.0), field="meadow")
    d.register_instance("pine-9", position=(100.0, 0.0), field="meadow")
    d.set_wind(1.0, 0.0)
    d.set_lod_budget(10, far_stride=3)
    for step in range(6):
        result = d.update(float(step))
        assert result["updated"] == (2 if step in (0, 3) else 1)
        assert result["deferred"] == 0
    tier = d.stats()["updates_by_tier"]
    assert tier["near"] == 6
    assert tier["far"] == 2
    assert d.stats()["near"] == 1
    assert d.stats()["far"] == 1


def test_sample_instance_matches_the_sway_formula():
    d = meadow()
    d.register_instance("grass-1", position=(4.0, 0.0), stiffness=1.5,
                        field="meadow")
    d.set_wind(2.0, 0.0)
    d.update(2.0)
    pose = d.sample_instance("grass-1", 2.0)
    phase_zero = d.phase_of("grass-1")
    assert pose.instance_id == "grass-1"
    assert pose.time == pytest.approx(2.0)
    assert pose.tier == "near"
    assert pose.interpolated is False
    assert pose.phase == pytest.approx((TWO_PI * 0.35 * 2.0 + phase_zero) % TWO_PI,
                                       abs=1e-5)
    assert pose.amplitude > 0.0
    assert pose.sway == pytest.approx(
        pose.amplitude * 1.5 * math.sin(pose.phase), abs=1e-4)


def test_sample_instance_clamps_outside_the_history():
    d = meadow()
    d.register_instance("grass-1", position=(1.0, 0.0), field="meadow")
    d.set_wind(1.0, 0.0)
    d.update(0.0)
    d.update(1.0)
    start = d.sample_instance("grass-1", 0.0)
    early = d.sample_instance("grass-1", -5.0)
    assert early.interpolated is False
    assert early.sway == pytest.approx(start.sway, abs=1e-9)
    assert early.amplitude == pytest.approx(start.amplitude, abs=1e-9)
    end = d.sample_instance("grass-1", 1.0)
    late = d.sample_instance("grass-1", 99.0)
    assert late.interpolated is False
    assert late.sway == pytest.approx(end.sway, abs=1e-9)
    assert late.amplitude == pytest.approx(end.amplitude, abs=1e-9)


def test_sample_instance_rejects_unknown_and_empty():
    d = meadow()
    with pytest.raises(vw.WindDriverError) as exc:
        d.sample_instance("ghost", 0.0)
    assert exc.value.code == "WIND_UNKNOWN_INSTANCE"
    d.register_instance("grass-1", position=(0.0, 0.0), field="meadow")
    d.set_wind(1.0, 0.0)
    with pytest.raises(vw.WindDriverError) as exc:
        d.sample_instance("grass-1", 0.0)
    assert exc.value.code == "WIND_NO_SAMPLE"
    d.update(0.0)
    with pytest.raises(vw.WindDriverError) as exc:
        d.sample_instance("grass-1", float("nan"))
    assert exc.value.code == "WIND_INVALID_TIME"


def test_batch_of_orders_instances_by_distance():
    d = meadow()
    d.register_instance("far-pine", position=(40.0, 0.0), field="meadow")
    d.register_instance("near-grass", position=(1.0, 0.0), field="meadow")
    d.register_instance("mid-bush", position=(10.0, 0.0), field="meadow")
    d.register_instance("far-reed", position=(40.0, 5.0), field="meadow")
    d.set_wind(1.0, 0.0)
    d.set_lod_budget(10)
    d.update(1.0)
    batch = d.batch_of(1.0)
    assert [pose.instance_id for pose in batch] == ["near-grass", "mid-bush",
                                                    "far-pine", "far-reed"]
    assert all(pose.time == pytest.approx(1.0) for pose in batch)
    assert all(pose.interpolated is False for pose in batch)
    assert batch[0].tier == "near"
    assert batch[3].tier == "far"


def test_concurrent_updates_stay_consistent():
    d = meadow()
    for index in range(3):
        d.register_instance(f"grass-{index}", position=(float(index), 0.0),
                            field="meadow")
    d.set_wind(1.0, 0.0)
    results = []
    failures = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(d.update(2.0))
        except Exception as exc:  # noqa: BLE001 - reported through failures
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert len(results) == 8
    assert all(item["updated"] == 3 for item in results)
    assert d.stats()["updates"] == 8
    assert d.stats()["updated"] == 24
    for index in range(3):
        pose = d.sample_instance(f"grass-{index}", 2.0)
        assert pose.time == pytest.approx(2.0)


def test_snapshot_roundtrip_keeps_wind_and_poses():
    d = meadow()
    d.register_field("reeds", wavelength=4.0, phase=0.25)
    d.register_instance("grass-1", position=(1.0, 2.0), stiffness=1.2,
                        field="meadow")
    d.register_instance("pine-1", position=(80.0, 0.0), field="reeds")
    d.set_wind(1.0, 30.0)
    d.set_lod_budget(8, far_stride=2)
    d.update(0.0)
    d.update(1.0)
    state = d.snapshot()
    assert set(state) == {"version", "fields", "instances", "wind", "previous",
                          "budget", "time", "update_index", "poses", "counters"}
    pristine = copy.deepcopy(state)
    state["poses"].clear()
    state["counters"]["updates"] = 99
    assert d.stats()["updates"] == 2
    assert d.stats()["updated"] == 3

    clone = driver()
    clone.restore(pristine)
    stats = clone.stats()
    assert stats["fields"] == 2
    assert stats["instances"] == 2
    assert stats["updates"] == 2
    assert stats["updated"] == 3
    assert stats["time"] == pytest.approx(1.0)
    assert stats["wind"]["strength"] == pytest.approx(1.0)
    assert stats["wind"]["direction"] == pytest.approx(30.0)
    assert clone.phase_of("grass-1") == pytest.approx(d.phase_of("grass-1"))
    before = d.sample_instance("grass-1", 1.0)
    after = clone.sample_instance("grass-1", 1.0)
    assert after.sway == pytest.approx(before.sway)
    assert after.amplitude == pytest.approx(before.amplitude)
    assert after.time == pytest.approx(before.time)
    assert clone.update(2.0)["updated"] >= 1
    assert clone.stats()["updates"] == 3


def test_restore_rejects_malformed_snapshots():
    d = meadow()
    d.register_instance("grass-1", position=(1.0, 0.0), field="meadow")
    d.set_wind(1.0, 0.0)
    d.update(0.0)
    valid = d.snapshot()
    bad_snapshots = [
        None,
        {},
        dict(valid, version=2),
        dict(valid, fields="none"),
        dict(valid, instances=[]),
        dict(valid, wind="gust"),
        dict(valid, budget=[]),
        dict(valid, poses="none"),
        dict(valid, counters=[]),
        {key: value for key, value in valid.items() if key != "budget"},
    ]
    for snapshot in bad_snapshots:
        with pytest.raises(vw.WindDriverError) as exc:
            d.restore(snapshot)
        assert exc.value.code == "WIND_SNAPSHOT_INVALID"
    assert d.stats()["updates"] == 1
    assert d.stats()["time"] == pytest.approx(0.0)
    assert d.sample_instance("grass-1", 0.0).time == pytest.approx(0.0)
    assert d.update(1.0)["updated"] == 1
