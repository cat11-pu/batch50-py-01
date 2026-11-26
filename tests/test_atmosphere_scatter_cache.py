import copy
import math
import threading

import pytest

import atmosphere_scatter_cache as asc

LOW = (2.5, 7.5)      # bucket (18, 0)
LOW2 = (7.5, 7.5)     # bucket (19, 0)
MID = (42.5, 7.5)     # bucket (26, 0)
HIGH = (62.5, 7.5)    # bucket (30, 0)


def cache(**kwargs):
    return asc.AtmosphereScatterCache(**kwargs)


def test_bucket_for_maps_angles_onto_the_grid():
    c = cache()
    assert c.bucket_for(-90.0, 0.0) == (0, 0)
    assert c.bucket_for(-90.0, 15.0) == (0, 1)
    assert c.bucket_for(-0.1, 359.9) == (17, 23)
    assert c.bucket_for(0.0, 0.0) == (18, 0)
    assert c.bucket_for(89.99, 7.5) == (35, 0)
    assert c.bucket_for(90.0, 0.0) == (35, 0)
    for altitude, azimuth in [(90.5, 0.0), (-90.5, 0.0), (10.0, 360.0),
                              (10.0, -0.5), (math.nan, 0.0), (10.0, math.nan)]:
        with pytest.raises(asc.AtmosphereCacheError) as exc:
            c.bucket_for(altitude, azimuth)
        assert exc.value.code == "ATMOSPHERE_INVALID_ANGLE"


def test_set_sun_is_idempotent_per_angle():
    c = cache()
    assert c.set_sun(2.5, 7.5) == (18, 0)
    assert c.set_sun(2.5, 7.5) == (18, 0)
    assert c.stats()["sun"] == (2.5, 7.5)
    assert c.stats()["builds"] == 0
    assert c.stats()["cached"] == 0
    assert c.set_sun(62.5, 7.5) == (30, 0)
    assert c.stats()["sun"] == (62.5, 7.5)
    with pytest.raises(asc.AtmosphereCacheError) as exc:
        c.set_sun(120.0, 0.0)
    assert exc.value.code == "ATMOSPHERE_INVALID_ANGLE"


def test_build_produces_quantised_values_once():
    c = cache()
    table = c.build(*LOW)
    assert table == (18000, 18003, 18006, 18009, 18012, 18015, 18018, 18021)
    assert c.build(*LOW) == table
    assert c.stats()["builds"] == 1
    assert c.stats()["cached"] == 1
    assert c.build(*HIGH) == (30000, 30003, 30006, 30009, 30012, 30015,
                              30018, 30021)
    assert c.stats()["builds"] == 2
    assert c.stats()["cached"] == 2


def test_lookup_at_bucket_centre_returns_table_values():
    c = cache()
    table = c.build(*LOW)
    for index, expected in enumerate(table):
        assert c.lookup(*LOW, index) == float(expected)
    row = c.stats_of(*LOW)
    assert row.bucket == (18, 0)
    assert row.cached is True
    assert row.values == table
    assert row.builds == 1
    assert row.lookups == 8


def test_lookup_rejects_bad_index_and_angles():
    c = cache()
    for index in (-1, 8):
        with pytest.raises(asc.AtmosphereCacheError) as exc:
            c.lookup(*LOW, index)
        assert exc.value.code == "ATMOSPHERE_INVALID_INDEX"
    for altitude, azimuth in [(100.0, 0.0), (0.0, 400.0), (0.0, -1.0)]:
        with pytest.raises(asc.AtmosphereCacheError) as exc:
            c.lookup(altitude, azimuth, 0)
        assert exc.value.code == "ATMOSPHERE_INVALID_ANGLE"
    assert c.stats()["builds"] == 0
    assert c.stats()["lookups"] == 0


def test_lookup_interpolates_between_neighbouring_buckets():
    c = cache()
    assert c.lookup(5.0, 7.5, 0) == pytest.approx(18500.0, abs=1e-6)
    lower = c.lookup(4.999, 7.5, 0)
    upper = c.lookup(5.001, 7.5, 0)
    assert 18000.0 <= lower <= 19000.0
    assert 18000.0 <= upper <= 19000.0
    assert abs(upper - lower) < 1.0
    assert c.lookup(5.0, 7.5, 7) > c.lookup(5.0, 7.5, 0)


def test_lookup_is_deterministic_and_reuses_the_bucket():
    c = cache()
    first = [c.lookup(*LOW, index) for index in range(8)]
    second = [c.lookup(*LOW, index) for index in range(8)]
    assert first == second
    assert len(set(first)) == 8
    row = c.stats_of(*LOW)
    assert row.builds == 1
    assert row.lookups == 16
    assert c.stats()["builds"] == 1
    assert c.stats()["lookups"] == 16


def test_lfu_eviction_drops_the_least_used_bucket():
    c = cache(capacity=2)
    c.build(*LOW)
    c.build(*HIGH)
    for index in range(3):
        c.lookup(*LOW, index)
    c.lookup(*HIGH, 0)
    assert c.build(*MID) == (26000, 26003, 26006, 26009, 26012, 26015,
                             26018, 26021)
    assert c.stats_of(*LOW).cached is True
    evicted = c.stats_of(*HIGH)
    assert evicted.cached is False
    assert evicted.builds == 1
    assert evicted.lookups == 1
    assert evicted.values is None
    assert c.stats()["cached"] == 2
    assert c.stats()["evictions"] == 1


def test_eviction_tie_breaks_on_the_older_bucket():
    c = cache(capacity=1)
    c.build(*LOW)
    c.build(*HIGH)
    assert c.stats_of(*LOW).cached is False
    assert c.stats_of(*LOW).builds == 1
    assert c.stats_of(*LOW).values is None
    assert c.stats_of(*HIGH).cached is True
    assert c.stats()["evictions"] == 1


def test_resize_shrinks_by_usage_and_rejects_bad_capacity():
    c = cache(capacity=3)
    c.build(*LOW)
    c.build(*HIGH)
    c.build(*MID)
    for _ in range(2):
        c.lookup(*LOW, 0)
    for _ in range(5):
        c.lookup(*HIGH, 0)
    c.lookup(*MID, 0)
    assert c.resize(1) == 2
    assert c.capacity == 1
    assert c.stats_of(*HIGH).cached is True
    assert c.stats_of(*LOW).cached is False
    assert c.stats_of(*MID).cached is False
    assert c.stats()["evictions"] == 2
    with pytest.raises(asc.AtmosphereCacheError) as exc:
        c.resize(0)
    assert exc.value.code == "ATMOSPHERE_INVALID_CAPACITY"
    assert c.capacity == 1
    assert c.resize(4) == 0
    assert c.capacity == 4
    assert c.stats()["evictions"] == 2


def test_invalidate_forces_a_rebuild():
    c = cache()
    c.build(*LOW)
    assert c.invalidate(*LOW) is True
    assert c.invalidate(*LOW) is False
    row = c.stats_of(*LOW)
    assert row.cached is False
    assert row.builds == 1
    value = c.lookup(*LOW, 0)
    assert isinstance(value, float)
    assert value > 0.0
    row = c.stats_of(*LOW)
    assert row.cached is True
    assert row.builds == 2
    assert row.lookups == 1
    assert c.stats()["invalidations"] == 1
    assert c.stats()["evictions"] == 0


def test_weather_change_only_drops_low_buckets():
    c = cache(capacity=4)
    c.build(*LOW)
    high_table = c.build(*HIGH)
    assert c.set_weather("clear") == 0
    assert c.set_weather("hazy") == 1
    assert c.stats()["weather"] == "hazy"
    assert c.stats_of(*LOW).cached is False
    assert c.stats_of(*LOW).builds == 1
    assert c.stats_of(*HIGH).cached is True
    assert c.stats_of(*HIGH).values == high_table
    assert c.stats_of(*HIGH).builds == 1
    assert c.lookup(*LOW, 0) == 25200.0
    assert c.stats_of(*LOW).builds == 2
    assert c.stats()["weather_changes"] == 1
    with pytest.raises(asc.AtmosphereCacheError) as exc:
        c.set_weather("snow")
    assert exc.value.code == "ATMOSPHERE_UNKNOWN_PRESET"
    assert c.stats()["weather"] == "hazy"


def test_concurrent_lookup_builds_the_bucket_once():
    c = cache(capacity=4)
    values = []
    failures = []
    barrier = threading.Barrier(10)

    def worker():
        try:
            barrier.wait(timeout=5)
            values.append(c.lookup(*LOW, 3))
        except Exception as exc:  # noqa: BLE001 - reported through failures
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert values == [18009.0] * 10
    assert c.stats_of(*LOW).builds == 1
    assert c.stats()["builds"] == 1


def test_snapshot_roundtrip_keeps_cache_and_counters():
    c = cache(capacity=3)
    c.set_sun(2.5, 7.5)
    low_table = c.build(*LOW)
    c.build(*HIGH)
    for index in range(3):
        c.lookup(*LOW, index)
    state = c.snapshot()
    assert set(state) == {"version", "weather", "sun", "settings", "buckets",
                          "registry", "counters"}
    pristine = copy.deepcopy(state)
    state["buckets"].clear()
    state["counters"]["builds"] = 99
    assert c.stats()["builds"] == 2
    assert c.stats_of(*LOW).cached is True

    clone = cache()
    clone.restore(pristine)
    assert clone.capacity == 3
    assert clone.stats()["weather"] == "clear"
    assert clone.stats()["sun"] == (2.5, 7.5)
    assert clone.stats()["builds"] == 2
    assert clone.stats()["lookups"] == 3
    assert clone.stats()["cached"] == 2
    row = clone.stats_of(*LOW)
    assert row.cached is True
    assert row.values == low_table
    assert row.lookups == 3
    assert clone.lookup(*LOW, 1) == 18003.0
    assert clone.stats_of(*LOW).lookups == 4
    assert clone.set_weather("overcast") == 1
    assert clone.stats_of(*HIGH).cached is True


def test_restore_rejects_malformed_snapshots():
    c = cache()
    c.build(*LOW)
    valid = c.snapshot()
    bad_snapshots = [
        None,
        {},
        dict(valid, version=2),
        dict(valid, weather="snow"),
        dict(valid, sun="noon"),
        dict(valid, settings={"capacity": 0, "samples": 8,
                              "boundary_tolerance": 5.0}),
        dict(valid, settings=[]),
        dict(valid, registry="none"),
        dict(valid, counters=[]),
        {key: value for key, value in valid.items() if key != "buckets"},
    ]
    for snapshot in bad_snapshots:
        with pytest.raises(asc.AtmosphereCacheError) as exc:
            c.restore(snapshot)
        assert exc.value.code == "ATMOSPHERE_SNAPSHOT_INVALID"
    assert c.stats_of(*LOW).cached is True
    assert c.stats()["builds"] == 1
    assert c.lookup(*LOW, 0) == 18000.0
