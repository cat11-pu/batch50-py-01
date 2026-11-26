import copy
import math

import pytest

import curve_keyframe_reducer as ck

RAMP = [float(index) for index in range(21)]
SINE = [math.sin(index / 7.0) * 10.0 for index in range(120)]


def reducer(**kwargs):
    return ck.CurveKeyframeReducer(**kwargs)


def loaded(samples=None, *, curve_id="walk", events=None, sample_rate=30,
           **kwargs):
    r = reducer(**kwargs)
    r.load(curve_id, RAMP if samples is None else samples, events=events,
           sample_rate=sample_rate)
    return r


def test_load_reports_curve_metadata_and_rejects_bad_input():
    r = reducer()
    info = r.load("walk", [0.0, 1.0, 0.5, 2.0, 1.5], events=[3, 1, 1],
                  sample_rate=30)
    assert info.curve_id == "walk"
    assert info.sample_rate == 30
    assert info.sample_count == 5
    assert info.events == (1, 3)
    assert r.stats()["samples"] == 5

    bad_calls = [
        ([], None, 30),
        ([0.0, 1.0, 2.0], None, 30),
        ([0.0, "x", 2.0, 3.0], None, 30),
        ([0.0, 1.0, 2.0, 3.0], None, 0),
        ([0.0, 1.0, 2.0, 3.0], None, -30),
        ([0.0, 1.0, 2.0, 3.0], [4], 30),
        ([0.0, 1.0, 2.0, 3.0], [-1], 30),
    ]
    for samples, events, sample_rate in bad_calls:
        with pytest.raises(ck.CurveReducerError) as exc:
            r.load("walk", samples, events=events, sample_rate=sample_rate)
        assert exc.value.code == "CURVE_INVALID_INPUT"
    assert r.stats()["samples"] == 5


def test_tolerance_validation_invalidates_the_compression():
    r = loaded()
    assert r.set_tolerance(0.25) == pytest.approx(0.25)
    keys = r.compress()
    assert r.error_stats()["tolerance"] == pytest.approx(0.25)
    assert len(keys) >= 2
    r.set_tolerance(0.5)
    with pytest.raises(ck.CurveReducerError) as exc:
        r.reconstruct()
    assert exc.value.code == "CURVE_NOT_COMPRESSED"
    for bad in (0, -0.5, math.nan, math.inf):
        with pytest.raises(ck.CurveReducerError) as exc:
            r.set_tolerance(bad)
        assert exc.value.code == "CURVE_INVALID_TOLERANCE"
    assert r.set_tolerance(0.125) == pytest.approx(0.125)


def test_compress_returns_sorted_unique_indices():
    r = loaded(SINE)
    keys = r.compress()
    assert keys[0] == 0
    assert keys[-1] == len(SINE) - 1
    assert keys == sorted(set(keys))
    assert all(0 <= key < len(SINE) for key in keys)
    assert 2 < len(keys) < len(SINE)
    assert r.compress() == keys


def test_compression_stays_inside_the_error_budget():
    r = loaded(SINE)
    r.set_tolerance(0.05)
    r.compress()
    stats = r.error_stats()
    assert stats["samples"] == len(SINE)
    assert stats["keys"] >= 2
    assert stats["max_error"] <= 0.05
    assert stats["violations"] == 0
    assert stats["mean_error"] <= stats["max_error"]
    rebuilt = r.reconstruct()
    assert len(rebuilt) == len(SINE)
    worst = max(abs(left - right) for left, right in zip(rebuilt, SINE))
    assert worst <= 0.05


def test_linear_curve_keeps_only_the_endpoints():
    r = loaded(RAMP)
    r.set_tolerance(0.01)
    assert r.compress() == [0, len(RAMP) - 1]
    rebuilt = r.reconstruct()
    assert list(rebuilt) == pytest.approx(RAMP)
    assert r.error_stats()["max_error"] == pytest.approx(0.0, abs=1e-12)


def test_forced_keys_keep_the_peak_of_the_curve():
    samples = [0.0] * 21
    samples[10] = 100.0
    r = loaded(samples)
    r.set_tolerance(5.0)
    keys = r.compress()
    assert 10 in keys
    assert 10 in r.forced_keys()
    assert r.reconstruct()[10] == pytest.approx(100.0)


def test_tighter_tolerance_never_loses_keys():
    r = loaded(SINE)
    r.set_tolerance(1.0)
    coarse = r.compress()
    coarse_error = r.error_stats()["max_error"]
    r.set_tolerance(0.05)
    fine = r.compress()
    fine_error = r.error_stats()["max_error"]
    assert len(fine) >= len(coarse)
    assert fine_error <= coarse_error
    assert fine_error <= 0.05
    r.set_tolerance(0.0005)
    finest = r.compress()
    assert len(finest) >= len(fine)
    assert r.error_stats()["max_error"] <= 0.0005


def test_reconstruct_interpolates_between_keys():
    samples = [0.0, 10.0, 0.0, 10.0, 0.0]
    r = loaded(samples)
    r.set_tolerance(100.0)
    assert r.compress() == [0, 1, 4]
    rebuilt = r.reconstruct()
    assert rebuilt[0] == pytest.approx(0.0)
    assert rebuilt[1] == pytest.approx(10.0)
    assert rebuilt[2] == pytest.approx(10.0 - 10.0 / 3.0)
    assert rebuilt[3] == pytest.approx(10.0 - 20.0 / 3.0)
    assert rebuilt[4] == pytest.approx(0.0)


def test_forced_keys_cover_endpoints_extrema_and_events():
    samples = [float((index % 5) - 2) for index in range(24)]
    r = loaded(samples, events=[9, 17])
    forced = r.forced_keys()
    assert 0 in forced
    assert len(samples) - 1 in forced
    assert 9 in forced
    assert 17 in forced
    assert samples.index(max(samples)) in forced
    assert samples.index(min(samples)) in forced
    assert list(forced) == sorted(set(forced))
    keys = r.compress()
    for index in (0, 9, 17, len(samples) - 1):
        assert index in keys


def test_loading_a_new_curve_resets_the_track():
    r = loaded(RAMP)
    r.compress()
    info = r.load("jump", SINE, events=[100], sample_rate=120)
    assert info.curve_id == "jump"
    assert info.events == (100,)
    assert info.sample_rate == 120
    with pytest.raises(ck.CurveReducerError) as exc:
        r.reconstruct()
    assert exc.value.code == "CURVE_NOT_COMPRESSED"
    r.compress()
    assert r.stats()["curve_id"] == "jump"
    assert r.stats()["samples"] == len(SINE)
    assert r.stats()["compressions"] == 2


def test_operations_require_a_loaded_and_compressed_curve():
    r = reducer()
    for call in (r.compress, r.reconstruct, r.forced_keys, r.error_stats,
                 r.serialize_curve):
        with pytest.raises(ck.CurveReducerError) as exc:
            call()
        assert exc.value.code == "CURVE_NOT_LOADED"
    r.load("walk", RAMP, sample_rate=30)
    for call in (r.reconstruct, r.error_stats, r.serialize_curve):
        with pytest.raises(ck.CurveReducerError) as exc:
            call()
        assert exc.value.code == "CURVE_NOT_COMPRESSED"


def test_serialize_roundtrip_reproduces_the_track():
    r = loaded(SINE, events=[30, 90])
    r.set_tolerance(0.1)
    keys = r.compress()
    blob = r.serialize_curve()
    assert isinstance(blob, str)
    assert "\n" not in blob
    assert blob.startswith("CURVE1|")
    assert r.serialize_curve() == blob

    clone = reducer()
    info = clone.deserialize(blob)
    assert info.curve_id == "walk"
    assert info.sample_count == len(SINE)
    assert info.sample_rate == 30
    assert info.events == (30, 90)
    assert clone.stats()["tolerance"] == pytest.approx(0.1)
    assert clone.compress() == keys
    assert clone.reconstruct() == r.reconstruct()
    assert list(clone.reconstruct()) == pytest.approx(SINE, abs=0.1)
    assert clone.error_stats()["max_error"] == pytest.approx(
        r.error_stats()["max_error"])


def test_deserialize_rejects_broken_payloads():
    r = loaded(RAMP)
    r.compress()
    blob = r.serialize_curve()
    for payload in ("", "garbage", "CURVE2|x=1", blob[:-7],
                    blob.replace("samples=", "sample=")):
        with pytest.raises(ck.CurveReducerError) as exc:
            r.deserialize(payload)
        assert exc.value.code == "CURVE_SERIALIZE_INVALID"
    assert r.compress() == [0, len(RAMP) - 1]


def test_snapshot_roundtrip_keeps_the_track():
    r = loaded(SINE, events=[30, 90])
    r.set_tolerance(0.2)
    keys = r.compress()
    state = r.snapshot()
    assert set(state) == {"version", "curve_id", "sample_rate", "tolerance",
                          "samples", "events", "keys", "counters"}
    pristine = copy.deepcopy(state)
    state["samples"].clear()
    state["counters"]["compressions"] = 99
    assert r.stats()["samples"] == len(SINE)
    assert r.stats()["compressions"] == 1

    clone = reducer()
    clone.restore(pristine)
    assert clone.stats()["curve_id"] == "walk"
    assert clone.stats()["sample_rate"] == 30
    assert clone.stats()["tolerance"] == pytest.approx(0.2)
    assert clone.stats()["compressions"] == 1
    assert clone.forced_keys() == r.forced_keys()
    assert clone.compress() == keys
    assert clone.reconstruct() == r.reconstruct()
    assert list(clone.reconstruct()) == pytest.approx(SINE, abs=0.2)


def test_restore_rejects_malformed_snapshots():
    r = loaded(RAMP)
    keys = r.compress()
    valid = r.snapshot()
    bad_snapshots = [
        None,
        {},
        dict(valid, version=2),
        dict(valid, samples=[0.0, 1.0]),
        dict(valid, samples="ramp"),
        dict(valid, sample_rate=0),
        dict(valid, keys="all"),
        dict(valid, events=[3, 3]),
        dict(valid, counters=[]),
        {key: value for key, value in valid.items() if key != "tolerance"},
    ]
    for snapshot in bad_snapshots:
        with pytest.raises(ck.CurveReducerError) as exc:
            r.restore(snapshot)
        assert exc.value.code == "CURVE_SNAPSHOT_INVALID"
    assert r.compress() == keys
    assert r.stats()["samples"] == len(RAMP)
