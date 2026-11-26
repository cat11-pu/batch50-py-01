import copy
import json
import threading

import pytest

import rlimit_profile_switcher as rp

BASE = rp.DEFAULT_LIMITS
T0 = "2026-11-20T08:00:00+00:00"


def guard(**kwargs):
    return rp.RlimitProfileSwitcher(**kwargs)


def test_define_profile_keeps_sorted_partial_targets():
    guard_obj = guard()
    spec = guard_obj.define_profile("build", {"nofile": (4096, None), "nproc": (256, 512)})
    assert isinstance(spec, rp.ProfileSpec)
    assert spec.name == "build"
    assert list(spec.limits) == ["nofile", "nproc"]
    assert spec.limits["nofile"] == (4096, None)
    assert spec.limits["nproc"] == (256, 512)
    assert guard_obj.stats()["profiles"] == 1


def test_define_profile_refuses_invalid_targets():
    guard_obj = guard()
    bad = [
        ("", {"nofile": (1, 2)}),
        ("   ", {"nofile": (1, 2)}),
        ("bad-key", {"files": (1, 2)}),
        ("empty", {}),
        ("neg", {"nofile": (-1, 8)}),
        ("order", {"nofile": (8, 4)}),
        ("bool", {"nofile": (True, 8)}),
        ("shape", {"nofile": (1, 2, 3)}),
        ("text", {"nofile": "1-2"}),
    ]
    for name, limits in bad:
        with pytest.raises(rp.RlimitError) as exc:
            guard_obj.define_profile(name, limits)
        assert exc.value.code == "PROFILE_INVALID"
    assert guard_obj.stats()["profiles"] == 0


def test_define_profile_refuses_duplicate_and_capacity():
    guard_obj = guard(max_profiles=2)
    guard_obj.define_profile("one", {"nofile": (1, 2)})
    guard_obj.define_profile("two", {"nofile": (1, 2)})
    with pytest.raises(rp.RlimitError) as dup:
        guard_obj.define_profile("one", {"nofile": (3, 4)})
    assert dup.value.code == "PROFILE_EXISTS"
    with pytest.raises(rp.RlimitError) as cap:
        guard_obj.define_profile("three", {"nofile": (1, 2)})
    assert cap.value.code == "PROFILE_CAPACITY"
    assert guard_obj.stats()["profiles"] == 2


def test_apply_profile_lowers_soft_and_hard_together():
    guard_obj = guard()
    guard_obj.define_profile("tight", {"nofile": (256, 512)})
    effective = guard_obj.apply_profile(4101, "tight")
    assert effective["nofile"] == (256, 512)
    assert effective["nproc"] == BASE["nproc"]
    assert effective["stack"] == BASE["stack"]
    effective["nofile"] = (1, 2)
    effective["extra"] = (0, 0)
    assert guard_obj.effective_limits(4101) == {
        "nofile": (256, 512),
        "nproc": BASE["nproc"],
        "stack": BASE["stack"],
    }
    assert guard_obj.profile_of(4101) == "tight"
    assert guard_obj.stats()["applied"] == 1
    assert guard_obj.effective_limits(9999) == BASE


def test_bind_refuses_hard_limit_raise_and_keeps_state():
    guard_obj = guard()
    guard_obj.define_profile("low", {"nofile": (256, 512)})
    guard_obj.define_profile("wide", {"nofile": (256, 4096)})
    assert guard_obj.bind_pid(4202, "low", start_time=T0) == 1
    with pytest.raises(rp.RlimitError) as exc:
        guard_obj.bind_pid(4202, "wide", start_time=T0)
    assert exc.value.code == "HARD_RAISE_REFUSED"
    assert guard_obj.effective_limits(4202)["nofile"] == (256, 512)
    assert [frame.profile for frame in guard_obj.frames(4202)] == ["low"]
    assert guard_obj.stats()["denied"] == 1


def test_bind_refuses_soft_above_resulting_hard():
    guard_obj = guard()
    guard_obj.define_profile("half", {"nofile": (None, 512)})
    with pytest.raises(rp.RlimitError) as exc:
        guard_obj.bind_pid(4303, "half", start_time=T0)
    assert exc.value.code == "SOFT_ABOVE_HARD"
    assert guard_obj.effective_limits(4303)["nofile"] == BASE["nofile"]


def test_rollback_is_lifo_and_reports_popped_names():
    guard_obj = guard()
    guard_obj.define_profile("a", {"nofile": (800, 2048)})
    guard_obj.define_profile("b", {"nofile": (400, 1024)})
    guard_obj.bind_pid(4404, "a", start_time=T0)
    assert guard_obj.bind_pid(4404, "b", start_time=T0) == 2
    assert guard_obj.effective_limits(4404)["nofile"] == (400, 1024)
    assert guard_obj.rollback_last(4404) == ("b",)
    assert guard_obj.effective_limits(4404)["nofile"] == (800, 2048)
    assert guard_obj.profile_of(4404) == "a"
    assert guard_obj.rollback_last(4404) == ("a",)
    assert guard_obj.effective_limits(4404) == BASE
    assert guard_obj.rollback_last(4404) == ()
    assert guard_obj.stats()["frames_popped"] == 2


def test_frame_capacity_and_unknown_profile_are_rejected():
    guard_obj = guard(max_frames_per_pid=2)
    guard_obj.define_profile("p1", {"nofile": (900, 3800)})
    guard_obj.define_profile("p2", {"nofile": (800, 3600)})
    guard_obj.define_profile("p3", {"nofile": (700, 3400)})
    guard_obj.bind_pid(4505, "p1", start_time=T0)
    guard_obj.bind_pid(4505, "p2", start_time=T0)
    with pytest.raises(rp.RlimitError) as cap:
        guard_obj.bind_pid(4505, "p3", start_time=T0)
    assert cap.value.code == "FRAME_CAPACITY"
    with pytest.raises(rp.RlimitError) as unknown:
        guard_obj.bind_pid(4506, "nope", start_time=T0)
    assert unknown.value.code == "PROFILE_UNKNOWN"
    assert len(guard_obj.frames(4505)) == 2


def test_remove_profile_refused_while_bound():
    guard_obj = guard()
    guard_obj.define_profile("held", {"nofile": (700, 3000)})
    guard_obj.bind_pid(4606, "held", start_time=T0)
    with pytest.raises(rp.RlimitError) as exc:
        guard_obj.remove_profile("held")
    assert exc.value.code == "PROFILE_IN_USE"
    assert guard_obj.remove_profile("absent") is False
    guard_obj.rollback_last(4606)
    assert guard_obj.remove_profile("held") is True
    assert guard_obj.stats()["profiles"] == 0


def test_child_inherits_parent_snapshot_and_keeps_it():
    guard_obj = guard()
    guard_obj.define_profile("svc", {"nofile": (600, 2048), "nproc": (128, 256)})
    guard_obj.bind_pid(4707, "svc", start_time=T0)
    inherited = guard_obj.inherit(4707, 4708, start_time="2026-11-20T08:01:00+00:00")
    assert inherited["nofile"] == (600, 2048)
    assert inherited["nproc"] == (128, 256)
    guard_obj.rollback_last(4707)
    assert guard_obj.effective_limits(4708)["nofile"] == (600, 2048)
    assert guard_obj.effective_limits(4708)["stack"] == BASE["stack"]
    with pytest.raises(rp.RlimitError) as exc:
        guard_obj.inherit(1, 4708, start_time="t-late")
    assert exc.value.code == "PID_UNKNOWN"


def test_save_and_load_reattach_frames(tmp_path):
    path = tmp_path / "profiles.json"
    guard_obj = guard()
    guard_obj.define_profile("outer", {"nofile": (900, 3800)})
    guard_obj.define_profile("inner", {"nofile": (300, 1200), "nproc": (64, 128)})
    guard_obj.register_process(4809, T0)
    guard_obj.bind_pid(4809, "outer", start_time=T0, tenant="acme")
    guard_obj.bind_pid(4809, "inner", start_time=T0)
    assert guard_obj.save(str(path)) == 1

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert raw["schema"] == rp.SCHEMA_VERSION
    assert list(raw["frames"]["4809"][0]) == ["outer", "acme"]

    other = guard()
    other.register_process(4809, T0)
    assert other.load(str(path)) == {"reattached": 1, "stale": 0}
    assert [frame.profile for frame in other.frames(4809)] == ["outer", "inner"]
    assert other.effective_limits(4809)["nofile"] == (300, 1200)
    assert other.effective_limits(4809)["nproc"] == (64, 128)
    assert other.profile_of(4809) == "inner"
    assert other.stats()["loads"] == 1


def test_load_rejects_broken_state_without_touching_live_data(tmp_path):
    guard_obj = guard()
    guard_obj.define_profile("keep", {"nofile": (500, 2000)})
    guard_obj.bind_pid(4901, "keep", start_time=T0)
    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")

    for path in (broken, tmp_path / "missing.json"):
        with pytest.raises(rp.RlimitError) as exc:
            guard_obj.load(str(path))
        assert exc.value.code == "STATE_INVALID"

    wrong = tmp_path / "wrong.json"
    wrong.write_text(json.dumps({"schema": 999}), encoding="utf-8")
    with pytest.raises(rp.RlimitError) as exc:
        guard_obj.load(str(wrong))
    assert exc.value.code == "STATE_INVALID"
    assert guard_obj.profile_of(4901) == "keep"
    assert guard_obj.stats()["loads"] == 0


def test_snapshot_is_detached_and_restore_validates():
    guard_obj = guard()
    guard_obj.define_profile("snap", {"nofile": (450, 1900)})
    guard_obj.bind_pid(5001, "snap", start_time=T0)
    state = guard_obj.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"schema", "profiles", "processes", "bases", "frames", "stats"}

    state["frames"].clear()
    state["stats"]["applied"] = 77
    assert guard_obj.profile_of(5001) == "snap"
    assert guard_obj.stats()["applied"] == 1

    clone = guard()
    clone.restore(pristine)
    assert clone.profile_of(5001) == "snap"
    assert clone.effective_limits(5001)["nofile"] == (450, 1900)
    assert clone.stats()["applied"] == 1

    for bad in (None, {}, {"schema": 1, "profiles": {}, "processes": {},
                           "bases": {}, "frames": {}}):
        with pytest.raises(rp.RlimitError) as exc:
            guard_obj.restore(bad)
        assert exc.value.code == "SNAPSHOT_INVALID"
    assert guard_obj.profile_of(5001) == "snap"


def test_stats_count_each_operation_once():
    guard_obj = guard()
    guard_obj.define_profile("s1", {"nofile": (800, 3200)})
    guard_obj.define_profile("s2", {"nofile": (700, 2800)})
    guard_obj.define_profile("s3", {"nofile": (700, 3000)})
    guard_obj.bind_pid(5102, "s1", start_time=T0)
    guard_obj.bind_pid(5102, "s2", start_time=T0)
    with pytest.raises(rp.RlimitError):
        guard_obj.bind_pid(5102, "s3", start_time=T0)
    guard_obj.rollback_last(5102)
    assert guard_obj.stats() == {
        "profiles": 2,
        "applied": 2,
        "denied": 1,
        "frames_popped": 1,
        "stale_bindings": 0,
        "saves": 0,
        "loads": 0,
    }


def test_concurrent_binds_serialize_on_one_pid():
    guard_obj = guard(max_frames_per_pid=8)
    names = [f"p{index}" for index in range(8)]
    for name in names:
        guard_obj.define_profile(name, {"nofile": (600, 2500)})
    barrier = threading.Barrier(len(names))
    errors = []

    def worker(name):
        try:
            barrier.wait(timeout=5)
            guard_obj.bind_pid(5203, name, start_time=T0)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(name,)) for name in names]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert [frame.profile for frame in guard_obj.frames(5203)] == names
    assert guard_obj.stats()["applied"] == len(names)
    assert guard_obj.stats()["denied"] == 0
