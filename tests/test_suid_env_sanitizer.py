import copy
import threading

import pytest

import suid_env_sanitizer as suid

NOW = "2026-11-26T00:00:00+00:00"


def sanitizer(**kwargs):
    params = dict(helper_id="logrotate-helper", allowed_callers=(1000, 1001))
    params.update(kwargs)
    return suid.SuidEnvSanitizer(**params)


def launch(s, *, caller_uid=1000, target_uid=1000, target_gid=1000,
           env=None, open_fds=None, now=NOW):
    return s.build_launch_plan(
        caller_uid=caller_uid,
        target_uid=target_uid,
        target_gid=target_gid,
        env={"PATH": "/usr/bin"} if env is None else env,
        open_fds=[0, 1, 2] if open_fds is None else open_fds,
        now=now,
    )


def test_sanitize_keeps_whitelisted_and_drops_unknown():
    s = sanitizer()
    report = s.sanitize_environment(
        {"PATH": "/usr/bin", "LANG": "C", "APP_TOKEN": "x", "USER": "svc"}
    )
    assert report.kept == {"LANG": "C", "PATH": "/usr/bin", "USER": "svc"}
    assert report.dropped == ("APP_TOKEN",)
    assert report.stripped == ()


def test_sanitize_strips_dangerous_prefixes_and_names():
    s = sanitizer()
    report = s.sanitize_environment(
        {"GCONV_PATH": "/tmp/x", "PYTHONPATH": "/tmp", "IFS": " ", "HOME": "/root"}
    )
    assert report.stripped == ("GCONV_PATH", "IFS", "PYTHONPATH")
    assert report.kept == {"HOME": "/root"}
    assert report.dropped == ()


def test_sanitize_rejects_malformed_environment():
    s = sanitizer()
    bad_envs = [None, ["PATH=/bin"], {"": "x"}, {"A=B": "x"}, {"OK": 5},
                {"OK": "a\0b"}]
    for env in bad_envs:
        with pytest.raises(suid.SuidEnvError) as exc:
            s.sanitize_environment(env)
        assert exc.value.code == "SUID_INVALID_REQUEST"


def test_sanitize_enforces_byte_budget():
    s = sanitizer(max_env_bytes=16)
    with pytest.raises(suid.SuidEnvError) as exc:
        s.sanitize_environment({"PATH": "/usr/local/bin"})
    assert exc.value.code == "SUID_ENV_TOO_LARGE"


def test_descriptor_plan_closes_inherited_extras():
    s = sanitizer()
    plan = s.plan_descriptors([0, 1, 2, 7, 7, 9])
    assert {0, 1, 2} <= set(plan.keep)
    assert plan.close == (7, 9)
    assert len(plan.close) == 2


def test_descriptor_plan_rejects_out_of_range():
    s = sanitizer(max_fd=64)
    for fds in ([-1], [0, 600], ["3"], [2.5]):
        with pytest.raises(suid.SuidEnvError) as exc:
            s.plan_descriptors(fds)
        assert exc.value.code == "SUID_FD_INVALID"


def test_caller_not_allowed_is_refused_and_audited():
    s = sanitizer()
    with pytest.raises(suid.SuidEnvError) as exc:
        launch(s, caller_uid=2000)
    assert exc.value.code == "SUID_CALLER_NOT_ALLOWED"
    assert s.stats()["refused"] == 1
    assert s.stats()["pending"] == 0
    entries = s.audit_entries()
    assert len(entries) == 1
    assert entries[0].outcome == "refused"
    assert entries[0].code == "SUID_CALLER_NOT_ALLOWED"


def test_root_caller_requires_explicit_optin():
    s = sanitizer()
    with pytest.raises(suid.SuidEnvError) as exc:
        launch(s, caller_uid=0)
    assert exc.value.code == "SUID_ROOT_CALLER_REFUSED"

    allowed = sanitizer(allowed_callers=(0, 1000), allow_root_caller=True)
    plan = launch(allowed, caller_uid=0)
    assert plan.caller_uid == 0
    assert plan.state == "planned"
    assert allowed.pending_launches() == (plan.launch_id,)


def test_drop_target_cannot_be_root():
    s = sanitizer()
    with pytest.raises(suid.SuidEnvError) as exc:
        launch(s, target_uid=0, target_gid=0)
    assert exc.value.code == "SUID_DROP_REFUSED"
    assert s.stats()["pending"] == 0


def test_advance_enforces_stage_order():
    s = sanitizer()
    plan = launch(s)
    with pytest.raises(suid.SuidEnvError) as exc:
        s.advance(plan.launch_id, "drop_privileges")
    assert exc.value.code == "SUID_STAGE_ORDER"
    assert s.advance(plan.launch_id, "sanitize_env") == "sanitize_env"
    with pytest.raises(suid.SuidEnvError) as exc:
        s.advance(plan.launch_id, "sanitize_env")
    assert exc.value.code == "SUID_STAGE_ORDER"
    assert s.advance(plan.launch_id, "close_fds") == "close_fds"
    assert s.stats()["pending"] == 1


def test_commit_writes_audit_and_receipt():
    s = sanitizer()
    plan = launch(s, env={"PATH": "/usr/bin", "IFS": " ", "JUNK": "1"},
                  open_fds=[0, 1, 2, 7, 9])
    receipt = s.commit(plan.launch_id)
    assert receipt.status == "launched"
    assert receipt.stages == suid.STAGES
    assert receipt.audit_seq == 1
    stats = s.stats()
    assert stats["launches"] == 1
    assert stats["audit_writes"] == 1
    assert stats["pending"] == 0
    assert stats["env_kept"] == 1
    assert stats["env_stripped"] == 1
    assert stats["env_dropped"] == 1
    assert stats["fds_closed"] == 2
    entries = s.audit_entries()
    assert len(entries) == 1
    assert entries[0].launch_id == plan.launch_id
    assert entries[0].outcome == "launched"
    assert len(s.audit_digest()) == 64
    assert s.verify_audit() is True


def test_commit_replay_is_refused_once():
    s = sanitizer()
    plan = launch(s)
    s.commit(plan.launch_id)
    with pytest.raises(suid.SuidEnvError) as exc:
        s.commit(plan.launch_id)
    assert exc.value.code == "SUID_LAUNCH_REPLAY"
    stats = s.stats()
    assert stats["launches"] == 1
    assert stats["replayed"] == 1
    assert stats["audit_writes"] == 2
    assert [entry.outcome for entry in s.audit_entries()] == ["launched", "replayed"]


def test_snapshot_restore_roundtrip():
    s = sanitizer()
    plan = launch(s)
    s.commit(plan.launch_id)
    snap = s.snapshot()
    assert set(snap) == {"config", "plans", "audit", "counters", "stats"}
    pristine = copy.deepcopy(snap)

    snap["stats"]["launches"] = 999
    snap["plans"].clear()
    snap["audit"].clear()
    assert s.stats()["launches"] == 1
    assert len(s.audit_entries()) == 1

    clone = sanitizer()
    clone.restore(pristine)
    assert clone.stats() == s.stats()
    assert clone.audit_digest() == s.audit_digest()
    assert clone.audit_entries()[0].launch_id == plan.launch_id
    second = launch(clone)
    receipt = clone.commit(second.launch_id)
    assert receipt.audit_seq == 2


def test_restore_rejects_malformed_snapshot():
    s = sanitizer()
    plan = launch(s)
    s.commit(plan.launch_id)
    before = s.audit_digest()
    snap = s.snapshot()

    missing_key = copy.deepcopy(snap)
    missing_key.pop("stats")
    bad_plans = copy.deepcopy(snap)
    bad_plans["plans"] = "nope"
    bad_audit = copy.deepcopy(snap)
    bad_audit["audit"] = "nope"
    bad_counters = copy.deepcopy(snap)
    bad_counters["counters"] = {"launch_seq": "x", "audit_seq": 1}
    bad_states = [None, {}, missing_key, bad_plans, bad_audit, bad_counters]

    for bad in bad_states:
        with pytest.raises(suid.SuidEnvError) as exc:
            s.restore(bad)
        assert exc.value.code == "SUID_SNAPSHOT_INVALID"

    assert s.stats()["launches"] == 1
    assert s.audit_digest() == before
    assert s.pending_launches() == ()


def test_concurrent_launches_get_unique_ids_and_ordered_audit():
    callers = tuple(range(1000, 1012))
    s = sanitizer(allowed_callers=callers)
    errors = []
    barrier = threading.Barrier(len(callers))

    def worker(uid):
        try:
            barrier.wait(timeout=5)
            plan = launch(s, caller_uid=uid, target_uid=uid, target_gid=uid,
                          open_fds=[0, 1, 2, 7])
            s.commit(plan.launch_id)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(uid,)) for uid in callers]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    stats = s.stats()
    assert stats["launches"] == len(callers)
    assert stats["pending"] == 0
    assert stats["fds_closed"] == len(callers)
    entries = s.audit_entries()
    assert [entry.seq for entry in entries] == list(range(1, len(callers) + 1))
    assert len({entry.launch_id for entry in entries}) == len(callers)
