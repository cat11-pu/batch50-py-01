import os

import pytest

import cron_job_warden as cjw

T0 = "2026-11-26T00:00:00+00:00"
T600 = "2026-11-26T00:10:00+00:00"
T3599 = "2026-11-26T00:59:59+00:00"
T3600 = "2026-11-26T01:00:00+00:00"
T7200 = "2026-11-26T02:00:00+00:00"


def warden(tmp_path, **kwargs):
    kwargs.setdefault("work_root", str(tmp_path / "jobs"))
    return cjw.CronJobWarden(**kwargs)


def register(a, job_id="job-a", *, user="alice", command="/bin/true",
             schedule="every:600", crontab_path=None, **kwargs):
    return a.register(job_id, user=user, command=command, schedule=schedule,
                      crontab_path=crontab_path or f"/etc/cron.d/{job_id}", **kwargs)


def test_register_records_job(tmp_path):
    a = warden(tmp_path)
    rec = register(a, crontab_owner="alice", max_concurrent=2, now=T0)
    assert (rec.job_id, rec.user, rec.schedule, rec.enabled) == (
        "job-a", "alice", "every:600", True)
    assert rec.max_concurrent == 2
    assert rec.registered_at == T0
    assert a.status()["jobs"] == 1
    assert a.status()["enabled"] == 1
    assert a.stats()["registered"] == 1


def test_register_rejects_ownership_mismatch(tmp_path):
    a = warden(tmp_path)
    with pytest.raises(cjw.CronWardenError) as exc:
        register(a, crontab_owner="bob")
    assert exc.value.code == "CRON_OWNERSHIP_MISMATCH"
    assert a.status()["jobs"] == 0
    assert a.stats()["registered"] == 0


def test_register_rejects_duplicate_job_id(tmp_path):
    a = warden(tmp_path)
    register(a, command="/bin/true")
    with pytest.raises(cjw.CronWardenError) as exc:
        register(a, command="/bin/false")
    assert exc.value.code == "CRON_JOB_DUPLICATE"
    assert a.status()["jobs"] == 1
    assert a.stats()["registered"] == 1
    assert a.render_crontab("alice") == "every:600 /bin/true\n"


def test_register_enforces_per_user_quota(tmp_path):
    a = warden(tmp_path, max_jobs_per_user=2)
    register(a, "job-1")
    register(a, "job-2")
    with pytest.raises(cjw.CronWardenError) as exc:
        register(a, "job-3")
    assert exc.value.code == "CRON_JOB_QUOTA_EXCEEDED"
    assert a.status()["jobs"] == 2
    assert a.stats()["registered"] == 2


def test_register_rejects_invalid_schedule(tmp_path):
    a = warden(tmp_path)
    for index, bad in enumerate(("not-a-schedule", "every:30", "every:90000", "daily:25:00")):
        with pytest.raises(cjw.CronWardenError) as exc:
            register(a, f"job-{index}", schedule=bad)
        assert exc.value.code == "CRON_SCHEDULE_INVALID"
    assert a.status()["jobs"] == 0


def test_disable_blocks_authorize_run(tmp_path):
    a = warden(tmp_path)
    register(a)
    assert a.disable("job-a") is True
    assert a.disable("job-a") is False
    with pytest.raises(cjw.CronWardenError) as exc:
        a.authorize_run("job-a", now=T0)
    assert exc.value.code == "CRON_JOB_DISABLED"
    assert a.enable("job-a") is True
    assert a.authorize_run("job-a", now=T0).state == "queued"
    assert a.stats()["disabled"] == 1
    assert a.stats()["enabled"] == 1


def test_acquire_slot_respects_job_concurrency(tmp_path):
    a = warden(tmp_path)
    register(a, max_concurrent=1)
    first = a.authorize_run("job-a", now=T0)
    second = a.authorize_run("job-a", now=T0)
    assert first.state == "queued"
    assert first.run_id != second.run_id
    running = a.acquire_slot(first.run_id, now=T0)
    assert (running.state, running.slot, running.started_at) == ("running", 1, T0)
    with pytest.raises(cjw.CronWardenError) as exc:
        a.acquire_slot(second.run_id, now=T0)
    assert exc.value.code == "CRON_CONCURRENCY_LIMIT"
    a.finish(first.run_id, now=T600)
    assert a.acquire_slot(second.run_id, now=T600).slot == 1


def test_finish_releases_slot_and_is_idempotent(tmp_path):
    a = warden(tmp_path)
    register(a)
    run = a.authorize_run("job-a", now=T0)
    a.acquire_slot(run.run_id, now=T0)
    done = a.finish(run.run_id, now=T600, exit_code=0)
    assert (done.state, done.exit_code, done.slot) == ("finished", 0, None)
    again = a.finish(run.run_id, now=T7200, exit_code=9)
    assert again.state == "finished"
    assert again.exit_code == 0
    assert a.stats()["runs_finished"] == 1
    assert a.status()["running"] == 0


def test_authorize_run_rejects_unknown_job_and_run(tmp_path):
    a = warden(tmp_path)
    with pytest.raises(cjw.CronWardenError) as exc:
        a.authorize_run("job-missing", now=T0)
    assert exc.value.code == "CRON_JOB_UNKNOWN"
    with pytest.raises(cjw.CronWardenError) as exc:
        a.finish("run-999", now=T0)
    assert exc.value.code == "CRON_RUN_UNKNOWN"
    assert a.stats()["runs_authorized"] == 0


def test_reap_stops_overdue_runs(tmp_path):
    a = warden(tmp_path, max_runtime=3600)
    register(a)
    run = a.authorize_run("job-a", now=T0)
    a.acquire_slot(run.run_id, now=T0)
    assert a.reap(now=T3599) == 0
    assert a.reap(now=T3600) == 1
    assert a.reap(now=T7200) == 0
    assert a.status()["running"] == 0
    assert a.status()["reaped"] == 1
    assert a.stats()["runs_reaped"] == 1


def test_restore_reaps_dangling_runs_after_restart(tmp_path):
    a = warden(tmp_path, max_runtime=3600)
    register(a)
    run = a.authorize_run("job-a", now=T0)
    a.acquire_slot(run.run_id, now=T0)
    state = a.snapshot()
    clone = warden(tmp_path, max_runtime=3600)
    clone.restore(state)
    assert clone.status()["running"] == 1
    assert clone.reap(now=T3600) == 1
    assert clone.status()["reaped"] == 1
    assert clone.stats()["runs_reaped"] == 1


def test_env_for_drops_dangerous_variables(tmp_path):
    root = tmp_path / "jobs"
    a = warden(tmp_path)
    register(a)
    environ = {
        "PATH": "/usr/bin:/bin",
        "HOME": "/home/alice",
        "LANG": "C.UTF-8",
        "LOGNAME": "alice",
        "IFS": " ",
        "LD_PRELOAD": "/tmp/inject.so",
        "BASH_ENV": "/tmp/env.sh",
        "PYTHONPATH": "/tmp/py",
        "FOO": "bar",
    }
    assert a.env_for("job-a", environ) == {
        "PATH": "/usr/bin:/bin",
        "HOME": "/home/alice",
        "LANG": "C.UTF-8",
        "LOGNAME": "alice",
        "SHELL": "/bin/sh",
        "PWD": os.path.join(str(root), "alice"),
    }
    assert environ["IFS"] == " "


def test_workdir_for_is_user_scoped(tmp_path):
    root = tmp_path / "jobs"
    a = warden(tmp_path)
    register(a, "job-a", user="alice")
    register(a, "job-b", user="bob")
    assert a.workdir_for("job-a") == os.path.join(str(root), "alice")
    assert a.workdir_for("job-b") == os.path.join(str(root), "bob")
    assert a.workdir_for("job-a") != a.workdir_for("job-b")


def test_render_crontab_and_write_is_atomic(tmp_path):
    a = warden(tmp_path)
    register(a, "job-b", command="echo b", schedule="every:300",
             crontab_path=str(tmp_path / "cron.b"))
    register(a, "job-a", command="/usr/local/bin/a", schedule="daily:03:00",
             crontab_path=str(tmp_path / "cron.a"))
    text = a.render_crontab("alice")
    assert text == "daily:03:00 /usr/local/bin/a\nevery:300 echo b\n"
    target = tmp_path / "crontab.alice"
    written = a.write_crontab("alice", str(target))
    assert written == len(text.encode("utf-8"))
    assert target.read_text(encoding="utf-8") == text
    a.disable("job-b")
    trimmed = "daily:03:00 /usr/local/bin/a\n"
    assert a.write_crontab("alice", str(target)) == len(trimmed.encode("utf-8"))
    assert target.read_text(encoding="utf-8") == trimmed


def test_status_and_stats_lifecycle(tmp_path):
    a = warden(tmp_path)
    register(a, "job-1", user="alice", command="echo 1", schedule="every:600")
    register(a, "job-2", user="bob", command="echo 2", schedule="daily:01:00",
             max_concurrent=2)
    a.disable("job-2")
    run = a.authorize_run("job-1", now=T0)
    a.acquire_slot(run.run_id, now=T0)
    a.finish(run.run_id, now=T600, exit_code=3)
    assert a.status() == {
        "jobs": 2,
        "enabled": 1,
        "disabled": 1,
        "queued": 0,
        "running": 0,
        "finished": 1,
        "reaped": 0,
        "users": 2,
        "locked_users": 0,
    }
    assert a.stats() == {
        "registered": 2,
        "removed": 0,
        "disabled": 1,
        "enabled": 0,
        "runs_authorized": 1,
        "slots_acquired": 1,
        "runs_finished": 1,
        "runs_reaped": 0,
    }
