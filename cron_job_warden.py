"""Cron job governance: ownership checks, quotas, environment scrubbing, run locks."""

from __future__ import annotations

import copy
import os
import re
import tempfile
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone


ERR_INVALID_REQUEST = "CRON_INVALID_REQUEST"
ERR_JOB_DUPLICATE = "CRON_JOB_DUPLICATE"
ERR_JOB_UNKNOWN = "CRON_JOB_UNKNOWN"
ERR_JOB_DISABLED = "CRON_JOB_DISABLED"
ERR_OWNERSHIP_MISMATCH = "CRON_OWNERSHIP_MISMATCH"
ERR_SYMLINK_REFUSED = "CRON_SYMLINK_REFUSED"
ERR_JOB_QUOTA_EXCEEDED = "CRON_JOB_QUOTA_EXCEEDED"
ERR_SCHEDULE_INVALID = "CRON_SCHEDULE_INVALID"
ERR_CONCURRENCY_LIMIT = "CRON_CONCURRENCY_LIMIT"
ERR_RUN_UNKNOWN = "CRON_RUN_UNKNOWN"
ERR_USER_LOCKED = "CRON_USER_LOCKED"
ERR_DUPLICATE_FIRE = "CRON_DUPLICATE_FIRE"
ERR_SNAPSHOT_INVALID = "CRON_SNAPSHOT_INVALID"


_EVERY_RE = re.compile(r"every:(\d+)\Z")
_DAILY_RE = re.compile(r"daily:(?:[01]\d|2[0-3]):[0-5]\d\Z")
_ENV_ALLOWED = ("PATH", "HOME", "LANG", "LOGNAME")
_STATUS_KEYS = (
    "jobs",
    "enabled",
    "disabled",
    "queued",
    "running",
    "finished",
    "reaped",
    "users",
    "locked_users",
)
_STATS_KEYS = (
    "registered",
    "removed",
    "disabled",
    "enabled",
    "runs_authorized",
    "slots_acquired",
    "runs_finished",
    "runs_reaped",
)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _normalize_now(now):
    return _utc_now_iso() if now is None else now


def _timestamp(value) -> float:
    if value is None:
        return datetime.now(timezone.utc).timestamp()
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        return float(value)
    else:
        text = str(value)
        try:
            return float(text)
        except (TypeError, ValueError):
            if text.endswith(("Z", "z")):
                text = text[:-1] + "+00:00"
            parsed = datetime.fromisoformat(text)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.timestamp()


def _valid_schedule(schedule) -> bool:
    if not isinstance(schedule, str):
        return False
    every_match = _EVERY_RE.fullmatch(schedule)
    if every_match:
        return 60 <= int(every_match.group(1)) <= 86400
    return _DAILY_RE.fullmatch(schedule) is not None


def _owner_matches(owner, user) -> bool:
    if owner == user:
        return True
    if isinstance(owner, int) and not isinstance(owner, bool):
        try:
            import pwd

            return pwd.getpwuid(owner).pw_name == user
        except KeyError:
            return False
    return False


def _fire_key(value):
    try:
        hash(value)
        return value
    except TypeError:
        return repr(value)


class CronWardenError(ValueError):
    """Raised when a cron governance step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class JobRecord:
    job_id: str
    user: str
    command: str
    schedule: str
    crontab_path: str
    max_concurrent: int
    enabled: bool
    registered_at: object


@dataclass(frozen=True)
class RunInstance:
    run_id: str
    job_id: str
    user: str
    state: str
    slot: object
    started_at: object
    finished_at: object
    exit_code: object


class CronJobWarden:
    """Register cron jobs, gate their runs and sanitize their execution context."""

    def __init__(self, *, work_root: str = "/var/tmp/jobs",
                 max_jobs_per_user: int = 10,
                 max_concurrent_per_user: int = 4,
                 max_runtime: int = 3600) -> None:
        self.work_root = str(work_root)
        self.max_jobs_per_user = int(max_jobs_per_user)
        self.max_concurrent_per_user = int(max_concurrent_per_user)
        self.max_runtime = int(max_runtime)
        self._lock = threading.RLock()
        self._jobs: dict[str, dict] = {}
        self._runs: dict[str, dict] = {}
        self._locked_users: set[str] = set()
        self._fired: dict[str, set] = {}
        self._stats: dict[str, int] = {key: 0 for key in _STATS_KEYS}

    def _job_record(self, job: dict) -> JobRecord:
        return JobRecord(
            job_id=job["job_id"],
            user=job["user"],
            command=job["command"],
            schedule=job["schedule"],
            crontab_path=job["crontab_path"],
            max_concurrent=job["max_concurrent"],
            enabled=job["enabled"],
            registered_at=job["registered_at"],
        )

    def _run_instance(self, run: dict) -> RunInstance:
        return RunInstance(
            run_id=run["run_id"],
            job_id=run["job_id"],
            user=run["user"],
            state=run["state"],
            slot=run["slot"],
            started_at=run["started_at"],
            finished_at=run["finished_at"],
            exit_code=run["exit_code"],
        )

    def register(self, job_id: str, *, user: str, command: str, schedule: str,
                 crontab_path: str, crontab_owner=None, max_concurrent: int = 1,
                 now=None) -> JobRecord:
        if not _valid_schedule(schedule):
            raise CronWardenError(ERR_SCHEDULE_INVALID)

        with self._lock:
            if job_id in self._jobs:
                raise CronWardenError(ERR_JOB_DUPLICATE)
            if crontab_owner is not None and not _owner_matches(crontab_owner, user):
                raise CronWardenError(ERR_OWNERSHIP_MISMATCH)

            user_job_count = sum(
                1 for job in self._jobs.values() if job["user"] == user
            )
            if user_job_count >= self.max_jobs_per_user:
                raise CronWardenError(ERR_JOB_QUOTA_EXCEEDED)

            job = {
                "job_id": job_id,
                "user": user,
                "command": command,
                "schedule": schedule,
                "crontab_path": crontab_path,
                "crontab_owner": crontab_owner,
                "max_concurrent": max_concurrent,
                "enabled": True,
                "registered_at": _normalize_now(now),
            }
            self._jobs[job_id] = job
            self._stats["registered"] += 1
            return self._job_record(job)

    def remove(self, job_id: str) -> bool:
        with self._lock:
            if job_id not in self._jobs:
                raise CronWardenError(ERR_JOB_UNKNOWN)
            del self._jobs[job_id]
            self._fired.pop(job_id, None)
            self._stats["removed"] += 1
            return True

    def disable(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise CronWardenError(ERR_JOB_UNKNOWN)
            if not job["enabled"]:
                return False
            job["enabled"] = False
            self._stats["disabled"] += 1
            return True

    def enable(self, job_id: str) -> bool:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise CronWardenError(ERR_JOB_UNKNOWN)
            if job["enabled"]:
                return False
            job["enabled"] = True
            self._stats["enabled"] += 1
            return True

    def lock_user(self, user: str) -> None:
        with self._lock:
            self._locked_users.add(user)

    def unlock_user(self, user: str) -> bool:
        with self._lock:
            was_locked = user in self._locked_users
            self._locked_users.discard(user)
            return was_locked

    def authorize_run(self, job_id: str, *, now=None, scheduled_for=None) -> RunInstance:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise CronWardenError(ERR_JOB_UNKNOWN)
            if job["user"] in self._locked_users:
                raise CronWardenError(ERR_USER_LOCKED)
            if not job["enabled"]:
                raise CronWardenError(ERR_JOB_DISABLED)

            fire_key = None
            if scheduled_for is not None:
                fire_key = _fire_key(scheduled_for)
                fired = self._fired.setdefault(job_id, set())
                if fire_key in fired:
                    raise CronWardenError(ERR_DUPLICATE_FIRE)

            run_id = f"run-{uuid.uuid4().hex}"
            run = {
                "run_id": run_id,
                "job_id": job_id,
                "user": job["user"],
                "state": "queued",
                "slot": None,
                "started_at": None,
                "finished_at": None,
                "exit_code": None,
                "authorized_at": _normalize_now(now),
                "scheduled_for": scheduled_for,
                "max_concurrent": job["max_concurrent"],
            }
            self._runs[run_id] = run
            if fire_key is not None:
                fired.add(fire_key)
            self._stats["runs_authorized"] += 1
            return self._run_instance(run)

    def acquire_slot(self, run_id: str, *, now=None) -> RunInstance:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise CronWardenError(ERR_RUN_UNKNOWN)
            if run["state"] == "running":
                return self._run_instance(run)
            if run["state"] != "queued":
                return self._run_instance(run)
            if run["user"] in self._locked_users:
                raise CronWardenError(ERR_USER_LOCKED)

            user_running = sum(
                1
                for candidate in self._runs.values()
                if candidate["user"] == run["user"]
                and candidate["state"] == "running"
            )
            if user_running >= self.max_concurrent_per_user:
                raise CronWardenError(ERR_CONCURRENCY_LIMIT)

            used_job_slots = {
                candidate["slot"]
                for candidate in self._runs.values()
                if candidate["job_id"] == run["job_id"]
                and candidate["state"] == "running"
                and candidate["slot"] is not None
            }
            job_limit = int(run.get("max_concurrent", 1))
            slot = next(
                (
                    candidate_slot
                    for candidate_slot in range(1, job_limit + 1)
                    if candidate_slot not in used_job_slots
                ),
                None,
            )
            if slot is None:
                raise CronWardenError(ERR_CONCURRENCY_LIMIT)

            run["state"] = "running"
            run["slot"] = slot
            run["started_at"] = _normalize_now(now)
            self._stats["slots_acquired"] += 1
            return self._run_instance(run)

    def finish(self, run_id: str, *, now=None, exit_code: int = 0) -> RunInstance:
        with self._lock:
            run = self._runs.get(run_id)
            if run is None:
                raise CronWardenError(ERR_RUN_UNKNOWN)
            if run["state"] in ("finished", "reaped"):
                return self._run_instance(run)

            run["state"] = "finished"
            run["slot"] = None
            run["finished_at"] = _normalize_now(now)
            run["exit_code"] = exit_code
            self._stats["runs_finished"] += 1
            return self._run_instance(run)

    def reap(self, *, now=None, max_runtime=None) -> int:
        runtime = self.max_runtime if max_runtime is None else max_runtime
        with self._lock:
            reap_now = _normalize_now(now)
            reaped = 0
            for run in self._runs.values():
                if run["state"] != "running":
                    continue
                started_at = run.get("started_at")
                if started_at is None:
                    continue
                if _timestamp(reap_now) - _timestamp(started_at) < runtime:
                    continue

                run["state"] = "reaped"
                run["slot"] = None
                run["finished_at"] = reap_now
                reaped += 1
                self._stats["runs_reaped"] += 1
            return reaped

    def env_for(self, job_id: str, environ) -> dict:
        workdir = self.workdir_for(job_id)
        clean_env = {
            key: environ[key] for key in _ENV_ALLOWED if key in environ
        }
        clean_env["SHELL"] = "/bin/sh"
        clean_env["PWD"] = workdir
        return clean_env

    def workdir_for(self, job_id: str) -> str:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise CronWardenError(ERR_JOB_UNKNOWN)
            return os.path.join(self.work_root, job["user"])

    def render_crontab(self, user: str) -> str:
        with self._lock:
            lines = []
            jobs = sorted(
                (job for job in self._jobs.values() if job["user"] == user),
                key=lambda job: job["job_id"],
            )
            for job in jobs:
                if job["enabled"]:
                    lines.append(f"{job['schedule']} {job['command']}\n")
            return "".join(lines)

    def write_crontab(self, user: str, path: str) -> int:
        target = os.fspath(path)
        if os.path.islink(target):
            raise CronWardenError(ERR_SYMLINK_REFUSED)

        absolute_target = os.path.abspath(target)
        parent = os.path.dirname(absolute_target) or "."
        os.makedirs(parent, exist_ok=True)
        if os.path.islink(target):
            raise CronWardenError(ERR_SYMLINK_REFUSED)

        content = self.render_crontab(user)
        payload = content.encode("utf-8")
        fd, temporary_path = tempfile.mkstemp(
            prefix=f".{os.path.basename(target)}.",
            suffix=".tmp",
            dir=parent,
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(temporary_path, 0o600)
            os.replace(temporary_path, absolute_target)
        except BaseException:
            try:
                os.unlink(temporary_path)
            except OSError:
                pass
            raise
        return len(payload)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "jobs": copy.deepcopy(list(self._jobs.values())),
                "runs": copy.deepcopy(list(self._runs.values())),
                "locked_users": sorted(self._locked_users),
                "stats": copy.deepcopy(self._stats),
                "fired": {
                    job_id: list(fire_keys)
                    for job_id, fire_keys in self._fired.items()
                },
            }

    def restore(self, state) -> None:
        if not isinstance(state, dict):
            raise CronWardenError(ERR_SNAPSHOT_INVALID)
        data = copy.deepcopy(state)

        raw_jobs = data.get("jobs", [])
        if isinstance(raw_jobs, dict):
            raw_jobs = list(raw_jobs.values())
        raw_runs = data.get("runs", [])
        if isinstance(raw_runs, dict):
            raw_runs = list(raw_runs.values())
        if not isinstance(raw_jobs, list) or not isinstance(raw_runs, list):
            raise CronWardenError(ERR_SNAPSHOT_INVALID)

        jobs: dict[str, dict] = {}
        for raw_job in raw_jobs:
            if not isinstance(raw_job, dict):
                raise CronWardenError(ERR_SNAPSHOT_INVALID)
            job_id = raw_job.get("job_id")
            if not isinstance(job_id, str):
                raise CronWardenError(ERR_SNAPSHOT_INVALID)
            jobs[job_id] = {
                "job_id": job_id,
                "user": raw_job.get("user"),
                "command": raw_job.get("command"),
                "schedule": raw_job.get("schedule"),
                "crontab_path": raw_job.get("crontab_path"),
                "crontab_owner": raw_job.get("crontab_owner"),
                "max_concurrent": (
                    1
                    if raw_job.get("max_concurrent") is None
                    else int(raw_job.get("max_concurrent"))
                ),
                "enabled": bool(raw_job.get("enabled", True)),
                "registered_at": raw_job.get("registered_at"),
            }

        runs: dict[str, dict] = {}
        for raw_run in raw_runs:
            if not isinstance(raw_run, dict):
                raise CronWardenError(ERR_SNAPSHOT_INVALID)
            run_id = raw_run.get("run_id")
            if not isinstance(run_id, str):
                raise CronWardenError(ERR_SNAPSHOT_INVALID)
            run_state = raw_run.get("state", "queued")
            runs[run_id] = {
                "run_id": run_id,
                "job_id": raw_run.get("job_id"),
                "user": raw_run.get("user"),
                "state": run_state,
                "slot": raw_run.get("slot") if run_state == "running" else None,
                "started_at": raw_run.get("started_at"),
                "finished_at": raw_run.get("finished_at"),
                "exit_code": raw_run.get("exit_code"),
                "authorized_at": raw_run.get("authorized_at"),
                "scheduled_for": raw_run.get("scheduled_for"),
                "max_concurrent": (
                    1
                    if raw_run.get("max_concurrent") is None
                    else int(raw_run.get("max_concurrent"))
                ),
            }

        raw_stats = data.get("stats", data.get("counters", {}))
        if not isinstance(raw_stats, dict):
            raise CronWardenError(ERR_SNAPSHOT_INVALID)
        stats = {
            key: int(raw_stats.get(key, 0) or 0)
            for key in _STATS_KEYS
        }

        raw_locked_users = data.get("locked_users", [])
        if not isinstance(raw_locked_users, (list, tuple, set)):
            raise CronWardenError(ERR_SNAPSHOT_INVALID)
        locked_users = set(raw_locked_users)

        fired: dict[str, set] = {}
        raw_fired = data.get("fired", data.get("fires"))
        if raw_fired is not None:
            if not isinstance(raw_fired, dict):
                raise CronWardenError(ERR_SNAPSHOT_INVALID)
            for job_id, fire_keys in raw_fired.items():
                if not isinstance(fire_keys, (list, tuple, set)):
                    raise CronWardenError(ERR_SNAPSHOT_INVALID)
                fired[job_id] = set(fire_keys)
        else:
            for run in runs.values():
                scheduled_for = run.get("scheduled_for")
                if scheduled_for is not None and run.get("job_id") is not None:
                    fired.setdefault(run["job_id"], set()).add(
                        _fire_key(scheduled_for)
                    )

        with self._lock:
            self._jobs = jobs
            self._runs = runs
            self._stats = stats
            self._locked_users = locked_users
            self._fired = fired

    def status(self) -> dict:
        with self._lock:
            job_values = list(self._jobs.values())
            run_values = list(self._runs.values())
            return {
                "jobs": len(job_values),
                "enabled": sum(1 for job in job_values if job["enabled"]),
                "disabled": sum(1 for job in job_values if not job["enabled"]),
                "queued": sum(1 for run in run_values if run["state"] == "queued"),
                "running": sum(1 for run in run_values if run["state"] == "running"),
                "finished": sum(1 for run in run_values if run["state"] == "finished"),
                "reaped": sum(1 for run in run_values if run["state"] == "reaped"),
                "users": len({job["user"] for job in job_values}),
                "locked_users": len(self._locked_users),
            }

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
