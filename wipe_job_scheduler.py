"""Wipe job scheduler: per-device shard leases, persisted progress, offline resume."""

from __future__ import annotations

import threading
from dataclasses import dataclass, replace


class WipeError(ValueError):
    """Raised when a wipe job operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ShardView:
    index: int
    start: int
    end: int
    state: str
    done_blocks: int


@dataclass(frozen=True)
class JobView:
    job_id: str
    device: str
    start: int
    end: int
    total_blocks: int
    done_blocks: int
    state: str
    shard_count: int
    pending: int
    leased: int
    done: int


@dataclass(frozen=True)
class Lease:
    lease_id: str
    job_id: str
    shard_index: int
    start: int
    end: int
    expires_at: int


@dataclass
class _Device:
    blocks: int
    online: bool


@dataclass
class _Job:
    job_id: str
    device: str
    start: int
    end: int
    shard_blocks: int
    state: str
    done_blocks: int


@dataclass
class _Shard:
    index: int
    start: int
    end: int
    state: str
    done_blocks: int


@dataclass
class _LeaseRecord:
    worker: str
    lease: Lease
    lease_ms: int


_COUNTER_KEYS = (
    "submitted",
    "claimed",
    "completed",
    "cancelled",
    "requeued",
    "offline_drops",
    "leases_expired",
)

_SNAPSHOT_KEYS = {
    "version",
    "devices",
    "jobs",
    "shards",
    "leases",
    "counters",
    "next_job",
    "next_lease",
}


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_int(
    value: object,
    *,
    minimum: int | None = None,
    code: str = "WIPE_INVALID_REQUEST",
    detail: object = None,
) -> int:
    if not _is_int(value):
        raise WipeError(code, detail)
    result = int(value)
    if minimum is not None and result < minimum:
        raise WipeError(code, detail)
    return result


def _job_number(job_id: str) -> int:
    if not isinstance(job_id, str) or not job_id.startswith("job-"):
        raise WipeError("WIPE_INVALID_REQUEST", job_id)
    suffix = job_id[4:]
    if not suffix.isdigit():
        raise WipeError("WIPE_INVALID_REQUEST", job_id)
    return int(suffix)


def _lease_number(lease_id: str) -> int:
    if not isinstance(lease_id, str) or not lease_id.startswith("lease-"):
        raise WipeError("WIPE_INVALID_REQUEST", lease_id)
    suffix = lease_id[6:]
    if not suffix.isdigit():
        raise WipeError("WIPE_INVALID_REQUEST", lease_id)
    return int(suffix)


class WipeJobScheduler:
    """Hand out wipe shards under time-bounded leases and persist per-shard progress."""

    def __init__(self, *, lease_ms: int = 30000) -> None:
        if not _is_int(lease_ms) or lease_ms <= 0:
            raise WipeError("WIPE_INVALID_REQUEST", "lease_ms")
        self.lease_ms = lease_ms
        self._lock = threading.RLock()
        self._devices: dict[str, _Device] = {}
        self._jobs: dict[str, _Job] = {}
        self._shards: dict[str, list[_Shard]] = {}
        self._leases: dict[str, _LeaseRecord] = {}
        self._counters = {key: 0 for key in _COUNTER_KEYS}
        self._next_job = 1
        self._next_lease = 1

    def register_device(self, name: str, *, blocks: int) -> None:
        if not isinstance(name, str) or not name.strip():
            raise WipeError("WIPE_INVALID_REQUEST", "device")
        if not _is_int(blocks) or blocks <= 0:
            raise WipeError("WIPE_INVALID_REQUEST", "blocks")
        with self._lock:
            if name in self._devices:
                raise WipeError("WIPE_DUPLICATE_DEVICE", name)
            self._devices[name] = _Device(blocks=int(blocks), online=True)

    def set_device_online(self, name: str, *, online: bool) -> int:
        if not isinstance(name, str):
            raise WipeError("WIPE_INVALID_REQUEST", "device")
        if not isinstance(online, bool):
            raise WipeError("WIPE_INVALID_REQUEST", "online")
        with self._lock:
            device = self._devices.get(name)
            if device is None:
                raise WipeError("WIPE_UNKNOWN_DEVICE", name)

            device.online = online
            if online:
                return 0

            dropped = 0
            for worker, record in list(self._leases.items()):
                job = self._jobs[record.lease.job_id]
                if job.device != name:
                    continue
                self._leases.pop(worker)
                shard = self._shards[job.job_id][record.lease.shard_index]
                if shard.state == "leased":
                    shard.state = "pending"
                dropped += 1
            self._counters["offline_drops"] += dropped
            return dropped

    def submit(self, *, device: str, start: int, end: int, shard_blocks: int) -> str:
        if not isinstance(device, str):
            raise WipeError("WIPE_INVALID_REQUEST", "device")
        with self._lock:
            registered = self._devices.get(device)
            if registered is None:
                raise WipeError("WIPE_UNKNOWN_DEVICE", device)

            start_value = _require_int(start, minimum=0, detail="start")
            end_value = _require_int(end, minimum=0, detail="end")
            shard_value = _require_int(shard_blocks, minimum=1, detail="shard_blocks")
            if start_value >= end_value or end_value > registered.blocks:
                raise WipeError("WIPE_INVALID_REQUEST", "range")

            for job in self._jobs.values():
                if (
                    job.device == device
                    and job.state == "active"
                    and start_value < job.end
                    and end_value > job.start
                ):
                    raise WipeError("WIPE_RANGE_CONFLICT", job.job_id)

            job_id = f"job-{self._next_job}"
            self._next_job += 1
            shards: list[_Shard] = []
            index = 0
            cursor = start_value
            while cursor < end_value:
                shard_end = min(cursor + shard_value, end_value)
                shards.append(
                    _Shard(
                        index=index,
                        start=cursor,
                        end=shard_end,
                        state="pending",
                        done_blocks=0,
                    )
                )
                index += 1
                cursor = shard_end

            self._jobs[job_id] = _Job(
                job_id=job_id,
                device=device,
                start=start_value,
                end=end_value,
                shard_blocks=shard_value,
                state="active",
                done_blocks=0,
            )
            self._shards[job_id] = shards
            self._counters["submitted"] += 1
            return job_id

    def claim(self, worker: str, *, now: int, lease_ms: int | None = None) -> Lease | None:
        if not isinstance(worker, str) or not worker.strip():
            raise WipeError("WIPE_INVALID_REQUEST", "worker")
        if not _is_int(now):
            raise WipeError("WIPE_INVALID_REQUEST", "now")
        duration = self.lease_ms if lease_ms is None else lease_ms
        if not _is_int(duration) or duration <= 0:
            raise WipeError("WIPE_INVALID_REQUEST", "lease_ms")

        with self._lock:
            self._expire_all(now)
            if worker in self._leases:
                raise WipeError("WIPE_LEASE_ACTIVE", worker)

            ordered_jobs = sorted(self._jobs.values(), key=lambda job: _job_number(job.job_id))
            for job in ordered_jobs:
                if job.state != "active":
                    continue
                if not self._devices[job.device].online:
                    continue
                for shard in self._shards[job.job_id]:
                    if shard.state != "pending":
                        continue
                    lease_id = f"lease-{self._next_lease}"
                    self._next_lease += 1
                    lease = Lease(
                        lease_id=lease_id,
                        job_id=job.job_id,
                        shard_index=shard.index,
                        start=shard.start,
                        end=shard.end,
                        expires_at=now + int(duration),
                    )
                    self._leases[worker] = _LeaseRecord(
                        worker=worker,
                        lease=lease,
                        lease_ms=int(duration),
                    )
                    shard.state = "leased"
                    self._counters["claimed"] += 1
                    return lease
            return None

    def report_progress(self, lease_id: str, done_blocks: int, *, now: int) -> dict:
        if not _is_int(now):
            raise WipeError("WIPE_INVALID_REQUEST", "now")
        with self._lock:
            record = self._find_lease(lease_id)
            if record is None:
                raise WipeError("WIPE_LEASE_LOST", lease_id)
            if now > record.lease.expires_at:
                self._expire_record(record)
                raise WipeError("WIPE_LEASE_LOST", lease_id)

            job = self._jobs[record.lease.job_id]
            shard = self._shards[job.job_id][record.lease.shard_index]
            if shard.state != "leased":
                self._leases.pop(record.worker, None)
                raise WipeError("WIPE_LEASE_LOST", lease_id)

            if not _is_int(done_blocks):
                raise WipeError("WIPE_INVALID_REQUEST", "done_blocks")
            done_value = int(done_blocks)
            if done_value < shard.done_blocks:
                raise WipeError("WIPE_PROGRESS_REGRESS", done_value)
            shard_length = shard.end - shard.start
            if done_value > shard_length:
                raise WipeError("WIPE_INVALID_REQUEST", "done_blocks")

            old_done = shard.done_blocks
            shard.done_blocks = done_value
            job.done_blocks += done_value - old_done
            completed = done_value == shard_length
            remaining = shard_length - done_value
            if completed:
                shard.state = "done"
                self._leases.pop(record.worker, None)
                self._counters["completed"] += 1
                if all(item.state == "done" for item in self._shards[job.job_id]):
                    job.state = "complete"
            else:
                record.lease = replace(
                    record.lease,
                    expires_at=now + record.lease_ms,
                )
                self._leases[record.worker] = record
            return {
                "completed": completed,
                "done_blocks": done_value,
                "remaining": remaining,
            }

    def resume(self, job_id: str, *, now: int) -> int:
        if not isinstance(job_id, str):
            raise WipeError("WIPE_UNKNOWN_JOB", job_id)
        if not _is_int(now):
            raise WipeError("WIPE_INVALID_REQUEST", "now")
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise WipeError("WIPE_UNKNOWN_JOB", job_id)
            if job.state in ("complete", "cancelled"):
                return 0
            requeued = self._expire_job(job_id, now)
            self._counters["requeued"] += requeued
            return requeued

    def cancel(self, job_id: str) -> int:
        if not isinstance(job_id, str):
            raise WipeError("WIPE_UNKNOWN_JOB", job_id)
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise WipeError("WIPE_UNKNOWN_JOB", job_id)
            if job.state == "complete":
                raise WipeError("WIPE_JOB_COMPLETE", job_id)
            if job.state == "cancelled":
                return 0

            reclaimed = 0
            for shard in self._shards[job_id]:
                if shard.state in ("pending", "leased"):
                    shard.state = "cancelled"
                    reclaimed += 1
            for worker, record in list(self._leases.items()):
                if record.lease.job_id == job_id:
                    self._leases.pop(worker)
            job.state = "cancelled"
            self._counters["cancelled"] += reclaimed
            return reclaimed

    def status(self, job_id: str) -> JobView:
        if not isinstance(job_id, str):
            raise WipeError("WIPE_UNKNOWN_JOB", job_id)
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise WipeError("WIPE_UNKNOWN_JOB", job_id)
            shards = self._shards[job_id]
            return JobView(
                job_id=job.job_id,
                device=job.device,
                start=job.start,
                end=job.end,
                total_blocks=job.end - job.start,
                done_blocks=job.done_blocks,
                state=job.state,
                shard_count=len(shards),
                pending=sum(1 for shard in shards if shard.state == "pending"),
                leased=sum(1 for shard in shards if shard.state == "leased"),
                done=sum(1 for shard in shards if shard.state == "done"),
            )

    def shards(self, job_id: str) -> tuple[ShardView, ...]:
        if not isinstance(job_id, str):
            raise WipeError("WIPE_UNKNOWN_JOB", job_id)
        with self._lock:
            if job_id not in self._jobs:
                raise WipeError("WIPE_UNKNOWN_JOB", job_id)
            return tuple(
                ShardView(
                    index=shard.index,
                    start=shard.start,
                    end=shard.end,
                    state=shard.state,
                    done_blocks=shard.done_blocks,
                )
                for shard in self._shards[job_id]
            )

    def leases(self) -> dict:
        with self._lock:
            return {worker: record.lease for worker, record in self._leases.items()}

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "devices": {
                    name: {"blocks": device.blocks, "online": device.online}
                    for name, device in self._devices.items()
                },
                "jobs": {
                    job_id: {
                        "job_id": job.job_id,
                        "device": job.device,
                        "start": job.start,
                        "end": job.end,
                        "shard_blocks": job.shard_blocks,
                        "state": job.state,
                        "done_blocks": job.done_blocks,
                    }
                    for job_id, job in self._jobs.items()
                },
                "shards": {
                    job_id: [
                        {
                            "index": shard.index,
                            "start": shard.start,
                            "end": shard.end,
                            "state": shard.state,
                            "done_blocks": shard.done_blocks,
                        }
                        for shard in shards
                    ]
                    for job_id, shards in self._shards.items()
                },
                "leases": {
                    worker: {
                        "lease_id": record.lease.lease_id,
                        "job_id": record.lease.job_id,
                        "shard_index": record.lease.shard_index,
                        "start": record.lease.start,
                        "end": record.lease.end,
                        "expires_at": record.lease.expires_at,
                        "lease_ms": record.lease_ms,
                    }
                    for worker, record in self._leases.items()
                },
                "counters": dict(self._counters),
                "next_job": self._next_job,
                "next_lease": self._next_lease,
            }

    def restore(self, state: dict) -> None:
        try:
            parsed = self._parse_snapshot(state)
        except Exception as exc:
            raise WipeError("WIPE_SNAPSHOT_INVALID", state) from exc
        with self._lock:
            devices, jobs, shards, leases, counters, next_job, next_lease = parsed
            self._devices = devices
            self._jobs = jobs
            self._shards = shards
            self._leases = leases
            self._counters = counters
            self._next_job = next_job
            self._next_lease = next_lease

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def _parse_snapshot(self, state: object):
        if not isinstance(state, dict) or not _SNAPSHOT_KEYS <= set(state):
            raise ValueError("snapshot keys")
        if not _is_int(state["version"]) or state["version"] != 1:
            raise ValueError("snapshot version")

        raw_devices = state["devices"]
        raw_jobs = state["jobs"]
        raw_shards = state["shards"]
        raw_leases = state["leases"]
        raw_counters = state["counters"]
        if not all(
            isinstance(item, dict)
            for item in (raw_devices, raw_jobs, raw_shards, raw_leases, raw_counters)
        ):
            raise ValueError("snapshot containers")

        devices: dict[str, _Device] = {}
        for name, payload in raw_devices.items():
            if not isinstance(name, str) or not name.strip() or not isinstance(payload, dict):
                raise ValueError("device")
            blocks = payload.get("blocks")
            online = payload.get("online")
            if not _is_int(blocks) or blocks <= 0 or not isinstance(online, bool):
                raise ValueError("device payload")
            devices[name] = _Device(blocks=int(blocks), online=online)

        jobs: dict[str, _Job] = {}
        highest_job = 0
        for key, payload in raw_jobs.items():
            if not isinstance(key, str) or not isinstance(payload, dict):
                raise ValueError("job")
            job_id = payload.get("job_id")
            if job_id != key:
                raise ValueError("job id")
            highest_job = max(highest_job, _job_number(job_id))
            device = payload.get("device")
            if not isinstance(device, str) or device not in devices:
                raise ValueError("job device")
            start = payload.get("start")
            end = payload.get("end")
            shard_blocks = payload.get("shard_blocks")
            job_state = payload.get("state")
            job_done = payload.get("done_blocks")
            if (
                not _is_int(start)
                or not _is_int(end)
                or not _is_int(shard_blocks)
                or start < 0
                or start >= end
                or end > devices[device].blocks
                or shard_blocks <= 0
            ):
                raise ValueError("job range")
            if job_state not in ("active", "complete", "cancelled"):
                raise ValueError("job state")
            if not _is_int(job_done) or job_done < 0 or job_done > end - start:
                raise ValueError("job progress")
            jobs[job_id] = _Job(
                job_id=job_id,
                device=device,
                start=int(start),
                end=int(end),
                shard_blocks=int(shard_blocks),
                state=job_state,
                done_blocks=int(job_done),
            )

        for index, left in enumerate(jobs.values()):
            for right in list(jobs.values())[index + 1 :]:
                if (
                    left.state == "active"
                    and right.state == "active"
                    and left.device == right.device
                    and left.start < right.end
                    and left.end > right.start
                ):
                    raise ValueError("overlapping active jobs")

        next_job = _require_int(state["next_job"], minimum=1, code="WIPE_SNAPSHOT_INVALID")
        if next_job <= highest_job:
            raise ValueError("next job")

        shards: dict[str, list[_Shard]] = {}
        if set(raw_shards) != set(jobs):
            raise ValueError("shard jobs")
        for job_id, job in jobs.items():
            rows = raw_shards[job_id]
            if not isinstance(rows, list) or not rows:
                raise ValueError("job shards")
            expected_count = (job.end - job.start + job.shard_blocks - 1) // job.shard_blocks
            if len(rows) != expected_count:
                raise ValueError("shard count")
            parsed_shards: list[_Shard] = []
            for index, payload in enumerate(rows):
                if not isinstance(payload, dict):
                    raise ValueError("shard")
                expected_start = job.start + index * job.shard_blocks
                expected_end = min(expected_start + job.shard_blocks, job.end)
                shard_state = payload.get("state")
                shard_done = payload.get("done_blocks")
                if (
                    payload.get("index") != index
                    or payload.get("start") != expected_start
                    or payload.get("end") != expected_end
                    or shard_state not in ("pending", "leased", "done", "cancelled")
                    or not _is_int(shard_done)
                    or shard_done < 0
                    or shard_done > expected_end - expected_start
                ):
                    raise ValueError("shard fields")
                length = expected_end - expected_start
                if shard_state == "done":
                    if shard_done != length:
                        raise ValueError("done shard")
                elif shard_done >= length:
                    raise ValueError("incomplete shard")
                parsed_shards.append(
                    _Shard(
                        index=index,
                        start=expected_start,
                        end=expected_end,
                        state=shard_state,
                        done_blocks=int(shard_done),
                    )
                )
            if sum(shard.done_blocks for shard in parsed_shards) != job.done_blocks:
                raise ValueError("job progress mismatch")
            if job.state == "complete":
                if any(shard.state != "done" for shard in parsed_shards):
                    raise ValueError("complete job")
            elif job.state == "cancelled":
                if any(shard.state in ("pending", "leased") for shard in parsed_shards):
                    raise ValueError("cancelled job")
                if all(shard.state == "done" for shard in parsed_shards):
                    raise ValueError("finished cancelled job")
            else:
                if any(shard.state == "cancelled" for shard in parsed_shards):
                    raise ValueError("active job")
                if all(shard.state == "done" for shard in parsed_shards):
                    raise ValueError("finished active job")
            shards[job_id] = parsed_shards

        counters = {}
        if any(key not in raw_counters for key in _COUNTER_KEYS):
            raise ValueError("counters")
        for key in _COUNTER_KEYS:
            value = raw_counters[key]
            if not _is_int(value) or value < 0:
                raise ValueError("counter")
            counters[key] = int(value)

        leases: dict[str, _LeaseRecord] = {}
        lease_ids: set[str] = set()
        shard_owners: set[tuple[str, int]] = set()
        highest_lease = 0
        for worker, payload in raw_leases.items():
            if not isinstance(worker, str) or not worker.strip() or not isinstance(payload, dict):
                raise ValueError("lease")
            lease_id = payload.get("lease_id")
            job_id = payload.get("job_id")
            shard_index = payload.get("shard_index")
            start = payload.get("start")
            end = payload.get("end")
            expires_at = payload.get("expires_at")
            lease_ms = payload.get("lease_ms")
            if not isinstance(lease_id, str) or not isinstance(job_id, str):
                raise ValueError("lease ids")
            if lease_id in lease_ids or not _is_int(shard_index):
                raise ValueError("lease duplicate")
            if job_id not in jobs:
                raise ValueError("lease job")
            job = jobs[job_id]
            if job.state != "active" or not (0 <= shard_index < len(shards[job_id])):
                raise ValueError("lease shard")
            if not devices[job.device].online:
                raise ValueError("lease on offline device")
            shard = shards[job_id][shard_index]
            if (
                shard.state != "leased"
                or shard.start != start
                or shard.end != end
                or (job_id, shard_index) in shard_owners
                or not _is_int(expires_at)
                or not _is_int(lease_ms)
                or lease_ms <= 0
            ):
                raise ValueError("lease payload")
            highest_lease = max(highest_lease, _lease_number(lease_id))
            lease = Lease(
                lease_id=lease_id,
                job_id=job_id,
                shard_index=shard_index,
                start=shard.start,
                end=shard.end,
                expires_at=int(expires_at),
            )
            leases[worker] = _LeaseRecord(
                worker=worker,
                lease=lease,
                lease_ms=int(lease_ms),
            )
            lease_ids.add(lease_id)
            shard_owners.add((job_id, shard_index))

        for job_id, rows in shards.items():
            for shard in rows:
                if shard.state == "leased" and (job_id, shard.index) not in shard_owners:
                    raise ValueError("leased shard without lease")

        next_lease = _require_int(state["next_lease"], minimum=1, code="WIPE_SNAPSHOT_INVALID")
        if next_lease <= highest_lease:
            raise ValueError("next lease")

        return devices, jobs, shards, leases, counters, next_job, next_lease

    def _find_lease(self, lease_id: str) -> _LeaseRecord | None:
        for record in self._leases.values():
            if record.lease.lease_id == lease_id:
                return record
        return None

    def _expire_record(self, record: _LeaseRecord) -> None:
        self._leases.pop(record.worker, None)
        job = self._jobs[record.lease.job_id]
        shard = self._shards[job.job_id][record.lease.shard_index]
        if shard.state == "leased":
            shard.state = "pending"
        self._counters["leases_expired"] += 1

    def _expire_all(self, now: int) -> int:
        expired = 0
        for record in list(self._leases.values()):
            if now > record.lease.expires_at:
                self._expire_record(record)
                expired += 1
        return expired

    def _expire_job(self, job_id: str, now: int) -> int:
        expired = 0
        for record in list(self._leases.values()):
            if record.lease.job_id == job_id and now > record.lease.expires_at:
                self._expire_record(record)
                expired += 1
        return expired
