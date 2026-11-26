"""Wipe job scheduler: per-device shard leases, persisted progress, offline resume."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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


class WipeJobScheduler:
    """Hand out wipe shards under time-bounded leases and persist per-shard progress."""

    def __init__(self, *, lease_ms: int = 30000) -> None:
        self.lease_ms = lease_ms
        self._lock = threading.RLock()

    def register_device(self, name: str, *, blocks: int) -> None:
        raise NotImplementedError

    def set_device_online(self, name: str, *, online: bool) -> int:
        raise NotImplementedError

    def submit(self, *, device: str, start: int, end: int, shard_blocks: int) -> str:
        raise NotImplementedError

    def claim(self, worker: str, *, now: int, lease_ms: int | None = None) -> Lease | None:
        raise NotImplementedError

    def report_progress(self, lease_id: str, done_blocks: int, *, now: int) -> dict:
        raise NotImplementedError

    def resume(self, job_id: str, *, now: int) -> int:
        raise NotImplementedError

    def cancel(self, job_id: str) -> int:
        raise NotImplementedError

    def status(self, job_id: str) -> JobView:
        raise NotImplementedError

    def shards(self, job_id: str) -> tuple[ShardView, ...]:
        raise NotImplementedError

    def leases(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
