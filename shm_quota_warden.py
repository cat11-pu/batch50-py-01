"""System V shared-memory quota governance: ownership, attach accounting, reaping."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass


class ShmError(ValueError):
    """Raised when a shared-memory operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SegmentRecord:
    namespace: str
    key: int
    owner: str
    size: int
    segment_id: str
    state: str = "live"
    refcount: int = 0
    created_at: str = ""
    last_attach_at: str | None = None


class ShmQuotaWarden:
    """Own segment lifecycle and per-user / per-namespace quota watermarks."""

    def __init__(self, *, user_bytes: int = 1048576, user_segments: int = 8,
                 ns_bytes: int = 2097152, ns_segments: int = 12,
                 clock=None) -> None:
        self.user_bytes = user_bytes
        self.user_segments = user_segments
        self.ns_bytes = ns_bytes
        self.ns_segments = ns_segments
        self._clock = clock
        self._lock = threading.Lock()

    def create(self, namespace: str, key: int, *, owner: str, size: int,
               now: str | None = None) -> SegmentRecord:
        raise NotImplementedError

    def attach(self, namespace: str, key: int, pid: int, *,
               now: str | None = None) -> int:
        raise NotImplementedError

    def detach(self, namespace: str, key: int, pid: int, *,
               now: str | None = None) -> int:
        raise NotImplementedError

    def remove(self, namespace: str, key: int, *,
               now: str | None = None) -> int:
        raise NotImplementedError

    def sweep(self, *, stale_after: int = 3600, now: str | None = None,
              whitelist=()) -> list:
        raise NotImplementedError

    def reap(self, pid: int, *, now: str | None = None) -> int:
        raise NotImplementedError

    def drop_namespace(self, namespace: str) -> int:
        raise NotImplementedError

    def status(self, namespace: str, key: int) -> dict:
        raise NotImplementedError

    def segments(self, namespace: str | None = None) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
