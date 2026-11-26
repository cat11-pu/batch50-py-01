"""Exec guard for anonymous memory files: seal tracking, source resolution, quarantine."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class MemfdError(ValueError):
    """Raised when a guard operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


SEAL_SEAL = "F_SEAL_SEAL"
SEAL_SHRINK = "F_SEAL_SHRINK"
SEAL_GROW = "F_SEAL_GROW"
SEAL_WRITE = "F_SEAL_WRITE"
SEAL_FUTURE_WRITE = "F_SEAL_FUTURE_WRITE"

ALL_SEALS = frozenset({SEAL_SEAL, SEAL_SHRINK, SEAL_GROW, SEAL_WRITE, SEAL_FUTURE_WRITE})


@dataclass(frozen=True)
class MemfdRecord:
    inode: int
    name: str
    pid: int
    fd: int
    seals: frozenset
    state: str
    updated_at: str


@dataclass(frozen=True)
class ExecDecision:
    pid: int
    path: str
    source: str
    inode: int | None
    decision: str
    code: str


class MemfdExecGuard:
    """Track memfd seals, resolve exec sources, permit or block anonymous-memory execution."""

    def __init__(self, *, allow_ttl: int = 300, default_deny: bool = True) -> None:
        self.allow_ttl = allow_ttl
        self.default_deny = default_deny
        self._lock = threading.RLock()
        self._memfds: dict[int, MemfdRecord] = {}
        self._by_name: dict[str, int] = {}
        self._by_fd: dict[tuple[int, int], int] = {}
        self._allowed: dict[int, str] = {}
        self._quarantined_inodes: dict[int, str] = {}
        self._quarantined_pids: dict[int, str] = {}
        self._children: dict[int, set[int]] = {}
        self._events: list[dict] = []
        self._counters: dict[str, int] = {}

    def on_memfd_create(self, *, pid: int, fd: int, inode: int, name: str,
                        seals, now: str) -> MemfdRecord:
        raise NotImplementedError

    def on_exec(self, *, pid: int, path: str, now: str) -> ExecDecision:
        raise NotImplementedError

    def allow(self, inode: int, *, ttl=None, now: str) -> MemfdRecord:
        raise NotImplementedError

    def quarantine(self, inode: int, *, reason: str, now: str) -> MemfdRecord:
        raise NotImplementedError

    def quarantine_process(self, pid: int, *, reason: str, now: str) -> dict:
        raise NotImplementedError

    def on_write(self, *, inode: int, offset: int, length: int, now: str) -> MemfdRecord:
        raise NotImplementedError

    def on_clone(self, *, parent_pid: int, child_pid: int) -> dict:
        raise NotImplementedError

    def report(self, *, kind=None) -> list[dict]:
        raise NotImplementedError

    def records(self) -> list[MemfdRecord]:
        raise NotImplementedError

    def seals_for(self, inode: int) -> frozenset:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
