"""Backup immutability warden: retention locks, monotonic extension, canary freeze."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class WardenError(ValueError):
    """Raised when a warden operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATUS_LOCKED = "locked"
STATUS_RELEASED = "released"
STATUS_VERIFIED = "verified"
STATUS_UNUSABLE = "unusable"


@dataclass(frozen=True)
class LockRecord:
    restore_point: str
    size_gb: float
    min_retention_days: int
    locked_at: str
    expires_at: str
    extensions: int
    status: str


@dataclass(frozen=True)
class RestoreVerdict:
    restore_point: str
    status: str
    total_chunks: int
    ok_chunks: int
    usable: bool


class BackupImmutabilityWarden:
    """Hold restore points immutable, freeze the repository on canary drift."""

    def __init__(self, *, quota_gb: float = 1000.0) -> None:
        self.quota_gb = quota_gb
        self._lock = threading.RLock()
        self._locks: dict[str, LockRecord] = {}
        self._released: dict[str, dict] = {}
        self._canaries: dict[str, str] = {}
        self._frozen: str = ""
        self._verdicts: dict[str, RestoreVerdict] = {}
        self._audit: list[dict] = []
        self._counters: dict[str, int] = {}

    def register_canary(self, path: str, digest: str) -> None:
        raise NotImplementedError

    def lock(self, restore_point: str, *, size_gb: float,
             min_retention_days: int, now: str) -> LockRecord:
        raise NotImplementedError

    def extend(self, restore_point: str, *, extra_days: int, now: str) -> LockRecord:
        raise NotImplementedError

    def release(self, restore_point: str, *, actor: str, now: str) -> dict:
        raise NotImplementedError

    def on_lock_file_missing(self, restore_point: str, *, actor: str, now: str) -> dict:
        raise NotImplementedError

    def check_canary(self, path: str, *, observed_digest: str, now: str) -> dict:
        raise NotImplementedError

    def verify_restore(self, restore_point: str, *, total_chunks: int,
                       ok_chunks: int, now: str) -> RestoreVerdict:
        raise NotImplementedError

    def can_backup(self) -> bool:
        raise NotImplementedError

    def restore_allowed(self, restore_point: str) -> bool:
        raise NotImplementedError

    def retention(self, restore_point: str, *, now: str) -> dict:
        raise NotImplementedError

    def locks(self) -> list[LockRecord]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
