"""Sample quarantine vault: hash based dedup, reference protection, tombstones."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class VaultError(ValueError):
    """Raised when the vault refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATUS_ACTIVE = "active"
STATUS_TOMBSTONE = "tombstone"

RECORD_STATES = (STATUS_ACTIVE, STATUS_TOMBSTONE)


@dataclass(frozen=True)
class SampleRecord:
    content_hash: str
    size_bytes: int
    source: str
    admitted_at: str
    retain_until: str
    priority: int
    refcount: int
    admissions: int
    status: str


class SampleQuarantineVault:
    """Hold quarantined samples by content hash with case references."""

    def __init__(self, *, quota_bytes: int = 100000000,
                 retention_days: int = 30,
                 tombstone_days: int = 7) -> None:
        self.quota_bytes = quota_bytes
        self.retention_days = retention_days
        self.tombstone_days = tombstone_days
        self._lock = threading.RLock()
        self._records: dict[str, SampleRecord] = {}
        self._cases: dict[str, list[str]] = {}
        self._tombstones: dict[str, dict] = {}
        self._audit: list[dict] = []
        self._counters: dict[str, int] = {}

    def admit(self, content_hash: str, *, size_bytes: int, source: str,
              now: str, priority: int = 0,
              retention_days: int | None = None) -> SampleRecord:
        raise NotImplementedError

    def lookup(self, content_hash: str) -> dict:
        raise NotImplementedError

    def tag(self, content_hash: str, case_id: str) -> int:
        raise NotImplementedError

    def untag(self, content_hash: str, case_id: str) -> int:
        raise NotImplementedError

    def evict(self, *, needed_bytes: int, now: str) -> list[str]:
        raise NotImplementedError

    def purge_expired(self, *, now: str) -> list[str]:
        raise NotImplementedError

    def destroy(self, content_hash: str, *, actor: str, now: str) -> dict:
        raise NotImplementedError

    def samples(self) -> list[SampleRecord]:
        raise NotImplementedError

    def tombstones(self) -> list[dict]:
        raise NotImplementedError

    def capacity_report(self) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
