"""Tenant disk quota arbiter: soft/hard limits, grace freeze and audit trail."""

from __future__ import annotations

import threading
from dataclasses import dataclass

SCHEMA_VERSION = 1

OUTCOMES = ("allowed", "grace", "denied")

STATES = ("ok", "grace", "frozen")


class QuotaError(ValueError):
    """Raised when a quota request or a state transition is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class QuotaPolicy:
    """Per tenant and volume limit pair."""

    tenant: str
    volume: str
    soft_limit: int
    hard_limit: int


@dataclass(frozen=True)
class WriteDecision:
    """Admission decision for one write request."""

    tenant: str
    volume: str
    path: str
    size: int
    outcome: str
    state: str
    code: str | None
    usage: int
    remaining: int
    grace_deadline: str | None


@dataclass(frozen=True)
class ReclaimResult:
    """Result of deleting or shrinking one object."""

    tenant: str
    volume: str
    path: str
    reclaimed: int
    usage: int
    state: str


@dataclass(frozen=True)
class TruncateResult:
    """Result of a truncation, either a reclaim or an admission."""

    tenant: str
    volume: str
    path: str
    action: str
    reclaimed: int
    decision: WriteDecision | None
    usage: int
    state: str


@dataclass(frozen=True)
class AuditEntry:
    """One sealed quota decision record."""

    seq: int
    action: str
    tenant: str
    volume: str
    path: str
    outcome: str
    code: str | None
    usage_after: int


class QuotaFreezeArbiter:
    """Track tenant usage per volume and freeze writes at the agreed limits."""

    def __init__(self, *, soft_limit: int = 1024, hard_limit: int = 4096,
                 grace_seconds: int = 3600, max_write_bytes: int = 1024,
                 aggregate_hard_limit: int | None = None, clock=None) -> None:
        self.soft_limit = soft_limit
        self.hard_limit = hard_limit
        self.grace_seconds = grace_seconds
        self.max_write_bytes = max_write_bytes
        self.aggregate_hard_limit = aggregate_hard_limit
        self._clock = clock
        self._lock = threading.RLock()
        self._volumes: dict = {}
        self._policies: dict = {}
        self._tenant_limits: dict = {}
        self._objects: dict = {}
        self._states: dict = {}
        self._audit: list = []
        self._counters = {"object_seq": 0, "audit_seq": 0}
        self._stats = {
            "admitted": 0,
            "grace_admitted": 0,
            "denied": 0,
            "written_bytes": 0,
            "reclaimed_bytes": 0,
            "grace_entered": 0,
            "frozen": 0,
            "released": 0,
            "audit_writes": 0,
        }

    def register_volume(self, volume: str) -> str:
        """Register a storage volume that tenants may be limited on."""
        raise NotImplementedError

    def volumes(self) -> tuple:
        """Return the registered volume names in order."""
        raise NotImplementedError

    def set_quota(self, tenant: str, volume: str, *, soft_limit: int,
                  hard_limit: int) -> QuotaPolicy:
        """Install a limit pair for one tenant on one volume."""
        raise NotImplementedError

    def quota_policy(self, tenant: str, volume: str) -> QuotaPolicy | None:
        """Return the explicit policy for a tenant and volume, if any."""
        raise NotImplementedError

    def set_tenant_limit(self, tenant: str, hard_limit: int) -> int:
        """Cap the aggregate usage of a tenant across all volumes."""
        raise NotImplementedError

    def admit_write(self, tenant: str, volume: str, path: str, size: int,
                    *, inode: int | None = None,
                    now=None) -> WriteDecision:
        """Decide whether a write may proceed and account for it when it does."""
        raise NotImplementedError

    def delete_object(self, tenant: str, volume: str, path: str,
                      *, now=None) -> ReclaimResult:
        """Remove a tracked object and reclaim its bytes."""
        raise NotImplementedError

    def truncate_object(self, tenant: str, volume: str, path: str,
                        new_size: int, *, now=None) -> TruncateResult:
        """Shrink or grow a tracked object under the same rules as writes."""
        raise NotImplementedError

    def usage(self, tenant: str) -> int:
        """Return aggregate tenant usage across all volumes."""
        raise NotImplementedError

    def usage_by_volume(self, tenant: str) -> dict:
        """Return tenant usage per registered volume."""
        raise NotImplementedError

    def tenant_state(self, tenant: str, now=None) -> str:
        """Return ok, grace or frozen for the tenant."""
        raise NotImplementedError

    def freeze_tenant(self, tenant: str, reason: str, *, now=None) -> str:
        """Freeze a tenant by operator decision."""
        raise NotImplementedError

    def lift_freeze(self, tenant: str, *, now=None) -> bool:
        """Release an operator freeze when usage has fallen below the soft limit."""
        raise NotImplementedError

    def audit_entries(self) -> tuple:
        """Return the sealed decision records in sequence order."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached copy of volumes, policies, objects and audit."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace live state with a validated snapshot."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the admission, reclaim and freeze counters."""
        raise NotImplementedError
