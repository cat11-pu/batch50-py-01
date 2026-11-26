"""Thread scoped fsuid/gid switching with nesting, fallback and audit trail."""

from __future__ import annotations

import threading
from dataclasses import dataclass

SCHEMA_VERSION = 1

FAULT_POINTS = ("uid", "gid")


class GuardError(ValueError):
    """Raised when an identity switch is refused or rolled back."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ScopeHandle:
    """Token handed out by push_scope and required by pop_scope."""

    worker: int
    depth: int
    target: tuple
    deadline: int | None


@dataclass(frozen=True)
class AuditEntry:
    """One audited identity action."""

    seq: int
    worker: int
    action: str
    identity_from: tuple
    identity_to: tuple
    reason: str
    ok: bool


class FsuidSwitchGuard:
    """Switch the calling thread's fsuid/gid inside nested scopes."""

    def __init__(self, *, baseline=(1000, 1000), privileged: bool = False,
                 max_depth: int = 8) -> None:
        self.baseline = baseline
        self.privileged = privileged
        self.max_depth = max_depth
        self._lock = threading.RLock()
        self._workers = {}
        self._seq = 0
        self._audit = []
        self._faults = {}
        self._stats = {
            "pushes": 0,
            "pops": 0,
            "denied": 0,
            "forced_returns": 0,
            "expired_scopes": 0,
            "depth_peak": 0,
            "faults_injected": 0,
        }

    def push_scope(self, target, *, reason: str = "", timeout: int | None = None,
                   now: int | None = None) -> ScopeHandle:
        raise NotImplementedError

    def pop_scope(self, handle: ScopeHandle) -> tuple:
        raise NotImplementedError

    def current_identity(self) -> tuple:
        raise NotImplementedError

    def force_baseline(self, *, reason: str = "manual") -> tuple:
        raise NotImplementedError

    def tick(self, now: int) -> int:
        raise NotImplementedError

    def scope_depth(self) -> int:
        raise NotImplementedError

    def audit_trail(self, *, limit: int | None = None) -> tuple:
        raise NotImplementedError

    def set_baseline(self, uid: int, gid: int) -> tuple:
        raise NotImplementedError

    def inject_fault(self, point: str, *, times: int = 1) -> None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
