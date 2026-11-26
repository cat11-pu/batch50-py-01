"""Credential-leak containment for supervised processes.

The supervisor keeps a registry of credential fingerprints, scans the environment
and open descriptors of supervised child processes for those fingerprints, and
contains any process that carries live credential material.  A separate heartbeat
ledger drives backoff restarts and a crash-loop circuit breaker.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "CredentialWatchError",
    "ProcessView",
    "Finding",
    "TickAction",
    "CredentialWatchSupervisor",
]


class CredentialWatchError(ValueError):
    """Raised when a supervisor operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ProcessView:
    """Immutable snapshot of one supervised process."""

    name: str
    pid: int
    state: str
    deadline_at: int
    last_heartbeat_at: int
    heartbeat_count: int
    consecutive_crashes: int
    restart_count: int
    restart_due_at: int | None
    containment_reason: str | None
    credential_ids: tuple[str, ...]


@dataclass(frozen=True)
class Finding:
    """One credential fingerprint observed inside a supervised process."""

    process: str
    credential_id: str
    fingerprint: str
    source: str
    location: str
    fd: int | None
    detected_at: int
    status: str


@dataclass(frozen=True)
class TickAction:
    """One decision produced by a heartbeat tick."""

    process: str
    action: str
    at: int
    due_at: int | None
    attempt: int


class CredentialWatchSupervisor:
    """Scan supervised processes for credentials, contain leaks, break crash loops."""

    def __init__(self, *, heartbeat_timeout_ms: int = 5000,
                 backoff_base_ms: int = 1000, backoff_cap_ms: int = 30000,
                 crash_threshold: int = 3, crash_window_ms: int = 60000,
                 max_fingerprints: int = 256,
                 max_findings: int = 1024) -> None:
        self.heartbeat_timeout_ms = heartbeat_timeout_ms
        self.backoff_base_ms = backoff_base_ms
        self.backoff_cap_ms = backoff_cap_ms
        self.crash_threshold = crash_threshold
        self.crash_window_ms = crash_window_ms
        self.max_fingerprints = max_fingerprints
        self.max_findings = max_findings
        self._lock = threading.RLock()

    def register_credential(self, credential_id: str, fingerprint: str, *,
                            now: int = 0) -> None:
        raise NotImplementedError

    def rotate_credential(self, credential_id: str, fingerprint: str, *,
                          now: int = 0) -> int:
        raise NotImplementedError

    def register_process(self, name: str, *, pid: int,
                         credential_ids=(), now: int = 0) -> ProcessView:
        raise NotImplementedError

    def unregister_process(self, name: str, *, now: int = 0) -> None:
        raise NotImplementedError

    def heartbeat(self, name: str, *, now: int) -> int:
        raise NotImplementedError

    def scan_environment(self, name: str, environ, *,
                         now: int) -> tuple[Finding, ...]:
        raise NotImplementedError

    def scan_descriptors(self, name: str, descriptors, *,
                         now: int) -> tuple[Finding, ...]:
        raise NotImplementedError

    def tick(self, now: int) -> tuple[TickAction, ...]:
        raise NotImplementedError

    def process_view(self, name: str) -> ProcessView:
        raise NotImplementedError

    def process_views(self) -> tuple[ProcessView, ...]:
        raise NotImplementedError

    def findings(self, name: str | None = None) -> tuple[Finding, ...]:
        raise NotImplementedError

    def release(self, name: str, *, operator: str, now: int = 0) -> None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
