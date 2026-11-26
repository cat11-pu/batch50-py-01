"""Identity proofing case ledger: attempt budgets, review leases, final decisions."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class ProofingError(ValueError):
    """Refused proofing operation carrying a stable machine-readable code."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    applicant: str
    document_digest: str
    state: str
    opened_at: int
    ready_at: int | None
    decision: str | None
    decided_by: str | None
    decided_at: int | None


@dataclass(frozen=True)
class AttemptRecord:
    attempt_id: str
    case_id: str
    kind: str
    material_digest: str
    result: str
    at: int
    window: int


@dataclass(frozen=True)
class LeaseRecord:
    case_id: str
    reviewer: str
    granted_at: int
    expires_at: int
    generation: int


class ProofingCaseLedger:
    """Track applicants from document and liveness attempts to a final review verdict."""

    def __init__(self, *, attempt_limit: int = 3, cooldown_seconds: int = 600,
                 lease_seconds: int = 300, clock=None) -> None:
        self.attempt_limit = attempt_limit
        self.cooldown_seconds = cooldown_seconds
        self.lease_seconds = lease_seconds
        self._clock = clock
        self._lock = threading.RLock()

    def open(self, applicant: str, doc_digest: str, *,
             now: int | None = None) -> CaseRecord:
        raise NotImplementedError

    def attempt(self, case_id: str, kind: str, material: str, result: str, *,
                now: int | None = None) -> AttemptRecord:
        raise NotImplementedError

    def budget(self, case_id: str, kind: str, *, now: int | None = None) -> int:
        raise NotImplementedError

    def assign(self, case_id: str, reviewer: str, *,
               now: int | None = None) -> LeaseRecord:
        raise NotImplementedError

    def decide(self, case_id: str, reviewer: str, decision: str, reason: str, *,
               now: int | None = None) -> CaseRecord:
        raise NotImplementedError

    def reclaim(self, case_id: str, *, now: int | None = None) -> LeaseRecord | None:
        raise NotImplementedError

    def view(self, case_id: str) -> CaseRecord:
        raise NotImplementedError

    def queue(self, *, now: int | None = None) -> list[str]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
