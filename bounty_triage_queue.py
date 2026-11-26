"""Bounty triage queue: root-cause dedupe, review leases, award ledger."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class BountyError(ValueError):
    """Raised when a triage operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

STATE_QUEUED = "queued"
STATE_DUPLICATE = "duplicate"
STATE_TRIAGED = "triaged"
STATE_AWARDED = "awarded"
STATE_ACKNOWLEDGED = "acknowledged"
STATE_CLOSED = "closed"


@dataclass(frozen=True)
class BountyReport:
    report_id: str
    target: str
    fingerprint: str
    reporter: str
    severity: str
    state: str
    duplicate_of: str | None
    verdict: str | None
    award_amount: int
    submitted_at: str
    closed_at: str | None


@dataclass(frozen=True)
class ReviewLease:
    lease_id: str
    report_id: str
    reviewer: str
    expires_at: str


class BountyTriageQueue:
    """Queue bounty reports, lease reviews and settle awards against a budget."""

    def __init__(self, *, lease_seconds: int = 900,
                 project_budget: int = 10000) -> None:
        self.lease_seconds = lease_seconds
        self.project_budget = project_budget
        self._lock = threading.RLock()
        self._reports: dict[str, dict] = {}
        self._leases: dict[str, dict] = {}
        self._ledger: list = []
        self._adjustments: list = []
        self._budget = project_budget
        self._stats = {
            "submitted": 0,
            "duplicates": 0,
            "verdicts": 0,
            "awards": 0,
            "acknowledged": 0,
            "adjusted": 0,
        }

    def submit(self, report_id: str, *, target: str, fingerprint: str,
               reporter: str, severity: str, now: str) -> BountyReport:
        raise NotImplementedError

    def dedupe_against(self, target: str, fingerprint: str) -> tuple:
        raise NotImplementedError

    def claim_review(self, report_id: str, *, reviewer: str,
                     now: str) -> ReviewLease:
        raise NotImplementedError

    def record_verdict(self, report_id: str, *, reviewer: str, lease_id: str,
                       verdict: str, severity: str, now: str) -> BountyReport:
        raise NotImplementedError

    def award(self, report_id: str, *, amount: int, now: str) -> dict:
        raise NotImplementedError

    def adjust_severity(self, report_id: str, *, new_severity: str,
                        actor: str, now: str) -> dict:
        raise NotImplementedError

    def close(self, report_id: str, *, reason: str, now: str) -> BountyReport:
        raise NotImplementedError

    def queue(self, *, state: str | None = None) -> list:
        raise NotImplementedError

    def ledger(self) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
