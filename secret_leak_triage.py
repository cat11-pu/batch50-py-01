"""Secret leak triage: fingerprint normalization, verification cache, revocation closure."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class LeakError(ValueError):
    """Raised when a triage operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATE_PENDING = "pending_verification"
STATE_VALID = "valid"
STATE_INVALID = "invalid"
STATE_DISPOSED = "disposed"

VERDICTS = ("valid", "invalid", "error")


@dataclass(frozen=True)
class LeakRecord:
    fingerprint: str
    state: str
    first_seen_at: str
    last_seen_at: str
    occurrences: int
    locations: tuple
    verdict: str | None
    verified_at: str | None
    verify_expires_at: str | None
    disposed_at: str | None


@dataclass(frozen=True)
class RevocationTicket:
    ticket_id: str
    fingerprint: str
    provider: str
    owner: str
    state: str
    opened_at: str
    closed_at: str | None
    resolution: str | None


class SecretLeakTriage:
    """Normalize leaked-secret findings by fingerprint and drive revocation."""

    def __init__(self, *, verify_ttl_seconds: int = 3600) -> None:
        self.verify_ttl_seconds = verify_ttl_seconds
        self._lock = threading.RLock()
        self._records: dict[str, dict] = {}
        self._findings: dict[str, str] = {}
        self._tickets: dict[str, dict] = {}
        self._stats = {
            "ingested": 0,
            "occurrences": 0,
            "verified_valid": 0,
            "verified_invalid": 0,
            "disposed": 0,
            "revocations": 0,
        }

    def ingest(self, finding_id: str, *, repo: str, commit: str, path: str,
               fingerprint: str, now: str) -> dict:
        raise NotImplementedError

    def verify_result(self, fingerprint: str, *, verdict: str,
                      now: str) -> LeakRecord:
        raise NotImplementedError

    def dedupe(self, fingerprint: str) -> tuple:
        raise NotImplementedError

    def open_revocation(self, fingerprint: str, *, provider: str, owner: str,
                        now: str) -> RevocationTicket:
        raise NotImplementedError

    def close_revocation(self, ticket_id: str, *, resolution: str,
                         now: str) -> dict:
        raise NotImplementedError

    def close_finding(self, fingerprint: str, *, resolution: str,
                      now: str) -> LeakRecord:
        raise NotImplementedError

    def status(self, fingerprint: str) -> dict:
        raise NotImplementedError

    def findings(self, *, state: str | None = None) -> list:
        raise NotImplementedError

    def revocations(self, *, state: str | None = None) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
