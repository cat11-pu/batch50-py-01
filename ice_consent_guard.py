"""ICE candidate-pair governance: nomination, role conflict and consent freshness."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class IceError(ValueError):
    """Raised when candidate, nomination or consent handling is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Candidate:
    key: str
    foundation: str
    component: str
    transport: str
    address: str
    port: int
    priority: int
    side: str


@dataclass(frozen=True)
class PairReport:
    pair_id: str
    state: str
    priority: int
    nominated: bool
    consent_until: int | None


@dataclass(frozen=True)
class NominationReport:
    pair_id: str
    state: str
    nominated: bool
    role: str


@dataclass(frozen=True)
class ConsentReport:
    pair_id: str
    state: str
    failures: int
    consent_until: int | None
    selected: str | None


@dataclass(frozen=True)
class Selection:
    pair_id: str
    state: str
    consent_until: int


class IceConsentGuard:
    """Govern candidate pairs, nominations and consent timers for one session."""

    def __init__(self, *, max_candidates: int = 16, max_pairs: int = 32,
                 consent_ttl: int = 6, max_consent_failures: int = 2,
                 role: str = "controlling", clock=None) -> None:
        self.max_candidates = max_candidates
        self.max_pairs = max_pairs
        self.consent_ttl = consent_ttl
        self.max_consent_failures = max_consent_failures
        self._role = role
        self._clock = clock
        self._lock = threading.RLock()

    def add_candidates(self, candidates, *, side: str,
                       now: int | None = None) -> tuple[Candidate, ...]:
        raise NotImplementedError

    def resolve_role(self, local_role: str, local_tie_breaker: int,
                     remote_role: str, remote_tie_breaker: int) -> str:
        raise NotImplementedError

    def check_pair(self, pair_id: str, *, responded: bool = True,
                   failed: bool = False, now: int | None = None) -> PairReport:
        raise NotImplementedError

    def nominate(self, pair_id: str, *, replace: bool = False,
                 now: int | None = None) -> NominationReport:
        raise NotImplementedError

    def consent(self, pair_id: str, *, ok: bool, now: int | None = None) -> ConsentReport:
        raise NotImplementedError

    def select(self, *, now: int | None = None) -> Selection:
        raise NotImplementedError

    def remove_candidate(self, key: str) -> int:
        raise NotImplementedError

    def pairs(self) -> tuple[PairReport, ...]:
        raise NotImplementedError

    def status(self) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
