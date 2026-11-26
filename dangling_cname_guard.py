"""Dangling CNAME takeover guard: chain evidence, service fingerprints, rescan state machine."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class TakeoverError(ValueError):
    """Raised when a takeover inspection or transition is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Conclusion:
    domain: str
    zone: str
    owner: str
    chain: tuple[str, ...]
    target: str
    service: str | None
    state: str
    evidence: tuple[str, ...]
    conflict: bool
    exploitable: bool
    ttl: int
    fetched_at: str
    first_seen: int
    rescanned_at: int | None
    service_version: int


@dataclass(frozen=True)
class ScanResult:
    domain: str
    state: str
    evidence: tuple[str, ...]
    cached: bool = False
    conflict: bool = False


class DanglingCnameGuard:
    """Track external domains, CNAME chains, ownership evidence and rescan conclusions."""

    def __init__(self, *, rescan_interval: int = 1800, max_conclusions: int = 200,
                 max_evidence: int = 6, scan_rate: int = 20, resolver=None) -> None:
        self.rescan_interval = rescan_interval
        self.max_conclusions = max_conclusions
        self.max_evidence = max_evidence
        self.scan_rate = scan_rate
        self._resolver = resolver
        self._lock = threading.RLock()

    def register_zone(self, zone: str, records: dict, *, owner: str,
                      owned_hosts=()) -> int:
        raise NotImplementedError

    def scan_domain(self, domain: str, *, now: int | None = None) -> ScanResult:
        raise NotImplementedError

    def scan_zone(self, zone: str, *, now: int | None = None) -> list[ScanResult]:
        raise NotImplementedError

    def fingerprint(self, service: str, *, suffixes=None, markers=None) -> dict:
        raise NotImplementedError

    def confirm(self, domain: str, *, verdict: str = "confirmed",
                now: int | None = None) -> str:
        raise NotImplementedError

    def rescan(self, domain: str, *, now: int | None = None) -> ScanResult:
        raise NotImplementedError

    def conclusions(self, *, state: str | None = None) -> list[Conclusion]:
        raise NotImplementedError

    def evidence_for(self, domain: str) -> tuple[str, ...]:
        raise NotImplementedError

    def set_scan_rate(self, limit: int) -> None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
