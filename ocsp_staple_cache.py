"""Reverse-proxy OCSP staple cache: nextUpdate refresh, must-staple and revocation."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class StapleError(ValueError):
    """Raised when a staple lookup or refresh operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CertRecord:
    site: str
    fingerprint: str
    issuer: str
    serial: int
    must_staple: bool
    registered_at: int


@dataclass(frozen=True)
class StapleView:
    site: str
    available: bool
    body: bytes | None
    state: str
    this_update: int | None
    next_update: int | None
    issuer: str


@dataclass(frozen=True)
class RefreshLease:
    site: str
    fingerprint: str
    issuer: str
    acquired_at: int
    expires_at: int
    lease_id: str


@dataclass(frozen=True)
class RefreshResult:
    site: str
    fingerprint: str
    issuer: str
    state: str
    body_size: int
    this_update: int
    next_update: int


@dataclass(frozen=True)
class SweepReport:
    due: int
    expired: int
    evicted: int


class OcspStapleCache:
    """Hold one OCSP response per site and keep handshakes supplied with fresh bytes."""

    def __init__(self, *, max_bytes: int = 65536, max_fingerprints: int = 16,
                 refresh_ratio: float = 0.75, retry_backoff: int = 30,
                 lease_ttl: int = 10, clock=None) -> None:
        self.max_bytes = max_bytes
        self.max_fingerprints = max_fingerprints
        self.refresh_ratio = refresh_ratio
        self.retry_backoff = retry_backoff
        self.lease_ttl = lease_ttl
        self._clock = clock
        self._lock = threading.RLock()

    def register(self, site: str, *, fingerprint: str, issuer: str, serial: int,
                 must_staple: bool = False, now: int | None = None) -> CertRecord:
        raise NotImplementedError

    def get_staple(self, site: str, *, now: int | None = None) -> StapleView:
        raise NotImplementedError

    def acquire_refresh(self, site: str, *, now: int | None = None) -> RefreshLease:
        raise NotImplementedError

    def release_refresh(self, site: str, *, now: int | None = None) -> bool:
        raise NotImplementedError

    def refresh(self, site: str, *, body: bytes, this_update: int, next_update: int,
                status: str = "good", serial: int | None = None,
                issuer: str | None = None, signature_ok: bool = True,
                lease: RefreshLease | None = None,
                now: int | None = None) -> RefreshResult:
        raise NotImplementedError

    def invalidate(self, fingerprint: str, *, issuer: str | None = None,
                   status: str = "revoked", now: int | None = None) -> int:
        raise NotImplementedError

    def mark_revoked(self, issuer: str, serial: int, *,
                     now: int | None = None) -> int:
        raise NotImplementedError

    def status(self, site: str | None = None) -> dict:
        raise NotImplementedError

    def sweep(self, *, now: int | None = None) -> SweepReport:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
