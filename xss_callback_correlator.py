"""Blind XSS payload leases and callback correlation."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class CallbackError(ValueError):
    """Raised when a payload or callback operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PayloadLease:
    payload_id: str
    target: str
    injection_point: str
    tenant: str
    issued_at: str
    expires_at: str
    signature: str
    status: str


@dataclass(frozen=True)
class CallbackEvent:
    payload_id: str
    source_ip: str
    ua: str
    received_at: str
    dedupe_key: str


@dataclass(frozen=True)
class Correlation:
    payload_id: str
    conclusion: str
    tenant: str
    evidence: dict


class XssCallbackCorrelator:
    """Issue payload leases per injection point and correlate returning callbacks."""

    def __init__(self, *, secret: str = "corr-secret", max_payloads: int = 200,
                 default_ttl: int = 1800, per_source_limit: int = 10,
                 per_payload_limit: int = 3, clock=None) -> None:
        self.secret = secret
        self.max_payloads = max_payloads
        self.default_ttl = default_ttl
        self.per_source_limit = per_source_limit
        self.per_payload_limit = per_payload_limit
        self._clock = clock
        self._lock = threading.RLock()

    def issue_payload(self, target: str, injection_point: str, *,
                      tenant: str = "t1", ttl=None, now=None) -> PayloadLease:
        raise NotImplementedError

    def handle_callback(self, payload_id: str, *, signature: str,
                        source_ip: str, ua: str, now=None) -> Correlation:
        raise NotImplementedError

    def lookup(self, payload_id: str):
        raise NotImplementedError

    def expire(self, now=None) -> int:
        raise NotImplementedError

    def revoke_payload(self, payload_id: str, reason: str) -> PayloadLease:
        raise NotImplementedError

    def list_payloads(self, target=None) -> tuple:
        raise NotImplementedError

    def set_rate_limit(self, *, per_source=None, per_payload=None) -> None:
        raise NotImplementedError

    def report(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
