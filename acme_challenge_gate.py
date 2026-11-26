"""ACME challenge gate: orders, authorizations, attempts budget and finalize."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

__all__ = [
    "AcmeError",
    "AccountRecord",
    "OrderRecord",
    "AuthorizationRecord",
    "CertificateRecord",
    "ValidationResult",
    "AcmeChallengeGate",
]


class AcmeError(ValueError):
    """Raised when an order, challenge or certificate operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AccountRecord:
    account_id: str
    thumbprint: str
    created_at: str
    rotated_at: str | None


@dataclass(frozen=True)
class OrderRecord:
    order_id: str
    account_id: str
    identifiers: tuple[str, ...]
    status: str
    created_at: str
    expires_at: str
    certificate_serial: str | None


@dataclass(frozen=True)
class AuthorizationRecord:
    authorization_id: str
    order_id: str
    identifier: str
    challenge_type: str
    token: str
    status: str
    attempts: int
    next_at: str | None


@dataclass(frozen=True)
class CertificateRecord:
    serial: str
    order_id: str
    account_id: str
    identifier: str
    issued_at: str
    revoked_at: str | None


@dataclass(frozen=True)
class ValidationResult:
    order_id: str
    identifier: str
    accepted: bool
    status: str
    attempts: int
    next_at: str | None
    detail: str


class AcmeChallengeGate:
    """Accept ACME orders and gate issuance on per-authorization validation."""

    def __init__(self, *, max_orders_per_account: int = 8, max_attempts: int = 3,
                 order_ttl: int = 3600, propagation_delay: float = 30.0,
                 clock=None) -> None:
        self.max_orders_per_account = max_orders_per_account
        self.max_attempts = max_attempts
        self.order_ttl = order_ttl
        self.propagation_delay = propagation_delay
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()

    def register_account(self, account_id: str, thumbprint: str,
                         now: str | None = None) -> AccountRecord:
        raise NotImplementedError

    def rotate_account_key(self, account_id: str, thumbprint: str,
                           now: str | None = None) -> AccountRecord:
        raise NotImplementedError

    def account_for(self, account_id: str) -> AccountRecord:
        raise NotImplementedError

    def new_order(self, account_id: str, identifiers, now: str | None = None) -> OrderRecord:
        raise NotImplementedError

    def authorize(self, order_id: str, identifier: str, challenge_type: str = "http-01",
                  token: str | None = None, now: str | None = None) -> AuthorizationRecord:
        raise NotImplementedError

    def validate(self, order_id: str, identifier: str, nonce: str, value: str,
                 now: str | None = None) -> ValidationResult:
        raise NotImplementedError

    def finalize(self, order_id: str, csr: str, now: str | None = None) -> CertificateRecord:
        raise NotImplementedError

    def revoke(self, serial: str, reason: str | None = None,
               now: str | None = None) -> bool:
        raise NotImplementedError

    def order_status(self, order_id: str) -> OrderRecord:
        raise NotImplementedError

    def authorization_for(self, order_id: str, identifier: str) -> AuthorizationRecord:
        raise NotImplementedError

    def status(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
