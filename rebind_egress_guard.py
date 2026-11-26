"""Outbound DNS rebinding guard: pin resolved addresses per tenant before connecting."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

__all__ = [
    "RebindError",
    "TenantPolicy",
    "PinRecord",
    "ConnectDecision",
    "RebindEgressGuard",
]


class RebindError(ValueError):
    """Raised when an egress resolution or connection is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TenantPolicy:
    tenant: str
    allow_private: bool
    allow_metadata: bool
    max_addresses: int


@dataclass(frozen=True)
class PinRecord:
    tenant: str
    host: str
    addresses: tuple[str, ...]
    created_at: str
    expires_at: str
    hops: tuple[str, ...]


@dataclass(frozen=True)
class ConnectDecision:
    tenant: str
    host: str
    peer_address: str
    accepted: bool
    reason: str
    pinned_addresses: tuple[str, ...]


class RebindEgressGuard:
    """Pin DNS answers per tenant and refuse connections that leave the pin set."""

    def __init__(self, *, default_ttl: int = 60, max_pins_per_tenant: int = 32,
                 max_addresses_per_pin: int = 8, reject_window: float = 60.0,
                 max_rejects_per_host: int = 5, clock=None) -> None:
        self.default_ttl = default_ttl
        self.max_pins_per_tenant = max_pins_per_tenant
        self.max_addresses_per_pin = max_addresses_per_pin
        self.reject_window = reject_window
        self.max_rejects_per_host = max_rejects_per_host
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()

    def register_tenant(self, tenant: str, *, allow_private: bool = False,
                        allow_metadata: bool = False,
                        max_addresses: int | None = None) -> TenantPolicy:
        raise NotImplementedError

    def policy_for(self, tenant: str) -> TenantPolicy:
        raise NotImplementedError

    def resolve(self, tenant: str, host: str, addresses, ttl: int | None = None,
                now: str | None = None) -> PinRecord:
        raise NotImplementedError

    def pin(self, tenant: str, host: str, addresses, ttl: int | None = None,
            now: str | None = None) -> PinRecord:
        raise NotImplementedError

    def check_connect(self, tenant: str, host: str, peer_address: str,
                      sni: str | None = None, cert_subject: str | None = None,
                      now: str | None = None) -> ConnectDecision:
        raise NotImplementedError

    def release(self, tenant: str, host: str) -> int:
        raise NotImplementedError

    def purge(self, now: str | None = None) -> int:
        raise NotImplementedError

    def blocked_address(self, address: str) -> bool:
        raise NotImplementedError

    def status(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
