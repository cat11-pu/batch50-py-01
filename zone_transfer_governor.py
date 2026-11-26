"""Authoritative zone-transfer governance: double-factor authorization and budgets."""

from __future__ import annotations

import threading
from dataclasses import dataclass

SERIAL_MOD = 2 ** 32
SERIAL_HALF = 2 ** 31


def serial_is_newer(candidate: int, reference: int) -> bool:
    """Return True when candidate is newer than reference under RFC 1982 arithmetic."""
    raise NotImplementedError


class TransferDenied(ValueError):
    """Raised when an authorization or transfer step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ZoneState:
    zone: str
    serial: int
    digest: str
    records: tuple[str, ...]
    history: tuple[int, ...]
    loaded_at: int


@dataclass(frozen=True)
class AuthGrant:
    zone: str
    secondary: str
    source: str
    key_name: str
    expires_at: int
    state: str


@dataclass(frozen=True)
class TransferPlan:
    zone: str
    secondary: str
    mode: str
    since: int | None
    serial: int
    messages: int
    digest: str


@dataclass(frozen=True)
class ProgressReport:
    zone: str
    secondary: str
    mode: str
    messages: int
    bytes_sent: int
    remaining_messages: int
    remaining_bytes: int
    last_soa: int | None


@dataclass(frozen=True)
class TransferReceipt:
    zone: str
    secondary: str
    mode: str
    serial: int
    digest: str
    messages: int
    bytes_sent: int
    state: str


class ZoneTransferGovernor:
    """Decide who may transfer a zone and how much of it may be sent."""

    def __init__(self, *, max_messages: int = 64, max_bytes: int = 1048576,
                 auth_ttl: int = 300, clock=None) -> None:
        self.max_messages = max_messages
        self.max_bytes = max_bytes
        self.auth_ttl = auth_ttl
        self._clock = clock
        self._lock = threading.Lock()

    def load_zone(self, zone: str, *, serial: int, digest: str, records,
                  history=(), now: int | None = None) -> ZoneState:
        raise NotImplementedError

    def register_key(self, zone: str, key_name: str) -> tuple[str, ...]:
        raise NotImplementedError

    def authorize(self, zone: str, *, secondary: str, source: str,
                  key_name: str, now: int | None = None) -> AuthGrant:
        raise NotImplementedError

    def remove_secondary(self, zone: str, secondary: str) -> int:
        raise NotImplementedError

    def begin_transfer(self, zone: str, *, secondary: str, source: str,
                       key_name: str, mode: str = "auto", since: int | None = None,
                       now: int | None = None) -> TransferPlan:
        raise NotImplementedError

    def record_progress(self, zone: str, secondary: str, *, messages: int = 0,
                        bytes_: int = 0, last_soa: int | None = None,
                        now: int | None = None) -> ProgressReport:
        raise NotImplementedError

    def complete(self, zone: str, secondary: str, *, digest: str,
                 now: int | None = None) -> TransferReceipt:
        raise NotImplementedError

    def abort(self, zone: str, secondary: str, *, reason: str = "",
              now: int | None = None) -> dict:
        raise NotImplementedError

    def resume(self, zone: str, secondary: str, *, source: str, key_name: str,
               now: int | None = None) -> TransferPlan:
        raise NotImplementedError

    def zone_status(self, zone: str) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
