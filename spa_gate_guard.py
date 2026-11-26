"""Single-packet authorization gate: HMAC window, NAT rebinding and one-shot tickets."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SpaError(ValueError):
    """Raised when an enrollment, packet or ticket operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Enrollment:
    client: str
    generation: int
    ports: tuple[int, ...]
    enrolled_at: int


@dataclass(frozen=True)
class KeyRecord:
    generation: int
    created_at: int
    state: str


@dataclass(frozen=True)
class SpaVerdict:
    status: str
    client: str
    port: int
    nonce: str
    generation: int
    source: str


@dataclass(frozen=True)
class Ticket:
    ticket_id: str
    client: str
    port: int
    source: str
    nonce: str
    generation: int
    issued_at: int
    expires_at: int
    state: str


class SpaGateGuard:
    """Authorize single packets and issue short-lived per-port tickets."""

    def __init__(self, *, window: int = 30, skew_steps: int = 1,
                 max_clients: int = 8, max_tickets: int = 32,
                 max_keys: int = 4, cooldown: int = 3,
                 max_failures: int = 5, clock=None) -> None:
        self.window = window
        self.skew_steps = skew_steps
        self.max_clients = max_clients
        self.max_tickets = max_tickets
        self.max_keys = max_keys
        self.cooldown = cooldown
        self.max_failures = max_failures
        self._clock = clock
        self._lock = threading.RLock()

    def enroll(self, client: str, *, ports, generation: int, key: bytes,
               now: int | None = None) -> Enrollment:
        raise NotImplementedError

    def rotate_key(self, generation: int, *, key: bytes,
                   now: int | None = None) -> KeyRecord:
        raise NotImplementedError

    def verify(self, packet: dict, *, now: int | None = None) -> SpaVerdict:
        raise NotImplementedError

    def grant(self, packet: dict, *, ttl: int = 120,
              now: int | None = None) -> Ticket:
        raise NotImplementedError

    def revoke(self, ticket_id: str, *, now: int | None = None) -> int:
        raise NotImplementedError

    def rebind(self, client: str, *, source: str, ticket_id: str,
               now: int | None = None) -> Ticket:
        raise NotImplementedError

    def status(self, client: str, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def tickets(self, client: str | None = None,
                *, now: int | None = None) -> tuple[Ticket, ...]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
