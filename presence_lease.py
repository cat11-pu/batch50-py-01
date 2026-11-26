"""Presence lease registry: heartbeats, reconnect grace and preemption.

Each session owns a lease with an absolute expiry.  Heartbeats extend the
lease from the current time, a disconnect parks the session in a reconnect
grace window, and only after the grace expires is an offline event emitted.
A newer device login demotes older sessions of the same account to preemptable.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "PresenceError",
    "SessionView",
    "OfflineEvent",
    "PresenceLease",
]


class PresenceError(ValueError):
    """Raised when a presence operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SessionView:
    """Immutable view of one presence session."""

    session_id: str
    account: str
    device: str
    status: str
    expires_at: int
    grace_until: int | None
    preemptable: bool
    shard: int


@dataclass(frozen=True)
class OfflineEvent:
    """Offline broadcast emitted after a grace window runs out."""

    session_id: str
    account: str
    reason: str
    lease_expired_at: int


class PresenceLease:
    """Own presence leases, reconnect grace windows and offline broadcasts."""

    def __init__(self, *, ttl: int = 60, grace: int = 30,
                 shard_count: int = 4) -> None:
        self.ttl = ttl
        self.grace = grace
        self.shard_count = shard_count
        self._lock = threading.RLock()

    def acquire(self, account: str, session_id: str, *, device: str,
                shard: int = 0, now: int) -> SessionView:
        raise NotImplementedError

    def renew(self, session_id: str, *, now: int) -> SessionView:
        raise NotImplementedError

    def release(self, session_id: str, *, now: int) -> SessionView:
        raise NotImplementedError

    def resume(self, session_id: str, *, now: int) -> SessionView:
        raise NotImplementedError

    def expire_sweep(self, *, now: int) -> tuple[OfflineEvent, ...]:
        raise NotImplementedError

    def shard_recover(self, shard: int, *, now: int) -> dict:
        raise NotImplementedError

    def sessions_on(self, account: str) -> tuple[SessionView, ...]:
        raise NotImplementedError

    def shard_sessions(self, shard: int) -> tuple[SessionView, ...]:
        raise NotImplementedError

    def session_of(self, session_id: str) -> SessionView:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
