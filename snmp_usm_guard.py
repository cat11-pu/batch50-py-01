"""SNMPv3 USM authoritative-engine guard: discovery, key localization, replay window."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

__all__ = [
    "UsmError",
    "EngineContext",
    "LocalizedKey",
    "UsmReport",
    "UsmDecision",
    "SnmpUsmGuard",
]

MAX_ENGINE_BOOTS = 2147483647


class UsmError(ValueError):
    """Raised when a USM operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class EngineContext:
    engine_id: str
    boots: int
    engine_time: int
    restarts: int
    window_entries: int


@dataclass(frozen=True)
class LocalizedKey:
    engine_id: str
    user: str
    generation: int
    digest: str
    created_at: str
    expires_at: str | None
    send: bool
    recv: bool


@dataclass(frozen=True)
class UsmReport:
    msg_id: str
    engine_id: str
    user: str
    reason: str
    boots: int
    engine_time: int


@dataclass(frozen=True)
class UsmDecision:
    msg_id: str
    engine_id: str
    user: str
    accepted: bool
    reason: str
    boots: int
    engine_time: int
    generation: int


class SnmpUsmGuard:
    """Serve SNMPv3 USM discovery and verify authenticated requests per engine."""

    def __init__(self, *, time_window: int = 150, max_window_entries: int = 64,
                 per_user_limit: int = 20, rate_period: float = 60.0,
                 grace_seconds: float = 30.0, clock=None) -> None:
        self.time_window = time_window
        self.max_window_entries = max_window_entries
        self.per_user_limit = per_user_limit
        self.rate_period = rate_period
        self.grace_seconds = grace_seconds
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()

    def register_engine(self, engine_id: str, boots: int = 0, now: str | None = None) -> EngineContext:
        raise NotImplementedError

    def register_user(self, engine_id: str, user: str, secret: str) -> LocalizedKey:
        raise NotImplementedError

    def discover(self, engine_id: str | None = None) -> dict:
        raise NotImplementedError

    def localize_key(self, engine_id: str, user: str, secret: str | None = None) -> LocalizedKey:
        raise NotImplementedError

    def verify_request(self, msg_id: str, engine_id: str, user: str, boots: int,
                       engine_time: int, digest: str) -> UsmDecision:
        raise NotImplementedError

    def rotate_key(self, engine_id: str, user: str, secret: str) -> LocalizedKey:
        raise NotImplementedError

    def expire_keys(self, now: str | None = None) -> int:
        raise NotImplementedError

    def restart(self, engine_id: str | None = None) -> EngineContext:
        raise NotImplementedError

    def purge_window(self, engine_id: str | None = None) -> int:
        raise NotImplementedError

    def status(self, engine_id: str | None = None) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
