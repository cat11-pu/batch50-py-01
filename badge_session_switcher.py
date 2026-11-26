"""Shared-terminal badge sessions: tap idempotency, suspend and resume, offline grace."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class BadgeError(ValueError):
    """Refused badge operation carrying a stable machine-readable code."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    terminal_id: str
    badge_serial: str
    state: str
    opened_at: int
    last_seen_at: int
    expires_at: int | None


@dataclass(frozen=True)
class TapResult:
    session_id: str
    terminal_id: str
    badge_serial: str
    state: str
    status: str
    replayed: bool


class BadgeSessionSwitcher:
    """Keep badge sessions per shared terminal with suspend, resume and idle sweeping."""

    def __init__(self, *, max_active_per_terminal: int = 2,
                 max_terminals_per_badge: int = 3, idle_timeout: int = 300,
                 suspended_ttl: int = 900, offline_grace: int = 120,
                 clock=None) -> None:
        self.max_active_per_terminal = max_active_per_terminal
        self.max_terminals_per_badge = max_terminals_per_badge
        self.idle_timeout = idle_timeout
        self.suspended_ttl = suspended_ttl
        self.offline_grace = offline_grace
        self._clock = clock
        self._lock = threading.RLock()

    def tap(self, terminal_id: str, badge_serial: str, seq: int, *,
            now: int | None = None) -> TapResult:
        raise NotImplementedError

    def suspend(self, terminal_id: str, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def resume(self, terminal_id: str, badge_serial: str, *,
               now: int | None = None) -> SessionRecord:
        raise NotImplementedError

    def logout(self, terminal_id: str, badge_serial: str | None = None, *,
               now: int | None = None) -> int:
        raise NotImplementedError

    def list_active(self, terminal_id: str | None = None) -> list[SessionRecord]:
        raise NotImplementedError

    def mark_offline(self, terminal_id: str, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def mark_online(self, terminal_id: str, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def sweep(self, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def session_view(self, session_id: str) -> SessionRecord:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
