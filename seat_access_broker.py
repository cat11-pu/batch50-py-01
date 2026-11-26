"""Seat access broker: session-bound device grants, active switch, crash residue sweep."""

from __future__ import annotations

import posixpath
import threading
from dataclasses import dataclass


class SeatError(ValueError):
    """Raised when a seat access operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DeviceView:
    path: str
    state: str
    holder: str | None


@dataclass(frozen=True)
class SessionView:
    name: str
    seat: str
    active: bool
    alive: bool
    devices: tuple[str, ...]


@dataclass(frozen=True)
class SweepReport:
    removed: tuple[tuple[str, str], ...]
    kept: int


@dataclass(frozen=True)
class AuditEntry:
    op: str
    session: str
    device: str
    at: int


class SeatAccessBroker:
    """Grant display device nodes to the session that currently owns a seat."""

    def __init__(self) -> None:
        self._lock = threading.RLock()

    def register_session(self, name: str, *, seat: str, active: bool = False) -> None:
        raise NotImplementedError

    def register_device(self, path: str, *, state: str = "ready") -> None:
        raise NotImplementedError

    def set_device_state(self, path: str, *, state: str) -> None:
        raise NotImplementedError

    def set_session_alive(self, name: str, *, alive: bool) -> None:
        raise NotImplementedError

    def set_session_active(self, name: str, *, active: bool) -> None:
        raise NotImplementedError

    def attach_session(self, session: str, device: str, *, now: int) -> bool:
        raise NotImplementedError

    def detach_session(self, session: str, *, now: int,
                       device: str | None = None) -> int:
        raise NotImplementedError

    def switch_active(self, seat: str, session: str, *, now: int) -> dict:
        raise NotImplementedError

    def holders(self, device: str | None = None):
        raise NotImplementedError

    def session_view(self, name: str) -> SessionView:
        raise NotImplementedError

    def device_view(self, path: str) -> DeviceView:
        raise NotImplementedError

    def sweep(self, *, now: int) -> SweepReport:
        raise NotImplementedError

    def audit_log(self) -> tuple[AuditEntry, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
