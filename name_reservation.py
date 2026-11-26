"""Name reservation book: atomic claims, retention window and rename cooldown.

Names are owned by exactly one account at a time.  Releasing a name parks it
in a retention window during which only the previous owner can take it back;
a rename holds the new name before dropping the old one and starts a cooldown.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "ReservationError",
    "NameState",
    "RenameResult",
    "HistoryEntry",
    "NameReservation",
]


class ReservationError(ValueError):
    """Raised when a reservation operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class NameState:
    """Immutable view of one name slot."""

    name: str
    status: str
    owner: str | None
    held_until: int | None
    last_owner: str | None


@dataclass(frozen=True)
class RenameResult:
    """Result of one rename request."""

    account: str
    old_name: str
    new_name: str
    renamed: bool
    replayed: bool
    cooldown_until: int


@dataclass(frozen=True)
class HistoryEntry:
    """One historical ownership event."""

    name: str
    account: str
    action: str
    at: int


class NameReservation:
    """Allocate names, recycle them after retention and throttle renames."""

    def __init__(self, *, retention: int = 604800,
                 rename_cooldown: int = 2592000,
                 max_history: int = 200) -> None:
        self.retention = retention
        self.rename_cooldown = rename_cooldown
        self.max_history = max_history
        self._lock = threading.RLock()

    def reserve(self, name: str, account: str, *, now: int,
                request_id: str | None = None) -> NameState:
        raise NotImplementedError

    def release(self, name: str, account: str, *, now: int) -> NameState:
        raise NotImplementedError

    def rename(self, account: str, new_name: str, *, now: int,
               request_id: str | None = None) -> RenameResult:
        raise NotImplementedError

    def lookup(self, name: str) -> str:
        raise NotImplementedError

    def owner_of(self, name: str) -> str | None:
        raise NotImplementedError

    def expire_sweep(self, *, now: int) -> int:
        raise NotImplementedError

    def history_of(self, name: str) -> tuple[HistoryEntry, ...]:
        raise NotImplementedError

    def rename_ready_at(self, account: str) -> int | None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
