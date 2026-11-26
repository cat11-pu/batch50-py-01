"""World event window planner.

Expands weekly world events from a calendar definition into concrete windows
with start and end timestamps, materializes them while the server clock
advances, and backfills windows that were missed while the service was down.
Every window can be claimed exactly once; claims and the server clock survive
a snapshot round trip.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "WorldEventError",
    "EventSpec",
    "EventWindow",
    "ClaimResult",
    "WorldEventWindowPlanner",
]


class WorldEventError(ValueError):
    """Raised when a world event operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class EventSpec:
    """Calendar definition of one weekly world event."""

    event_id: str
    weekday: int
    start_minute: int
    duration_minutes: int
    cancelled: bool
    first_start_ts: int


@dataclass(frozen=True)
class EventWindow:
    """One materialized occurrence of a world event."""

    window_id: str
    event_id: str
    start_ts: int
    end_ts: int
    status: str
    compensated: bool
    claims: tuple[str, ...]


@dataclass(frozen=True)
class ClaimResult:
    """Outcome of a successful window claim."""

    window_id: str
    event_id: str
    account: str
    points: int
    compensated: bool


class WorldEventWindowPlanner:
    """Turn weekly event definitions into claimable windows on a server clock."""

    def __init__(self, *, start_ts: int = 0, compensation_cap: int = 3,
                 utc_offset_minutes: int = 0) -> None:
        self.start_ts = start_ts
        self.compensation_cap = compensation_cap
        self.utc_offset_minutes = utc_offset_minutes
        self._lock = threading.RLock()

    def schedule(self, event_id: str, *, weekday: int, start_minute: int,
                 duration_minutes: int = 30,
                 now: int | None = None) -> EventSpec:
        """Register a weekly event starting at *start_minute* local time."""
        raise NotImplementedError

    def cancel_event(self, event_id: str,
                     now: int | None = None) -> EventSpec:
        """Cancel an event so no further windows are materialized."""
        raise NotImplementedError

    def advance(self, to_ts: int) -> tuple[EventWindow, ...]:
        """Move the server clock forward and materialize the windows crossed."""
        raise NotImplementedError

    def windows_between(self, start_ts: int,
                        end_ts: int) -> tuple[EventWindow, ...]:
        """Return windows whose start falls in ``[start_ts, end_ts)``."""
        raise NotImplementedError

    def claim_window(self, window_id: str, account: str,
                     now: int | None = None) -> ClaimResult:
        """Claim the reward of an open window for *account*."""
        raise NotImplementedError

    def compensated_count(self) -> int:
        """Return how many compensated windows were materialized so far."""
        raise NotImplementedError

    def event_record(self, event_id: str) -> EventSpec:
        """Return the calendar record of one event."""
        raise NotImplementedError

    def window_of(self, window_id: str) -> EventWindow:
        """Return one materialized window by id."""
        raise NotImplementedError

    def open_windows(self) -> tuple[EventWindow, ...]:
        """Return windows open for claiming at the current server clock."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a deep copy of the clock, events, windows and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace planner state with a snapshot, validating its structure."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative counters for windows, claims and refusals."""
        raise NotImplementedError
