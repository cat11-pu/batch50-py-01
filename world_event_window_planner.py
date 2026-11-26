"""World event window planner.

Expands weekly world events from a calendar definition into concrete windows
with start and end timestamps, materializes them while the server clock
advances, and backfills windows that were missed while the service was down.
Every window can be claimed exactly once; claims and the server clock survive
a snapshot round trip.
"""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, replace

__all__ = [
    "WorldEventError",
    "EventSpec",
    "EventWindow",
    "ClaimResult",
    "WorldEventWindowPlanner",
]

DAY = 86400
WEEK = 7 * DAY

_COUNTER_KEYS = (
    "cancelled",
    "opened",
    "compensated",
    "dropped",
    "claims",
    "duplicates",
    "closed",
    "clock_rewinds",
)
_WINDOW_STATUSES = frozenset({"open", "closed", "claimed"})


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


@dataclass
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


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _invalid(detail: object = None) -> WorldEventError:
    return WorldEventError("WORLD_EVENT_INVALID_REQUEST", detail)


class WorldEventWindowPlanner:
    """Turn weekly event definitions into claimable windows on a server clock."""

    def __init__(self, *, start_ts: int = 0, compensation_cap: int = 3,
                 utc_offset_minutes: int = 0) -> None:
        if not _is_int(start_ts):
            raise _invalid("start_ts must be an integer")
        if not _is_int(compensation_cap) or compensation_cap < 0:
            raise _invalid("compensation_cap must be a non-negative integer")
        if not _is_int(utc_offset_minutes):
            raise _invalid("utc_offset_minutes must be an integer")

        self.start_ts = start_ts
        self.compensation_cap = compensation_cap
        self.utc_offset_minutes = utc_offset_minutes

        self._clock = start_ts
        self._events: dict[str, EventSpec] = {}
        self._windows: dict[str, EventWindow] = {}
        self._cursors: dict[str, int] = {}
        self._window_seq = 0
        self._counters = {key: 0 for key in _COUNTER_KEYS}
        self._lock = threading.RLock()

    def _first_occurrence_ts(self, weekday: int, start_minute: int,
                             reference: int) -> int:
        """Return the first local-calendar occurrence at or after *reference*."""
        offset_seconds = self.utc_offset_minutes * 60
        local_reference = reference + offset_seconds
        local_day = local_reference // DAY
        local_weekday = (local_day + 3) % 7
        days_ahead = (weekday - local_weekday) % 7
        local_start = (local_day + days_ahead) * DAY + start_minute * 60
        first_ts = local_start - offset_seconds
        if first_ts < reference:
            first_ts += WEEK
        return first_ts

    def _new_window(self, event_id: str, start_ts: int, duration_seconds: int,
                    compensated: bool) -> EventWindow:
        self._window_seq += 1
        return EventWindow(
            window_id=f"w{self._window_seq}",
            event_id=event_id,
            start_ts=start_ts,
            end_ts=start_ts + duration_seconds,
            status="open",
            compensated=compensated,
            claims=(),
        )

    def _close_expired_windows(self, now: int) -> None:
        for window in self._windows.values():
            if (window.status == "open" and not window.compensated
                    and now >= window.end_ts):
                window.status = "closed"

    def schedule(self, event_id: str, *, weekday: int, start_minute: int,
                 duration_minutes: int = 30,
                 now: int | None = None) -> EventSpec:
        """Register a weekly event starting at *start_minute* local time."""
        with self._lock:
            if not isinstance(event_id, str) or not event_id.strip():
                raise _invalid("event_id must be a non-empty string")
            if not _is_int(weekday) or not 0 <= weekday <= 6:
                raise _invalid("weekday must be in 0..6")
            if not _is_int(start_minute) or not 0 <= start_minute <= 1439:
                raise _invalid("start_minute must be in 0..1439")
            if not _is_int(duration_minutes) or duration_minutes <= 0:
                raise _invalid("duration_minutes must be positive")
            if now is not None and not _is_int(now):
                raise _invalid("now must be an integer")

            if event_id in self._events:
                self._counters["duplicates"] += 1
                raise WorldEventError("WORLD_EVENT_DUPLICATE_EVENT", event_id)

            reference = self._clock if now is None else now
            first_start_ts = self._first_occurrence_ts(
                weekday, start_minute, reference
            )
            spec = EventSpec(
                event_id=event_id,
                weekday=weekday,
                start_minute=start_minute,
                duration_minutes=duration_minutes,
                cancelled=False,
                first_start_ts=first_start_ts,
            )
            self._events[event_id] = spec
            self._cursors[event_id] = 0
            return spec

    def cancel_event(self, event_id: str,
                     now: int | None = None) -> EventSpec:
        """Cancel an event so no further windows are materialized."""
        with self._lock:
            if now is not None and not _is_int(now):
                raise _invalid("now must be an integer")
            spec = self._events.get(event_id)
            if spec is None:
                raise WorldEventError(
                    "WORLD_EVENT_UNKNOWN_EVENT", event_id
                )
            if spec.cancelled:
                raise WorldEventError(
                    "WORLD_EVENT_EVENT_CANCELLED", event_id
                )
            cancelled = replace(spec, cancelled=True)
            self._events[event_id] = cancelled
            self._counters["cancelled"] += 1
            return cancelled

    def advance(self, to_ts: int) -> tuple[EventWindow, ...]:
        """Move the server clock forward and materialize the windows crossed."""
        with self._lock:
            if not _is_int(to_ts):
                raise _invalid("to_ts must be an integer")
            if to_ts < self._clock:
                self._counters["clock_rewinds"] += 1
                raise WorldEventError(
                    "WORLD_EVENT_CLOCK_REWIND", to_ts
                )

            self._close_expired_windows(to_ts)

            active_windows: list[EventWindow] = []
            missed_candidates: list[tuple[int, int, str, int]] = []
            total_missed = 0
            next_cursors: dict[str, int] = {}

            for event_id, spec in self._events.items():
                if spec.cancelled:
                    continue

                first_start = spec.first_start_ts
                if to_ts < first_start:
                    continue

                duration_seconds = spec.duration_minutes * 60
                latest_index = (to_ts - first_start) // WEEK
                cursor = self._cursors.get(event_id, 0)
                if latest_index < cursor:
                    continue

                if to_ts >= first_start + duration_seconds:
                    last_missed = (
                        to_ts - first_start - duration_seconds
                    ) // WEEK
                else:
                    last_missed = -1
                last_missed = min(last_missed, latest_index)

                if last_missed >= cursor:
                    missed_count = last_missed - cursor + 1
                    total_missed += missed_count
                    take = min(self.compensation_cap, missed_count)
                    for index in range(last_missed - take + 1,
                                       last_missed + 1):
                        start_ts = first_start + index * WEEK
                        missed_candidates.append(
                            (start_ts, index, event_id, duration_seconds)
                        )

                active_from = max(cursor, last_missed + 1)
                for index in range(active_from, latest_index + 1):
                    start_ts = first_start + index * WEEK
                    window = self._new_window(
                        event_id, start_ts, duration_seconds, False
                    )
                    self._windows[window.window_id] = window
                    self._counters["opened"] += 1
                    active_windows.append(window)

                next_cursors[event_id] = latest_index + 1

            missed_candidates.sort(
                key=lambda item: (item[0], item[2], item[1])
            )
            selected = (missed_candidates[-self.compensation_cap:]
                        if self.compensation_cap else [])
            compensated_windows: list[EventWindow] = []
            for start_ts, _index, event_id, duration_seconds in selected:
                window = self._new_window(
                    event_id, start_ts, duration_seconds, True
                )
                self._windows[window.window_id] = window
                self._counters["compensated"] += 1
                compensated_windows.append(window)

            self._counters["dropped"] += total_missed - len(selected)
            self._cursors.update(next_cursors)
            self._clock = max(self._clock, to_ts)

            created = active_windows + compensated_windows
            created.sort(
                key=lambda window: (
                    window.start_ts, window.event_id, window.window_id
                )
            )
            return tuple(created)

    def windows_between(self, start_ts: int,
                        end_ts: int) -> tuple[EventWindow, ...]:
        """Return windows whose start falls in ``[start_ts, end_ts)``."""
        with self._lock:
            if not _is_int(start_ts) or not _is_int(end_ts):
                raise _invalid("start_ts and end_ts must be integers")
            if start_ts > end_ts:
                raise WorldEventError(
                    "WORLD_EVENT_INVALID_RANGE", (start_ts, end_ts)
                )
            found = [
                window for window in self._windows.values()
                if start_ts <= window.start_ts < end_ts
            ]
            found.sort(
                key=lambda window: (
                    window.start_ts, window.event_id, window.window_id
                )
            )
            return tuple(found)

    def claim_window(self, window_id: str, account: str,
                     now: int | None = None) -> ClaimResult:
        """Claim the reward of an open window for *account*."""
        with self._lock:
            if not isinstance(account, str) or not account:
                raise _invalid("account must be a non-empty string")
            if now is not None and not _is_int(now):
                raise _invalid("now must be an integer")

            window = self._windows.get(window_id)
            if window is None:
                raise WorldEventError(
                    "WORLD_EVENT_UNKNOWN_WINDOW", window_id
                )

            if window.claims:
                if account in window.claims:
                    self._counters["duplicates"] += 1
                    raise WorldEventError(
                        "WORLD_EVENT_DUPLICATE_CLAIM", window_id
                    )
                self._counters["closed"] += 1
                raise WorldEventError(
                    "WORLD_EVENT_WINDOW_CLOSED", window_id
                )

            spec = self._events.get(window.event_id)
            if spec is None or spec.cancelled:
                self._counters["closed"] += 1
                raise WorldEventError(
                    "WORLD_EVENT_WINDOW_CLOSED", window_id
                )

            reference = self._clock if now is None else now
            if window.status != "open":
                self._counters["closed"] += 1
                raise WorldEventError(
                    "WORLD_EVENT_WINDOW_CLOSED", window_id
                )

            if not window.compensated:
                if reference < window.start_ts:
                    self._counters["closed"] += 1
                    raise WorldEventError(
                        "WORLD_EVENT_WINDOW_CLOSED", window_id
                    )
                if reference >= window.end_ts:
                    window.status = "closed"
                    self._counters["closed"] += 1
                    raise WorldEventError(
                        "WORLD_EVENT_WINDOW_CLOSED", window_id
                    )

            points = 50 if window.compensated else 100
            window.status = "claimed"
            window.claims = (account,)
            self._counters["claims"] += 1
            return ClaimResult(
                window_id=window_id,
                event_id=window.event_id,
                account=account,
                points=points,
                compensated=window.compensated,
            )

    def compensated_count(self) -> int:
        """Return how many compensated windows were materialized so far."""
        with self._lock:
            return self._counters["compensated"]

    def event_record(self, event_id: str) -> EventSpec:
        """Return the calendar record of one event."""
        with self._lock:
            spec = self._events.get(event_id)
            if spec is None:
                raise WorldEventError(
                    "WORLD_EVENT_UNKNOWN_EVENT", event_id
                )
            return spec

    def window_of(self, window_id: str) -> EventWindow:
        """Return one materialized window by id."""
        with self._lock:
            window = self._windows.get(window_id)
            if window is None:
                raise WorldEventError(
                    "WORLD_EVENT_UNKNOWN_WINDOW", window_id
                )
            return window

    def open_windows(self) -> tuple[EventWindow, ...]:
        """Return windows open for claiming at the current server clock."""
        with self._lock:
            found = []
            for window in self._windows.values():
                if window.status != "open":
                    continue
                spec = self._events.get(window.event_id)
                if spec is None or spec.cancelled:
                    continue
                if (not window.compensated
                        and self._clock >= window.end_ts):
                    continue
                found.append(window)
            found.sort(
                key=lambda window: (
                    window.start_ts, window.event_id, window.window_id
                )
            )
            return tuple(found)

    def snapshot(self) -> dict:
        """Return a deep copy of the clock, events, windows and counters."""
        with self._lock:
            state = {
                "clock": self._clock,
                "events": {
                    key: {
                        "event_id": spec.event_id,
                        "weekday": spec.weekday,
                        "start_minute": spec.start_minute,
                        "duration_minutes": spec.duration_minutes,
                        "cancelled": spec.cancelled,
                        "first_start_ts": spec.first_start_ts,
                    }
                    for key, spec in self._events.items()
                },
                "windows": {
                    key: {
                        "window_id": window.window_id,
                        "event_id": window.event_id,
                        "start_ts": window.start_ts,
                        "end_ts": window.end_ts,
                        "status": window.status,
                        "compensated": window.compensated,
                        "claims": list(window.claims),
                    }
                    for key, window in self._windows.items()
                },
                "cursors": dict(self._cursors),
                "counters": dict(self._counters),
                "window_seq": self._window_seq,
                "compensation_cap": self.compensation_cap,
                "utc_offset_minutes": self.utc_offset_minutes,
                "start_ts": self.start_ts,
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        """Replace planner state with a snapshot, validating its structure."""
        with self._lock:
            def fail(detail: object = None) -> None:
                raise WorldEventError(
                    "WORLD_EVENT_SNAPSHOT_INVALID", detail
                )

            try:
                data = copy.deepcopy(state)
            except Exception as exc:
                fail(str(exc))

            if not isinstance(data, dict):
                fail("snapshot must be a dict")

            clock = data.get("clock")
            if not _is_int(clock):
                fail("clock must be an integer")

            raw_events = data.get("events")
            raw_windows = data.get("windows")
            if not isinstance(raw_events, dict):
                fail("events must be a dict")
            if not isinstance(raw_windows, dict):
                fail("windows must be a dict")

            events: dict[str, EventSpec] = {}
            for key, raw in raw_events.items():
                if not isinstance(key, str) or not key.strip():
                    fail("event keys must be non-empty strings")
                if isinstance(raw, EventSpec):
                    spec = raw
                    if (spec.event_id != key
                            or not isinstance(spec.event_id, str)
                            or not _is_int(spec.weekday)
                            or not 0 <= spec.weekday <= 6
                            or not _is_int(spec.start_minute)
                            or not 0 <= spec.start_minute <= 1439
                            or not _is_int(spec.duration_minutes)
                            or spec.duration_minutes <= 0
                            or not isinstance(spec.cancelled, bool)
                            or not _is_int(spec.first_start_ts)):
                        fail("invalid event record")
                elif isinstance(raw, dict):
                    event_id = raw.get("event_id", key)
                    weekday = raw.get("weekday")
                    start_minute = raw.get("start_minute")
                    duration = raw.get("duration_minutes")
                    cancelled = raw.get("cancelled")
                    first_start = raw.get("first_start_ts")
                    if event_id != key or not isinstance(event_id, str):
                        fail("event_id does not match its key")
                    if (not _is_int(weekday) or not 0 <= weekday <= 6
                            or not _is_int(start_minute)
                            or not 0 <= start_minute <= 1439
                            or not _is_int(duration) or duration <= 0
                            or not isinstance(cancelled, bool)
                            or not _is_int(first_start)):
                        fail("invalid event record")
                    spec = EventSpec(
                        event_id=event_id,
                        weekday=weekday,
                        start_minute=start_minute,
                        duration_minutes=duration,
                        cancelled=cancelled,
                        first_start_ts=first_start,
                    )
                else:
                    fail("invalid event record")
                events[key] = spec

            windows: dict[str, EventWindow] = {}
            for key, raw in raw_windows.items():
                if not isinstance(key, str) or not key:
                    fail("window keys must be non-empty strings")
                if isinstance(raw, EventWindow):
                    window = raw
                    if (window.window_id != key
                            or not isinstance(window.window_id, str)
                            or not isinstance(window.event_id, str)
                            or not _is_int(window.start_ts)
                            or not _is_int(window.end_ts)
                            or window.end_ts <= window.start_ts
                            or window.status not in _WINDOW_STATUSES
                            or not isinstance(window.compensated, bool)
                            or (not isinstance(window.claims, tuple)
                                and not isinstance(window.claims, list))
                            or any(not isinstance(account, str)
                                   for account in window.claims)):
                        fail("invalid window record")
                elif isinstance(raw, dict):
                    window_id = raw.get("window_id", key)
                    event_id = raw.get("event_id")
                    start_ts = raw.get("start_ts")
                    end_ts = raw.get("end_ts")
                    status = raw.get("status")
                    compensated = raw.get("compensated")
                    claims = raw.get("claims", ())
                    if window_id != key or not isinstance(window_id, str):
                        fail("window_id does not match its key")
                    if not isinstance(event_id, str):
                        fail("invalid window event_id")
                    if (not _is_int(start_ts) or not _is_int(end_ts)
                            or end_ts <= start_ts):
                        fail("invalid window timestamps")
                    if status not in _WINDOW_STATUSES:
                        fail("invalid window status")
                    if not isinstance(compensated, bool):
                        fail("invalid window compensated flag")
                    if (not isinstance(claims, (list, tuple))
                            or any(not isinstance(account, str)
                                   for account in claims)):
                        fail("invalid window claims")
                    window = EventWindow(
                        window_id=window_id,
                        event_id=event_id,
                        start_ts=start_ts,
                        end_ts=end_ts,
                        status=status,
                        compensated=compensated,
                        claims=tuple(claims),
                    )
                else:
                    fail("invalid window record")
                if window.event_id not in events:
                    fail("window references an unknown event")
                windows[key] = window

            raw_cursors = data.get("cursors", {})
            if not isinstance(raw_cursors, dict):
                fail("cursors must be a dict")

            cursors: dict[str, int] = {}
            for event_id, spec in events.items():
                cursor = raw_cursors.get(event_id, 0)
                if not _is_int(cursor) or cursor < 0:
                    fail("invalid event cursor")
                derived = 0
                for window in windows.values():
                    if window.event_id != event_id:
                        continue
                    delta = window.start_ts - spec.first_start_ts
                    if delta >= 0 and delta % WEEK == 0:
                        derived = max(derived, delta // WEEK + 1)
                cursors[event_id] = max(cursor, derived)

            raw_counters = data.get("counters", {})
            if not isinstance(raw_counters, dict):
                fail("counters must be a dict")

            counters = {key: 0 for key in _COUNTER_KEYS}
            counters["opened"] = sum(
                1 for window in windows.values() if not window.compensated
            )
            counters["compensated"] = sum(
                1 for window in windows.values() if window.compensated
            )
            counters["claims"] = sum(
                len(window.claims) for window in windows.values()
            )
            counters["cancelled"] = sum(
                1 for spec in events.values() if spec.cancelled
            )
            for key, value in raw_counters.items():
                if key in counters:
                    if not _is_int(value) or value < 0:
                        fail("invalid counter value")
                    counters[key] = value

            derived_seq = len(windows)
            for window_id in windows:
                if (window_id.startswith("w")
                        and window_id[1:].isdigit()):
                    derived_seq = max(derived_seq, int(window_id[1:]))
            window_seq = data.get("window_seq", derived_seq)
            if not _is_int(window_seq) or window_seq < 0:
                fail("window_seq must be a non-negative integer")
            window_seq = max(window_seq, derived_seq)

            compensation_cap = data.get(
                "compensation_cap", self.compensation_cap
            )
            if not _is_int(compensation_cap) or compensation_cap < 0:
                fail("invalid compensation_cap")
            utc_offset = data.get(
                "utc_offset_minutes", self.utc_offset_minutes
            )
            if not _is_int(utc_offset):
                fail("invalid utc_offset_minutes")
            start_ts = data.get("start_ts", self.start_ts)
            if not _is_int(start_ts):
                fail("invalid start_ts")

            self._clock = clock
            self._events = events
            self._windows = windows
            self._cursors = cursors
            self._counters = counters
            self._window_seq = window_seq
            self.compensation_cap = compensation_cap
            self.utc_offset_minutes = utc_offset
            self.start_ts = start_ts

    def stats(self) -> dict:
        """Return cumulative counters for windows, claims and refusals."""
        with self._lock:
            result: dict[str, int] = {
                "events": len(self._events),
                "windows": len(self._windows),
            }
            result.update(self._counters)
            return result
