"""Watermark scheduling per clip segment with region avoidance.

Every watermark slot owns a display interval, a preferred region and a list of
fallback regions.  Planning assigns at most one watermark per region and per
moment, moving lower priority slots to their alternatives; assignments that
cross a segment boundary are marked as continuations of the earlier segment.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "WatermarkError",
    "Slot",
    "Assignment",
    "Conflict",
    "Plan",
    "WatermarkRegionPlanner",
]


class WatermarkError(ValueError):
    """Raised when a watermark planning step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Slot:
    """One requested watermark slot."""

    slot_id: str
    start: int
    end: int
    region: str
    alternatives: tuple[str, ...]
    priority: int
    opacity: float
    fade_in: int


@dataclass(frozen=True)
class Assignment:
    """One slot placed inside one segment."""

    slot_id: str
    region: str
    requested_region: str
    start: int
    end: int
    segment_id: str
    continued: bool
    priority: int
    opacity: float
    fade_in: int
    fade_origin: int

    def opacity_at(self, time: int) -> float:
        """Return the effective opacity of this assignment at *time*."""
        raise NotImplementedError


@dataclass(frozen=True)
class Conflict:
    """Two slots asking for the same region over overlapping time."""

    slot_id: str
    other_slot_id: str
    region: str
    start: int
    end: int


@dataclass(frozen=True)
class Plan:
    """Resolved assignment table of one planning run."""

    plan_id: str
    assignments: tuple[Assignment, ...]
    conflicts: tuple[Conflict, ...]
    degradations: tuple[tuple[str, str], ...]


class WatermarkRegionPlanner:
    """Place watermark slots on the timeline without region collisions."""

    def __init__(self, *, default_opacity: float = 0.8) -> None:
        self.default_opacity = default_opacity
        self._lock = threading.RLock()

    def set_regions(self, regions) -> tuple[str, ...]:
        """Declare the on-screen regions in display order."""
        raise NotImplementedError

    def add_segment(self, segment_id: str, *, start: int, end: int) -> None:
        """Register one non-overlapping clip segment."""
        raise NotImplementedError

    def add_slot(self, slot_id: str, *, start: int, end: int, region: str,
                 alternatives=(), priority: int = 0, opacity: float = 0.8,
                 fade_in: int = 0) -> Slot:
        """Request a watermark slot on the absolute timeline."""
        raise NotImplementedError

    def remove_slot(self, slot_id: str) -> bool:
        """Drop one requested slot; return whether it existed."""
        raise NotImplementedError

    def plan(self) -> Plan:
        """Resolve every slot into a per-segment assignment table."""
        raise NotImplementedError

    def conflicts(self) -> tuple[Conflict, ...]:
        """Return overlapping same-region slot pairs."""
        raise NotImplementedError

    def apply(self, plan_id: str) -> Plan:
        """Make a planned assignment table the active one."""
        raise NotImplementedError

    def at_time(self, time: int) -> tuple[Assignment, ...]:
        """Return the active assignments at *time* in region order."""
        raise NotImplementedError

    def active_plan(self) -> str | None:
        """Return the id of the currently active plan."""
        raise NotImplementedError

    def slots(self) -> tuple[Slot, ...]:
        """Return the requested slots ordered by slot id."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of the planner state."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the planner state with a previously taken snapshot."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the planning, relocation and degradation counters."""
        raise NotImplementedError
