"""Watermark scheduling per clip segment with region avoidance."""

from __future__ import annotations

import copy
import math
import threading
from dataclasses import asdict, dataclass, fields
from typing import Any

__all__ = [
    "WatermarkError",
    "Slot",
    "Assignment",
    "Conflict",
    "Plan",
    "WatermarkRegionPlanner",
]


_SNAPSHOT_VERSION = 1
_SNAPSHOT_KEYS = (
    "version",
    "regions",
    "segments",
    "slots",
    "plans",
    "active",
    "sequence",
    "stats",
)
_REQUIRED_STATS = (
    "segments",
    "slots",
    "plans",
    "applied",
    "conflicts",
    "relocations",
    "degraded",
    "continuations",
)
_UNSET = object()


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
        if self.fade_in == 0:
            return self.opacity
        effective = self.opacity * min(
            1.0, (float(time) - self.fade_origin + 1) / self.fade_in
        )
        return round(effective, 3)


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


@dataclass(frozen=True)
class _Segment:
    segment_id: str
    start: float
    end: float


def _invalid(detail: object = None) -> WatermarkError:
    return WatermarkError("WATERMARK_INVALID", detail)


def _is_real_number(value: object) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(value)
    )


def _validate_interval(start: object, end: object) -> None:
    if not _is_real_number(start) or start < 0:
        raise _invalid("start must be a non-negative finite number")
    if not _is_real_number(end) or end <= start:
        raise _invalid("end must be greater than start")


def _valid_opacity(value: object) -> bool:
    return _is_real_number(value) and 0 < float(value) <= 1


def _validate_priority(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _invalid("priority must be an integer from 0 to 9")
    if not 0 <= value <= 9:
        raise _invalid("priority must be an integer from 0 to 9")


def _validate_fade_in(value: object) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _invalid("fade_in must be a non-negative integer")


def _normalize_regions(regions: object) -> tuple[str, ...]:
    if isinstance(regions, (str, bytes)):
        raise _invalid("regions must be a non-empty sequence of strings")
    try:
        items = tuple(regions)  # type: ignore[arg-type]
    except TypeError as exc:
        raise _invalid("regions must be a non-empty sequence of strings") from exc

    if not items:
        raise _invalid("regions must not be empty")
    normalized: list[str] = []
    seen: set[str] = set()
    for region in items:
        if not isinstance(region, str) or not region:
            raise _invalid("region names must be non-empty strings")
        if region in seen:
            raise _invalid("region names must be unique")
        seen.add(region)
        normalized.append(region)
    return tuple(normalized)


def _normalize_alternatives(
    alternatives: object, region: str, regions: tuple[str, ...]
) -> tuple[str, ...]:
    if isinstance(alternatives, (str, bytes)):
        raise _invalid("alternatives must be a sequence of region names")
    try:
        items = tuple(alternatives)  # type: ignore[arg-type]
    except TypeError as exc:
        raise _invalid("alternatives must be a sequence of region names") from exc

    seen: set[str] = set()
    for alternative in items:
        if not isinstance(alternative, str):
            raise _invalid("alternatives must contain registered region names")
        if alternative not in regions:
            raise _invalid("alternatives must contain registered region names")
        if alternative == region:
            raise _invalid("alternatives must not contain the primary region")
        if alternative in seen:
            raise _invalid("alternatives must not contain duplicates")
        seen.add(alternative)
    return tuple(items)


def _plan_identifier(sequence: int) -> str:
    return f"plan-{sequence:04d}"


class WatermarkRegionPlanner:
    """Place watermark slots on the timeline without region collisions."""

    def __init__(self, *, default_opacity: float = 0.8) -> None:
        if not _valid_opacity(default_opacity):
            raise _invalid("default_opacity must be in (0, 1]")
        self.default_opacity = default_opacity
        self._lock = threading.RLock()
        self._regions: tuple[str, ...] = ()
        self._segments: dict[str, _Segment] = {}
        self._slots: dict[str, Slot] = {}
        self._plans: dict[str, Plan] = {}
        self._active: str | None = None
        self._sequence = 0
        self._stats: dict[str, int] = {key: 0 for key in _REQUIRED_STATS}

    def set_regions(self, regions) -> tuple[str, ...]:
        """Declare the on-screen regions in display order."""
        with self._lock:
            normalized = _normalize_regions(regions)
            if self._slots:
                raise WatermarkError(
                    "WATERMARK_REGIONS_LOCKED",
                    "regions cannot be changed while slots are registered",
                )
            self._regions = normalized
            return self._regions

    def add_segment(self, segment_id: str, *, start: int, end: int) -> None:
        """Register one non-overlapping clip segment."""
        with self._lock:
            if not isinstance(segment_id, str):
                raise _invalid("segment_id must be a string")
            if segment_id in self._segments:
                raise WatermarkError(
                    "WATERMARK_SEGMENT_EXISTS",
                    f"segment {segment_id!r} already exists",
                )
            _validate_interval(start, end)
            for existing in self._segments.values():
                if start < existing.end and existing.start < end:
                    raise _invalid(
                        f"segment {segment_id!r} overlaps "
                        f"{existing.segment_id!r}"
                    )
            self._segments[segment_id] = _Segment(segment_id, start, end)
            self._stats["segments"] = len(self._segments)

    def add_slot(
        self,
        slot_id: str,
        *,
        start: int,
        end: int,
        region: str,
        alternatives=(),
        priority: int = 0,
        opacity: float | object = _UNSET,
        fade_in: int = 0,
    ) -> Slot:
        """Request a watermark slot on the absolute timeline."""
        with self._lock:
            if not isinstance(slot_id, str):
                raise _invalid("slot_id must be a string")
            if slot_id in self._slots:
                raise WatermarkError(
                    "WATERMARK_SLOT_EXISTS",
                    f"slot {slot_id!r} already exists",
                )

            _validate_interval(start, end)
            if not isinstance(region, str) or region not in self._regions:
                raise _invalid("region must be registered")
            normalized_alternatives = _normalize_alternatives(
                alternatives, region, self._regions
            )
            _validate_priority(priority)
            effective_opacity = (
                self.default_opacity if opacity is _UNSET else opacity
            )
            if not _valid_opacity(effective_opacity):
                raise _invalid("opacity must be in (0, 1]")
            _validate_fade_in(fade_in)

            slot = Slot(
                slot_id=slot_id,
                start=start,
                end=end,
                region=region,
                alternatives=normalized_alternatives,
                priority=priority,
                opacity=float(effective_opacity),
                fade_in=fade_in,
            )
            self._slots[slot_id] = slot
            self._active = None
            self._stats["slots"] = len(self._slots)
            return slot

    def remove_slot(self, slot_id: str) -> bool:
        """Drop one requested slot; return whether it existed."""
        with self._lock:
            if slot_id not in self._slots:
                return False
            del self._slots[slot_id]
            self._active = None
            self._stats["slots"] = len(self._slots)
            return True

    def plan(self) -> Plan:
        """Resolve every slot into a per-segment assignment table."""
        with self._lock:
            conflicts = self._compute_conflicts_locked()
            segments = self._ordered_segments_locked()
            ordered_slots = sorted(
                self._slots.values(),
                key=lambda slot: (-slot.priority, slot.start, slot.slot_id),
            )

            occupied: dict[str, list[tuple[float, float]]] = {
                region: [] for region in self._regions
            }
            assignments: list[Assignment] = []
            degradations: list[tuple[str, str]] = []
            relocations = 0
            continuations = 0

            for slot in ordered_slots:
                pieces = self._segment_pieces_locked(slot, segments)
                if not pieces:
                    continue

                selected_region: str | None = None
                for candidate in (slot.region, *slot.alternatives):
                    if self._region_free_locked(candidate, pieces, occupied):
                        selected_region = candidate
                        break

                if selected_region is None:
                    degradations.append((slot.slot_id, "all_regions_occupied"))
                    continue

                if selected_region != slot.region:
                    relocations += 1

                for segment_id, piece_start, piece_end, continued in pieces:
                    assignment = Assignment(
                        slot_id=slot.slot_id,
                        region=selected_region,
                        requested_region=slot.region,
                        start=piece_start,
                        end=piece_end,
                        segment_id=segment_id,
                        continued=continued,
                        priority=slot.priority,
                        opacity=slot.opacity,
                        fade_in=slot.fade_in,
                        fade_origin=slot.start,
                    )
                    assignments.append(assignment)
                    occupied[selected_region].append((piece_start, piece_end))
                    if continued:
                        continuations += 1

            assignments.sort(key=lambda item: (item.start, item.slot_id))
            degradations.sort(key=lambda item: item[0])

            self._sequence += 1
            plan_id = _plan_identifier(self._sequence)
            plan = Plan(
                plan_id=plan_id,
                assignments=tuple(assignments),
                conflicts=conflicts,
                degradations=tuple(degradations),
            )
            self._plans[plan_id] = plan
            self._stats["plans"] += 1
            self._stats["conflicts"] = len(conflicts)
            self._stats["relocations"] = relocations
            self._stats["degraded"] = len(degradations)
            self._stats["continuations"] = continuations
            return plan

    def conflicts(self) -> tuple[Conflict, ...]:
        """Return overlapping same-region slot pairs."""
        with self._lock:
            result = self._compute_conflicts_locked()
            self._stats["conflicts"] = len(result)
            return result

    def apply(self, plan_id: str) -> Plan:
        """Make a planned assignment table the active one."""
        with self._lock:
            plan = self._plans.get(plan_id)
            if plan is None:
                raise WatermarkError(
                    "WATERMARK_UNKNOWN_PLAN", f"unknown plan {plan_id!r}"
                )
            self._active = plan_id
            self._stats["applied"] += 1
            return plan

    def at_time(self, time: int) -> tuple[Assignment, ...]:
        """Return the active assignments at *time* in region order."""
        with self._lock:
            if self._active is None:
                raise WatermarkError(
                    "WATERMARK_NO_PLAN", "no plan is currently applied"
                )
            plan = self._plans.get(self._active)
            if plan is None:
                raise WatermarkError(
                    "WATERMARK_NO_PLAN", "active plan is unavailable"
                )
            if not _is_real_number(time):
                raise _invalid("time must be a finite number")

            by_region: dict[str, Assignment] = {}
            for assignment in plan.assignments:
                if assignment.start <= time < assignment.end:
                    current = by_region.get(assignment.region)
                    if current is None or assignment.priority > current.priority:
                        by_region[assignment.region] = assignment

            order = {region: index for index, region in enumerate(self._regions)}
            return tuple(
                sorted(
                    by_region.values(),
                    key=lambda assignment: (
                        order.get(assignment.region, len(order)),
                        assignment.region,
                        assignment.slot_id,
                    ),
                )
            )

    def active_plan(self) -> str | None:
        """Return the id of the currently active plan."""
        with self._lock:
            return self._active

    def slots(self) -> tuple[Slot, ...]:
        """Return the requested slots ordered by slot id."""
        with self._lock:
            return tuple(sorted(self._slots.values(), key=lambda slot: slot.slot_id))

    def snapshot(self) -> dict:
        """Return a detached snapshot of the planner state."""
        with self._lock:
            state = {
                "version": _SNAPSHOT_VERSION,
                "regions": tuple(self._regions),
                "segments": copy.deepcopy(self._ordered_segments_locked()),
                "slots": copy.deepcopy(self._slots),
                "plans": copy.deepcopy(self._plans),
                "active": self._active,
                "sequence": self._sequence,
                "stats": copy.deepcopy(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        """Replace the planner state with a previously taken snapshot."""
        with self._lock:
            try:
                decoded = _decode_snapshot(state)
            except WatermarkError as exc:
                if exc.code == "WATERMARK_SNAPSHOT_INVALID":
                    raise
                raise WatermarkError(
                    "WATERMARK_SNAPSHOT_INVALID", exc.detail
                ) from exc
            except Exception as exc:
                raise WatermarkError(
                    "WATERMARK_SNAPSHOT_INVALID", str(exc)
                ) from exc

            self._regions = decoded["regions"]
            self._segments = decoded["segments"]
            self._slots = decoded["slots"]
            self._plans = decoded["plans"]
            self._active = decoded["active"]
            self._sequence = decoded["sequence"]
            self._stats = decoded["stats"]

    def stats(self) -> dict:
        """Return the planning, relocation and degradation counters."""
        with self._lock:
            return copy.deepcopy(self._stats)

    def _ordered_segments_locked(self) -> list[_Segment]:
        return sorted(
            self._segments.values(),
            key=lambda segment: (segment.start, segment.segment_id),
        )

    def _timeline_segments_locked(self) -> list[_Segment]:
        segments = self._ordered_segments_locked()
        if segments:
            return segments
        return [_Segment("", -math.inf, math.inf)]

    def _has_timeline_overlap_locked(self, start: float, end: float) -> bool:
        for segment in self._timeline_segments_locked():
            clipped_start = max(start, segment.start)
            clipped_end = min(end, segment.end)
            if clipped_start < clipped_end:
                return True
        return False

    def _compute_conflicts_locked(self) -> tuple[Conflict, ...]:
        slots = sorted(
            self._slots.values(), key=lambda slot: (slot.slot_id, slot.start)
        )
        conflicts: list[Conflict] = []
        for index, left in enumerate(slots):
            for right in slots[index + 1 :]:
                if left.region != right.region:
                    continue
                overlap_start = max(left.start, right.start)
                overlap_end = min(left.end, right.end)
                if overlap_start >= overlap_end:
                    continue
                if not self._has_timeline_overlap_locked(
                    overlap_start, overlap_end
                ):
                    continue
                conflicts.append(
                    Conflict(
                        slot_id=left.slot_id,
                        other_slot_id=right.slot_id,
                        region=left.region,
                        start=overlap_start,
                        end=overlap_end,
                    )
                )
        conflicts.sort(
            key=lambda conflict: (
                conflict.start,
                conflict.slot_id,
                conflict.other_slot_id,
            )
        )
        return tuple(conflicts)

    def _segment_pieces_locked(
        self, slot: Slot, segments: list[_Segment]
    ) -> list[tuple[str, float, float, bool]]:
        effective_segments = segments or [_Segment("", -math.inf, math.inf)]
        pieces: list[tuple[str, float, float, bool]] = []
        for segment in effective_segments:
            piece_start = max(slot.start, segment.start)
            piece_end = min(slot.end, segment.end)
            if piece_start < piece_end:
                pieces.append(
                    (
                        segment.segment_id,
                        piece_start,
                        piece_end,
                        bool(pieces),
                    )
                )
        return pieces

    @staticmethod
    def _region_free_locked(
        region: str,
        pieces: list[tuple[str, float, float, bool]],
        occupied: dict[str, list[tuple[float, float]]],
    ) -> bool:
        for _, piece_start, piece_end, _ in pieces:
            for occupied_start, occupied_end in occupied.get(region, ()):
                if piece_start < occupied_end and occupied_start < piece_end:
                    return False
        return True


def _snapshot_invalid(detail: object = None) -> WatermarkError:
    return WatermarkError("WATERMARK_SNAPSHOT_INVALID", detail)


def _decode_snapshot(state: object) -> dict[str, Any]:
    if not isinstance(state, dict):
        raise _snapshot_invalid("snapshot must be a dict")
    for key in _SNAPSHOT_KEYS:
        if key not in state:
            raise _snapshot_invalid(f"missing snapshot field {key!r}")

    version = state["version"]
    if isinstance(version, bool) or not isinstance(version, int):
        raise _snapshot_invalid("version must be an integer")
    if version != _SNAPSHOT_VERSION:
        raise _snapshot_invalid("unsupported snapshot version")

    regions = _normalize_regions(state["regions"])
    segments = _decode_segments(state["segments"])
    slots = _decode_slots(state["slots"], regions)
    plans = _decode_plans(state["plans"])

    active = state["active"]
    if active is not None:
        if not isinstance(active, str) or active not in plans:
            raise _snapshot_invalid("active plan is unknown")

    sequence = state["sequence"]
    if (
        isinstance(sequence, bool)
        or not isinstance(sequence, int)
        or sequence < 0
    ):
        raise _snapshot_invalid("sequence must be a non-negative integer")

    raw_stats = state["stats"]
    if not isinstance(raw_stats, dict):
        raise _snapshot_invalid("stats must be a dict")
    for key in _REQUIRED_STATS:
        if key not in raw_stats:
            raise _snapshot_invalid(f"missing stat {key!r}")
        value = raw_stats[key]
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise _snapshot_invalid(
                f"stat {key!r} must be a non-negative integer"
            )
    stats = copy.deepcopy(raw_stats)

    return {
        "regions": regions,
        "segments": segments,
        "slots": slots,
        "plans": plans,
        "active": active,
        "sequence": sequence,
        "stats": stats,
    }


def _mapping_items(value: object, label: str) -> list[tuple[object, object]]:
    if isinstance(value, dict):
        return list(value.items())
    if isinstance(value, (list, tuple)):
        return [(None, item) for item in value]
    raise _snapshot_invalid(f"{label} must be a mapping or sequence")


def _decode_segments(value: object) -> dict[str, _Segment]:
    items = _mapping_items(value, "segments")
    segments: dict[str, _Segment] = {}
    for key, item in items:
        if isinstance(item, _Segment):
            item = asdict(item)
        if isinstance(item, (list, tuple)):
            if len(item) == 3:
                segment_id, start, end = item
            elif len(item) == 2 and key is not None:
                segment_id = key
                start, end = item
            else:
                raise _snapshot_invalid("invalid segment record")
        elif isinstance(item, dict):
            segment_id = item.get("segment_id", key)
            if key is not None and segment_id != key:
                raise _snapshot_invalid("segment id does not match its key")
            start = item.get("start")
            end = item.get("end")
        else:
            raise _snapshot_invalid("segment record must be a dict")

        if not isinstance(segment_id, str):
            raise _snapshot_invalid("segment_id must be a string")
        _validate_interval(start, end)
        segment = _Segment(segment_id, start, end)  # type: ignore[arg-type]

        if segment.segment_id in segments:
            raise _snapshot_invalid("duplicate segment in snapshot")
        for existing in segments.values():
            if segment.start < existing.end and existing.start < segment.end:
                raise _snapshot_invalid("overlapping segments in snapshot")
        segments[segment.segment_id] = segment
    return segments


def _decode_slots(
    value: object, regions: tuple[str, ...]
) -> dict[str, Slot]:
    items = _mapping_items(value, "slots")
    slots: dict[str, Slot] = {}
    for key, item in items:
        if isinstance(item, Slot):
            item = asdict(item)
        if isinstance(item, dict):
            slot_id = item.get("slot_id", key)
            if key is not None and slot_id != key:
                raise _snapshot_invalid("slot id does not match its key")
            if not isinstance(slot_id, str):
                raise _snapshot_invalid("slot_id must be a string")

            start = item.get("start")
            end = item.get("end")
            region = item.get("region")
            alternatives = item.get("alternatives", ())
            priority = item.get("priority", 0)
            opacity = item.get("opacity")
            fade_in = item.get("fade_in", 0)

            _validate_interval(start, end)
            if not isinstance(region, str) or region not in regions:
                raise _snapshot_invalid("slot region is not registered")
            alternatives = _normalize_alternatives(alternatives, region, regions)
            _validate_priority(priority)
            if not _valid_opacity(opacity):
                raise _snapshot_invalid("invalid slot opacity")
            _validate_fade_in(fade_in)
            slot = Slot(
                slot_id=slot_id,
                start=start,  # type: ignore[arg-type]
                end=end,  # type: ignore[arg-type]
                region=region,
                alternatives=alternatives,
                priority=priority,  # type: ignore[arg-type]
                opacity=float(opacity),  # type: ignore[arg-type]
                fade_in=fade_in,  # type: ignore[arg-type]
            )
        else:
            raise _snapshot_invalid("slot record must be a dict")

        if slot.slot_id in slots:
            raise _snapshot_invalid("duplicate slot in snapshot")
        slots[slot.slot_id] = slot
    return slots


def _dataclass_record(cls: type, value: object) -> Any:
    if isinstance(value, cls):
        return value
    if not isinstance(value, dict):
        raise _snapshot_invalid(f"{cls.__name__} record must be a dict")
    try:
        allowed = {field.name for field in fields(cls)}
        missing = allowed - value.keys()
        if missing:
            raise KeyError(sorted(missing)[0])
        return cls(**{key: value[key] for key in allowed})
    except (KeyError, TypeError) as exc:
        raise _snapshot_invalid(f"invalid {cls.__name__} record") from exc


def _decode_plans(value: object) -> dict[str, Plan]:
    items = _mapping_items(value, "plans")
    plans: dict[str, Plan] = {}
    for key, item in items:
        if isinstance(item, Plan):
            item = asdict(item)
        if isinstance(item, dict):
            plan_id = item.get("plan_id", key)
            if key is not None and plan_id != key:
                raise _snapshot_invalid("plan id does not match its key")
            if not isinstance(plan_id, str):
                raise _snapshot_invalid("plan_id must be a string")

            raw_assignments = item.get("assignments", ())
            raw_conflicts = item.get("conflicts", ())
            raw_degradations = item.get("degradations", ())
            if not isinstance(raw_assignments, (list, tuple)):
                raise _snapshot_invalid("plan assignments must be a sequence")
            if not isinstance(raw_conflicts, (list, tuple)):
                raise _snapshot_invalid("plan conflicts must be a sequence")
            if not isinstance(raw_degradations, (list, tuple)):
                raise _snapshot_invalid("degradations must be a sequence")

            assignments = tuple(
                _decode_assignment(record) for record in raw_assignments
            )
            conflicts = tuple(_decode_conflict(record) for record in raw_conflicts)
            degradations: list[tuple[str, str]] = []
            for degradation in raw_degradations:
                if (
                    not isinstance(degradation, (list, tuple))
                    or len(degradation) != 2
                    or not all(isinstance(part, str) for part in degradation)
                ):
                    raise _snapshot_invalid("invalid degradation record")
                degradations.append((degradation[0], degradation[1]))

            plan = Plan(
                plan_id=plan_id,
                assignments=assignments,
                conflicts=conflicts,
                degradations=tuple(degradations),
            )
        else:
            raise _snapshot_invalid("plan record must be a dict")

        if plan.plan_id in plans:
            raise _snapshot_invalid("duplicate plan in snapshot")
        plans[plan.plan_id] = plan
    return plans


def _decode_assignment(value: object) -> Assignment:
    assignment = _dataclass_record(Assignment, value)
    required_strings = (
        "slot_id",
        "region",
        "requested_region",
        "segment_id",
    )
    if any(
        not isinstance(getattr(assignment, key), str) for key in required_strings
    ):
        raise _snapshot_invalid(
            "assignment id and region fields must be strings"
        )
    _validate_interval(assignment.start, assignment.end)
    if not _is_real_number(assignment.fade_origin):
        raise _snapshot_invalid("fade_origin must be a number")
    if not isinstance(assignment.continued, bool):
        raise _snapshot_invalid("continued must be a boolean")
    _validate_priority(assignment.priority)
    if not _valid_opacity(assignment.opacity):
        raise _snapshot_invalid("invalid assignment opacity")
    _validate_fade_in(assignment.fade_in)
    return assignment


def _decode_conflict(value: object) -> Conflict:
    conflict = _dataclass_record(Conflict, value)
    if not all(
        isinstance(getattr(conflict, key), str)
        for key in ("slot_id", "other_slot_id", "region")
    ):
        raise _snapshot_invalid("conflict id and region fields must be strings")
    _validate_interval(conflict.start, conflict.end)
    return conflict
