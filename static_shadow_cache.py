"""Static shadow map cache with per-frame slot reuse."""

from __future__ import annotations

import math
import threading
from collections.abc import Sequence
from dataclasses import dataclass
from numbers import Real

__all__ = [
    "ShadowCacheError",
    "ObjectRecord",
    "SlotRender",
    "SlotInfo",
    "StaticShadowCache",
    "INVALIDATION_REASONS",
]

INVALIDATION_REASONS = ("transform", "material", "lod")

_SNAPSHOT_VERSION = 1
_SNAPSHOT_KEYS = {
    "version",
    "capacity",
    "frame",
    "objects",
    "slots",
    "entries",
    "counters",
    "use_seq",
}
_COUNTER_KEYS = ("renders", "reuse_hits", "invalidations", "evictions")


class ShadowCacheError(ValueError):
    """Raised when a shadow-cache request is rejected."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ObjectRecord:
    object_id: str
    transform: tuple[float, float, float]
    material: str
    lod: int


@dataclass(frozen=True)
class SlotRender:
    object_id: str
    slot: int
    frame: int
    generation: int
    payload: dict
    rendered: bool


@dataclass(frozen=True)
class SlotInfo:
    object_id: str
    slot: int | None
    dirty: bool
    generation: int
    last_frame: int
    uses: int
    rendered: bool


@dataclass
class _Entry:
    transform: tuple[float, float, float]
    material: str
    lod: int
    slot: int | None = None
    dirty: bool = False
    generation: int = 0
    last_frame: int = 0
    uses: int = 0
    use_seq: int = 0
    rendered: bool = False
    blocked_slot: int | None = None
    blocked_frame: int = -1


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_capacity(value: object) -> bool:
    return _is_int(value) and value >= 1


def _finite_number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, Real):
        return None
    try:
        result = float(value)
    except (OverflowError, TypeError, ValueError):
        return None
    return result if math.isfinite(result) else None


def _is_transform(value: object) -> bool:
    return (
        isinstance(value, Sequence)
        and not isinstance(value, (str, bytes, bytearray))
        and len(value) == 3
    )


class StaticShadowCache:
    """Reuse the shadow maps of static objects across frames."""

    def __init__(self, *, capacity: int = 4) -> None:
        if not _valid_capacity(capacity):
            raise ShadowCacheError("SHADOW_INVALID_CAPACITY", capacity)
        self.capacity = capacity
        self._lock = threading.RLock()
        self._frame = 0
        self._entries: dict[str, _Entry] = {}
        self._slots: dict[int, str] = {}
        self._counters = {name: 0 for name in _COUNTER_KEYS}
        self._use_seq = 0

    def register(self, object_id: str, *, transform=(0.0, 0.0, 0.0),
                 material: str = "default", lod: int = 0) -> ObjectRecord:
        with self._lock:
            if not isinstance(object_id, str) or not object_id.strip():
                raise ShadowCacheError("SHADOW_INVALID_INPUT", object_id)
            if object_id in self._entries:
                raise ShadowCacheError("SHADOW_INVALID_INPUT", object_id)

            if not _is_transform(transform):
                raise ShadowCacheError("SHADOW_INVALID_INPUT", transform)
            normalized_transform = tuple(_finite_number(v) for v in transform)
            if any(v is None for v in normalized_transform):
                raise ShadowCacheError("SHADOW_INVALID_INPUT", transform)

            if not isinstance(material, str) or not material.strip():
                raise ShadowCacheError("SHADOW_INVALID_INPUT", material)
            if not _is_int(lod) or lod < 0:
                raise ShadowCacheError("SHADOW_INVALID_INPUT", lod)

            entry = _Entry(
                transform=normalized_transform,
                material=material,
                lod=lod,
            )
            self._entries[object_id] = entry
            return ObjectRecord(
                object_id=object_id,
                transform=entry.transform,
                material=entry.material,
                lod=entry.lod,
            )

    def tick(self) -> int:
        with self._lock:
            self._frame += 1
            for entry in self._entries.values():
                if entry.blocked_frame < self._frame:
                    entry.blocked_slot = None
                    entry.blocked_frame = -1
            return self._frame

    def acquire_slot(self, object_id: str) -> int:
        with self._lock:
            entry = self._entry(object_id)
            slot = self._ensure_slot(object_id, entry)
            self._record_use(entry)
            return slot

    def release_slot(self, object_id: str) -> bool:
        with self._lock:
            entry = self._entry(object_id)
            if entry.slot is None:
                return False
            self._slots.pop(entry.slot, None)
            entry.slot = None
            entry.dirty = True
            entry.rendered = False
            return True

    def refresh(self, object_id: str) -> SlotRender:
        with self._lock:
            entry = self._entry(object_id)
            slot = self._ensure_slot(object_id, entry)
            self._record_use(entry)

            if entry.dirty or entry.generation == 0:
                entry.generation += 1
                entry.dirty = False
                entry.rendered = True
                rendered = True
                self._counters["renders"] += 1
            else:
                entry.rendered = False
                rendered = False
                self._counters["reuse_hits"] += 1

            payload = {
                "object": object_id,
                "transform": entry.transform,
                "material": entry.material,
                "lod": entry.lod,
                "generation": entry.generation,
            }
            return SlotRender(
                object_id=object_id,
                slot=slot,
                frame=self._frame,
                generation=entry.generation,
                payload=payload,
                rendered=rendered,
            )

    def invalidate(self, object_id: str, reason: str = "transform") -> bool:
        with self._lock:
            entry = self._entry(object_id)
            if reason not in INVALIDATION_REASONS:
                raise ShadowCacheError("SHADOW_INVALID_INPUT", reason)
            self._counters["invalidations"] += 1
            if entry.dirty:
                return False
            entry.dirty = True
            return True

    def lookup(self, object_id: str) -> SlotInfo:
        with self._lock:
            entry = self._entry(object_id)
            return SlotInfo(
                object_id=object_id,
                slot=entry.slot,
                dirty=entry.dirty,
                generation=entry.generation,
                last_frame=entry.last_frame,
                uses=entry.uses,
                rendered=entry.rendered,
            )

    def resize(self, capacity: int) -> int:
        with self._lock:
            if not _valid_capacity(capacity):
                raise ShadowCacheError("SHADOW_INVALID_CAPACITY", capacity)
            if capacity == self.capacity:
                return 0
            if capacity > self.capacity:
                self.capacity = capacity
                return 0

            in_use = sum(
                1 for entry in self._entries.values()
                if entry.slot is not None and entry.last_frame == self._frame
            )
            if in_use > capacity:
                raise ShadowCacheError("SHADOW_CAPACITY_EXCEEDED", capacity)

            remove_count = max(0, len(self._slots) - capacity)
            victims = self._eviction_candidates()[:remove_count]
            for object_id, entry in victims:
                self._evict(object_id, entry)
            self.capacity = capacity
            return len(victims)

    def stats(self) -> dict:
        with self._lock:
            return {
                "frame": self._frame,
                "capacity": self.capacity,
                "objects": len(self._entries),
                "slotted": len(self._slots),
                "renders": self._counters["renders"],
                "evictions": self._counters["evictions"],
                "invalidations": self._counters["invalidations"],
                "reuse_hits": self._counters["reuse_hits"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            objects = {
                object_id: {
                    "object_id": object_id,
                    "transform": list(entry.transform),
                    "material": entry.material,
                    "lod": entry.lod,
                }
                for object_id, entry in self._entries.items()
            }
            entries = {
                object_id: {
                    "slot": entry.slot,
                    "dirty": entry.dirty,
                    "generation": entry.generation,
                    "last_frame": entry.last_frame,
                    "uses": entry.uses,
                    "rendered": entry.rendered,
                    "use_seq": entry.use_seq,
                    "blocked_slot": entry.blocked_slot,
                    "blocked_frame": entry.blocked_frame,
                }
                for object_id, entry in self._entries.items()
            }
            return {
                "version": _SNAPSHOT_VERSION,
                "capacity": self.capacity,
                "frame": self._frame,
                "objects": objects,
                "slots": dict(self._slots),
                "entries": entries,
                "counters": dict(self._counters),
                "use_seq": self._use_seq,
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._parse_snapshot(state)
            except ShadowCacheError:
                raise
            except Exception as exc:
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", exc) from exc

            capacity, frame, entries, slots, counters, use_seq = restored
            self.capacity = capacity
            self._frame = frame
            self._entries = entries
            self._slots = slots
            self._counters = counters
            self._use_seq = use_seq

    def _entry(self, object_id: str) -> _Entry:
        try:
            return self._entries[object_id]
        except (KeyError, TypeError) as exc:
            raise ShadowCacheError("SHADOW_UNKNOWN_OBJECT", object_id) from exc

    def _record_use(self, entry: _Entry) -> None:
        self._use_seq += 1
        entry.uses += 1
        entry.use_seq = self._use_seq
        entry.last_frame = self._frame

    def _is_used_this_frame(self, entry: _Entry) -> bool:
        return entry.last_frame == self._frame

    def _blocked_for_current_frame(self, entry: _Entry) -> int | None:
        if entry.blocked_slot is not None and entry.blocked_frame == self._frame:
            return entry.blocked_slot
        return None

    def _all_free_slots(self) -> list[int]:
        return [
            slot for slot in range(self.capacity)
            if slot not in self._slots
        ]

    def _free_slots(self, blocked: int | None = None) -> list[int]:
        free = self._all_free_slots()
        if blocked is not None:
            return [slot for slot in free if slot != blocked]
        return free

    def _eviction_candidates(self) -> list[tuple[str, _Entry]]:
        candidates = [
            (entry.use_seq, object_id, entry)
            for object_id, entry in self._entries.items()
            if entry.slot is not None and not self._is_used_this_frame(entry)
        ]
        candidates.sort(key=lambda item: (item[0], item[1]))
        return [(object_id, entry) for _, object_id, entry in candidates]

    def _evict(self, object_id: str, entry: _Entry) -> int | None:
        slot = entry.slot
        if slot is None:
            return None
        self._slots.pop(slot, None)
        entry.slot = None
        entry.dirty = True
        entry.rendered = False
        entry.blocked_slot = slot
        entry.blocked_frame = self._frame
        self._counters["evictions"] += 1
        return slot

    def _ensure_slot(self, object_id: str, entry: _Entry) -> int:
        if entry.slot is not None:
            return entry.slot

        blocked = self._blocked_for_current_frame(entry)
        free = self._free_slots(blocked)

        if free and len(self._slots) < self.capacity:
            return self._assign_slot(object_id, entry, free[0])

        if len(self._slots) < self.capacity:
            # Only the evicted slot is free.  Reclaim another unused slot
            # rather than handing the object its old index straight back.
            candidates = [
                (candidate_id, candidate)
                for candidate_id, candidate in self._eviction_candidates()
                if candidate.slot != blocked
            ]
            if candidates:
                victim_id, victim = candidates[0]
                self._evict(victim_id, victim)
                free = self._free_slots(blocked)
                if free:
                    return self._assign_slot(object_id, entry, free[0])
            raise ShadowCacheError("SHADOW_CAPACITY_EXCEEDED", object_id)

        candidates = self._eviction_candidates()
        if blocked is not None:
            preferred = [
                (candidate_id, candidate)
                for candidate_id, candidate in candidates
                if candidate.slot != blocked
            ]
            if preferred:
                candidates = preferred
        if not candidates:
            raise ShadowCacheError("SHADOW_CAPACITY_EXCEEDED", object_id)

        victim_id, victim = candidates[0]
        self._evict(victim_id, victim)
        free = self._free_slots(blocked)
        if not free and blocked is None:
            free = self._all_free_slots()
        if not free:
            raise ShadowCacheError("SHADOW_CAPACITY_EXCEEDED", object_id)
        return self._assign_slot(object_id, entry, free[0])

    def _assign_slot(self, object_id: str, entry: _Entry, slot: int) -> int:
        self._slots[slot] = object_id
        entry.slot = slot
        entry.rendered = False
        return slot

    def _parse_snapshot(self, state: object):
        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", state)

        version = state["version"]
        if not _is_int(version) or version != _SNAPSHOT_VERSION:
            raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", version)

        capacity = state["capacity"]
        if not _valid_capacity(capacity):
            raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", capacity)

        frame = state["frame"]
        if not _is_int(frame) or frame < 0:
            raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", frame)

        objects = state["objects"]
        raw_entries = state["entries"]
        raw_slots = state["slots"]
        counters = state["counters"]
        use_seq = state["use_seq"]
        if not isinstance(objects, dict):
            raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", objects)
        if not isinstance(raw_entries, dict):
            raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw_entries)
        if not isinstance(raw_slots, dict):
            raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw_slots)
        if not isinstance(counters, dict):
            raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", counters)
        if not _is_int(use_seq) or use_seq < 0:
            raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", use_seq)

        normalized_objects: dict[str, dict] = {}
        for object_id, raw in objects.items():
            if not isinstance(object_id, str) or not object_id.strip():
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", object_id)
            if not isinstance(raw, dict):
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw)
            stored_id = raw.get("object_id", object_id)
            if stored_id != object_id:
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw)
            transform = raw.get("transform")
            material = raw.get("material")
            lod = raw.get("lod")
            if not _is_transform(transform):
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", transform)
            normalized_transform = tuple(_finite_number(v) for v in transform)
            if any(v is None for v in normalized_transform):
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", transform)
            if not isinstance(material, str) or not material.strip():
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", material)
            if not _is_int(lod) or lod < 0:
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", lod)
            normalized_objects[object_id] = {
                "transform": normalized_transform,
                "material": material,
                "lod": lod,
            }

        if set(raw_entries) != set(normalized_objects):
            raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw_entries)

        slots: dict[int, str] = {}
        for slot, object_id in raw_slots.items():
            if not _is_int(slot) or slot < 0:
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw_slots)
            if not isinstance(object_id, str) or object_id not in normalized_objects:
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw_slots)
            if object_id in slots.values():
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw_slots)
            slots[slot] = object_id
        if len(slots) > capacity:
            raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw_slots)

        normalized_counters: dict[str, int] = {}
        for name in _COUNTER_KEYS:
            value = counters.get(name)
            if not _is_int(value) or value < 0:
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", counters)
            normalized_counters[name] = value

        entries: dict[str, _Entry] = {}
        max_use_seq = 0
        for object_id, raw in raw_entries.items():
            if not isinstance(raw, dict):
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw)
            slot = raw.get("slot")
            dirty = raw.get("dirty")
            generation = raw.get("generation")
            last_frame = raw.get("last_frame")
            uses = raw.get("uses")
            rendered = raw.get("rendered")
            entry_use_seq = raw.get("use_seq")
            blocked_slot = raw.get("blocked_slot")
            blocked_frame = raw.get("blocked_frame", -1)

            if slot is not None and (not _is_int(slot) or slot < 0):
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw)
            if not isinstance(dirty, bool) or not isinstance(rendered, bool):
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw)
            if not _is_int(generation) or generation < 0:
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw)
            if not _is_int(last_frame) or not 0 <= last_frame <= frame:
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw)
            if not _is_int(uses) or uses < 0:
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw)
            if not _is_int(entry_use_seq) or not 0 <= entry_use_seq <= use_seq:
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw)
            if blocked_slot is not None and (
                    not _is_int(blocked_slot) or blocked_slot < 0):
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw)
            if not _is_int(blocked_frame) or blocked_frame > frame:
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw)

            if slot is None:
                if object_id in slots.values():
                    raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw)
            elif slots.get(slot) != object_id:
                raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", raw)

            max_use_seq = max(max_use_seq, entry_use_seq)
            object_state = normalized_objects[object_id]
            entries[object_id] = _Entry(
                transform=object_state["transform"],
                material=object_state["material"],
                lod=object_state["lod"],
                slot=slot,
                dirty=dirty,
                generation=generation,
                last_frame=last_frame,
                uses=uses,
                use_seq=entry_use_seq,
                rendered=rendered,
                blocked_slot=blocked_slot,
                blocked_frame=blocked_frame,
            )

        if max_use_seq > use_seq:
            raise ShadowCacheError("SHADOW_SNAPSHOT_INVALID", use_seq)

        return (
            capacity,
            frame,
            entries,
            slots,
            normalized_counters,
            use_seq,
        )
