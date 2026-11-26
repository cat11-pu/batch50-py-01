"""Voice pool allocation with priority stealing and virtual voice recovery.

The allocator hands out a fixed number of simultaneous audio voices.  Every
request names a source, a priority and a listener distance; when the pool is
full the weakest live voice is compared against the newcomer and, if the
newcomer is stronger, the weakest voice is cut immediately and remembered in
the virtual queue so it can be restored on a later frame.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass

__all__ = [
    "VoiceError",
    "VoiceSlot",
    "VirtualVoice",
    "VoiceStealingAllocator",
]


class VoiceError(ValueError):
    """Raised when a voice pool operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class VoiceSlot:
    """Immutable view of one voice occupying a pool slot."""

    voice_id: str
    source_id: str
    priority: int
    distance: float
    started_frame: int
    last_used_frame: int
    state: str


@dataclass(frozen=True)
class VirtualVoice:
    """A voice that lost its slot and waits for a free one."""

    entry_id: str
    source_id: str
    priority: int
    distance: float
    requested_frame: int
    reason: str


class VoiceStealingAllocator:
    """Allocate, steal and recover audio voices inside one mixer frame."""

    def __init__(self, *, capacity: int = 24, fade_frames: int = 2,
                 virtual_timeout: int = 120) -> None:
        if not self._is_int(capacity) or capacity < 1:
            raise VoiceError("AUDIO_VOICE_INVALID", "capacity must be >= 1")
        if not self._is_int(fade_frames) or fade_frames < 0:
            raise VoiceError("AUDIO_VOICE_INVALID", "fade_frames must be >= 0")
        if not self._is_int(virtual_timeout) or virtual_timeout < 0:
            raise VoiceError("AUDIO_VOICE_INVALID",
                             "virtual_timeout must be >= 0")
        self.capacity = capacity
        self.fade_frames = fade_frames
        self.virtual_timeout = virtual_timeout
        self._lock = threading.RLock()
        self._frame = 0
        self._voices: dict[str, _Voice] = {}
        self._virtual: list[_Virtual] = []
        self._next_voice = 1
        self._next_virtual = 1
        self._stats = {
            "requests": 0,
            "duplicates": 0,
            "refused": 0,
            "steals": 0,
            "evictions": 0,
            "recovered": 0,
            "expired": 0,
        }

    def request_voice(self, source_id: str, *, priority: int = 0,
                      distance: float = 0.0, frame: int | None = None):
        """Ask for a voice for *source_id*; return the slot or ``None``."""
        with self._lock:
            source = self._validate_source(source_id)
            priority = self._validate_priority(priority)
            distance = self._validate_distance(distance)
            current = self._resolve_frame(frame)
            self._stats["requests"] += 1

            existing = self._voice_for_source(source)
            if existing is not None:
                existing.last_used_frame = current
                self._stats["duplicates"] += 1
                return self._view(existing)

            if len(self._voices) < self.capacity:
                return self._view(
                    self._allocate(source, priority, distance, current))

            victim = self._weakest_live()
            if victim is not None and self._is_stronger(
                    priority, distance, victim.priority, victim.distance):
                self._make_virtual(victim, "stolen")
                self._stats["steals"] += 1
                return self._view(
                    self._allocate(source, priority, distance, current))

            self._stats["refused"] += 1
            return None

    def touch(self, source_id: str, *, frame: int | None = None) -> VoiceSlot:
        """Mark *source_id* as still audible so its age is refreshed."""
        with self._lock:
            source = self._validate_source(source_id)
            current = self._resolve_frame(frame)
            voice = self._voice_for_source(source)
            if voice is None:
                raise VoiceError("AUDIO_UNKNOWN_VOICE", source)
            voice.last_used_frame = current
            return self._view(voice)

    def release(self, voice_id: str) -> None:
        """Start the fade-out of *voice_id* and free it after the fade."""
        with self._lock:
            if not isinstance(voice_id, str):
                raise VoiceError("AUDIO_UNKNOWN_VOICE", voice_id)
            voice = self._voices.get(voice_id)
            if voice is None or voice.state != "live":
                raise VoiceError("AUDIO_UNKNOWN_VOICE", voice_id)
            voice.state = "fading"
            voice.fade_remaining = self.fade_frames

    def preempt(self, voice_id: str, *, reason: str = "manual") -> VirtualVoice:
        """Cut *voice_id* immediately and queue it for a later restore."""
        with self._lock:
            if not isinstance(reason, str):
                raise VoiceError("AUDIO_VOICE_INVALID",
                                 "reason must be a string")
            if not isinstance(voice_id, str):
                raise VoiceError("AUDIO_UNKNOWN_VOICE", voice_id)
            voice = self._voices.get(voice_id)
            if voice is None:
                raise VoiceError("AUDIO_UNKNOWN_VOICE", voice_id)
            entry = self._make_virtual(voice, reason)
            self._stats["steals"] += 1
            return entry

    def tick(self, *, frames: int = 1) -> dict:
        """Advance the mixer clock, expire fades and restore queued voices."""
        with self._lock:
            if not self._is_int(frames) or frames < 0:
                raise VoiceError("AUDIO_VOICE_INVALID",
                                 "frames must be a non-negative integer")
            recovered: list[str] = []
            expired = 0
            for _ in range(frames):
                self._frame += 1
                expired += self._expire_virtual()
                self._advance_fades()
                recovered.extend(self._recover_virtual())
            return {
                "frame": self._frame,
                "recovered": recovered,
                "expired": expired,
            }

    def virtual_queue(self) -> tuple[VirtualVoice, ...]:
        """Return the queued voices in recovery order."""
        with self._lock:
            return tuple(entry.view() for entry in self._sorted_virtual())

    def voice_of(self, source_id: str) -> VoiceSlot | None:
        """Return the slot currently held by *source_id*, if any."""
        if not isinstance(source_id, str):
            return None
        source = source_id.strip()
        if not source:
            return None
        with self._lock:
            voice = self._voice_for_source(source)
            return None if voice is None else self._view(voice)

    def voices(self, *, state: str | None = None) -> tuple[VoiceSlot, ...]:
        """Return the pool contents ordered by priority then source id."""
        with self._lock:
            return tuple(
                self._view(voice) for voice in self._sorted_voices()
                if state is None or voice.state == state
            )

    def set_capacity(self, capacity: int) -> int:
        """Resize the pool, evicting the weakest voices when shrinking."""
        with self._lock:
            if not self._is_int(capacity) or capacity < 1:
                raise VoiceError("AUDIO_VOICE_INVALID",
                                 "capacity must be >= 1")

            overflow = len(self._voices) - capacity
            self.capacity = capacity
            if overflow <= 0:
                return capacity

            live = sorted(
                (voice for voice in self._voices.values()
                 if voice.state == "live"),
                key=self._weakest_key,
            )
            for voice in live:
                if overflow <= 0:
                    break
                self._make_virtual(voice, "evicted")
                self._stats["evictions"] += 1
                overflow -= 1

            if overflow > 0:
                fading = sorted(
                    (voice for voice in self._voices.values()
                     if voice.state == "fading"),
                    key=self._weakest_key,
                )
                for voice in fading:
                    if overflow <= 0:
                        break
                    del self._voices[voice.voice_id]
                    overflow -= 1
            return capacity

    def free_slots(self) -> int:
        """Return how many voices may still start this frame."""
        with self._lock:
            return self.capacity - len(self._voices)

    def snapshot(self) -> dict:
        """Return a detached snapshot of the allocator state."""
        with self._lock:
            snapshot = _Snapshot({
                "version": 1,
                "capacity": self.capacity,
                "frame": self._frame,
                "voices": [
                    {
                        "voice_id": voice.voice_id,
                        "source_id": voice.source_id,
                        "priority": voice.priority,
                        "distance": voice.distance,
                        "started_frame": voice.started_frame,
                        "last_used_frame": voice.last_used_frame,
                        "state": voice.state,
                        "fade_remaining": voice.fade_remaining,
                        "requested_frame": voice.requested_frame,
                    }
                    for voice in self._sorted_voices()
                ],
                "virtual": [
                    self._snapshot_virtual_entry(entry)
                    for entry in self._sorted_virtual()
                ],
                "stats": dict(self._stats),
            })
            snapshot._next_voice = self._next_voice
            snapshot._next_virtual = self._next_virtual
            return snapshot

    @staticmethod
    def _snapshot_virtual_entry(entry: _Virtual) -> dict:
        item = _SnapshotEntry({
            "entry_id": entry.entry_id,
            "source_id": entry.source_id,
            "priority": entry.priority,
            "distance": entry.distance,
            "requested_frame": entry.requested_frame,
            "reason": entry.reason,
        })
        item._queued_frame = entry.queued_frame
        return item

    def restore(self, state: dict) -> None:
        """Replace the allocator state with a previously taken snapshot."""
        with self._lock:
            restored = self._parse_snapshot(state)
            (self.capacity, self._frame, self._voices, self._virtual,
             self._stats, self._next_voice,
             self._next_virtual) = restored

    def stats(self) -> dict:
        """Return the request, steal, eviction and recovery counters."""
        with self._lock:
            return dict(self._stats)

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _validate_source(cls, source_id: object) -> str:
        if not isinstance(source_id, str):
            raise VoiceError("AUDIO_VOICE_INVALID",
                             "source_id must be a string")
        source = source_id.strip()
        if not source:
            raise VoiceError("AUDIO_VOICE_INVALID",
                             "source_id must not be empty")
        return source

    @classmethod
    def _validate_priority(cls, priority: object) -> int:
        if not cls._is_int(priority) or not 0 <= priority <= 15:
            raise VoiceError("AUDIO_VOICE_INVALID",
                             "priority must be an integer from 0 to 15")
        return priority

    @classmethod
    def _validate_distance(cls, distance: object) -> float:
        if (isinstance(distance, bool)
                or not isinstance(distance, (int, float))):
            raise VoiceError("AUDIO_VOICE_INVALID",
                             "distance must be a number")
        value = float(distance)
        if math.isnan(value) or value < 0:
            raise VoiceError("AUDIO_VOICE_INVALID",
                             "distance must not be negative")
        return value

    @classmethod
    def _validate_frame(cls, frame: object) -> int:
        if not cls._is_int(frame) or frame < 0:
            raise VoiceError("AUDIO_VOICE_INVALID",
                             "frame must be a non-negative integer")
        return frame

    def _resolve_frame(self, frame: int | None) -> int:
        if frame is None:
            return self._frame
        value = self._validate_frame(frame)
        if value > self._frame:
            self._frame = value
        return value

    def _allocate(self, source: str, priority: int, distance: float,
                  frame: int,
                  requested_frame: int | None = None) -> _Voice:
        voice_id = f"voice-{self._next_voice:04d}"
        self._next_voice += 1
        voice = _Voice(
            voice_id=voice_id,
            source_id=source,
            priority=priority,
            distance=distance,
            started_frame=frame,
            last_used_frame=frame,
            state="live",
            fade_remaining=0,
            requested_frame=(
                frame if requested_frame is None else requested_frame),
        )
        self._voices[voice_id] = voice
        return voice

    def _make_virtual(self, voice: _Voice, reason: str) -> VirtualVoice:
        entry = _Virtual(
            entry_id=f"virtual-{self._next_virtual:04d}",
            source_id=voice.source_id,
            priority=voice.priority,
            distance=voice.distance,
            requested_frame=voice.requested_frame,
            reason=reason,
            queued_frame=self._frame,
        )
        self._next_virtual += 1
        del self._voices[voice.voice_id]
        self._virtual.append(entry)
        return entry.view()

    def _voice_for_source(self, source: str) -> _Voice | None:
        for voice in self._voices.values():
            if voice.source_id == source:
                return voice
        return None

    def _weakest_live(self) -> _Voice | None:
        live = (voice for voice in self._voices.values()
                if voice.state == "live")
        return min(live, key=self._weakest_key, default=None)

    @staticmethod
    def _weakest_key(voice: _Voice):
        return (voice.priority, -voice.distance, voice.last_used_frame,
                voice.started_frame,
                VoiceStealingAllocator._numeric_suffix(voice.voice_id))

    @staticmethod
    def _is_stronger(priority: int, distance: float,
                     other_priority: int, other_distance: float) -> bool:
        if priority != other_priority:
            return priority > other_priority
        return distance < other_distance

    @staticmethod
    def _view(voice: _Voice) -> VoiceSlot:
        return VoiceSlot(
            voice_id=voice.voice_id,
            source_id=voice.source_id,
            priority=voice.priority,
            distance=voice.distance,
            started_frame=voice.started_frame,
            last_used_frame=voice.last_used_frame,
            state=voice.state,
        )

    def _sorted_voices(self) -> list[_Voice]:
        return sorted(self._voices.values(),
                      key=lambda voice: (voice.priority, voice.source_id))

    def _sorted_virtual(self) -> list[_Virtual]:
        return sorted(
            self._virtual,
            key=lambda entry: (-entry.priority, entry.distance,
                               entry.requested_frame,
                               self._numeric_suffix(entry.entry_id)),
        )

    def _expire_virtual(self) -> int:
        kept: list[_Virtual] = []
        expired = 0
        for entry in self._virtual:
            if self._frame - entry.queued_frame > self.virtual_timeout:
                expired += 1
            else:
                kept.append(entry)
        self._virtual = kept
        self._stats["expired"] += expired
        return expired

    def _advance_fades(self) -> None:
        for voice_id, voice in list(self._voices.items()):
            if voice.state != "fading":
                continue
            voice.fade_remaining -= 1
            if voice.fade_remaining <= 0:
                del self._voices[voice_id]

    def _recover_virtual(self) -> list[str]:
        recovered: list[str] = []
        free = self.capacity - len(self._voices)
        if free <= 0:
            return recovered

        remaining = list(self._virtual)
        for entry in self._sorted_virtual():
            if free <= 0:
                break
            if self._voice_for_source(entry.source_id) is not None:
                continue
            remaining.remove(entry)
            voice = self._allocate(
                entry.source_id, entry.priority, entry.distance, self._frame,
                requested_frame=entry.requested_frame)
            recovered.append(voice.voice_id)
            self._stats["recovered"] += 1
            free -= 1
        self._virtual = remaining
        return recovered

    @classmethod
    def _parse_snapshot(cls, state: object):
        def invalid(detail: str):
            raise VoiceError("AUDIO_VOICE_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict):
            invalid("snapshot must be a mapping")
        required = {"version", "capacity", "frame", "voices", "virtual",
                    "stats"}
        if not required.issubset(state):
            invalid("snapshot is missing required fields")

        version = state["version"]
        if not cls._is_int(version) or version != 1:
            invalid("unsupported snapshot version")

        capacity = state["capacity"]
        if not cls._is_int(capacity) or capacity < 1:
            invalid("capacity must be a positive integer")

        frame = state["frame"]
        if not cls._is_int(frame) or frame < 0:
            invalid("frame must be a non-negative integer")

        raw_voices = state["voices"]
        raw_virtual = state["virtual"]
        raw_stats = state["stats"]
        if not isinstance(raw_voices, (list, tuple)):
            invalid("voices must be a sequence")
        if not isinstance(raw_virtual, (list, tuple)):
            invalid("virtual must be a sequence")
        if not isinstance(raw_stats, dict):
            invalid("stats must be a mapping")
        if len(raw_voices) > capacity:
            invalid("voices exceed capacity")

        stats = {}
        for key in cls._STAT_KEYS:
            if key not in raw_stats:
                invalid(f"missing stat {key}")
            value = raw_stats[key]
            if not cls._is_int(value) or value < 0:
                invalid(f"stat {key} must be a non-negative integer")
            stats[key] = value

        voices: dict[str, _Voice] = {}
        sources: set[str] = set()
        for item in raw_voices:
            if not isinstance(item, dict):
                invalid("voice entries must be mappings")
            try:
                voice_id = item["voice_id"]
                source = item["source_id"]
                priority = item["priority"]
                distance = item["distance"]
                started = item["started_frame"]
                last_used = item["last_used_frame"]
                voice_state = item["state"]
                fade_remaining = item["fade_remaining"]
            except KeyError as exc:
                invalid(f"voice entry is missing {exc.args[0]}")
            if not isinstance(voice_id, str) or not voice_id:
                invalid("voice_id must be a non-empty string")
            if not isinstance(source, str) or not source.strip():
                invalid("source_id must be a non-empty string")
            source = source.strip()
            if not cls._is_int(priority) or not 0 <= priority <= 15:
                invalid("invalid voice priority")
            try:
                distance = cls._validate_distance(distance)
            except VoiceError:
                invalid("invalid voice distance")
            if not cls._is_int(started) or started < 0:
                invalid("invalid started_frame")
            if not cls._is_int(last_used) or last_used < 0:
                invalid("invalid last_used_frame")
            if voice_state not in ("live", "fading"):
                invalid("invalid voice state")
            if not cls._is_int(fade_remaining) or fade_remaining < 0:
                invalid("invalid fade_remaining")
            requested = item.get("requested_frame", started)
            if not cls._is_int(requested) or requested < 0:
                invalid("invalid requested_frame")
            if voice_id in voices or source in sources:
                invalid("duplicate voice or source")
            voices[voice_id] = _Voice(
                voice_id=voice_id,
                source_id=source,
                priority=priority,
                distance=distance,
                started_frame=started,
                last_used_frame=last_used,
                state=voice_state,
                fade_remaining=fade_remaining,
                requested_frame=requested,
            )
            sources.add(source)

        virtual: list[_Virtual] = []
        entry_ids: set[str] = set()
        for item in raw_virtual:
            if not isinstance(item, dict):
                invalid("virtual entries must be mappings")
            try:
                entry_id = item["entry_id"]
                source = item["source_id"]
                priority = item["priority"]
                distance = item["distance"]
                requested = item["requested_frame"]
                reason = item["reason"]
            except KeyError as exc:
                invalid(f"virtual entry is missing {exc.args[0]}")
            if not isinstance(entry_id, str) or not entry_id:
                invalid("entry_id must be a non-empty string")
            if entry_id in entry_ids:
                invalid("duplicate virtual entry id")
            if not isinstance(source, str) or not source.strip():
                invalid("source_id must be a non-empty string")
            source = source.strip()
            if not cls._is_int(priority) or not 0 <= priority <= 15:
                invalid("invalid virtual priority")
            try:
                distance = cls._validate_distance(distance)
            except VoiceError:
                invalid("invalid virtual distance")
            if not cls._is_int(requested) or requested < 0:
                invalid("invalid requested_frame")
            if not isinstance(reason, str):
                invalid("reason must be a string")
            queued = getattr(item, "_queued_frame", None)
            if queued is None:
                queued = item.get("queued_frame", requested)
            if not cls._is_int(queued) or queued < 0:
                invalid("invalid queued_frame")
            entry_ids.add(entry_id)
            virtual.append(_Virtual(
                entry_id=entry_id,
                source_id=source,
                priority=priority,
                distance=distance,
                requested_frame=requested,
                reason=reason,
                queued_frame=queued,
            ))

        next_voice = 1 + max(
            (cls._numeric_suffix(voice.voice_id) for voice in voices.values()),
            default=0,
        )
        next_virtual = 1 + max(
            (cls._numeric_suffix(entry.entry_id) for entry in virtual),
            default=0,
        )
        stored_voice = getattr(state, "_next_voice", None)
        if cls._is_int(stored_voice) and stored_voice >= 1:
            next_voice = max(next_voice, stored_voice)
        stored_virtual = getattr(state, "_next_virtual", None)
        if cls._is_int(stored_virtual) and stored_virtual >= 1:
            next_virtual = max(next_virtual, stored_virtual)
        return capacity, frame, voices, virtual, stats, next_voice, next_virtual

    _STAT_KEYS = ("requests", "duplicates", "refused", "steals",
                  "evictions", "recovered", "expired")

    @staticmethod
    def _numeric_suffix(identifier: str) -> int:
        prefix, separator, suffix = identifier.rpartition("-")
        if not separator or not suffix.isdigit():
            return 0
        return int(suffix)


@dataclass
class _Voice:
    voice_id: str
    source_id: str
    priority: int
    distance: float
    started_frame: int
    last_used_frame: int
    state: str
    fade_remaining: int
    requested_frame: int


@dataclass
class _Virtual:
    entry_id: str
    source_id: str
    priority: int
    distance: float
    requested_frame: int
    reason: str
    queued_frame: int

    def view(self) -> VirtualVoice:
        return VirtualVoice(
            entry_id=self.entry_id,
            source_id=self.source_id,
            priority=self.priority,
            distance=self.distance,
            requested_frame=self.requested_frame,
            reason=self.reason,
        )


class _Snapshot(dict):
    pass


class _SnapshotEntry(dict):
    pass
