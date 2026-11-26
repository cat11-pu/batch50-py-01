"""Sampler voice allocation with priority stealing, groups and release stages."""

from __future__ import annotations

import threading
from dataclasses import dataclass

MAX_POLYPHONY = 64

_STAGE_SUSTAIN = "sustain"
_STAGE_RELEASE = "release"
_KNOWN_STAGES = (_STAGE_SUSTAIN, _STAGE_RELEASE)

_STATS_KEYS = ("note_ons", "note_offs", "steals", "panics")


class VoiceError(ValueError):
    """Raised when an allocation request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class VoiceInfo:
    """Public view of one allocated sampler voice."""

    voice_id: int
    note: int
    sample_id: str
    group: str | None
    stage: str
    priority: int


@dataclass
class _Voice:
    """Mutable internal record for one allocated voice."""

    voice_id: int
    note: int
    sample_id: str
    group: str | None
    stage: str
    priority: int

    def info(self) -> VoiceInfo:
        return VoiceInfo(
            voice_id=self.voice_id,
            note=self.note,
            sample_id=self.sample_id,
            group=self.group,
            stage=self.stage,
            priority=self.priority,
        )


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class VoiceAllocator:
    """Allocate, steal and release sampler voices under a polyphony ceiling."""

    def __init__(self, *, polyphony: int = 8) -> None:
        self._lock = threading.RLock()
        self._polyphony = self._check_polyphony(polyphony)
        self._voices: dict[int, _Voice] = {}
        self._next_voice_id = 1
        self._priorities: dict[str, int] = {}
        self._sample_limits: dict[str, int] = {}
        self._sustain = False
        self._note_ons = 0
        self._note_offs = 0
        self._steals = 0
        self._panics = 0

    @staticmethod
    def _check_polyphony(n: object) -> int:
        if not _is_int(n) or not 1 <= n <= MAX_POLYPHONY:
            raise VoiceError("INVALID_POLYPHONY", n)
        return n

    def _remove_voice(self, voice_id: int) -> None:
        # A victim still in its release tail is faded out quickly by the
        # render side instead of being hard-cut, avoiding audible clicks.
        del self._voices[voice_id]

    def _steal_victim(self, voice_id: int) -> None:
        self._remove_voice(voice_id)
        self._steals += 1

    def _global_victim(self) -> _Voice:
        # Lowest priority first; ties go to the oldest voice.
        return min(self._voices.values(), key=lambda v: (v.priority, v.voice_id))

    def note_on(self, note, *, sample_id="default", velocity=100,
                group=None, priority=None):
        if not _is_int(note) or not 0 <= note <= 127:
            raise VoiceError("INVALID_NOTE", note)
        if not _is_int(velocity) or not 1 <= velocity <= 127:
            raise VoiceError("INVALID_VELOCITY", velocity)
        if priority is not None and not _is_int(priority):
            raise VoiceError("INVALID_PRIORITY", priority)
        with self._lock:
            limit = self._sample_limits.get(sample_id)
            if limit is not None:
                used = sum(1 for v in self._voices.values()
                           if v.sample_id == sample_id)
                if used >= limit:
                    raise VoiceError("SAMPLE_LIMIT", sample_id)
            if group is not None:
                # Group exclusivity: steal the oldest voice(s) of the same
                # group first so only the new voice remains in the group.
                same_group = sorted(
                    (v for v in self._voices.values() if v.group == group),
                    key=lambda v: v.voice_id,
                )
                for victim in same_group:
                    self._steal_victim(victim.voice_id)
            while len(self._voices) + 1 > self._polyphony:
                self._steal_victim(self._global_victim().voice_id)
            voice_id = self._next_voice_id
            self._next_voice_id += 1
            effective = (priority if priority is not None
                         else self._priorities.get(sample_id, 0))
            self._voices[voice_id] = _Voice(
                voice_id=voice_id,
                note=note,
                sample_id=sample_id,
                group=group,
                stage=_STAGE_SUSTAIN,
                priority=effective,
            )
            self._note_ons += 1
            return voice_id

    def note_off(self, note):
        with self._lock:
            matches = [v for v in self._voices.values() if v.note == note]
            if not matches:
                return 0
            if self._sustain:
                # Pedal down: only mark pending release, keep the voice.
                for voice in matches:
                    voice.stage = _STAGE_RELEASE
            else:
                for voice in matches:
                    self._remove_voice(voice.voice_id)
            self._note_offs += len(matches)
            return len(matches)

    def set_polyphony(self, n):
        with self._lock:
            n = self._check_polyphony(n)
            self._polyphony = n
            while len(self._voices) > n:
                self._steal_victim(self._global_victim().voice_id)
            return n

    def set_priority(self, sample_id, priority):
        if not _is_int(priority):
            raise VoiceError("INVALID_PRIORITY", priority)
        with self._lock:
            self._priorities[sample_id] = priority

    def set_sample_limit(self, sample_id, limit):
        if not _is_int(limit) or limit < 1:
            raise VoiceError("INVALID_SAMPLE_LIMIT", limit)
        with self._lock:
            self._sample_limits[sample_id] = limit

    def set_sustain(self, on):
        with self._lock:
            self._sustain = bool(on)
            if not self._sustain:
                pending = [vid for vid, v in self._voices.items()
                           if v.stage == _STAGE_RELEASE]
                for vid in pending:
                    self._remove_voice(vid)

    def steal(self, note):
        with self._lock:
            matches = [v for v in self._voices.values() if v.note == note]
            if not matches:
                return None
            victim = min(matches, key=lambda v: v.voice_id)
            self._steal_victim(victim.voice_id)
            return victim.voice_id

    def panic(self):
        with self._lock:
            count = len(self._voices)
            self._voices.clear()
            self._panics += 1
            return count

    def active_voices(self):
        with self._lock:
            return [self._voices[vid].info() for vid in sorted(self._voices)]

    def group_voices(self, group):
        with self._lock:
            return [v for v in self.active_voices() if v.group == group]

    def voice_count(self):
        with self._lock:
            return len(self._voices)

    def snapshot(self):
        with self._lock:
            return {
                "version": 1,
                "polyphony": self._polyphony,
                "next_voice_id": self._next_voice_id,
                "sustain": self._sustain,
                "priorities": dict(self._priorities),
                "sample_limits": dict(self._sample_limits),
                "stats": {
                    "note_ons": self._note_ons,
                    "note_offs": self._note_offs,
                    "steals": self._steals,
                    "panics": self._panics,
                },
                "voices": [
                    {
                        "voice_id": v.voice_id,
                        "note": v.note,
                        "sample_id": v.sample_id,
                        "group": v.group,
                        "stage": v.stage,
                        "priority": v.priority,
                    }
                    for v in (self._voices[vid] for vid in sorted(self._voices))
                ],
            }

    def restore(self, state):
        parsed = self._parse_snapshot(state)
        with self._lock:
            (self._polyphony, self._next_voice_id, self._sustain,
             self._priorities, self._sample_limits, self._voices) = parsed[:6]
            stats = parsed[6]
            self._note_ons = stats["note_ons"]
            self._note_offs = stats["note_offs"]
            self._steals = stats["steals"]
            self._panics = stats["panics"]

    @staticmethod
    def _parse_snapshot(state):
        def invalid(detail):
            raise VoiceError("SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict) or state.get("version") != 1:
            invalid(state)
        polyphony = state.get("polyphony")
        if not _is_int(polyphony) or not 1 <= polyphony <= MAX_POLYPHONY:
            invalid(polyphony)
        next_voice_id = state.get("next_voice_id")
        if not _is_int(next_voice_id) or next_voice_id < 1:
            invalid(next_voice_id)
        sustain = state.get("sustain")
        if not isinstance(sustain, bool):
            invalid(sustain)
        priorities = state.get("priorities")
        if (not isinstance(priorities, dict)
                or any(not isinstance(k, str) or not _is_int(v)
                       for k, v in priorities.items())):
            invalid(priorities)
        sample_limits = state.get("sample_limits")
        if (not isinstance(sample_limits, dict)
                or any(not isinstance(k, str) or not _is_int(v) or v < 1
                       for k, v in sample_limits.items())):
            invalid(sample_limits)
        stats = state.get("stats")
        if (not isinstance(stats, dict)
                or any(not _is_int(stats.get(k)) or stats.get(k) < 0
                       for k in _STATS_KEYS)):
            invalid(stats)
        raw_voices = state.get("voices")
        if not isinstance(raw_voices, list):
            invalid(raw_voices)
        voices: dict[int, _Voice] = {}
        for entry in raw_voices:
            if not isinstance(entry, dict):
                invalid(entry)
            voice_id = entry.get("voice_id")
            note = entry.get("note")
            sample_id = entry.get("sample_id")
            group = entry.get("group")
            stage = entry.get("stage")
            priority = entry.get("priority")
            if (not _is_int(voice_id) or voice_id < 1
                    or voice_id in voices
                    or not _is_int(note) or not 0 <= note <= 127
                    or not isinstance(sample_id, str)
                    or not (group is None or isinstance(group, str))
                    or stage not in _KNOWN_STAGES
                    or not _is_int(priority)):
                invalid(entry)
            voices[voice_id] = _Voice(
                voice_id=voice_id,
                note=note,
                sample_id=sample_id,
                group=group,
                stage=stage,
                priority=priority,
            )
        if len(voices) > polyphony:
            invalid(raw_voices)
        if voices:
            # Never let future ids collide with voices already sounding.
            next_voice_id = max(next_voice_id, max(voices) + 1)
        return (
            polyphony,
            next_voice_id,
            sustain,
            dict(priorities),
            dict(sample_limits),
            voices,
            {k: stats[k] for k in _STATS_KEYS},
        )

    def stats(self):
        with self._lock:
            return {
                "note_ons": self._note_ons,
                "note_offs": self._note_offs,
                "steals": self._steals,
                "panics": self._panics,
                "active": len(self._voices),
                "polyphony": self._polyphony,
            }
