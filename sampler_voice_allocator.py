"""Sampler voice allocation with priority stealing, groups and release stages."""

from __future__ import annotations

import threading
from dataclasses import dataclass

MAX_POLYPHONY = 64


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


class VoiceAllocator:
    """Allocate, steal and release sampler voices under a polyphony ceiling."""

    def __init__(self, *, polyphony: int = 8) -> None:
        self.polyphony = polyphony
        self._lock = threading.RLock()

    def note_on(self, note, *, sample_id="default", velocity=100,
                group=None, priority=None):
        raise NotImplementedError

    def note_off(self, note):
        raise NotImplementedError

    def set_polyphony(self, n):
        raise NotImplementedError

    def set_priority(self, sample_id, priority):
        raise NotImplementedError

    def set_sample_limit(self, sample_id, limit):
        raise NotImplementedError

    def set_sustain(self, on):
        raise NotImplementedError

    def steal(self, note):
        raise NotImplementedError

    def panic(self):
        raise NotImplementedError

    def active_voices(self):
        raise NotImplementedError

    def group_voices(self, group):
        raise NotImplementedError

    def voice_count(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
