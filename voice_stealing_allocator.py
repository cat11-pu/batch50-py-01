"""Voice pool allocation with priority stealing and virtual voice recovery.

The allocator hands out a fixed number of simultaneous audio voices.  Every
request names a source, a priority and a listener distance; when the pool is
full the weakest live voice is compared against the newcomer and, if the
newcomer is stronger, the weakest voice is cut immediately and remembered in
the virtual queue so it can be restored on a later frame.
"""

from __future__ import annotations

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
        self.capacity = capacity
        self.fade_frames = fade_frames
        self.virtual_timeout = virtual_timeout
        self._lock = threading.RLock()

    def request_voice(self, source_id: str, *, priority: int = 0,
                      distance: float = 0.0, frame: int | None = None):
        """Ask for a voice for *source_id*; return the slot or ``None``."""
        raise NotImplementedError

    def touch(self, source_id: str, *, frame: int | None = None) -> VoiceSlot:
        """Mark *source_id* as still audible so its age is refreshed."""
        raise NotImplementedError

    def release(self, voice_id: str) -> None:
        """Start the fade-out of *voice_id* and free it after the fade."""
        raise NotImplementedError

    def preempt(self, voice_id: str, *, reason: str = "manual") -> VirtualVoice:
        """Cut *voice_id* immediately and queue it for a later restore."""
        raise NotImplementedError

    def tick(self, *, frames: int = 1) -> dict:
        """Advance the mixer clock, expire fades and restore queued voices."""
        raise NotImplementedError

    def virtual_queue(self) -> tuple[VirtualVoice, ...]:
        """Return the queued voices in recovery order."""
        raise NotImplementedError

    def voice_of(self, source_id: str) -> VoiceSlot | None:
        """Return the slot currently held by *source_id*, if any."""
        raise NotImplementedError

    def voices(self, *, state: str | None = None) -> tuple[VoiceSlot, ...]:
        """Return the pool contents ordered by priority then source id."""
        raise NotImplementedError

    def set_capacity(self, capacity: int) -> int:
        """Resize the pool, evicting the weakest voices when shrinking."""
        raise NotImplementedError

    def free_slots(self) -> int:
        """Return how many voices may still start this frame."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of the allocator state."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the allocator state with a previously taken snapshot."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the request, steal, eviction and recovery counters."""
        raise NotImplementedError
