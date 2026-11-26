"""Player audio track selection with preload window and language fallback.

Tracks are registered per language; the selector preloads a target track and
only swaps the audible track once the switch lands on a keyframe of the target
track.  Missing languages degrade along the preference, system and default
language chain.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "TrackError",
    "TrackInfo",
    "PreloadResult",
    "SwitchResult",
    "AudioTrackSelector",
]


class TrackError(ValueError):
    """Raised when a track selection operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TrackInfo:
    """One registered audio track."""

    track_id: str
    language: str
    codec: str
    channels: int
    bitrate: int
    keyframes: tuple[int, ...]


@dataclass(frozen=True)
class PreloadResult:
    """Outcome of one preload attempt."""

    status: str
    track_id: str | None
    language: str
    reason: str | None


@dataclass(frozen=True)
class SwitchResult:
    """Outcome of one switch request."""

    status: str
    track_id: str | None
    language: str | None
    position: int
    scheduled_at: int | None
    reason: str | None


class AudioTrackSelector:
    """Resolve languages to tracks, preload them and switch at keyframes."""

    def __init__(self, *, system_language: str = "zh",
                 default_language: str = "und", max_preloaded: int = 2,
                 device_codecs: tuple[str, ...] = ("aac", "opus"),
                 max_channels: int = 8) -> None:
        self.system_language = system_language
        self.default_language = default_language
        self.max_preloaded = max_preloaded
        self.device_codecs = device_codecs
        self.max_channels = max_channels
        self._lock = threading.RLock()

    def add_track(self, track_id: str, *, language: str,
                  keyframes: tuple[int, ...] = (0,), codec: str = "aac",
                  channels: int = 2, bitrate: int = 128000) -> TrackInfo:
        """Register one track of *language* with its keyframe positions."""
        raise NotImplementedError

    def set_device(self, *, codecs: tuple[str, ...] | None = None,
                   max_channels: int | None = None) -> dict:
        """Declare the decoder capabilities of the current device."""
        raise NotImplementedError

    def set_preference(self, languages) -> tuple[str, ...]:
        """Store the ordered language preference list."""
        raise NotImplementedError

    def available(self, *, language: str | None = None) -> tuple[TrackInfo, ...]:
        """Return the tracks the current device can decode."""
        raise NotImplementedError

    def preload(self, language: str) -> PreloadResult:
        """Load the best track of *language* into the preload window."""
        raise NotImplementedError

    def switch_to(self, language: str, *, position: int = 0) -> SwitchResult:
        """Switch to *language* at *position*, queueing until a keyframe."""
        raise NotImplementedError

    def advance_to(self, position: int) -> tuple[SwitchResult, ...]:
        """Advance the playback clock and apply due queued switches."""
        raise NotImplementedError

    def current(self) -> TrackInfo | None:
        """Return the audible track, if any."""
        raise NotImplementedError

    def active_tracks(self) -> tuple[TrackInfo, ...]:
        """Return the tracks currently producing sound."""
        raise NotImplementedError

    def fallback_chain(self) -> tuple[str, ...]:
        """Return the language try order used when a track is missing."""
        raise NotImplementedError

    def abort_preload(self, language: str | None = None) -> int:
        """Drop preloaded tracks; return how many were dropped."""
        raise NotImplementedError

    def abort_switch(self) -> bool:
        """Cancel a queued switch; return whether one was cancelled."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of the selector state."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the selector state with a previously taken snapshot."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the preload, switch and abort counters."""
        raise NotImplementedError
