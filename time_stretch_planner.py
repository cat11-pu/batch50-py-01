"""Time-stretch planning for pitch-preserving audio clip rendering.

The planner registers audio clips, derives analysis and synthesis frame
hops from a stretch ratio, walks the clip frame by frame while searching an
alignment offset inside a bounded window, records every overlap-add seam and
keeps enough state to resume after a restart.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "TimeStretchError",
    "ClipSpec",
    "FramePlan",
    "StretchFrame",
    "TimeStretchPlanner",
]


class TimeStretchError(ValueError):
    """Raised when the planner refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ClipSpec:
    """Registered audio clip with its stretch parameters."""

    clip_id: str
    sample_rate: int
    channels: int
    source_samples: int
    target_ratio: float
    search_window: int
    overlap: int


@dataclass(frozen=True)
class FramePlan:
    """Hop arithmetic derived from one clip and one stretch ratio."""

    clip_id: str
    ratio: float
    analysis_hop: int
    synthesis_hop: int
    frame_count: int
    output_samples: int
    search_window: int
    overlap: int


@dataclass(frozen=True)
class StretchFrame:
    """One rendered frame after alignment search and overlap-add."""

    clip_id: str
    index: int
    source_offset: int
    output_offset: int
    offset: int
    seam: bool


class TimeStretchPlanner:
    """Plan and render frame-aligned time stretching for audio clips."""

    def __init__(self, *, frame_size: int = 1024, max_search_window: int = 512,
                 max_overlap: int = 256, max_clips: int = 64) -> None:
        self.frame_size = frame_size
        self.max_search_window = max_search_window
        self.max_overlap = max_overlap
        self.max_clips = max_clips
        self._lock = threading.RLock()

    def register_clip(self, clip_id: str, sample_rate: int, channels: int,
                      source_samples: int, *, target_ratio: float = 1.0,
                      search_window: int | None = None,
                      overlap: int | None = None) -> ClipSpec:
        """Register a clip with its sample rate, channel count and ratio."""
        raise NotImplementedError

    def plan_stretch(self, clip_id: str,
                     target_ratio: float | None = None) -> FramePlan:
        """Derive analysis hop, synthesis hop and frame count for a clip."""
        raise NotImplementedError

    def next_frame(self, clip_id: str) -> StretchFrame:
        """Render and return the next frame of a planned clip."""
        raise NotImplementedError

    def drain(self, clip_id: str, limit: int) -> tuple[StretchFrame, ...]:
        """Return at most *limit* pending frames for a clip."""
        raise NotImplementedError

    def pending(self, clip_id: str) -> int:
        """Return how many frames of a planned clip are still unrendered."""
        raise NotImplementedError

    def rendered_samples(self, clip_id: str) -> int:
        """Return how many output samples were already produced."""
        raise NotImplementedError

    def seam_count(self, clip_id: str) -> int:
        """Return how many overlap-add seams were recorded for a clip."""
        raise NotImplementedError

    def cancel(self, clip_id: str) -> int:
        """Cancel a clip and return the samples produced so far."""
        raise NotImplementedError

    def clip_of(self, clip_id: str) -> ClipSpec:
        """Return the registered specification of one clip."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative planner counters."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a deep copy of clips, plans and rendering progress."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace planner state from a snapshot, validating its structure."""
        raise NotImplementedError
