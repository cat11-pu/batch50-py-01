"""Camera path smoothing and crop window keyframes for video stabilization.

The planner ingests per frame camera motion, smooths the accumulated path
inside a bounded window, derives a crop window for every frame, compresses
the crop track into keyframes and keeps a commit watermark so a restarted
process resumes from the last committed keyframe.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "StabilizationError",
    "ClipSpec",
    "MotionSample",
    "CropWindow",
    "CropKeyframe",
    "StabilizationPlanner",
]


class StabilizationError(ValueError):
    """Raised when the planner refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ClipSpec:
    """Registered video clip and its stabilization parameters."""

    clip_id: str
    width: int
    height: int
    fps: int
    smooth_radius: int
    sample_count: int
    rolling_shutter: int


@dataclass(frozen=True)
class MotionSample:
    """One camera motion estimate between two frames."""

    index: int
    dx: float
    dy: float
    confidence: float


@dataclass(frozen=True)
class CropWindow:
    """One crop rectangle inside the source frame."""

    x: int
    y: int
    width: int
    height: int


@dataclass(frozen=True)
class CropKeyframe:
    """One keyframe of the compressed crop track."""

    index: int
    crop: CropWindow


class StabilizationPlanner:
    """Plan crop windows from a smoothed camera path."""

    def __init__(self, *, smooth_radius: int = 8, max_samples: int = 4096,
                 min_confidence: float = 0.3,
                 max_scale: float = 1.25) -> None:
        self.smooth_radius = smooth_radius
        self.max_samples = max_samples
        self.min_confidence = min_confidence
        self.max_scale = max_scale
        self._lock = threading.RLock()

    def register_clip(self, clip_id: str, width: int, height: int, *,
                      fps: int = 60,
                      smooth_radius: int | None = None) -> ClipSpec:
        """Register a video clip with its frame size and smoothing radius."""
        raise NotImplementedError

    def ingest_motion(self, clip_id: str,
                      samples: list[tuple[float, float, float]]) -> int:
        """Append per frame motion samples and return the accepted count."""
        raise NotImplementedError

    def set_rolling_shutter(self, clip_id: str, skew_lines: int) -> int:
        """Set the rolling shutter skew of a clip in lines."""
        raise NotImplementedError

    def smooth_path(self, clip_id: str,
                    radius: int | None = None) -> tuple[tuple[float, float], ...]:
        """Return the smoothed camera path of a clip."""
        raise NotImplementedError

    def plan_crop(self, clip_id: str, out_width: int,
                  out_height: int) -> tuple[CropWindow, ...]:
        """Return one crop window per frame for the requested output size."""
        raise NotImplementedError

    def keyframe_crop(self, clip_id: str,
                      interval: int) -> tuple[CropKeyframe, ...]:
        """Compress the crop track into keyframes every *interval* frames."""
        raise NotImplementedError

    def validate_bounds(self, clip_id: str, crop: CropWindow) -> bool:
        """Return whether a crop window stays inside the source frame."""
        raise NotImplementedError

    def committed_keyframes(self, clip_id: str) -> int:
        """Return how many keyframes are already committed."""
        raise NotImplementedError

    def commit(self, clip_id: str, upto_index: int) -> int:
        """Advance the commit watermark of a clip and return it."""
        raise NotImplementedError

    def clip_of(self, clip_id: str) -> ClipSpec:
        """Return the registered specification of one clip."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative planner counters."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a deep copy of clips, motion, crop tracks and watermarks."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace planner state from a snapshot, validating its structure."""
        raise NotImplementedError
