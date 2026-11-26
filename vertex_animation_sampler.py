"""Vertex animation texture sampler.

Samples pre-baked vertex animation clips for many instances.  A clip carries a
frame count, a frame rate, a bounding box and one probe vertex position per
frame; instances carry their own local time plus a phase offset and run in
loop, once or clamp mode.  Sampling interpolates between adjacent frames and
shares per-(clip, mode, phase) state slots under a bounded cache.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "VertexAnimError",
    "ClipView",
    "InstanceView",
    "SampleResult",
    "VertexAnimationSampler",
]

MODES = ("loop", "once", "clamp")


class VertexAnimError(ValueError):
    """Raised when a clip or instance operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ClipView:
    """Immutable summary of one registered clip."""

    clip_id: str
    frames: int
    fps: float
    duration: float
    bbox: tuple[float, ...]
    has_normals: bool
    version: int
    instance_count: int


@dataclass(frozen=True)
class InstanceView:
    """Per-instance playback state."""

    instance_id: str
    clip_id: str
    mode: str
    phase: float
    time: float
    local_time: float
    finished: bool
    version: int


@dataclass(frozen=True)
class SampleResult:
    """One sample of a clip at an instance's current time."""

    instance_id: str
    clip_id: str
    mode: str
    phase: float
    frame: int
    next_frame: int
    alpha: float
    local_time: float
    finished: bool


class VertexAnimationSampler:
    """Sample baked vertex animation clips for many runtime instances."""

    def __init__(self, *, max_instances: int = 256,
                 max_state_cache: int = 128) -> None:
        self.max_instances = max_instances
        self.max_state_cache = max_state_cache
        self._lock = threading.RLock()

    def register_clip(self, clip_id: str, *, frames: int, fps: float,
                      bbox: tuple[float, ...], marker_track,
                      has_normals: bool = False, version: int = 1) -> ClipView:
        """Register a clip with its probe vertex track per frame."""
        raise NotImplementedError

    def clip_view(self, clip_id: str) -> ClipView:
        """Return the current clip metadata."""
        raise NotImplementedError

    def acquire_instance(self, instance_id: str, clip_id: str, *,
                         mode: str = "loop", phase: float = 0.0) -> InstanceView:
        """Create a playback instance bound to one clip version."""
        raise NotImplementedError

    def instance_view(self, instance_id: str) -> InstanceView:
        """Return the playback state of one instance."""
        raise NotImplementedError

    def set_phase(self, instance_id: str, phase: float) -> InstanceView:
        """Replace the phase offset of an instance."""
        raise NotImplementedError

    def advance(self, instance_id: str, delta_seconds: float) -> InstanceView:
        """Advance the instance clock by a non-negative delta."""
        raise NotImplementedError

    def sample_frame(self, instance_id: str) -> SampleResult:
        """Sample frame indices and the interpolation weight."""
        raise NotImplementedError

    def sample_position(self, instance_id: str) -> tuple[float, float, float]:
        """Sample the probe vertex position at the instance's current time."""
        raise NotImplementedError

    def release_instance(self, instance_id: str) -> InstanceView:
        """Drop an instance and free its slot."""
        raise NotImplementedError

    def cache_usage(self) -> dict:
        """Return state slot counts, limits, hits, misses and evictions."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a deep copy of clips, instances and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace sampler state with a snapshot, validating its structure."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative counters for acquires, advances and samples."""
        raise NotImplementedError
