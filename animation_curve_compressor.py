"""Error-bounded keyframe reduction for skeletal animation curves.

Each clip holds position, rotation and scale tracks.  A track is planned with
its raw keys, reduced while staying inside a per-clip error bound, quantized to
the tolerance grid and only then committed as the new version.  Loop clips have
to close their seam, and staged work never replaces the current version until
it is committed.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "CurveError",
    "ClipView",
    "TrackPlan",
    "TrackReport",
    "LoopReport",
    "AnimationCurveCompressor",
]

KINDS = ("position", "rotation", "scale")
ARITY = {"position": 3, "rotation": 4, "scale": 3}
MAX_KEYS_PER_TRACK = 4096


class CurveError(ValueError):
    """Raised when a curve operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ClipView:
    """Immutable summary of one animation clip."""

    clip_id: str
    track_count: int
    key_budget: int
    error_bound: float
    looping: bool
    version: int
    committed_tracks: int
    staged_tracks: int


@dataclass(frozen=True)
class TrackPlan:
    """One planned track with its raw keys."""

    track: str
    kind: str
    keys: tuple[tuple[int, tuple[float, ...]], ...]
    key_budget: int
    error_bound: float


@dataclass(frozen=True)
class TrackReport:
    """Outcome of compressing one track."""

    track: str
    kind: str
    input_count: int
    output_count: int
    dropped_keys: int
    max_deviation: float
    tolerance: float
    within_bound: bool
    status: str
    keys: tuple[tuple[int, tuple[float, ...]], ...]


@dataclass(frozen=True)
class LoopReport:
    """Seam check for a looping track."""

    track: str
    closure_error: float
    within_bound: bool
    seam_frame: int


class AnimationCurveCompressor:
    """Reduce animation tracks inside an error bound and commit per version."""

    def __init__(self, *, max_tracks_per_clip: int = 64, key_budget: int = 256,
                 error_bound: float = 0.001, max_clips: int = 32) -> None:
        self.max_tracks_per_clip = max_tracks_per_clip
        self.key_budget = key_budget
        self.error_bound = error_bound
        self.max_clips = max_clips
        self._lock = threading.RLock()

    def register_clip(self, clip_id: str, *, track_count: int,
                      key_budget: int | None = None,
                      error_bound: float | None = None,
                      looping: bool = False) -> ClipView:
        """Register a clip with its track budget and error bound."""
        raise NotImplementedError

    def clip_view(self, clip_id: str) -> ClipView:
        """Return the current clip summary."""
        raise NotImplementedError

    def plan_tracks(self, clip_id: str, tracks) -> tuple[TrackPlan, ...]:
        """Load raw tracks for the current version, sorted by track name."""
        raise NotImplementedError

    def compress_track(self, clip_id: str, track: str,
                       *, tolerance: float | None = None) -> TrackReport:
        """Reduce one planned track and stage the result."""
        raise NotImplementedError

    def validate_loop(self, clip_id: str, track: str) -> LoopReport:
        """Check that a looping track closes its seam inside the error bound."""
        raise NotImplementedError

    def track_keys(self, clip_id: str, track: str) -> tuple[tuple[int, tuple[float, ...]], ...]:
        """Return the keys of the current committed version of a track."""
        raise NotImplementedError

    def report(self, clip_id: str) -> tuple[TrackReport, ...]:
        """Return staged reports sorted by track name."""
        raise NotImplementedError

    def commit(self, clip_id: str) -> ClipView:
        """Promote every staged track to the next clip version."""
        raise NotImplementedError

    def rollback(self, clip_id: str) -> ClipView:
        """Discard staged results, keeping the committed version untouched."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a deep copy of clips and counters suitable for ``restore``."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace compressor state with a snapshot, validating its structure."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative counters for plans, compressions and commits."""
        raise NotImplementedError
