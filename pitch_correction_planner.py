"""Pitch correction planning for vocal takes.

The planner keeps one pitch track per take, snaps voiced frames onto the
degrees of a scale, derives a correction curve with a bounded rate of change
and records which frame ranges were already committed.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "PitchError",
    "TakeSpec",
    "PitchFrame",
    "CorrectionPoint",
    "CorrectionPlan",
    "PitchCorrectionPlanner",
]


class PitchError(ValueError):
    """Raised when the planner refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TakeSpec:
    """Registered vocal take and its analysis parameters."""

    take_id: str
    sample_rate: int
    hop: int
    frame_count: int
    root: int
    mode: str
    preserve_formant: bool


@dataclass(frozen=True)
class PitchFrame:
    """One analyzed frame with its pitch estimate in MIDI semitones."""

    index: int
    pitch: float
    confidence: float
    voiced: bool


@dataclass(frozen=True)
class CorrectionPoint:
    """One planned correction of a frame."""

    frame: int
    source_pitch: float
    target_pitch: float
    shift: float
    applied_shift: float


@dataclass(frozen=True)
class CorrectionPlan:
    """Summary of a planned correction curve."""

    take_id: str
    points: int
    max_shift: float
    scale: tuple[int, ...]


class PitchCorrectionPlanner:
    """Plan scale snapping and rate limited pitch correction for takes."""

    def __init__(self, *, hop: int = 256, sample_rate: int = 48000,
                 confidence_floor: float = 0.5,
                 max_semitones_per_second: float = 1.5,
                 max_frames: int = 4096) -> None:
        self.hop = hop
        self.sample_rate = sample_rate
        self.confidence_floor = confidence_floor
        self.max_semitones_per_second = max_semitones_per_second
        self.max_frames = max_frames
        self._lock = threading.RLock()

    def register_take(self, take_id: str, sample_rate: int, *,
                      hop: int | None = None,
                      preserve_formant: bool = True) -> TakeSpec:
        """Register a take with its sample rate and frame hop."""
        raise NotImplementedError

    def analyze_pitch(self, take_id: str,
                      frames: list[tuple[float, float]]) -> int:
        """Store per frame pitch estimates and return the voiced count."""
        raise NotImplementedError

    def set_scale(self, take_id: str, root: int,
                  mode: str = "major") -> tuple[int, ...]:
        """Select the scale used to snap voiced frames."""
        raise NotImplementedError

    def plan_correction(self, take_id: str) -> CorrectionPlan:
        """Derive the correction curve of an analyzed take."""
        raise NotImplementedError

    def correction_curve(self, take_id: str) -> tuple[CorrectionPoint, ...]:
        """Return the planned correction points of a take."""
        raise NotImplementedError

    def apply_segment(self, take_id: str, start_frame: int,
                      end_frame: int) -> int:
        """Commit the correction of a frame range and return its length."""
        raise NotImplementedError

    def committed_frames(self, take_id: str) -> int:
        """Return how many frames of a take are already committed."""
        raise NotImplementedError

    def take_of(self, take_id: str) -> TakeSpec:
        """Return the registered specification of one take."""
        raise NotImplementedError

    def confidence_at(self, take_id: str, index: int) -> float:
        """Return the confidence of one analyzed frame."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative planner counters."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a deep copy of takes, frames, curves and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace planner state from a snapshot, validating its structure."""
        raise NotImplementedError
