"""Overdub latency measurement and sample-accurate take alignment.

The aligner owns a small number of recording tracks, measures the round-trip
latency of the monitoring chain, aligns newly recorded takes by a whole number
of samples and commits a take over a punch range while the previously
committed version is replaced in one step.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "OverdubError",
    "TrackSpec",
    "Take",
    "PunchRange",
    "CommitResult",
    "OverdubAligner",
]


class OverdubError(ValueError):
    """Raised when the aligner refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TrackSpec:
    """One recording track and its current latency state."""

    track_id: str
    sample_rate: int
    latency_samples: int
    drift_samples: int
    max_latency: int


@dataclass(frozen=True)
class Take:
    """One recorded take placed on a track timeline."""

    take_id: str
    track_id: str
    start_sample: int
    length: int
    aligned_start: int
    punch_start: int
    punch_end: int
    status: str


@dataclass(frozen=True)
class PunchRange:
    """Punch in and punch out points of one take including its fades."""

    take_id: str
    start_sample: int
    end_sample: int
    fade_in: int
    fade_out: int


@dataclass(frozen=True)
class CommitResult:
    """Outcome of a committed take and the resulting span table."""

    track_id: str
    take_id: str
    replaced: bool
    start_sample: int
    end_sample: int
    spans: tuple[tuple[int, int], ...]


class OverdubAligner:
    """Align overdubbed takes to the backing track by measured latency."""

    def __init__(self, *, max_latency: int = 48000, drift_limit: int = 500,
                 max_tracks: int = 16) -> None:
        self.max_latency = max_latency
        self.drift_limit = drift_limit
        self.max_tracks = max_tracks
        self._lock = threading.RLock()

    def add_track(self, track_id: str, sample_rate: int, *,
                  max_latency: int | None = None) -> TrackSpec:
        """Register a recording track with a zero initial latency."""
        raise NotImplementedError

    def calibrate(self, track_id: str,
                  measurements: list[int]) -> int:
        """Measure round-trip latency from samples and store the median."""
        raise NotImplementedError

    def set_latency(self, track_id: str, latency_samples: int) -> int:
        """Set the latency of a track explicitly within its hard limit."""
        raise NotImplementedError

    def place_take(self, track_id: str, take_id: str, start_sample: int,
                   length: int) -> Take:
        """Place a newly recorded take on the track timeline."""
        raise NotImplementedError

    def punch_range(self, take_id: str, start_sample: int,
                    end_sample: int) -> PunchRange:
        """Define the punch range and fades of one placed take."""
        raise NotImplementedError

    def align_take(self, take_id: str) -> int:
        """Return the aligned start of a take in whole samples."""
        raise NotImplementedError

    def take_of(self, take_id: str) -> Take:
        """Return one take record by id."""
        raise NotImplementedError

    def commit(self, take_id: str) -> CommitResult:
        """Commit an aligned take over its punch range."""
        raise NotImplementedError

    def discard_take(self, take_id: str) -> bool:
        """Drop an uncommitted take from its track."""
        raise NotImplementedError

    def committed_spans(self, track_id: str) -> tuple[tuple[int, int], ...]:
        """Return the merged committed spans of a track in ascending order."""
        raise NotImplementedError

    def drift_estimate(self, track_id: str) -> int:
        """Return the drift estimate of the last calibration of a track."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative aligner counters."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a deep copy of tracks, takes, latency and span tables."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace aligner state from a snapshot, validating its structure."""
        raise NotImplementedError
