"""Multicamera audio fingerprint alignment with long-term drift reporting."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SyncError(ValueError):
    """Raised when an alignment request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TrackInfo:
    """Public description of one ingested camera track."""

    track_id: str
    sample_rate: int
    windows: int
    locked: bool


@dataclass(frozen=True)
class OffsetEstimate:
    """Estimated offset of one track against a reference track."""

    track_id: str
    offset_ms: int
    confidence: float
    ambiguous: bool


@dataclass(frozen=True)
class DriftSegment:
    """One segment of the piecewise-linear drift report."""

    start_ms: int
    end_ms: int
    drift_ppm: int


class MulticamSyncAligner:
    """Align camera tracks onto one timeline and report long-term drift."""

    def __init__(self, *, window_ms: int = 10, max_lag_ms: int = 500,
                 segment_ms: int = 1000, max_tracks: int = 16) -> None:
        self.window_ms = window_ms
        self.max_lag_ms = max_lag_ms
        self.segment_ms = segment_ms
        self.max_tracks = max_tracks
        self._lock = threading.RLock()

    def ingest_track(self, track_id, samples, sample_rate=48000):
        raise NotImplementedError

    def estimate_offset(self, track_id, reference_id):
        raise NotImplementedError

    def align(self, reference_id):
        raise NotImplementedError

    def drift_report(self, track_id, reference_id=None):
        raise NotImplementedError

    def commit(self, project_version):
        raise NotImplementedError

    def lock_track(self, track_id):
        raise NotImplementedError

    def track_info(self, track_id):
        raise NotImplementedError

    def fingerprint_count(self, track_id):
        raise NotImplementedError

    def set_max_tracks(self, n):
        raise NotImplementedError

    def track_stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError
