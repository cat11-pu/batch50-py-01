"""Narrow-band feedback detection and notch allocation for live sound."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class FeedbackError(ValueError):
    """Raised when a suppression request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FeedbackPeak:
    """One narrow-band peak seen in the incoming spectrum."""

    freq_hz: float
    confidence: float
    bin_index: int
    confirmed: bool


@dataclass(frozen=True)
class NotchFilter:
    """One allocated notch filter and its remaining hold time."""

    notch_id: int
    freq_hz: float
    depth_db: float
    bandwidth_hz: float
    remaining_ms: int


class FeedbackSuppressor:
    """Detect sustained narrow-band feedback and spend the notch budget on it."""

    def __init__(self, *, sample_rate: int = 48000, detect_floor: float = 0.6,
                 notch_cap: int = 8, hold_ms: int = 500,
                 ceiling_db: float = -6.0) -> None:
        self.sample_rate = sample_rate
        self.detect_floor = detect_floor
        self.notch_cap = notch_cap
        self.hold_ms = hold_ms
        self.ceiling_db = ceiling_db
        self._lock = threading.RLock()

    def set_sample_rate(self, rate):
        raise NotImplementedError

    def feed_spectrum(self, bins):
        raise NotImplementedError

    def detect_feedback(self):
        raise NotImplementedError

    def allocate_notch(self, freq_hz, depth_db=None):
        raise NotImplementedError

    def release_notch(self, notch_id):
        raise NotImplementedError

    def set_ceiling(self, ceiling_db):
        raise NotImplementedError

    def set_hold_ms(self, ms):
        raise NotImplementedError

    def advance_time(self, ms):
        raise NotImplementedError

    def notch_table(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError
