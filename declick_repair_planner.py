"""Block-streamed click and clipping repair planner for restoration work."""

from __future__ import annotations

import threading
from dataclasses import dataclass

CLIP_LEVEL = 0.98


class DeclickError(ValueError):
    """Raised when a planner request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Click:
    """A detected click or clipping plateau, in global sample indices."""

    start: int
    end: int
    kind: str
    peak: float


@dataclass(frozen=True)
class RepairSpan:
    """A planned repair range and the reconstruction mode for it."""

    start: int
    end: int
    mode: str


class DeclickRepairPlanner:
    """Plan repairs over a stream of audio blocks and account for residual error."""

    def __init__(self, *, threshold: float = 0.5, sample_rate: int = 48000,
                 max_repair_len: int = 64, max_points_per_block: int = 8,
                 merge_gap: int = 2, residual_limit: float = 0.25) -> None:
        self.threshold = threshold
        self.sample_rate = sample_rate
        self.max_repair_len = max_repair_len
        self.max_points_per_block = max_points_per_block
        self.merge_gap = merge_gap
        self.residual_limit = residual_limit
        self._lock = threading.RLock()

    def feed_block(self, block):
        raise NotImplementedError

    def detect_clicks(self):
        raise NotImplementedError

    def plan_repair(self, clicks):
        raise NotImplementedError

    def apply_repair(self, spans):
        raise NotImplementedError

    def verify_residual(self):
        raise NotImplementedError

    def set_threshold(self, value):
        raise NotImplementedError

    def set_sample_rate(self, rate):
        raise NotImplementedError

    def set_limits(self, *, max_repair_len=None, max_points_per_block=None):
        raise NotImplementedError

    def committed_blocks(self):
        raise NotImplementedError

    def repair_stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError
