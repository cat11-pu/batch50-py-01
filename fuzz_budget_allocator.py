"""Fuzz budget allocator: yield feedback, per round decay, starvation floor."""

from __future__ import annotations

import threading


class AllocError(ValueError):
    """Raised when the allocator refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATE_ACTIVE = "active"
STATE_OBSERVING = "observing"

OBSERVE_AFTER_ROUNDS = 3


class FuzzBudgetAllocator:
    """Split a per-round compute budget across fuzz targets."""

    def __init__(self, *, floor_quota: int = 64,
                 yield_threshold: int = 1) -> None:
        self.floor_quota = floor_quota
        self.yield_threshold = yield_threshold
        self._lock = threading.RLock()
        self._targets: dict[str, dict] = {}
        self._round = 0
        self._allocated: dict[str, int] = {}
        self._consumed: dict[str, int] = {}
        self._counters: dict[str, int] = {}

    def register(self, target: str, *, weight: float = 1.0,
                 note: str = "") -> dict:
        raise NotImplementedError

    def allocate(self, total_budget: int) -> dict[str, int]:
        raise NotImplementedError

    def report_yield(self, target: str, *, new_coverage: int = 0,
                     crashes: int = 0) -> dict:
        raise NotImplementedError

    def rebalance(self, *, total_budget: int) -> dict[str, int]:
        raise NotImplementedError

    def consume(self, target: str, units: int) -> int:
        raise NotImplementedError

    def usage(self) -> dict:
        raise NotImplementedError

    def targets(self) -> list[dict]:
        raise NotImplementedError

    def states(self) -> dict[str, str]:
        raise NotImplementedError

    def round_no(self) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
