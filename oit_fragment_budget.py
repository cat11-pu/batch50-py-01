"""Order-independent transparency fragment budget with overflow degradation."""

from __future__ import annotations

import threading


class OitError(ValueError):
    """Raised when a fragment budget operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class OitFragmentBudget:
    """Hold translucent fragments per pixel under a fixed slot budget."""

    MAX_CAPACITY = 32

    def __init__(self, *, capacity: int = 8, merge_mode: str = "average") -> None:
        if merge_mode not in ("average", "drop"):
            raise OitError("OIT_INVALID_MERGE_MODE", merge_mode)
        if not isinstance(capacity, int) or isinstance(capacity, bool):
            raise OitError("OIT_INVALID_CAPACITY", capacity)
        minimum = 2 if merge_mode == "average" else 1
        if capacity < minimum or capacity > self.MAX_CAPACITY:
            raise OitError("OIT_INVALID_CAPACITY", capacity)
        self.capacity = capacity
        self.merge_mode = merge_mode
        self._lock = threading.RLock()

    def begin_frame(self, frame_id, *, width=1, height=1):
        raise NotImplementedError

    def push_fragment(self, *, x, y, depth, color, alpha=1.0, seq=None):
        raise NotImplementedError

    def resolve_pixel(self, *, x, y, background=(0, 0, 0)):
        raise NotImplementedError

    def pending_count(self, x=None, y=None):
        raise NotImplementedError

    def frame_info(self):
        raise NotImplementedError

    def set_capacity(self, capacity):
        raise NotImplementedError

    def overflow_stats(self):
        raise NotImplementedError

    def reset(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
