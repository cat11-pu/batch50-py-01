"""Decoded picture buffer reference marking for H.264 style decoding."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class DpbError(ValueError):
    """Raised when a buffer request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SlotView:
    """Public view of one decoded picture buffer slot."""

    slot: int
    frame_num: int
    pic_num: int
    is_reference: bool
    long_term: bool
    long_term_index: int
    output_done: bool
    generation: int


class DpbReferenceManager:
    """Mark short and long term references, slide the window and reclaim slots."""

    def __init__(self, *, capacity: int = 16, max_long_term: int = 2) -> None:
        self.capacity = capacity
        self.max_long_term = max_long_term
        self._lock = threading.RLock()

    def allocate(self, frame_num, pic_num):
        raise NotImplementedError

    def mark_reference(self, pic_num, *, long_term=False):
        raise NotImplementedError

    def sliding_window(self):
        raise NotImplementedError

    def clear_refs(self):
        raise NotImplementedError

    def get_ref(self, pic_num):
        raise NotImplementedError

    def flush(self):
        raise NotImplementedError

    def mark_output_done(self, pic_num):
        raise NotImplementedError

    def mark_gap(self, frame_num):
        raise NotImplementedError

    def gap_pending(self):
        raise NotImplementedError

    def set_max_long_term(self, n):
        raise NotImplementedError

    def slot_table(self):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError
