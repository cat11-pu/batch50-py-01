"""Decoded picture buffer reference marking for H.264 style decoding."""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any


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


@dataclass
class _Slot:
    slot: int
    frame_num: int
    pic_num: int
    is_reference: bool
    long_term: bool
    long_term_index: int
    output_done: bool
    generation: int


_SNAPSHOT_VERSION = 1
_SLOT_FIELDS = (
    "slot",
    "frame_num",
    "pic_num",
    "is_reference",
    "long_term",
    "long_term_index",
    "output_done",
    "generation",
)


class DpbReferenceManager:
    """Mark short and long term references, slide the window and reclaim slots."""

    def __init__(self, *, capacity: int = 16, max_long_term: int = 2) -> None:
        if not _is_int(capacity) or capacity < 0:
            raise DpbError("INVALID_CAPACITY", capacity)
        if not _is_int(max_long_term) or max_long_term < 0:
            raise DpbError("INVALID_LIMIT", max_long_term)
        self.capacity = capacity
        self.max_long_term = max_long_term
        self._lock = threading.RLock()
        self._slots: list[_Slot | None] = [None] * capacity
        self._by_pic: dict[int, int] = {}
        self._allocated = 0
        self._freed = 0
        self._gaps = 0
        self._gap_pending = False

    def allocate(self, frame_num, pic_num):
        with self._lock:
            if pic_num in self._by_pic:
                raise DpbError("DUPLICATE_PIC", pic_num)

            slot_index = self._lowest_free_slot()
            if slot_index is None:
                raise DpbError("DPB_FULL", {"capacity": self.capacity})

            generation = self._allocated + 1
            slot = _Slot(
                slot=slot_index,
                frame_num=frame_num,
                pic_num=pic_num,
                is_reference=False,
                long_term=False,
                long_term_index=-1,
                output_done=False,
                generation=generation,
            )
            self._slots[slot_index] = slot
            self._by_pic[pic_num] = slot_index
            self._allocated = generation
            return slot_index

    def mark_reference(self, pic_num, *, long_term=False):
        with self._lock:
            slot = self._find_slot(pic_num)

            if slot.is_reference:
                if long_term and not slot.long_term:
                    index = self._lowest_free_long_term_index()
                    if index is None:
                        raise DpbError("LT_LIMIT", {"max_long_term": self.max_long_term})
                    slot.long_term = True
                    slot.long_term_index = index
                return slot.slot

            if long_term:
                index = self._lowest_free_long_term_index()
                if index is None:
                    raise DpbError("LT_LIMIT", {"max_long_term": self.max_long_term})
                slot.long_term = True
                slot.long_term_index = index
            else:
                slot.long_term = False
                slot.long_term_index = -1

            slot.is_reference = True
            return slot.slot

    def sliding_window(self):
        with self._lock:
            oldest = None
            for slot in self._slots:
                if slot is None or not slot.is_reference or slot.long_term:
                    continue
                if oldest is None or slot.generation < oldest.generation:
                    oldest = slot

            if oldest is None:
                return []

            oldest.is_reference = False
            oldest.long_term = False
            oldest.long_term_index = -1
            return [oldest.pic_num]

    def clear_refs(self):
        with self._lock:
            cleared = 0
            for slot in self._slots:
                if slot is None or not slot.is_reference:
                    continue
                slot.is_reference = False
                slot.long_term = False
                slot.long_term_index = -1
                cleared += 1
            return cleared

    def get_ref(self, pic_num):
        with self._lock:
            slot_index = self._by_pic.get(pic_num)
            if slot_index is None:
                return None
            slot = self._slots[slot_index]
            if slot is None or not slot.is_reference:
                return None
            return slot.slot

    def flush(self):
        with self._lock:
            reclaimed = 0
            for slot_index, slot in enumerate(self._slots):
                if slot is None or not slot.output_done or slot.is_reference:
                    continue
                self._slots[slot_index] = None
                del self._by_pic[slot.pic_num]
                reclaimed += 1
            self._freed += reclaimed
            return reclaimed

    def mark_output_done(self, pic_num):
        with self._lock:
            slot = self._find_slot(pic_num)
            slot.output_done = True
            return True

    def mark_gap(self, frame_num):
        with self._lock:
            self._gaps += 1
            self._gap_pending = True

    def gap_pending(self):
        with self._lock:
            return self._gap_pending

    def set_max_long_term(self, n):
        with self._lock:
            if not _is_int(n) or n < 0:
                raise DpbError("INVALID_LIMIT", n)
            indexes = [
                slot.long_term_index
                for slot in self._slots
                if slot is not None and slot.is_reference and slot.long_term
            ]
            if len(indexes) > n or any(index >= n for index in indexes):
                raise DpbError("LT_LIMIT", {"max_long_term": n})
            self.max_long_term = n

    def slot_table(self):
        with self._lock:
            return [
                SlotView(
                    slot=slot.slot,
                    frame_num=slot.frame_num,
                    pic_num=slot.pic_num,
                    is_reference=slot.is_reference,
                    long_term=slot.long_term,
                    long_term_index=slot.long_term_index,
                    output_done=slot.output_done,
                    generation=slot.generation,
                )
                for slot in self._slots
                if slot is not None
            ]

    def stats(self):
        with self._lock:
            refs = 0
            long_term_refs = 0
            for slot in self._slots:
                if slot is None or not slot.is_reference:
                    continue
                refs += 1
                if slot.long_term:
                    long_term_refs += 1
            return {
                "allocated": self._allocated,
                "freed": self._freed,
                "refs": refs,
                "long_term_refs": long_term_refs,
                "gaps": self._gaps,
                "capacity": self.capacity,
            }

    def snapshot(self):
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "capacity": self.capacity,
                "max_long_term": self.max_long_term,
                "slots": [
                    {
                        "slot": slot.slot,
                        "frame_num": slot.frame_num,
                        "pic_num": slot.pic_num,
                        "is_reference": slot.is_reference,
                        "long_term": slot.long_term,
                        "long_term_index": slot.long_term_index,
                        "output_done": slot.output_done,
                        "generation": slot.generation,
                    }
                    for slot in self._slots
                    if slot is not None
                ],
                "allocated": self._allocated,
                "freed": self._freed,
                "gaps": self._gaps,
                "gap_pending": self._gap_pending,
            }

    def restore(self, state):
        parsed = self._parse_snapshot(state)
        with self._lock:
            (
                self.capacity,
                self.max_long_term,
                self._slots,
                self._by_pic,
                self._allocated,
                self._freed,
                self._gaps,
                self._gap_pending,
            ) = parsed

    def _lowest_free_slot(self):
        for slot_index, slot in enumerate(self._slots):
            if slot is None:
                return slot_index
        return None

    def _find_slot(self, pic_num):
        slot_index = self._by_pic.get(pic_num)
        if slot_index is None:
            raise DpbError("UNKNOWN_PIC", pic_num)
        slot = self._slots[slot_index]
        if slot is None:
            raise DpbError("UNKNOWN_PIC", pic_num)
        return slot

    def _lowest_free_long_term_index(self):
        used = {
            slot.long_term_index
            for slot in self._slots
            if slot is not None and slot.is_reference and slot.long_term
        }
        if len(used) >= self.max_long_term:
            return None
        for index in range(self.max_long_term):
            if index not in used:
                return index
        return None

    def _parse_snapshot(self, state):
        try:
            if not isinstance(state, dict):
                raise ValueError("snapshot must be a mapping")
            if state.get("version") != _SNAPSHOT_VERSION:
                raise ValueError("unsupported snapshot version")

            capacity = state["capacity"]
            max_long_term = state["max_long_term"]
            raw_slots = state["slots"]
            allocated = state["allocated"]
            freed = state["freed"]
            gaps = state["gaps"]
            gap_pending = state["gap_pending"]

            if not _is_int(capacity) or capacity < 0:
                raise ValueError("invalid capacity")
            if not _is_int(max_long_term) or max_long_term < 0:
                raise ValueError("invalid max_long_term")
            if not isinstance(raw_slots, list):
                raise ValueError("slots must be a list")
            if not _is_int(allocated) or allocated < 0:
                raise ValueError("invalid allocated counter")
            if not _is_int(freed) or freed < 0:
                raise ValueError("invalid freed counter")
            if not _is_int(gaps) or gaps < 0:
                raise ValueError("invalid gaps counter")
            if not isinstance(gap_pending, bool):
                raise ValueError("invalid gap_pending")

            slots: list[_Slot | None] = [None] * capacity
            by_pic: dict[int, int] = {}
            long_term_indexes: set[int] = set()
            generations: set[int] = set()

            for raw in raw_slots:
                if not isinstance(raw, dict):
                    raise ValueError("slot entry must be a mapping")
                if any(field not in raw for field in _SLOT_FIELDS):
                    raise ValueError("slot entry is missing fields")

                slot_index = raw["slot"]
                frame_num = raw["frame_num"]
                pic_num = raw["pic_num"]
                is_reference = raw["is_reference"]
                long_term = raw["long_term"]
                long_term_index = raw["long_term_index"]
                output_done = raw["output_done"]
                generation = raw["generation"]

                if not _is_int(slot_index) or not 0 <= slot_index < capacity:
                    raise ValueError("invalid slot number")
                if not _is_int(frame_num):
                    raise ValueError("invalid frame_num")
                if not _is_int(pic_num):
                    raise ValueError("invalid pic_num")
                if not isinstance(is_reference, bool):
                    raise ValueError("invalid is_reference")
                if not isinstance(long_term, bool):
                    raise ValueError("invalid long_term")
                if not _is_int(long_term_index):
                    raise ValueError("invalid long_term_index")
                if not isinstance(output_done, bool):
                    raise ValueError("invalid output_done")
                if not _is_int(generation) or generation <= 0:
                    raise ValueError("invalid generation")

                if slots[slot_index] is not None:
                    raise ValueError("duplicate slot number")
                if pic_num in by_pic:
                    raise ValueError("duplicate pic_num")
                if generation in generations:
                    raise ValueError("duplicate generation")

                if not is_reference:
                    if long_term or long_term_index != -1:
                        raise ValueError("non-reference slot has long-term state")
                elif long_term:
                    if not 0 <= long_term_index < max_long_term:
                        raise ValueError("invalid long-term index")
                    if long_term_index in long_term_indexes:
                        raise ValueError("duplicate long-term index")
                    long_term_indexes.add(long_term_index)
                elif long_term_index != -1:
                    raise ValueError("short-term slot has long-term index")

                slots[slot_index] = _Slot(
                    slot=slot_index,
                    frame_num=frame_num,
                    pic_num=pic_num,
                    is_reference=is_reference,
                    long_term=long_term,
                    long_term_index=long_term_index,
                    output_done=output_done,
                    generation=generation,
                )
                by_pic[pic_num] = slot_index
                generations.add(generation)

            if len(long_term_indexes) > max_long_term:
                raise ValueError("too many long-term references")
            if len(raw_slots) + freed != allocated:
                raise ValueError("allocation counters are inconsistent")
            if any(generation > allocated for generation in generations):
                raise ValueError("generation exceeds allocation counter")

            return (
                capacity,
                max_long_term,
                slots,
                by_pic,
                allocated,
                freed,
                gaps,
                gap_pending,
            )
        except DpbError:
            raise
        except Exception as exc:
            raise DpbError("SNAPSHOT_INVALID", str(exc)) from exc


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
