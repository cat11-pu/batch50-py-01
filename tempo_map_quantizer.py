"""Tempo map maintenance and musical grid quantization.

The map keeps tempo anchors and meter changes in musical ticks, converts
between ticks and sample positions segment by segment and snaps note events
onto the nearest grid point of the meter segment that contains them.
"""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

__all__ = [
    "TempoMapError",
    "TempoAnchor",
    "MeterAnchor",
    "TempoMapQuantizer",
]

_GRID_DIVISORS = {
    "1/4": 1,
    "1/8": 2,
    "1/16": 4,
    "1/32": 8,
}

_ALLOWED_DENOMINATORS = (2, 4, 8, 16, 32)
_MAX_BPM = 400.0
_DEFAULT_BPM = 120.0
_DEFAULT_METER = (4, 4)


class TempoMapError(ValueError):
    """Raised when the tempo map refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TempoAnchor:
    """One tempo change placed at a musical tick."""

    tick: int
    bpm: float


@dataclass(frozen=True)
class MeterAnchor:
    """One meter change placed on a bar line."""

    tick: int
    numerator: int
    denominator: int


class TempoMapQuantizer:
    """Maintain a tempo map and quantize tick positions onto a grid."""

    def __init__(self, *, ppq: int = 480, sample_rate: int = 48000,
                 max_anchors: int = 256) -> None:
        self.ppq = ppq
        self.sample_rate = sample_rate
        self.max_anchors = max_anchors
        self._lock = threading.RLock()
        self._tempos: list[TempoAnchor] = [TempoAnchor(0, _DEFAULT_BPM)]
        self._meters: list[MeterAnchor] = [
            MeterAnchor(0, _DEFAULT_METER[0], _DEFAULT_METER[1])
        ]
        self._quantized = 0
        self._removed = 0
        self._refuses = 0

    def _fail(self, code: str, detail: object = None) -> None:
        self._refuses += 1
        raise TempoMapError(code, detail)

    @staticmethod
    def _check_tick(tick: object) -> bool:
        return isinstance(tick, int) and not isinstance(tick, bool) and tick >= 0

    def _samples_per_tick(self, bpm: float) -> float:
        return self.sample_rate * 60.0 / (bpm * self.ppq)

    def _bar_ticks(self, meter: MeterAnchor) -> int:
        return meter.numerator * (self.ppq * 4 // meter.denominator)

    def _bar_line_locked(self, tick: int) -> int:
        for index, meter in enumerate(self._meters):
            end = (self._meters[index + 1].tick
                   if index + 1 < len(self._meters) else None)
            if end is None or tick < end:
                bar = self._bar_ticks(meter)
                return meter.tick + ((tick - meter.tick) // bar) * bar
        return 0

    def _grid_ticks(self, grid: str, triplet: bool) -> int:
        divisor = _GRID_DIVISORS.get(grid)
        if divisor is None:
            self._fail("TEMPO_GRID_UNSUPPORTED", {"grid": grid})
        ticks = self.ppq // divisor
        if triplet:
            ticks = ticks * 2 // 3
        return ticks

    def add_tempo(self, tick: int, bpm: float) -> TempoAnchor:
        """Insert or replace a tempo anchor at *tick*."""
        with self._lock:
            if not self._check_tick(tick):
                self._fail("TEMPO_INVALID_REQUEST", {"tick": tick})
            try:
                bpm = float(bpm)
            except (TypeError, ValueError):
                self._fail("TEMPO_INVALID_BPM", {"bpm": bpm})
            if not 0.0 < bpm <= _MAX_BPM:
                self._fail("TEMPO_INVALID_BPM", {"bpm": bpm})
            anchor = TempoAnchor(tick, bpm)
            for index, existing in enumerate(self._tempos):
                if existing.tick == tick:
                    self._tempos[index] = anchor
                    return anchor
            if len(self._tempos) >= self.max_anchors:
                self._fail("TEMPO_ANCHOR_LIMIT",
                           {"max_anchors": self.max_anchors})
            self._tempos.append(anchor)
            self._tempos.sort(key=lambda item: item.tick)
            return anchor

    def add_meter(self, tick: int, numerator: int,
                  denominator: int) -> MeterAnchor:
        """Insert a meter change on an existing bar line."""
        with self._lock:
            if not self._check_tick(tick):
                self._fail("TEMPO_INVALID_REQUEST", {"tick": tick})
            if (not isinstance(numerator, int) or isinstance(numerator, bool)
                    or not 1 <= numerator <= 16
                    or denominator not in _ALLOWED_DENOMINATORS):
                self._fail("TEMPO_INVALID_METER",
                           {"numerator": numerator, "denominator": denominator})
            if self._bar_line_locked(tick) != tick:
                self._fail("TEMPO_INVALID_METER_POSITION", {"tick": tick})
            anchor = MeterAnchor(tick, numerator, denominator)
            for index, existing in enumerate(self._meters):
                if existing.tick == tick:
                    self._meters[index] = anchor
                    return anchor
            if len(self._meters) >= self.max_anchors:
                self._fail("TEMPO_ANCHOR_LIMIT",
                           {"max_anchors": self.max_anchors})
            self._meters.append(anchor)
            self._meters.sort(key=lambda item: item.tick)
            return anchor

    def remove_tempo(self, tick: int) -> TempoAnchor:
        """Remove the tempo anchor at *tick* and return it."""
        with self._lock:
            if not self._check_tick(tick) or tick == 0:
                self._fail("TEMPO_INVALID_REQUEST", {"tick": tick})
            for index, existing in enumerate(self._tempos):
                if existing.tick == tick:
                    del self._tempos[index]
                    self._removed += 1
                    return existing
            self._fail("TEMPO_UNKNOWN_ANCHOR", {"tick": tick})

    def tick_to_sample(self, tick: int) -> int:
        """Convert a musical tick to a sample position."""
        with self._lock:
            if not self._check_tick(tick):
                self._fail("TEMPO_INVALID_REQUEST", {"tick": tick})
            total = 0.0
            for index, anchor in enumerate(self._tempos):
                if anchor.tick > tick:
                    break
                end = (self._tempos[index + 1].tick
                       if index + 1 < len(self._tempos) else tick)
                end = min(end, tick)
                if end > anchor.tick:
                    total += (end - anchor.tick) * self._samples_per_tick(
                        anchor.bpm)
                if end == tick:
                    break
            return int(round(total))

    def sample_to_tick(self, sample: int) -> int:
        """Convert a sample position back to a musical tick."""
        with self._lock:
            if (not isinstance(sample, int) or isinstance(sample, bool)
                    or sample < 0):
                self._fail("TEMPO_INVALID_REQUEST", {"sample": sample})
            remaining = float(sample)
            for index, anchor in enumerate(self._tempos):
                per_tick = self._samples_per_tick(anchor.bpm)
                if index + 1 < len(self._tempos):
                    segment_ticks = self._tempos[index + 1].tick - anchor.tick
                    segment_samples = segment_ticks * per_tick
                    if remaining >= segment_samples:
                        remaining -= segment_samples
                        continue
                return int(round(anchor.tick + remaining / per_tick))
            return 0

    def quantize(self, tick: int, *, grid: str = "1/16",
                 triplet: bool = False, swing: float = 0.0) -> int:
        """Snap *tick* onto the nearest grid point of its meter segment."""
        with self._lock:
            if not self._check_tick(tick):
                self._fail("TEMPO_INVALID_REQUEST", {"tick": tick})
            grid_ticks = self._grid_ticks(grid, triplet)
            origin = self._bar_line_locked(tick)
            segment_end = None
            for meter in self._meters:
                if meter.tick > tick:
                    segment_end = meter.tick
                    break
            base = (tick - origin) // grid_ticks
            candidates = []
            for index in range(max(0, base - 2), base + 4):
                point = origin + index * grid_ticks
                if swing and not triplet and index % 2 == 1:
                    point += int(round(swing * grid_ticks))
                if segment_end is not None and point >= segment_end:
                    continue
                candidates.append(point)
            best = min(candidates, key=lambda p: (abs(p - tick), p))
            self._quantized += 1
            return best

    def grid_at(self, tick: int, grid: str = "1/16", *,
                triplet: bool = False) -> int:
        """Return the grid size in ticks for one grid name."""
        with self._lock:
            if not self._check_tick(tick):
                self._fail("TEMPO_INVALID_REQUEST", {"tick": tick})
            return self._grid_ticks(grid, triplet)

    def anchors(self) -> tuple[TempoAnchor, ...]:
        """Return all tempo anchors ordered by tick."""
        with self._lock:
            return tuple(self._tempos)

    def meter_at(self, tick: int) -> MeterAnchor:
        """Return the meter anchor in effect at *tick*."""
        with self._lock:
            if not self._check_tick(tick):
                self._fail("TEMPO_INVALID_REQUEST", {"tick": tick})
            current = self._meters[0]
            for meter in self._meters:
                if meter.tick > tick:
                    break
                current = meter
            return current

    def bar_line(self, tick: int) -> int:
        """Return the tick of the bar line at or before *tick*."""
        with self._lock:
            if not self._check_tick(tick):
                self._fail("TEMPO_INVALID_REQUEST", {"tick": tick})
            return self._bar_line_locked(tick)

    def stats(self) -> dict:
        """Return cumulative tempo map counters."""
        with self._lock:
            return {
                "tempos": len(self._tempos),
                "meters": len(self._meters),
                "quantized": self._quantized,
                "removed": self._removed,
                "refuses": self._refuses,
            }

    def snapshot(self) -> dict:
        """Return a deep copy of anchors, meters and counters."""
        with self._lock:
            return copy.deepcopy({
                "ppq": self.ppq,
                "sample_rate": self.sample_rate,
                "max_anchors": self.max_anchors,
                "tempos": [(a.tick, a.bpm) for a in self._tempos],
                "meters": [(m.tick, m.numerator, m.denominator)
                           for m in self._meters],
                "counters": {
                    "quantized": self._quantized,
                    "removed": self._removed,
                    "refuses": self._refuses,
                },
            })

    def restore(self, state: dict) -> None:
        """Replace map state from a snapshot, validating its structure."""
        with self._lock:
            tempos, meters, counters = self._validate_snapshot(state)
            self._tempos = tempos
            self._meters = meters
            self._quantized = counters["quantized"]
            self._removed = counters["removed"]
            self._refuses = counters["refuses"]

    def _validate_snapshot(self, state: object):
        def invalid(detail: object) -> None:
            self._fail("TEMPO_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict):
            invalid({"reason": "not a mapping"})
        for key in ("ppq", "sample_rate", "max_anchors"):
            if state.get(key) != getattr(self, key):
                invalid({"reason": "config mismatch", "key": key})

        raw_tempos = state.get("tempos")
        if (not isinstance(raw_tempos, (list, tuple)) or not raw_tempos
                or len(raw_tempos) > self.max_anchors):
            invalid({"reason": "bad tempos"})
        tempos = []
        previous = -1
        for entry in raw_tempos:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                invalid({"reason": "bad tempo entry", "entry": entry})
            tick, bpm = entry
            if not self._check_tick(tick) or tick <= previous:
                invalid({"reason": "bad tempo tick", "entry": entry})
            if not isinstance(bpm, (int, float)) or isinstance(bpm, bool) \
                    or not 0.0 < float(bpm) <= _MAX_BPM:
                invalid({"reason": "bad tempo bpm", "entry": entry})
            tempos.append(TempoAnchor(tick, float(bpm)))
            previous = tick
        if tempos[0].tick != 0:
            invalid({"reason": "missing default tempo"})

        raw_meters = state.get("meters")
        if (not isinstance(raw_meters, (list, tuple)) or not raw_meters
                or len(raw_meters) > self.max_anchors):
            invalid({"reason": "bad meters"})
        meters = []
        previous = -1
        for entry in raw_meters:
            if not isinstance(entry, (list, tuple)) or len(entry) != 3:
                invalid({"reason": "bad meter entry", "entry": entry})
            tick, numerator, denominator = entry
            if not self._check_tick(tick) or tick <= previous:
                invalid({"reason": "bad meter tick", "entry": entry})
            if (not isinstance(numerator, int) or isinstance(numerator, bool)
                    or not 1 <= numerator <= 16
                    or denominator not in _ALLOWED_DENOMINATORS):
                invalid({"reason": "bad meter value", "entry": entry})
            meter = MeterAnchor(tick, numerator, denominator)
            if meters:
                bar = self._bar_ticks_for(meters[-1])
                segment_start = meters[-1].tick
                if (tick - segment_start) % bar != 0:
                    invalid({"reason": "meter off bar line", "entry": entry})
            meters.append(meter)
            previous = tick
        if meters[0].tick != 0:
            invalid({"reason": "missing default meter"})

        counters = state.get("counters")
        if not isinstance(counters, dict):
            invalid({"reason": "bad counters"})
        for key in ("quantized", "removed", "refuses"):
            value = counters.get(key)
            if (not isinstance(value, int) or isinstance(value, bool)
                    or value < 0):
                invalid({"reason": "bad counter", "key": key})
        return tempos, meters, counters

    def _bar_ticks_for(self, meter: MeterAnchor) -> int:
        return meter.numerator * (self.ppq * 4 // meter.denominator)
