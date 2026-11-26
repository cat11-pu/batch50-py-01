"""Narrow-band feedback detection and notch allocation for live sound."""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass


_SNAPSHOT_VERSION = 1
_DEFAULT_BIN_COUNT = 64
_MAX_ATTENUATION_DB = 24.0


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


@dataclass
class _NotchState:
    notch_id: int
    freq_hz: float
    depth_db: float
    bandwidth_hz: float
    remaining_ms: int
    active: bool = False


def _require_int(value: object, code: str, *, minimum: int | None = None) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise FeedbackError(code, value)
    if minimum is not None and value < minimum:
        raise FeedbackError(code, value)
    return value


def _require_number(value: object, code: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FeedbackError(code, value)
    number = float(value)
    if not math.isfinite(number):
        raise FeedbackError(code, value)
    return number


def _require_ceiling(value: object) -> float:
    number = _require_number(value, "INVALID_CEILING")
    if number >= 0.0 or number < -_MAX_ATTENUATION_DB:
        raise FeedbackError("INVALID_CEILING", value)
    return number


def _require_hold_ms(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise FeedbackError("INVALID_HOLD", value)
    if not math.isfinite(float(value)) or float(value) < 0.0:
        raise FeedbackError("INVALID_HOLD", value)
    return int(value)


class FeedbackSuppressor:
    """Detect sustained narrow-band feedback and spend the notch budget on it."""

    def __init__(self, *, sample_rate: int = 48000, detect_floor: float = 0.6,
                 notch_cap: int = 8, hold_ms: int = 500,
                 ceiling_db: float = -6.0) -> None:
        self._lock = threading.RLock()
        self.sample_rate = _require_int(
            sample_rate, "INVALID_SAMPLE_RATE", minimum=1
        )
        self.detect_floor = _require_number(detect_floor, "INVALID_DETECT_FLOOR")
        if self.detect_floor < 0.0:
            raise FeedbackError("INVALID_DETECT_FLOOR", detect_floor)
        self.notch_cap = _require_int(notch_cap, "INVALID_NOTCH_CAP", minimum=1)
        self.hold_ms = _require_hold_ms(hold_ms)
        self.ceiling_db = _require_ceiling(ceiling_db)

        self._length_locked = False
        self._bin_count = _DEFAULT_BIN_COUNT
        self._bins: tuple[float, ...] | None = None
        self._streaks: dict[int, int] = {}
        self._candidates: set[int] = set()
        self._current_peaks: list[FeedbackPeak] = []
        self._last_auto_frame: int | None = None

        self._notches: dict[int, _NotchState] = {}
        self._next_notch_id = 1

        self._frames = 0
        self._confirmed = 0
        self._allocated = 0
        self._released = 0
        self._rejections = 0

    @property
    def _bin_width(self) -> float:
        return self.sample_rate / 2.0 / self._bin_count

    def set_sample_rate(self, rate):
        rate = _require_int(rate, "INVALID_SAMPLE_RATE", minimum=1)
        with self._lock:
            if rate != self.sample_rate:
                self.sample_rate = rate
                self._discard_old_frame()
            return self._bin_width

    def feed_spectrum(self, bins):
        with self._lock:
            try:
                values = tuple(float(value) for value in bins)
            except (TypeError, ValueError, OverflowError):
                raise FeedbackError("SPECTRUM_INVALID", bins) from None

            if not values:
                raise FeedbackError("SPECTRUM_LENGTH", len(values))
            if not all(math.isfinite(value) for value in values):
                raise FeedbackError("SPECTRUM_INVALID", "non-finite value")

            if not self._length_locked:
                self._bin_count = len(values)
                self._length_locked = True
            elif len(values) != self._bin_count:
                raise FeedbackError(
                    "SPECTRUM_LENGTH",
                    {"expected": self._bin_count, "actual": len(values)},
                )

            frame_index = self._frames
            self._frames += 1
            self._bins = values
            self._update_detection_history(values)
            self._update_notch_activity()
            self._last_auto_frame = None
            return frame_index

    def detect_feedback(self):
        with self._lock:
            peaks = list(self._current_peaks)
            frame_index = self._frames - 1
            if (
                peaks
                and frame_index >= 0
                and self._last_auto_frame != frame_index
            ):
                self._last_auto_frame = frame_index
                for peak in peaks:
                    if peak.confirmed:
                        self._allocate_locked(
                            peak.freq_hz,
                            self.ceiling_db,
                            merge_near=True,
                            active=True,
                            raise_on_reject=False,
                        )
            return peaks

    def allocate_notch(self, freq_hz, depth_db=None):
        freq = _require_number(freq_hz, "INVALID_FREQUENCY")
        with self._lock:
            if freq < 0.0 or freq >= self.sample_rate / 2.0:
                raise FeedbackError("INVALID_FREQUENCY", freq_hz)
            depth = self.ceiling_db if depth_db is None else _require_number(
                depth_db, "INVALID_DEPTH"
            )
            if depth >= 0.0 or depth < -_MAX_ATTENUATION_DB:
                raise FeedbackError("INVALID_DEPTH", depth_db)
            return self._allocate_locked(
                freq,
                depth,
                merge_near=self._length_locked,
                active=False,
                raise_on_reject=True,
            )

    def release_notch(self, notch_id):
        if isinstance(notch_id, bool) or not isinstance(notch_id, int):
            return False
        with self._lock:
            if notch_id not in self._notches:
                return False
            del self._notches[notch_id]
            self._released += 1
            return True

    def set_ceiling(self, ceiling_db):
        ceiling = _require_ceiling(ceiling_db)
        with self._lock:
            self.ceiling_db = ceiling
            return ceiling

    def set_hold_ms(self, ms):
        hold = _require_hold_ms(ms)
        with self._lock:
            self.hold_ms = hold
            return hold

    def advance_time(self, ms):
        if isinstance(ms, bool) or not isinstance(ms, (int, float)):
            raise FeedbackError("INVALID_TIME", ms)
        if not math.isfinite(float(ms)) or float(ms) < 0.0:
            raise FeedbackError("INVALID_TIME", ms)
        elapsed_ms = int(ms)

        with self._lock:
            released_ids = []
            for notch_id, notch in self._notches.items():
                if notch.active:
                    continue
                notch.remaining_ms -= elapsed_ms
                if notch.remaining_ms <= 0:
                    released_ids.append(notch_id)
            for notch_id in released_ids:
                del self._notches[notch_id]
            self._released += len(released_ids)
            return len(released_ids)

    def notch_table(self):
        with self._lock:
            notches = [
                NotchFilter(
                    notch_id=notch.notch_id,
                    freq_hz=notch.freq_hz,
                    depth_db=notch.depth_db,
                    bandwidth_hz=notch.bandwidth_hz,
                    remaining_ms=max(0, notch.remaining_ms),
                )
                for notch in self._notches.values()
            ]
            return sorted(notches, key=lambda notch: (notch.freq_hz, notch.notch_id))

    def stats(self):
        with self._lock:
            return {
                "frames": self._frames,
                "confirmed": self._confirmed,
                "allocated": self._allocated,
                "released": self._released,
                "rejections": self._rejections,
                "sample_rate": self.sample_rate,
                "ceiling_db": self.ceiling_db,
            }

    def snapshot(self):
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "sample_rate": self.sample_rate,
                "detect_floor": self.detect_floor,
                "notch_cap": self.notch_cap,
                "hold_ms": self.hold_ms,
                "ceiling_db": self.ceiling_db,
                "length_locked": self._length_locked,
                "bin_count": self._bin_count,
                "bins": None if self._bins is None else list(self._bins),
                "streaks": [
                    {"bin_index": bin_index, "count": count}
                    for bin_index, count in sorted(self._streaks.items())
                ],
                "candidates": sorted(self._candidates),
                "peaks": [
                    {
                        "freq_hz": peak.freq_hz,
                        "confidence": peak.confidence,
                        "bin_index": peak.bin_index,
                        "confirmed": peak.confirmed,
                    }
                    for peak in self._current_peaks
                ],
                "last_auto_frame": self._last_auto_frame,
                "next_notch_id": self._next_notch_id,
                "notches": [
                    {
                        "notch_id": notch.notch_id,
                        "freq_hz": notch.freq_hz,
                        "depth_db": notch.depth_db,
                        "bandwidth_hz": notch.bandwidth_hz,
                        "remaining_ms": notch.remaining_ms,
                        "active": notch.active,
                    }
                    for notch in sorted(
                        self._notches.values(),
                        key=lambda item: (item.freq_hz, item.notch_id),
                    )
                ],
                "counters": {
                    "frames": self._frames,
                    "confirmed": self._confirmed,
                    "allocated": self._allocated,
                    "released": self._released,
                    "rejections": self._rejections,
                },
            }

    def restore(self, state):
        restored = self._validate_snapshot(state)
        with self._lock:
            self.sample_rate = restored["sample_rate"]
            self.detect_floor = restored["detect_floor"]
            self.notch_cap = restored["notch_cap"]
            self.hold_ms = restored["hold_ms"]
            self.ceiling_db = restored["ceiling_db"]
            self._length_locked = restored["length_locked"]
            self._bin_count = restored["bin_count"]
            self._bins = restored["bins"]
            self._streaks = restored["streaks"]
            self._candidates = restored["candidates"]
            self._current_peaks = restored["peaks"]
            self._last_auto_frame = restored["last_auto_frame"]
            self._next_notch_id = restored["next_notch_id"]
            self._notches = restored["notches"]
            self._frames = restored["counters"]["frames"]
            self._confirmed = restored["counters"]["confirmed"]
            self._allocated = restored["counters"]["allocated"]
            self._released = restored["counters"]["released"]
            self._rejections = restored["counters"]["rejections"]

    def _discard_old_frame(self) -> None:
        self._bins = None
        self._streaks.clear()
        self._candidates.clear()
        self._current_peaks = []
        self._last_auto_frame = None
        for notch in self._notches.values():
            notch.active = False

    def _update_detection_history(self, bins: tuple[float, ...]) -> None:
        candidates = self._find_candidates(bins)
        updated_streaks: dict[int, int] = {}
        for bin_index in candidates:
            count = min(3, self._streaks.get(bin_index, 0) + 1)
            updated_streaks[bin_index] = count
            if count == 3:
                self._confirmed += 1

        self._candidates = candidates
        self._streaks = updated_streaks
        self._current_peaks = [
            FeedbackPeak(
                freq_hz=bin_index * self._bin_width,
                confidence=round(self._streaks[bin_index] / 3.0, 2),
                bin_index=bin_index,
                confirmed=self._streaks[bin_index] >= 3,
            )
            for bin_index in sorted(candidates)
        ]

    def _find_candidates(self, bins: tuple[float, ...]) -> set[int]:
        candidates: set[int] = set()
        for bin_index in range(2, len(bins) - 2):
            value = bins[bin_index]
            if value < self.detect_floor:
                continue
            if value <= bins[bin_index - 1] or value <= bins[bin_index + 1]:
                continue
            neighbor_mean = (
                bins[bin_index - 2]
                + bins[bin_index - 1]
                + bins[bin_index + 1]
                + bins[bin_index + 2]
            ) / 4.0
            if value >= neighbor_mean * 4.0:
                candidates.add(bin_index)
        return candidates

    def _update_notch_activity(self) -> None:
        for notch in self._notches.values():
            tolerance = notch.bandwidth_hz / 2.0 + self._bin_width / 2.0
            active = any(
                abs(bin_index * self._bin_width - notch.freq_hz) <= tolerance
                for bin_index in self._candidates
            )
            notch.active = active
            if active:
                notch.remaining_ms = self.hold_ms

    def _allocate_locked(
        self,
        freq_hz: float,
        depth_db: float,
        *,
        merge_near: bool,
        active: bool,
        raise_on_reject: bool,
    ) -> int:
        target = self._find_merge_target(freq_hz, merge_near)
        if target is not None:
            bandwidth = max(
                target.bandwidth_hz,
                abs(freq_hz - target.freq_hz) + self._bin_width,
            )
            depth = min(target.depth_db, depth_db)
            replacement = _NotchState(
                notch_id=target.notch_id,
                freq_hz=target.freq_hz,
                depth_db=depth,
                bandwidth_hz=bandwidth,
                remaining_ms=self.hold_ms,
                active=active or target.active,
            )
            candidate_notches = [
                replacement if item is target else item
                for item in self._notches.values()
            ]
            if self._maximum_response(candidate_notches) > _MAX_ATTENUATION_DB + 1e-9:
                return self._reject(
                    "TOTAL_ATTENUATION",
                    "combined notch response exceeds 24 dB",
                    raise_on_reject,
                )
            self._notches[target.notch_id] = replacement
            return target.notch_id

        if len(self._notches) >= self.notch_cap:
            return self._reject(
                "NOTCH_CAPACITY",
                self.notch_cap,
                raise_on_reject,
            )

        notch_id = self._next_notch_id
        new_notch = _NotchState(
            notch_id=notch_id,
            freq_hz=freq_hz,
            depth_db=depth_db,
            bandwidth_hz=max(self._bin_width, 1e-9),
            remaining_ms=self.hold_ms,
            active=active,
        )
        candidate_notches = list(self._notches.values()) + [new_notch]
        if self._maximum_response(candidate_notches) > _MAX_ATTENUATION_DB + 1e-9:
            return self._reject(
                "TOTAL_ATTENUATION",
                "combined notch response exceeds 24 dB",
                raise_on_reject,
            )

        self._notches[notch_id] = new_notch
        self._next_notch_id += 1
        self._allocated += 1
        return notch_id

    def _find_merge_target(
        self, freq_hz: float, merge_near: bool
    ) -> _NotchState | None:
        nearest: _NotchState | None = None
        nearest_distance = math.inf
        for notch in self._notches.values():
            distance = abs(freq_hz - notch.freq_hz)
            tolerance = 1e-9
            if merge_near:
                tolerance = max(
                    tolerance,
                    self._bin_width * 1.25,
                    notch.bandwidth_hz / 2.0 + self._bin_width / 2.0,
                )
            if distance <= tolerance and distance < nearest_distance:
                nearest = notch
                nearest_distance = distance
        return nearest

    def _reject(
        self, code: str, detail: object, raise_on_reject: bool
    ) -> int:
        self._rejections += 1
        if raise_on_reject:
            raise FeedbackError(code, detail)
        return -1

    @staticmethod
    def _maximum_response(notches: list[_NotchState]) -> float:
        if not notches:
            return 0.0

        centers = [notch.freq_hz for notch in notches]
        points = list(centers)
        points.extend(
            (left + right) / 2.0
            for index, left in enumerate(centers)
            for right in centers[index + 1:]
        )
        low = min(centers)
        high = max(centers)
        if high > low:
            points.extend(
                low + (high - low) * step / 256.0 for step in range(257)
            )

        maximum = 0.0
        for freq_hz in points:
            total = 0.0
            for notch in notches:
                offset = 2.0 * (freq_hz - notch.freq_hz) / notch.bandwidth_hz
                total += abs(notch.depth_db) / (1.0 + offset * offset)
            maximum = max(maximum, total)
        return maximum

    def _validate_snapshot(self, state: object) -> dict:
        try:
            if not isinstance(state, dict):
                raise ValueError
            if state.get("version") != _SNAPSHOT_VERSION:
                raise ValueError

            required = {
                "sample_rate",
                "detect_floor",
                "notch_cap",
                "hold_ms",
                "ceiling_db",
                "length_locked",
                "bin_count",
                "bins",
                "streaks",
                "candidates",
                "peaks",
                "last_auto_frame",
                "next_notch_id",
                "notches",
                "counters",
            }
            if not required.issubset(state):
                raise ValueError

            sample_rate = _require_int(
                state["sample_rate"], "INVALID_SAMPLE_RATE", minimum=1
            )
            detect_floor = _require_number(
                state["detect_floor"], "INVALID_DETECT_FLOOR"
            )
            if detect_floor < 0.0:
                raise ValueError
            notch_cap = _require_int(
                state["notch_cap"], "INVALID_NOTCH_CAP", minimum=1
            )
            hold_ms = _require_hold_ms(state["hold_ms"])
            ceiling_db = _require_ceiling(state["ceiling_db"])

            length_locked = state["length_locked"]
            if not isinstance(length_locked, bool):
                raise ValueError
            bin_count = _require_int(
                state["bin_count"], "INVALID_BIN_COUNT", minimum=1
            )

            raw_bins = state["bins"]
            if raw_bins is None:
                bins = None
            else:
                if not isinstance(raw_bins, (list, tuple)):
                    raise ValueError
                bins = tuple(float(value) for value in raw_bins)
                if len(bins) != bin_count or not all(
                    math.isfinite(value) for value in bins
                ):
                    raise ValueError
                if not length_locked:
                    raise ValueError
            if not length_locked and bins is not None:
                raise ValueError

            raw_streaks = state["streaks"]
            if not isinstance(raw_streaks, list):
                raise ValueError
            streaks: dict[int, int] = {}
            for item in raw_streaks:
                if not isinstance(item, dict):
                    raise ValueError
                bin_index = _require_int(
                    item.get("bin_index"), "INVALID_BIN_INDEX", minimum=0
                )
                count = _require_int(
                    item.get("count"), "INVALID_STREAK", minimum=1
                )
                if count > 3 or bin_index >= bin_count or bin_index in streaks:
                    raise ValueError
                streaks[bin_index] = count

            raw_candidates = state["candidates"]
            if not isinstance(raw_candidates, list):
                raise ValueError
            candidates = {
                _require_int(value, "INVALID_BIN_INDEX", minimum=0)
                for value in raw_candidates
            }
            if len(candidates) != len(raw_candidates):
                raise ValueError
            if any(
                bin_index >= bin_count or bin_index not in streaks
                for bin_index in candidates
            ):
                raise ValueError

            raw_peaks = state["peaks"]
            if not isinstance(raw_peaks, list):
                raise ValueError
            peaks = []
            seen_peak_bins: set[int] = set()
            bin_width = sample_rate / 2.0 / bin_count
            for item in raw_peaks:
                if not isinstance(item, dict):
                    raise ValueError
                bin_index = _require_int(
                    item.get("bin_index"), "INVALID_BIN_INDEX", minimum=0
                )
                freq_hz = _require_number(item.get("freq_hz"), "SNAPSHOT_INVALID")
                confidence = _require_number(
                    item.get("confidence"), "SNAPSHOT_INVALID"
                )
                confirmed = item.get("confirmed")
                if (
                    bin_index >= bin_count
                    or bin_index in seen_peak_bins
                    or bin_index not in candidates
                    or not math.isclose(
                        freq_hz, bin_index * bin_width, rel_tol=0.0, abs_tol=1e-9
                    )
                    or not math.isclose(
                        confidence,
                        round(streaks[bin_index] / 3.0, 2),
                        rel_tol=0.0,
                        abs_tol=1e-9,
                    )
                    or not isinstance(confirmed, bool)
                    or confirmed != (streaks[bin_index] >= 3)
                ):
                    raise ValueError
                seen_peak_bins.add(bin_index)
                peaks.append(
                    FeedbackPeak(
                        freq_hz=freq_hz,
                        confidence=confidence,
                        bin_index=bin_index,
                        confirmed=confirmed,
                    )
                )
            if seen_peak_bins != candidates:
                raise ValueError

            last_auto_frame = state["last_auto_frame"]
            if last_auto_frame is not None:
                last_auto_frame = _require_int(
                    last_auto_frame, "SNAPSHOT_INVALID", minimum=0
                )

            raw_notches = state["notches"]
            if not isinstance(raw_notches, list):
                raise ValueError
            notches: dict[int, _NotchState] = {}
            for item in raw_notches:
                if not isinstance(item, dict):
                    raise ValueError
                notch_id = _require_int(
                    item.get("notch_id"), "SNAPSHOT_INVALID", minimum=1
                )
                freq_hz = _require_number(item.get("freq_hz"), "SNAPSHOT_INVALID")
                depth_db = _require_number(item.get("depth_db"), "SNAPSHOT_INVALID")
                bandwidth_hz = _require_number(
                    item.get("bandwidth_hz"), "SNAPSHOT_INVALID"
                )
                remaining_ms = _require_int(
                    item.get("remaining_ms"), "SNAPSHOT_INVALID", minimum=0
                )
                active = item.get("active")
                if (
                    notch_id in notches
                    or freq_hz < 0.0
                    or not -_MAX_ATTENUATION_DB <= depth_db < 0.0
                    or bandwidth_hz <= 0.0
                    or not isinstance(active, bool)
                ):
                    raise ValueError
                notches[notch_id] = _NotchState(
                    notch_id=notch_id,
                    freq_hz=freq_hz,
                    depth_db=depth_db,
                    bandwidth_hz=bandwidth_hz,
                    remaining_ms=remaining_ms,
                    active=active,
                )
            if (
                len(notches) > notch_cap
                or self._maximum_response(list(notches.values()))
                > _MAX_ATTENUATION_DB + 1e-9
            ):
                raise ValueError

            next_notch_id = _require_int(
                state["next_notch_id"], "SNAPSHOT_INVALID", minimum=1
            )
            if notches and next_notch_id <= max(notches):
                raise ValueError

            raw_counters = state["counters"]
            if not isinstance(raw_counters, dict):
                raise ValueError
            counter_names = {
                "frames",
                "confirmed",
                "allocated",
                "released",
                "rejections",
            }
            if set(raw_counters) != counter_names:
                raise ValueError
            counters = {
                name: _require_int(
                    raw_counters[name], "SNAPSHOT_INVALID", minimum=0
                )
                for name in counter_names
            }
            if counters["allocated"] < len(notches):
                raise ValueError

            return {
                "sample_rate": sample_rate,
                "detect_floor": detect_floor,
                "notch_cap": notch_cap,
                "hold_ms": hold_ms,
                "ceiling_db": ceiling_db,
                "length_locked": length_locked,
                "bin_count": bin_count,
                "bins": bins,
                "streaks": streaks,
                "candidates": candidates,
                "peaks": peaks,
                "last_auto_frame": last_auto_frame,
                "next_notch_id": next_notch_id,
                "notches": notches,
                "counters": counters,
            }
        except FeedbackError:
            raise FeedbackError("SNAPSHOT_INVALID", "malformed snapshot") from None
        except (TypeError, ValueError, KeyError, OverflowError):
            raise FeedbackError("SNAPSHOT_INVALID", "malformed snapshot") from None
