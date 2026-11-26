"""Pitch correction planning for vocal takes.

The planner keeps one pitch track per take, snaps voiced frames onto the
degrees of a scale, derives a correction curve with a bounded rate of change
and records which frame ranges were already committed.
"""

from __future__ import annotations

import math
import threading
from dataclasses import dataclass, replace
from numbers import Integral, Real

__all__ = [
    "PitchError",
    "TakeSpec",
    "PitchFrame",
    "CorrectionPoint",
    "CorrectionPlan",
    "PitchCorrectionPlanner",
]


class PitchError(ValueError):
    """Raised when the planner refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TakeSpec:
    """Registered vocal take and its analysis parameters."""

    take_id: str
    sample_rate: int
    hop: int
    frame_count: int
    root: int
    mode: str
    preserve_formant: bool


@dataclass(frozen=True)
class PitchFrame:
    """One analyzed frame with its pitch estimate in MIDI semitones."""

    index: int
    pitch: float
    confidence: float
    voiced: bool


@dataclass(frozen=True)
class CorrectionPoint:
    """One planned correction of a frame."""

    frame: int
    source_pitch: float
    target_pitch: float
    shift: float
    applied_shift: float


@dataclass(frozen=True)
class CorrectionPlan:
    """Summary of a planned correction curve."""

    take_id: str
    points: int
    max_shift: float
    scale: tuple[int, ...]


_SCALE_INTERVALS = {
    "major": (0, 2, 4, 5, 7, 9, 11),
    "minor": (0, 2, 3, 5, 7, 8, 10),
}

_COUNTER_KEYS = (
    "takes",
    "analyzed",
    "voiced",
    "planned",
    "committed",
    "refuses",
)


def _is_int(value: object) -> bool:
    return isinstance(value, Integral) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return isinstance(value, Real) and not isinstance(value, bool)


def _finite_number(value: object) -> bool:
    if not _is_number(value):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, TypeError, ValueError):
        return False


class PitchCorrectionPlanner:
    """Plan scale snapping and rate limited pitch correction for takes."""

    def __init__(self, *, hop: int = 256, sample_rate: int = 48000,
                 confidence_floor: float = 0.5,
                 max_semitones_per_second: float = 1.5,
                 max_frames: int = 4096) -> None:
        if not _is_int(hop) or hop <= 0:
            raise PitchError("PITCH_INVALID_REQUEST", "hop must be positive")
        if not _is_int(sample_rate) or sample_rate <= 0:
            raise PitchError(
                "PITCH_INVALID_REQUEST", "sample_rate must be positive")
        if not _finite_number(confidence_floor) or not 0.0 <= float(
                confidence_floor) <= 1.0:
            raise PitchError(
                "PITCH_INVALID_REQUEST",
                "confidence_floor must be between 0 and 1",
            )
        if (not _finite_number(max_semitones_per_second)
                or float(max_semitones_per_second) < 0.0):
            raise PitchError(
                "PITCH_INVALID_REQUEST",
                "max_semitones_per_second must not be negative",
            )
        if not _is_int(max_frames) or max_frames <= 0:
            raise PitchError(
                "PITCH_INVALID_REQUEST", "max_frames must be positive")

        self.hop = int(hop)
        self.sample_rate = int(sample_rate)
        self.confidence_floor = float(confidence_floor)
        self.max_semitones_per_second = float(max_semitones_per_second)
        self.max_frames = int(max_frames)
        self._lock = threading.RLock()
        self._takes: dict[str, TakeSpec] = {}
        self._frames: dict[str, tuple[PitchFrame, ...]] = {}
        self._scales: dict[str, tuple[int, ...]] = {}
        self._curves: dict[str, tuple[CorrectionPoint, ...]] = {}
        self._committed: dict[str, tuple[tuple[int, int], ...]] = {}
        self._analyzed: set[str] = set()
        self._counters = {key: 0 for key in _COUNTER_KEYS}

    @staticmethod
    def _scale_for(root: int, mode: str) -> tuple[int, ...]:
        return tuple(sorted((root + interval) % 12
                            for interval in _SCALE_INTERVALS[mode]))

    def _refuse(self, code: str, detail: object = None) -> None:
        self._counters["refuses"] += 1
        raise PitchError(code, detail)

    def _take(self, take_id: str) -> TakeSpec:
        if not isinstance(take_id, str) or not take_id:
            self._refuse("PITCH_INVALID_REQUEST", "invalid take id")
        try:
            return self._takes[take_id]
        except KeyError:
            self._refuse("PITCH_INVALID_REQUEST", f"unknown take: {take_id!r}")
            raise AssertionError("unreachable")

    @staticmethod
    def _nearest_scale_pitch(pitch: float,
                             scale: tuple[int, ...]) -> int:
        base_octave = math.floor(pitch) // 12
        candidates = (
            (base_octave + octave_offset) * 12 + pitch_class
            for octave_offset in (-1, 0, 1)
            for pitch_class in scale
        )
        return min(candidates, key=lambda note: (abs(note - pitch), note))

    def register_take(self, take_id: str, sample_rate: int, *,
                      hop: int | None = None,
                      preserve_formant: bool = True) -> TakeSpec:
        """Register a take with its sample rate and frame hop."""
        with self._lock:
            if not isinstance(take_id, str) or not take_id:
                self._refuse("PITCH_INVALID_REQUEST", "invalid take id")
            if take_id in self._takes:
                self._refuse("PITCH_DUPLICATE_TAKE", take_id)
            if not _is_int(sample_rate) or sample_rate <= 0:
                self._refuse(
                    "PITCH_INVALID_REQUEST", "sample_rate must be positive")

            actual_hop = self.hop if hop is None else hop
            if not _is_int(actual_hop) or actual_hop <= 0:
                self._refuse("PITCH_INVALID_REQUEST", "hop must be positive")
            if not isinstance(preserve_formant, bool):
                self._refuse(
                    "PITCH_INVALID_REQUEST", "preserve_formant must be bool")

            spec = TakeSpec(
                take_id=take_id,
                sample_rate=int(sample_rate),
                hop=int(actual_hop),
                frame_count=0,
                root=0,
                mode="major",
                preserve_formant=preserve_formant,
            )
            self._takes[take_id] = spec
            self._scales[take_id] = self._scale_for(0, "major")
            self._curves[take_id] = ()
            self._committed[take_id] = ()
            self._counters["takes"] += 1
            return spec

    def analyze_pitch(self, take_id: str,
                      frames: list[tuple[float, float]]) -> int:
        """Store per frame pitch estimates and return the voiced count."""
        with self._lock:
            spec = self._take(take_id)

            if frames is None or isinstance(frames, (str, bytes)):
                self._refuse("PITCH_INVALID_FRAME", "frames must be a sequence")
            try:
                raw_frames = list(frames)
            except TypeError:
                self._refuse("PITCH_INVALID_FRAME", "frames must be a sequence")

            if len(raw_frames) > self.max_frames:
                self._refuse(
                    "PITCH_INVALID_REQUEST",
                    f"frame count exceeds {self.max_frames}",
                )

            parsed: list[PitchFrame] = []
            voiced_count = 0
            for index, frame in enumerate(raw_frames):
                if not isinstance(frame, (tuple, list)) or len(frame) != 2:
                    self._refuse(
                        "PITCH_INVALID_FRAME",
                        f"frame {index} must be a (pitch, confidence) pair",
                    )
                pitch, confidence = frame
                if (not _finite_number(pitch)
                        or not _finite_number(confidence)
                        or float(pitch) < 0.0
                        or not 0.0 <= float(confidence) <= 1.0):
                    self._refuse(
                        "PITCH_INVALID_FRAME", f"invalid frame at index {index}")

                pitch_value = float(pitch)
                confidence_value = float(confidence)
                voiced = confidence_value >= self.confidence_floor
                if voiced:
                    voiced_count += 1
                parsed.append(PitchFrame(
                    index=index,
                    pitch=pitch_value,
                    confidence=confidence_value,
                    voiced=voiced,
                ))

            self._takes[take_id] = replace(spec, frame_count=len(parsed))
            self._frames[take_id] = tuple(parsed)
            self._analyzed.add(take_id)
            self._curves[take_id] = ()
            self._committed[take_id] = ()
            self._counters["analyzed"] += 1
            self._counters["voiced"] += voiced_count
            return voiced_count

    def set_scale(self, take_id: str, root: int,
                  mode: str = "major") -> tuple[int, ...]:
        """Select the scale used to snap voiced frames."""
        with self._lock:
            spec = self._take(take_id)
            if not isinstance(mode, str) or mode not in _SCALE_INTERVALS:
                self._refuse("PITCH_INVALID_MODE", mode)
            if not _is_int(root) or not 0 <= root <= 11:
                self._refuse(
                    "PITCH_INVALID_REQUEST", "root must be between 0 and 11")

            scale = self._scale_for(int(root), mode)
            self._takes[take_id] = replace(spec, root=int(root), mode=mode)
            self._scales[take_id] = scale
            return scale

    def plan_correction(self, take_id: str) -> CorrectionPlan:
        """Derive the correction curve of an analyzed take."""
        with self._lock:
            spec = self._take(take_id)
            if take_id not in self._analyzed:
                self._refuse("PITCH_NOT_ANALYZED", take_id)

            frames = self._frames[take_id]
            scale = self._scales[take_id]
            max_step = (
                self.max_semitones_per_second
                * spec.hop
                / spec.sample_rate
            )

            points: list[CorrectionPoint] = []
            previous_applied = 0.0
            max_shift = 0.0
            for frame in frames:
                if not frame.voiced:
                    previous_applied = 0.0
                    continue

                target = float(self._nearest_scale_pitch(frame.pitch, scale))
                shift = target - frame.pitch
                applied = min(
                    max(shift, previous_applied - max_step),
                    previous_applied + max_step,
                )
                points.append(CorrectionPoint(
                    frame=frame.index,
                    source_pitch=frame.pitch,
                    target_pitch=target,
                    shift=shift,
                    applied_shift=applied,
                ))
                previous_applied = applied
                max_shift = max(max_shift, abs(shift))

            curve = tuple(points)
            self._curves[take_id] = curve
            self._counters["planned"] += 1
            return CorrectionPlan(
                take_id=take_id,
                points=len(curve),
                max_shift=max_shift,
                scale=scale,
            )

    def correction_curve(self, take_id: str) -> tuple[CorrectionPoint, ...]:
        """Return the planned correction points of a take."""
        with self._lock:
            self._take(take_id)
            return self._curves.get(take_id, ())

    def apply_segment(self, take_id: str, start_frame: int,
                      end_frame: int) -> int:
        """Commit the correction of a frame range and return its length."""
        with self._lock:
            spec = self._take(take_id)
            if take_id not in self._analyzed:
                self._refuse("PITCH_NOT_ANALYZED", take_id)
            if (not _is_int(start_frame) or not _is_int(end_frame)
                    or start_frame < 0 or end_frame <= start_frame
                    or end_frame > spec.frame_count):
                self._refuse(
                    "PITCH_INVALID_REQUEST",
                    "frame range must be ordered and within the take",
                )

            intervals = self._committed.get(take_id, ())
            for old_start, old_end in intervals:
                if start_frame < old_end and end_frame > old_start:
                    self._refuse(
                        "PITCH_ALREADY_COMMITTED",
                        (start_frame, end_frame),
                    )

            self._committed[take_id] = tuple(sorted(
                intervals + ((start_frame, end_frame),)))
            length = end_frame - start_frame
            self._counters["committed"] += length
            return length

    def committed_frames(self, take_id: str) -> int:
        """Return how many frames of a take are already committed."""
        with self._lock:
            self._take(take_id)
            return sum(end - start
                       for start, end in self._committed.get(take_id, ()))

    def take_of(self, take_id: str) -> TakeSpec:
        """Return the registered specification of one take."""
        with self._lock:
            return self._take(take_id)

    def confidence_at(self, take_id: str, index: int) -> float:
        """Return the confidence of one analyzed frame."""
        with self._lock:
            self._take(take_id)
            if take_id not in self._analyzed:
                self._refuse("PITCH_NOT_ANALYZED", take_id)
            frames = self._frames[take_id]
            if not _is_int(index) or not 0 <= index < len(frames):
                self._refuse("PITCH_INVALID_FRAME", index)
            return frames[int(index)].confidence

    def stats(self) -> dict:
        """Return cumulative planner counters."""
        with self._lock:
            return {key: self._counters[key] for key in _COUNTER_KEYS}

    def snapshot(self) -> dict:
        """Return a deep copy of takes, frames, curves and counters."""
        with self._lock:
            takes = {
                take_id: {
                    "take_id": spec.take_id,
                    "sample_rate": spec.sample_rate,
                    "hop": spec.hop,
                    "frame_count": spec.frame_count,
                    "root": spec.root,
                    "mode": spec.mode,
                    "preserve_formant": spec.preserve_formant,
                }
                for take_id, spec in self._takes.items()
            }
            frames = {
                take_id: [
                    {
                        "index": frame.index,
                        "pitch": frame.pitch,
                        "confidence": frame.confidence,
                        "voiced": frame.voiced,
                    }
                    for frame in frames_for_take
                ]
                for take_id, frames_for_take in self._frames.items()
            }
            scales = {
                take_id: list(scale)
                for take_id, scale in self._scales.items()
            }
            curves = {
                take_id: [
                    {
                        "frame": point.frame,
                        "source_pitch": point.source_pitch,
                        "target_pitch": point.target_pitch,
                        "shift": point.shift,
                        "applied_shift": point.applied_shift,
                    }
                    for point in curve
                ]
                for take_id, curve in self._curves.items()
            }
            committed = {
                take_id: [[start, end] for start, end in intervals]
                for take_id, intervals in self._committed.items()
            }
            return {
                "version": 1,
                "takes": takes,
                "frames": frames,
                "scales": scales,
                "curves": curves,
                "committed": committed,
                "analyzed": sorted(self._analyzed),
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        """Replace planner state from a snapshot, validating its structure."""
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except Exception as exc:
                raise PitchError("PITCH_SNAPSHOT_INVALID", str(exc)) from None

            (takes, frames, scales, curves, committed,
             analyzed, counters) = parsed
            self._takes = takes
            self._frames = frames
            self._scales = scales
            self._curves = curves
            self._committed = committed
            self._analyzed = analyzed
            self._counters = counters

    def _parse_snapshot(self, state: dict) -> tuple:
        if not isinstance(state, dict):
            raise ValueError("snapshot must be a dict")
        if state.get("version") != 1:
            raise ValueError("unsupported snapshot version")

        raw_takes = state.get("takes")
        raw_frames = state.get("frames")
        raw_scales = state.get("scales")
        raw_curves = state.get("curves")
        raw_committed = state.get("committed")
        raw_analyzed = state.get("analyzed")
        raw_counters = state.get("counters")
        for name, value in (
                ("takes", raw_takes),
                ("frames", raw_frames),
                ("scales", raw_scales),
                ("curves", raw_curves),
                ("committed", raw_committed),
                ("counters", raw_counters)):
            if not isinstance(value, dict):
                raise ValueError(f"{name} must be a dict")
        if not isinstance(raw_analyzed, list):
            raise ValueError("analyzed must be a list")

        takes: dict[str, TakeSpec] = {}
        for take_id, raw_spec in raw_takes.items():
            if not isinstance(take_id, str) or not take_id:
                raise ValueError("invalid take id")
            if not isinstance(raw_spec, dict):
                raise ValueError(f"take {take_id!r} must be a dict")
            if raw_spec.get("take_id") != take_id:
                raise ValueError(f"take id mismatch for {take_id!r}")

            sample_rate = raw_spec.get("sample_rate")
            hop = raw_spec.get("hop")
            frame_count = raw_spec.get("frame_count")
            root = raw_spec.get("root")
            mode = raw_spec.get("mode")
            preserve_formant = raw_spec.get("preserve_formant")
            if not _is_int(sample_rate) or sample_rate <= 0:
                raise ValueError(f"invalid sample rate for {take_id!r}")
            if not _is_int(hop) or hop <= 0:
                raise ValueError(f"invalid hop for {take_id!r}")
            if not _is_int(frame_count) or frame_count < 0:
                raise ValueError(f"invalid frame count for {take_id!r}")
            if frame_count > self.max_frames:
                raise ValueError(f"frame count exceeds limit for {take_id!r}")
            if not _is_int(root) or not 0 <= root <= 11:
                raise ValueError(f"invalid root for {take_id!r}")
            if not isinstance(mode, str) or mode not in _SCALE_INTERVALS:
                raise ValueError(f"invalid mode for {take_id!r}")
            if not isinstance(preserve_formant, bool):
                raise ValueError(f"invalid preserve_formant for {take_id!r}")

            takes[take_id] = TakeSpec(
                take_id=take_id,
                sample_rate=int(sample_rate),
                hop=int(hop),
                frame_count=int(frame_count),
                root=int(root),
                mode=mode,
                preserve_formant=preserve_formant,
            )

        take_ids = set(takes)
        if set(raw_scales) != take_ids:
            raise ValueError("scales must cover every take")
        scales: dict[str, tuple[int, ...]] = {}
        for take_id, raw_scale in raw_scales.items():
            if not isinstance(raw_scale, (list, tuple)):
                raise ValueError(f"invalid scale for {take_id!r}")
            if any(not _is_int(pitch_class)
                   or not 0 <= pitch_class <= 11
                   for pitch_class in raw_scale):
                raise ValueError(f"invalid scale for {take_id!r}")
            scale = tuple(int(pitch_class) for pitch_class in raw_scale)
            spec = takes[take_id]
            if scale != self._scale_for(spec.root, spec.mode):
                raise ValueError(f"scale does not match take {take_id!r}")
            scales[take_id] = scale

        analyzed: set[str] = set()
        for take_id in raw_analyzed:
            if not isinstance(take_id, str) or take_id not in take_ids:
                raise ValueError("analyzed contains an unknown take")
            if take_id in analyzed:
                raise ValueError("analyzed contains a duplicate take")
            analyzed.add(take_id)
        if set(raw_frames) != analyzed:
            raise ValueError("frames must cover exactly the analyzed takes")

        frames: dict[str, tuple[PitchFrame, ...]] = {}
        for take_id in raw_analyzed:
            raw_take_frames = raw_frames[take_id]
            if not isinstance(raw_take_frames, (list, tuple)):
                raise ValueError(f"invalid frames for {take_id!r}")
            spec = takes[take_id]
            if len(raw_take_frames) != spec.frame_count:
                raise ValueError(f"frame count mismatch for {take_id!r}")

            parsed_frames: list[PitchFrame] = []
            for index, raw_frame in enumerate(raw_take_frames):
                if not isinstance(raw_frame, dict):
                    raise ValueError(
                        f"invalid frame at {take_id!r}:{index}")
                frame_index = raw_frame.get("index")
                pitch = raw_frame.get("pitch")
                confidence = raw_frame.get("confidence")
                voiced = raw_frame.get("voiced")
                if frame_index != index:
                    raise ValueError(
                        f"frame index mismatch at {take_id!r}:{index}")
                if not _finite_number(pitch) or float(pitch) < 0.0:
                    raise ValueError(
                        f"invalid pitch at {take_id!r}:{index}")
                if (not _finite_number(confidence)
                        or not 0.0 <= float(confidence) <= 1.0):
                    raise ValueError(
                        f"invalid confidence at {take_id!r}:{index}")
                if not isinstance(voiced, bool):
                    raise ValueError(
                        f"invalid voiced flag at {take_id!r}:{index}")
                parsed_frames.append(PitchFrame(
                    index=index,
                    pitch=float(pitch),
                    confidence=float(confidence),
                    voiced=voiced,
                ))
            frames[take_id] = tuple(parsed_frames)

        if set(raw_curves) != take_ids:
            raise ValueError("curves must cover every take")
        curves: dict[str, tuple[CorrectionPoint, ...]] = {}
        for take_id, raw_curve in raw_curves.items():
            if not isinstance(raw_curve, (list, tuple)):
                raise ValueError(f"invalid curve for {take_id!r}")
            if raw_curve and take_id not in analyzed:
                raise ValueError(
                    f"curve exists for unanalyzed take {take_id!r}")

            parsed_points: list[CorrectionPoint] = []
            previous_frame = -1
            for raw_point in raw_curve:
                if not isinstance(raw_point, dict):
                    raise ValueError(f"invalid point for {take_id!r}")
                frame_index = raw_point.get("frame")
                source_pitch = raw_point.get("source_pitch")
                target_pitch = raw_point.get("target_pitch")
                shift = raw_point.get("shift")
                applied_shift = raw_point.get("applied_shift")
                if not _is_int(frame_index):
                    raise ValueError(f"invalid point frame for {take_id!r}")
                if frame_index <= previous_frame:
                    raise ValueError(
                        f"curve is not ordered for {take_id!r}")
                if not 0 <= frame_index < takes[take_id].frame_count:
                    raise ValueError(f"point frame out of range for {take_id!r}")
                if (not _finite_number(source_pitch)
                        or not _finite_number(target_pitch)
                        or not _finite_number(shift)
                        or not _finite_number(applied_shift)):
                    raise ValueError(f"invalid point value for {take_id!r}")

                frame = frames[take_id][frame_index]
                if not frame.voiced:
                    raise ValueError(
                        f"curve point on unvoiced frame for {take_id!r}")
                if float(source_pitch) != frame.pitch:
                    raise ValueError(
                        f"source pitch mismatch for {take_id!r}")
                if not math.isclose(
                        float(shift),
                        float(target_pitch) - float(source_pitch),
                        rel_tol=0.0,
                        abs_tol=1e-12):
                    raise ValueError(f"shift mismatch for {take_id!r}")

                parsed_points.append(CorrectionPoint(
                    frame=int(frame_index),
                    source_pitch=float(source_pitch),
                    target_pitch=float(target_pitch),
                    shift=float(shift),
                    applied_shift=float(applied_shift),
                ))
                previous_frame = int(frame_index)
            curves[take_id] = tuple(parsed_points)

        if set(raw_committed) != take_ids:
            raise ValueError("committed intervals must cover every take")
        committed: dict[str, tuple[tuple[int, int], ...]] = {}
        for take_id, raw_intervals in raw_committed.items():
            if not isinstance(raw_intervals, (list, tuple)):
                raise ValueError(f"invalid committed intervals for {take_id!r}")
            if raw_intervals and take_id not in analyzed:
                raise ValueError(
                    f"commits exist for unanalyzed take {take_id!r}")

            parsed_intervals: list[tuple[int, int]] = []
            previous_end = 0
            for raw_interval in raw_intervals:
                if (not isinstance(raw_interval, (list, tuple))
                        or len(raw_interval) != 2):
                    raise ValueError(
                        f"invalid committed interval for {take_id!r}")
                start, end = raw_interval
                if not _is_int(start) or not _is_int(end):
                    raise ValueError(
                        f"invalid committed interval for {take_id!r}")
                if start < previous_end or end <= start:
                    raise ValueError(
                        f"overlapping committed interval for {take_id!r}")
                if end > takes[take_id].frame_count:
                    raise ValueError(
                        f"committed interval out of range for {take_id!r}")
                parsed_intervals.append((int(start), int(end)))
                previous_end = int(end)
            committed[take_id] = tuple(parsed_intervals)

        counters: dict[str, int] = {}
        for key in _COUNTER_KEYS:
            value = raw_counters.get(key)
            if not _is_int(value) or value < 0:
                raise ValueError(f"invalid counter {key!r}")
            counters[key] = int(value)
        if counters["takes"] != len(takes):
            raise ValueError("take counter does not match takes")
        if counters["analyzed"] < len(analyzed):
            raise ValueError("analyzed counter is too small")
        current_voiced = sum(
            frame.voiced
            for take_frames in frames.values()
            for frame in take_frames
        )
        if counters["voiced"] < current_voiced:
            raise ValueError("voiced counter is too small")
        planned_takes = sum(1 for curve in curves.values() if curve)
        if counters["planned"] < planned_takes:
            raise ValueError("planned counter is too small")
        current_committed = sum(
            end - start
            for intervals in committed.values()
            for start, end in intervals
        )
        if counters["committed"] < current_committed:
            raise ValueError("committed counter is too small")

        return (takes, frames, scales, curves, committed,
                analyzed, counters)
