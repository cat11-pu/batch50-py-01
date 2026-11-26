"""Camera path smoothing and crop window keyframes for video stabilization.

The planner ingests per frame camera motion, smooths the accumulated path
inside a bounded window, derives a crop window for every frame, compresses
the crop track into keyframes and keeps a commit watermark so a restarted
process resumes from the last committed keyframe.
"""

from __future__ import annotations

import copy
import math
import threading
from dataclasses import dataclass, replace
from numbers import Integral, Real
from typing import NoReturn

__all__ = [
    "StabilizationError",
    "ClipSpec",
    "MotionSample",
    "CropWindow",
    "CropKeyframe",
    "StabilizationPlanner",
]


class StabilizationError(ValueError):
    """Raised when the planner refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ClipSpec:
    """Registered video clip and its stabilization parameters."""

    clip_id: str
    width: int
    height: int
    fps: int
    smooth_radius: int
    sample_count: int
    rolling_shutter: int


@dataclass(frozen=True)
class MotionSample:
    """One camera motion estimate between two frames."""

    index: int
    dx: float
    dy: float
    confidence: float


@dataclass(frozen=True)
class CropWindow:
    """One crop rectangle inside the source frame."""

    x: int
    y: int
    width: int
    height: int


@dataclass(frozen=True)
class CropKeyframe:
    """One keyframe of the compressed crop track."""

    index: int
    crop: CropWindow


@dataclass
class _ClipState:
    """Mutable planner state for one registered clip."""

    spec: ClipSpec
    motion: list[MotionSample]
    smooth_path: tuple[tuple[float, float], ...] | None = None
    crop_size: tuple[int, int] | None = None
    crops: tuple[CropWindow, ...] | None = None
    keyframe_indices: tuple[int, ...] = ()
    keyframe_interval: int | None = None
    watermark: int = -1


def _is_int(value: object) -> bool:
    return isinstance(value, Integral) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return isinstance(value, Real) and not isinstance(value, bool)


def _is_finite_number(value: object) -> bool:
    return _is_number(value) and math.isfinite(float(value))


def _round_coordinate(value: float) -> int:
    return int(math.floor(value + 0.5))


class StabilizationPlanner:
    """Plan crop windows from a smoothed camera path."""

    def __init__(self, *, smooth_radius: int = 8, max_samples: int = 4096,
                 min_confidence: float = 0.3,
                 max_scale: float = 1.25) -> None:
        if not _is_int(smooth_radius) or smooth_radius < 0:
            raise StabilizationError(
                "STAB_INVALID_REQUEST",
                {"smooth_radius": smooth_radius},
            )
        if not _is_int(max_samples) or max_samples <= 0:
            raise StabilizationError(
                "STAB_INVALID_REQUEST", {"max_samples": max_samples})
        if (not _is_finite_number(min_confidence)
                or not 0.0 <= float(min_confidence) <= 1.0):
            raise StabilizationError(
                "STAB_INVALID_REQUEST",
                {"min_confidence": min_confidence},
            )
        if (not _is_finite_number(max_scale)
                or float(max_scale) < 1.0):
            raise StabilizationError(
                "STAB_INVALID_REQUEST", {"max_scale": max_scale})

        self.smooth_radius = int(smooth_radius)
        self.max_samples = int(max_samples)
        self.min_confidence = float(min_confidence)
        self.max_scale = float(max_scale)
        self._lock = threading.RLock()
        self._clips: dict[str, _ClipState] = {}
        self._refuses = 0

    def _reject(self, code: str, detail: object = None) -> NoReturn:
        self._refuses += 1
        raise StabilizationError(code, detail)

    def _invalid_snapshot(self, detail: object) -> NoReturn:
        self._reject("STAB_SNAPSHOT_INVALID", detail)

    def _require_clip(self, clip_id: object) -> _ClipState:
        try:
            return self._clips[clip_id]  # type: ignore[index]
        except (KeyError, TypeError):
            self._reject("STAB_UNKNOWN_CLIP", {"clip_id": clip_id})

    def _require_positive_int(self, value: object, name: str) -> int:
        if not _is_int(value) or int(value) <= 0:
            self._reject("STAB_INVALID_REQUEST", {name: value})
        return int(value)

    def register_clip(self, clip_id: str, width: int, height: int, *,
                      fps: int = 60,
                      smooth_radius: int | None = None) -> ClipSpec:
        """Register a video clip with its frame size and smoothing radius."""
        with self._lock:
            if not isinstance(clip_id, str) or not clip_id:
                self._reject("STAB_INVALID_REQUEST",
                             {"clip_id": clip_id})
            if not _is_int(width) or int(width) <= 0:
                self._reject("STAB_INVALID_REQUEST", {"width": width})
            if not _is_int(height) or int(height) <= 0:
                self._reject("STAB_INVALID_REQUEST", {"height": height})
            if not _is_int(fps) or int(fps) <= 0:
                self._reject("STAB_INVALID_REQUEST", {"fps": fps})

            radius = self.smooth_radius if smooth_radius is None \
                else smooth_radius
            if not _is_int(radius) or int(radius) < 0:
                self._reject("STAB_INVALID_REQUEST",
                             {"smooth_radius": smooth_radius})
            if clip_id in self._clips:
                self._reject("STAB_DUPLICATE_CLIP", {"clip_id": clip_id})

            spec = ClipSpec(
                clip_id=clip_id,
                width=int(width),
                height=int(height),
                fps=int(fps),
                smooth_radius=int(radius),
                sample_count=0,
                rolling_shutter=0,
            )
            self._clips[clip_id] = _ClipState(spec=spec, motion=[])
            return spec

    @staticmethod
    def _coerce_sample(index: int, sample: object) -> MotionSample:
        if isinstance(sample, MotionSample):
            dx = sample.dx
            dy = sample.dy
            confidence = sample.confidence
        elif isinstance(sample, dict):
            try:
                dx = sample["dx"]
                dy = sample["dy"]
                confidence = sample["confidence"]
            except (KeyError, TypeError):
                raise StabilizationError(
                    "STAB_INVALID_SAMPLE", {"sample": sample})
        elif isinstance(sample, (tuple, list)):
            if len(sample) == 3:
                dx, dy, confidence = sample
            elif len(sample) == 4:
                _, dx, dy, confidence = sample
            else:
                raise StabilizationError(
                    "STAB_INVALID_SAMPLE", {"sample": sample})
        else:
            raise StabilizationError(
                "STAB_INVALID_SAMPLE", {"sample": sample})

        if (not _is_finite_number(dx) or not _is_finite_number(dy)
                or not _is_finite_number(confidence)):
            raise StabilizationError(
                "STAB_INVALID_SAMPLE", {"sample": sample})
        confidence_value = float(confidence)
        if not 0.0 <= confidence_value <= 1.0:
            raise StabilizationError(
                "STAB_INVALID_SAMPLE", {"confidence": confidence_value})
        return MotionSample(
            index=index,
            dx=float(dx),
            dy=float(dy),
            confidence=confidence_value,
        )

    def ingest_motion(self, clip_id: str,
                      samples: list[tuple[float, float, float]]) -> int:
        """Append per frame motion samples and return the accepted count."""
        with self._lock:
            clip = self._require_clip(clip_id)
            if not isinstance(samples, (list, tuple)) or len(samples) == 0:
                self._reject("STAB_INVALID_REQUEST",
                             {"sample_count": 0})

            start_index = len(clip.motion)
            try:
                accepted = [
                    self._coerce_sample(start_index + offset, sample)
                    for offset, sample in enumerate(samples)
                ]
            except StabilizationError as exc:
                self._reject(exc.code, exc.detail)
            if len(clip.motion) + len(accepted) > self.max_samples:
                self._reject(
                    "STAB_SAMPLE_LIMIT",
                    {
                        "clip_id": clip_id,
                        "limit": self.max_samples,
                        "sample_count": len(clip.motion) + len(accepted),
                    },
                )

            clip.motion.extend(accepted)
            clip.spec = replace(clip.spec, sample_count=len(clip.motion))
            # Derived tracks describe the previous sample generation.
            clip.smooth_path = None
            clip.crops = None
            clip.crop_size = None
            clip.keyframe_indices = ()
            clip.keyframe_interval = None
            return len(accepted)

    def set_rolling_shutter(self, clip_id: str, skew_lines: int) -> int:
        """Set the rolling shutter skew of a clip in lines."""
        with self._lock:
            clip = self._require_clip(clip_id)
            if not _is_int(skew_lines) or int(skew_lines) < 0:
                self._reject("STAB_INVALID_REQUEST",
                             {"skew_lines": skew_lines})

            skew = int(skew_lines)
            if skew != clip.spec.rolling_shutter:
                # RS correction must precede smoothing; invalidate tracks
                # produced without the newly configured readout phase.
                clip.smooth_path = None
                clip.crops = None
                clip.crop_size = None
                clip.keyframe_indices = ()
                clip.keyframe_interval = None
            clip.spec = replace(clip.spec, rolling_shutter=skew)
            return skew

    def _rolling_shutter_correct(
            self, clip: _ClipState
    ) -> list[tuple[float, float]]:
        """Return frame vectors after centered rolling-shutter alignment."""
        return [(sample.dx, sample.dy) for sample in clip.motion]

    @staticmethod
    def _smooth_values(
            values: list[tuple[float, float]], radius: int
    ) -> tuple[tuple[float, float], ...]:
        count = len(values)
        prefix_x = [0.0] * (count + 1)
        prefix_y = [0.0] * (count + 1)
        for index, (value_x, value_y) in enumerate(values):
            prefix_x[index + 1] = prefix_x[index] + value_x
            prefix_y[index + 1] = prefix_y[index] + value_y

        smoothed: list[tuple[float, float]] = []
        for index in range(count):
            start = max(0, index - radius)
            end = min(count, index + radius + 1)
            window_size = end - start
            sum_x = prefix_x[end] - prefix_x[start]
            sum_y = prefix_y[end] - prefix_y[start]
            smoothed.append((sum_x / window_size, sum_y / window_size))
        return tuple(smoothed)

    def smooth_path(self, clip_id: str,
                    radius: int | None = None
                    ) -> tuple[tuple[float, float], ...]:
        """Return the smoothed camera path of a clip."""
        with self._lock:
            clip = self._require_clip(clip_id)
            if radius is None:
                effective_radius = clip.spec.smooth_radius
            else:
                effective_radius = radius
            if not _is_int(effective_radius) or int(effective_radius) < 0:
                self._reject("STAB_INVALID_REQUEST",
                             {"radius": effective_radius})
            if not clip.motion:
                self._reject("STAB_INVALID_REQUEST",
                             {"clip_id": clip_id, "reason": "no motion"})

            corrected = self._rolling_shutter_correct(clip)
            path = self._smooth_values(corrected, int(effective_radius))
            clip.smooth_path = path
            # A new path makes any previously planned crop version stale.
            clip.crops = None
            clip.crop_size = None
            clip.keyframe_indices = ()
            clip.keyframe_interval = None
            return path

    def _check_output_size(
            self, clip: _ClipState, out_width: object,
            out_height: object) -> tuple[int, int]:
        width = self._require_positive_int(out_width, "out_width")
        height = self._require_positive_int(out_height, "out_height")
        source_width = clip.spec.width
        source_height = clip.spec.height

        scale = max(width / source_width, height / source_height)
        if width > source_width or height > source_height:
            self._reject(
                "STAB_INVALID_REQUEST",
                {
                    "reason": "output exceeds source resolution",
                    "out_width": width,
                    "out_height": height,
                    "source_width": source_width,
                    "source_height": source_height,
                },
            )
        if scale > self.max_scale + 1e-12:
            self._reject(
                "STAB_INVALID_REQUEST",
                {
                    "reason": "output scale exceeds max_scale",
                    "scale": scale,
                    "max_scale": self.max_scale,
                },
            )
        return width, height

    def plan_crop(self, clip_id: str, out_width: int,
                  out_height: int) -> tuple[CropWindow, ...]:
        """Return one crop window per frame for the requested output size."""
        with self._lock:
            clip = self._require_clip(clip_id)
            if clip.smooth_path is None:
                self._reject("STAB_NOT_SMOOTHED", {"clip_id": clip_id})
            width, height = self._check_output_size(
                clip, out_width, out_height)

            source_width = clip.spec.width
            source_height = clip.spec.height
            max_x = source_width - width
            max_y = source_height - height
            base_x = max_x // 2
            base_y = max_y // 2

            last_crop = CropWindow(base_x, base_y, width, height)
            crops: list[CropWindow] = []

            for index, (path_x, path_y) in enumerate(clip.smooth_path):
                confidence = clip.motion[index].confidence
                if confidence < self.min_confidence:
                    crop = last_crop
                else:
                    raw_x = base_x + path_x
                    raw_y = base_y + path_y
                    if raw_x <= 0:
                        x = 0
                    elif raw_x >= max_x:
                        x = max_x
                    else:
                        x = _round_coordinate(raw_x)

                    if raw_y <= 0:
                        y = 0
                    elif raw_y >= max_y:
                        y = max_y
                    else:
                        y = _round_coordinate(raw_y)

                    crop = CropWindow(x=x, y=y, width=width, height=height)

                crops.append(crop)
                last_crop = crop

            crop_track = tuple(crops)
            # Publish the complete tuple in one reference assignment.
            clip.crop_size = (width, height)
            clip.crops = crop_track
            clip.keyframe_indices = ()
            clip.keyframe_interval = None
            return crop_track

    def keyframe_crop(self, clip_id: str,
                      interval: int) -> tuple[CropKeyframe, ...]:
        """Compress the crop track into keyframes every *interval* frames."""
        with self._lock:
            clip = self._require_clip(clip_id)
            if not _is_int(interval) or int(interval) <= 0:
                self._reject("STAB_INVALID_REQUEST", {"interval": interval})
            if clip.crops is None:
                self._reject("STAB_NOT_SMOOTHED",
                             {"clip_id": clip_id, "reason": "no crop track"})

            step = int(interval)
            keyframes = tuple(
                CropKeyframe(index=index, crop=clip.crops[index])
                for index in range(0, len(clip.crops), step)
            )
            clip.keyframe_indices = tuple(item.index for item in keyframes)
            clip.keyframe_interval = step
            return keyframes

    def validate_bounds(self, clip_id: str, crop: CropWindow) -> bool:
        """Return whether a crop window stays inside the source frame."""
        with self._lock:
            clip = self._require_clip(clip_id)
            if not isinstance(crop, CropWindow):
                return False
            if not all(_is_int(value) for value in (
                    crop.x, crop.y, crop.width, crop.height)):
                return False
            if crop.width <= 0 or crop.height <= 0:
                return False
            return (
                crop.x >= 0
                and crop.y >= 0
                and crop.x + crop.width <= clip.spec.width
                and crop.y + crop.height <= clip.spec.height
            )

    @staticmethod
    def _committed_count_locked(clip: _ClipState) -> int:
        indices = clip.keyframe_indices
        if not indices and clip.keyframe_interval is not None:
            frame_count = len(clip.crops or clip.motion)
            indices = tuple(range(0, frame_count, clip.keyframe_interval))
        if clip.watermark < 0:
            return 0
        return sum(1 for index in indices if index <= clip.watermark)

    def committed_keyframes(self, clip_id: str) -> int:
        """Return how many keyframes are already committed."""
        with self._lock:
            clip = self._require_clip(clip_id)
            return self._committed_count_locked(clip)

    def commit(self, clip_id: str, upto_index: int) -> int:
        """Advance the commit watermark of a clip and return it."""
        with self._lock:
            clip = self._require_clip(clip_id)
            if not _is_int(upto_index) or int(upto_index) < 0:
                self._reject("STAB_INVALID_REQUEST",
                             {"upto_index": upto_index})
            if int(upto_index) < clip.watermark:
                self._reject(
                    "STAB_ORDER_VIOLATION",
                    {
                        "upto_index": upto_index,
                        "watermark": clip.watermark,
                    },
                )
            clip.watermark = int(upto_index)
            return clip.watermark

    def clip_of(self, clip_id: str) -> ClipSpec:
        """Return the registered specification of one clip."""
        with self._lock:
            return self._require_clip(clip_id).spec

    def stats(self) -> dict:
        """Return current planner counts."""
        with self._lock:
            clips = list(self._clips.values())
            return {
                "clips": len(clips),
                "samples": sum(len(clip.motion) for clip in clips),
                "planned": sum(clip.crops is not None for clip in clips),
                "keyframes": sum(
                    len(clip.keyframe_indices) for clip in clips),
                "committed": sum(
                    self._committed_count_locked(clip) for clip in clips),
                "refuses": self._refuses,
            }

    def snapshot(self) -> dict:
        """Return a deep copy of clips, motion, crop tracks and watermarks."""
        with self._lock:
            state = {
                "version": 1,
                "config": {
                    "smooth_radius": self.smooth_radius,
                    "max_samples": self.max_samples,
                    "min_confidence": self.min_confidence,
                    "max_scale": self.max_scale,
                },
                "stats": self.stats(),
                "clips": {
                    clip_id: {
                        "spec": {
                            "clip_id": clip.spec.clip_id,
                            "width": clip.spec.width,
                            "height": clip.spec.height,
                            "fps": clip.spec.fps,
                            "smooth_radius": clip.spec.smooth_radius,
                            "sample_count": clip.spec.sample_count,
                            "rolling_shutter": clip.spec.rolling_shutter,
                        },
                        "motion": [
                            {
                                "index": sample.index,
                                "dx": sample.dx,
                                "dy": sample.dy,
                                "confidence": sample.confidence,
                            }
                            for sample in clip.motion
                        ],
                        "smooth_path": (
                            [[x, y] for x, y in clip.smooth_path]
                            if clip.smooth_path is not None else None
                        ),
                        "crop_size": (
                            list(clip.crop_size)
                            if clip.crop_size is not None else None
                        ),
                        "crops": (
                            [
                                {
                                    "x": crop.x,
                                    "y": crop.y,
                                    "width": crop.width,
                                    "height": crop.height,
                                }
                                for crop in clip.crops
                            ]
                            if clip.crops is not None else None
                        ),
                        "keyframe_indices": list(clip.keyframe_indices),
                        "keyframe_interval": clip.keyframe_interval,
                        "watermark": clip.watermark,
                    }
                    for clip_id, clip in self._clips.items()
                },
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        """Replace planner state from a snapshot, validating its structure."""
        with self._lock:
            try:
                clips, refuses = self._parse_snapshot(state)
            except StabilizationError:
                raise
            except Exception as exc:
                self._reject(
                    "STAB_SNAPSHOT_INVALID",
                    {"reason": "unparseable snapshot", "error": repr(exc)},
                )

            self._clips = clips
            self._refuses = refuses

    def _parse_snapshot(
            self, state: object
    ) -> tuple[dict[str, _ClipState], int]:
        if not isinstance(state, dict):
            self._invalid_snapshot({"reason": "snapshot must be a dict"})
        if state.get("version") != 1:
            self._invalid_snapshot({"reason": "unsupported version"})

        raw_config = state.get("config")
        if raw_config is not None:
            if not isinstance(raw_config, dict):
                self._invalid_snapshot({"reason": "bad config"})
            for key in ("smooth_radius", "max_samples"):
                if key in raw_config:
                    minimum = 0 if key == "smooth_radius" else 1
                    if not _is_int(raw_config[key]) or int(
                            raw_config[key]) < minimum:
                        self._invalid_snapshot({"reason": f"bad {key}"})
            if "min_confidence" in raw_config and (
                    not _is_finite_number(raw_config["min_confidence"])
                    or not 0.0 <= float(
                        raw_config["min_confidence"]) <= 1.0):
                self._invalid_snapshot({"reason": "bad min_confidence"})
            if "max_scale" in raw_config and (
                    not _is_finite_number(raw_config["max_scale"])
                    or float(raw_config["max_scale"]) < 1.0):
                self._invalid_snapshot({"reason": "bad max_scale"})

        raw_stats = state.get("stats", {})
        if not isinstance(raw_stats, dict):
            self._invalid_snapshot({"reason": "bad stats"})
        for key in ("clips", "samples", "planned", "keyframes",
                    "committed", "refuses"):
            if key in raw_stats and (
                    not _is_int(raw_stats[key]) or raw_stats[key] < 0):
                self._invalid_snapshot({"reason": f"bad stats.{key}"})

        refuses = raw_stats.get("refuses", state.get("refuses", 0))
        if not _is_int(refuses) or int(refuses) < 0:
            self._invalid_snapshot({"reason": "bad refuses"})

        raw_clips = state.get("clips")
        if not isinstance(raw_clips, dict):
            self._invalid_snapshot({"reason": "missing clips mapping"})

        clips: dict[str, _ClipState] = {}
        for clip_id, raw_clip in raw_clips.items():
            if not isinstance(clip_id, str) or not clip_id:
                self._invalid_snapshot({"reason": "bad clip id"})
            if not isinstance(raw_clip, dict):
                self._invalid_snapshot({"clip_id": clip_id})

            raw_spec = raw_clip.get("spec", raw_clip)
            if not isinstance(raw_spec, dict):
                self._invalid_snapshot(
                    {"clip_id": clip_id, "reason": "bad spec"})
            spec_clip_id = raw_spec.get("clip_id", clip_id)
            if spec_clip_id != clip_id:
                self._invalid_snapshot(
                    {"clip_id": clip_id, "reason": "clip id mismatch"})

            width = raw_spec.get("width")
            height = raw_spec.get("height")
            fps = raw_spec.get("fps", 60)
            radius = raw_spec.get("smooth_radius", self.smooth_radius)
            rolling_shutter = raw_spec.get(
                "rolling_shutter", raw_clip.get("rolling_shutter", 0))
            for name, value in (("width", width), ("height", height),
                                ("fps", fps)):
                if not _is_int(value) or int(value) <= 0:
                    self._invalid_snapshot(
                        {"clip_id": clip_id, "field": name})
            if not _is_int(radius) or int(radius) < 0:
                self._invalid_snapshot(
                    {"clip_id": clip_id, "field": "smooth_radius"})
            if not _is_int(rolling_shutter) or int(rolling_shutter) < 0:
                self._invalid_snapshot(
                    {"clip_id": clip_id, "field": "rolling_shutter"})

            raw_motion = raw_clip.get("motion", [])
            if not isinstance(raw_motion, (list, tuple)):
                self._invalid_snapshot(
                    {"clip_id": clip_id, "reason": "bad motion"})
            if len(raw_motion) > self.max_samples:
                self._invalid_snapshot(
                    {"clip_id": clip_id, "reason": "sample limit"})

            motion: list[MotionSample] = []
            for expected_index, raw_sample in enumerate(raw_motion):
                try:
                    sample = self._coerce_sample(
                        expected_index, raw_sample)
                except StabilizationError:
                    self._invalid_snapshot(
                        {"clip_id": clip_id, "reason": "bad sample"})
                raw_index: object = None
                if isinstance(raw_sample, MotionSample):
                    raw_index = raw_sample.index
                elif isinstance(raw_sample, dict):
                    raw_index = raw_sample.get("index")
                elif isinstance(raw_sample, (tuple, list)) and len(
                        raw_sample) == 4:
                    raw_index = raw_sample[0]
                if raw_index is not None and (
                        not _is_int(raw_index)
                        or int(raw_index) != expected_index):
                    self._invalid_snapshot(
                        {"clip_id": clip_id,
                         "reason": "bad sample index"})
                motion.append(sample)

            sample_count = raw_spec.get("sample_count")
            if sample_count is not None and (
                    not _is_int(sample_count)
                    or int(sample_count) != len(motion)):
                self._invalid_snapshot(
                    {"clip_id": clip_id, "reason": "bad sample_count"})

            raw_path = raw_clip.get("smooth_path")
            smooth_path: tuple[tuple[float, float], ...] | None = None
            if raw_path is not None:
                if not isinstance(raw_path, (list, tuple)) or (
                        len(raw_path) not in (0, len(motion))):
                    self._invalid_snapshot(
                        {"clip_id": clip_id,
                         "reason": "bad smooth_path"})
                parsed_path: list[tuple[float, float]] = []
                for pair in raw_path:
                    if (not isinstance(pair, (list, tuple))
                            or len(pair) != 2
                            or not all(_is_finite_number(value)
                                       for value in pair)):
                        self._invalid_snapshot(
                            {"clip_id": clip_id,
                             "reason": "bad smooth_path point"})
                    parsed_path.append((float(pair[0]), float(pair[1])))
                if parsed_path:
                    smooth_path = tuple(parsed_path)

            raw_size = raw_clip.get("crop_size")
            crop_size: tuple[int, int] | None = None
            if raw_size is not None:
                if (not isinstance(raw_size, (list, tuple))
                        or len(raw_size) != 2
                        or not all(_is_int(value) and int(value) > 0
                                   for value in raw_size)):
                    self._invalid_snapshot(
                        {"clip_id": clip_id, "reason": "bad crop_size"})
                crop_size = (int(raw_size[0]), int(raw_size[1]))

            raw_crops = raw_clip.get("crops")
            crops: tuple[CropWindow, ...] | None = None
            if raw_crops is not None:
                if not isinstance(raw_crops, (list, tuple)) or (
                        len(raw_crops) != len(motion)):
                    self._invalid_snapshot(
                        {"clip_id": clip_id, "reason": "bad crops"})
                parsed_crops: list[CropWindow] = []
                for raw_crop in raw_crops:
                    if isinstance(raw_crop, CropWindow):
                        crop = raw_crop
                    elif isinstance(raw_crop, dict):
                        try:
                            crop = CropWindow(
                                x=raw_crop["x"],
                                y=raw_crop["y"],
                                width=raw_crop["width"],
                                height=raw_crop["height"],
                            )
                        except (KeyError, TypeError):
                            self._invalid_snapshot(
                                {"clip_id": clip_id, "reason": "bad crop"})
                    elif isinstance(raw_crop, (list, tuple)) and len(
                            raw_crop) == 4:
                        crop = CropWindow(*raw_crop)
                    else:
                        self._invalid_snapshot(
                            {"clip_id": clip_id, "reason": "bad crop"})

                    if not all(_is_int(value) for value in (
                            crop.x, crop.y, crop.width, crop.height)):
                        self._invalid_snapshot(
                            {"clip_id": clip_id,
                             "reason": "bad crop integers"})
                    if crop.width <= 0 or crop.height <= 0:
                        self._invalid_snapshot(
                            {"clip_id": clip_id,
                             "reason": "bad crop size"})
                    if (crop.x < 0 or crop.y < 0
                            or crop.x + crop.width > width
                            or crop.y + crop.height > height):
                        self._invalid_snapshot(
                            {"clip_id": clip_id,
                             "reason": "crop out of bounds"})
                    if crop_size is not None and (
                            crop.width != crop_size[0]
                            or crop.height != crop_size[1]):
                        self._invalid_snapshot(
                            {"clip_id": clip_id,
                             "reason": "crop size mismatch"})
                    parsed_crops.append(crop)

                if parsed_crops:
                    crops = tuple(parsed_crops)
                    if crop_size is None:
                        crop_size = (crops[0].width, crops[0].height)

            raw_indices = raw_clip.get("keyframe_indices", ())
            if not isinstance(raw_indices, (list, tuple)):
                self._invalid_snapshot(
                    {"clip_id": clip_id, "reason": "bad keyframes"})
            keyframe_indices: list[int] = []
            for index in raw_indices:
                if not _is_int(index) or int(index) < 0:
                    self._invalid_snapshot(
                        {"clip_id": clip_id,
                         "reason": "bad keyframe index"})
                if crops is None or int(index) >= len(crops):
                    self._invalid_snapshot(
                        {"clip_id": clip_id,
                         "reason": "keyframe without crop"})
                if keyframe_indices and int(index) <= keyframe_indices[-1]:
                    self._invalid_snapshot(
                        {"clip_id": clip_id,
                         "reason": "keyframe order"})
                keyframe_indices.append(int(index))

            interval = raw_clip.get("keyframe_interval")
            if interval is not None and (
                    not _is_int(interval) or int(interval) <= 0):
                self._invalid_snapshot(
                    {"clip_id": clip_id,
                     "reason": "bad keyframe interval"})
            if interval is not None and crops is not None:
                expected = tuple(range(0, len(crops), int(interval)))
                if tuple(keyframe_indices) != expected:
                    self._invalid_snapshot(
                        {"clip_id": clip_id,
                         "reason": "keyframe interval mismatch"})

            watermark = raw_clip.get("watermark", -1)
            if not _is_int(watermark) or int(watermark) < -1:
                self._invalid_snapshot(
                    {"clip_id": clip_id, "reason": "bad watermark"})

            spec = ClipSpec(
                clip_id=clip_id,
                width=int(width),
                height=int(height),
                fps=int(fps),
                smooth_radius=int(radius),
                sample_count=len(motion),
                rolling_shutter=int(rolling_shutter),
            )
            clips[clip_id] = _ClipState(
                spec=spec,
                motion=motion,
                smooth_path=smooth_path,
                crop_size=crop_size,
                crops=crops,
                keyframe_indices=tuple(keyframe_indices),
                keyframe_interval=(
                    int(interval) if interval is not None else None),
                watermark=int(watermark),
            )

        return clips, refuses
