"""Vertex animation texture sampler.

Samples pre-baked vertex animation clips for many instances.  A clip carries a
frame count, a frame rate, a bounding box and one probe vertex position per
frame; instances carry their own local time plus a phase offset and run in
loop, once or clamp mode.  Sampling interpolates between adjacent frames and
shares per-(clip, mode, phase) state slots under a bounded cache.
"""

from __future__ import annotations

import copy
import math
import threading
from collections import OrderedDict
from contextlib import contextmanager
from dataclasses import dataclass

__all__ = [
    "VertexAnimError",
    "ClipView",
    "InstanceView",
    "SampleResult",
    "VertexAnimationSampler",
]

MODES = ("loop", "once", "clamp")

CLIP_EXISTS = "VERTANIM_CLIP_EXISTS"
INVALID_REQUEST = "VERTANIM_INVALID_REQUEST"
UNKNOWN_CLIP = "VERTANIM_UNKNOWN_CLIP"
INSTANCE_EXISTS = "VERTANIM_INSTANCE_EXISTS"
INSTANCE_LIMIT = "VERTANIM_INSTANCE_LIMIT"
UNKNOWN_INSTANCE = "VERTANIM_UNKNOWN_INSTANCE"
SNAPSHOT_INVALID = "VERTANIM_SNAPSHOT_INVALID"

_STAT_COUNTERS = ("acquires", "advances", "samples", "releases", "refusals")


class VertexAnimError(ValueError):
    """Raised when a clip or instance operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ClipView:
    """Immutable summary of one registered clip."""

    clip_id: str
    frames: int
    fps: float
    duration: float
    bbox: tuple[float, ...]
    has_normals: bool
    version: int
    instance_count: int


@dataclass(frozen=True)
class InstanceView:
    """Per-instance playback state."""

    instance_id: str
    clip_id: str
    mode: str
    phase: float
    time: float
    local_time: float
    finished: bool
    version: int


@dataclass(frozen=True)
class SampleResult:
    """One sample of a clip at an instance's current time."""

    instance_id: str
    clip_id: str
    mode: str
    phase: float
    frame: int
    next_frame: int
    alpha: float
    local_time: float
    finished: bool


@dataclass(frozen=True)
class _ClipRecord:
    clip_id: str
    frames: int
    fps: float
    duration: float
    bbox: tuple[float, ...]
    marker_track: tuple[tuple[float, float, float], ...]
    has_normals: bool
    version: int


@dataclass
class _InstanceState:
    instance_id: str
    clip_id: str
    mode: str
    phase: float
    time: float
    version: int


@dataclass(frozen=True)
class _FrameState:
    frame: int
    next_frame: int
    alpha: float
    local_time: float
    finished: bool


def _is_real_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, ValueError):
        return False


def _is_count(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _validate_clip_fields(
    clip_id: object,
    *,
    frames: object,
    fps: object,
    bbox: object,
    marker_track: object,
    has_normals: object,
    version: object,
) -> dict:
    if not isinstance(clip_id, str) or not clip_id.strip():
        raise VertexAnimError(
            INVALID_REQUEST, "clip_id must be a non-empty string"
        )
    if not isinstance(frames, int) or isinstance(frames, bool) or frames < 2:
        raise VertexAnimError(
            INVALID_REQUEST, "frames must be an integer of at least two"
        )
    if not _is_real_number(fps) or float(fps) <= 0.0:
        raise VertexAnimError(INVALID_REQUEST, "fps must be positive")
    if not _is_count(version) or version < 1:
        raise VertexAnimError(
            INVALID_REQUEST, "version must be a positive integer"
        )
    if not isinstance(has_normals, bool):
        raise VertexAnimError(
            INVALID_REQUEST, "has_normals must be a boolean"
        )
    if not isinstance(bbox, (tuple, list)) or len(bbox) != 6:
        raise VertexAnimError(
            INVALID_REQUEST, "bbox must contain six numeric values"
        )

    bbox_values = []
    for value in bbox:
        if not _is_real_number(value):
            raise VertexAnimError(
                INVALID_REQUEST, "bbox values must be finite numbers"
            )
        bbox_values.append(float(value))

    for axis in range(3):
        if not bbox_values[axis] < bbox_values[axis + 3]:
            raise VertexAnimError(
                INVALID_REQUEST,
                "bbox minimum must be smaller than maximum on every axis",
            )

    try:
        raw_markers = tuple(marker_track)
    except Exception as exc:
        raise VertexAnimError(
            INVALID_REQUEST, "marker_track must be an iterable of 3D points"
        ) from exc

    if len(raw_markers) != frames:
        raise VertexAnimError(
            INVALID_REQUEST,
            "marker_track must contain exactly one point per frame",
        )

    markers = []
    for marker in raw_markers:
        try:
            coordinates = tuple(marker)
        except Exception as exc:
            raise VertexAnimError(
                INVALID_REQUEST, "marker points must contain three values"
            ) from exc
        if len(coordinates) != 3 or not all(
            _is_real_number(coordinate) for coordinate in coordinates
        ):
            raise VertexAnimError(
                INVALID_REQUEST, "each marker must be a finite 3D point"
            )
        markers.append(tuple(float(value) for value in coordinates))

    fps_value = float(fps)
    return {
        "clip_id": clip_id,
        "frames": frames,
        "fps": fps_value,
        "duration": (frames - 1) / fps_value,
        "bbox": tuple(bbox_values),
        "marker_track": tuple(markers),
        "has_normals": has_normals,
        "version": version,
    }


class VertexAnimationSampler:
    """Sample baked vertex animation clips for many runtime instances."""

    def __init__(
        self, *, max_instances: int = 256, max_state_cache: int = 128
    ) -> None:
        if not _is_count(max_instances):
            raise VertexAnimError(
                INVALID_REQUEST,
                "max_instances must be a non-negative integer",
            )
        if not _is_count(max_state_cache):
            raise VertexAnimError(
                INVALID_REQUEST,
                "max_state_cache must be a non-negative integer",
            )

        self.max_instances = max_instances
        self.max_state_cache = max_state_cache
        self._lock = threading.RLock()
        self._clips: dict[str, _ClipRecord] = {}
        self._clip_versions: dict[str, set[int]] = {}
        self._instances: dict[str, _InstanceState] = {}
        self._state_slots: OrderedDict[tuple[str, str, float], None] = (
            OrderedDict()
        )
        self._cache_hits = 0
        self._cache_misses = 0
        self._cache_evictions = 0
        self._stats = {
            "acquires": 0,
            "advances": 0,
            "samples": 0,
            "releases": 0,
            "refusals": 0,
        }

    @contextmanager
    def _count_refusals(self):
        try:
            yield
        except VertexAnimError:
            self._stats["refusals"] += 1
            raise

    def register_clip(
        self,
        clip_id: str,
        *,
        frames: int,
        fps: float,
        bbox: tuple[float, ...],
        marker_track,
        has_normals: bool = False,
        version: int = 1,
    ) -> ClipView:
        """Register a clip with its probe vertex track per frame."""
        with self._lock, self._count_refusals():
            fields = _validate_clip_fields(
                clip_id,
                frames=frames,
                fps=fps,
                bbox=bbox,
                marker_track=marker_track,
                has_normals=has_normals,
                version=version,
            )
            clip_id = fields["clip_id"]
            known_versions = self._clip_versions.get(clip_id)
            if known_versions is not None and version in known_versions:
                raise VertexAnimError(
                    CLIP_EXISTS, {"clip_id": clip_id, "version": version}
                )

            previous = self._clips.get(clip_id)
            self._clips[clip_id] = _ClipRecord(**fields)
            if known_versions is None:
                self._clip_versions[clip_id] = {version}
            else:
                known_versions.add(version)

            if previous is not None:
                for instance in self._instances.values():
                    if instance.clip_id == clip_id:
                        instance.version = version
                for key in list(self._state_slots):
                    if key[0] == clip_id:
                        del self._state_slots[key]

            return self._clip_view_locked(clip_id)

    def clip_view(self, clip_id: str) -> ClipView:
        """Return the current clip metadata."""
        with self._lock, self._count_refusals():
            return self._clip_view_locked(clip_id)

    def acquire_instance(
        self,
        instance_id: str,
        clip_id: str,
        *,
        mode: str = "loop",
        phase: float = 0.0,
    ) -> InstanceView:
        """Create a playback instance bound to one clip version."""
        with self._lock, self._count_refusals():
            if not isinstance(instance_id, str) or not instance_id:
                raise VertexAnimError(
                    INVALID_REQUEST,
                    "instance_id must be a non-empty string",
                )
            if not isinstance(clip_id, str) or not clip_id.strip():
                raise VertexAnimError(
                    INVALID_REQUEST, "clip_id must be a non-empty string"
                )
            if mode not in MODES:
                raise VertexAnimError(
                    INVALID_REQUEST, {"mode": mode, "allowed": MODES}
                )
            if not _is_real_number(phase):
                raise VertexAnimError(
                    INVALID_REQUEST, "phase must be a finite number"
                )

            clip = self._clips.get(clip_id)
            if clip is None:
                raise VertexAnimError(UNKNOWN_CLIP, {"clip_id": clip_id})
            if instance_id in self._instances:
                raise VertexAnimError(
                    INSTANCE_EXISTS, {"instance_id": instance_id}
                )
            if len(self._instances) >= self.max_instances:
                raise VertexAnimError(
                    INSTANCE_LIMIT, {"max_instances": self.max_instances}
                )

            instance = _InstanceState(
                instance_id=instance_id,
                clip_id=clip_id,
                mode=mode,
                phase=float(phase),
                time=0.0,
                version=clip.version,
            )
            self._instances[instance_id] = instance
            self._stats["acquires"] += 1
            self._touch_state_slot(instance)
            return self._instance_view_locked(instance)

    def instance_view(self, instance_id: str) -> InstanceView:
        """Return the playback state of one instance."""
        with self._lock, self._count_refusals():
            instance = self._get_instance_locked(instance_id)
            return self._instance_view_locked(instance)

    def set_phase(self, instance_id: str, phase: float) -> InstanceView:
        """Replace the phase offset of an instance."""
        with self._lock, self._count_refusals():
            instance = self._get_instance_locked(instance_id)
            if not _is_real_number(phase):
                raise VertexAnimError(
                    INVALID_REQUEST, "phase must be a finite number"
                )
            instance.phase = float(phase)
            self._touch_state_slot(instance)
            return self._instance_view_locked(instance)

    def advance(
        self, instance_id: str, delta_seconds: float
    ) -> InstanceView:
        """Advance the instance clock by a non-negative delta."""
        with self._lock, self._count_refusals():
            instance = self._get_instance_locked(instance_id)
            if not _is_real_number(delta_seconds):
                raise VertexAnimError(
                    INVALID_REQUEST,
                    "delta_seconds must be a finite non-negative number",
                )
            delta = float(delta_seconds)
            if delta < 0.0:
                raise VertexAnimError(
                    INVALID_REQUEST, "delta_seconds must be non-negative"
                )

            instance.time += delta
            self._stats["advances"] += 1
            return self._instance_view_locked(instance)

    def sample_frame(self, instance_id: str) -> SampleResult:
        """Sample frame indices and the interpolation weight."""
        with self._lock, self._count_refusals():
            instance = self._get_instance_locked(instance_id)
            result = self._build_sample_locked(instance)
            self._stats["samples"] += 1
            return result

    def sample_position(
        self, instance_id: str
    ) -> tuple[float, float, float]:
        """Sample the probe vertex position at the instance's current time."""
        with self._lock, self._count_refusals():
            instance = self._get_instance_locked(instance_id)
            sample = self._build_sample_locked(instance)
            self._stats["samples"] += 1
            clip = self._clips[instance.clip_id]
            start = clip.marker_track[sample.frame]
            end = clip.marker_track[sample.next_frame]
            alpha = sample.alpha
            return (
                start[0] + (end[0] - start[0]) * alpha,
                start[1] + (end[1] - start[1]) * alpha,
                start[2] + (end[2] - start[2]) * alpha,
            )

    def release_instance(self, instance_id: str) -> InstanceView:
        """Drop an instance and free its slot."""
        with self._lock, self._count_refusals():
            instance = self._get_instance_locked(instance_id)
            view = self._instance_view_locked(instance)
            del self._instances[instance_id]
            self._stats["releases"] += 1
            return view

    def cache_usage(self) -> dict:
        """Return state slot counts, limits, hits, misses and evictions."""
        with self._lock:
            return {
                "entries": len(self._state_slots),
                "limit": self.max_state_cache,
                "hits": self._cache_hits,
                "misses": self._cache_misses,
                "evictions": self._cache_evictions,
            }

    def snapshot(self) -> dict:
        """Return a deep copy of clips, instances and counters."""
        with self._lock:
            clips = {}
            for clip_id, clip in self._clips.items():
                clips[clip_id] = {
                    "clip_id": clip.clip_id,
                    "frames": clip.frames,
                    "fps": clip.fps,
                    "duration": clip.duration,
                    "bbox": clip.bbox,
                    "marker_track": clip.marker_track,
                    "has_normals": clip.has_normals,
                    "version": clip.version,
                    "versions": sorted(
                        self._clip_versions.get(clip_id, {clip.version})
                    ),
                }

            instances = {
                instance_id: {
                    "instance_id": instance.instance_id,
                    "clip_id": instance.clip_id,
                    "mode": instance.mode,
                    "phase": instance.phase,
                    "time": instance.time,
                    "version": instance.version,
                }
                for instance_id, instance in self._instances.items()
            }

            state = {
                "snapshot_format": 1,
                "clips": clips,
                "instances": instances,
                "stats": self.stats(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        """Replace sampler state with a snapshot, validating its structure."""
        try:
            parsed = self._parse_snapshot(state)
        except Exception as exc:
            raise VertexAnimError(
                SNAPSHOT_INVALID, "snapshot structure is invalid"
            ) from exc

        with self._lock:
            clips, clip_versions, instances, stats = parsed
            self._clips = clips
            self._clip_versions = clip_versions
            self._instances = instances
            self._stats = stats
            self._state_slots = OrderedDict()
            self._cache_hits = 0
            self._cache_misses = 0
            self._cache_evictions = 0

    def stats(self) -> dict:
        """Return cumulative counters for acquires, advances and samples."""
        with self._lock:
            stats = copy.deepcopy(self._stats)
            stats["clips"] = len(self._clips)
            stats["instances"] = len(self._instances)
            return stats

    def _clip_view_locked(self, clip_id: str) -> ClipView:
        if not isinstance(clip_id, str) or not clip_id.strip():
            raise VertexAnimError(
                INVALID_REQUEST, "clip_id must be a non-empty string"
            )
        clip = self._clips.get(clip_id)
        if clip is None:
            raise VertexAnimError(UNKNOWN_CLIP, {"clip_id": clip_id})

        instance_count = sum(
            instance.clip_id == clip_id
            for instance in self._instances.values()
        )
        return ClipView(
            clip_id=clip.clip_id,
            frames=clip.frames,
            fps=clip.fps,
            duration=clip.duration,
            bbox=clip.bbox,
            has_normals=clip.has_normals,
            version=clip.version,
            instance_count=instance_count,
        )

    def _get_instance_locked(self, instance_id: object) -> _InstanceState:
        if not isinstance(instance_id, str) or not instance_id:
            raise VertexAnimError(
                INVALID_REQUEST, "instance_id must be a non-empty string"
            )
        instance = self._instances.get(instance_id)
        if instance is None:
            raise VertexAnimError(
                UNKNOWN_INSTANCE, {"instance_id": instance_id}
            )
        return instance

    def _normalized_phase_locked(self, instance: _InstanceState) -> float:
        if instance.mode == "loop":
            return instance.phase % 1.0
        return float(instance.phase)

    def _state_key_locked(
        self, instance: _InstanceState
    ) -> tuple[str, str, float]:
        return (
            instance.clip_id,
            instance.mode,
            self._normalized_phase_locked(instance),
        )

    def _touch_state_slot(self, instance: _InstanceState) -> None:
        key = self._state_key_locked(instance)
        if key in self._state_slots:
            self._cache_hits += 1
            self._state_slots.move_to_end(key)
            return

        self._cache_misses += 1
        self._state_slots[key] = None
        while len(self._state_slots) > self.max_state_cache:
            self._state_slots.popitem(last=False)
            self._cache_evictions += 1

    def _sample_state_locked(
        self, instance: _InstanceState
    ) -> _FrameState:
        clip = self._clips[instance.clip_id]
        last_frame = clip.frames - 1
        normalized_phase = self._normalized_phase_locked(instance)
        if instance.mode == "loop":
            cycle_duration = clip.frames / clip.fps
            phase_frames = normalized_phase * last_frame
            bounded_time = instance.time % cycle_duration
            position = (bounded_time * clip.fps + phase_frames) % clip.frames
            frame = math.floor(position)
            alpha = position - frame
            if frame >= clip.frames:
                frame = 0
                alpha = 0.0
            next_frame = (frame + 1) % clip.frames
            local_time = position / clip.fps
            return _FrameState(
                frame=frame,
                next_frame=next_frame,
                alpha=alpha,
                local_time=local_time,
                finished=False,
            )

        local_time = instance.time
        if local_time <= 0.0:
            return _FrameState(
                frame=0,
                next_frame=1,
                alpha=0.0,
                local_time=0.0,
                finished=False,
            )
        if local_time >= clip.duration:
            return _FrameState(
                frame=last_frame,
                next_frame=last_frame,
                alpha=0.0,
                local_time=clip.duration,
                finished=True,
            )

        position = local_time * clip.fps
        frame = math.floor(position)
        if frame >= last_frame:
            return _FrameState(
                frame=last_frame,
                next_frame=last_frame,
                alpha=0.0,
                local_time=clip.duration,
                finished=local_time >= clip.duration,
            )

        return _FrameState(
            frame=frame,
            next_frame=frame + 1,
            alpha=position - frame,
            local_time=local_time,
            finished=False,
        )

    def _build_sample_locked(
        self, instance: _InstanceState
    ) -> SampleResult:
        self._touch_state_slot(instance)
        state = self._sample_state_locked(instance)
        return SampleResult(
            instance_id=instance.instance_id,
            clip_id=instance.clip_id,
            mode=instance.mode,
            phase=instance.phase,
            frame=state.frame,
            next_frame=state.next_frame,
            alpha=state.alpha,
            local_time=state.local_time,
            finished=state.finished,
        )

    def _instance_view_locked(
        self, instance: _InstanceState
    ) -> InstanceView:
        state = self._sample_state_locked(instance)
        return InstanceView(
            instance_id=instance.instance_id,
            clip_id=instance.clip_id,
            mode=instance.mode,
            phase=instance.phase,
            time=instance.time,
            local_time=state.local_time,
            finished=state.finished,
            version=instance.version,
        )

    def _parse_snapshot(self, state: object):
        data = copy.deepcopy(state)
        if not isinstance(data, dict):
            raise VertexAnimError(SNAPSHOT_INVALID, "state must be a mapping")

        clips_data = data.get("clips")
        instances_data = data.get("instances")
        stats_data = data.get("stats")
        if not isinstance(clips_data, dict):
            raise VertexAnimError(SNAPSHOT_INVALID, "clips must be a mapping")
        if not isinstance(instances_data, dict):
            raise VertexAnimError(
                SNAPSHOT_INVALID, "instances must be a mapping"
            )
        if not isinstance(stats_data, dict):
            raise VertexAnimError(SNAPSHOT_INVALID, "stats must be a mapping")

        clips: dict[str, _ClipRecord] = {}
        clip_versions: dict[str, set[int]] = {}
        for clip_id, clip_state in clips_data.items():
            if not isinstance(clip_id, str) or not clip_id.strip():
                raise VertexAnimError(
                    SNAPSHOT_INVALID, "clip id must be a non-empty string"
                )
            if not isinstance(clip_state, dict):
                raise VertexAnimError(
                    SNAPSHOT_INVALID, "clip state must be a mapping"
                )

            fields = _validate_clip_fields(
                clip_state.get("clip_id", clip_id),
                frames=clip_state.get("frames"),
                fps=clip_state.get("fps"),
                bbox=clip_state.get("bbox"),
                marker_track=clip_state.get("marker_track"),
                has_normals=clip_state.get("has_normals", False),
                version=clip_state.get("version", 1),
            )
            if fields["clip_id"] != clip_id:
                raise VertexAnimError(
                    SNAPSHOT_INVALID, "clip id does not match its state"
                )

            known_versions = clip_state.get(
                "versions", [fields["version"]]
            )
            if not isinstance(known_versions, (list, tuple, set)):
                raise VertexAnimError(
                    SNAPSHOT_INVALID, "clip versions must be a sequence"
                )
            versions = set()
            for version in known_versions:
                if not _is_count(version) or version < 1:
                    raise VertexAnimError(
                        SNAPSHOT_INVALID, "invalid clip version"
                    )
                versions.add(version)
            if fields["version"] not in versions:
                raise VertexAnimError(
                    SNAPSHOT_INVALID,
                    "current clip version is not recorded",
                )

            clips[clip_id] = _ClipRecord(**fields)
            clip_versions[clip_id] = versions

        instances: dict[str, _InstanceState] = {}
        for instance_id, instance_state in instances_data.items():
            if not isinstance(instance_id, str) or not instance_id:
                raise VertexAnimError(
                    SNAPSHOT_INVALID,
                    "instance id must be a non-empty string",
                )
            if not isinstance(instance_state, dict):
                raise VertexAnimError(
                    SNAPSHOT_INVALID, "instance state must be a mapping"
                )
            if instance_state.get("instance_id", instance_id) != instance_id:
                raise VertexAnimError(
                    SNAPSHOT_INVALID,
                    "instance id does not match its state",
                )

            clip_id = instance_state.get("clip_id")
            clip = clips.get(clip_id)
            if clip is None:
                raise VertexAnimError(
                    SNAPSHOT_INVALID, "instance references unknown clip"
                )

            mode = instance_state.get("mode")
            if mode not in MODES:
                raise VertexAnimError(
                    SNAPSHOT_INVALID, "instance mode is invalid"
                )

            phase = instance_state.get("phase", 0.0)
            if not _is_real_number(phase):
                raise VertexAnimError(
                    SNAPSHOT_INVALID, "instance phase is invalid"
                )

            time = instance_state.get("time", 0.0)
            if not _is_real_number(time) or time < 0.0:
                raise VertexAnimError(
                    SNAPSHOT_INVALID, "instance time is invalid"
                )

            version = instance_state.get("version", clip.version)
            if version != clip.version:
                raise VertexAnimError(
                    SNAPSHOT_INVALID,
                    "instance version does not match migrated clip",
                )

            instances[instance_id] = _InstanceState(
                instance_id=instance_id,
                clip_id=clip_id,
                mode=mode,
                phase=float(phase),
                time=float(time),
                version=version,
            )

        if len(instances) > self.max_instances:
            raise VertexAnimError(
                SNAPSHOT_INVALID,
                "snapshot contains more instances than this sampler allows",
            )

        stats = copy.deepcopy(stats_data)
        for key in _STAT_COUNTERS:
            if not _is_count(stats.get(key)):
                raise VertexAnimError(
                    SNAPSHOT_INVALID, f"stats.{key} must be non-negative"
                )
        for key in ("clips", "instances"):
            if key in stats and not _is_count(stats[key]):
                raise VertexAnimError(
                    SNAPSHOT_INVALID, f"stats.{key} must be non-negative"
                )

        return clips, clip_versions, instances, stats
