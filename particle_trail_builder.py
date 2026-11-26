"""Particle trail builder: sample history ring, ribbon geometry and budgets."""

from __future__ import annotations

import copy
import math
import threading
from collections import deque
from collections.abc import Mapping, Sequence
from numbers import Real

__all__ = [
    "ParticleError",
    "ParticleTrailBuilder",
    "DEFAULT_COLOR",
]

DEFAULT_COLOR = (1.0, 1.0, 1.0, 1.0)
_SNAPSHOT_SCHEMA = 1
_STAT_KEYS = (
    "registered",
    "removed",
    "samples",
    "dropped_capacity",
    "expired_samples",
    "breaks",
    "builds",
    "truncated_builds",
)


class ParticleError(ValueError):
    """Raised when a trail request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_real(value: object) -> bool:
    return isinstance(value, Real) and not isinstance(value, bool)


def _emitter_key(emitter_id: object) -> str:
    if not isinstance(emitter_id, str):
        raise ParticleError(
            "PARTICLE_INVALID_REQUEST", "emitter_id must be a string"
        )
    normalized = emitter_id.strip()
    if not normalized:
        raise ParticleError(
            "PARTICLE_INVALID_REQUEST", "emitter_id must not be empty"
        )
    return normalized


def _position(value: object) -> tuple[float, float]:
    if (
        isinstance(value, (str, bytes))
        or not isinstance(value, Sequence)
        or len(value) != 2
    ):
        raise ParticleError(
            "PARTICLE_INVALID_REQUEST",
            "position must be a two-coordinate pair",
        )
    try:
        raw_x, raw_y = value[0], value[1]
        if not _is_real(raw_x) or not _is_real(raw_y):
            raise ParticleError(
                "PARTICLE_INVALID_REQUEST",
                "position coordinates must be numeric",
            )
        x = float(raw_x)
        y = float(raw_y)
    except (TypeError, ValueError) as exc:
        raise ParticleError(
            "PARTICLE_INVALID_REQUEST",
            "position coordinates must be numeric",
        ) from exc
    if not (math.isfinite(x) and math.isfinite(y)):
        raise ParticleError(
            "PARTICLE_INVALID_REQUEST",
            "position coordinates must be finite",
        )
    return x, y


def _positive_number(value: object, name: str) -> float:
    if not _is_real(value):
        raise ParticleError(
            "PARTICLE_INVALID_REQUEST", f"{name} must be a positive number"
        )
    result = float(value)
    if not result > 0.0:
        raise ParticleError(
            "PARTICLE_INVALID_REQUEST", f"{name} must be positive"
        )
    return result


def _positive_integer(value: object, name: str) -> int:
    if not _is_integer(value) or value <= 0:
        raise ParticleError(
            "PARTICLE_INVALID_REQUEST", f"{name} must be a positive integer"
        )
    return value


def _color(value: object) -> tuple[float, float, float, float]:
    if (
        isinstance(value, (str, bytes))
        or not isinstance(value, Sequence)
        or len(value) != 4
    ):
        raise ParticleError(
            "PARTICLE_INVALID_REQUEST", "color must contain four components"
        )
    components: list[float] = []
    for component in value:
        if not _is_real(component):
            raise ParticleError(
                "PARTICLE_INVALID_REQUEST",
                "color components must be numeric",
            )
        channel = float(component)
        if not 0.0 <= channel <= 1.0:
            raise ParticleError(
                "PARTICLE_INVALID_REQUEST",
                "color components must be between 0 and 1",
            )
        components.append(channel)
    return tuple(components)  # type: ignore[return-value]


def _segment_views(samples: Sequence[Mapping[str, object]]) -> tuple[dict, ...]:
    segments: list[dict] = []
    current_generation: int | None = None
    sample_count = 0
    for sample in samples:
        generation = int(sample["generation"])
        if current_generation is None:
            current_generation = generation
            sample_count = 1
        elif generation == current_generation:
            sample_count += 1
        else:
            segments.append(
                {"generation": current_generation, "sample_count": sample_count}
            )
            current_generation = generation
            sample_count = 1
    if current_generation is not None:
        segments.append(
            {"generation": current_generation, "sample_count": sample_count}
        )
    return tuple(segments)


def _normal(
    points: Sequence[tuple[float, float]], index: int
) -> tuple[float, float]:
    count = len(points)

    def tangent(start: int, end: int) -> tuple[float, float] | None:
        dx = points[end][0] - points[start][0]
        dy = points[end][1] - points[start][1]
        length = math.hypot(dx, dy)
        if length == 0.0:
            return None
        return dx / length, dy / length

    direction: tuple[float, float] | None = None
    if 0 < index < count - 1:
        direction = tangent(index - 1, index + 1)
    if direction is None and index + 1 < count:
        direction = tangent(index, index + 1)
    if direction is None and index > 0:
        direction = tangent(index - 1, index)
    if direction is None:
        return 0.0, 1.0
    dx, dy = direction
    return -dy, dx


def _build_geometry(
    samples: Sequence[Mapping[str, object]],
) -> tuple[tuple[tuple[float, float, float], ...], int]:
    vertices: list[tuple[float, float, float]] = []
    triangles = 0
    start = 0
    total = len(samples)

    while start < total:
        end = start + 1
        generation = samples[start]["generation"]
        while end < total and samples[end]["generation"] == generation:
            end += 1

        segment = samples[start:end]
        if len(segment) >= 2:
            points = [sample["position"] for sample in segment]
            for index, sample in enumerate(segment):
                x, y = points[index]
                normal_x, normal_y = _normal(points, index)
                half_width = float(sample["width"]) * 0.5
                vertices.append(
                    (
                        x + normal_x * half_width,
                        y + normal_y * half_width,
                        0.0,
                    )
                )
                vertices.append(
                    (
                        x - normal_x * half_width,
                        y - normal_y * half_width,
                        1.0,
                    )
                )
            triangles += 2 * (len(segment) - 1)

        start = end

    return tuple(vertices), triangles


class ParticleTrailBuilder:
    """Keep per-emitter sample rings and turn them into camera-facing ribbons."""

    def __init__(
        self,
        *,
        teleport_distance: float = 1000.0,
        vertex_budget: int = 4096,
        max_emitters: int = 16,
    ) -> None:
        if not _is_real(teleport_distance):
            raise ParticleError(
                "PARTICLE_INVALID_REQUEST",
                "teleport_distance must be numeric",
            )
        _positive_integer(vertex_budget, "vertex_budget")
        _positive_integer(max_emitters, "max_emitters")

        self.teleport_distance = float(teleport_distance)
        self.vertex_budget = vertex_budget
        self.max_emitters = max_emitters
        self._lock = threading.RLock()
        self._emitters: dict[str, dict[str, object]] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

    def register_emitter(
        self,
        emitter_id: str,
        *,
        capacity: int = 64,
        max_age: float = 2.0,
        min_distance: float = 0.1,
        priority: int = 0,
    ) -> None:
        key = _emitter_key(emitter_id)
        with self._lock:
            if key in self._emitters:
                raise ParticleError(
                    "PARTICLE_EMITTER_EXISTS",
                    f"emitter {key!r} is already registered",
                )
            if not _is_integer(capacity) or capacity < 2:
                raise ParticleError(
                    "PARTICLE_INVALID_REQUEST",
                    "capacity must be an integer >= 2",
                )
            max_age_value = _positive_number(max_age, "max_age")
            min_distance_value = _positive_number(
                min_distance, "min_distance"
            )
            if not _is_real(priority) or not math.isfinite(float(priority)):
                raise ParticleError(
                    "PARTICLE_INVALID_REQUEST",
                    "priority must be numeric",
                )
            if len(self._emitters) >= self.max_emitters:
                raise ParticleError(
                    "PARTICLE_EMITTER_LIMIT",
                    f"at most {self.max_emitters} emitters are supported",
                )

            self._emitters[key] = {
                "emitter_id": key,
                "capacity": capacity,
                "max_age": max_age_value,
                "min_distance": min_distance_value,
                "priority": priority,
                "generation": 0,
                "samples": deque(),
                "last_time": None,
                "last_position": None,
            }
            self._stats["registered"] += 1

    def remove_emitter(self, emitter_id: str) -> None:
        with self._lock:
            key, _ = self._require_emitter(emitter_id)
            del self._emitters[key]
            self._stats["removed"] += 1

    def push_sample(
        self,
        emitter_id: str,
        *,
        position,
        time,
        width: float = 1.0,
        color=DEFAULT_COLOR,
    ) -> None:
        key = _emitter_key(emitter_id)
        with self._lock:
            _, emitter = self._require_emitter(key)
            point = _position(position)
            if not _is_real(time):
                raise ParticleError(
                    "PARTICLE_INVALID_REQUEST",
                    "time must be a numeric value",
                )
            sample_time = float(time)
            if not math.isfinite(sample_time):
                raise ParticleError(
                    "PARTICLE_INVALID_REQUEST",
                    "time must be finite",
                )
            width_value = _positive_number(width, "width")
            if not math.isfinite(width_value):
                raise ParticleError(
                    "PARTICLE_INVALID_REQUEST",
                    "width must be finite",
                )
            color_value = _color(color)

            last_time = emitter["last_time"]
            if last_time is not None and sample_time < float(last_time):
                raise ParticleError(
                    "PARTICLE_INVALID_REQUEST",
                    "time must not be earlier than the previous frame",
                )

            samples: deque[dict[str, object]] = emitter["samples"]  # type: ignore[assignment]
            generation = int(emitter["generation"])
            last_sample = samples[-1] if samples else None
            has_current_generation = (
                last_sample is not None
                and int(last_sample["generation"]) == generation
            )
            last_position = emitter["last_position"]

            if has_current_generation and last_position is not None:
                jump = math.hypot(
                    point[0] - last_position[0],  # type: ignore[index]
                    point[1] - last_position[1],  # type: ignore[index]
                )
                if jump > float(self.teleport_distance):
                    generation += 1
                    emitter["generation"] = generation
                    self._stats["breaks"] += 1
                    has_current_generation = False

            emitter["last_time"] = sample_time
            emitter["last_position"] = point
            self._stats["samples"] += 1

            if has_current_generation:
                assert last_sample is not None
                retained_position = last_sample["position"]
                distance = math.hypot(
                    point[0] - retained_position[0],
                    point[1] - retained_position[1],
                )
                if distance < float(emitter["min_distance"]):
                    last_sample["width"] = width_value
                    last_sample["color"] = color_value
                    return

            if len(samples) >= int(emitter["capacity"]):
                samples.popleft()
                self._stats["dropped_capacity"] += 1

            samples.append(
                {
                    "position": point,
                    "time": sample_time,
                    "width": width_value,
                    "color": color_value,
                    "generation": generation,
                }
            )

    def build_ribbon(
        self, emitter_id: str, *, budget: int | float | None = None
    ) -> dict:
        key = _emitter_key(emitter_id)
        with self._lock:
            _, emitter = self._require_emitter(key)
            if budget is not None and (
                not _is_real(budget)
                or isinstance(budget, bool)
                or budget <= 0
            ):
                raise ParticleError(
                    "PARTICLE_INVALID_REQUEST",
                    "budget must be a positive number",
                )

            expired = self._prune_expired(emitter)
            self._stats["expired_samples"] += expired
            if budget is None:
                vertex_budget = self._priority_budget_locked(key)
            else:
                vertex_budget = int(math.floor(float(budget)))

            samples: deque[dict[str, object]] = emitter["samples"]  # type: ignore[assignment]
            ordered_samples = list(samples)
            kept_count = min(len(ordered_samples), vertex_budget // 2)
            selected_samples = ordered_samples[:kept_count]
            truncated = kept_count < len(ordered_samples)

            segments = _segment_views(selected_samples)
            vertices, triangles = _build_geometry(selected_samples)

            self._stats["builds"] += 1
            if truncated:
                self._stats["truncated_builds"] += 1

            return {
                "vertices": vertices,
                "vertex_count": len(vertices),
                "triangles": triangles,
                "segments": segments,
                "truncated": truncated,
            }

    def break_trail(self, emitter_id: str, *, reason: str = "manual") -> int:
        with self._lock:
            _, emitter = self._require_emitter(emitter_id)
            emitter["generation"] = int(emitter["generation"]) + 1
            self._stats["breaks"] += 1
            return int(emitter["generation"])

    def set_budget(self, vertex_budget: int) -> None:
        _positive_integer(vertex_budget, "vertex_budget")
        with self._lock:
            self.vertex_budget = vertex_budget

    def segments(self, emitter_id: str) -> tuple[dict, ...]:
        with self._lock:
            _, emitter = self._require_emitter(emitter_id)
            samples: deque[dict[str, object]] = emitter["samples"]  # type: ignore[assignment]
            return _segment_views(list(samples))

    def emitter_state(self, emitter_id: str) -> dict:
        with self._lock:
            key, emitter = self._require_emitter(emitter_id)
            samples: deque[dict[str, object]] = emitter["samples"]  # type: ignore[assignment]
            public_samples = tuple(
                {
                    "position": (
                        float(sample["position"][0]),  # type: ignore[index]
                        float(sample["position"][1]),  # type: ignore[index]
                    ),
                    "time": float(sample["time"]),
                    "width": float(sample["width"]),
                    "color": tuple(
                        float(channel) for channel in sample["color"]
                    ),  # type: ignore[arg-type]
                }
                for sample in samples
            )
            segments = _segment_views(list(samples))
            return {
                "emitter_id": key,
                "capacity": int(emitter["capacity"]),
                "max_age": float(emitter["max_age"]),
                "min_distance": float(emitter["min_distance"]),
                "priority": emitter["priority"],
                "generation": int(emitter["generation"]),
                "segment_count": len(segments),
                "sample_count": len(samples),
                "samples": public_samples,
            }

    def emitters(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                sorted(
                    self._emitters,
                    key=lambda emitter_id: (
                        -self._emitters[emitter_id]["priority"],
                        emitter_id,
                    ),
                )
            )

    def snapshot(self) -> dict:
        with self._lock:
            emitter_snapshots: dict[str, dict[str, object]] = {}
            for key, emitter in self._emitters.items():
                samples: deque[dict[str, object]] = emitter["samples"]  # type: ignore[assignment]
                emitter_snapshots[key] = {
                    "emitter_id": key,
                    "capacity": emitter["capacity"],
                    "max_age": emitter["max_age"],
                    "min_distance": emitter["min_distance"],
                    "priority": emitter["priority"],
                    "generation": emitter["generation"],
                    "last_time": emitter["last_time"],
                    "last_position": (
                        tuple(emitter["last_position"])
                        if emitter["last_position"] is not None
                        else None
                    ),
                    "samples": [
                        {
                            "position": tuple(sample["position"]),
                            "time": sample["time"],
                            "width": sample["width"],
                            "color": tuple(sample["color"]),  # type: ignore[arg-type]
                            "generation": sample["generation"],
                        }
                        for sample in samples
                    ],
                }

            state = {
                "schema": _SNAPSHOT_SCHEMA,
                "emitters": emitter_snapshots,
                "budget": self.vertex_budget,
                "stats": copy.deepcopy(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        try:
            parsed = self._parse_snapshot(state)
        except Exception as exc:
            if isinstance(exc, ParticleError) and (
                exc.code == "PARTICLE_SNAPSHOT_INVALID"
            ):
                raise
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID",
                "snapshot structure is invalid",
            ) from exc

        with self._lock:
            self._emitters = parsed["emitters"]  # type: ignore[assignment]
            self.vertex_budget = int(parsed["budget"])
            self._stats = parsed["stats"]  # type: ignore[assignment]

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

    def _require_emitter(
        self, emitter_id: object
    ) -> tuple[str, dict[str, object]]:
        key = _emitter_key(emitter_id)
        emitter = self._emitters.get(key)
        if emitter is None:
            raise ParticleError(
                "PARTICLE_UNKNOWN_EMITTER",
                f"emitter {key!r} is not registered",
            )
        return key, emitter

    @staticmethod
    def _prune_expired(emitter: dict[str, object]) -> int:
        samples: deque[dict[str, object]] = emitter["samples"]  # type: ignore[assignment]
        if not samples:
            return 0

        latest_time = float(samples[-1]["time"])
        max_age = float(emitter["max_age"])
        expired = 0
        while samples:
            oldest_age = latest_time - float(samples[0]["time"])
            if oldest_age <= max_age:
                break
            samples.popleft()
            expired += 1
        return expired

    def _priority_budget_locked(self, target_id: str) -> int:
        remaining_pairs = self.vertex_budget // 2
        ordered_ids = sorted(
            self._emitters,
            key=lambda emitter_id: (
                -self._emitters[emitter_id]["priority"],
                emitter_id,
            ),
        )
        for emitter_id in ordered_ids:
            emitter = self._emitters[emitter_id]
            active_samples = self._active_sample_count_locked(emitter)
            allocated_pairs = min(active_samples, remaining_pairs)
            if emitter_id == target_id:
                return 2 * allocated_pairs
            remaining_pairs -= allocated_pairs
        return 0

    @staticmethod
    def _active_sample_count_locked(emitter: dict[str, object]) -> int:
        samples: deque[dict[str, object]] = emitter["samples"]  # type: ignore[assignment]
        if not samples:
            return 0
        latest_time = float(samples[-1]["time"])
        max_age = float(emitter["max_age"])
        return sum(
            1
            for sample in samples
            if latest_time - float(sample["time"]) <= max_age
        )

    def _parse_snapshot(self, state: object) -> dict[str, object]:
        if not isinstance(state, dict):
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID", "state must be a dict"
            )
        if set(state) != {"schema", "emitters", "budget", "stats"}:
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID", "state has invalid top-level keys"
            )
        if state["schema"] != _SNAPSHOT_SCHEMA:
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID", "unsupported schema"
            )

        budget = _positive_integer(state["budget"], "budget")
        raw_emitters = state["emitters"]
        if not isinstance(raw_emitters, Mapping):
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID", "emitters must be a mapping"
            )
        if len(raw_emitters) > self.max_emitters:
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID",
                "emitter limit exceeded by snapshot",
            )

        raw_stats = state["stats"]
        if not isinstance(raw_stats, Mapping):
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID", "stats must be a mapping"
            )
        stats: dict[str, object] = {}
        for key in _STAT_KEYS:
            if key not in raw_stats:
                raise ParticleError(
                    "PARTICLE_SNAPSHOT_INVALID", f"missing stat {key!r}"
                )
            value = raw_stats[key]
            if not _is_integer(value) or int(value) < 0:
                raise ParticleError(
                    "PARTICLE_SNAPSHOT_INVALID",
                    f"stat {key!r} must be nonnegative",
                )
            stats[key] = int(value)
        for key, value in raw_stats.items():
            if key not in _STAT_KEYS:
                stats[key] = copy.deepcopy(value)

        emitters: dict[str, dict[str, object]] = {}
        for raw_key, raw_emitter in raw_emitters.items():
            emitter = self._parse_emitter_snapshot(raw_key, raw_emitter)
            emitters[str(emitter["emitter_id"])] = emitter

        return {"emitters": emitters, "budget": budget, "stats": stats}

    def _parse_emitter_snapshot(
        self, raw_key: object, raw_emitter: object
    ) -> dict[str, object]:
        key = _emitter_key(raw_key)
        if not isinstance(raw_emitter, Mapping):
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID", "emitter state must be a mapping"
            )

        required = {
            "emitter_id",
            "capacity",
            "max_age",
            "min_distance",
            "priority",
            "generation",
            "last_time",
            "last_position",
            "samples",
        }
        if not required.issubset(raw_emitter):
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID", "emitter state is missing fields"
            )
        if _emitter_key(raw_emitter["emitter_id"]) != key:
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID",
                "emitter id does not match its key",
            )

        capacity = raw_emitter["capacity"]
        if not _is_integer(capacity) or capacity < 2:
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID", "invalid snapshot capacity"
            )
        max_age = _positive_number(raw_emitter["max_age"], "max_age")
        min_distance = _positive_number(
            raw_emitter["min_distance"], "min_distance"
        )
        priority = raw_emitter["priority"]
        if not _is_real(priority) or not math.isfinite(float(priority)):
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID", "invalid snapshot priority"
            )
        generation = raw_emitter["generation"]
        if not _is_integer(generation) or generation < 0:
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID", "invalid snapshot generation"
            )

        last_time = raw_emitter["last_time"]
        if last_time is not None:
            if not _is_real(last_time) or not math.isfinite(float(last_time)):
                raise ParticleError(
                    "PARTICLE_SNAPSHOT_INVALID", "invalid snapshot last_time"
                )
            last_time = float(last_time)

        last_position_raw = raw_emitter["last_position"]
        last_position = (
            None
            if last_position_raw is None
            else _position(last_position_raw)
        )

        raw_samples = raw_emitter["samples"]
        if not isinstance(raw_samples, (list, tuple, deque)):
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID",
                "snapshot samples must be a sequence",
            )
        if len(raw_samples) > capacity:
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID", "snapshot exceeds capacity"
            )

        samples = deque()
        previous_time: float | None = None
        previous_generation: int | None = None
        for raw_sample in raw_samples:
            if not isinstance(raw_sample, Mapping):
                raise ParticleError(
                    "PARTICLE_SNAPSHOT_INVALID", "sample must be a mapping"
                )
            sample_position = _position(raw_sample["position"])
            sample_time_value = raw_sample["time"]
            if not _is_real(sample_time_value):
                raise ParticleError(
                    "PARTICLE_SNAPSHOT_INVALID",
                    "sample time must be numeric",
                )
            sample_time = float(sample_time_value)
            if not math.isfinite(sample_time):
                raise ParticleError(
                    "PARTICLE_SNAPSHOT_INVALID",
                    "sample time must be finite",
                )
            if previous_time is not None and sample_time < previous_time:
                raise ParticleError(
                    "PARTICLE_SNAPSHOT_INVALID",
                    "samples must be time ordered",
                )
            width = _positive_number(raw_sample["width"], "width")
            if not math.isfinite(width):
                raise ParticleError(
                    "PARTICLE_SNAPSHOT_INVALID",
                    "sample width must be finite",
                )
            color = _color(raw_sample["color"])
            sample_generation = raw_sample["generation"]
            if not _is_integer(sample_generation) or sample_generation < 0:
                raise ParticleError(
                    "PARTICLE_SNAPSHOT_INVALID",
                    "invalid sample generation",
                )
            if sample_generation > generation:
                raise ParticleError(
                    "PARTICLE_SNAPSHOT_INVALID",
                    "sample generation exceeds emitter generation",
                )
            if (
                previous_generation is not None
                and sample_generation < previous_generation
            ):
                raise ParticleError(
                    "PARTICLE_SNAPSHOT_INVALID",
                    "sample generations must be ordered",
                )

            samples.append(
                {
                    "position": sample_position,
                    "time": sample_time,
                    "width": width,
                    "color": color,
                    "generation": sample_generation,
                }
            )
            previous_time = sample_time
            previous_generation = sample_generation

        if (
            last_time is not None
            and samples
            and last_time < float(samples[-1]["time"])
        ):
            raise ParticleError(
                "PARTICLE_SNAPSHOT_INVALID",
                "last_time precedes the newest sample time",
            )

        return {
            "emitter_id": key,
            "capacity": capacity,
            "max_age": max_age,
            "min_distance": min_distance,
            "priority": priority,
            "generation": generation,
            "last_time": last_time,
            "last_position": last_position,
            "samples": samples,
        }
