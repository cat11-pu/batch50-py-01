from __future__ import annotations

import copy
import math
import threading
from dataclasses import dataclass
from dataclasses import replace
from typing import Any

__all__ = [
    "WindDriverError",
    "FieldRecord",
    "InstanceRecord",
    "Pose",
    "VegetationWindDriver",
    "DEFAULT_FREQUENCY",
]

DEFAULT_FREQUENCY = 0.35
SNAPSHOT_VERSION = 1
TWO_PI = 2.0 * math.pi
DEFAULT_PER_UPDATE = 64


class WindDriverError(ValueError):
    """Raised when a wind-driver request is rejected."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FieldRecord:
    field_id: str
    wavelength: float
    phase: float


@dataclass(frozen=True)
class InstanceRecord:
    instance_id: str
    position: tuple[float, float]
    stiffness: float
    field: str
    tier: str
    phase: float


@dataclass(frozen=True)
class Pose:
    instance_id: str
    time: float
    phase: float
    amplitude: float
    sway: float
    tier: str
    interpolated: bool


@dataclass(frozen=True)
class _Sample:
    time: float
    amplitude: float
    sway: float


class VegetationWindDriver:
    """Drive the sway state of many vegetation instances per frame."""

    def __init__(self, *, frequency: float = DEFAULT_FREQUENCY) -> None:
        self.frequency = frequency
        self._lock = threading.RLock()
        self._fields: dict[str, FieldRecord] = {}
        self._instances: dict[str, InstanceRecord] = {}
        self._wind: dict[str, float] | None = None
        self._wind_transition: dict[str, Any] | None = None
        self._budget = {
            "per_update": DEFAULT_PER_UPDATE,
            "near_radius": 30.0,
            "far_stride": 3,
        }
        self._time: float | None = None
        self._update_index = 0
        self._poses: dict[str, list[_Sample]] = {}
        self._counters = {
            "updates": 0,
            "updated": 0,
            "deferred": 0,
            "due": 0,
            "near": 0,
            "far": 0,
            "near_updates": 0,
            "far_updates": 0,
        }

    def register_field(self, field_id: str, *, wavelength: float,
                       phase: float = 0.0) -> FieldRecord:
        clean_id = _clean_identifier(field_id, "WIND_INVALID_INPUT")
        wavelength_value = _finite_number(
            wavelength, "WIND_INVALID_INPUT", "wavelength", positive=True
        )
        phase_value = _finite_number(phase, "WIND_INVALID_INPUT", "phase")

        with self._lock:
            if clean_id in self._fields:
                raise WindDriverError(
                    "WIND_INVALID_INPUT",
                    {"field_id": field_id, "reason": "duplicate_field"},
                )
            record = FieldRecord(clean_id, wavelength_value, phase_value)
            self._fields[clean_id] = record
            return record

    def register_instance(self, instance_id: str, *, position,
                          stiffness: float = 1.0,
                          field: str) -> InstanceRecord:
        clean_id = _clean_identifier(instance_id, "WIND_INVALID_INPUT")
        coordinates = _parse_position(position)
        stiffness_value = _finite_number(
            stiffness, "WIND_INVALID_INPUT", "stiffness", positive=True
        )
        if not isinstance(field, str) or not field.strip():
            raise WindDriverError(
                "WIND_UNKNOWN_FIELD", {"field": field, "reason": "unknown_field"}
            )
        field_id = field.strip()

        with self._lock:
            if clean_id in self._instances:
                raise WindDriverError(
                    "WIND_INVALID_INPUT",
                    {"instance_id": instance_id, "reason": "duplicate_instance"},
                )
            if field_id not in self._fields:
                raise WindDriverError(
                    "WIND_UNKNOWN_FIELD", {"field": field_id}
                )

            distance = math.hypot(coordinates[0], coordinates[1])
            tier = _tier_for_distance(
                distance, float(self._budget["near_radius"])
            )
            phase = _instance_phase(clean_id)
            record = InstanceRecord(
                instance_id=clean_id,
                position=coordinates,
                stiffness=stiffness_value,
                field=field_id,
                tier=tier,
                phase=phase,
            )
            self._instances[clean_id] = record
            self._poses[clean_id] = []
            return record

    def set_wind(self, strength: float, direction: float, *,
                 transition: float = 0.0) -> dict:
        strength_value = _finite_number(
            strength, "WIND_INVALID_WIND", "strength", nonnegative=True
        )
        direction_value = _finite_number(
            direction, "WIND_INVALID_WIND", "direction"
        )
        transition_value = _finite_number(
            transition, "WIND_INVALID_WIND", "transition", nonnegative=True
        )
        normalized_direction = direction_value % 360.0

        with self._lock:
            start_amplitudes: dict[str, float] = {}
            started_at = self._time
            if self._wind is not None:
                for instance_id, record in self._instances.items():
                    if self._time is None:
                        start_amplitudes[instance_id] = self._target_amplitude(
                            record, self._wind
                        )
                    else:
                        start_amplitudes[instance_id] = (
                            self._effective_amplitude(record, self._time)
                        )
            else:
                start_amplitudes = {
                    instance_id: 0.0 for instance_id in self._instances
                }

            self._wind = {
                "strength": strength_value,
                "direction": normalized_direction,
                "transition": transition_value,
            }
            if transition_value == 0.0:
                self._wind_transition = None
            else:
                self._wind_transition = {
                    "started_at": started_at,
                    "amplitudes": start_amplitudes,
                }
            return dict(self._wind)

    def set_lod_budget(self, per_update: int, *, near_radius: float = 30.0,
                       far_stride: int = 3) -> dict:
        per_update_value = _positive_integer(
            per_update, "WIND_INVALID_BUDGET", "per_update"
        )
        far_stride_value = _positive_integer(
            far_stride, "WIND_INVALID_BUDGET", "far_stride"
        )
        near_radius_value = _finite_number(
            near_radius, "WIND_INVALID_BUDGET", "near_radius", positive=True
        )

        with self._lock:
            self._budget = {
                "per_update": per_update_value,
                "near_radius": near_radius_value,
                "far_stride": far_stride_value,
            }
            for instance_id, record in list(self._instances.items()):
                distance = math.hypot(*record.position)
                tier = _tier_for_distance(distance, near_radius_value)
                if tier != record.tier:
                    self._instances[instance_id] = _replace_record(
                        record, tier=tier
                    )
            return dict(self._budget)

    def update(self, time: float) -> dict:
        with self._lock:
            if self._wind is None:
                raise WindDriverError("WIND_NOT_SET")
            time_value = _validate_time(time, "WIND_INVALID_TIME")
            if self._time is not None and time_value < self._time:
                raise WindDriverError(
                    "WIND_INVALID_TIME",
                    {"time": time_value, "last_time": self._time},
                )

            self._update_index += 1
            update_index = self._update_index
            far_stride = int(self._budget["far_stride"])
            candidates: list[tuple[float, str, InstanceRecord]] = []

            for instance_id, record in self._instances.items():
                is_due = (
                    record.tier == "near"
                    or (update_index - 1) % far_stride == 0
                )
                if is_due:
                    distance = math.hypot(*record.position)
                    candidates.append((distance, instance_id, record))

            candidates.sort(key=lambda item: (item[0], item[1]))
            due = len(candidates)
            selected = candidates[: int(self._budget["per_update"])]
            updated = len(selected)
            deferred = due - updated

            for _, instance_id, record in selected:
                amplitude = self._effective_amplitude(record, time_value)
                phase = self._phase_at(record.phase, time_value)
                sway = amplitude * record.stiffness * math.sin(phase)
                samples = self._poses.setdefault(instance_id, [])
                samples.append(_Sample(time_value, amplitude, sway))
                if len(samples) > 2:
                    del samples[0]

                self._counters["updated"] += 1
                if record.tier == "near":
                    self._counters["near"] += 1
                    self._counters["near_updates"] += 1
                else:
                    self._counters["far"] += 1
                    self._counters["far_updates"] += 1

            self._counters["updates"] = self._update_index
            self._counters["deferred"] += deferred
            self._counters["due"] += due
            self._time = time_value

            return {
                "updated": updated,
                "deferred": deferred,
                "due": due,
            }

    def sample_instance(self, instance_id: str, time: float) -> Pose:
        with self._lock:
            record = self._get_instance(instance_id)
            samples = self._poses.get(record.instance_id, [])
            if not samples:
                raise WindDriverError(
                    "WIND_NO_SAMPLE", {"instance_id": record.instance_id}
                )
            time_value = _validate_time(time, "WIND_INVALID_TIME")
            amplitude, sway, interpolated = _interpolate_samples(
                samples, time_value
            )
            phase = self._phase_at(record.phase, time_value)
            return Pose(
                instance_id=record.instance_id,
                time=time_value,
                phase=phase,
                amplitude=amplitude,
                sway=sway,
                tier=record.tier,
                interpolated=interpolated,
            )

    def batch_of(self, time: float) -> list[Pose]:
        with self._lock:
            ordered = sorted(
                self._instances.values(),
                key=lambda record: (
                    math.hypot(*record.position),
                    record.instance_id,
                ),
            )
            for record in ordered:
                if not self._poses.get(record.instance_id):
                    raise WindDriverError(
                        "WIND_NO_SAMPLE",
                        {"instance_id": record.instance_id},
                    )
            time_value = _validate_time(time, "WIND_INVALID_TIME")
            return [
                self._sample_instance_locked(record.instance_id, time_value)
                for record in ordered
            ]

    def phase_of(self, instance_id: str) -> float:
        with self._lock:
            return self._get_instance(instance_id).phase

    def stats(self) -> dict:
        with self._lock:
            near = sum(
                record.tier == "near" for record in self._instances.values()
            )
            far = len(self._instances) - near
            return {
                "fields": len(self._fields),
                "instances": len(self._instances),
                "updates": self._update_index,
                "updated": self._counters["updated"],
                "deferred": self._counters["deferred"],
                "due": self._counters["due"],
                "time": self._time,
                "near": near,
                "far": far,
                "updates_by_tier": {
                    "near": self._counters["near_updates"],
                    "far": self._counters["far_updates"],
                },
                "wind": dict(self._wind) if self._wind is not None else None,
                "budget": dict(self._budget),
                "counters": dict(self._counters),
            }

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": SNAPSHOT_VERSION,
                "fields": {
                    field_id: {
                        "field_id": field.field_id,
                        "wavelength": field.wavelength,
                        "phase": field.phase,
                    }
                    for field_id, field in self._fields.items()
                },
                "instances": {
                    instance_id: {
                        "instance_id": record.instance_id,
                        "position": list(record.position),
                        "stiffness": record.stiffness,
                        "field": record.field,
                        "tier": record.tier,
                        "phase": record.phase,
                    }
                    for instance_id, record in self._instances.items()
                },
                "wind": dict(self._wind) if self._wind is not None else None,
                "previous": copy.deepcopy(self._wind_transition),
                "budget": dict(self._budget),
                "time": self._time,
                "update_index": self._update_index,
                "poses": {
                    instance_id: [
                        {
                            "instance_id": instance_id,
                            "time": sample.time,
                            "phase": self._phase_at(
                                self._instances[instance_id].phase,
                                sample.time,
                            ),
                            "amplitude": sample.amplitude,
                            "sway": sample.sway,
                            "tier": self._instances[instance_id].tier,
                            "interpolated": False,
                        }
                        for sample in samples
                    ]
                    for instance_id, samples in self._poses.items()
                    if samples
                },
                "counters": dict(self._counters),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                data = copy.deepcopy(state)
                parsed = _parse_snapshot(data)
            except WindDriverError:
                raise
            except Exception as exc:
                raise WindDriverError(
                    "WIND_SNAPSHOT_INVALID", {"reason": "unparseable_snapshot"}
                ) from exc

            self._fields = parsed["fields"]
            self._instances = parsed["instances"]
            self._wind = parsed["wind"]
            self._wind_transition = parsed["previous"]
            self._budget = parsed["budget"]
            self._time = parsed["time"]
            self._update_index = parsed["update_index"]
            self._poses = parsed["poses"]
            self._counters = parsed["counters"]

    def _get_instance(self, instance_id: str) -> InstanceRecord:
        if not isinstance(instance_id, str):
            raise WindDriverError(
                "WIND_UNKNOWN_INSTANCE", {"instance_id": instance_id}
            )
        clean_id = instance_id.strip()
        record = self._instances.get(clean_id)
        if record is None:
            raise WindDriverError(
                "WIND_UNKNOWN_INSTANCE", {"instance_id": instance_id}
            )
        return record

    def _phase_at(self, instance_phase: float, time: float) -> float:
        return (
            TWO_PI * float(self.frequency) * float(time) + instance_phase
        ) % TWO_PI

    def _target_amplitude(
        self, record: InstanceRecord, wind: dict[str, float] | None = None
    ) -> float:
        wind_state = self._wind if wind is None else wind
        if wind_state is None:
            raise WindDriverError("WIND_NOT_SET")
        field = self._fields[record.field]
        angle = math.radians(float(wind_state["direction"]))
        x, y = record.position
        along_wind = x * math.cos(angle) + y * math.sin(angle)
        field_phase = (
            TWO_PI * along_wind / field.wavelength + field.phase
        )
        field_wave = math.sin(field_phase)
        field_gain = 0.75 + 0.25 * field_wave
        return float(wind_state["strength"]) * field_gain

    def _effective_amplitude(
        self, record: InstanceRecord, time: float
    ) -> float:
        target = self._target_amplitude(record)
        transition = self._wind_transition
        if transition is None:
            return target
        duration = float(self._wind["transition"]) if self._wind else 0.0
        if duration <= 0.0:
            return target

        started_at = transition.get("started_at")
        if started_at is None:
            started_at = time
            transition["started_at"] = time
        alpha = (float(time) - float(started_at)) / duration
        if alpha <= 0.0:
            return float(transition.get("amplitudes", {}).get(
                record.instance_id, target
            ))
        if alpha >= 1.0:
            return target

        start = float(
            transition.get("amplitudes", {}).get(record.instance_id, target)
        )
        return start + (target - start) * alpha

    def _sample_instance_locked(
        self, instance_id: str, time: float
    ) -> Pose:
        record = self._instances[instance_id]
        samples = self._poses[instance_id]
        amplitude, sway, interpolated = _interpolate_samples(samples, time)
        return Pose(
            instance_id=instance_id,
            time=time,
            phase=self._phase_at(record.phase, time),
            amplitude=amplitude,
            sway=sway,
            tier=record.tier,
            interpolated=interpolated,
        )


def _clean_identifier(value: Any, code: str) -> str:
    if not isinstance(value, str):
        raise WindDriverError(code, {"id": value, "reason": "invalid_id_type"})
    clean = value.strip()
    if not clean:
        raise WindDriverError(code, {"id": value, "reason": "empty_id"})
    return clean


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _finite_number(
    value: Any,
    code: str,
    field_name: str,
    *,
    positive: bool = False,
    nonnegative: bool = False,
) -> float:
    if not _is_number(value):
        raise WindDriverError(
            code, {"field": field_name, "value": value, "reason": "invalid_type"}
        )
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise WindDriverError(
            code, {"field": field_name, "value": value, "reason": "invalid_number"}
        ) from exc
    if not math.isfinite(result):
        raise WindDriverError(
            code, {"field": field_name, "value": value, "reason": "not_finite"}
        )
    if positive and result <= 0.0:
        raise WindDriverError(
            code, {"field": field_name, "value": value, "reason": "not_positive"}
        )
    if nonnegative and result < 0.0:
        raise WindDriverError(
            code,
            {"field": field_name, "value": value, "reason": "negative_value"},
        )
    return result


def _positive_integer(value: Any, code: str, field_name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise WindDriverError(
            code, {"field": field_name, "value": value, "reason": "not_positive_int"}
        )
    return int(value)


def _nonnegative_integer(value: Any) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise WindDriverError(
            "WIND_SNAPSHOT_INVALID",
            {"value": value, "reason": "not_nonnegative_int"},
        )
    return int(value)


def _validate_time(value: Any, code: str) -> float:
    if not _is_number(value):
        raise WindDriverError(code, {"time": value, "reason": "invalid_type"})
    try:
        result = float(value)
    except (OverflowError, ValueError) as exc:
        raise WindDriverError(
            code, {"time": value, "reason": "invalid_number"}
        ) from exc
    if not math.isfinite(result):
        raise WindDriverError(code, {"time": value, "reason": "not_finite"})
    return result


def _parse_position(position: Any) -> tuple[float, float]:
    try:
        coordinates = tuple(position)
    except TypeError as exc:
        raise WindDriverError(
            "WIND_INVALID_INPUT", {"position": position, "reason": "invalid_position"}
        ) from exc
    if len(coordinates) != 2:
        raise WindDriverError(
            "WIND_INVALID_INPUT",
            {"position": position, "reason": "position_must_have_two_values"},
        )
    x = _finite_number(coordinates[0], "WIND_INVALID_INPUT", "position[0]")
    y = _finite_number(coordinates[1], "WIND_INVALID_INPUT", "position[1]")
    return x, y


def _instance_phase(instance_id: str) -> float:
    checksum = sum(
        (index + 1) * ord(character)
        for index, character in enumerate(instance_id)
    ) % 1024
    return round(TWO_PI * checksum / 1024.0, 6)


def _tier_for_distance(distance: float, near_radius: float) -> str:
    return "near" if distance < near_radius else "far"


def _replace_record(record: InstanceRecord, **changes: Any) -> InstanceRecord:
    return replace(record, **changes)


def _interpolate_samples(
    samples: list[_Sample], time: float
) -> tuple[float, float, bool]:
    first = samples[0]
    last = samples[-1]

    if time == last.time:
        return last.amplitude, last.sway, False
    if time == first.time:
        return first.amplitude, first.sway, False
    if time <= first.time:
        return first.amplitude, first.sway, False
    if time >= last.time:
        return last.amplitude, last.sway, False
    if last.time == first.time:
        return last.amplitude, last.sway, False

    ratio = (time - first.time) / (last.time - first.time)
    amplitude = first.amplitude + (last.amplitude - first.amplitude) * ratio
    sway = first.sway + (last.sway - first.sway) * ratio
    return amplitude, sway, True


_SNAPSHOT_KEYS = {
    "version",
    "fields",
    "instances",
    "wind",
    "previous",
    "budget",
    "time",
    "update_index",
    "poses",
    "counters",
}


def _snapshot_invalid(detail: Any) -> WindDriverError:
    return WindDriverError("WIND_SNAPSHOT_INVALID", detail)


def _parse_snapshot(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise _snapshot_invalid({"reason": "snapshot_not_mapping"})
    if set(data.keys()) != _SNAPSHOT_KEYS:
        raise _snapshot_invalid({"reason": "unexpected_snapshot_keys"})
    if (
        not isinstance(data["version"], int)
        or isinstance(data["version"], bool)
        or data["version"] != SNAPSHOT_VERSION
    ):
        raise _snapshot_invalid({"field": "version"})
    if not isinstance(data["fields"], dict):
        raise _snapshot_invalid({"field": "fields"})
    if not isinstance(data["instances"], dict):
        raise _snapshot_invalid({"field": "instances"})
    if not isinstance(data["poses"], dict):
        raise _snapshot_invalid({"field": "poses"})
    if not isinstance(data["counters"], dict):
        raise _snapshot_invalid({"field": "counters"})
    if not isinstance(data["budget"], dict):
        raise _snapshot_invalid({"field": "budget"})

    fields = _parse_snapshot_fields(data["fields"])
    budget = _parse_snapshot_budget(data["budget"])
    instances = _parse_snapshot_instances(
        data["instances"], fields, float(budget["near_radius"])
    )
    wind = _parse_snapshot_wind(data["wind"])
    previous = _parse_snapshot_previous(data["previous"], instances)
    time_value = _parse_optional_finite(data["time"], "time")
    update_index = _nonnegative_integer(data["update_index"])
    poses = _parse_snapshot_poses(data["poses"], instances)
    counters = _parse_snapshot_counters(data["counters"])
    counters["updates"] = update_index

    return {
        "fields": fields,
        "instances": instances,
        "wind": wind,
        "previous": previous,
        "budget": budget,
        "time": time_value,
        "update_index": update_index,
        "poses": poses,
        "counters": counters,
    }


def _parse_optional_finite(value: Any, field_name: str) -> float | None:
    if value is None:
        return None
    return _finite_number(value, "WIND_SNAPSHOT_INVALID", field_name)


def _parse_snapshot_fields(data: dict) -> dict[str, FieldRecord]:
    fields: dict[str, FieldRecord] = {}
    for key, value in data.items():
        if not isinstance(key, str) or not key.strip() or not isinstance(value, dict):
            raise _snapshot_invalid({"field": "fields", "id": key})
        field_id = key.strip()
        if value.get("field_id", field_id) != key and (
            not isinstance(value.get("field_id"), str)
            or value["field_id"].strip() != field_id
        ):
            raise _snapshot_invalid({"field": "fields", "id": key})
        wavelength = _finite_number(
            value.get("wavelength"),
            "WIND_SNAPSHOT_INVALID",
            "wavelength",
            positive=True,
        )
        phase = _finite_number(
            value.get("phase", 0.0), "WIND_SNAPSHOT_INVALID", "phase"
        )
        fields[field_id] = FieldRecord(field_id, wavelength, phase)
    return fields


def _parse_snapshot_budget(data: dict) -> dict[str, Any]:
    per_update = _positive_integer(
        data.get("per_update"), "WIND_SNAPSHOT_INVALID", "per_update"
    )
    far_stride = _positive_integer(
        data.get("far_stride"), "WIND_SNAPSHOT_INVALID", "far_stride"
    )
    near_radius = _finite_number(
        data.get("near_radius"),
        "WIND_SNAPSHOT_INVALID",
        "near_radius",
        positive=True,
    )
    return {
        "per_update": per_update,
        "far_stride": far_stride,
        "near_radius": near_radius,
    }


def _parse_snapshot_instances(
    data: dict, fields: dict[str, FieldRecord], near_radius: float
) -> dict[str, InstanceRecord]:
    instances: dict[str, InstanceRecord] = {}
    for key, value in data.items():
        if not isinstance(key, str) or not key.strip() or not isinstance(value, dict):
            raise _snapshot_invalid({"field": "instances", "id": key})
        instance_id = key.strip()
        position_data = value.get("position")
        if not isinstance(position_data, (list, tuple)):
            raise _snapshot_invalid({"field": "instances.position", "id": key})
        try:
            position = _parse_position(position_data)
        except WindDriverError as exc:
            raise _snapshot_invalid(
                {"field": "instances.position", "id": key}
            ) from exc
        stiffness = _finite_number(
            value.get("stiffness", 1.0),
            "WIND_SNAPSHOT_INVALID",
            "stiffness",
            positive=True,
        )
        field_id = value.get("field")
        if not isinstance(field_id, str) or field_id.strip() not in fields:
            raise _snapshot_invalid({"field": "instances.field", "id": key})
        field_id = field_id.strip()
        if "tier" in value and value["tier"] not in ("near", "far"):
            raise _snapshot_invalid({"field": "instances.tier", "id": key})
        phase_value = value.get("phase", _instance_phase(instance_id))
        phase = _finite_number(
            phase_value, "WIND_SNAPSHOT_INVALID", "instance_phase"
        )
        if not math.isfinite(phase):
            raise _snapshot_invalid({"field": "instances.phase", "id": key})
        distance = math.hypot(*position)
        tier = _tier_for_distance(distance, near_radius)
        instances[instance_id] = InstanceRecord(
            instance_id=instance_id,
            position=position,
            stiffness=stiffness,
            field=field_id,
            tier=tier,
            phase=_instance_phase(instance_id),
        )
    return instances


def _parse_snapshot_wind(value: Any) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise _snapshot_invalid({"field": "wind"})
    strength = _finite_number(
        value.get("strength"),
        "WIND_SNAPSHOT_INVALID",
        "strength",
        nonnegative=True,
    )
    direction = _finite_number(
        value.get("direction"), "WIND_SNAPSHOT_INVALID", "direction"
    )
    transition = _finite_number(
        value.get("transition", 0.0),
        "WIND_SNAPSHOT_INVALID",
        "transition",
        nonnegative=True,
    )
    return {
        "strength": strength,
        "direction": direction % 360.0,
        "transition": transition,
    }


def _parse_snapshot_previous(
    value: Any, instances: dict[str, InstanceRecord]
) -> dict[str, Any] | None:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise _snapshot_invalid({"field": "previous"})
    started_at = _parse_optional_finite(value.get("started_at"), "started_at")
    amplitudes_data = value.get("amplitudes", {})
    if not isinstance(amplitudes_data, dict):
        raise _snapshot_invalid({"field": "previous.amplitudes"})
    amplitudes: dict[str, float] = {}
    for instance_id, amplitude in amplitudes_data.items():
        if not isinstance(instance_id, str) or instance_id not in instances:
            raise _snapshot_invalid({"field": "previous.amplitudes", "id": instance_id})
        amplitudes[instance_id] = _finite_number(
            amplitude, "WIND_SNAPSHOT_INVALID", "amplitude", nonnegative=True
        )
    return {"started_at": started_at, "amplitudes": amplitudes}


def _parse_snapshot_poses(
    data: dict, instances: dict[str, InstanceRecord]
) -> dict[str, list[_Sample]]:
    poses: dict[str, list[_Sample]] = {}
    for instance_id, pose_data in data.items():
        if not isinstance(instance_id, str) or instance_id not in instances:
            raise _snapshot_invalid({"field": "poses", "id": instance_id})
        if not isinstance(pose_data, list) or not 1 <= len(pose_data) <= 2:
            raise _snapshot_invalid({"field": "poses", "id": instance_id})
        samples: list[_Sample] = []
        last_time: float | None = None
        for item in pose_data:
            if not isinstance(item, dict):
                raise _snapshot_invalid({"field": "poses.item", "id": instance_id})
            sample_time = _finite_number(
                item.get("time"), "WIND_SNAPSHOT_INVALID", "pose.time"
            )
            amplitude = _finite_number(
                item.get("amplitude"),
                "WIND_SNAPSHOT_INVALID",
                "pose.amplitude",
            )
            sway = _finite_number(
                item.get("sway"), "WIND_SNAPSHOT_INVALID", "pose.sway"
            )
            if last_time is not None and sample_time < last_time:
                raise _snapshot_invalid(
                    {"field": "poses.time", "id": instance_id}
                )
            last_time = sample_time
            samples.append(_Sample(sample_time, amplitude, sway))
        poses[instance_id] = samples
    return poses


def _parse_snapshot_counters(data: dict) -> dict[str, int]:
    counters: dict[str, int] = {}
    for key, value in data.items():
        counters[key] = _nonnegative_integer(value)
    for key in ("updated", "deferred", "due", "near", "far",
                "near_updates", "far_updates"):
        counters.setdefault(key, 0)
    if counters["near_updates"] == 0 and counters["near"]:
        counters["near_updates"] = counters["near"]
    if counters["far_updates"] == 0 and counters["far"]:
        counters["far_updates"] = counters["far"]
    counters["near"] = counters["near_updates"]
    counters["far"] = counters["far_updates"]
    return counters
