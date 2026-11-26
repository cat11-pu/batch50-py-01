"""Pose blend stack: ordered animation layers, masks, and quaternion blending."""

from __future__ import annotations

import copy
import math
import threading
from collections import deque
from collections.abc import Mapping, Sequence

__all__ = [
    "PoseError",
    "PoseBlendStack",
    "IDENTITY",
]

IDENTITY = (0.0, 0.0, 0.0, 1.0)
SCHEMA_VERSION = 1


class PoseError(ValueError):
    """Raised when a pose stack request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _finite_number(value) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _valid_weight(weight) -> bool:
    return _finite_number(weight) and weight >= 0.0


def _valid_layer_id(layer_id) -> bool:
    return isinstance(layer_id, str) and layer_id != ""


def _normalize_quaternion(value) -> tuple[float, float, float, float]:
    if isinstance(value, (str, bytes, bytearray)) or not isinstance(
        value, Sequence
    ):
        raise PoseError("POSE_INVALID_POSE", {"quaternion": value})

    components = tuple(value)
    if len(components) != 4 or not all(
        _finite_number(component) for component in components
    ):
        raise PoseError("POSE_INVALID_POSE", {"quaternion": value})

    x, y, z, w = (float(component) for component in components)
    scale = max(abs(x), abs(y), abs(z), abs(w))
    if scale == 0.0:
        raise PoseError("POSE_INVALID_POSE", {"quaternion": value})

    sx, sy, sz, sw = x / scale, y / scale, z / scale, w / scale
    norm = math.sqrt(sx * sx + sy * sy + sz * sz + sw * sw)
    return (sx / norm, sy / norm, sz / norm, sw / norm)


def _normalize_pose(pose) -> dict[str, tuple[float, float, float, float]]:
    if not isinstance(pose, Mapping):
        raise PoseError("POSE_INVALID_REQUEST", {"pose": pose})

    normalized = {}
    for bone, quaternion in pose.items():
        if not _valid_layer_id(bone):
            raise PoseError("POSE_INVALID_REQUEST", {"bone": bone})
        normalized[bone] = _normalize_quaternion(quaternion)
    return normalized


def _validate_mask(mask, max_mask_bones: int):
    if mask is None:
        return None
    if not isinstance(mask, Mapping):
        raise PoseError("POSE_INVALID_REQUEST", {"mask": mask})
    if len(mask) > max_mask_bones:
        raise PoseError("POSE_MASK_LIMIT", {"max_mask_bones": max_mask_bones})

    cleaned = {}
    for bone, value in mask.items():
        if not _valid_layer_id(bone):
            raise PoseError("POSE_INVALID_REQUEST", {"bone": bone})
        if not _finite_number(value) or not 0.0 <= float(value) <= 1.0:
            raise PoseError("POSE_INVALID_REQUEST", {"mask_value": value})
        cleaned[bone] = float(value)
    return cleaned


def _quaternion_dot(a, b) -> float:
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2] + a[3] * b[3]


def _quaternion_multiply(a, b):
    ax, ay, az, aw = a
    bx, by, bz, bw = b
    return (
        aw * bx + ax * bw + ay * bz - az * by,
        aw * by - ax * bz + ay * bw + az * bx,
        aw * bz + ax * by - ay * bx + az * bw,
        aw * bw - ax * bx - ay * by - az * bz,
    )


def _slerp(a, b, t: float):
    if t <= 0.0:
        return a
    if t >= 1.0:
        return b

    dot = max(-1.0, min(1.0, _quaternion_dot(a, b)))
    if dot < 0.0:
        b = tuple(-component for component in b)
        dot = -dot

    if dot > 0.9995:
        result = tuple(
            a[index] + (b[index] - a[index]) * t for index in range(4)
        )
        norm = math.sqrt(sum(component * component for component in result))
        return tuple(component / norm for component in result)

    theta_0 = math.acos(dot)
    theta = theta_0 * t
    sin_theta = math.sin(theta)
    sin_theta_0 = math.sin(theta_0)
    scale_a = math.cos(theta) - dot * sin_theta / sin_theta_0
    scale_b = sin_theta / sin_theta_0
    result = tuple(
        a[index] * scale_a + b[index] * scale_b for index in range(4)
    )
    norm = math.sqrt(sum(component * component for component in result))
    return tuple(component / norm for component in result)


def _normalized_quaternion(q) -> tuple[float, float, float, float]:
    norm = math.sqrt(sum(component * component for component in q))
    return tuple(component / norm for component in q)


def _scaled_rotation(q, weight: float):
    """Scale the shortest axis-angle rotation represented by *q*."""
    x, y, z, w = q
    if w < 0.0:
        x, y, z, w = -x, -y, -z, -w
    w = max(-1.0, min(1.0, w))
    angle = 2.0 * math.acos(w)
    if angle == 0.0:
        return IDENTITY

    sin_half = math.sqrt(max(0.0, 1.0 - w * w))
    if sin_half < 1e-12:
        return IDENTITY

    axis = (x / sin_half, y / sin_half, z / sin_half)
    scaled_half = angle * weight * 0.5
    sin_scaled = math.sin(scaled_half)
    return (
        axis[0] * sin_scaled,
        axis[1] * sin_scaled,
        axis[2] * sin_scaled,
        math.cos(scaled_half),
    )


class PoseBlendStack:
    """Stack animation layers and evaluate one blended pose per bone."""

    def __init__(self, *, max_layers: int = 8, max_history: int = 8,
                 max_mask_bones: int = 64) -> None:
        if (
            not isinstance(max_layers, int)
            or isinstance(max_layers, bool)
            or max_layers < 0
        ):
            raise PoseError("POSE_INVALID_REQUEST", {"max_layers": max_layers})
        if (
            not isinstance(max_history, int)
            or isinstance(max_history, bool)
            or max_history < 0
        ):
            raise PoseError(
                "POSE_INVALID_REQUEST", {"max_history": max_history}
            )
        if (
            not isinstance(max_mask_bones, int)
            or isinstance(max_mask_bones, bool)
            or max_mask_bones < 0
        ):
            raise PoseError(
                "POSE_INVALID_REQUEST", {"max_mask_bones": max_mask_bones}
            )

        self.max_layers = max_layers
        self.max_history = max_history
        self.max_mask_bones = max_mask_bones
        self._lock = threading.RLock()
        self._layers: dict[str, dict] = {}
        self._history = deque(maxlen=max_history)
        self._limits: dict[str, tuple] = {}
        self._stats = {
            "layers_added": 0,
            "layers_removed": 0,
            "poses_pushed": 0,
            "evaluations": 0,
            "weight_updates": 0,
            "mask_updates": 0,
        }

    def _require_layer(self, layer_id: str) -> dict:
        if not _valid_layer_id(layer_id):
            raise PoseError("POSE_INVALID_REQUEST", {"layer_id": layer_id})
        try:
            return self._layers[layer_id]
        except KeyError:
            raise PoseError(
                "POSE_UNKNOWN_LAYER", {"layer_id": layer_id}
            ) from None

    def _effective_weight(self, layer: dict, bone: str) -> float:
        weight = layer["weight"]
        mask = layer["mask"]
        if mask is None:
            return weight
        if bone not in mask:
            return 0.0
        return weight * mask[bone]

    def _bone_order(self) -> list[str]:
        bones = []
        seen = set()
        for layer in self._layers.values():
            for bone in layer["pose"]:
                if bone not in seen:
                    seen.add(bone)
                    bones.append(bone)
        return bones

    def _blend_override_bone(self, bone: str):
        contributors = []
        for layer in self._layers.values():
            if layer["mode"] != "override":
                continue
            quaternion = layer["pose"].get(bone)
            if quaternion is None:
                continue
            weight = self._effective_weight(layer, bone)
            if weight <= 0.0:
                continue
            contributors.append((quaternion, weight))

        if not contributors:
            return None

        max_weight = max(weight for _, weight in contributors)
        scaled_weights = [
            weight / max_weight for _, weight in contributors
        ]
        total_weight = math.fsum(scaled_weights)
        normalized_weights = [
            weight / total_weight for weight in scaled_weights
        ]
        result = contributors[0][0]
        accumulated = normalized_weights[0]
        for index in range(1, len(contributors)):
            target = contributors[index][0]
            target_weight = normalized_weights[index]
            t = target_weight / (accumulated + target_weight)
            result = _slerp(result, target, t)
            accumulated += target_weight
        return tuple(float(component) for component in result)

    def _apply_additive_layers(self, pose: dict) -> dict:
        result = dict(pose)
        for layer in self._layers.values():
            if layer["mode"] != "additive":
                continue
            for bone, quaternion in layer["pose"].items():
                weight = self._effective_weight(layer, bone)
                if weight <= 0.0:
                    continue
                base = result.get(bone, IDENTITY)
                delta = _scaled_rotation(quaternion, weight)
                result[bone] = _normalized_quaternion(
                    _quaternion_multiply(base, delta)
                )

        for bone in list(result):
            result[bone] = self._clamp_to_limits(bone, result[bone])
        return result

    def _clamp_to_limits(self, bone: str, quaternion):
        if bone not in self._limits:
            return quaternion

        low, high = self._limits[bone]
        if isinstance(low, Sequence) and isinstance(high, Sequence):
            low = tuple(low)
            high = tuple(high)
            if len(low) == 4 and len(high) == 4:
                clamped = tuple(
                    max(low[index], min(high[index], quaternion[index]))
                    for index in range(4)
                )
                norm = math.sqrt(sum(value * value for value in clamped))
                if norm > 0.0:
                    return tuple(value / norm for value in clamped)
            return quaternion

        max_angle = float(high)
        min_angle = float(low)
        x, y, z, w = quaternion
        if w < 0.0:
            x, y, z, w = -x, -y, -z, -w
        w = max(-1.0, min(1.0, w))
        angle = 2.0 * math.acos(w)
        clamped_angle = max(min_angle, min(max_angle, angle))
        if angle == 0.0 or clamped_angle == angle:
            return quaternion
        if clamped_angle == 0.0:
            return IDENTITY

        sin_half = math.sqrt(max(0.0, 1.0 - w * w))
        if sin_half == 0.0:
            return quaternion
        axis = (x / sin_half, y / sin_half, z / sin_half)
        half = clamped_angle * 0.5
        return (
            axis[0] * math.sin(half),
            axis[1] * math.sin(half),
            axis[2] * math.sin(half),
            math.copysign(math.cos(half), w),
        )

    def add_layer(self, layer_id: str, *, mode: str = "override",
                  weight: float = 1.0, mask=None) -> None:
        with self._lock:
            if not _valid_layer_id(layer_id):
                raise PoseError(
                    "POSE_INVALID_REQUEST", {"layer_id": layer_id}
                )
            if layer_id in self._layers:
                raise PoseError(
                    "POSE_LAYER_EXISTS", {"layer_id": layer_id}
                )
            if mode not in ("override", "additive"):
                raise PoseError("POSE_INVALID_REQUEST", {"mode": mode})
            if not _valid_weight(weight):
                raise PoseError("POSE_INVALID_REQUEST", {"weight": weight})

            cleaned_mask = _validate_mask(mask, self.max_mask_bones)
            if len(self._layers) >= self.max_layers:
                raise PoseError(
                    "POSE_LAYER_LIMIT", {"max_layers": self.max_layers}
                )

            self._layers[layer_id] = {
                "layer_id": layer_id,
                "mode": mode,
                "weight": float(weight),
                "mask": cleaned_mask,
                "pose": {},
            }
            self._stats["layers_added"] += 1

    def set_weight(self, layer_id: str, weight: float) -> None:
        with self._lock:
            layer = self._require_layer(layer_id)
            if not _valid_weight(weight):
                raise PoseError("POSE_INVALID_REQUEST", {"weight": weight})
            layer["weight"] = float(weight)
            self._stats["weight_updates"] += 1

    def set_mask(self, layer_id: str, mask) -> None:
        with self._lock:
            layer = self._require_layer(layer_id)
            cleaned_mask = _validate_mask(mask, self.max_mask_bones)
            layer["mask"] = cleaned_mask
            self._stats["mask_updates"] += 1

    def push_pose(self, layer_id: str, pose) -> None:
        with self._lock:
            layer = self._require_layer(layer_id)
            normalized_pose = _normalize_pose(pose)
            layer["pose"] = normalized_pose
            self._stats["poses_pushed"] += 1

    def evaluate(self) -> dict:
        with self._lock:
            pose = {}
            for bone in self._bone_order():
                blended = self._blend_override_bone(bone)
                if blended is not None:
                    pose[bone] = blended
            pose = self._apply_additive_layers(pose)

            self._stats["evaluations"] += 1
            revision = self._stats["evaluations"]
            record_pose = dict(pose)
            self._history.append({"revision": revision, "pose": record_pose})
            return {"revision": revision, "pose": dict(pose)}

    def remove_layer(self, layer_id: str) -> None:
        with self._lock:
            self._require_layer(layer_id)
            del self._layers[layer_id]
            self._stats["layers_removed"] += 1

    def layer_state(self, layer_id: str) -> dict:
        with self._lock:
            layer = self._require_layer(layer_id)
            return {
                "layer_id": layer["layer_id"],
                "mode": layer["mode"],
                "weight": layer["weight"],
                "mask": None
                if layer["mask"] is None
                else dict(layer["mask"]),
                "pose": {
                    bone: tuple(quaternion)
                    for bone, quaternion in layer["pose"].items()
                },
            }

    def layers(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(self._layers)

    def set_limits(self, bone: str, low, high) -> None:
        with self._lock:
            if not _valid_layer_id(bone):
                raise PoseError("POSE_INVALID_REQUEST", {"bone": bone})

            if isinstance(low, Sequence) or isinstance(high, Sequence):
                if not (isinstance(low, Sequence) and isinstance(high, Sequence)):
                    raise PoseError(
                        "POSE_INVALID_REQUEST", {"low": low, "high": high}
                    )
                low_tuple = tuple(low)
                high_tuple = tuple(high)
                if len(low_tuple) != len(high_tuple) or len(low_tuple) not in (
                    3,
                    4,
                ):
                    raise PoseError(
                        "POSE_INVALID_REQUEST", {"low": low, "high": high}
                    )
                if not all(_finite_number(v) for v in low_tuple + high_tuple):
                    raise PoseError(
                        "POSE_INVALID_REQUEST", {"low": low, "high": high}
                    )
                if any(
                    low_tuple[i] > high_tuple[i]
                    for i in range(len(low_tuple))
                ):
                    raise PoseError(
                        "POSE_INVALID_REQUEST", {"low": low, "high": high}
                    )
                self._limits[bone] = (low_tuple, high_tuple)
                return

            if not _finite_number(low) or not _finite_number(high):
                raise PoseError(
                    "POSE_INVALID_REQUEST", {"low": low, "high": high}
                )
            if float(low) > float(high):
                raise PoseError(
                    "POSE_INVALID_REQUEST", {"low": low, "high": high}
                )
            self._limits[bone] = (float(low), float(high))

    def history(self) -> tuple[dict, ...]:
        with self._lock:
            return tuple(
                {
                    "revision": record["revision"],
                    "pose": dict(record["pose"]),
                }
                for record in self._history
            )

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "schema": SCHEMA_VERSION,
                "layers": [
                    {
                        "layer_id": layer["layer_id"],
                        "mode": layer["mode"],
                        "weight": layer["weight"],
                        "mask": None
                        if layer["mask"] is None
                        else dict(layer["mask"]),
                        "pose": {
                            bone: tuple(quaternion)
                            for bone, quaternion in layer["pose"].items()
                        },
                    }
                    for layer in self._layers.values()
                ],
                "history": [
                    {
                        "revision": record["revision"],
                        "pose": dict(record["pose"]),
                    }
                    for record in self._history
                ],
                "stats": dict(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._parse_snapshot(state)
            except PoseError:
                raise
            except Exception as exc:
                raise PoseError(
                    "POSE_SNAPSHOT_INVALID", {"error": str(exc)}
                ) from exc
            self._layers = restored["layers"]
            self._history = restored["history"]
            self._stats = restored["stats"]

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _parse_snapshot(self, state) -> dict:
        invalid = PoseError("POSE_SNAPSHOT_INVALID", None)
        if not isinstance(state, Mapping):
            raise invalid
        if set(state) != {"schema", "layers", "history", "stats"}:
            raise invalid
        if state["schema"] != SCHEMA_VERSION:
            raise invalid

        raw_layers = state["layers"]
        raw_history = state["history"]
        raw_stats = state["stats"]
        if not isinstance(raw_layers, list):
            raise invalid
        if not isinstance(raw_history, list):
            raise invalid
        if not isinstance(raw_stats, Mapping):
            raise invalid
        if len(raw_layers) > self.max_layers:
            raise invalid
        if len(raw_history) > self.max_history:
            raise invalid

        layers = {}
        for raw_layer in raw_layers:
            layer = self._parse_snapshot_layer(raw_layer)
            if layer["layer_id"] in layers:
                raise invalid
            layers[layer["layer_id"]] = layer

        history = deque(maxlen=self.max_history)
        previous_revision = 0
        for raw_record in raw_history:
            if not isinstance(raw_record, Mapping):
                raise invalid
            if set(raw_record) != {"revision", "pose"}:
                raise invalid
            revision = raw_record["revision"]
            if (
                not isinstance(revision, int)
                or isinstance(revision, bool)
                or revision <= previous_revision
            ):
                raise invalid
            try:
                pose = _normalize_pose(raw_record["pose"])
            except PoseError:
                raise invalid from None
            history.append({"revision": revision, "pose": pose})
            previous_revision = revision

        stats = self._parse_snapshot_stats(raw_stats)
        if history and history[-1]["revision"] != stats["evaluations"]:
            raise invalid
        if not history and raw_history:
            raise invalid

        return {"layers": layers, "history": history, "stats": stats}

    def _parse_snapshot_layer(self, raw_layer) -> dict:
        invalid = PoseError("POSE_SNAPSHOT_INVALID", None)
        if not isinstance(raw_layer, Mapping):
            raise invalid
        if set(raw_layer) != {
            "layer_id",
            "mode",
            "weight",
            "mask",
            "pose",
        }:
            raise invalid

        layer_id = raw_layer["layer_id"]
        if not _valid_layer_id(layer_id):
            raise invalid
        if raw_layer["mode"] not in ("override", "additive"):
            raise invalid
        if not _valid_weight(raw_layer["weight"]):
            raise invalid

        raw_mask = raw_layer["mask"]
        if raw_mask is not None:
            try:
                mask = _validate_mask(raw_mask, self.max_mask_bones)
            except PoseError:
                raise invalid from None
        else:
            mask = None

        try:
            pose = _normalize_pose(raw_layer["pose"])
        except PoseError:
            raise invalid from None

        return {
            "layer_id": layer_id,
            "mode": raw_layer["mode"],
            "weight": float(raw_layer["weight"]),
            "mask": mask,
            "pose": pose,
        }

    @staticmethod
    def _parse_snapshot_stats(raw_stats) -> dict:
        invalid = PoseError("POSE_SNAPSHOT_INVALID", None)
        expected = {
            "layers_added",
            "layers_removed",
            "poses_pushed",
            "evaluations",
            "weight_updates",
            "mask_updates",
        }
        if set(raw_stats) != expected:
            raise invalid

        stats = {}
        for key in expected:
            value = raw_stats[key]
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise invalid
            stats[key] = value
        return stats
