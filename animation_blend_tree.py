"""Animation blend tree with weight normalization, sync groups and layer masks."""

from __future__ import annotations

import math
import threading
from collections.abc import Mapping


class BlendError(ValueError):
    """Raised when an animation blend operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class AnimationBlendTree:
    """Blend layered animation clips per bone with normalized weights."""

    def __init__(self, *, default_pose=None) -> None:
        if default_pose is not None:
            if not isinstance(default_pose, dict):
                raise BlendError("BLEND_INVALID_ARGUMENT", default_pose)
            for bone, value in default_pose.items():
                if not isinstance(bone, str) or not bone:
                    raise BlendError("BLEND_INVALID_ARGUMENT", bone)
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    raise BlendError("BLEND_INVALID_ARGUMENT", value)
        self.default_pose = dict(default_pose or {})
        self._clips: dict[str, dict] = {}
        self._groups: dict[str, set[str]] = {}
        self._clip_group: dict[str, str] = {}
        self._masks: dict[int, tuple[str, ...]] = {}
        self._counters = {
            "evaluations": 0,
            "fallback_evals": 0,
            "sync_joins": 0,
            "mask_updates": 0,
        }
        self._lock = threading.RLock()

    def add_clip(self, clip_id, *, layer=0, length=1.0, weight=1.0,
                 phase=0.0, bones=None):
        with self._lock:
            if not self._valid_name(clip_id):
                raise BlendError("BLEND_INVALID_ARGUMENT", clip_id)
            if clip_id in self._clips:
                raise BlendError("BLEND_DUPLICATE", clip_id)

            record = self._build_record(clip_id, layer, length, weight, phase,
                                        bones)
            self._clips[clip_id] = record
            return self._public_record(record)

    def remove_clip(self, clip_id):
        with self._lock:
            if not self._valid_name(clip_id) or clip_id not in self._clips:
                raise BlendError("BLEND_UNKNOWN", clip_id)

            record = self._clips.pop(clip_id)
            group = self._clip_group.pop(clip_id, None)
            if group is not None:
                members = self._groups.get(group)
                if members is not None:
                    members.discard(clip_id)
                    if not members:
                        del self._groups[group]
            return self._public_record(record)

    def set_weight(self, clip_id, weight):
        with self._lock:
            if not self._valid_name(clip_id) or clip_id not in self._clips:
                raise BlendError("BLEND_UNKNOWN", clip_id)
            if not self._valid_weight(weight):
                raise BlendError("BLEND_INVALID_ARGUMENT", weight)
            value = float(weight)
            self._clips[clip_id]["weight"] = value
            return value

    def set_phase(self, clip_id, phase):
        with self._lock:
            if not self._valid_name(clip_id) or clip_id not in self._clips:
                raise BlendError("BLEND_UNKNOWN", clip_id)
            if not self._valid_phase(phase):
                raise BlendError("BLEND_INVALID_ARGUMENT", phase)
            value = float(phase)
            self._clips[clip_id]["phase"] = value
            return value

    def join_sync_group(self, group, clip_id):
        with self._lock:
            if not self._valid_name(group):
                raise BlendError("BLEND_INVALID_ARGUMENT", group)
            if not self._valid_name(clip_id) or clip_id not in self._clips:
                raise BlendError("BLEND_UNKNOWN", clip_id)

            current = self._clip_group.get(clip_id)
            if current is not None:
                if current != group:
                    raise BlendError("BLEND_SYNC_CONFLICT", clip_id)
                return tuple(sorted(self._groups[current]))

            members = self._groups.get(group)
            if members:
                length = self._clips[clip_id]["length"]
                reference = next(iter(members))
                if self._clips[reference]["length"] != length:
                    raise BlendError("BLEND_SYNC_LENGTH", clip_id)
            else:
                members = set()
                self._groups[group] = members

            members.add(clip_id)
            self._clip_group[clip_id] = group
            self._counters["sync_joins"] += 1
            return tuple(sorted(members))

    def evaluate(self, time):
        if not self._valid_time(time):
            raise BlendError("BLEND_INVALID_ARGUMENT", time)

        with self._lock:
            self._counters["evaluations"] += 1

            overrides = self._sync_phases(time)
            layers: dict[int, list[str]] = {}
            all_bones: set[str] = set()
            for clip_id, record in self._clips.items():
                all_bones.update(record["bones"])
                if record["weight"] > 0.0:
                    layers.setdefault(record["layer"], []).append(clip_id)

            result: dict[str, float] = {}
            for layer in sorted(layers):
                totals: dict[str, list[float]] = {}
                for clip_id in sorted(layers[layer]):
                    record = self._clips[clip_id]
                    weight = record["weight"]
                    if weight <= 0.0:
                        continue
                    effective = overrides.get(clip_id)
                    if effective is None:
                        effective = self._effective(record, time)
                    ratio = effective / record["length"]
                    for bone, (start, end) in record["bones"].items():
                        value = start + (end - start) * ratio
                        entry = totals.get(bone)
                        if entry is None:
                            totals[bone] = [value * weight, weight]
                        else:
                            entry[0] += value * weight
                            entry[1] += weight

                blended = {
                    bone: total / weight
                    for bone, (total, weight) in totals.items()
                    if weight > 0.0
                }
                allowed = self._masks.get(layer)
                if allowed is None:
                    for bone, value in blended.items():
                        result[bone] = value
                else:
                    allowed_set = set(allowed)
                    for bone, value in blended.items():
                        if bone in allowed_set:
                            result[bone] = value

            if not result:
                self._counters["fallback_evals"] += 1
                return {
                    "bones": dict(sorted(self.default_pose.items())),
                    "fallback": True,
                    "normalized": False,
                }

            for bone in all_bones:
                if bone not in result and bone in self.default_pose:
                    result[bone] = self.default_pose[bone]

            return {
                "bones": dict(sorted(result.items())),
                "fallback": False,
                "normalized": True,
            }

    def set_layer_mask(self, layer, bones):
        with self._lock:
            if not self._valid_layer(layer):
                raise BlendError("BLEND_INVALID_ARGUMENT", layer)
            if isinstance(bones, (str, bytes)) or bones is None:
                raise BlendError("BLEND_INVALID_ARGUMENT", bones)
            try:
                items = list(bones)
            except TypeError as exc:
                raise BlendError("BLEND_INVALID_ARGUMENT", bones) from exc
            if not items:
                raise BlendError("BLEND_INVALID_ARGUMENT", bones)
            for bone in items:
                if not self._valid_name(bone):
                    raise BlendError("BLEND_INVALID_ARGUMENT", bone)

            mask = tuple(sorted(set(items)))
            self._masks[layer] = mask
            self._counters["mask_updates"] += 1
            return mask

    def pose_of(self, clip_id, time):
        with self._lock:
            if not self._valid_name(clip_id) or clip_id not in self._clips:
                raise BlendError("BLEND_UNKNOWN", clip_id)
            if not self._valid_time(time):
                raise BlendError("BLEND_INVALID_ARGUMENT", time)

            record = self._clips[clip_id]
            effective = self._effective(record, time)
            ratio = effective / record["length"]
            pose = {
                bone: start + (end - start) * ratio
                for bone, (start, end) in record["bones"].items()
            }
            return {
                "effective": effective,
                "bones": dict(sorted(pose.items())),
            }

    def snapshot(self):
        with self._lock:
            clips = {}
            for clip_id in sorted(self._clips):
                record = self._clips[clip_id]
                clips[clip_id] = {
                    "clip_id": clip_id,
                    "layer": record["layer"],
                    "length": record["length"],
                    "weight": record["weight"],
                    "phase": record["phase"],
                    "bones": {
                        bone: tuple(record["bones"][bone])
                        for bone in sorted(record["bones"])
                    },
                }
            groups = {
                group: list(sorted(members))
                for group, members in sorted(self._groups.items())
            }
            masks = {
                layer: tuple(mask)
                for layer, mask in sorted(self._masks.items())
            }
            stats = self._stats_unlocked()
            return {
                "version": 1,
                "clips": clips,
                "groups": groups,
                "masks": masks,
                "default_pose": dict(self.default_pose),
                "stats": stats,
            }

    def restore(self, state):
        with self._lock:
            try:
                (clips, groups, clip_group, masks, default_pose,
                 counters) = self._parse_snapshot(state)
            except BlendError:
                raise BlendError("BLEND_SNAPSHOT_INVALID", state) from None
            except Exception as exc:
                raise BlendError("BLEND_SNAPSHOT_INVALID", state) from exc

            self._clips = clips
            self._groups = groups
            self._clip_group = clip_group
            self._masks = masks
            self.default_pose = default_pose
            self._counters = counters

    def stats(self):
        with self._lock:
            return self._stats_unlocked()

    @staticmethod
    def _valid_name(value):
        return isinstance(value, str) and bool(value)

    @staticmethod
    def _is_number(value):
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            return False
        try:
            return math.isfinite(value)
        except (TypeError, OverflowError):
            return False

    @classmethod
    def _valid_layer(cls, layer):
        return (isinstance(layer, int) and not isinstance(layer, bool)
                and layer >= 0)

    @classmethod
    def _valid_weight(cls, weight):
        return cls._is_number(weight) and 0.0 <= float(weight) <= 1.0

    @classmethod
    def _valid_phase(cls, phase):
        return cls._is_number(phase) and float(phase) >= 0.0

    @classmethod
    def _valid_time(cls, time):
        return cls._is_number(time) and float(time) >= 0.0

    @classmethod
    def _build_record(cls, clip_id, layer, length, weight, phase, bones):
        if not cls._valid_layer(layer):
            raise BlendError("BLEND_INVALID_ARGUMENT", layer)
        if not cls._is_number(length) or float(length) <= 0.0:
            raise BlendError("BLEND_INVALID_ARGUMENT", length)
        if not cls._valid_weight(weight):
            raise BlendError("BLEND_INVALID_ARGUMENT", weight)
        if not cls._valid_phase(phase):
            raise BlendError("BLEND_INVALID_ARGUMENT", phase)
        if not isinstance(bones, Mapping) or not bones:
            raise BlendError("BLEND_INVALID_ARGUMENT", bones)

        parsed_bones = {}
        for bone, endpoints in bones.items():
            if not cls._valid_name(bone):
                raise BlendError("BLEND_INVALID_ARGUMENT", bone)
            if (isinstance(endpoints, (str, bytes))
                    or not isinstance(endpoints, (tuple, list))
                    or len(endpoints) != 2):
                raise BlendError("BLEND_INVALID_ARGUMENT", endpoints)
            start, end = endpoints
            if not cls._is_number(start) or not cls._is_number(end):
                raise BlendError("BLEND_INVALID_ARGUMENT", endpoints)
            parsed_bones[bone] = (float(start), float(end))

        return {
            "clip_id": clip_id,
            "layer": layer,
            "length": float(length),
            "weight": float(weight),
            "phase": float(phase),
            "bones": parsed_bones,
        }

    @staticmethod
    def _public_record(record):
        return {
            "clip_id": record["clip_id"],
            "layer": record["layer"],
            "length": record["length"],
            "weight": record["weight"],
            "phase": record["phase"],
            "bones": tuple(sorted(record["bones"])),
        }

    @staticmethod
    def _effective(record, time):
        return (float(time) + record["phase"]) % record["length"]

    def _sync_phases(self, time):
        overrides: dict[str, float] = {}
        for group in sorted(self._groups):
            members = self._groups[group]
            if not members:
                continue
            reference = min(members)
            length = self._clips[reference]["length"]
            reference_effective = self._effective(
                self._clips[reference], time)
            for clip_id in sorted(members):
                record = self._clips[clip_id]
                own = self._effective(record, time)
                delta = (reference_effective - own) % length
                if delta > length / 2.0:
                    delta -= length
                overrides[clip_id] = (own + delta) % length
        return overrides

    def _stats_unlocked(self):
        return {
            "clips": len(self._clips),
            "evaluations": self._counters["evaluations"],
            "fallback_evals": self._counters["fallback_evals"],
            "sync_joins": self._counters["sync_joins"],
            "mask_updates": self._counters["mask_updates"],
        }

    @classmethod
    def _parse_snapshot(cls, state):
        if not isinstance(state, dict):
            raise BlendError("BLEND_SNAPSHOT_INVALID", state)
        version = state.get("version")
        if (not isinstance(version, int) or isinstance(version, bool)
                or version != 1):
            raise BlendError("BLEND_SNAPSHOT_INVALID", state)

        clips_raw = state["clips"]
        groups_raw = state["groups"]
        masks_raw = state["masks"]
        default_raw = state["default_pose"]
        stats_raw = state["stats"]
        if not isinstance(clips_raw, (dict, list)):
            raise BlendError("BLEND_SNAPSHOT_INVALID", clips_raw)
        if not isinstance(groups_raw, dict):
            raise BlendError("BLEND_SNAPSHOT_INVALID", groups_raw)
        if not isinstance(masks_raw, dict):
            raise BlendError("BLEND_SNAPSHOT_INVALID", masks_raw)
        if not isinstance(default_raw, dict):
            raise BlendError("BLEND_SNAPSHOT_INVALID", default_raw)
        if not isinstance(stats_raw, dict):
            raise BlendError("BLEND_SNAPSHOT_INVALID", stats_raw)

        clips = {}
        if isinstance(clips_raw, dict):
            entries = []
            for clip_id, record in clips_raw.items():
                entries.append((clip_id, record))
        else:
            entries = [(record.get("clip_id") if isinstance(record, dict)
                        else None, record) for record in clips_raw]

        for key_id, record in entries:
            if not isinstance(record, dict):
                raise BlendError("BLEND_SNAPSHOT_INVALID", record)
            clip_id = record.get("clip_id", key_id)
            if key_id is not None and record.get("clip_id") is not None:
                if key_id != record["clip_id"]:
                    raise BlendError("BLEND_SNAPSHOT_INVALID", record)
            if not cls._valid_name(clip_id) or clip_id in clips:
                raise BlendError("BLEND_SNAPSHOT_INVALID", clip_id)
            parsed = cls._build_record(
                clip_id,
                record.get("layer"),
                record.get("length"),
                record.get("weight"),
                record.get("phase"),
                record.get("bones"),
            )
            clips[clip_id] = parsed

        default_pose = {}
        for bone, value in default_raw.items():
            if not cls._valid_name(bone):
                raise BlendError("BLEND_SNAPSHOT_INVALID", bone)
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                raise BlendError("BLEND_SNAPSHOT_INVALID", value)
            default_pose[bone] = value

        groups = {}
        clip_group = {}
        for group, members in groups_raw.items():
            if not cls._valid_name(group):
                raise BlendError("BLEND_SNAPSHOT_INVALID", group)
            if (isinstance(members, (str, bytes))
                    or not isinstance(members, (list, tuple, set, frozenset))):
                raise BlendError("BLEND_SNAPSHOT_INVALID", members)
            member_list = list(members)
            if not member_list:
                raise BlendError("BLEND_SNAPSHOT_INVALID", group)
            if len(set(member_list)) != len(member_list):
                raise BlendError("BLEND_SNAPSHOT_INVALID", group)
            group_members = set()
            group_length = None
            for clip_id in member_list:
                if clip_id not in clips:
                    raise BlendError("BLEND_SNAPSHOT_INVALID", clip_id)
                if clip_id in clip_group:
                    raise BlendError("BLEND_SNAPSHOT_INVALID", clip_id)
                length = clips[clip_id]["length"]
                if group_length is None:
                    group_length = length
                elif length != group_length:
                    raise BlendError("BLEND_SNAPSHOT_INVALID", group)
                group_members.add(clip_id)
                clip_group[clip_id] = group
            groups[group] = group_members

        masks = {}
        for layer, bones in masks_raw.items():
            if not cls._valid_layer(layer):
                raise BlendError("BLEND_SNAPSHOT_INVALID", layer)
            if (isinstance(bones, (str, bytes))
                    or not isinstance(bones, (list, tuple, set, frozenset))):
                raise BlendError("BLEND_SNAPSHOT_INVALID", bones)
            mask_items = list(bones)
            if not mask_items:
                raise BlendError("BLEND_SNAPSHOT_INVALID", bones)
            for bone in mask_items:
                if not cls._valid_name(bone):
                    raise BlendError("BLEND_SNAPSHOT_INVALID", bone)
            masks[layer] = tuple(sorted(set(mask_items)))

        required_stats = (
            "clips",
            "evaluations",
            "fallback_evals",
            "sync_joins",
            "mask_updates",
        )
        counters = {}
        for name in required_stats:
            value = stats_raw.get(name)
            if (not isinstance(value, int) or isinstance(value, bool)
                    or value < 0):
                raise BlendError("BLEND_SNAPSHOT_INVALID", stats_raw)
            if name != "clips":
                counters[name] = value

        return clips, groups, clip_group, masks, default_pose, counters
