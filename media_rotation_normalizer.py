"""Media asset orientation normalization driven by rotation and pixel aspect.

Each asset carries a rotation, optional horizontal or vertical flip and a
pixel aspect ratio.  Normalizing folds those into a transcode filter chain,
rewrites the stored metadata into a single upright orientation and keeps the
previous metadata so the operation can be rolled back.
"""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

__all__ = [
    "MediaError",
    "AssetState",
    "NormalizePlan",
    "MediaRotationNormalizer",
]


class MediaError(ValueError):
    """Raised when an orientation normalization step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AssetState:
    """Stored orientation metadata of one media asset."""

    asset_id: str
    width: int
    height: int
    rotation: int
    flip_h: bool
    flip_v: bool
    sar: tuple[int, int]
    revision: int
    normalized: bool


@dataclass(frozen=True)
class NormalizePlan:
    """Planned transcode for one asset."""

    plan_id: str
    asset_id: str
    status: str
    rotation: int
    filters: tuple[str, ...]
    output_width: int
    output_height: int


class MediaRotationNormalizer:
    """Turn stored rotation metadata into an upright, square-pixel asset."""

    def __init__(self, *, profile: str = "mp4-h264",
                 allow_downscale: bool = False) -> None:
        self.profile = profile
        self.allow_downscale = allow_downscale
        self._lock = threading.RLock()
        self._assets: dict[str, dict] = {}
        self._plans: dict[str, NormalizePlan] = {}
        self._sequence = 0
        self._stats = {
            "registered": 0,
            "plans": 0,
            "skipped": 0,
            "applied": 0,
            "rollbacks": 0,
            "discarded": 0,
        }

    def register(self, asset_id: str, *, width: int, height: int,
                 rotation: int = 0, flip_h: bool = False,
                 flip_v: bool = False, sar: str = "1:1") -> AssetState:
        """Register an asset with its display matrix and aspect metadata."""
        with self._lock:
            asset_id = _validate_asset_id(asset_id)
            _validate_dimension(width, "width")
            _validate_dimension(height, "height")
            if type(rotation) is not int or rotation not in (0, 90, 180, 270):
                raise MediaError("MEDIA_ASSET_INVALID",
                                 {"field": "rotation", "value": rotation})
            if type(flip_h) is not bool:
                raise MediaError("MEDIA_ASSET_INVALID",
                                 {"field": "flip_h", "value": flip_h})
            if type(flip_v) is not bool:
                raise MediaError("MEDIA_ASSET_INVALID",
                                 {"field": "flip_v", "value": flip_v})
            sar_tuple = _parse_sar(sar)
            if asset_id in self._assets:
                raise MediaError("MEDIA_ASSET_EXISTS",
                                 {"asset_id": asset_id})
            metadata = {
                "rotation": rotation,
                "flip_h": flip_h,
                "flip_v": flip_v,
                "width": width,
                "height": height,
                "sar": sar_tuple,
            }
            self._assets[asset_id] = {
                "asset_id": asset_id,
                "current": metadata,
                "before": copy.deepcopy(metadata),
                "after": None,
                "revision": 0,
                "normalized": False,
            }
            self._stats["registered"] += 1
            return self._asset_state_locked(asset_id)

    def inspect(self, asset_id: str) -> dict:
        """Return the stored and normalized geometry of *asset_id*."""
        with self._lock:
            record = self._require_asset(asset_id)
            current = record["current"]
            output_width, output_height, _ = _build_filters(current)
            return {
                "asset_id": record["asset_id"],
                "rotation": current["rotation"],
                "flip_h": current["flip_h"],
                "flip_v": current["flip_v"],
                "width": current["width"],
                "height": current["height"],
                "sar": current["sar"],
                "output_width": output_width,
                "output_height": output_height,
                "normalized": record["normalized"],
                "revision": record["revision"],
            }

    def plan_filters(self, asset_id: str) -> tuple[str, ...]:
        """Return the ordered filter chain needed for *asset_id*."""
        with self._lock:
            record = self._require_asset(asset_id)
            return _build_filters(record["current"])[2]

    def normalize(self, asset_id: str) -> NormalizePlan:
        """Create (or reuse) the normalization plan for *asset_id*."""
        with self._lock:
            record = self._require_asset(asset_id)
            asset_id = record["asset_id"]

            if record["normalized"]:
                self._stats["skipped"] += 1
                current = record["current"]
                return NormalizePlan(
                    plan_id="",
                    asset_id=asset_id,
                    status="skipped",
                    rotation=0,
                    filters=(),
                    output_width=current["width"],
                    output_height=current["height"],
                )

            existing = self._pending_plan_for_asset_locked(asset_id)
            if existing is not None:
                return existing

            current = record["current"]
            output_width, output_height, filters = _build_filters(current)
            plan_id = self._next_plan_id_locked()
            plan = NormalizePlan(
                plan_id=plan_id,
                asset_id=asset_id,
                status="planned",
                rotation=current["rotation"],
                filters=filters,
                output_width=output_width,
                output_height=output_height,
            )
            self._plans[plan_id] = plan
            self._stats["plans"] += 1
            return plan

    def apply(self, plan_id: str) -> NormalizePlan:
        """Apply a pending plan and mark the asset as normalized."""
        with self._lock:
            plan = self._get_plan_locked(plan_id)
            if plan is None or plan.status != "planned":
                raise MediaError("MEDIA_UNKNOWN_PLAN", {"plan_id": plan_id})

            record = self._assets.get(plan.asset_id)
            if record is None:
                del self._plans[plan_id]
                raise MediaError("MEDIA_UNKNOWN_PLAN", {"plan_id": plan_id})

            before = _copy_metadata(record["current"])
            after = {
                "rotation": 0,
                "flip_h": False,
                "flip_v": False,
                "width": plan.output_width,
                "height": plan.output_height,
                "sar": (1, 1),
            }
            record["before"] = before
            record["after"] = after
            record["current"] = _copy_metadata(after)
            record["normalized"] = True
            record["revision"] += 1

            del self._plans[plan_id]
            applied = _replace_plan_status(plan, "applied")
            self._stats["applied"] += 1
            return applied

    def rollback(self, asset_id: str) -> AssetState:
        """Restore the metadata captured before normalization."""
        with self._lock:
            asset_id = _validate_asset_id(asset_id)
            record = self._assets.get(asset_id)
            if (record is None or not record["normalized"]
                    or record["before"] is None):
                raise MediaError("MEDIA_NOT_NORMALIZED",
                                 {"asset_id": asset_id})

            before = record["before"]
            record["current"] = _copy_metadata(before)
            record["after"] = None
            record["normalized"] = False
            record["revision"] += 1
            self._stats["rollbacks"] += 1
            return self._asset_state_locked(record["asset_id"])

    def metadata_of(self, asset_id: str) -> dict:
        """Return before/after metadata of *asset_id* as a detached copy."""
        with self._lock:
            record = self._require_asset(asset_id)
            return {
                "asset_id": record["asset_id"],
                "before": _copy_metadata(record["before"]),
                "after": _copy_metadata(record["after"]),
                "normalized": record["normalized"],
                "revision": record["revision"],
            }

    def is_normalized(self, asset_id: str) -> bool:
        """Tell whether *asset_id* already carries upright metadata."""
        with self._lock:
            try:
                asset_id = _validate_asset_id(asset_id)
            except MediaError:
                return False
            record = self._assets.get(asset_id)
            return bool(record and record["normalized"])

    def pending_plans(self) -> tuple[str, ...]:
        """Return the ids of the plans that were not applied yet."""
        with self._lock:
            return tuple(sorted(self._plans, key=_plan_sequence))

    def discard_plan(self, plan_id: str) -> bool:
        """Drop a pending plan without touching the asset metadata."""
        with self._lock:
            plan = self._get_plan_locked(plan_id)
            if plan is None or plan.status != "planned":
                return False
            del self._plans[plan_id]
            self._stats["discarded"] += 1
            return True

    def snapshot(self) -> dict:
        """Return a detached snapshot of the normalizer state."""
        with self._lock:
            assets = []
            for asset_id in self._assets:
                record = self._assets[asset_id]
                current = record["current"]
                assets.append({
                    "asset_id": record["asset_id"],
                    "rotation": current["rotation"],
                    "flip_h": current["flip_h"],
                    "flip_v": current["flip_v"],
                    "width": current["width"],
                    "height": current["height"],
                    "sar": current["sar"],
                    "revision": record["revision"],
                    "normalized": record["normalized"],
                    "before": _copy_metadata(record["before"]),
                    "after": _copy_metadata(record["after"]),
                })

            plans = {}
            for plan_id in sorted(self._plans, key=_plan_sequence):
                plan = self._plans[plan_id]
                plans[plan_id] = {
                    "plan_id": plan.plan_id,
                    "asset_id": plan.asset_id,
                    "status": plan.status,
                    "rotation": plan.rotation,
                    "filters": list(plan.filters),
                    "output_width": plan.output_width,
                    "output_height": plan.output_height,
                }

            return {
                "version": 1,
                "assets": copy.deepcopy(assets),
                "plans": copy.deepcopy(plans),
                "sequence": self._sequence,
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        """Replace the normalizer state with a previously taken snapshot."""
        with self._lock:
            try:
                restored = _parse_snapshot(state)
            except MediaError:
                raise
            except Exception as exc:
                raise MediaError("MEDIA_SNAPSHOT_INVALID", str(exc)) from exc
            self._assets = restored["assets"]
            self._plans = restored["plans"]
            self._sequence = restored["sequence"]
            self._stats = restored["stats"]

    def stats(self) -> dict:
        """Return the registration, planning and apply counters."""
        with self._lock:
            return copy.deepcopy(self._stats)

    def _require_asset(self, asset_id: str) -> dict:
        asset_id = _validate_asset_id(asset_id)
        record = self._assets.get(asset_id)
        if record is None:
            raise MediaError("MEDIA_UNKNOWN_ASSET", {"asset_id": asset_id})
        return record

    def _asset_state_locked(self, asset_id: str) -> AssetState:
        record = self._assets[asset_id]
        current = record["current"]
        return AssetState(
            asset_id=record["asset_id"],
            width=current["width"],
            height=current["height"],
            rotation=current["rotation"],
            flip_h=current["flip_h"],
            flip_v=current["flip_v"],
            sar=current["sar"],
            revision=record["revision"],
            normalized=record["normalized"],
        )

    def _pending_plan_for_asset_locked(self, asset_id: str):
        for plan_id in sorted(self._plans, key=_plan_sequence):
            plan = self._plans[plan_id]
            if plan.status == "planned" and plan.asset_id == asset_id:
                return plan
        return None

    def _next_plan_id_locked(self) -> str:
        while True:
            self._sequence += 1
            plan_id = f"plan-{self._sequence:04d}"
            if plan_id not in self._plans:
                return plan_id

    def _get_plan_locked(self, plan_id: object):
        try:
            return self._plans.get(plan_id)  # type: ignore[arg-type]
        except TypeError:
            return None


def _validate_asset_id(asset_id: object) -> str:
    if type(asset_id) is not str:
        raise MediaError("MEDIA_ASSET_INVALID", {"field": "asset_id"})
    normalized = asset_id.strip()
    if not normalized:
        raise MediaError("MEDIA_ASSET_INVALID", {"field": "asset_id"})
    return normalized


def _validate_dimension(value: object, field: str) -> None:
    if type(value) is not int or value <= 0:
        raise MediaError("MEDIA_ASSET_INVALID",
                         {"field": field, "value": value})


def _parse_sar(value: object) -> tuple[int, int]:
    if type(value) is not str:
        raise MediaError("MEDIA_ASSET_INVALID", {"field": "sar", "value": value})
    parts = value.split(":")
    if len(parts) != 2 or not all(part.isascii() and part.isdigit()
                                  for part in parts):
        raise MediaError("MEDIA_ASSET_INVALID", {"field": "sar", "value": value})
    numerator, denominator = (int(part) for part in parts)
    if numerator <= 0 or denominator <= 0:
        raise MediaError("MEDIA_ASSET_INVALID", {"field": "sar", "value": value})
    return numerator, denominator


def _copy_metadata(metadata: dict | None):
    if metadata is None:
        return None
    return copy.deepcopy(metadata)


def _orientation_filters(metadata: dict) -> tuple[str, ...]:
    filters: list[str] = []
    if metadata["flip_h"]:
        filters.append("hflip")
    if metadata["flip_v"]:
        filters.append("vflip")
    rotation = metadata["rotation"]
    if rotation == 90:
        filters.append("transpose=1")
    elif rotation == 180:
        filters.append("rotate=180")
    elif rotation == 270:
        filters.append("transpose=2")
    return tuple(filters)


def _rotated_dimensions(width: int, height: int,
                        rotation: int) -> tuple[int, int]:
    if rotation in (90, 270):
        return height, width
    return width, height


def _build_filters(metadata: dict) -> tuple[int, int, tuple[str, ...]]:
    orientation = _orientation_filters(metadata)
    rotated_width, rotated_height = _rotated_dimensions(
        metadata["width"], metadata["height"], metadata["rotation"]
    )

    aligned_width = max(1, rotated_width - (rotated_width % 2))
    aligned_height = max(1, rotated_height - (rotated_height % 2))
    filters = list(orientation)
    if (aligned_width != rotated_width or
            aligned_height != rotated_height):
        crop_x = (rotated_width - aligned_width) // 2
        crop_y = (rotated_height - aligned_height) // 2
        filters.append(
            f"crop={aligned_width}:{aligned_height}:{crop_x}:{crop_y}"
        )

    output_width, output_height = aligned_width, aligned_height
    numerator, denominator = metadata["sar"]
    if numerator != denominator:
        if metadata["rotation"] in (90, 270):
            output_height = aligned_height * numerator // denominator
        else:
            output_width = aligned_width * numerator // denominator
        filters.append(f"scale={output_width}:{output_height}")

    return output_width, output_height, tuple(filters)


def _plan_sequence(plan_id: str) -> int:
    try:
        return int(plan_id.rsplit("-", 1)[1])
    except (IndexError, ValueError):
        return -1


def _replace_plan_status(plan: NormalizePlan,
                         status: str) -> NormalizePlan:
    return NormalizePlan(
        plan_id=plan.plan_id,
        asset_id=plan.asset_id,
        status=status,
        rotation=plan.rotation,
        filters=plan.filters,
        output_width=plan.output_width,
        output_height=plan.output_height,
    )


def _parse_snapshot(state: object) -> dict:
    if type(state) is not dict:
        raise MediaError("MEDIA_SNAPSHOT_INVALID")
    expected = {"version", "assets", "plans", "sequence", "stats"}
    if set(state) != expected:
        raise MediaError("MEDIA_SNAPSHOT_INVALID")
    if type(state["version"]) is not int or state["version"] != 1:
        raise MediaError("MEDIA_SNAPSHOT_INVALID")
    if type(state["sequence"]) is not int or state["sequence"] < 0:
        raise MediaError("MEDIA_SNAPSHOT_INVALID")
    if type(state["stats"]) is not dict:
        raise MediaError("MEDIA_SNAPSHOT_INVALID")

    stats = {}
    for key in ("registered", "plans", "skipped", "applied",
                "rollbacks", "discarded"):
        value = state["stats"].get(key)
        if type(value) is not int or value < 0:
            raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": f"stats.{key}"})
        stats[key] = value
    for key, value in state["stats"].items():
        if key not in stats:
            if type(value) is not int or value < 0:
                raise MediaError("MEDIA_SNAPSHOT_INVALID",
                                 {"field": f"stats.{key}"})
            stats[key] = value

    assets = _parse_snapshot_assets(state["assets"])
    plans = _parse_snapshot_plans(state["plans"], assets)
    return {
        "assets": assets,
        "plans": plans,
        "sequence": state["sequence"],
        "stats": stats,
    }


def _parse_snapshot_assets(value: object) -> dict[str, dict]:
    if type(value) is not list:
        raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "assets"})

    assets = {}
    for index, item in enumerate(value):
        if type(item) is not dict:
            raise MediaError("MEDIA_SNAPSHOT_INVALID",
                             {"field": f"assets[{index}]"})
        asset_id = _validate_snapshot_asset_id(item.get("asset_id"))
        if asset_id in assets:
            raise MediaError("MEDIA_SNAPSHOT_INVALID",
                             {"field": "assets", "asset_id": asset_id})

        if "current" in item:
            current = _parse_snapshot_metadata(item["current"])
        else:
            current = _parse_snapshot_metadata(item)
        before = _parse_optional_metadata(item.get("before"))
        after = _parse_optional_metadata(item.get("after"))
        revision = item.get("revision")
        normalized = item.get("normalized")
        if type(revision) is not int or revision < 0:
            raise MediaError("MEDIA_SNAPSHOT_INVALID",
                             {"field": "revision"})
        if type(normalized) is not bool:
            raise MediaError("MEDIA_SNAPSHOT_INVALID",
                             {"field": "normalized"})
        if before is None:
            raise MediaError("MEDIA_SNAPSHOT_INVALID",
                             {"field": "before"})
        if normalized and after is None:
            raise MediaError("MEDIA_SNAPSHOT_INVALID",
                             {"field": "after"})
        if not normalized and after is not None:
            raise MediaError("MEDIA_SNAPSHOT_INVALID",
                             {"field": "after"})

        assets[asset_id] = {
            "asset_id": asset_id,
            "current": current,
            "before": before,
            "after": after if normalized else None,
            "revision": revision,
            "normalized": normalized,
        }
    return assets


def _validate_snapshot_asset_id(value: object) -> str:
    if type(value) is not str or not value.strip():
        raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "asset_id"})
    return value.strip()


def _parse_optional_metadata(value: object):
    if value is None:
        return None
    return _parse_snapshot_metadata(value)


def _parse_snapshot_metadata(value: object) -> dict:
    if type(value) is not dict:
        raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "metadata"})
    fields = ("rotation", "flip_h", "flip_v", "width", "height", "sar")
    if any(field not in value for field in fields):
        raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "metadata"})

    rotation = value["rotation"]
    width = value["width"]
    height = value["height"]
    flip_h = value["flip_h"]
    flip_v = value["flip_v"]
    sar = value["sar"]
    if type(rotation) is not int or rotation not in (0, 90, 180, 270):
        raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "rotation"})
    if type(width) is not int or width <= 0:
        raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "width"})
    if type(height) is not int or height <= 0:
        raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "height"})
    if type(flip_h) is not bool or type(flip_v) is not bool:
        raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "flip"})
    if type(sar) not in (tuple, list) or len(sar) != 2:
        raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "sar"})
    if any(type(part) is not int or part <= 0 for part in sar):
        raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "sar"})

    return {
        "rotation": rotation,
        "flip_h": flip_h,
        "flip_v": flip_v,
        "width": width,
        "height": height,
        "sar": (sar[0], sar[1]),
    }


def _parse_snapshot_plans(value: object,
                          assets: dict[str, dict]) -> dict[str, NormalizePlan]:
    if type(value) is not dict:
        raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "plans"})

    plans = {}
    for supplied_id, item in value.items():
        if type(item) is not dict:
            raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "plans"})
        plan_id = item.get("plan_id", supplied_id)
        if type(plan_id) is not str or not plan_id:
            raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "plan_id"})
        if supplied_id != plan_id:
            raise MediaError("MEDIA_SNAPSHOT_INVALID",
                             {"field": "plans.plan_id"})
        if plan_id in plans:
            raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "plans"})
        if item.get("status", "planned") != "planned":
            # Snapshots in this implementation contain only pending plans,
            # but tolerate consumed records supplied by other serializers.
            continue

        asset_id = _validate_snapshot_asset_id(item.get("asset_id"))
        if asset_id not in assets:
            raise MediaError("MEDIA_SNAPSHOT_INVALID",
                             {"field": "plans.asset_id"})
        rotation = item.get("rotation")
        if type(rotation) is not int or rotation not in (0, 90, 180, 270):
            raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "rotation"})
        filters = item.get("filters", ())
        if type(filters) not in (list, tuple) or any(
                type(filter_name) is not str for filter_name in filters):
            raise MediaError("MEDIA_SNAPSHOT_INVALID", {"field": "filters"})
        output_width = item.get("output_width")
        output_height = item.get("output_height")
        if type(output_width) is not int or output_width <= 0:
            raise MediaError("MEDIA_SNAPSHOT_INVALID",
                             {"field": "output_width"})
        if type(output_height) is not int or output_height <= 0:
            raise MediaError("MEDIA_SNAPSHOT_INVALID",
                             {"field": "output_height"})

        plans[plan_id] = NormalizePlan(
            plan_id=plan_id,
            asset_id=asset_id,
            status="planned",
            rotation=rotation,
            filters=tuple(filters),
            output_width=output_width,
            output_height=output_height,
        )
    return plans
