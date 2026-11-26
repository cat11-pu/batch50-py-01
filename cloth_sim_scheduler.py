"""Cloth substep scheduling with fixed timestep and snapshot continuity."""

from __future__ import annotations

import math
import threading
from collections.abc import Iterable
from copy import deepcopy


class ClothError(ValueError):
    """Raised when a cloth scheduling operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    if not isinstance(value, (int, float)) or isinstance(value, bool):
        return False
    try:
        return math.isfinite(float(value))
    except (OverflowError, TypeError, ValueError):
        return False


def _copy_points(value: object, code: str) -> list[list[float]]:
    if value is None or isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise ClothError(code, value)

    try:
        raw_points = list(value)
    except TypeError as exc:
        raise ClothError(code, value) from exc

    if not raw_points:
        raise ClothError(code, value)

    points: list[list[float]] = []
    for raw_point in raw_points:
        if isinstance(raw_point, (str, bytes)) or not isinstance(raw_point, Iterable):
            raise ClothError(code, raw_point)
        try:
            coordinates = list(raw_point)
        except TypeError as exc:
            raise ClothError(code, raw_point) from exc
        if len(coordinates) != 3 or not all(_is_number(item) for item in coordinates):
            raise ClothError(code, raw_point)
        points.append([float(item) for item in coordinates])

    return points


def _copy_pinned(value: object, vertex_count: int, code: str) -> tuple[int, ...]:
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise ClothError(code, value)

    try:
        indices = list(value)
    except TypeError as exc:
        raise ClothError(code, value) from exc

    seen: set[int] = set()
    for index in indices:
        if not _is_integer(index) or index < 0 or index >= vertex_count:
            raise ClothError(code, value)
        if index in seen:
            raise ClothError(code, value)
        seen.add(index)

    return tuple(sorted(seen))


class ClothSimScheduler:
    """Allocate a per-frame substep budget across several cloth instances."""

    MAX_SUBSTEPS = 64
    NEAR_DISTANCE = 2.0
    MID_DISTANCE = 6.0
    SNAPSHOT_VERSION = 1
    SPRING_STIFFNESS = 60.0
    STAT_KEYS = (
        "frames",
        "substeps",
        "registrations",
        "detaches",
        "collisions",
        "throttled_frames",
    )

    def __init__(
        self,
        *,
        fixed_step: float = 1.0 / 120.0,
        substep_budget: int = 8,
        damping: float = 2.0,
    ) -> None:
        if not _is_number(fixed_step) or fixed_step <= 0:
            raise ClothError("CLOTH_INVALID_ARGUMENT", fixed_step)
        if not _is_integer(substep_budget) or not 1 <= substep_budget <= self.MAX_SUBSTEPS:
            raise ClothError("CLOTH_INVALID_ARGUMENT", substep_budget)
        if not _is_number(damping) or damping < 0:
            raise ClothError("CLOTH_INVALID_ARGUMENT", damping)

        self.fixed_step = float(fixed_step)
        self.substep_budget = int(substep_budget)
        self.damping = float(damping)

        self._lock = threading.RLock()
        self._cloths: dict[str, dict] = {}
        self._frame = 0
        self._accumulator = 0.0
        self._release_counter = 0
        self._collision_cache: list[dict] | None = None
        self._stats = {key: 0 for key in self.STAT_KEYS}

    @staticmethod
    def _tier_for_distance(distance: float) -> str:
        if distance <= ClothSimScheduler.NEAR_DISTANCE:
            return "near"
        if distance <= ClothSimScheduler.MID_DISTANCE:
            return "mid"
        return "far"

    @staticmethod
    def _tier_rank(tier: str) -> int:
        return {"near": 0, "mid": 1, "far": 2}[tier]

    def _require_cloth(self, cloth_id: str) -> dict:
        try:
            return self._cloths[cloth_id]
        except KeyError as exc:
            raise ClothError("CLOTH_UNKNOWN", cloth_id) from exc

    def register(
        self,
        cloth_id,
        *,
        vertices,
        pinned=(),
        rest=None,
        distance=1.0,
        visible=True,
    ):
        with self._lock:
            if not isinstance(cloth_id, str) or not cloth_id:
                raise ClothError("CLOTH_INVALID_ARGUMENT", cloth_id)
            if cloth_id in self._cloths:
                raise ClothError("CLOTH_DUPLICATE", cloth_id)

            points = _copy_points(vertices, "CLOTH_INVALID_ARGUMENT")
            vertex_count = len(points)
            pinned_indices = _copy_pinned(
                pinned, vertex_count, "CLOTH_INVALID_ARGUMENT"
            )

            if rest is None:
                rest_points = deepcopy(points)
            else:
                rest_points = _copy_points(rest, "CLOTH_INVALID_ARGUMENT")
                if len(rest_points) != vertex_count:
                    raise ClothError("CLOTH_INVALID_ARGUMENT", rest)

            if not _is_number(distance) or distance < 0:
                raise ClothError("CLOTH_INVALID_ARGUMENT", distance)
            if not isinstance(visible, bool):
                raise ClothError("CLOTH_INVALID_ARGUMENT", visible)

            record = {
                "cloth_id": cloth_id,
                "vertices": points,
                "velocities": [[0.0, 0.0, 0.0] for _ in points],
                "pinned": pinned_indices,
                "pin_positions": deepcopy(points),
                "rest": rest_points,
                "distance": float(distance),
                "tier": self._tier_for_distance(float(distance)),
                "visible": visible,
                "attached": True,
                "last_substeps": 0,
                "total_substeps": 0,
                "release_order": None,
                "damping": self.damping,
                "stiffness": self.SPRING_STIFFNESS,
                "host_ref": vertices,
            }
            self._cloths[cloth_id] = record
            self._stats["registrations"] += 1
            self._collision_cache = None

            return {
                "cloth_id": cloth_id,
                "tier": record["tier"],
                "attached": True,
                "frame": self._frame,
                "visible": visible,
                "vertices": vertex_count,
                "distance": float(distance),
                "release_order": None,
            }

    def unregister(self, cloth_id):
        with self._lock:
            record = self._require_cloth(cloth_id)
            if record["attached"]:
                raise ClothError("CLOTH_STILL_ATTACHED", cloth_id)

            release_order = record["release_order"]
            del self._cloths[cloth_id]
            self._collision_cache = None
            return {
                "cloth_id": cloth_id,
                "release_order": release_order,
                "removed": True,
            }

    def set_budget(self, substeps):
        if not _is_integer(substeps) or not 1 <= substeps <= self.MAX_SUBSTEPS:
            raise ClothError("CLOTH_INVALID_BUDGET", substeps)
        with self._lock:
            self.substep_budget = substeps
            return self.substep_budget

    def _allocate_substeps(
        self, records: list[dict], total: int, requested: int
    ) -> dict[str, int]:
        counts = {record["cloth_id"]: 1 for record in records}
        remaining = total - len(records)
        if remaining <= 0:
            return counts

        capacity = max(1, requested)
        while remaining > 0:
            candidates = [
                record
                for record in records
                if counts[record["cloth_id"]] < capacity
            ]
            if not candidates:
                capacity += 1
                candidates = records

            chosen = min(
                candidates,
                key=lambda record: (
                    self._tier_rank(record["tier"]),
                    counts[record["cloth_id"]],
                    record["cloth_id"],
                ),
            )
            counts[chosen["cloth_id"]] += 1
            remaining -= 1

        return counts

    def _simulate_substep(self, record: dict, dt: float) -> None:
        positions = record["vertices"]
        velocities = record["velocities"]
        rest = record["rest"]
        damping = float(record.get("damping", self.damping))
        stiffness = float(record.get("stiffness", self.SPRING_STIFFNESS))

        for index in range(len(positions)):
            if index in record["pinned"]:
                continue
            for axis in range(3):
                position = positions[index][axis]
                velocity = velocities[index][axis]
                target = rest[index][axis]
                denominator = 1.0 + damping * dt + stiffness * dt * dt
                velocity = (
                    velocity - dt * stiffness * (position - target)
                ) / denominator
                position += dt * velocity
                velocities[index][axis] = velocity
                positions[index][axis] = position

        for index in record["pinned"]:
            for axis in range(3):
                positions[index][axis] = record["pin_positions"][index][axis]
            velocities[index] = [0.0, 0.0, 0.0]

    def step(self, dt):
        if not _is_number(dt):
            raise ClothError("CLOTH_INVALID_DT", dt)
        if dt <= 0:
            raise ClothError("CLOTH_INVALID_DT", dt)

        with self._lock:
            visible_records = [
                record for record in self._cloths.values() if record["visible"]
            ]
            visible_count = len(visible_records)
            if self.substep_budget < visible_count:
                raise ClothError("CLOTH_BUDGET_TOO_SMALL", self.substep_budget)

            self._frame += 1
            self._stats["frames"] += 1
            self._accumulator += float(dt)

            requested = math.floor(self._accumulator / self.fixed_step)
            if requested < 0:
                requested = 0

            for record in self._cloths.values():
                record["last_substeps"] = 0

            executed = 0
            if requested > 0 and visible_records:
                total = min(requested, self.substep_budget)
                if total < visible_count:
                    total = visible_count

                allocations = self._allocate_substeps(
                    visible_records, total, requested
                )
                for record in visible_records:
                    cloth_id = record["cloth_id"]
                    count = allocations[cloth_id]
                    record["last_substeps"] = count
                    record["total_substeps"] += count
                    for _ in range(count):
                        self._simulate_substep(record, self.fixed_step)
                    executed += count

                self._stats["substeps"] += executed
                charged_steps = min(executed, requested)
                self._accumulator -= charged_steps * self.fixed_step
                if self._accumulator < 0.0:
                    self._accumulator = 0.0

            throttled = executed < requested
            if throttled:
                self._stats["throttled_frames"] += 1
            self._collision_cache = None

            return {
                "frame": self._frame,
                "requested": requested,
                "executed": executed,
                "throttled": throttled,
                "accumulator": self._accumulator,
            }

    def state_of(self, cloth_id):
        with self._lock:
            record = self._require_cloth(cloth_id)
            return {
                "frame": self._frame,
                "attached": record["attached"],
                "tier": record["tier"],
                "visible": record["visible"],
                "last_substeps": record["last_substeps"],
                "total_substeps": record["total_substeps"],
                "positions": deepcopy(record["vertices"]),
            }

    def positions_of(self, cloth_id):
        with self._lock:
            self._require_cloth(cloth_id)
            return deepcopy(self._cloths[cloth_id]["vertices"])

    def _writeback_host(self, record: dict) -> None:
        host = record.get("host_ref")
        positions = record["vertices"]
        if host is None:
            return

        if isinstance(host, list):
            try:
                host[:] = deepcopy(positions)
                return
            except Exception:
                pass

        try:
            for host_point, source_point in zip(host, positions):
                if isinstance(host_point, list):
                    host_point[:] = deepcopy(source_point)
        except Exception:
            pass

    def detach(self, cloth_id):
        with self._lock:
            record = self._require_cloth(cloth_id)
            if not record["attached"]:
                raise ClothError("CLOTH_ALREADY_DETACHED", cloth_id)

            self._release_counter += 1
            release_order = self._release_counter
            record["attached"] = False
            record["release_order"] = release_order
            self._stats["detaches"] += 1
            self._writeback_host(record)
            self._collision_cache = None

            return {
                "cloth_id": cloth_id,
                "vertices": len(record["vertices"]),
                "frame": self._frame,
                "release_order": release_order,
            }

    @staticmethod
    def _aabb(record: dict) -> tuple[float, ...]:
        positions = record["vertices"]
        lower = [min(point[axis] for point in positions) for axis in range(3)]
        upper = [max(point[axis] for point in positions) for axis in range(3)]
        return (lower[0], lower[1], lower[2], upper[0], upper[1], upper[2])

    @staticmethod
    def _aabbs_intersect(
        left: tuple[float, ...], right: tuple[float, ...]
    ) -> bool:
        return all(
            left[axis] <= right[axis + 3]
            and right[axis] <= left[axis + 3]
            for axis in range(3)
        )

    def _build_collision_batches(self) -> list[dict]:
        records = sorted(
            (
                record
                for record in self._cloths.values()
                if record["visible"] and record["attached"]
            ),
            key=lambda record: record["cloth_id"],
        )
        labels = [record["cloth_id"] for record in records]
        boxes = [self._aabb(record) for record in records]
        parent = list(range(len(records)))

        def find(index: int) -> int:
            while parent[index] != index:
                parent[index] = parent[parent[index]]
                index = parent[index]
            return index

        def union(left: int, right: int) -> None:
            left_root = find(left)
            right_root = find(right)
            if left_root != right_root:
                parent[right_root] = left_root

        for left_index in range(len(records)):
            for right_index in range(left_index + 1, len(records)):
                if self._aabbs_intersect(boxes[left_index], boxes[right_index]):
                    union(left_index, right_index)

        groups: dict[int, list[str]] = {}
        for index, cloth_id in enumerate(labels):
            root = find(index)
            groups.setdefault(root, []).append(cloth_id)

        cloth_groups = sorted(
            (tuple(sorted(cloth_ids)) for cloth_ids in groups.values()),
            key=lambda cloth_ids: cloth_ids[0],
        )
        return [
            {"batch": batch_index, "cloths": cloth_ids}
            for batch_index, cloth_ids in enumerate(cloth_groups)
        ]

    def collision_batch(self):
        with self._lock:
            self._stats["collisions"] += 1
            if self._collision_cache is None:
                self._collision_cache = self._build_collision_batches()
            return deepcopy(self._collision_cache)

    def snapshot(self):
        with self._lock:
            cloths = []
            for record in self._cloths.values():
                cloths.append(
                    {
                        "cloth_id": record["cloth_id"],
                        "vertices": deepcopy(record["vertices"]),
                        "velocities": deepcopy(record["velocities"]),
                        "pinned": list(record["pinned"]),
                        "pin_positions": deepcopy(record["pin_positions"]),
                        "rest": deepcopy(record["rest"]),
                        "distance": record["distance"],
                        "tier": record["tier"],
                        "visible": record["visible"],
                        "attached": record["attached"],
                        "last_substeps": record["last_substeps"],
                        "total_substeps": record["total_substeps"],
                        "release_order": record["release_order"],
                        "damping": record["damping"],
                        "stiffness": record["stiffness"],
                    }
                )

            return {
                "version": self.SNAPSHOT_VERSION,
                "fixed_step": self.fixed_step,
                "damping": self.damping,
                "budget": self.substep_budget,
                "frame": self._frame,
                "accumulator": self._accumulator,
                "release_counter": self._release_counter,
                "cloths": cloths,
                "stats": dict(self._stats),
            }

    def _record_from_snapshot(
        self, item: object, fallback_damping: float
    ) -> dict:
        if not isinstance(item, dict):
            raise ClothError("CLOTH_SNAPSHOT_INVALID", item)

        cloth_id = item.get("cloth_id", item.get("id"))
        if not isinstance(cloth_id, str) or not cloth_id:
            raise ClothError("CLOTH_SNAPSHOT_INVALID", cloth_id)

        vertices = _copy_points(
            item.get("vertices"), "CLOTH_SNAPSHOT_INVALID"
        )
        vertex_count = len(vertices)

        velocities_value = item.get("velocities")
        if velocities_value is None:
            velocities = [[0.0, 0.0, 0.0] for _ in vertices]
        else:
            velocities = _copy_points(
                velocities_value, "CLOTH_SNAPSHOT_INVALID"
            )
            if len(velocities) != vertex_count:
                raise ClothError("CLOTH_SNAPSHOT_INVALID", velocities_value)

        pinned = _copy_pinned(
            item.get("pinned", ()),
            vertex_count,
            "CLOTH_SNAPSHOT_INVALID",
        )

        rest_value = item.get("rest")
        if rest_value is None:
            rest = deepcopy(vertices)
        else:
            rest = _copy_points(
                rest_value, "CLOTH_SNAPSHOT_INVALID"
            )
            if len(rest) != vertex_count:
                raise ClothError("CLOTH_SNAPSHOT_INVALID", rest_value)

        distance = item.get("distance", 1.0)
        if not _is_number(distance) or distance < 0:
            raise ClothError("CLOTH_SNAPSHOT_INVALID", distance)

        visible = item.get("visible", True)
        attached = item.get("attached", True)
        if not isinstance(visible, bool) or not isinstance(attached, bool):
            raise ClothError("CLOTH_SNAPSHOT_INVALID", item)

        last_substeps = item.get("last_substeps", 0)
        total_substeps = item.get("total_substeps", 0)
        if not _is_integer(last_substeps) or last_substeps < 0:
            raise ClothError("CLOTH_SNAPSHOT_INVALID", last_substeps)
        if not _is_integer(total_substeps) or total_substeps < 0:
            raise ClothError("CLOTH_SNAPSHOT_INVALID", total_substeps)

        release_order = item.get("release_order")
        if release_order is not None and (
            not _is_integer(release_order) or release_order <= 0
        ):
            raise ClothError("CLOTH_SNAPSHOT_INVALID", release_order)

        damping = item.get("damping", fallback_damping)
        if not _is_number(damping) or damping < 0:
            raise ClothError("CLOTH_SNAPSHOT_INVALID", damping)

        stiffness = item.get("stiffness", self.SPRING_STIFFNESS)
        if not _is_number(stiffness) or stiffness <= 0:
            raise ClothError("CLOTH_SNAPSHOT_INVALID", stiffness)

        return {
            "cloth_id": cloth_id,
            "vertices": vertices,
            "velocities": velocities,
            "pinned": pinned,
            "pin_positions": deepcopy(vertices),
            "rest": rest,
            "distance": float(distance),
            "tier": self._tier_for_distance(float(distance)),
            "visible": visible,
            "attached": attached,
            "last_substeps": last_substeps,
            "total_substeps": total_substeps,
            "release_order": release_order,
            "damping": float(damping),
            "stiffness": float(stiffness),
            "host_ref": None,
        }

    def _state_from_snapshot(self, state: object) -> dict:
        if not isinstance(state, dict):
            raise ClothError("CLOTH_SNAPSHOT_INVALID", state)

        version = state.get("version")
        if not _is_integer(version) or version != self.SNAPSHOT_VERSION:
            raise ClothError("CLOTH_SNAPSHOT_INVALID", version)

        fixed_step = state.get("fixed_step")
        if not _is_number(fixed_step) or fixed_step <= 0:
            raise ClothError("CLOTH_SNAPSHOT_INVALID", fixed_step)

        damping = state.get("damping")
        if not _is_number(damping) or damping < 0:
            raise ClothError("CLOTH_SNAPSHOT_INVALID", damping)

        budget = state.get("budget")
        if not _is_integer(budget) or not 1 <= budget <= self.MAX_SUBSTEPS:
            raise ClothError("CLOTH_SNAPSHOT_INVALID", budget)

        frame = state.get("frame")
        if not _is_integer(frame) or frame < 0:
            raise ClothError("CLOTH_SNAPSHOT_INVALID", frame)

        accumulator = state.get("accumulator")
        if not _is_number(accumulator) or accumulator < 0:
            raise ClothError("CLOTH_SNAPSHOT_INVALID", accumulator)

        stats = state.get("stats")
        if not isinstance(stats, dict):
            raise ClothError("CLOTH_SNAPSHOT_INVALID", stats)
        normalized_stats = {}
        for key in self.STAT_KEYS:
            value = stats.get(key)
            if not _is_integer(value) or value < 0:
                raise ClothError("CLOTH_SNAPSHOT_INVALID", value)
            normalized_stats[key] = value

        raw_cloths = state.get("cloths")
        if isinstance(raw_cloths, dict):
            cloth_items = list(raw_cloths.values())
        elif isinstance(raw_cloths, (list, tuple)):
            cloth_items = list(raw_cloths)
        else:
            raise ClothError("CLOTH_SNAPSHOT_INVALID", raw_cloths)

        records: dict[str, dict] = {}
        for item in cloth_items:
            if (
                isinstance(item, dict)
                and "cloth_id" not in item
                and "id" not in item
            ):
                raise ClothError("CLOTH_SNAPSHOT_INVALID", item)
            record = self._record_from_snapshot(item, float(damping))
            if record["cloth_id"] in records:
                raise ClothError("CLOTH_SNAPSHOT_INVALID", record["cloth_id"])
            records[record["cloth_id"]] = record

        release_counter = state.get(
            "release_counter", normalized_stats["detaches"]
        )
        if (
            not _is_integer(release_counter)
            or release_counter < normalized_stats["detaches"]
        ):
            raise ClothError("CLOTH_SNAPSHOT_INVALID", release_counter)

        max_release_order = max(
            (
                record["release_order"]
                for record in records.values()
                if record["release_order"] is not None
            ),
            default=0,
        )
        release_counter = max(release_counter, max_release_order)

        return {
            "fixed_step": float(fixed_step),
            "damping": float(damping),
            "budget": int(budget),
            "frame": int(frame),
            "accumulator": float(accumulator),
            "stats": normalized_stats,
            "release_counter": int(release_counter),
            "cloths": records,
        }

    def restore(self, state):
        with self._lock:
            try:
                restored = self._state_from_snapshot(state)
            except ClothError as exc:
                if exc.code == "CLOTH_SNAPSHOT_INVALID":
                    raise
                raise ClothError(
                    "CLOTH_SNAPSHOT_INVALID", exc.detail
                ) from exc
            except Exception as exc:
                raise ClothError(
                    "CLOTH_SNAPSHOT_INVALID", state
                ) from exc

            for cloth_id, record in restored["cloths"].items():
                old_record = self._cloths.get(cloth_id)
                record["host_ref"] = (
                    old_record["host_ref"] if old_record else None
                )

            self.fixed_step = restored["fixed_step"]
            self.damping = restored["damping"]
            self.substep_budget = restored["budget"]
            self._frame = restored["frame"]
            self._accumulator = restored["accumulator"]
            self._stats = restored["stats"]
            self._release_counter = restored["release_counter"]
            self._cloths = restored["cloths"]
            self._collision_cache = None

    def stats(self):
        with self._lock:
            return dict(self._stats)
