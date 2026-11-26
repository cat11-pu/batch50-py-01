"""Deterministic mesh decimation planning and round-based collapse state."""

from __future__ import annotations

import copy
import math
import threading
from dataclasses import dataclass
from typing import Any

__all__ = [
    "MeshPlanError",
    "MeshSummary",
    "AppliedRound",
    "MeshDecimationPlanner",
]


SNAPSHOT_VERSION = 1
SNAPSHOT_KEYS = (
    "version",
    "mesh_id",
    "vertices",
    "faces",
    "locked",
    "boundary",
    "target",
    "history",
    "counters",
)


class MeshPlanError(ValueError):
    """Raised when a decimation request is rejected."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class MeshSummary:
    mesh_id: str
    vertices: int
    faces: int
    boundary_vertices: tuple[int, ...]
    locked: int


@dataclass(frozen=True)
class AppliedRound:
    round: int
    survivor: int
    removed: int
    cost: float
    faces_before: int
    faces_after: int
    vertices: int


def _strict_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _finite_point(value: Any) -> bool:
    if isinstance(value, (str, bytes, bytearray)):
        return False
    if not isinstance(value, (list, tuple)) or len(value) != 3:
        return False
    return all(
        isinstance(component, (int, float))
        and not isinstance(component, bool)
        and math.isfinite(component)
        for component in value
    )


def _normalized_point(value: Any) -> list[float]:
    return [float(value[0]), float(value[1]), float(value[2])]


def _valid_face(value: Any, vertex_count: int) -> tuple[int, int, int] | None:
    if isinstance(value, (str, bytes, bytearray)):
        return None
    if not isinstance(value, (list, tuple)) or len(value) != 3:
        return None
    if not all(_strict_int(index) for index in value):
        return None
    if any(index < 0 or index >= vertex_count for index in value):
        return None
    if len(set(value)) != 3:
        return None
    return (int(value[0]), int(value[1]), int(value[2]))


def _round6(value: float) -> float:
    result = round(float(value), 6)
    return 0.0 if result == 0 else result


def _edge_key(left: int, right: int) -> tuple[int, int]:
    return (left, right) if left < right else (right, left)


def _edge_usage(faces: list[tuple[int, int, int]]) -> dict[tuple[int, int], int]:
    usage: dict[tuple[int, int], int] = {}
    for face in faces:
        pairs = ((face[0], face[1]), (face[1], face[2]), (face[2], face[0]))
        for left, right in pairs:
            key = _edge_key(left, right)
            usage[key] = usage.get(key, 0) + 1
    return usage


def _boundary_vertices(faces: list[tuple[int, int, int]]) -> tuple[int, ...]:
    boundary: set[int] = set()
    for (left, right), count in _edge_usage(faces).items():
        if count == 1:
            boundary.add(left)
            boundary.add(right)
    return tuple(sorted(boundary))


def _cost_between(vertices: list[list[float]], left: int, right: int) -> float:
    total = 0.0
    for axis in range(3):
        delta = vertices[left][axis] - vertices[right][axis]
        total += delta * delta
    return _round6(total)


def _deduplicate_faces(
    faces: list[tuple[int, int, int]],
) -> list[tuple[int, int, int]]:
    result: list[tuple[int, int, int]] = []
    seen: set[tuple[int, ...]] = set()
    for face in faces:
        key = tuple(sorted(face))
        if key in seen:
            continue
        seen.add(key)
        result.append(face)
    return result


def _remap_forward(index: int, removed: int) -> int:
    return index if index < removed else index - 1


def _remap_backward(index: int, removed: int) -> int:
    return index if index < removed else index + 1


def _remap_locked_forward(
    locked: set[int], removed: int, survivor: int
) -> set[int]:
    result: set[int] = set()
    for index in locked:
        if index == removed:
            index = survivor
        result.add(_remap_forward(index, removed))
    return result


def _collapse_state(
    vertices: list[list[float]],
    faces: list[tuple[int, int, int]],
    survivor: int,
    removed: int,
    locked: set[int] | None = None,
) -> tuple[list[list[float]], list[tuple[int, int, int]], set[int]] | None:
    """Simulate one canonical collapse and return the compacted state."""

    if not (0 <= survivor < removed < len(vertices)):
        return None

    midpoint = [
        _round6((vertices[survivor][axis] + vertices[removed][axis]) / 2.0)
        for axis in range(3)
    ]

    mapped_faces: list[tuple[int, int, int]] = []
    used_before: set[int] = set()
    for face in faces:
        used_before.update(face)
        if survivor in face and removed in face:
            continue
        mapped = tuple(survivor if index == removed else index for index in face)
        if len(set(mapped)) != 3:
            return None
        mapped_faces.append(mapped)  # type: ignore[arg-type]

    mapped_faces = _deduplicate_faces(mapped_faces)
    if not mapped_faces:
        return None

    used_after: set[int] = set()
    usage: dict[tuple[int, int], int] = {}
    for face in mapped_faces:
        if removed in face:
            return None
        used_after.update(face)
        pairs = ((face[0], face[1]), (face[1], face[2]), (face[2], face[0]))
        for left, right in pairs:
            key = _edge_key(left, right)
            usage[key] = usage.get(key, 0) + 1
            if usage[key] > 2:
                return None

    for vertex in used_before:
        if vertex != removed and vertex not in used_after:
            return None

    new_vertices: list[list[float]] = []
    for index, point in enumerate(vertices):
        if index == removed:
            continue
        new_vertices.append(midpoint if index == survivor else _normalized_point(point))

    new_faces: list[tuple[int, int, int]] = []
    for face in mapped_faces:
        compact_face = tuple(_remap_forward(index, removed) for index in face)
        if not all(0 <= index < len(new_vertices) for index in compact_face):
            return None
        if len(set(compact_face)) != 3:
            return None
        new_faces.append(compact_face)  # type: ignore[arg-type]

    new_locked: set[int] = set()
    if locked is not None:
        new_locked = _remap_locked_forward(set(locked), removed, survivor)
        new_locked = {
            index for index in new_locked if 0 <= index < len(new_vertices)
        }

    return new_vertices, new_faces, new_locked


def _build_plan(
    vertices: list[list[float]],
    faces: list[tuple[int, int, int]],
    locked: set[int],
    lineage_boundary: set[int] | None = None,
) -> list[tuple[float, int, int]]:
    usage = _edge_usage(faces)
    edge_set = set(usage)
    boundary_now = {
        index
        for (left, right), count in usage.items()
        if count == 1
        for index in (left, right)
    }
    if lineage_boundary:
        boundary_now.update(lineage_boundary)

    candidates: list[tuple[float, int, int]] = []
    for left in range(len(vertices)):
        for right in range(left + 1, len(vertices)):
            if (left, right) not in edge_set:
                continue

            # A higher-index boundary vertex cannot be absorbed into a lower
            # interior vertex.  Two boundary vertices remain the same class.
            if right in boundary_now and left not in boundary_now:
                continue

            # Manually locked seam vertices use the same directional rule.
            if right in locked and left not in locked:
                if not (left in boundary_now and right in boundary_now):
                    continue

            if _collapse_state(vertices, faces, left, right, locked) is None:
                continue

            candidates.append((_cost_between(vertices, left, right), left, right))

    candidates.sort(key=lambda item: (item[0], item[1], item[2]))
    return candidates


class MeshDecimationPlanner:
    """Plan, apply, roll back, snapshot and restore mesh collapses."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._loaded = False
        self._mesh_id: str | None = None
        self._vertices: list[list[float]] = []
        self._faces: list[tuple[int, int, int]] = []
        self._boundary: tuple[int, ...] = ()
        self._locked: set[int] = set()
        self._target: int | None = None
        self._round = 0
        self._history: list[dict[str, Any]] = []
        self._counters: dict[str, int] = {"applied": 0}

    def _require_loaded(self) -> None:
        if not self._loaded:
            raise MeshPlanError("MESH_NO_MESH")

    def _history_entry(self, round_number: int) -> dict[str, Any]:
        return {
            "round": round_number,
            "vertices": copy.deepcopy(self._vertices),
            "faces": copy.deepcopy(self._faces),
            "boundary": list(self._boundary),
        }

    def _plan_current(self) -> list[tuple[float, int, int]]:
        return _build_plan(
            self._vertices,
            self._faces,
            self._locked,
            set(self._boundary),
        )

    def _reachable_faces(self) -> int:
        vertices = copy.deepcopy(self._vertices)
        faces = list(self._faces)
        locked = set(self._locked)
        boundary = set(self._boundary)
        reachable = len(faces)

        while True:
            if self._target is not None and reachable <= self._target:
                break
            plan = _build_plan(vertices, faces, locked, boundary)
            if not plan:
                break
            _cost, survivor, removed = plan[0]
            collapsed = _collapse_state(vertices, faces, survivor, removed, locked)
            if collapsed is None:
                break
            vertices, faces, locked = collapsed
            boundary = _remap_locked_forward(boundary, removed, survivor)
            reachable = len(faces)

        return reachable

    def load(self, mesh_id: str, vertices, faces) -> MeshSummary:
        with self._lock:
            if not isinstance(mesh_id, str) or not mesh_id.strip():
                raise MeshPlanError("MESH_INVALID_INPUT", "mesh_id is invalid")
            normalized_id = mesh_id.strip()

            if not isinstance(vertices, (list, tuple)) or len(vertices) < 4:
                raise MeshPlanError(
                    "MESH_INVALID_INPUT", "at least four vertices are required"
                )
            normalized_vertices: list[list[float]] = []
            for point in vertices:
                if not _finite_point(point):
                    raise MeshPlanError("MESH_INVALID_INPUT", "invalid vertex")
                normalized_vertices.append(_normalized_point(point))

            if not isinstance(faces, (list, tuple)) or len(faces) < 1:
                raise MeshPlanError(
                    "MESH_INVALID_INPUT", "at least one face is required"
                )
            normalized_faces: list[tuple[int, int, int]] = []
            for face in faces:
                valid_face = _valid_face(face, len(normalized_vertices))
                if valid_face is None:
                    raise MeshPlanError("MESH_INVALID_INPUT", "invalid face")
                normalized_faces.append(valid_face)

            boundary = _boundary_vertices(normalized_faces)

            self._loaded = True
            self._mesh_id = normalized_id
            self._vertices = normalized_vertices
            self._faces = normalized_faces
            self._boundary = boundary
            self._locked = set()
            self._target = None
            self._round = 0
            self._counters = {"applied": 0}
            self._history = [self._history_entry(0)]

            return MeshSummary(
                mesh_id=normalized_id,
                vertices=len(normalized_vertices),
                faces=len(normalized_faces),
                boundary_vertices=boundary,
                locked=0,
            )

    def set_target(self, faces: int) -> int:
        with self._lock:
            self._require_loaded()
            if not _strict_int(faces) or faces < 1 or faces >= len(self._faces):
                raise MeshPlanError("MESH_INVALID_TARGET", {"target": faces})
            self._target = faces
            return faces

    def lock_boundary(self, vertices=None) -> int:
        with self._lock:
            self._require_loaded()
            if vertices is None:
                requested = list(self._boundary)
            elif isinstance(vertices, (str, bytes, bytearray)) or not isinstance(
                vertices, (list, tuple, set, frozenset)
            ):
                raise MeshPlanError("MESH_INVALID_INPUT", "invalid vertex list")
            else:
                requested = list(vertices)

            additions: set[int] = set()
            for index in requested:
                if not _strict_int(index) or not 0 <= index < len(self._vertices):
                    raise MeshPlanError("MESH_INVALID_INPUT", {"vertex": index})
                additions.add(index)

            self._locked.update(additions)
            return len(self._locked)

    def edge_cost(self, left: int, right: int) -> float:
        with self._lock:
            self._require_loaded()
            valid_indices = (
                _strict_int(left)
                and _strict_int(right)
                and 0 <= left < len(self._vertices)
                and 0 <= right < len(self._vertices)
            )
            if not valid_indices or left == right:
                raise MeshPlanError(
                    "MESH_INVALID_INPUT", {"left": left, "right": right}
                )
            return _cost_between(self._vertices, left, right)

    def plan(self) -> list[tuple[float, int, int]]:
        with self._lock:
            self._require_loaded()
            return self._plan_current()

    def apply_round(self) -> AppliedRound:
        with self._lock:
            self._require_loaded()
            if self._target is None:
                raise MeshPlanError("MESH_NO_TARGET")

            faces_before = len(self._faces)
            if faces_before <= self._target:
                raise MeshPlanError(
                    "MESH_TARGET_REACHED",
                    {"faces": faces_before, "target": self._target},
                )

            plan = self._plan_current()
            if not plan:
                raise MeshPlanError(
                    "MESH_NO_CANDIDATE",
                    {"faces": faces_before, "target": self._target},
                )

            cost, survivor, removed = plan[0]
            collapsed = _collapse_state(
                self._vertices,
                self._faces,
                survivor,
                removed,
                self._locked,
            )
            if collapsed is None:
                raise MeshPlanError(
                    "MESH_NO_CANDIDATE",
                    {"faces": faces_before, "target": self._target},
                )

            new_vertices, new_faces, new_locked = collapsed
            self._vertices = new_vertices
            self._faces = new_faces
            self._locked = new_locked
            boundary_set = _remap_locked_forward(
                set(self._boundary), removed, survivor
            )
            self._boundary = tuple(sorted(boundary_set))
            self._round += 1
            self._counters["applied"] = self._round

            entry = self._history_entry(self._round)
            entry.update({"survivor": survivor, "removed": removed, "cost": cost})
            self._history.append(entry)

            return AppliedRound(
                round=self._round,
                survivor=survivor,
                removed=removed,
                cost=cost,
                faces_before=faces_before,
                faces_after=len(new_faces),
                vertices=len(new_vertices),
            )

    def report(self) -> dict:
        with self._lock:
            self._require_loaded()
            faces = len(self._faces)
            return {
                "target": self._target,
                "faces": faces,
                "vertices": len(self._vertices),
                "rounds": self._round,
                "reached": self._target is not None and faces <= self._target,
                "reachable": self._reachable_faces(),
            }

    def rollback(self, rounds: int) -> int:
        with self._lock:
            self._require_loaded()
            target_round = rounds
            if not _strict_int(target_round):
                raise MeshPlanError(
                    "MESH_ROLLBACK_OUT_OF_RANGE", {"rounds": rounds}
                )
            if target_round < 0 or target_round > self._round:
                raise MeshPlanError(
                    "MESH_ROLLBACK_OUT_OF_RANGE",
                    {"rounds": target_round, "available": self._round},
                )

            mapped_locked = set(self._locked)
            for round_number in range(self._round, target_round, -1):
                removed = self._history[round_number].get("removed")
                if not _strict_int(removed):
                    raise MeshPlanError(
                        "MESH_ROLLBACK_OUT_OF_RANGE", "history is incomplete"
                    )
                mapped_locked = {
                    _remap_backward(index, removed) for index in mapped_locked
                }

            entry = self._history[target_round]
            restored_vertices = copy.deepcopy(entry["vertices"])
            self._vertices = restored_vertices
            self._faces = copy.deepcopy(entry["faces"])
            self._locked = {
                index for index in mapped_locked if 0 <= index < len(self._vertices)
            }
            stored_boundary = entry.get("boundary")
            if isinstance(stored_boundary, (list, tuple)):
                self._boundary = tuple(sorted(int(index) for index in stored_boundary))
            else:
                self._boundary = _boundary_vertices(self._faces)
            self._round = target_round
            self._history = self._history[: target_round + 1]
            self._counters["applied"] = target_round
            return len(self._faces)

    def stats(self) -> dict:
        with self._lock:
            self._require_loaded()
            return {
                "mesh": self._mesh_id,
                "mesh_id": self._mesh_id,
                "vertices": len(self._vertices),
                "faces": len(self._faces),
                "locked": len(self._locked),
                "boundary": len(self._boundary),
                "target": self._target,
                "rounds": self._round,
                "applied": self._counters.get("applied", self._round),
            }

    def snapshot(self) -> dict:
        with self._lock:
            self._require_loaded()
            history: list[dict[str, Any]] = []
            for entry in self._history:
                item: dict[str, Any] = {
                    "round": int(entry["round"]),
                    "vertices": copy.deepcopy(entry["vertices"]),
                    "faces": [list(face) for face in entry["faces"]],
                }
                for key in ("survivor", "removed", "cost", "boundary"):
                    if key in entry and entry[key] is not None:
                        value = entry[key]
                        item[key] = copy.deepcopy(value)
                history.append(item)

            return {
                "version": SNAPSHOT_VERSION,
                "mesh_id": self._mesh_id,
                "vertices": copy.deepcopy(self._vertices),
                "faces": [list(face) for face in self._faces],
                "locked": sorted(self._locked),
                "boundary": list(self._boundary),
                "target": self._target,
                "history": history,
                "counters": copy.deepcopy(self._counters),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._validate_snapshot(state)
            except MeshPlanError:
                raise
            except Exception as exc:  # Defensive schema boundary.
                raise MeshPlanError("MESH_SNAPSHOT_INVALID", str(exc)) from exc

            self._loaded = True
            self._mesh_id = restored["mesh_id"]
            self._vertices = restored["vertices"]
            self._faces = restored["faces"]
            self._boundary = restored["boundary"]
            self._locked = restored["locked"]
            self._target = restored["target"]
            self._round = restored["round"]
            self._history = restored["history"]
            self._counters = restored["counters"]

    @staticmethod
    def _invalid_snapshot(detail: object = None) -> MeshPlanError:
        return MeshPlanError("MESH_SNAPSHOT_INVALID", detail)

    @classmethod
    def _validate_snapshot(cls, state: Any) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise cls._invalid_snapshot("snapshot must be an object")
        if set(state) != set(SNAPSHOT_KEYS):
            raise cls._invalid_snapshot("snapshot keys do not match the fixed schema")

        version = state["version"]
        if not _strict_int(version) or version != SNAPSHOT_VERSION:
            raise cls._invalid_snapshot("unsupported snapshot version")

        mesh_id = state["mesh_id"]
        if not isinstance(mesh_id, str) or not mesh_id.strip():
            raise cls._invalid_snapshot("invalid mesh_id")
        mesh_id = mesh_id.strip()

        vertices_raw = state["vertices"]
        if not isinstance(vertices_raw, (list, tuple)):
            raise cls._invalid_snapshot("vertices must be a list")
        vertices: list[list[float]] = []
        for point in vertices_raw:
            if not _finite_point(point):
                raise cls._invalid_snapshot("invalid snapshot vertex")
            vertices.append(_normalized_point(point))

        faces_raw = state["faces"]
        if not isinstance(faces_raw, (list, tuple)) or not faces_raw:
            raise cls._invalid_snapshot("faces must be a non-empty list")
        faces: list[tuple[int, int, int]] = []
        for face in faces_raw:
            valid_face = _valid_face(face, len(vertices))
            if valid_face is None:
                raise cls._invalid_snapshot("invalid snapshot face")
            faces.append(valid_face)

        def parse_index_list(key: str, raw: Any) -> set[int]:
            if not isinstance(raw, (list, tuple, set, frozenset)):
                raise cls._invalid_snapshot(f"{key} must be a list")
            values: set[int] = set()
            for index in raw:
                if not _strict_int(index) or not 0 <= index < len(vertices):
                    raise cls._invalid_snapshot(f"invalid {key} index")
                if index in values:
                    raise cls._invalid_snapshot(f"duplicate {key} index")
                values.add(index)
            return values

        locked = parse_index_list("locked", state["locked"])
        boundary = tuple(sorted(parse_index_list("boundary", state["boundary"])))

        target = state["target"]
        if target is not None and (not _strict_int(target) or target < 1):
            raise cls._invalid_snapshot("invalid target")

        counters = state["counters"]
        if not isinstance(counters, dict):
            raise cls._invalid_snapshot("counters must be an object")
        applied = counters.get("applied")
        if not _strict_int(applied) or applied < 0:
            raise cls._invalid_snapshot("invalid applied counter")

        history_raw = state["history"]
        if not isinstance(history_raw, (list, tuple)) or not history_raw:
            raise cls._invalid_snapshot("history must be a non-empty list")
        if applied != len(history_raw) - 1:
            raise cls._invalid_snapshot("history length does not match applied counter")

        history: list[dict[str, Any]] = []
        previous_vertex_count: int | None = None
        previous_face_count: int | None = None
        for index, raw_entry in enumerate(history_raw):
            if not isinstance(raw_entry, dict):
                raise cls._invalid_snapshot("history entry must be an object")
            if "vertices" not in raw_entry or "faces" not in raw_entry:
                raise cls._invalid_snapshot("history entry is incomplete")

            entry_vertices_raw = raw_entry["vertices"]
            if not isinstance(entry_vertices_raw, (list, tuple)):
                raise cls._invalid_snapshot("history vertices must be a list")
            entry_vertices: list[list[float]] = []
            for point in entry_vertices_raw:
                if not _finite_point(point):
                    raise cls._invalid_snapshot("invalid history vertex")
                entry_vertices.append(_normalized_point(point))

            entry_faces_raw = raw_entry["faces"]
            if not isinstance(entry_faces_raw, (list, tuple)) or not entry_faces_raw:
                raise cls._invalid_snapshot("history faces must be non-empty")
            entry_faces: list[tuple[int, int, int]] = []
            for face in entry_faces_raw:
                valid_face = _valid_face(face, len(entry_vertices))
                if valid_face is None:
                    raise cls._invalid_snapshot("invalid history face")
                entry_faces.append(valid_face)

            if index == 0 and len(entry_vertices) < 4:
                raise cls._invalid_snapshot("base snapshot has too few vertices")
            if previous_vertex_count is not None:
                if len(entry_vertices) != previous_vertex_count - 1:
                    raise cls._invalid_snapshot("history vertex sequence is inconsistent")
            if previous_face_count is not None:
                if len(entry_faces) >= previous_face_count:
                    raise cls._invalid_snapshot("history face sequence is inconsistent")

            entry: dict[str, Any] = {
                "round": index,
                "vertices": entry_vertices,
                "faces": entry_faces,
            }
            raw_entry_boundary = raw_entry.get("boundary")
            if raw_entry_boundary is None:
                entry_boundary = set(_boundary_vertices(entry_faces))
            else:
                if not isinstance(
                    raw_entry_boundary, (list, tuple, set, frozenset)
                ):
                    raise cls._invalid_snapshot("invalid history boundary")
                entry_boundary = set()
                for boundary_index in raw_entry_boundary:
                    if not _strict_int(boundary_index) or not (
                        0 <= boundary_index < len(entry_vertices)
                    ):
                        raise cls._invalid_snapshot("invalid history boundary index")
                    entry_boundary.add(boundary_index)
            entry["boundary"] = list(sorted(entry_boundary))

            if index > 0:
                survivor = raw_entry.get("survivor")
                removed = raw_entry.get("removed")
                cost = raw_entry.get("cost")
                if not _strict_int(survivor) or not _strict_int(removed):
                    raise cls._invalid_snapshot("history collapse indices are invalid")
                if not (0 <= survivor < removed < (previous_vertex_count or 0)):
                    raise cls._invalid_snapshot("history collapse is out of range")
                if cost is not None and (
                    not isinstance(cost, (int, float))
                    or isinstance(cost, bool)
                    or not math.isfinite(cost)
                ):
                    raise cls._invalid_snapshot("invalid history cost")
                entry["survivor"] = survivor
                entry["removed"] = removed
                if cost is not None:
                    entry["cost"] = _round6(cost)

            history.append(entry)
            previous_vertex_count = len(entry_vertices)
            previous_face_count = len(entry_faces)

        if target is not None and target >= len(history[0]["faces"]):
            raise cls._invalid_snapshot("target is outside the base face budget")

        last = history[-1]
        current_faces_normalized = [list(face) for face in faces]
        history_faces_normalized = [list(face) for face in last["faces"]]
        if (
            last["vertices"] != vertices
            or history_faces_normalized != current_faces_normalized
        ):
            raise cls._invalid_snapshot("last history entry must match current state")

        restored_counters = copy.deepcopy(counters)
        restored_counters["applied"] = applied
        return {
            "mesh_id": mesh_id,
            "vertices": vertices,
            "faces": faces,
            "locked": locked,
            "boundary": boundary,
            "target": target,
            "round": applied,
            "history": history,
            "counters": restored_counters,
        }
