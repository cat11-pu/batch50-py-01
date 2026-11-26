"""Tangent frame builder: reconstruct per-vertex tangents from UV derivatives."""

from __future__ import annotations

import copy
import math
import numbers
import operator
import threading
from typing import Any

__all__ = [
    "TangentError",
    "TangentFrameBuilder",
    "DEFAULT_MAX_VERTICES",
    "SNAPSHOT_SCHEMA",
]

DEFAULT_MAX_VERTICES = 4096
SNAPSHOT_SCHEMA = 1
_DEFAULT_ANGLE_THRESHOLD = 60.0


class TangentError(ValueError):
    """Raised when a tangent frame request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _invalid(detail: object = None) -> TangentError:
    return TangentError("TANGENT_INVALID_REQUEST", detail)


def _unknown(mesh_id: object = None) -> TangentError:
    return TangentError("TANGENT_UNKNOWN_MESH", mesh_id)


def _snapshot_invalid(detail: object = None) -> TangentError:
    return TangentError("TANGENT_SNAPSHOT_INVALID", detail)


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _channel_value(channel: object) -> int:
    if isinstance(channel, bool):
        raise _invalid("uv channel must be a non-negative integer")
    try:
        value = operator.index(channel)  # type: ignore[arg-type]
    except TypeError as exc:
        raise _invalid("uv channel must be a non-negative integer") from exc
    if value < 0:
        raise _invalid("uv channel must be a non-negative integer")
    return value


def _snapshot_channel_value(channel: object) -> int:
    if isinstance(channel, str) and channel.isdigit():
        return int(channel)
    return _channel_value(channel)


def _as_vector_tuple(
    value: object, width: int, name: str
) -> tuple[tuple[float, ...], ...]:
    if value is None or isinstance(value, (str, bytes, bytearray)):
        raise _invalid(f"{name} must be a sequence of {width}D vectors")
    try:
        raw_rows = tuple(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise _invalid(f"{name} must be a sequence of {width}D vectors") from exc

    rows: list[tuple[float, ...]] = []
    for row_index, raw_row in enumerate(raw_rows):
        if raw_row is None or isinstance(raw_row, (str, bytes, bytearray)):
            raise _invalid(f"{name}[{row_index}] must be a {width}D vector")
        try:
            coordinates = tuple(raw_row)  # type: ignore[arg-type]
        except TypeError as exc:
            raise _invalid(f"{name}[{row_index}] must be a {width}D vector") from exc
        if len(coordinates) != width:
            raise _invalid(f"{name}[{row_index}] must contain exactly {width} components")

        components: list[float] = []
        for component in coordinates:
            if isinstance(component, bool):
                number: float | None = float(component)
            elif isinstance(component, numbers.Real):
                number = float(component)
            else:
                number = None
            if number is None or not math.isfinite(number):
                raise _invalid(f"{name}[{row_index}] contains a non-finite number")
            components.append(number)
        rows.append(tuple(components))
    return tuple(rows)


def _as_index_tuple(value: object, vertex_count: int) -> tuple[int, ...]:
    if value is None or isinstance(value, (str, bytes, bytearray)):
        raise _invalid("indices must be a sequence of integers")
    try:
        raw_indices = tuple(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise _invalid("indices must be a sequence of integers") from exc

    indices: list[int] = []
    for index in raw_indices:
        if isinstance(index, bool):
            raise _invalid("indices must not contain boolean values")
        try:
            parsed = operator.index(index)  # type: ignore[arg-type]
        except TypeError as exc:
            raise _invalid("indices must contain integers") from exc
        if parsed < 0 or parsed >= vertex_count:
            raise _invalid(f"index {parsed} is outside 0..{vertex_count - 1}")
        indices.append(parsed)

    if len(indices) % 3 != 0:
        raise _invalid("indices length must be a multiple of three")
    return tuple(indices)


def _as_group_tuple(value: object) -> tuple[object, ...] | None:
    if value is None:
        return None
    if isinstance(value, (str, bytes, bytearray)):
        raise _invalid("material_groups must be a sequence")
    try:
        return tuple(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise _invalid("material_groups must be a sequence") from exc


def _sub(a: tuple[float, ...], b: tuple[float, ...]) -> tuple[float, float, float]:
    return (a[0] - b[0], a[1] - b[1], a[2] - b[2])


def _add_to(target: list[float], value: tuple[float, ...]) -> None:
    target[0] += value[0]
    target[1] += value[1]
    target[2] += value[2]


def _scale(value: tuple[float, ...], factor: float) -> tuple[float, float, float]:
    return (value[0] * factor, value[1] * factor, value[2] * factor)


def _dot(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    return a[0] * b[0] + a[1] * b[1] + a[2] * b[2]


def _cross(a: tuple[float, ...], b: tuple[float, ...]) -> tuple[float, float, float]:
    return (
        a[1] * b[2] - a[2] * b[1],
        a[2] * b[0] - a[0] * b[2],
        a[0] * b[1] - a[1] * b[0],
    )


def _normalized(value: tuple[float, ...]) -> tuple[float, float, float] | None:
    length_squared = _dot(value, value)
    if length_squared <= 0.0:
        return None
    length = math.sqrt(length_squared)
    return (value[0] / length, value[1] / length, value[2] / length)


def _orthogonalize(
    vector_sum: tuple[float, ...], normal: tuple[float, float, float]
) -> tuple[float, float, float] | None:
    normal_component = _dot(vector_sum, normal)
    tangent = (
        vector_sum[0] - normal[0] * normal_component,
        vector_sum[1] - normal[1] * normal_component,
        vector_sum[2] - normal[2] * normal_component,
    )
    return _normalized(tangent)


def _fallback_tangent(normal: tuple[float, float, float]) -> tuple[float, float, float]:
    reference = (1.0, 0.0, 0.0) if abs(normal[0]) < 0.9 else (0.0, 1.0, 0.0)
    tangent = _cross(reference, normal)
    normalized = _normalized(tangent)
    if normalized is not None:
        return normalized
    return (0.0, 1.0, 0.0) if abs(normal[1]) < 0.9 else (0.0, 0.0, 1.0)


class _Topology:
    __slots__ = ("indices", "sources", "vertex_count", "wedge_signs")

    def __init__(
        self,
        indices: tuple[int, ...],
        sources: tuple[int, ...],
        wedge_signs: tuple[int, ...],
    ) -> None:
        self.indices = indices
        self.sources = sources
        self.vertex_count = len(sources)
        self.wedge_signs = wedge_signs


class TangentFrameBuilder:
    """Build and cache per-vertex tangent frames for registered meshes."""

    def __init__(self, *, max_vertices: int = DEFAULT_MAX_VERTICES) -> None:
        if not _is_positive_int(max_vertices):
            raise _invalid("max_vertices must be a positive integer")
        self.max_vertices = max_vertices
        self._lock = threading.RLock()
        self._meshes: dict[str, dict[str, Any]] = {}
        self._cache: dict[str, dict[str, Any]] = {}
        self._stats: dict[str, int] = {
            "meshes": 0,
            "versions": 0,
            "builds": 0,
            "cache_hits": 0,
            "invalidations": 0,
            "vertex_limit_refusals": 0,
        }

    def register_mesh(
        self,
        mesh_id: str,
        *,
        positions,
        uvs,
        indices,
        normals=None,
        uv_channel: int = 0,
        material_groups=None,
    ) -> int:
        if not isinstance(mesh_id, str) or not mesh_id:
            raise _invalid("mesh_id must be a non-empty string")
        channel = _channel_value(uv_channel)
        parsed_positions = _as_vector_tuple(positions, 3, "positions")
        if not parsed_positions:
            raise _invalid("positions must not be empty")
        vertex_count = len(parsed_positions)

        parsed_uvs = _as_vector_tuple(uvs, 2, "uvs")
        if len(parsed_uvs) != vertex_count:
            raise _invalid("positions and uvs must have the same length")

        parsed_indices = _as_index_tuple(indices, vertex_count)
        triangle_count = len(parsed_indices) // 3

        parsed_normals = None
        if normals is not None:
            parsed_normals = _as_vector_tuple(normals, 3, "normals")
            if len(parsed_normals) != vertex_count:
                raise _invalid("normals must have the same length as positions")

        parsed_groups = _as_group_tuple(material_groups)
        group_kind: str | None = None
        if parsed_groups is not None:
            if len(parsed_groups) == triangle_count:
                group_kind = "triangle"
            elif len(parsed_groups) == vertex_count:
                group_kind = "vertex"
            else:
                raise _invalid(
                    "material_groups length must match triangle or vertex count"
                )

        if vertex_count > self.max_vertices:
            with self._lock:
                self._stats["vertex_limit_refusals"] += 1
            raise TangentError(
                "TANGENT_VERTEX_LIMIT",
                f"vertex count {vertex_count} exceeds limit {self.max_vertices}",
            )

        with self._lock:
            existing = self._meshes.get(mesh_id)
            version = int(existing["version"]) + 1 if existing is not None else 1
            self._meshes[mesh_id] = {
                "mesh_id": mesh_id,
                "version": version,
                "positions": parsed_positions,
                "uvs": {channel: parsed_uvs},
                "indices": parsed_indices,
                "normals": parsed_normals,
                "material_groups": parsed_groups,
                "material_group_kind": group_kind,
                "split_maps": {},
            }
            self._drop_mesh_cache_locked(mesh_id)
            self._stats["versions"] += 1
            self._stats["meshes"] = len(self._meshes)
            return version

    def set_uv_channel(self, mesh_id: str, channel: int, uvs) -> int:
        with self._lock:
            self._get_mesh_locked(mesh_id)
            parsed_channel = _channel_value(channel)
            mesh = self._meshes[mesh_id]
            parsed_uvs = _as_vector_tuple(uvs, 2, "uvs")
            if len(parsed_uvs) != len(mesh["positions"]):
                raise _invalid("uvs must have the same length as positions")

            mesh["uvs"][parsed_channel] = parsed_uvs
            mesh["version"] = int(mesh["version"]) + 1
            mesh["split_maps"].pop(parsed_channel, None)
            self._drop_mesh_cache_locked(mesh_id)
            self._stats["versions"] += 1
            return int(mesh["version"])

    def build_frames(self, mesh_id: str, *, uv_channel: int = 0) -> dict:
        with self._lock:
            mesh = self._get_mesh_locked(mesh_id)
            channel = _channel_value(uv_channel)
            if channel not in mesh["uvs"]:
                raise _invalid(f"unknown uv channel {channel}")

            version = int(mesh["version"])
            key = self._cache_key_locked(mesh_id, version, channel)
            if len(mesh["positions"]) > self.max_vertices:
                self._stats["vertex_limit_refusals"] += 1
                raise TangentError(
                    "TANGENT_VERTEX_LIMIT",
                    f"vertex count exceeds limit {self.max_vertices}",
                )

            split_state = mesh["split_maps"].get(channel)
            if (
                split_state is not None
                and int(split_state["vertex_count"]) > self.max_vertices
            ):
                self._stats["vertex_limit_refusals"] += 1
                raise TangentError(
                    "TANGENT_VERTEX_LIMIT", "split vertex count exceeds limit"
                )

            cached = self._cache.get(key)
            if cached is not None:
                if int(cached["vertex_count"]) > self.max_vertices:
                    self._stats["vertex_limit_refusals"] += 1
                    raise TangentError(
                        "TANGENT_VERTEX_LIMIT", "cached vertex count exceeds limit"
                    )
                self._stats["cache_hits"] += 1
                return self._cache_view(cached, cached=True)

            threshold = _DEFAULT_ANGLE_THRESHOLD
            split_state_for_build = mesh["split_maps"].get(channel)
            if split_state_for_build is not None:
                threshold = float(
                    split_state_for_build.get(
                        "angle_threshold", _DEFAULT_ANGLE_THRESHOLD
                    )
                )
            topology = self._build_topology(mesh, channel, threshold)
            if topology.vertex_count > self.max_vertices:
                self._stats["vertex_limit_refusals"] += 1
                raise TangentError(
                    "TANGENT_VERTEX_LIMIT", "split vertex count exceeds limit"
                )

            entry = self._compute_entry(mesh, channel, key, topology)
            self._cache[key] = entry
            self._stats["builds"] += 1
            return self._cache_view(entry, cached=False)

    def split_vertices(
        self,
        mesh_id: str,
        *,
        uv_channel: int = 0,
        angle_threshold: float = 60.0,
    ) -> int:
        with self._lock:
            mesh = self._get_mesh_locked(mesh_id)
            channel = _channel_value(uv_channel)
            if channel not in mesh["uvs"]:
                raise _invalid(f"unknown uv channel {channel}")
            if isinstance(angle_threshold, bool) or not isinstance(
                angle_threshold, numbers.Real
            ):
                raise _invalid("angle_threshold must be a number in [0, 180]")
            threshold = float(angle_threshold)
            if not math.isfinite(threshold) or threshold < 0.0 or threshold > 180.0:
                raise _invalid("angle_threshold must be a number in [0, 180]")
            if len(mesh["positions"]) > self.max_vertices:
                self._stats["vertex_limit_refusals"] += 1
                raise TangentError("TANGENT_VERTEX_LIMIT", "vertex count exceeds limit")

            topology = self._build_topology(mesh, channel, threshold)
            if topology.vertex_count > self.max_vertices:
                self._stats["vertex_limit_refusals"] += 1
                raise TangentError(
                    "TANGENT_VERTEX_LIMIT", "split vertex count exceeds limit"
                )

            old_vertex_count = len(mesh["positions"])
            if topology.vertex_count > old_vertex_count:
                sources = topology.sources
                mesh["positions"] = tuple(
                    mesh["positions"][source_index] for source_index in sources
                )
                if mesh["normals"] is not None:
                    mesh["normals"] = tuple(
                        mesh["normals"][source_index] for source_index in sources
                    )
                mesh["uvs"] = {
                    uv_channel: tuple(
                        channel_uvs[source_index] for source_index in sources
                    )
                    for uv_channel, channel_uvs in mesh["uvs"].items()
                }
                if (
                    mesh["material_groups"] is not None
                    and mesh["material_group_kind"] == "vertex"
                ):
                    mesh["material_groups"] = tuple(
                        mesh["material_groups"][source_index]
                        for source_index in sources
                    )
                mesh["indices"] = topology.indices

            for existing_state in mesh["split_maps"].values():
                existing_state["vertex_count"] = topology.vertex_count
            mesh["split_maps"][channel] = {
                "angle_threshold": threshold,
                "vertex_count": topology.vertex_count,
            }
            self._drop_mesh_cache_locked(mesh_id)
            return topology.vertex_count - old_vertex_count

    def validate(self, mesh_id: str) -> dict:
        with self._lock:
            mesh = self._get_mesh_locked(mesh_id)
            channel = 0 if 0 in mesh["uvs"] else min(mesh["uvs"])
            uvs = mesh["uvs"][channel]
            indices = mesh["indices"]

            degenerate = 0
            mirrored = 0
            for base in range(0, len(indices), 3):
                i0, i1, i2 = indices[base], indices[base + 1], indices[base + 2]
                uv0, uv1, uv2 = uvs[i0], uvs[i1], uvs[i2]
                du1 = uv1[0] - uv0[0]
                dv1 = uv1[1] - uv0[1]
                du2 = uv2[0] - uv0[0]
                dv2 = uv2[1] - uv0[1]
                determinant = du1 * dv2 - du2 * dv1
                if determinant == 0.0:
                    degenerate += 1
                elif determinant < 0.0:
                    mirrored += 1

            return {
                "valid": degenerate == 0,
                "vertex_count": len(mesh["positions"]),
                "triangle_count": len(indices) // 3,
                "degenerate_uv_triangles": degenerate,
                "mirrored_triangles": mirrored,
            }

    def cache_key(self, mesh_id: str, uv_channel: int = 0) -> str:
        with self._lock:
            mesh = self._get_mesh_locked(mesh_id)
            return self._cache_key_locked(
                mesh_id, int(mesh["version"]), uv_channel
            )

    def invalidate(self, mesh_id: str) -> int:
        with self._lock:
            self._get_mesh_locked(mesh_id)
            removed = self._drop_mesh_cache_locked(mesh_id)
            self._stats["invalidations"] += 1
            return removed

    def mesh_info(self, mesh_id: str) -> dict:
        with self._lock:
            mesh = self._get_mesh_locked(mesh_id)
            return {
                "mesh_id": mesh["mesh_id"],
                "version": int(mesh["version"]),
                "vertex_count": len(mesh["positions"]),
                "triangle_count": len(mesh["indices"]) // 3,
                "uv_channels": tuple(sorted(mesh["uvs"].keys())),
            }

    def set_max_vertices(self, limit: int) -> None:
        if not _is_positive_int(limit):
            raise _invalid("max_vertices must be a positive integer")
        with self._lock:
            self.max_vertices = limit

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(
                {
                    "schema": SNAPSHOT_SCHEMA,
                    "meshes": self._meshes,
                    "cache": self._cache,
                    "stats": self._stats,
                }
            )

    def restore(self, state: dict) -> None:
        try:
            frozen = copy.deepcopy(state)
        except Exception as exc:
            raise _snapshot_invalid("state could not be copied") from exc

        with self._lock:
            meshes, cache, stats = self._parse_snapshot(frozen)
            self._meshes = meshes
            self._cache = cache
            self._stats = stats
            self._stats["meshes"] = len(self._meshes)

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    @staticmethod
    def _cache_key_locked(mesh_id: str, version: int, uv_channel: object) -> str:
        return f"{mesh_id}:v{version}:uv{uv_channel}"

    def _get_mesh_locked(self, mesh_id: object) -> dict[str, Any]:
        mesh = self._meshes.get(mesh_id)  # type: ignore[arg-type]
        if mesh is None:
            raise _unknown(mesh_id)
        return mesh

    def _drop_mesh_cache_locked(self, mesh_id: str) -> int:
        stale = [
            key for key, entry in self._cache.items() if entry.get("mesh_id") == mesh_id
        ]
        for key in stale:
            del self._cache[key]
        return len(stale)

    def _cache_view(self, entry: dict[str, Any], *, cached: bool) -> dict:
        result = {key: value for key, value in entry.items() if key != "cached"}
        result["cached"] = cached
        return result

    def _build_topology(
        self,
        mesh: dict[str, Any],
        channel: int,
        angle_threshold: float = _DEFAULT_ANGLE_THRESHOLD,
    ) -> _Topology:
        positions = mesh["positions"]
        uvs = mesh["uvs"][channel]
        indices = mesh["indices"]
        normals = mesh["normals"]
        triangle_count = len(indices) // 3
        wedge_count = len(indices)

        sources = [0] * wedge_count
        wedge_triangle = [0] * wedge_count
        wedge_sign = [0] * wedge_count
        wedge_tangent: list[tuple[float, float, float] | None] = [
            None
        ] * wedge_count
        triangle_normals: list[tuple[float, float, float] | None] = []
        triangle_materials: list[object] = []

        for triangle_index in range(triangle_count):
            base = triangle_index * 3
            i0, i1, i2 = indices[base], indices[base + 1], indices[base + 2]
            sources[base] = i0
            sources[base + 1] = i1
            sources[base + 2] = i2
            wedge_triangle[base] = wedge_triangle[base + 1] = wedge_triangle[
                base + 2
            ] = triangle_index

            p0, p1, p2 = positions[i0], positions[i1], positions[i2]
            edge1 = _sub(p1, p0)
            edge2 = _sub(p2, p0)
            geometric_normal = _cross(edge1, edge2)
            triangle_normal = _normalized(geometric_normal)
            triangle_normals.append(triangle_normal)

            if (
                mesh["material_groups"] is not None
                and mesh["material_group_kind"] == "triangle"
            ):
                triangle_materials.append(mesh["material_groups"][triangle_index])
            else:
                triangle_materials.append(None)

            uv0, uv1, uv2 = uvs[i0], uvs[i1], uvs[i2]
            du1 = uv1[0] - uv0[0]
            dv1 = uv1[1] - uv0[1]
            du2 = uv2[0] - uv0[0]
            dv2 = uv2[1] - uv0[1]
            determinant = du1 * dv2 - du2 * dv1
            tangent = None
            bitangent = None
            if determinant != 0.0:
                inverse = 1.0 / determinant
                tangent = (
                    inverse * (dv2 * edge1[0] - dv1 * edge2[0]),
                    inverse * (dv2 * edge1[1] - dv1 * edge2[1]),
                    inverse * (dv2 * edge1[2] - dv1 * edge2[2]),
                )
                bitangent = (
                    inverse * (-du2 * edge1[0] + du1 * edge2[0]),
                    inverse * (-du2 * edge1[1] + du1 * edge2[1]),
                    inverse * (-du2 * edge1[2] + du1 * edge2[2]),
                )

            for corner, source_index in enumerate((i0, i1, i2)):
                wedge = base + corner
                reference_normal = None
                if normals is not None:
                    reference_normal = _normalized(normals[source_index])
                if reference_normal is None:
                    reference_normal = triangle_normal
                if reference_normal is None:
                    reference_normal = (0.0, 0.0, 1.0)

                if tangent is not None and bitangent is not None:
                    handedness = _dot(
                        _cross(bitangent, reference_normal), tangent
                    )
                    if handedness != 0.0:
                        wedge_sign[wedge] = 1 if handedness > 0.0 else -1
                    else:
                        wedge_sign[wedge] = 1 if determinant > 0.0 else -1
                    wedge_tangent[wedge] = _orthogonalize(
                        tangent, reference_normal
                    )

        parent = list(range(wedge_count))
        size = [1] * wedge_count
        root_sign = list(wedge_sign)

        def find(wedge: int) -> int:
            root = wedge
            while parent[root] != root:
                root = parent[root]
            while parent[wedge] != wedge:
                next_wedge = parent[wedge]
                parent[wedge] = root
                wedge = next_wedge
            return root

        def union(first: int, second: int) -> bool:
            root_first = find(first)
            root_second = find(second)
            if root_first == root_second:
                return True
            signs = {root_sign[root_first], root_sign[root_second]}
            signs.discard(0)
            if 1 in signs and -1 in signs:
                return False
            if size[root_first] < size[root_second]:
                root_first, root_second = root_second, root_first
            parent[root_second] = root_first
            size[root_first] += size[root_second]
            if 1 in signs:
                root_sign[root_first] = 1
            elif -1 in signs:
                root_sign[root_first] = -1
            else:
                root_sign[root_first] = 0
            return True

        cosine_limit = None
        if angle_threshold < 180.0:
            cosine_limit = math.cos(math.radians(angle_threshold))

        source_wedges: dict[int, list[int]] = {}
        for wedge, source_index in enumerate(sources):
            source_wedges.setdefault(source_index, []).append(wedge)

        for wedges in source_wedges.values():
            for left_position in range(len(wedges)):
                wedge_a = wedges[left_position]
                for right_position in range(left_position + 1, len(wedges)):
                    wedge_b = wedges[right_position]
                    tri_a = wedge_triangle[wedge_a]
                    tri_b = wedge_triangle[wedge_b]

                    if triangle_materials[tri_a] != triangle_materials[tri_b]:
                        continue

                    sign_a = wedge_sign[wedge_a]
                    sign_b = wedge_sign[wedge_b]
                    if sign_a and sign_b and sign_a != sign_b:
                        continue

                    if cosine_limit is not None:
                        normal_a = triangle_normals[tri_a]
                        normal_b = triangle_normals[tri_b]
                        if normal_a is not None and normal_b is not None:
                            normal_cosine = _dot(normal_a, normal_b)
                            if normal_cosine + 1e-12 < cosine_limit:
                                continue

                        tangent_a = wedge_tangent[wedge_a]
                        tangent_b = wedge_tangent[wedge_b]
                        if tangent_a is not None and tangent_b is not None:
                            tangent_cosine = _dot(tangent_a, tangent_b)
                            if tangent_cosine + 1e-12 < cosine_limit:
                                continue

                    union(wedge_a, wedge_b)

        root_to_output: dict[int, int] = {}
        remapped: list[int] = []
        primary_root_by_source: dict[int, int] = {}
        sources_output: list[int] = list(range(len(positions)))
        for wedge in range(wedge_count):
            root = find(wedge)
            output_index = root_to_output.get(root)
            if output_index is None:
                source_index = sources[wedge]
                if source_index not in primary_root_by_source:
                    primary_root_by_source[source_index] = root
                    output_index = source_index
                else:
                    output_index = len(sources_output)
                    sources_output.append(source_index)
                root_to_output[root] = output_index
            remapped.append(output_index)

        output_wedge_signs = [0] * len(sources_output)
        for wedge in range(wedge_count):
            output_index = remapped[wedge]
            sign = wedge_sign[wedge]
            if sign != 0:
                output_wedge_signs[output_index] = sign

        return _Topology(
            indices=tuple(remapped),
            sources=tuple(sources_output),
            wedge_signs=tuple(output_wedge_signs),
        )

    def _compute_entry(
        self,
        mesh: dict[str, Any],
        channel: int,
        key: str,
        topology: _Topology,
    ) -> dict[str, Any]:
        positions = mesh["positions"]
        uvs = mesh["uvs"][channel]
        indices = mesh["indices"]
        normals = mesh["normals"]
        triangle_count = len(indices) // 3
        output_count = topology.vertex_count

        tangent_sums = [[0.0, 0.0, 0.0] for _ in range(output_count)]
        bitangent_sums = [[0.0, 0.0, 0.0] for _ in range(output_count)]
        geometric_normal_sums = [[0.0, 0.0, 0.0] for _ in range(output_count)]

        for triangle_index in range(triangle_count):
            base = triangle_index * 3
            i0, i1, i2 = indices[base], indices[base + 1], indices[base + 2]
            o0 = topology.indices[base]
            o1 = topology.indices[base + 1]
            o2 = topology.indices[base + 2]

            p0, p1, p2 = positions[i0], positions[i1], positions[i2]
            edge1 = _sub(p1, p0)
            edge2 = _sub(p2, p0)
            geometric_normal = _cross(edge1, edge2)
            for output_index in (o0, o1, o2):
                _add_to(geometric_normal_sums[output_index], geometric_normal)

            uv0, uv1, uv2 = uvs[i0], uvs[i1], uvs[i2]
            du1 = uv1[0] - uv0[0]
            dv1 = uv1[1] - uv0[1]
            du2 = uv2[0] - uv0[0]
            dv2 = uv2[1] - uv0[1]
            determinant = du1 * dv2 - du2 * dv1
            if determinant == 0.0:
                continue

            inverse = 1.0 / determinant
            tangent = (
                inverse * (dv2 * edge1[0] - dv1 * edge2[0]),
                inverse * (dv2 * edge1[1] - dv1 * edge2[1]),
                inverse * (dv2 * edge1[2] - dv1 * edge2[2]),
            )
            bitangent = (
                inverse * (-du2 * edge1[0] + du1 * edge2[0]),
                inverse * (-du2 * edge1[1] + du1 * edge2[1]),
                inverse * (-du2 * edge1[2] + du1 * edge2[2]),
            )
            for output_index in (o0, o1, o2):
                _add_to(tangent_sums[output_index], tangent)
                _add_to(bitangent_sums[output_index], bitangent)

        tangents: list[tuple[float, float, float, float]] = []
        for output_index in range(output_count):
            source_index = topology.sources[output_index]
            normal = None
            if normals is not None:
                normal = _normalized(normals[source_index])
            if normal is None:
                normal = _normalized(tuple(geometric_normal_sums[output_index]))
            if normal is None:
                normal = (0.0, 0.0, 1.0)

            tangent_sum = tuple(tangent_sums[output_index])
            tangent = _orthogonalize(tangent_sum, normal)
            if tangent is None:
                bitangent_sum = tuple(bitangent_sums[output_index])
                bitangent_direction = _normalized(_cross(bitangent_sum, normal))
                expected_sign = topology.wedge_signs[output_index]
                if bitangent_direction is not None and expected_sign:
                    tangent = _scale(bitangent_direction, float(expected_sign))
                elif bitangent_direction is not None:
                    tangent = bitangent_direction
                else:
                    tangent = _fallback_tangent(normal)

            bitangent_sum = tuple(bitangent_sums[output_index])
            handedness = _dot(_cross(bitangent_sum, normal), tangent)
            handedness_sign = -1.0 if handedness < 0.0 else 1.0
            tangents.append((tangent[0], tangent[1], tangent[2], handedness_sign))

        return {
            "mesh_id": mesh["mesh_id"],
            "version": int(mesh["version"]),
            "uv_channel": channel,
            "tangents": tuple(tangents),
            "indices": tuple(topology.indices),
            "vertex_count": output_count,
            "triangle_count": triangle_count,
            "cache_key": key,
            "cached": False,
        }

    def _parse_snapshot(
        self, state: object
    ) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]], dict[str, int]]:
        if not isinstance(state, dict):
            raise _snapshot_invalid("state must be a dict")
        if set(state.keys()) != {"schema", "meshes", "cache", "stats"}:
            raise _snapshot_invalid("state has invalid top-level keys")
        if state.get("schema") != SNAPSHOT_SCHEMA:
            raise _snapshot_invalid("unsupported snapshot schema")

        raw_meshes = state.get("meshes")
        raw_cache = state.get("cache")
        raw_stats = state.get("stats")
        if not isinstance(raw_meshes, dict):
            raise _snapshot_invalid("meshes must be a dict")
        if not isinstance(raw_cache, dict):
            raise _snapshot_invalid("cache must be a dict")
        if not isinstance(raw_stats, dict):
            raise _snapshot_invalid("stats must be a dict")

        required_stats = set(self._stats.keys())
        if set(raw_stats.keys()) != required_stats:
            raise _snapshot_invalid("stats has invalid keys")
        stats: dict[str, int] = {}
        for key in required_stats:
            value = raw_stats.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise _snapshot_invalid(f"stats.{key} must be a non-negative integer")
            stats[key] = int(value)

        meshes: dict[str, dict[str, Any]] = {}
        for mesh_id, raw_mesh in raw_meshes.items():
            if not isinstance(mesh_id, str) or not mesh_id or not isinstance(raw_mesh, dict):
                raise _snapshot_invalid("invalid mesh entry")
            meshes[mesh_id] = self._parse_snapshot_mesh(mesh_id, raw_mesh)

        cache: dict[str, dict[str, Any]] = {}
        for cache_key, raw_entry in raw_cache.items():
            if not isinstance(cache_key, str) or not isinstance(raw_entry, dict):
                raise _snapshot_invalid("invalid cache entry")
            try:
                entry = self._parse_snapshot_cache_entry(cache_key, raw_entry, meshes)
            except TangentError as exc:
                if exc.code == "TANGENT_SNAPSHOT_INVALID":
                    raise
                raise _snapshot_invalid("invalid cache snapshot entry") from exc
            except Exception as exc:
                raise _snapshot_invalid("invalid cache snapshot entry") from exc
            cache[cache_key] = entry

        return meshes, cache, stats

    def _parse_snapshot_mesh(
        self, mesh_id: str, raw: dict[str, Any]
    ) -> dict[str, Any]:
        required = {
            "mesh_id",
            "version",
            "positions",
            "uvs",
            "indices",
            "normals",
            "material_groups",
            "material_group_kind",
            "split_maps",
        }
        if set(raw.keys()) != required:
            raise _snapshot_invalid(f"mesh {mesh_id} has invalid keys")
        if raw.get("mesh_id") != mesh_id or not _is_positive_int(raw.get("version")):
            raise _snapshot_invalid(f"mesh {mesh_id} identity/version is invalid")

        try:
            positions = _as_vector_tuple(raw.get("positions"), 3, "positions")
            if not positions:
                raise _snapshot_invalid("empty positions")
            uvs_raw = raw.get("uvs")
            if not isinstance(uvs_raw, dict) or not uvs_raw:
                raise _snapshot_invalid("uvs must be a non-empty dict")
            uvs: dict[int, tuple[tuple[float, ...], ...]] = {}
            for channel_raw, channel_uvs in uvs_raw.items():
                channel = _snapshot_channel_value(channel_raw)
                parsed_uvs = _as_vector_tuple(channel_uvs, 2, "uvs")
                if len(parsed_uvs) != len(positions):
                    raise _snapshot_invalid("uv count does not match positions")
                uvs[channel] = parsed_uvs
            indices = _as_index_tuple(raw.get("indices"), len(positions))

            normals = None
            if raw.get("normals") is not None:
                normals = _as_vector_tuple(raw.get("normals"), 3, "normals")
                if len(normals) != len(positions):
                    raise _snapshot_invalid("normal count does not match positions")

            material_groups = _as_group_tuple(raw.get("material_groups"))
            triangle_count = len(indices) // 3
            if material_groups is not None:
                if len(material_groups) == triangle_count:
                    group_kind = "triangle"
                elif len(material_groups) == len(positions):
                    group_kind = "vertex"
                else:
                    raise _snapshot_invalid("material_groups length is invalid")
            else:
                group_kind = None

            split_maps_raw = raw.get("split_maps")
            if not isinstance(split_maps_raw, dict):
                raise _snapshot_invalid("split_maps must be a dict")
            split_maps: dict[int, dict[str, Any]] = {}
            for channel_raw, split_state in split_maps_raw.items():
                channel = _snapshot_channel_value(channel_raw)
                if not isinstance(split_state, dict):
                    raise _snapshot_invalid("split state must be a dict")
                threshold = split_state.get("angle_threshold")
                total = split_state.get("vertex_count")
                if (
                    not isinstance(threshold, numbers.Real)
                    or isinstance(threshold, bool)
                    or not math.isfinite(float(threshold))
                    or float(threshold) < 0.0
                    or float(threshold) > 180.0
                    or not _is_positive_int(total)
                ):
                    raise _snapshot_invalid("invalid split state")
                split_maps[channel] = {
                    "angle_threshold": float(threshold),
                    "vertex_count": int(total),
                }
        except TangentError as exc:
            if exc.code == "TANGENT_SNAPSHOT_INVALID":
                raise
            raise _snapshot_invalid(str(exc.detail or exc.code)) from exc
        except Exception as exc:
            raise _snapshot_invalid("invalid mesh snapshot entry") from exc

        return {
            "mesh_id": mesh_id,
            "version": int(raw["version"]),
            "positions": positions,
            "uvs": uvs,
            "indices": indices,
            "normals": normals,
            "material_groups": material_groups,
            "material_group_kind": group_kind,
            "split_maps": split_maps,
        }

    def _parse_snapshot_cache_entry(
        self,
        key: str,
        raw: dict[str, Any],
        meshes: dict[str, dict[str, Any]],
    ) -> dict[str, Any]:
        required = {
            "mesh_id",
            "version",
            "uv_channel",
            "tangents",
            "indices",
            "vertex_count",
            "triangle_count",
            "cache_key",
            "cached",
        }
        if set(raw.keys()) != required:
            raise _snapshot_invalid(f"cache entry {key} has invalid keys")

        mesh_id = raw.get("mesh_id")
        mesh = meshes.get(mesh_id)  # type: ignore[arg-type]
        if mesh is None:
            raise _snapshot_invalid("cache entry references unknown mesh")
        if not _is_positive_int(raw.get("version")):
            raise _snapshot_invalid("cache entry version is invalid")
        if int(raw["version"]) != mesh["version"]:
            raise _snapshot_invalid("cache entry version does not match mesh")
        channel = _snapshot_channel_value(raw.get("uv_channel"))
        if channel not in mesh["uvs"]:
            raise _snapshot_invalid("cache entry references unknown uv channel")
        if raw.get("cache_key") != key:
            raise _snapshot_invalid("cache key does not match entry")
        expected_key = self._cache_key_locked(
            str(mesh_id), int(mesh["version"]), channel
        )
        if key != expected_key:
            raise _snapshot_invalid("cache key format is invalid")
        if not _is_positive_int(raw.get("vertex_count")):
            raise _snapshot_invalid("cache entry vertex_count is invalid")
        triangle_count = raw.get("triangle_count")
        if not _is_positive_int(triangle_count) and triangle_count != 0:
            raise _snapshot_invalid("cache entry triangle_count is invalid")

        vertex_count = int(raw["vertex_count"])
        parsed_triangle_count = int(triangle_count)
        if parsed_triangle_count != len(mesh["indices"]) // 3:
            raise _snapshot_invalid("cache entry triangle_count does not match mesh")

        try:
            tangents_value = raw.get("tangents")
            if tangents_value is None:
                raise _snapshot_invalid("cached tangents are missing")
            tangents_raw = tuple(tangents_value)
            indices = _as_index_tuple(raw.get("indices"), vertex_count)
        except TangentError as exc:
            if exc.code == "TANGENT_SNAPSHOT_INVALID":
                raise
            raise _snapshot_invalid("invalid cached tangents or indices") from exc
        except Exception as exc:
            raise _snapshot_invalid("invalid cached tangents or indices") from exc
        if len(indices) != parsed_triangle_count * 3:
            raise _snapshot_invalid("cached indices length is invalid")
        if len(tangents_raw) != vertex_count:
            raise _snapshot_invalid("cached tangent count is invalid")

        tangents: list[tuple[float, float, float, float]] = []
        for tangent in tangents_raw:
            try:
                components = tuple(tangent)
            except TypeError as exc:
                raise _snapshot_invalid("cached tangent is invalid") from exc
            if len(components) != 4:
                raise _snapshot_invalid(
                    "cached tangent must be a four-component tuple"
                )
            values: list[float] = []
            for component in components:
                if not isinstance(component, numbers.Real) or isinstance(
                    component, bool
                ):
                    raise _snapshot_invalid("cached tangent component is invalid")
                value = float(component)
                if not math.isfinite(value):
                    raise _snapshot_invalid("cached tangent component is not finite")
                values.append(value)
            tangents.append((values[0], values[1], values[2], values[3]))

        if not isinstance(raw.get("cached"), bool):
            raise _snapshot_invalid("cached flag must be boolean")

        return {
            "mesh_id": str(mesh_id),
            "version": int(raw["version"]),
            "uv_channel": channel,
            "tangents": tuple(tangents),
            "indices": indices,
            "vertex_count": vertex_count,
            "triangle_count": parsed_triangle_count,
            "cache_key": key,
            "cached": False,
        }
