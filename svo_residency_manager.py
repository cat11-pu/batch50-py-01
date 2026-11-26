"""Sparse voxel octree brick residency manager."""

from __future__ import annotations

import copy
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Hashable

__all__ = [
    "SvoError",
    "VolumeView",
    "NodeView",
    "BrickUsage",
    "SvoResidencyManager",
]

MAX_LEVEL = 8
_SNAPSHOT_VERSION = "svo-residency-snapshot/1"
_STAT_KEYS = (
    "volumes",
    "requests",
    "releases",
    "splits",
    "merges",
    "evictions",
    "refusals",
)


class SvoError(ValueError):
    """Raised when a residency operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class VolumeView:
    """Immutable summary of one declared volume."""

    volume_id: str
    depth: int
    bytes_per_voxel: int
    root_morton: int
    node_count: int
    resident_bricks: int
    missing_bricks: int


@dataclass(frozen=True)
class NodeView:
    """Immutable view of a single octree node."""

    volume_id: str
    morton: int
    level: int
    is_leaf: bool
    refcount: int
    lod_refs: int
    content_version: int
    resident: bool
    rev: int


@dataclass(frozen=True)
class BrickUsage:
    """Brick pool accounting for the whole pool or a single volume."""

    used_bytes: int
    limit_bytes: int
    free_bytes: int
    resident_bricks: int
    missing_bricks: int


@dataclass
class _Node:
    morton: int
    level: int
    children: tuple[int, ...] | None = None
    refcount: int = 0
    lod_refs: int = 0
    lod_tokens: dict[Hashable, int] = field(default_factory=dict)
    content_version: int = 0
    rev: int = 0
    resident: bool = False


@dataclass
class _Volume:
    volume_id: str
    depth: int
    bytes_per_voxel: int
    root_morton: int
    nodes: dict[tuple[int, int], _Node]


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_int(value: object, name: str, minimum: int | None = None,
                 maximum: int | None = None) -> int:
    if not _is_int(value):
        raise SvoError("SVO_SNAPSHOT_INVALID", f"{name} must be an integer")
    assert isinstance(value, int)
    if minimum is not None and value < minimum:
        raise SvoError("SVO_SNAPSHOT_INVALID", f"{name} is below {minimum}")
    if maximum is not None and value > maximum:
        raise SvoError("SVO_SNAPSHOT_INVALID", f"{name} is above {maximum}")
    return value


class SvoResidencyManager:
    """Track octree nodes and their bricks against a byte-capped pool."""

    def __init__(self, *, brick_pool_bytes: int = 1 << 20, brick_bytes: int = 4096,
                 max_depth: int = 6, max_nodes: int = 4096,
                 depth: int | None = None) -> None:
        del depth
        if not _is_int(brick_pool_bytes) or brick_pool_bytes < 0:
            raise SvoError("SVO_INVALID_REQUEST", "brick_pool_bytes must be non-negative")
        if not _is_int(brick_bytes) or brick_bytes <= 0:
            raise SvoError("SVO_INVALID_REQUEST", "brick_bytes must be positive")
        if not _is_int(max_depth) or not 1 <= max_depth <= MAX_LEVEL:
            raise SvoError("SVO_INVALID_REQUEST", "max_depth is invalid")
        if not _is_int(max_nodes) or max_nodes <= 0:
            raise SvoError("SVO_INVALID_REQUEST", "max_nodes must be positive")

        self.brick_pool_bytes = brick_pool_bytes
        self.brick_bytes = brick_bytes
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self._lock = threading.RLock()
        self._volumes: dict[str, _Volume] = {}
        self._lru: OrderedDict[tuple[str, int, int], None] = OrderedDict()
        self._stats: dict[str, Any] = {key: 0 for key in _STAT_KEYS}

    def declare_volume(self, volume_id: str, *, depth: int = 5,
                       bytes_per_voxel: int = 1, root_morton: int = 0) -> VolumeView:
        """Declare a volume and materialize its root node without a brick."""
        with self._lock:
            self._require_volume_name(volume_id)
            if volume_id in self._volumes:
                self._refuse("SVO_VOLUME_EXISTS", {"volume_id": volume_id})
            if not _is_int(depth) or not 1 <= depth <= self.max_depth:
                self._refuse("SVO_INVALID_REQUEST", {"field": "depth", "value": depth})
            if not _is_int(bytes_per_voxel) or bytes_per_voxel <= 0:
                self._refuse("SVO_INVALID_REQUEST", {"field": "bytes_per_voxel"})
            if not _is_int(root_morton) or root_morton < 0:
                self._refuse("SVO_INVALID_REQUEST", {"field": "root_morton"})

            root = _Node(morton=root_morton, level=0)
            volume = _Volume(
                volume_id=volume_id,
                depth=depth,
                bytes_per_voxel=bytes_per_voxel,
                root_morton=root_morton,
                nodes={(0, root_morton): root},
            )
            self._volumes[volume_id] = volume
            self._stats["volumes"] = len(self._volumes)
            return self._volume_view(volume)

    def volume_view(self, volume_id: str) -> VolumeView:
        """Return node and brick counters for one volume."""
        with self._lock:
            volume = self._get_volume(volume_id, count_refusal=False)
            return self._volume_view(volume)

    def request_node(self, volume_id: str, morton: int, level: int,
                     *, ticket: object = None) -> NodeView:
        """Take one request reference on a node and make its brick resident."""
        del ticket
        with self._lock:
            volume, node = self._get_node(volume_id, morton, level)
            global_key = self._global_key(volume.volume_id, node)

            if node.resident and global_key in self._lru:
                self._lru.move_to_end(global_key)
            else:
                if node.resident:
                    node.resident = False
                    self._lru.pop(global_key, None)
                self._make_room_for_brick()
                node.resident = True
                self._lru[global_key] = None

            node.refcount += 1
            self._stats["requests"] += 1
            return self._node_view(volume, node)

    def release_node(self, volume_id: str, morton: int, level: int,
                     *, ticket: object = None) -> NodeView:
        """Drop one request reference from a node."""
        del ticket
        with self._lock:
            volume, node = self._get_node(volume_id, morton, level)
            if node.refcount == 0:
                self._refuse("SVO_REF_UNDERFLOW", {
                    "volume_id": volume_id,
                    "level": level,
                    "morton": morton,
                })

            node.refcount -= 1
            self._stats["releases"] += 1
            return self._node_view(volume, node)

    def split_node(self, volume_id: str, morton: int, level: int) -> tuple[NodeView, ...]:
        """Expand a leaf into its eight children, indexed 0..7."""
        with self._lock:
            volume, parent = self._get_node(volume_id, morton, level)
            if parent.level >= volume.depth:
                self._refuse("SVO_DEPTH_EXCEEDED", {
                    "level": parent.level,
                    "depth": volume.depth,
                })
            if parent.children is not None:
                self._refuse("SVO_ALREADY_SPLIT", self._node_key(parent))
            if len(volume.nodes) + 8 > self.max_nodes:
                self._refuse("SVO_NODE_BUDGET", {
                    "node_count": len(volume.nodes),
                    "max_nodes": self.max_nodes,
                })

            child_level = parent.level + 1
            base_morton = parent.morton * 8
            children = [
                _Node(morton=base_morton + index, level=child_level)
                for index in range(8)
            ]
            for child in children:
                if (child.level, child.morton) in volume.nodes:
                    self._refuse("SVO_ALREADY_SPLIT", self._node_key(child))

            for child in children:
                volume.nodes[(child.level, child.morton)] = child
            parent.children = tuple(child.morton for child in children)
            parent.rev += 1
            self._stats["splits"] += 1
            return tuple(self._node_view(volume, child) for child in children)

    def merge_node(self, volume_id: str, morton: int, level: int) -> NodeView:
        """Collapse eight homogeneous leaf children back into their parent."""
        with self._lock:
            volume, parent = self._get_node(volume_id, morton, level)
            child_level = parent.level + 1
            base_morton = parent.morton * 8
            children: list[_Node] = []

            for index in range(8):
                key = (child_level, base_morton + index)
                child = volume.nodes.get(key)
                if child is None:
                    self._refuse("SVO_NOT_MERGEABLE", {"missing": key})
                assert child is not None
                if child.children is not None or child.refcount != 0 or child.lod_refs != 0:
                    self._refuse("SVO_NOT_MERGEABLE", self._node_key(child))
                children.append(child)

            versions = [child.content_version for child in children]
            if not self._versions_mergeable(versions):
                self._refuse("SVO_NOT_MERGEABLE", {"content_versions": versions})

            for child in children:
                global_key = self._global_key(volume.volume_id, child)
                self._lru.pop(global_key, None)
                child.resident = False
                volume.nodes.pop((child.level, child.morton), None)

            parent.children = None
            parent.content_version = max(versions)
            parent.rev += 1
            self._stats["merges"] += 1
            return self._node_view(volume, parent)

    def tag_node(self, volume_id: str, morton: int, level: int,
                 content_version: int) -> NodeView:
        """Stamp a node with a new content version."""
        with self._lock:
            volume, node = self._get_node(volume_id, morton, level)
            if not _is_int(content_version):
                self._refuse("SVO_INVALID_REQUEST", {"field": "content_version"})
            node.content_version = content_version
            return self._node_view(volume, node)

    def evict(self, volume_id: str, *, needed_bytes: int = 0) -> tuple[tuple[int, int], ...]:
        """Evict least recently used unreferenced bricks until the target is met."""
        with self._lock:
            self._get_volume(volume_id)
            if not _is_int(needed_bytes) or needed_bytes < 0:
                self._refuse("SVO_INVALID_REQUEST", {"needed_bytes": needed_bytes})

            candidates = self._eviction_candidates(
                needed_bytes=needed_bytes,
                volume_id=volume_id,
            )
            if needed_bytes > 0 and candidates is None:
                self._refuse("SVO_POOL_EXHAUSTED", {
                    "volume_id": volume_id,
                    "needed_bytes": needed_bytes,
                })
            assert candidates is not None

            evicted: list[tuple[int, int]] = []
            for global_key, node in candidates:
                self._lru.pop(global_key, None)
                node.resident = False
                evicted.append((node.level, node.morton))

            self._stats["evictions"] += len(evicted)
            return tuple(evicted)

    def brick_usage(self, volume_id: str | None = None) -> BrickUsage:
        """Return byte accounting for the whole pool or one volume."""
        with self._lock:
            if volume_id is None:
                resident_bricks = self._resident_brick_count()
                missing_bricks = sum(
                    self._missing_brick_count(volume)
                    for volume in self._volumes.values()
                )
            else:
                volume = self._get_volume(volume_id, count_refusal=False)
                resident_bricks = sum(
                    1 for node in volume.nodes.values() if node.resident
                )
                missing_bricks = self._missing_brick_count(volume)

            used_bytes = resident_bricks * self.brick_bytes
            return BrickUsage(
                used_bytes=used_bytes,
                limit_bytes=self.brick_pool_bytes,
                free_bytes=self.brick_pool_bytes - used_bytes,
                resident_bricks=resident_bricks,
                missing_bricks=missing_bricks,
            )

    def resident_keys(self, volume_id: str) -> tuple[tuple[int, int], ...]:
        """Return resident bricks as ``(level, morton)`` pairs in sorted order."""
        with self._lock:
            volume = self._get_volume(volume_id, count_refusal=False)
            return tuple(sorted(
                (node.level, node.morton)
                for node in volume.nodes.values()
                if node.resident
            ))

    def node_state(self, volume_id: str, morton: int, level: int) -> NodeView:
        """Return the current node view."""
        with self._lock:
            volume, node = self._get_node(
                volume_id, morton, level, count_refusal=False
            )
            return self._node_view(volume, node)

    def attach_lod(self, volume_id: str, lod: int, morton: int, level: int) -> NodeView:
        """Register one upper-LOD reference on a node."""
        with self._lock:
            volume, node = self._get_node(volume_id, morton, level)
            try:
                hash(lod)
            except TypeError:
                self._refuse("SVO_INVALID_REQUEST", {"lod": lod})
            node.lod_tokens[lod] = node.lod_tokens.get(lod, 0) + 1
            node.lod_refs += 1
            return self._node_view(volume, node)

    def detach_lod(self, volume_id: str, lod: int, morton: int, level: int) -> NodeView:
        """Remove one upper-LOD reference from a node."""
        with self._lock:
            volume, node = self._get_node(volume_id, morton, level)
            count = node.lod_tokens.get(lod, 0)
            if node.lod_refs == 0 or count == 0:
                self._refuse("SVO_INVALID_REQUEST", {"lod": lod})

            if count == 1:
                node.lod_tokens.pop(lod, None)
            else:
                node.lod_tokens[lod] = count - 1
            node.lod_refs -= 1
            return self._node_view(volume, node)

    def snapshot(self) -> dict:
        """Return a deep copy of volumes and counters suitable for ``restore``."""
        with self._lock:
            return copy.deepcopy(self._snapshot_locked())

    def restore(self, state: dict) -> None:
        """Replace manager state with a snapshot, validating its structure."""
        with self._lock:
            try:
                restored = self._parse_snapshot(state)
            except SvoError:
                raise
            except Exception as exc:
                raise SvoError("SVO_SNAPSHOT_INVALID", str(exc)) from exc

            self.brick_pool_bytes = restored["config"]["brick_pool_bytes"]
            self.brick_bytes = restored["config"]["brick_bytes"]
            self.max_depth = restored["config"]["max_depth"]
            self.max_nodes = restored["config"]["max_nodes"]
            self._volumes = restored["volumes"]
            self._lru = restored["lru"]
            self._stats = restored["stats"]

    def stats(self) -> dict:
        """Return cumulative counters for requests, splits, merges and evictions."""
        with self._lock:
            return copy.deepcopy(self._stats)

    def _require_volume_name(self, volume_id: object, *,
                             count_refusal: bool = True) -> None:
        if not isinstance(volume_id, str) or not volume_id.strip():
            detail = {"field": "volume_id"}
            if count_refusal:
                self._refuse("SVO_INVALID_REQUEST", detail)
            raise SvoError("SVO_INVALID_REQUEST", detail)

    def _get_volume(self, volume_id: object, *,
                    count_refusal: bool = True) -> _Volume:
        self._require_volume_name(volume_id, count_refusal=count_refusal)
        assert isinstance(volume_id, str)
        volume = self._volumes.get(volume_id)
        if volume is None:
            detail = {"volume_id": volume_id}
            if count_refusal:
                self._refuse("SVO_UNKNOWN_VOLUME", detail)
            raise SvoError("SVO_UNKNOWN_VOLUME", detail)
        assert volume is not None
        return volume

    def _get_node(self, volume_id: object, morton: object,
                  level: object, *, count_refusal: bool = True) -> tuple[_Volume, _Node]:
        volume = self._get_volume(volume_id, count_refusal=count_refusal)
        if not _is_int(level) or level < 0 or level > MAX_LEVEL:
            detail = {"field": "level", "value": level}
            if count_refusal:
                self._refuse("SVO_INVALID_REQUEST", detail)
            raise SvoError("SVO_INVALID_REQUEST", detail)
        if not _is_int(morton) or morton < 0:
            detail = {"field": "morton", "value": morton}
            if count_refusal:
                self._refuse("SVO_INVALID_REQUEST", detail)
            raise SvoError("SVO_INVALID_REQUEST", detail)
        assert _is_int(level) and _is_int(morton)

        node = volume.nodes.get((level, morton))
        if node is None:
            detail = {
                "volume_id": volume.volume_id,
                "level": level,
                "morton": morton,
            }
            if count_refusal:
                self._refuse("SVO_UNKNOWN_NODE", detail)
            raise SvoError("SVO_UNKNOWN_NODE", detail)
        assert node is not None
        return volume, node

    def _refuse(self, code: str, detail: object = None) -> None:
        self._stats["refusals"] += 1
        raise SvoError(code, detail)

    @staticmethod
    def _node_key(node: _Node) -> dict[str, int]:
        return {"level": node.level, "morton": node.morton}

    @staticmethod
    def _global_key(volume_id: str, node: _Node) -> tuple[str, int, int]:
        return volume_id, node.level, node.morton

    @staticmethod
    def _versions_mergeable(versions: list[int]) -> bool:
        return len(set(versions)) == 1 or all(version != 0 for version in versions)

    @staticmethod
    def _node_view(volume: _Volume, node: _Node) -> NodeView:
        return NodeView(
            volume_id=volume.volume_id,
            morton=node.morton,
            level=node.level,
            is_leaf=node.children is None,
            refcount=node.refcount,
            lod_refs=node.lod_refs,
            content_version=node.content_version,
            resident=node.resident,
            rev=node.rev,
        )

    def _volume_view(self, volume: _Volume) -> VolumeView:
        resident = sum(1 for node in volume.nodes.values() if node.resident)
        return VolumeView(
            volume_id=volume.volume_id,
            depth=volume.depth,
            bytes_per_voxel=volume.bytes_per_voxel,
            root_morton=volume.root_morton,
            node_count=len(volume.nodes),
            resident_bricks=resident,
            missing_bricks=len(volume.nodes) - resident,
        )

    @staticmethod
    def _missing_brick_count(volume: _Volume) -> int:
        resident = sum(1 for node in volume.nodes.values() if node.resident)
        return len(volume.nodes) - resident

    def _resident_brick_count(self) -> int:
        return sum(
            1
            for volume in self._volumes.values()
            for node in volume.nodes.values()
            if node.resident
        )

    def _make_room_for_brick(self) -> None:
        used_bytes = len(self._lru) * self.brick_bytes
        free_bytes = self.brick_pool_bytes - used_bytes
        if free_bytes >= self.brick_bytes:
            return

        deficit = self.brick_bytes - free_bytes
        candidates = self._eviction_candidates(needed_bytes=deficit)
        if candidates is None:
            self._refuse("SVO_POOL_EXHAUSTED", {
                "used_bytes": used_bytes,
                "limit_bytes": self.brick_pool_bytes,
                "brick_bytes": self.brick_bytes,
            })
        assert candidates is not None

        for global_key, node in candidates:
            self._lru.pop(global_key, None)
            node.resident = False

        self._stats["evictions"] += len(candidates)

    def _eviction_candidates(
        self, *, needed_bytes: int, volume_id: str | None = None
    ) -> list[tuple[tuple[str, int, int], _Node]] | None:
        candidates: list[tuple[tuple[str, int, int], _Node]] = []
        reclaimable_bytes = 0

        for global_key in self._lru:
            candidate_volume_id, _, _ = global_key
            if volume_id is not None and candidate_volume_id != volume_id:
                continue
            volume = self._volumes.get(candidate_volume_id)
            if volume is None:
                continue
            _, level, morton = global_key
            node = volume.nodes.get((level, morton))
            if node is None or node.refcount != 0:
                continue

            candidates.append((global_key, node))
            reclaimable_bytes += self.brick_bytes
            if needed_bytes > 0 and reclaimable_bytes >= needed_bytes:
                return candidates

        if needed_bytes > 0 and reclaimable_bytes < needed_bytes:
            return None
        return candidates

    def _snapshot_locked(self) -> dict[str, Any]:
        volumes: dict[str, Any] = {}
        for volume_id, volume in self._volumes.items():
            nodes = []
            for level, morton in sorted(volume.nodes):
                node = volume.nodes[(level, morton)]
                nodes.append({
                    "morton": node.morton,
                    "level": node.level,
                    "is_leaf": node.children is None,
                    "children": list(node.children) if node.children is not None else None,
                    "refcount": node.refcount,
                    "lod_refs": node.lod_refs,
                    "lod_tokens": [
                        [lod, count] for lod, count in node.lod_tokens.items()
                    ],
                    "content_version": node.content_version,
                    "rev": node.rev,
                    "resident": node.resident,
                })

            volumes[volume_id] = {
                "volume_id": volume.volume_id,
                "depth": volume.depth,
                "bytes_per_voxel": volume.bytes_per_voxel,
                "root_morton": volume.root_morton,
                "nodes": nodes,
            }

        return {
            "format": _SNAPSHOT_VERSION,
            "config": {
                "brick_pool_bytes": self.brick_pool_bytes,
                "brick_bytes": self.brick_bytes,
                "max_depth": self.max_depth,
                "max_nodes": self.max_nodes,
            },
            "volumes": volumes,
            "lru": [list(key) for key in self._lru],
            "stats": copy.deepcopy(self._stats),
        }

    def _parse_snapshot(self, state: object) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise SvoError("SVO_SNAPSHOT_INVALID", "snapshot must be a mapping")

        volumes_raw = state.get("volumes")
        stats_raw = state.get("stats")
        if not isinstance(volumes_raw, dict) or not isinstance(stats_raw, dict):
            raise SvoError("SVO_SNAPSHOT_INVALID", "volumes and stats must be mappings")

        config = self._parse_snapshot_config(state.get("config"))
        stats = self._parse_snapshot_stats(stats_raw)
        volumes: dict[str, _Volume] = {}
        resident_global_keys: set[tuple[str, int, int]] = set()

        for raw_volume_id, raw_volume in volumes_raw.items():
            if not isinstance(raw_volume_id, str) or not raw_volume_id.strip():
                raise SvoError("SVO_SNAPSHOT_INVALID", "invalid volume id")
            if not isinstance(raw_volume, dict):
                raise SvoError("SVO_SNAPSHOT_INVALID", f"volume {raw_volume_id} is invalid")
            if "volume_id" in raw_volume and raw_volume["volume_id"] != raw_volume_id:
                raise SvoError("SVO_SNAPSHOT_INVALID", "volume id mismatch")

            depth = _require_int(raw_volume.get("depth"), "depth", 1, config["max_depth"])
            bytes_per_voxel = _require_int(
                raw_volume.get("bytes_per_voxel"), "bytes_per_voxel", 1
            )
            root_morton = _require_int(raw_volume.get("root_morton"), "root_morton", 0)
            nodes_raw = raw_volume.get("nodes")
            if not isinstance(nodes_raw, list):
                raise SvoError("SVO_SNAPSHOT_INVALID", "nodes must be a list")

            volume = _Volume(
                volume_id=raw_volume_id,
                depth=depth,
                bytes_per_voxel=bytes_per_voxel,
                root_morton=root_morton,
                nodes={},
            )

            for raw_node in nodes_raw:
                node = self._parse_snapshot_node(raw_node)
                key = (node.level, node.morton)
                if key in volume.nodes:
                    raise SvoError("SVO_SNAPSHOT_INVALID", "duplicate node key")
                volume.nodes[key] = node
                if node.resident:
                    resident_global_keys.add((raw_volume_id, node.level, node.morton))

            self._validate_snapshot_tree(volume, config["max_nodes"])
            volumes[raw_volume_id] = volume

        lru = self._parse_snapshot_lru(state.get("lru"), volumes, resident_global_keys)
        if len(lru) * config["brick_bytes"] > config["brick_pool_bytes"]:
            raise SvoError("SVO_SNAPSHOT_INVALID", "resident bricks exceed pool bytes")

        stats["volumes"] = len(volumes)
        return {"config": config, "volumes": volumes, "lru": lru, "stats": stats}

    def _parse_snapshot_config(self, raw_config: object) -> dict[str, int]:
        config = {
            "brick_pool_bytes": self.brick_pool_bytes,
            "brick_bytes": self.brick_bytes,
            "max_depth": self.max_depth,
            "max_nodes": self.max_nodes,
        }
        if raw_config is None:
            return config
        if not isinstance(raw_config, dict):
            raise SvoError("SVO_SNAPSHOT_INVALID", "config must be a mapping")

        if "brick_pool_bytes" in raw_config:
            config["brick_pool_bytes"] = _require_int(
                raw_config["brick_pool_bytes"], "brick_pool_bytes", 0
            )
        if "brick_bytes" in raw_config:
            config["brick_bytes"] = _require_int(
                raw_config["brick_bytes"], "brick_bytes", 1
            )
        if "max_depth" in raw_config:
            config["max_depth"] = _require_int(
                raw_config["max_depth"], "max_depth", 1, MAX_LEVEL
            )
        if "max_nodes" in raw_config:
            config["max_nodes"] = _require_int(
                raw_config["max_nodes"], "max_nodes", 1
            )
        return config

    @staticmethod
    def _parse_snapshot_stats(raw_stats: dict) -> dict[str, Any]:
        for key in _STAT_KEYS:
            if key not in raw_stats:
                raise SvoError("SVO_SNAPSHOT_INVALID", f"missing stat {key}")
            value = raw_stats[key]
            if not _is_int(value) or value < 0:
                raise SvoError("SVO_SNAPSHOT_INVALID", f"invalid stat {key}")
        return copy.deepcopy(dict(raw_stats))

    @staticmethod
    def _parse_snapshot_node(raw_node: object) -> _Node:
        if not isinstance(raw_node, dict):
            raise SvoError("SVO_SNAPSHOT_INVALID", "node must be a mapping")

        morton = _require_int(raw_node.get("morton"), "morton", 0)
        level = _require_int(raw_node.get("level"), "level", 0, MAX_LEVEL)
        refcount = _require_int(raw_node.get("refcount", 0), "refcount", 0)
        lod_refs = _require_int(raw_node.get("lod_refs", 0), "lod_refs", 0)
        content_version = _require_int(raw_node.get("content_version", 0), "content_version")
        rev = _require_int(raw_node.get("rev", 0), "rev", 0)
        resident = raw_node.get("resident", False)
        if not isinstance(resident, bool):
            raise SvoError("SVO_SNAPSHOT_INVALID", "resident must be a boolean")

        is_leaf = raw_node.get("is_leaf")
        children_raw = raw_node.get("children")
        if is_leaf is None:
            is_leaf = children_raw is None
        if not isinstance(is_leaf, bool):
            raise SvoError("SVO_SNAPSHOT_INVALID", "is_leaf must be a boolean")
        if is_leaf and children_raw not in (None, []):
            raise SvoError("SVO_SNAPSHOT_INVALID", "leaf cannot have children")
        if not is_leaf:
            if not isinstance(children_raw, (list, tuple)) or len(children_raw) != 8:
                raise SvoError("SVO_SNAPSHOT_INVALID", "non-leaf needs eight children")
            children = tuple(_require_int(value, "child morton", 0) for value in children_raw)
            expected = tuple(morton * 8 + index for index in range(8))
            if children != expected:
                raise SvoError("SVO_SNAPSHOT_INVALID", "invalid child mortons")
        else:
            children = None

        lod_tokens: dict[Hashable, int] = {}
        tokens_raw = raw_node.get("lod_tokens", [])
        if isinstance(tokens_raw, dict):
            token_items = list(tokens_raw.items())
        elif isinstance(tokens_raw, (list, tuple)):
            token_items = []
            for item in tokens_raw:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    raise SvoError("SVO_SNAPSHOT_INVALID", "invalid LOD token")
                token_items.append((item[0], item[1]))
        else:
            raise SvoError("SVO_SNAPSHOT_INVALID", "invalid lod_tokens")

        token_total = 0
        for lod, count_raw in token_items:
            count = _require_int(count_raw, "lod token count", 1)
            lod_tokens[lod] = lod_tokens.get(lod, 0) + count
            token_total += count
        if token_total != lod_refs:
            raise SvoError("SVO_SNAPSHOT_INVALID", "lod_refs does not match tokens")

        return _Node(
            morton=morton,
            level=level,
            children=children,
            refcount=refcount,
            lod_refs=lod_refs,
            lod_tokens=lod_tokens,
            content_version=content_version,
            rev=rev,
            resident=resident,
        )

    @staticmethod
    def _validate_snapshot_tree(volume: _Volume, max_nodes: int) -> None:
        if len(volume.nodes) > max_nodes:
            raise SvoError("SVO_SNAPSHOT_INVALID", "node budget exceeded")
        if (0, volume.root_morton) not in volume.nodes:
            raise SvoError("SVO_SNAPSHOT_INVALID", "root node is missing")

        for level, morton in volume.nodes:
            if level > volume.depth:
                raise SvoError("SVO_SNAPSHOT_INVALID", "node exceeds volume depth")
            if level == 0 and morton != volume.root_morton:
                raise SvoError("SVO_SNAPSHOT_INVALID", "unexpected level-zero node")

        for (level, morton), node in volume.nodes.items():
            if level > 0:
                parent = volume.nodes.get((level - 1, morton // 8))
                if parent is None or parent.children is None:
                    raise SvoError("SVO_SNAPSHOT_INVALID", "orphan node")
                if morton != parent.morton * 8 + (morton % 8):
                    raise SvoError("SVO_SNAPSHOT_INVALID", "invalid morton lineage")

            if node.children is not None:
                if level >= volume.depth:
                    raise SvoError("SVO_SNAPSHOT_INVALID", "split node at volume depth")
                for index in range(8):
                    child_key = (level + 1, morton * 8 + index)
                    if child_key not in volume.nodes:
                        raise SvoError("SVO_SNAPSHOT_INVALID", "incomplete child set")

    @staticmethod
    def _parse_snapshot_lru(
        raw_lru: object,
        volumes: dict[str, _Volume],
        resident_keys: set[tuple[str, int, int]],
    ) -> OrderedDict[tuple[str, int, int], None]:
        lru: OrderedDict[tuple[str, int, int], None] = OrderedDict()
        if raw_lru is None:
            for global_key in sorted(resident_keys):
                lru[global_key] = None
            return lru
        if not isinstance(raw_lru, (list, tuple)):
            raise SvoError("SVO_SNAPSHOT_INVALID", "lru must be a list")

        seen: set[tuple[str, int, int]] = set()
        for item in raw_lru:
            if not isinstance(item, (list, tuple)) or len(item) != 3:
                raise SvoError("SVO_SNAPSHOT_INVALID", "invalid lru key")
            volume_id, level, morton = item
            if not isinstance(volume_id, str):
                raise SvoError("SVO_SNAPSHOT_INVALID", "invalid lru volume")
            if not _is_int(level) or not _is_int(morton):
                raise SvoError("SVO_SNAPSHOT_INVALID", "invalid lru coordinates")
            volume = volumes.get(volume_id)
            if volume is None or (level, morton) not in volume.nodes:
                raise SvoError("SVO_SNAPSHOT_INVALID", "lru references unknown node")
            node = volume.nodes[(level, morton)]
            if not node.resident:
                raise SvoError("SVO_SNAPSHOT_INVALID", "lru node is not resident")
            global_key = (volume_id, level, morton)
            if global_key in seen:
                raise SvoError("SVO_SNAPSHOT_INVALID", "duplicate lru key")
            seen.add(global_key)
            lru[global_key] = None

        if seen != resident_keys:
            raise SvoError("SVO_SNAPSHOT_INVALID", "lru does not match resident bricks")
        return lru
