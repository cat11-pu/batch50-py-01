"""Sparse voxel octree brick residency manager.

Keeps a CPU-side sparse octree per volume, moves node bricks into a byte-capped
pool on demand and folds homogeneous child sets back into their parent.  Nodes
carry a level, a morton key and a content version; the manager tracks request
references, upper-LOD references and structural revisions so streaming and
camera culling can share the same tree.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "SvoError",
    "VolumeView",
    "NodeView",
    "BrickUsage",
    "SvoResidencyManager",
]

MAX_LEVEL = 8


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


class SvoResidencyManager:
    """Track octree nodes and their bricks against a byte-capped pool."""

    def __init__(self, *, brick_pool_bytes: int = 1 << 20, brick_bytes: int = 4096,
                 max_depth: int = 6, max_nodes: int = 4096) -> None:
        self.brick_pool_bytes = brick_pool_bytes
        self.brick_bytes = brick_bytes
        self.max_depth = max_depth
        self.max_nodes = max_nodes
        self._lock = threading.RLock()

    def declare_volume(self, volume_id: str, *, depth: int = 5,
                       bytes_per_voxel: int = 1, root_morton: int = 0) -> VolumeView:
        """Declare a volume and materialize its root node without a brick."""
        raise NotImplementedError

    def volume_view(self, volume_id: str) -> VolumeView:
        """Return node and brick counters for one volume."""
        raise NotImplementedError

    def request_node(self, volume_id: str, morton: int, level: int,
                     *, ticket: object = None) -> NodeView:
        """Take one request reference on a node and make its brick resident."""
        raise NotImplementedError

    def release_node(self, volume_id: str, morton: int, level: int,
                     *, ticket: object = None) -> NodeView:
        """Drop one request reference from a node."""
        raise NotImplementedError

    def split_node(self, volume_id: str, morton: int, level: int) -> tuple[NodeView, ...]:
        """Expand a leaf into its eight children, indexed 0..7."""
        raise NotImplementedError

    def merge_node(self, volume_id: str, morton: int, level: int) -> NodeView:
        """Collapse eight homogeneous leaf children back into their parent."""
        raise NotImplementedError

    def tag_node(self, volume_id: str, morton: int, level: int,
                 content_version: int) -> NodeView:
        """Stamp a node with a new content version."""
        raise NotImplementedError

    def evict(self, volume_id: str, *, needed_bytes: int = 0) -> tuple[tuple[int, int], ...]:
        """Evict least recently used unreferenced bricks until the target is met."""
        raise NotImplementedError

    def brick_usage(self, volume_id: str | None = None) -> BrickUsage:
        """Return byte accounting for the whole pool or one volume."""
        raise NotImplementedError

    def resident_keys(self, volume_id: str) -> tuple[tuple[int, int], ...]:
        """Return resident bricks as ``(level, morton)`` pairs in sorted order."""
        raise NotImplementedError

    def node_state(self, volume_id: str, morton: int, level: int) -> NodeView:
        """Return the current node view."""
        raise NotImplementedError

    def attach_lod(self, volume_id: str, lod: int, morton: int, level: int) -> NodeView:
        """Register one upper-LOD reference on a node."""
        raise NotImplementedError

    def detach_lod(self, volume_id: str, lod: int, morton: int, level: int) -> NodeView:
        """Remove one upper-LOD reference from a node."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a deep copy of volumes and counters suitable for ``restore``."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace manager state with a snapshot, validating its structure."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative counters for requests, splits, merges and evictions."""
        raise NotImplementedError
