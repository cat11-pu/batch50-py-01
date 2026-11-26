"""Tangent frame builder: reconstruct per-vertex tangents from UV derivatives."""

from __future__ import annotations

import threading

__all__ = [
    "TangentError",
    "TangentFrameBuilder",
    "DEFAULT_MAX_VERTICES",
]

DEFAULT_MAX_VERTICES = 4096


class TangentError(ValueError):
    """Raised when a tangent frame request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class TangentFrameBuilder:
    """Build and cache per-vertex tangent frames for registered meshes."""

    def __init__(self, *, max_vertices: int = DEFAULT_MAX_VERTICES) -> None:
        self.max_vertices = max_vertices
        self._lock = threading.RLock()

    def register_mesh(self, mesh_id: str, *, positions, uvs, indices,
                      normals=None, uv_channel: int = 0,
                      material_groups=None) -> int:
        raise NotImplementedError

    def set_uv_channel(self, mesh_id: str, channel: int, uvs) -> int:
        raise NotImplementedError

    def build_frames(self, mesh_id: str, *, uv_channel: int = 0) -> dict:
        raise NotImplementedError

    def split_vertices(self, mesh_id: str, *, uv_channel: int = 0,
                       angle_threshold: float = 60.0) -> int:
        raise NotImplementedError

    def validate(self, mesh_id: str) -> dict:
        raise NotImplementedError

    def cache_key(self, mesh_id: str, uv_channel: int = 0) -> str:
        raise NotImplementedError

    def invalidate(self, mesh_id: str) -> int:
        raise NotImplementedError

    def mesh_info(self, mesh_id: str) -> dict:
        raise NotImplementedError

    def set_max_vertices(self, limit: int) -> None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
