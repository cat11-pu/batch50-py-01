"""Fog of war explorer: per-team visibility counts, permanent exploration, snapshots."""

from __future__ import annotations

import threading


class FogError(ValueError):
    """Raised when a fog operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class FogOfWarExplorer:
    """Track viewer vision over a grid per team, keeping permanent exploration."""

    def __init__(self, *, width: int = 32, height: int = 32, max_radius: int = 6,
                 default_radius: int = 2, max_viewers: int = 64) -> None:
        self.width = width
        self.height = height
        self.max_radius = max_radius
        self.default_radius = default_radius
        self.max_viewers = max_viewers
        self._lock = threading.RLock()

    def add_viewer(self, viewer_id: str, team: str, x: int, y: int,
                   radius=None) -> dict:
        raise NotImplementedError

    def move_viewer(self, viewer_id: str, x: int, y: int) -> dict:
        raise NotImplementedError

    def remove_viewer(self, viewer_id: str) -> dict:
        raise NotImplementedError

    def reveal_circle(self, team: str, x: int, y: int, radius: int) -> int:
        raise NotImplementedError

    def visibility_at(self, team: str, x: int, y: int) -> str:
        raise NotImplementedError

    def cell_info(self, team: str, x: int, y: int) -> dict:
        raise NotImplementedError

    def visible_cells(self, team: str) -> list:
        raise NotImplementedError

    def explored_cells(self, team: str) -> list:
        raise NotImplementedError

    def viewer_stats(self, viewer_id: str) -> dict:
        raise NotImplementedError

    def team_snapshot(self, team: str) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
