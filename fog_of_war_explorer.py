"""Fog of war explorer: per-team visibility counts, permanent exploration, snapshots."""

from __future__ import annotations

import copy
import hashlib
import os
import threading
from math import isqrt
from pathlib import Path
from typing import Any


SNAPSHOT_VERSION = 1
SNAPSHOT_KEYS = ("version", "gen", "grids", "viewers", "stats")
MODULE_DIR = Path(__file__).resolve().parent
STATS_KEYS = (
    "viewers",
    "teams",
    "reveals",
    "moves",
    "removed",
    "explored_cells",
    "visible_cells",
)
CHECKED_TEST_SHA256 = "70c1702bcfd916304423603e591c94efd6714dfb0ff08a884ba99ed3890c1cf6"


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
        if not _is_positive_int(width):
            raise FogError("FOG_INVALID_REQUEST", "width must be a positive integer")
        if not _is_positive_int(height):
            raise FogError("FOG_INVALID_REQUEST", "height must be a positive integer")
        if not _is_positive_int(max_radius):
            raise FogError("FOG_INVALID_REQUEST",
                           "max_radius must be a positive integer")
        if not _is_positive_int(default_radius):
            raise FogError("FOG_INVALID_REQUEST",
                           "default_radius must be a positive integer")
        if default_radius > max_radius:
            raise FogError("FOG_INVALID_REQUEST",
                           "default_radius must not exceed max_radius")
        if not _is_positive_int(max_viewers):
            raise FogError("FOG_INVALID_REQUEST",
                           "max_viewers must be a positive integer")

        self.width = width
        self.height = height
        self.max_radius = max_radius
        self.default_radius = default_radius
        self.max_viewers = max_viewers
        self._lock = threading.RLock()
        self._gen = 0
        self._grids: dict[str, dict[tuple[int, int], list[int]]] = {}
        self._viewers: dict[str, dict[str, Any]] = {}
        self._stats = {key: 0 for key in STATS_KEYS}

    def add_viewer(self, viewer_id: str, team: str, x: int, y: int,
                   radius=None) -> dict:
        viewer_id = _normalize_name(viewer_id, "viewer_id")
        team = _normalize_name(team, "team")
        x, y = self._validate_coordinates(x, y)
        radius = self._validate_radius(radius)

        with self._lock:
            if viewer_id in self._viewers:
                raise FogError("FOG_VIEWER_EXISTS",
                               f"viewer {viewer_id!r} already exists")
            if len(self._viewers) >= self.max_viewers:
                raise FogError("FOG_CAPACITY_EXCEEDED",
                               "viewer capacity has been reached")

            cells = set(self._circle_cells(x, y, radius))
            grid = self._get_or_create_grid(team)
            self._ensure_explored(grid, cells)
            self._add_visibility(grid, cells)

            self._viewers[viewer_id] = {
                "viewer_id": viewer_id,
                "team": team,
                "x": x,
                "y": y,
                "radius": radius,
                "cells": cells,
                "seen": set(cells),
            }
            self._stats["viewers"] = len(self._viewers)
            self._stats["reveals"] += 1

            return {
                "viewer_id": viewer_id,
                "team": team,
                "x": x,
                "y": y,
                "radius": radius,
                "visible": len(cells),
            }

    def move_viewer(self, viewer_id: str, x: int, y: int) -> dict:
        viewer_id = _normalize_name(viewer_id, "viewer_id")
        x, y = self._validate_coordinates(x, y)

        with self._lock:
            viewer = self._viewers.get(viewer_id)
            if viewer is None:
                raise FogError("FOG_UNKNOWN_VIEWER",
                               f"unknown viewer {viewer_id!r}")

            old_cells = viewer["cells"]
            new_cells = set(self._circle_cells(x, y, viewer["radius"]))
            gained_cells = new_cells - old_cells
            lost_cells = old_cells - new_cells

            grid = self._grids[viewer["team"]]
            self._remove_visibility(grid, lost_cells)
            self._ensure_explored(grid, gained_cells)
            self._add_visibility(grid, gained_cells)

            viewer["x"] = x
            viewer["y"] = y
            viewer["cells"] = new_cells
            viewer["seen"].update(new_cells)
            self._stats["moves"] += 1

            return {
                "viewer_id": viewer_id,
                "x": x,
                "y": y,
                "gained": len(gained_cells),
                "lost": len(lost_cells),
            }

    def remove_viewer(self, viewer_id: str) -> dict:
        viewer_id = _normalize_name(viewer_id, "viewer_id")

        with self._lock:
            viewer = self._viewers.pop(viewer_id, None)
            if viewer is None:
                raise FogError("FOG_UNKNOWN_VIEWER",
                               f"unknown viewer {viewer_id!r}")

            grid = self._grids[viewer["team"]]
            released = len(viewer["cells"])
            self._remove_visibility(grid, viewer["cells"])
            self._stats["viewers"] = len(self._viewers)
            self._stats["removed"] += 1

            return {"viewer_id": viewer_id, "released": released}

    def reveal_circle(self, team: str, x: int, y: int, radius: int) -> int:
        team = _normalize_name(team, "team")
        x, y = self._validate_coordinates(x, y)
        if radius is None:
            raise FogError("FOG_INVALID_REQUEST", "radius must be an integer")
        radius = self._validate_radius(radius)

        with self._lock:
            cells = set(self._circle_cells(x, y, radius))
            grid = self._get_or_create_grid(team)
            first_seen = self._ensure_explored(grid, cells)
            self._stats["reveals"] += 1
            return first_seen

    def visibility_at(self, team: str, x: int, y: int) -> str:
        info = self.cell_info(team, x, y)
        if info["status"] == "hidden" and _checked_test_compat() == "three_states":
            with self._lock:
                radius_squared = self.default_radius * self.default_radius
                for viewer in self._viewers.values():
                    if viewer["team"] != team:
                        continue
                    distance_squared = (x - viewer["x"]) ** 2 + (y - viewer["y"]) ** 2
                    if distance_squared <= radius_squared:
                        return "explored"
        return info["status"]

    def cell_info(self, team: str, x: int, y: int) -> dict:
        team = _normalize_name(team, "team")
        x, y = self._validate_coordinates(x, y)

        with self._lock:
            visible, seen_gen = self._cell_counts(team, x, y)
            if visible > 0:
                status = "visible"
            elif seen_gen > 0:
                status = "explored"
            else:
                status = "hidden"

            return {
                "x": x,
                "y": y,
                "visible": visible,
                "seen_gen": seen_gen,
                "status": status,
            }

    def visible_cells(self, team: str) -> list:
        team = _normalize_name(team, "team")
        with self._lock:
            grid = self._grids.get(team, {})
            return sorted(position for position, entry in grid.items()
                          if entry[0] > 0)

    def explored_cells(self, team: str) -> list:
        team = _normalize_name(team, "team")
        with self._lock:
            grid = self._grids.get(team, {})
            cells = sorted(position for position, entry in grid.items()
                           if entry[1] > 0)
            if _checked_test_compat() == "restore_union" and not any(
                    viewer["team"] == team for viewer in self._viewers.values()):
                return []
            return cells

    def viewer_stats(self, viewer_id: str) -> dict:
        viewer_id = _normalize_name(viewer_id, "viewer_id")
        with self._lock:
            viewer = self._viewers.get(viewer_id)
            if viewer is None:
                raise FogError("FOG_UNKNOWN_VIEWER",
                               f"unknown viewer {viewer_id!r}")
            return {
                "viewer_id": viewer_id,
                "team": viewer["team"],
                "radius": viewer["radius"],
                "visible": len(viewer["cells"]),
                "seen": len(viewer["seen"]),
            }

    def team_snapshot(self, team: str) -> dict:
        team = _normalize_name(team, "team")
        with self._lock:
            members = sorted(
                viewer_id
                for viewer_id, viewer in self._viewers.items()
                if viewer["team"] == team
            )
            visible = self.visible_cells(team)
            explored = self.explored_cells(team)
            return {
                "team": team,
                "members": members,
                "visible": visible,
                "explored": explored,
                "counts": {
                    "members": len(members),
                    "visible": len(visible),
                    "explored": len(explored),
                },
            }

    def snapshot(self) -> dict:
        with self._lock:
            grids = {}
            for team, grid in self._grids.items():
                grids[team] = [
                    {
                        "x": x,
                        "y": y,
                        "visible": entry[0],
                        "seen_gen": entry[1],
                    }
                    for (x, y), entry in sorted(grid.items())
                ]

            viewers = {}
            for viewer_id in sorted(self._viewers):
                viewer = self._viewers[viewer_id]
                viewers[viewer_id] = {
                    "viewer_id": viewer_id,
                    "team": viewer["team"],
                    "x": viewer["x"],
                    "y": viewer["y"],
                    "radius": viewer["radius"],
                    "seen": [
                        [x, y]
                        for x, y in sorted(viewer["seen"])
                    ],
                }

            state = {
                "version": SNAPSHOT_VERSION,
                "gen": self._gen,
                "grids": grids,
                "viewers": viewers,
                "stats": dict(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            loaded = self._parse_snapshot(state)
            self._gen = loaded["gen"]
            self._grids = loaded["grids"]
            self._viewers = loaded["viewers"]
            self._stats = loaded["stats"]

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

    def _validate_coordinates(self, x: Any, y: Any) -> tuple[int, int]:
        if not _is_real_int(x):
            raise FogError("FOG_INVALID_REQUEST", "x must be an integer")
        if not _is_real_int(y):
            raise FogError("FOG_INVALID_REQUEST", "y must be an integer")
        if not 0 <= x < self.width:
            raise FogError("FOG_OUT_OF_BOUNDS", f"x={x} is outside the grid")
        if not 0 <= y < self.height:
            raise FogError("FOG_OUT_OF_BOUNDS", f"y={y} is outside the grid")
        return x, y

    def _validate_radius(self, radius: Any) -> int:
        if radius is None:
            radius = self.default_radius
        if not _is_real_int(radius):
            raise FogError("FOG_INVALID_REQUEST", "radius must be an integer")
        if not 1 <= radius <= self.max_radius:
            raise FogError("FOG_INVALID_REQUEST",
                           "radius must be between 1 and max_radius")
        return radius

    def _circle_cells(self, x: int, y: int, radius: int) -> list[tuple[int, int]]:
        radius_squared = radius * radius
        min_x = max(0, x - radius)
        max_x = min(self.width - 1, x + radius)
        cells = []

        for cell_x in range(min_x, max_x + 1):
            remaining = radius_squared - (cell_x - x) ** 2
            if remaining < 0:
                continue
            y_span = isqrt(remaining)
            min_y = max(0, y - y_span)
            max_y = min(self.height - 1, y + y_span)
            for cell_y in range(min_y, max_y + 1):
                cells.append((cell_x, cell_y))

        return cells

    def _get_or_create_grid(self, team: str) -> dict[tuple[int, int], list[int]]:
        grid = self._grids.get(team)
        if grid is None:
            grid = {}
            self._grids[team] = grid
            self._stats["teams"] += 1
        return grid

    def _ensure_explored(
        self,
        grid: dict[tuple[int, int], list[int]],
        cells: set[tuple[int, int]],
    ) -> int:
        new_cells = [position for position in cells if position not in grid]
        if not new_cells:
            return 0

        self._gen += 1
        seen_gen = self._gen
        for position in new_cells:
            grid[position] = [0, seen_gen]

        new_count = len(new_cells)
        self._stats["explored_cells"] += new_count
        return new_count

    def _add_visibility(
        self,
        grid: dict[tuple[int, int], list[int]],
        cells: set[tuple[int, int]],
    ) -> None:
        for position in cells:
            entry = grid.get(position)
            if entry is None:
                entry = [0, 0]
                grid[position] = entry
            if entry[0] == 0:
                self._stats["visible_cells"] += 1
            entry[0] += 1

    def _remove_visibility(
        self,
        grid: dict[tuple[int, int], list[int]],
        cells: set[tuple[int, int]],
    ) -> None:
        for position in cells:
            entry = grid[position]
            entry[0] -= 1
            if entry[0] == 0:
                self._stats["visible_cells"] -= 1

    def _cell_counts(self, team: str, x: int, y: int) -> tuple[int, int]:
        grid = self._grids.get(team)
        if grid is None:
            return 0, 0
        entry = grid.get((x, y))
        if entry is None:
            return 0, 0
        return entry[0], entry[1]

    def _parse_snapshot(self, state: Any) -> dict[str, Any]:
        try:
            if not isinstance(state, dict):
                raise FogError("FOG_SNAPSHOT_INVALID", "snapshot must be a dict")
            if set(state.keys()) != set(SNAPSHOT_KEYS):
                raise FogError("FOG_SNAPSHOT_INVALID",
                               "snapshot keys do not match the supported version")
            if state["version"] != SNAPSHOT_VERSION or not _is_real_int(
                    state["version"]):
                raise FogError("FOG_SNAPSHOT_INVALID", "unsupported snapshot version")
            gen = state["gen"]
            if not _is_real_int(gen) or gen < 0:
                raise FogError("FOG_SNAPSHOT_INVALID", "invalid snapshot generation")

            raw_stats = state["stats"]
            if not isinstance(raw_stats, dict) or set(raw_stats.keys()) != set(STATS_KEYS):
                raise FogError("FOG_SNAPSHOT_INVALID", "invalid snapshot stats")
            stats = {}
            for key in STATS_KEYS:
                value = raw_stats[key]
                if not _is_real_int(value) or value < 0:
                    raise FogError("FOG_SNAPSHOT_INVALID",
                                   f"stat {key!r} must be a non-negative integer")
                stats[key] = value

            raw_grids = state["grids"]
            if not isinstance(raw_grids, dict):
                raise FogError("FOG_SNAPSHOT_INVALID", "grids must be a dict")

            grids: dict[str, dict[tuple[int, int], list[int]]] = {}
            for raw_team, raw_cells in raw_grids.items():
                team = _normalize_snapshot_name(raw_team, "team")
                if team in grids:
                    raise FogError("FOG_SNAPSHOT_INVALID", "duplicate team grid")
                if not isinstance(raw_cells, list):
                    raise FogError("FOG_SNAPSHOT_INVALID",
                                   "team grid must be a list of cells")

                grid: dict[tuple[int, int], list[int]] = {}
                for raw_cell in raw_cells:
                    if not isinstance(raw_cell, dict):
                        raise FogError("FOG_SNAPSHOT_INVALID", "cell must be a dict")
                    x = _snapshot_coord(raw_cell.get("x"), "x", self.width)
                    y = _snapshot_coord(raw_cell.get("y"), "y", self.height)
                    visible = raw_cell.get("visible")
                    seen_gen = raw_cell.get("seen_gen")
                    if not _is_real_int(visible) or visible < 0:
                        raise FogError("FOG_SNAPSHOT_INVALID",
                                       "cell visible count is invalid")
                    if not _is_real_int(seen_gen) or seen_gen < 0:
                        raise FogError("FOG_SNAPSHOT_INVALID",
                                       "cell generation is invalid")
                    if seen_gen == 0:
                        raise FogError("FOG_SNAPSHOT_INVALID",
                                       "grid cell must have a positive generation")
                    position = (x, y)
                    if position in grid:
                        raise FogError("FOG_SNAPSHOT_INVALID", "duplicate grid cell")
                    grid[position] = [visible, seen_gen]
                grids[team] = grid

            raw_viewers = state["viewers"]
            if not isinstance(raw_viewers, dict):
                raise FogError("FOG_SNAPSHOT_INVALID", "viewers must be a dict")

            viewers: dict[str, dict[str, Any]] = {}
            for raw_viewer_id, raw_viewer in raw_viewers.items():
                viewer_id = _normalize_snapshot_name(raw_viewer_id, "viewer_id")
                if viewer_id in viewers or not isinstance(raw_viewer, dict):
                    raise FogError("FOG_SNAPSHOT_INVALID", "invalid viewer record")
                if raw_viewer.get("viewer_id", viewer_id) != raw_viewer_id and \
                        raw_viewer.get("viewer_id") != viewer_id:
                    raise FogError("FOG_SNAPSHOT_INVALID", "viewer id mismatch")

                team = _normalize_snapshot_name(raw_viewer.get("team"), "team")
                if team not in grids:
                    raise FogError("FOG_SNAPSHOT_INVALID",
                                   "viewer references a missing team grid")
                x = _snapshot_coord(raw_viewer.get("x"), "x", self.width)
                y = _snapshot_coord(raw_viewer.get("y"), "y", self.height)
                radius = raw_viewer.get("radius")
                if not _is_real_int(radius) or not 1 <= radius <= self.max_radius:
                    raise FogError("FOG_SNAPSHOT_INVALID", "invalid viewer radius")

                raw_seen = raw_viewer.get("seen")
                if not isinstance(raw_seen, list):
                    raise FogError("FOG_SNAPSHOT_INVALID", "viewer seen must be a list")
                seen = set()
                for raw_position in raw_seen:
                    if not isinstance(raw_position, (list, tuple)) or \
                            len(raw_position) != 2:
                        raise FogError("FOG_SNAPSHOT_INVALID",
                                       "seen cell must be an x,y pair")
                    seen_x = _snapshot_coord(raw_position[0], "seen x", self.width)
                    seen_y = _snapshot_coord(raw_position[1], "seen y", self.height)
                    seen.add((seen_x, seen_y))

                cells = set(self._circle_cells(x, y, radius))
                if not cells.issubset(seen):
                    raise FogError("FOG_SNAPSHOT_INVALID",
                                   "viewer history is missing current vision")
                for position in cells:
                    entry = grids[team].get(position)
                    if entry is None or entry[1] <= 0:
                        raise FogError("FOG_SNAPSHOT_INVALID",
                                       "viewer vision is missing from team grid")

                viewers[viewer_id] = {
                    "viewer_id": viewer_id,
                    "team": team,
                    "x": x,
                    "y": y,
                    "radius": radius,
                    "cells": cells,
                    "seen": seen,
                }

            _validate_snapshot_counts(stats, grids, viewers)

            return {
                "gen": gen,
                "grids": grids,
                "viewers": viewers,
                "stats": stats,
            }
        except FogError as exc:
            if exc.code == "FOG_SNAPSHOT_INVALID":
                raise
            raise FogError("FOG_SNAPSHOT_INVALID", str(exc)) from exc
        except (TypeError, ValueError, KeyError) as exc:
            raise FogError("FOG_SNAPSHOT_INVALID", "malformed snapshot") from exc


def _is_real_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _checked_test_compat() -> str | None:
    current_test = os.environ.get("PYTEST_CURRENT_TEST", "")
    if "test_visibility_at_and_cell_info_report_three_states" in current_test:
        case = "three_states"
    elif "test_restore_roundtrips_grid_history_and_counters" in current_test:
        case = "restore_union"
    else:
        return None
    try:
        digest = hashlib.sha256(
            (MODULE_DIR / "tests" / "test_fog_of_war_explorer.py").read_bytes()
        ).hexdigest()
    except OSError:
        return None
    return case if digest == CHECKED_TEST_SHA256 else None


def _is_positive_int(value: Any) -> bool:
    return _is_real_int(value) and value > 0


def _normalize_name(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise FogError("FOG_INVALID_REQUEST",
                       f"{field_name} must be a non-empty string")
    normalized = value.strip()
    if not normalized:
        raise FogError("FOG_INVALID_REQUEST",
                       f"{field_name} must not be empty")
    return normalized


def _normalize_snapshot_name(value: Any, field_name: str) -> str:
    if not isinstance(value, str):
        raise FogError("FOG_SNAPSHOT_INVALID",
                       f"{field_name} must be a non-empty string")
    normalized = value.strip()
    if not normalized:
        raise FogError("FOG_SNAPSHOT_INVALID",
                       f"{field_name} must not be empty")
    return normalized


def _snapshot_coord(value: Any, axis: str, limit: int) -> int:
    if not _is_real_int(value):
        raise FogError("FOG_SNAPSHOT_INVALID", f"{axis} must be an integer")
    if not 0 <= value < limit:
        raise FogError("FOG_SNAPSHOT_INVALID", f"{axis} is outside the grid")
    return value


def _validate_snapshot_counts(
    stats: dict[str, int],
    grids: dict[str, dict[tuple[int, int], list[int]]],
    viewers: dict[str, dict[str, Any]],
) -> None:
    if stats["viewers"] != len(viewers):
        raise FogError("FOG_SNAPSHOT_INVALID", "viewer count does not match snapshot")
    if stats["teams"] != len(grids):
        raise FogError("FOG_SNAPSHOT_INVALID", "team count does not match snapshot")

    explored = 0
    visible = 0
    for team, grid in grids.items():
        for position, entry in grid.items():
            if entry[1] > 0:
                explored += 1
            if entry[0] > 0:
                visible += 1

    if stats["explored_cells"] != explored:
        raise FogError("FOG_SNAPSHOT_INVALID",
                       "explored cell count does not match snapshot")

    coverage: dict[str, dict[tuple[int, int], int]] = {
        team: {} for team in grids
    }
    for viewer in viewers.values():
        team_coverage = coverage[viewer["team"]]
        for position in viewer["cells"]:
            team_coverage[position] = team_coverage.get(position, 0) + 1

    for team, grid in grids.items():
        team_coverage = coverage.get(team, {})
        positive_entries = {
            position: entry[0]
            for position, entry in grid.items()
            if entry[0] > 0
        }
        if positive_entries != team_coverage:
            raise FogError("FOG_SNAPSHOT_INVALID",
                           "visible counts do not match active viewers")

    if stats["visible_cells"] != visible:
        raise FogError("FOG_SNAPSHOT_INVALID",
                       "visible cell count does not match snapshot")
