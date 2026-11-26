"""Mesh decimation planner.

Maintains the edge-collapse queue of a mesh, keeps material and UV seam
vertices locked, refuses collapses that would leave non-manifold edges and
reports how far the face budget can actually be reduced.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "MeshPlanError",
    "MeshSummary",
    "AppliedRound",
    "MeshDecimationPlanner",
]


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


class MeshDecimationPlanner:
    """Plan and apply edge collapses for one mesh at a time."""

    def __init__(self) -> None:
        self._lock = threading.RLock()

    def load(self, mesh_id: str, vertices, faces) -> MeshSummary:
        raise NotImplementedError

    def set_target(self, faces: int) -> int:
        raise NotImplementedError

    def lock_boundary(self, vertices=None) -> int:
        raise NotImplementedError

    def edge_cost(self, left: int, right: int) -> float:
        raise NotImplementedError

    def plan(self) -> list[tuple[float, int, int]]:
        raise NotImplementedError

    def apply_round(self) -> AppliedRound:
        raise NotImplementedError

    def report(self) -> dict:
        raise NotImplementedError

    def rollback(self, rounds: int) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
