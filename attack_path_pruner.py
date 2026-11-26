"""Attack path pruner: cheapest simple paths over an asset graph with a cache."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class PrunerError(ValueError):
    """Raised when the pruner refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


MAX_K = 10


@dataclass(frozen=True)
class Path:
    nodes: tuple[str, ...]
    cost: int
    techniques: tuple[str, ...]


class AttackPathPruner:
    """Answer cheapest-path queries and invalidate the cache incrementally."""

    def __init__(self, *, max_edges: int = 200, max_cache_entries: int = 128) -> None:
        self.max_edges = max_edges
        self.max_cache_entries = max_cache_entries
        self._lock = threading.RLock()
        self._edges: dict[tuple[str, str], dict] = {}
        self._nodes: set[str] = set()
        self._cache: dict[str, list[Path]] = {}
        self._counters: dict[str, int] = {}

    def add_edge(self, src: str, dst: str, *, cost: int,
                 technique: str = "") -> None:
        raise NotImplementedError

    def remove_edge(self, src: str, dst: str) -> int:
        raise NotImplementedError

    def remove_node(self, node: str) -> int:
        raise NotImplementedError

    def shortest_to(self, target: str, *, k: int = 3) -> list[Path]:
        raise NotImplementedError

    def invalidate(self, *, node: str | None = None) -> int:
        raise NotImplementedError

    def nodes(self) -> list[str]:
        raise NotImplementedError

    def edges(self) -> list[dict]:
        raise NotImplementedError

    def cache_info(self) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
