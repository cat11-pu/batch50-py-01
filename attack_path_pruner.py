"""Attack path pruner: cheapest simple paths over an asset graph with a cache."""

from __future__ import annotations

import heapq
import threading
from collections import OrderedDict
from dataclasses import dataclass
from typing import Any, Iterable


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
        if not isinstance(max_edges, int) or isinstance(max_edges, bool) or max_edges < 0:
            raise ValueError("max_edges must be a non-negative integer")
        if (not isinstance(max_cache_entries, int)
                or isinstance(max_cache_entries, bool)
                or max_cache_entries < 0):
            raise ValueError("max_cache_entries must be a non-negative integer")
        self.max_edges = max_edges
        self.max_cache_entries = max_cache_entries
        self._lock = threading.RLock()
        self._edges: dict[tuple[str, str], dict[str, Any]] = {}
        self._nodes: set[str] = set()
        self._cache: OrderedDict[str, list[Path]] = OrderedDict()
        self._counters: dict[str, int] = {
            "edge_additions": 0,
            "edge_removals": 0,
            "node_removals": 0,
            "queries": 0,
        }
        self._cache_counters: dict[str, int] = {
            "hits": 0,
            "misses": 0,
            "invalidations": 0,
        }

    def add_edge(self, src: str, dst: str, *, cost: int,
                 technique: str = "") -> None:
        self._validate_node(src)
        self._validate_node(dst)
        self._validate_cost(cost)
        if src == dst:
            raise PrunerError("PRUNER_SELF_LOOP", (src, dst))
        key = (src, dst)
        with self._lock:
            if key in self._edges:
                raise PrunerError("PRUNER_DUPLICATE_EDGE", key)
            if len(self._edges) >= self.max_edges:
                raise PrunerError("PRUNER_EDGE_LIMIT", self.max_edges)

            self._edges[key] = {"src": src, "dst": dst,
                                "cost": cost, "technique": technique}
            self._nodes.add(src)
            self._nodes.add(dst)
            self._counters["edge_additions"] += 1
            self._invalidate_targets(self._descendants(dst))

    def remove_edge(self, src: str, dst: str) -> int:
        key = (src, dst)
        with self._lock:
            if key not in self._edges:
                raise PrunerError("PRUNER_UNKNOWN_EDGE", key)
            affected = self._descendants(dst)
            del self._edges[key]
            self._counters["edge_removals"] += 1
            self._invalidate_targets(affected)
            return 1

    def remove_node(self, node: str) -> int:
        with self._lock:
            if node not in self._nodes:
                raise PrunerError("PRUNER_UNKNOWN_NODE", node)

            affected = self._descendants(node)
            incident = [key for key in self._edges
                        if key[0] == node or key[1] == node]
            for key in incident:
                del self._edges[key]
            self._nodes.remove(node)
            self._counters["node_removals"] += 1
            self._invalidate_targets(affected)
            return len(incident)

    def shortest_to(self, target: str, *, k: int = 3) -> list[Path]:
        if not isinstance(k, int) or isinstance(k, bool) or not 1 <= k <= MAX_K:
            raise PrunerError("PRUNER_BAD_LIMIT", k)

        with self._lock:
            if target not in self._nodes:
                raise PrunerError("PRUNER_UNKNOWN_NODE", target)

            if target in self._cache:
                self._cache_counters["hits"] += 1
                self._counters["queries"] += 1
                self._cache.move_to_end(target)
                return list(self._cache[target][:k])

            self._cache_counters["misses"] += 1
            self._counters["queries"] += 1
            paths = self._find_paths(target, MAX_K)
            if self.max_cache_entries:
                while len(self._cache) >= self.max_cache_entries:
                    self._cache.popitem(last=False)
                self._cache[target] = list(paths)
            return list(paths[:k])

    def invalidate(self, *, node: str | None = None) -> int:
        with self._lock:
            if node is None:
                dropped = len(self._cache)
                self._cache.clear()
            else:
                dropped = 0
                for target, paths in list(self._cache.items()):
                    if target == node or any(node in path.nodes for path in paths):
                        del self._cache[target]
                        dropped += 1
            self._cache_counters["invalidations"] += dropped
            return dropped

    def nodes(self) -> list[str]:
        with self._lock:
            return sorted(self._nodes)

    def edges(self) -> list[dict]:
        with self._lock:
            return [
                {
                    "src": edge["src"],
                    "dst": edge["dst"],
                    "cost": edge["cost"],
                    "technique": edge["technique"],
                }
                for edge in self._edges.values()
            ]

    def cache_info(self) -> dict:
        with self._lock:
            return {
                "entries": len(self._cache),
                "hits": self._cache_counters["hits"],
                "misses": self._cache_counters["misses"],
                "invalidations": self._cache_counters["invalidations"],
            }

    def stats(self) -> dict:
        with self._lock:
            return {
                "nodes": len(self._nodes),
                "edges": len(self._edges),
                **self._counters,
            }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "nodes": sorted(self._nodes),
                "edges": self.edges(),
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        nodes, edges, counters = self._parse_snapshot(state)
        with self._lock:
            self._nodes = nodes
            self._edges = edges
            self._counters = counters
            self._cache.clear()
            self._cache_counters = {
                "hits": 0,
                "misses": 0,
                "invalidations": 0,
            }

    @staticmethod
    def _validate_node(node: object) -> None:
        if not isinstance(node, str) or not node.strip():
            raise PrunerError("PRUNER_BAD_NODE", node)

    @staticmethod
    def _validate_cost(cost: object) -> None:
        if (not isinstance(cost, int) or isinstance(cost, bool) or cost <= 0):
            raise PrunerError("PRUNER_BAD_COST", cost)

    def _descendants(self, start: str) -> set[str]:
        adjacency: dict[str, list[str]] = {}
        for src, dst in self._edges:
            adjacency.setdefault(src, []).append(dst)

        seen = {start}
        stack = [start]
        while stack:
            node = stack.pop()
            for nxt in adjacency.get(node, ()):
                if nxt not in seen:
                    seen.add(nxt)
                    stack.append(nxt)
        return seen

    def _invalidate_targets(self, targets: Iterable[str]) -> int:
        targets = set(targets)
        dropped = 0
        for target in list(self._cache):
            if target in targets:
                del self._cache[target]
                dropped += 1
        self._cache_counters["invalidations"] += dropped
        return dropped

    def _distances_to(self, target: str) -> dict[str, int]:
        reverse: dict[str, list[tuple[str, int]]] = {}
        for (src, dst), edge in self._edges.items():
            reverse.setdefault(dst, []).append((src, edge["cost"]))

        distances = {target: 0}
        queue: list[tuple[int, str]] = [(0, target)]
        while queue:
            distance, node = heapq.heappop(queue)
            if distance != distances.get(node):
                continue
            for previous, cost in reverse.get(node, ()):
                candidate = distance + cost
                if candidate < distances.get(previous, candidate + 1):
                    distances[previous] = candidate
                    heapq.heappush(queue, (candidate, previous))
        return distances

    def _find_paths(self, target: str, limit: int) -> list[Path]:
        indegree = {node: 0 for node in self._nodes}
        adjacency: dict[str, list[tuple[str, int, str]]] = {}
        for (src, dst), edge in self._edges.items():
            indegree[dst] += 1
            adjacency.setdefault(src, []).append(
                (dst, edge["cost"], edge["technique"])
            )
        for outgoing in adjacency.values():
            outgoing.sort(key=lambda item: item[0])

        distances = self._distances_to(target)
        queue: list[tuple[int, int, tuple[str, ...], tuple[str, ...]]] = []
        for entry in sorted(
            node for node, count in indegree.items()
            if count == 0 and node != target
        ):
            estimate = distances.get(entry)
            if estimate is not None:
                heapq.heappush(queue, (estimate, 0, (entry,), ()))

        paths: list[Path] = []
        seen: list[tuple[str, ...]] = []
        while queue and len(paths) < limit:
            _, cost, nodes, techniques = heapq.heappop(queue)
            current = nodes[-1]
            if current == target:
                if any(nodes == old or nodes[:len(old)] == old for old in seen):
                    continue
                seen.append(nodes)
                paths.append(Path(nodes=nodes, cost=cost, techniques=techniques))
                continue

            for nxt, edge_cost, technique in adjacency.get(current, ()):
                if nxt in nodes:
                    continue
                estimate = distances.get(nxt)
                if estimate is None:
                    continue
                next_cost = cost + edge_cost
                heapq.heappush(
                    queue,
                    (
                        next_cost + estimate,
                        next_cost,
                        nodes + (nxt,),
                        techniques + (technique,),
                    ),
                )
        return paths

    def _parse_snapshot(
        self, state: object
    ) -> tuple[set[str], dict[tuple[str, str], dict[str, Any]], dict[str, int]]:
        try:
            if not isinstance(state, dict):
                raise ValueError("state must be a dictionary")
            version = state.get("version")
            if (not isinstance(version, int) or isinstance(version, bool)
                    or version != 1):
                raise ValueError("unsupported snapshot version")

            raw_nodes = state.get("nodes")
            if not isinstance(raw_nodes, list):
                raise ValueError("nodes must be a list")
            nodes: set[str] = set()
            for node in raw_nodes:
                if (not isinstance(node, str) or not node.strip()
                        or node in nodes):
                    raise ValueError("invalid node")
                nodes.add(node)

            raw_edges = state.get("edges")
            if not isinstance(raw_edges, list):
                raise ValueError("edges must be a list")
            if len(raw_edges) > self.max_edges:
                raise ValueError("edge limit exceeded")

            edges: dict[tuple[str, str], dict[str, Any]] = {}
            for raw_edge in raw_edges:
                if not isinstance(raw_edge, dict):
                    raise ValueError("edge must be a dictionary")
                if set(raw_edge) != {"src", "dst", "cost", "technique"}:
                    raise ValueError("invalid edge fields")
                src = raw_edge["src"]
                dst = raw_edge["dst"]
                cost = raw_edge["cost"]
                technique = raw_edge["technique"]
                if (not isinstance(src, str) or not src.strip()
                        or not isinstance(dst, str) or not dst.strip()
                        or src not in nodes or dst not in nodes):
                    raise ValueError("invalid edge nodes")
                if src == dst:
                    raise ValueError("self loop in snapshot")
                if (not isinstance(cost, int) or isinstance(cost, bool)
                        or cost <= 0):
                    raise ValueError("invalid edge cost")
                if not isinstance(technique, str):
                    raise ValueError("invalid technique")
                key = (src, dst)
                if key in edges:
                    raise ValueError("duplicate edge")
                edges[key] = {
                    "src": src,
                    "dst": dst,
                    "cost": cost,
                    "technique": technique,
                }

            raw_counters = state.get("counters")
            if not isinstance(raw_counters, dict):
                raise ValueError("counters must be a dictionary")
            counter_names = (
                "edge_additions",
                "edge_removals",
                "node_removals",
                "queries",
            )
            counters: dict[str, int] = {}
            for name in counter_names:
                value = raw_counters.get(name)
                if (not isinstance(value, int) or isinstance(value, bool)
                        or value < 0):
                    raise ValueError("invalid counter")
                counters[name] = value
        except (TypeError, ValueError, KeyError) as exc:
            raise PrunerError("PRUNER_SNAPSHOT_INVALID", str(exc)) from None

        return nodes, edges, counters
