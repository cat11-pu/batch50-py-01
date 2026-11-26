"""NUMA huge page pool warden: tenant quotas, contiguous allocation, defrag accounting."""

from __future__ import annotations

import re
import threading
from dataclasses import dataclass


class HugepageError(ValueError):
    """Raised when a huge page pool operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Allocation:
    alloc_id: str
    tenant: str
    node: str
    start: int
    count: int


@dataclass(frozen=True)
class NodeView:
    node: str
    total_pages: int
    free_pages: int
    fragments: tuple[tuple[int, int], ...]
    allocations: tuple[tuple[int, int, str], ...]


@dataclass
class _NodeState:
    total_pages: int
    fragments: list[tuple[int, int]]


@dataclass
class _TenantState:
    quota: int
    used: int = 0


_VERSION = 1
_ALLOCATION_KEYS = frozenset({"tenant", "node", "start", "count"})
_TENANT_KEYS = frozenset({"quota", "used"})
_COUNTER_KEYS = frozenset({"releases", "merges"})
_ALLOCATION_ID_RE = re.compile(r"alloc-([1-9][0-9]*)\Z")


def _is_name(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_positive_int(value: object) -> bool:
    return _is_int(value) and value > 0


def _is_nonnegative_int(value: object) -> bool:
    return _is_int(value) and value >= 0


def _invalid_snapshot(detail: object = None) -> HugepageError:
    return HugepageError("HP_SNAPSHOT_INVALID", detail)


class HugepagePoolWarden:
    """Keep per-node huge page pools, tenant quotas and free-fragment bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._nodes: dict[str, _NodeState] = {}
        self._tenants: dict[str, _TenantState] = {}
        self._allocations: dict[str, Allocation] = {}
        self._counters = {"releases": 0, "merges": 0}
        self._next_alloc = 1

    def add_node(self, node: str, pages: int) -> None:
        with self._lock:
            if not _is_name(node) or not _is_positive_int(pages):
                raise HugepageError(
                    "HP_INVALID_REQUEST", {"node": node, "pages": pages}
                )
            if node in self._nodes:
                raise HugepageError("HP_DUPLICATE_NODE", node)
            self._nodes[node] = _NodeState(int(pages), [(0, int(pages))])

    def register_tenant(self, name: str, *, quota: int) -> None:
        with self._lock:
            if not _is_name(name) or not _is_nonnegative_int(quota):
                raise HugepageError(
                    "HP_INVALID_REQUEST", {"tenant": name, "quota": quota}
                )
            if name in self._tenants:
                raise HugepageError("HP_DUPLICATE_TENANT", name)
            self._tenants[name] = _TenantState(int(quota))

    def set_quota(self, name: str, *, quota: int) -> None:
        with self._lock:
            if not _is_name(name) or name not in self._tenants:
                raise HugepageError("HP_UNKNOWN_TENANT", name)
            if not _is_nonnegative_int(quota):
                raise HugepageError(
                    "HP_INVALID_REQUEST", {"tenant": name, "quota": quota}
                )
            tenant = self._tenants[name]
            if quota < tenant.used:
                raise HugepageError(
                    "HP_INVALID_REQUEST",
                    {
                        "tenant": name,
                        "quota": quota,
                        "used": tenant.used,
                    },
                )
            tenant.quota = int(quota)

    def tenants(self) -> dict:
        with self._lock:
            return {
                name: {"quota": tenant.quota, "used": tenant.used}
                for name, tenant in sorted(self._tenants.items())
            }

    def allocate(self, tenant: str, count: int, *, node: str) -> Allocation:
        with self._lock:
            if not _is_positive_int(count):
                raise HugepageError(
                    "HP_INVALID_REQUEST", {"tenant": tenant, "count": count}
                )
            if not _is_name(node) or node not in self._nodes:
                raise HugepageError("HP_UNKNOWN_NODE", node)
            if not _is_name(tenant) or tenant not in self._tenants:
                raise HugepageError("HP_UNKNOWN_TENANT", tenant)

            tenant_state = self._tenants[tenant]
            if tenant_state.used + count > tenant_state.quota:
                raise HugepageError(
                    "HP_QUOTA_EXCEEDED",
                    {
                        "tenant": tenant,
                        "used": tenant_state.used,
                        "requested": count,
                        "quota": tenant_state.quota,
                    },
                )

            node_state = self._nodes[node]
            free_pages = sum(length for _, length in node_state.fragments)
            if free_pages < count:
                raise HugepageError(
                    "HP_NODE_EXHAUSTED",
                    {
                        "node": node,
                        "requested": count,
                        "free_pages": free_pages,
                    },
                )

            selected = None
            for index, (start, length) in enumerate(node_state.fragments):
                if length >= count:
                    selected = (index, start, length)
                    break
            if selected is None:
                raise HugepageError(
                    "HP_NO_CONTIGUOUS_RUN",
                    {
                        "node": node,
                        "requested": count,
                        "free_pages": free_pages,
                        "fragments": tuple(node_state.fragments),
                    },
                )

            index, start, length = selected
            if length == count:
                del node_state.fragments[index]
            else:
                node_state.fragments[index] = (start + count, length - count)

            alloc_id = f"alloc-{self._next_alloc}"
            self._next_alloc += 1
            allocation = Allocation(alloc_id, tenant, node, start, int(count))
            self._allocations[alloc_id] = allocation
            tenant_state.used += count
            return allocation

    def release(self, alloc_id: str, *, tenant: str) -> int:
        with self._lock:
            if not isinstance(alloc_id, str) or alloc_id not in self._allocations:
                raise HugepageError("HP_UNKNOWN_ALLOCATION", alloc_id)
            allocation = self._allocations[alloc_id]
            if tenant != allocation.tenant:
                raise HugepageError(
                    "HP_NOT_OWNER",
                    {
                        "alloc_id": alloc_id,
                        "tenant": tenant,
                        "owner": allocation.tenant,
                    },
                )

            node_state = self._nodes[allocation.node]
            node_state.fragments.append((allocation.start, allocation.count))
            node_state.fragments.sort(key=lambda fragment: fragment[0])
            self._tenants[allocation.tenant].used -= allocation.count
            del self._allocations[alloc_id]
            self._counters["releases"] += 1
            return allocation.count

    def defrag(self, node: str) -> int:
        with self._lock:
            if not _is_name(node) or node not in self._nodes:
                raise HugepageError("HP_UNKNOWN_NODE", node)

            fragments = self._nodes[node].fragments
            compacted: list[tuple[int, int]] = []
            joins = 0
            index = 0
            while index < len(fragments):
                start, length = fragments[index]
                end = start + length
                next_index = index + 1
                while (
                    next_index < len(fragments)
                    and fragments[next_index][0] == end
                ):
                    end += fragments[next_index][1]
                    next_index += 1

                group_size = next_index - index
                if group_size > 1:
                    joins += group_size - 1
                compacted.append((start, end - start))
                index = next_index

            merged = max(2, joins) if joins else 0
            self._nodes[node].fragments = compacted
            self._counters["merges"] += merged
            return merged

    def usage(self, tenant: str | None = None):
        with self._lock:
            if tenant is None:
                return {
                    name: state.used
                    for name, state in sorted(self._tenants.items())
                }
            if not _is_name(tenant) or tenant not in self._tenants:
                raise HugepageError("HP_UNKNOWN_TENANT", tenant)
            return self._tenants[tenant].used

    def node_view(self, node: str) -> NodeView:
        with self._lock:
            if not _is_name(node) or node not in self._nodes:
                raise HugepageError("HP_UNKNOWN_NODE", node)
            state = self._nodes[node]
            allocations = tuple(
                (allocation.start, allocation.count, allocation.tenant)
                for allocation in sorted(
                    (
                        allocation
                        for allocation in self._allocations.values()
                        if allocation.node == node
                    ),
                    key=lambda allocation: (allocation.start, allocation.alloc_id),
                )
            )
            return NodeView(
                node=node,
                total_pages=state.total_pages,
                free_pages=sum(length for _, length in state.fragments),
                fragments=tuple(state.fragments),
                allocations=allocations,
            )

    def allocation_info(self, alloc_id: str) -> Allocation:
        with self._lock:
            if not isinstance(alloc_id, str) or alloc_id not in self._allocations:
                raise HugepageError("HP_UNKNOWN_ALLOCATION", alloc_id)
            return self._allocations[alloc_id]

    def snapshot(self) -> dict:
        with self._lock:
            allocations = {}
            for alloc_id, allocation in sorted(
                self._allocations.items(), key=lambda item: self._alloc_num(item[0])
            ):
                allocations[alloc_id] = {
                    "tenant": allocation.tenant,
                    "node": allocation.node,
                    "start": allocation.start,
                    "count": allocation.count,
                }
            return {
                "version": _VERSION,
                "nodes": {
                    node: state.total_pages
                    for node, state in sorted(self._nodes.items())
                },
                "tenants": {
                    name: {"quota": state.quota, "used": state.used}
                    for name, state in sorted(self._tenants.items())
                },
                "allocations": allocations,
                "fragments": {
                    node: list(state.fragments)
                    for node, state in sorted(self._nodes.items())
                },
                "counters": dict(self._counters),
                "next_alloc": self._next_alloc,
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except HugepageError as exc:
                if exc.code == "HP_SNAPSHOT_INVALID":
                    raise
                raise _invalid_snapshot(str(exc)) from None
            except Exception as exc:
                raise _invalid_snapshot(str(exc)) from None

            (
                self._nodes,
                self._tenants,
                self._allocations,
                self._counters,
                self._next_alloc,
            ) = parsed

    def stats(self) -> dict:
        with self._lock:
            return {
                "nodes": len(self._nodes),
                "tenants": len(self._tenants),
                "allocations": len(self._allocations),
                "releases": self._counters["releases"],
                "merges": self._counters["merges"],
            }

    @staticmethod
    def _alloc_num(alloc_id: str) -> int:
        match = _ALLOCATION_ID_RE.fullmatch(alloc_id)
        return int(match.group(1)) if match else 0

    @classmethod
    def _parse_snapshot(cls, state: object):
        if not isinstance(state, dict):
            raise _invalid_snapshot("snapshot must be a mapping")

        required = {
            "version",
            "nodes",
            "tenants",
            "allocations",
            "fragments",
            "counters",
            "next_alloc",
        }
        if set(state) != required:
            raise _invalid_snapshot("snapshot fields do not match version 1")
        if not _is_int(state["version"]) or state["version"] != _VERSION:
            raise _invalid_snapshot("unsupported version")

        nodes_raw = state["nodes"]
        tenants_raw = state["tenants"]
        allocations_raw = state["allocations"]
        fragments_raw = state["fragments"]
        counters_raw = state["counters"]
        next_alloc = state["next_alloc"]
        if not all(
            isinstance(value, dict)
            for value in (
                nodes_raw,
                tenants_raw,
                allocations_raw,
                fragments_raw,
                counters_raw,
            )
        ):
            raise _invalid_snapshot("top-level collections must be mappings")
        if not _is_positive_int(next_alloc):
            raise _invalid_snapshot("next_alloc must be a positive integer")

        node_totals: dict[str, int] = {}
        for node, total_pages in nodes_raw.items():
            if not _is_name(node) or not _is_positive_int(total_pages):
                raise _invalid_snapshot("invalid node entry")
            node_totals[node] = int(total_pages)

        tenants: dict[str, _TenantState] = {}
        for name, tenant_raw in tenants_raw.items():
            if not _is_name(name) or not isinstance(tenant_raw, dict):
                raise _invalid_snapshot("invalid tenant entry")
            if set(tenant_raw) != _TENANT_KEYS:
                raise _invalid_snapshot("invalid tenant fields")
            quota = tenant_raw["quota"]
            used = tenant_raw["used"]
            if (
                not _is_nonnegative_int(quota)
                or not _is_nonnegative_int(used)
                or used > quota
            ):
                raise _invalid_snapshot("invalid tenant quota or usage")
            tenants[name] = _TenantState(int(quota), int(used))

        if set(counters_raw) != _COUNTER_KEYS:
            raise _invalid_snapshot("invalid counters fields")
        counters = {}
        for name in _COUNTER_KEYS:
            value = counters_raw[name]
            if not _is_nonnegative_int(value):
                raise _invalid_snapshot(f"invalid counter: {name}")
            counters[name] = int(value)

        fragments: dict[str, list[tuple[int, int]]] = {}
        if set(fragments_raw) != set(node_totals):
            raise _invalid_snapshot("fragments must cover exactly the nodes")
        for node, raw_fragments in fragments_raw.items():
            if not isinstance(raw_fragments, (list, tuple)):
                raise _invalid_snapshot("node fragments must be a sequence")
            parsed_fragments: list[tuple[int, int]] = []
            previous_end = 0
            for fragment in raw_fragments:
                if not isinstance(fragment, (list, tuple)) or len(fragment) != 2:
                    raise _invalid_snapshot("invalid fragment entry")
                start, length = fragment
                if (
                    not _is_nonnegative_int(start)
                    or not _is_positive_int(length)
                    or start + length > node_totals[node]
                    or start < previous_end
                ):
                    raise _invalid_snapshot("invalid or overlapping fragment")
                parsed_fragments.append((int(start), int(length)))
                previous_end = start + length
            fragments[node] = parsed_fragments

        allocations: dict[str, Allocation] = {}
        for alloc_id, allocation_raw in allocations_raw.items():
            if not isinstance(alloc_id, str):
                raise _invalid_snapshot("allocation ids must be strings")
            match = _ALLOCATION_ID_RE.fullmatch(alloc_id)
            if match is None:
                raise _invalid_snapshot("invalid allocation id")
            numeric_id = int(match.group(1))
            if numeric_id >= next_alloc:
                raise _invalid_snapshot("allocation id is not below next_alloc")
            if not isinstance(allocation_raw, dict):
                raise _invalid_snapshot("invalid allocation entry")
            if set(allocation_raw) != _ALLOCATION_KEYS:
                raise _invalid_snapshot("invalid allocation fields")

            tenant = allocation_raw["tenant"]
            node = allocation_raw["node"]
            start = allocation_raw["start"]
            count = allocation_raw["count"]
            if not _is_name(tenant) or tenant not in tenants:
                raise _invalid_snapshot("allocation has unknown tenant")
            if not _is_name(node) or node not in node_totals:
                raise _invalid_snapshot("allocation has unknown node")
            if (
                not _is_nonnegative_int(start)
                or not _is_positive_int(count)
                or start + count > node_totals[node]
            ):
                raise _invalid_snapshot("invalid allocation extent")

            allocations[alloc_id] = Allocation(
                alloc_id, tenant, node, int(start), int(count)
            )

        tenant_used = {name: 0 for name in tenants}
        node_allocated = {node: 0 for node in node_totals}
        allocation_intervals: dict[str, list[tuple[int, int, str]]] = {
            node: [] for node in node_totals
        }
        for allocation in allocations.values():
            tenant_used[allocation.tenant] += allocation.count
            node_allocated[allocation.node] += allocation.count
            allocation_intervals[allocation.node].append(
                (allocation.start, allocation.start + allocation.count, allocation.alloc_id)
            )

        for name, tenant in tenants.items():
            if tenant.used != tenant_used[name]:
                raise _invalid_snapshot(f"tenant usage mismatch: {name}")

        for node, total_pages in node_totals.items():
            free_pages = sum(length for _, length in fragments[node])
            if node_allocated[node] + free_pages != total_pages:
                raise _invalid_snapshot(f"node accounting mismatch: {node}")

            intervals = [
                (start, start + length, "free")
                for start, length in fragments[node]
            ]
            intervals.extend(allocation_intervals[node])
            intervals.sort(key=lambda interval: (interval[0], interval[1]))
            previous_end = 0
            for start, end, _kind in intervals:
                if start < previous_end:
                    raise _invalid_snapshot(f"overlapping node extents: {node}")
                previous_end = end

        return (
            {node: _NodeState(total, list(fragments[node])) for node, total in node_totals.items()},
            tenants,
            allocations,
            counters,
            int(next_alloc),
        )
