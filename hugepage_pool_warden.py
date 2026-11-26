"""NUMA huge page pool warden: tenant quotas, contiguous allocation, defrag accounting."""

from __future__ import annotations

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


class HugepagePoolWarden:
    """Keep per-node huge page pools, tenant quotas and free-fragment bookkeeping."""

    def __init__(self) -> None:
        self._lock = threading.RLock()

    def add_node(self, node: str, pages: int) -> None:
        raise NotImplementedError

    def register_tenant(self, name: str, *, quota: int) -> None:
        raise NotImplementedError

    def set_quota(self, name: str, *, quota: int) -> None:
        raise NotImplementedError

    def tenants(self) -> dict:
        raise NotImplementedError

    def allocate(self, tenant: str, count: int, *, node: str) -> Allocation:
        raise NotImplementedError

    def release(self, alloc_id: str, *, tenant: str) -> int:
        raise NotImplementedError

    def defrag(self, node: str) -> int:
        raise NotImplementedError

    def usage(self, tenant: str | None = None):
        raise NotImplementedError

    def node_view(self, node: str) -> NodeView:
        raise NotImplementedError

    def allocation_info(self, alloc_id: str) -> Allocation:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
