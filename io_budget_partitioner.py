"""Block-device IO budget partitioning: hierarchy, weighted sharing, loans and reclaim."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass


class IoBudgetError(ValueError):
    """Raised when a budget operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class GrantRecord:
    grant_id: str
    device: str
    borrower: str
    amount: int
    lenders: tuple = ()
    expires_at: str = ""


class IoBudgetPartitioner:
    """Track per-device limits, weights, loans and usage windows for a cgroup tree."""

    def __init__(self, *, clock=None) -> None:
        self._clock = clock
        self._lock = threading.Lock()

    def add_device(self, name: str, *, capacity: int,
                   window_seconds: int = 10, windows: int = 3) -> None:
        raise NotImplementedError

    def remove_device(self, name: str) -> dict:
        raise NotImplementedError

    def add_group(self, name: str, *, parent: str | None = None,
                  weight: int = 100) -> None:
        raise NotImplementedError

    def remove_group(self, name: str) -> None:
        raise NotImplementedError

    def set_limit(self, device: str, group: str, *, limit: int,
                  weight: int | None = None) -> dict:
        raise NotImplementedError

    def borrow(self, device: str, group: str, *, amount: int,
               ttl: int = 30, now: str | None = None) -> dict:
        raise NotImplementedError

    def account(self, device: str, group: str, *, bytes_done: int,
                now: str | None = None) -> dict:
        raise NotImplementedError

    def reclaim(self, device: str, *, now: str | None = None) -> dict:
        raise NotImplementedError

    def rebalance(self, device: str, *, now: str | None = None) -> dict:
        raise NotImplementedError

    def status(self, device: str, group: str) -> dict:
        raise NotImplementedError

    def grants(self, device: str) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
