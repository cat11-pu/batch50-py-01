"""Host locked memory budget ledger: unit quotas, two phase reservation, reclamation."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class MlockError(ValueError):
    """Raised when a locked memory request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Unit:
    unit_id: str
    soft_limit: int
    hard_limit: int
    priority: int
    privileged: bool


@dataclass(frozen=True)
class Reservation:
    reservation_id: str
    unit_id: str
    pid: int
    start_time: int
    exe: str
    size: int
    committed: bool
    expires_at: str
    created_at: str


@dataclass(frozen=True)
class UnitStatus:
    unit_id: str
    soft_limit: int
    hard_limit: int
    committed: int
    reserved: int
    remaining_hard: int
    over_soft: bool


class MlockBudgetLedger:
    """Account locked memory per unit with soft and hard quotas."""

    def __init__(self, *, host_limit: int = 8388608, reserved_pool: int = 1048576,
                 reservation_ttl: int = 60) -> None:
        self.host_limit = host_limit
        self.reserved_pool = reserved_pool
        self.reservation_ttl = reservation_ttl
        self._lock = threading.RLock()
        self._units: dict[str, Unit] = {}
        self._reservations: dict[str, Reservation] = {}
        self._children: dict[str, tuple[str, ...]] = {}
        self._next_reservation = 1
        self._counters = {
            "expired": 0, "reclaimed": 0, "soft_warnings": 0,
        }

    def register_unit(self, unit_id: str, *, soft_limit: int, hard_limit: int,
                      priority: int = 0, privileged: bool = False,
                      now: str) -> Unit:
        raise NotImplementedError

    def reserve(self, unit_id: str, *, pid: int, start_time: int, exe: str,
                size: int, now: str) -> Reservation:
        raise NotImplementedError

    def commit(self, reservation_id: str, *, now: str) -> int:
        raise NotImplementedError

    def release(self, reservation_id: str, *, now: str) -> int:
        raise NotImplementedError

    def inherit(self, reservation_id: str, *, child_pid: int,
                child_start_time: int, now: str) -> Reservation:
        raise NotImplementedError

    def process_exit(self, pid: int, *, start_time: int, exe: str,
                     now: str) -> list[str]:
        raise NotImplementedError

    def expire_reservations(self, *, now: str) -> list[str]:
        raise NotImplementedError

    def reclaim(self, *, target_free: int, now: str) -> list[str]:
        raise NotImplementedError

    def status(self, unit_id: str) -> UnitStatus:
        raise NotImplementedError

    def remove_unit(self, unit_id: str) -> int:
        raise NotImplementedError

    def units(self) -> list[Unit]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
