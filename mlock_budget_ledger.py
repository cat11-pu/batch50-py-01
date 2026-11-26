"""Host locked memory budget ledger with two-phase reservations."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


SNAPSHOT_VERSION = 1


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


@dataclass
class _ReservationRecord:
    reservation_id: str
    unit_id: str
    pid: int
    start_time: int
    exe: str
    size: int
    committed: bool
    expires_at: str
    created_at: str
    seq: int
    owner_active: bool = True
    children: dict[tuple[int, int], dict[str, Any]] = field(default_factory=dict)

    def to_public(self) -> Reservation:
        return Reservation(
            reservation_id=self.reservation_id,
            unit_id=self.unit_id,
            pid=self.pid,
            start_time=self.start_time,
            exe=self.exe,
            size=self.size,
            committed=self.committed,
            expires_at=self.expires_at,
            created_at=self.created_at,
        )


class MlockBudgetLedger:
    """Account locked memory per unit with soft and hard quotas."""

    def __init__(self, *, host_limit: int = 8388608, reserved_pool: int = 1048576,
                 reservation_ttl: int = 60) -> None:
        self.host_limit = host_limit
        self.reserved_pool = reserved_pool
        self.reservation_ttl = reservation_ttl
        self._lock = threading.RLock()
        self._units: dict[str, Unit] = {}
        self._reservations: dict[str, _ReservationRecord] = {}
        self._next_reservation = 1
        self._next_seq = 1
        self._last_now: datetime | None = None
        self._last_now_text: str | None = None
        self._counters = {
            "expired": 0,
            "reclaimed": 0,
            "soft_warnings": 0,
        }

    def register_unit(self, unit_id: str, *, soft_limit: int, hard_limit: int,
                      priority: int = 0, privileged: bool = False,
                      now: str) -> Unit:
        now_dt = self._parse_time(now)
        with self._lock:
            self._remember_now(now, now_dt)
            if unit_id in self._units:
                raise MlockError("MLOCK_DUPLICATE_UNIT", {"unit_id": unit_id})
            unit = Unit(
                unit_id=unit_id,
                soft_limit=soft_limit,
                hard_limit=hard_limit,
                priority=priority,
                privileged=privileged,
            )
            self._units[unit_id] = unit
            return unit

    def reserve(self, unit_id: str, *, pid: int, start_time: int, exe: str,
                size: int, now: str) -> Reservation:
        self._validate_size(size)
        self._validate_process_identity(pid, start_time, exe)
        now_dt = self._parse_time(now)

        with self._lock:
            self._remember_now(now, now_dt)
            unit = self._get_unit(unit_id)
            unit_committed, unit_reserved = self._unit_totals(unit_id)
            unit_used = unit_committed + unit_reserved

            if unit_used + size > unit.hard_limit:
                raise MlockError(
                    "MLOCK_HARD_LIMIT",
                    {
                        "unit_id": unit_id,
                        "hard_limit": unit.hard_limit,
                        "used": unit_used,
                        "requested": size,
                    },
                )

            if unit.privileged:
                pool_used = self._privileged_total()
                if pool_used + size > self.reserved_pool:
                    raise MlockError(
                        "MLOCK_HOST_LIMIT",
                        {
                            "scope": "reserved_pool",
                            "reserved_pool": self.reserved_pool,
                            "used": pool_used,
                            "requested": size,
                        },
                    )
            else:
                ordinary_limit = self.host_limit - self.reserved_pool
                ordinary_used = self._ordinary_total()
                if ordinary_used + size > ordinary_limit:
                    raise MlockError(
                        "MLOCK_HOST_LIMIT",
                        {
                            "scope": "ordinary",
                            "host_limit": self.host_limit,
                            "reserved_pool": self.reserved_pool,
                            "ordinary_limit": ordinary_limit,
                            "used": ordinary_used,
                            "requested": size,
                        },
                    )

            expires_dt = now_dt + timedelta(seconds=self.reservation_ttl)
            reservation_id = f"reservation-{self._next_reservation}"
            self._next_reservation += 1
            record = _ReservationRecord(
                reservation_id=reservation_id,
                unit_id=unit_id,
                pid=pid,
                start_time=start_time,
                exe=exe,
                size=size,
                committed=False,
                expires_at=expires_dt.isoformat(),
                created_at=now if isinstance(now, str) else now_dt.isoformat(),
                seq=self._next_seq,
            )
            self._next_seq += 1
            self._reservations[reservation_id] = record

            return record.to_public()

    def commit(self, reservation_id: str, *, now: str) -> int:
        now_dt = self._parse_time(now)
        with self._lock:
            self._remember_now(now, now_dt)
            record = self._get_record(reservation_id)
            if record.committed:
                return record.size

            if self._is_expired(record, now_dt):
                self._delete_record(record)
                self._counters["expired"] += 1
                raise MlockError(
                    "MLOCK_UNKNOWN_RESERVATION",
                    {"reservation_id": reservation_id, "reason": "expired"},
                )

            record.committed = True
            committed, _reserved = self._unit_totals(record.unit_id)
            unit = self._units[record.unit_id]
            if committed > unit.soft_limit:
                self._counters["soft_warnings"] += 1
            return record.size

    def release(self, reservation_id: str, *, now: str) -> int:
        now_dt = self._parse_time(now)
        with self._lock:
            self._remember_now(now, now_dt)
            record = self._reservations.get(reservation_id)
            if record is None:
                raise MlockError(
                    "MLOCK_UNKNOWN_RESERVATION",
                    {"reservation_id": reservation_id},
                )

            released = record.size if record.committed else 0
            self._delete_record(record)
            return released

    def inherit(self, reservation_id: str, *, child_pid: int,
                child_start_time: int, now: str) -> Reservation:
        self._validate_process_identity(
            child_pid, child_start_time, None, require_exe=False
        )
        now_dt = self._parse_time(now)
        with self._lock:
            self._remember_now(now, now_dt)
            record = self._get_record(reservation_id)
            if not record.committed and self._is_expired(record, now_dt):
                self._delete_record(record)
                self._counters["expired"] += 1
                raise MlockError(
                    "MLOCK_UNKNOWN_RESERVATION",
                    {"reservation_id": reservation_id, "reason": "expired"},
                )

            record.children[(child_pid, child_start_time)] = {
                "pid": child_pid,
                "start_time": child_start_time,
                "exe": record.exe,
            }
            return record.to_public()

    def process_exit(self, pid: int, *, start_time: int, exe: str,
                     now: str) -> list[str]:
        now_dt = self._parse_time(now)
        self._validate_process_identity(pid, start_time, exe)
        released: list[str] = []

        with self._lock:
            self._remember_now(now, now_dt)
            records = sorted(self._reservations.values(), key=lambda item: item.seq)
            for record in records:
                matched = False

                if (record.owner_active
                        and record.pid == pid
                        and record.start_time == start_time
                        and record.exe == exe):
                    record.owner_active = False
                    matched = True
                else:
                    child = record.children.get((pid, start_time))
                    if child is not None and child.get("exe") == exe:
                        del record.children[(pid, start_time)]
                        matched = True

                if not matched:
                    continue

                if not record.owner_active and not record.children:
                    released.append(record.reservation_id)
                    self._delete_record(record)
                    self._counters["reclaimed"] += 1

            return released

    def expire_reservations(self, *, now: str) -> list[str]:
        now_dt = self._parse_time(now)
        with self._lock:
            self._remember_now(now, now_dt)
            candidates = [
                record for record in self._reservations.values()
                if not record.committed and self._is_expired(record, now_dt)
            ]
            candidates.sort(key=lambda record: (
                self._parse_time(record.expires_at), record.seq
            ))

            expired_ids: list[str] = []
            for record in candidates:
                if record.reservation_id not in self._reservations:
                    continue
                expired_ids.append(record.reservation_id)
                self._delete_record(record)
                self._counters["expired"] += 1

            return expired_ids

    def reclaim(self, *, target_free: int, now: str) -> list[str]:
        now_dt = self._parse_time(now)
        with self._lock:
            self._remember_now(now, now_dt)
            if not isinstance(target_free, int) or isinstance(target_free, bool):
                raise MlockError(
                    "MLOCK_INVALID_REQUEST",
                    {"field": "target_free", "value": target_free},
                )
            if target_free <= 0:
                return []

            candidates = sorted(
                self._reservations.values(),
                key=lambda record: (
                    self._units[record.unit_id].priority,
                    self._parse_time(record.created_at),
                    record.seq,
                ),
            )

            reclaimed: list[str] = []
            freed_bytes = 0
            for record in candidates:
                if record.reservation_id not in self._reservations:
                    continue
                reclaimed.append(record.reservation_id)
                freed_bytes += record.size
                self._delete_record(record)
                self._counters["reclaimed"] += 1
                if freed_bytes >= target_free:
                    break

            return reclaimed

    def status(self, unit_id: str) -> UnitStatus:
        with self._lock:
            unit = self._get_unit(unit_id)
            committed, reserved = self._unit_totals(unit_id)
            remaining_hard = max(0, unit.hard_limit - committed - reserved)
            return UnitStatus(
                unit_id=unit_id,
                soft_limit=unit.soft_limit,
                hard_limit=unit.hard_limit,
                committed=committed,
                reserved=reserved,
                remaining_hard=remaining_hard,
                over_soft=committed > unit.soft_limit,
            )

    def remove_unit(self, unit_id: str) -> int:
        with self._lock:
            self._get_unit(unit_id)
            if any(record.unit_id == unit_id
                   for record in self._reservations.values()):
                committed, reserved = self._unit_totals(unit_id)
                raise MlockError(
                    "MLOCK_UNIT_NOT_EMPTY",
                    {
                        "unit_id": unit_id,
                        "committed": committed,
                        "reserved": reserved,
                    },
                )
            del self._units[unit_id]
            return 1

    def units(self) -> list[Unit]:
        with self._lock:
            return [self._units[unit_id] for unit_id in sorted(self._units)]

    def stats(self) -> dict:
        with self._lock:
            committed_bytes = sum(
                record.size for record in self._reservations.values()
                if record.committed
            )
            reserved_bytes = sum(
                record.size for record in self._reservations.values()
                if not record.committed
            )
            return {
                "units": len(self._units),
                "reservations": len(self._reservations),
                "committed_bytes": committed_bytes,
                "reserved_bytes": reserved_bytes,
                "expired": self._counters["expired"],
                "reclaimed": self._counters["reclaimed"],
                "soft_warnings": self._counters["soft_warnings"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": SNAPSHOT_VERSION,
                "host_limit": self.host_limit,
                "reserved_pool": self.reserved_pool,
                "reservation_ttl": self.reservation_ttl,
                "as_of": self._last_now_text,
                "next_reservation": self._next_reservation,
                "next_seq": self._next_seq,
                "counters": dict(self._counters),
                "units": [
                    {
                        "unit_id": unit.unit_id,
                        "soft_limit": unit.soft_limit,
                        "hard_limit": unit.hard_limit,
                        "priority": unit.priority,
                        "privileged": unit.privileged,
                    }
                    for unit in (self._units[key] for key in sorted(self._units))
                ],
                "reservations": [
                    {
                        "reservation_id": record.reservation_id,
                        "unit_id": record.unit_id,
                        "pid": record.pid,
                        "start_time": record.start_time,
                        "exe": record.exe,
                        "size": record.size,
                        "committed": record.committed,
                        "expires_at": record.expires_at,
                        "created_at": record.created_at,
                        "seq": record.seq,
                        "owner_active": record.owner_active,
                        "children": [
                            {
                                "child_pid": child["pid"],
                                "child_start_time": child["start_time"],
                                "exe": child["exe"],
                            }
                            for child in record.children.values()
                        ],
                    }
                    for record in sorted(
                        self._reservations.values(), key=lambda item: item.seq
                    )
                ],
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        restored = self._build_restored_state(state)
        with self._lock:
            self.host_limit = restored["host_limit"]
            self.reserved_pool = restored["reserved_pool"]
            self.reservation_ttl = restored["reservation_ttl"]
            self._units = restored["units"]
            self._reservations = restored["reservations"]
            self._next_reservation = restored["next_reservation"]
            self._next_seq = restored["next_seq"]
            self._counters = restored["counters"]
            self._last_now = restored["last_now"]
            self._last_now_text = restored["last_now_text"]

    def _build_restored_state(self, state: object) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise MlockError("MLOCK_SNAPSHOT_INVALID", {"reason": "state_not_dict"})

        try:
            if state.get("version") != SNAPSHOT_VERSION:
                raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "version"})

            host_limit = self._restore_int(
                state.get("host_limit", 8388608), "host_limit"
            )
            reserved_pool = self._restore_int(
                state.get("reserved_pool", 1048576), "reserved_pool"
            )
            reservation_ttl = self._restore_int(
                state.get("reservation_ttl", 60), "reservation_ttl"
            )
            if host_limit <= 0 or reserved_pool < 0 or reservation_ttl < 0:
                raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "limits"})

            units = self._restore_units(state.get("units"))
            records = self._restore_reservations(state.get("reservations"), units)
            counters = self._restore_counters(state.get("counters"))
            next_reservation = self._restore_int(
                state.get("next_reservation", 1), "next_reservation"
            )
            next_seq = self._restore_int(state.get("next_seq", 1), "next_seq")
            if next_reservation < 1 or next_seq < 1:
                raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "sequence"})

            for record in records.values():
                next_seq = max(next_seq, record.seq + 1)
                suffix = record.reservation_id.rsplit("-", 1)[-1]
                if suffix.isdigit():
                    next_reservation = max(next_reservation, int(suffix) + 1)
            next_reservation = max(next_reservation, next_seq)

            as_of_text = state.get("as_of")
            if as_of_text is None:
                as_of_text = state.get("now")
            as_of_dt = self._parse_time(as_of_text) if as_of_text is not None else None

            if as_of_dt is not None:
                for record in list(records.values()):
                    if not record.committed and self._is_expired(record, as_of_dt):
                        del records[record.reservation_id]
                        counters["expired"] += 1

            return {
                "host_limit": host_limit,
                "reserved_pool": reserved_pool,
                "reservation_ttl": reservation_ttl,
                "units": units,
                "reservations": records,
                "next_reservation": next_reservation,
                "next_seq": next_seq,
                "counters": counters,
                "last_now": as_of_dt,
                "last_now_text": as_of_text if isinstance(as_of_text, str) else None,
            }
        except MlockError as error:
            if error.code == "MLOCK_SNAPSHOT_INVALID":
                raise
            raise MlockError(
                "MLOCK_SNAPSHOT_INVALID",
                {"reason": "invalid_snapshot", "code": error.code},
            ) from error
        except (TypeError, ValueError, KeyError) as error:
            raise MlockError(
                "MLOCK_SNAPSHOT_INVALID",
                {"reason": "invalid_snapshot", "detail": str(error)},
            ) from error

    def _restore_units(self, raw_units: object) -> dict[str, Unit]:
        if not isinstance(raw_units, list):
            raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "units"})

        units: dict[str, Unit] = {}
        for raw in raw_units:
            if not isinstance(raw, dict):
                raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "units[]"})

            unit_id = raw.get("unit_id")
            if not isinstance(unit_id, str) or not unit_id or unit_id in units:
                raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "unit_id"})

            soft_limit = self._restore_int(raw.get("soft_limit"), "soft_limit")
            hard_limit = self._restore_int(raw.get("hard_limit"), "hard_limit")
            priority = self._restore_int(raw.get("priority", 0), "priority")
            privileged = raw.get("privileged", False)
            if not isinstance(privileged, bool):
                raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "privileged"})

            units[unit_id] = Unit(
                unit_id=unit_id,
                soft_limit=soft_limit,
                hard_limit=hard_limit,
                priority=priority,
                privileged=privileged,
            )
        return units

    def _restore_reservations(
        self, raw_records: object, units: dict[str, Unit]
    ) -> dict[str, _ReservationRecord]:
        if not isinstance(raw_records, list):
            raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "reservations"})

        records: dict[str, _ReservationRecord] = {}
        for raw in raw_records:
            if not isinstance(raw, dict):
                raise MlockError(
                    "MLOCK_SNAPSHOT_INVALID", {"field": "reservations[]"}
                )

            reservation_id = raw.get("reservation_id")
            unit_id = raw.get("unit_id")
            exe = raw.get("exe")
            created_at = raw.get("created_at")
            expires_at = raw.get("expires_at")
            if (not isinstance(reservation_id, str) or not reservation_id
                    or reservation_id in records):
                raise MlockError(
                    "MLOCK_SNAPSHOT_INVALID", {"field": "reservation_id"}
                )
            if not isinstance(unit_id, str) or unit_id not in units:
                raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "unit_id_ref"})
            if not isinstance(exe, str):
                raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "exe"})
            if not isinstance(created_at, str) or not isinstance(expires_at, str):
                raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "timestamp"})

            pid = self._restore_int(raw.get("pid"), "pid")
            start_time = self._restore_int(raw.get("start_time"), "start_time")
            size = self._restore_int(raw.get("size"), "size")
            seq = self._restore_int(raw.get("seq"), "seq")
            committed = raw.get("committed")
            owner_active = raw.get("owner_active", True)
            if size <= 0 or seq <= 0:
                raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "size_or_seq"})
            if not isinstance(committed, bool) or not isinstance(owner_active, bool):
                raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "boolean"})

            self._parse_time(created_at)
            self._parse_time(expires_at)

            children: dict[tuple[int, int], dict[str, Any]] = {}
            raw_children = raw.get("children", [])
            if not isinstance(raw_children, list):
                raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "children"})
            for raw_child in raw_children:
                if not isinstance(raw_child, dict):
                    raise MlockError(
                        "MLOCK_SNAPSHOT_INVALID", {"field": "children[]"}
                    )
                child_pid = self._restore_int(raw_child.get("child_pid"), "child_pid")
                child_start_time = self._restore_int(
                    raw_child.get("child_start_time"), "child_start_time"
                )
                child_exe = raw_child.get("exe", exe)
                if not isinstance(child_exe, str):
                    raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "child_exe"})
                children[(child_pid, child_start_time)] = {
                    "pid": child_pid,
                    "start_time": child_start_time,
                    "exe": child_exe,
                }

            records[reservation_id] = _ReservationRecord(
                reservation_id=reservation_id,
                unit_id=unit_id,
                pid=pid,
                start_time=start_time,
                exe=exe,
                size=size,
                committed=committed,
                expires_at=expires_at,
                created_at=created_at,
                seq=seq,
                owner_active=owner_active,
                children=children,
            )
        return records

    def _restore_counters(self, raw_counters: object) -> dict[str, int]:
        if not isinstance(raw_counters, dict):
            raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": "counters"})
        return {
            key: self._restore_nonnegative_int(
                raw_counters.get(key), f"counters.{key}"
            )
            for key in ("expired", "reclaimed", "soft_warnings")
        }

    def _get_unit(self, unit_id: str) -> Unit:
        unit = self._units.get(unit_id)
        if unit is None:
            raise MlockError("MLOCK_UNKNOWN_UNIT", {"unit_id": unit_id})
        return unit

    def _get_record(self, reservation_id: str) -> _ReservationRecord:
        record = self._reservations.get(reservation_id)
        if record is None:
            raise MlockError(
                "MLOCK_UNKNOWN_RESERVATION",
                {"reservation_id": reservation_id},
            )
        return record

    def _delete_record(self, record: _ReservationRecord) -> None:
        self._reservations.pop(record.reservation_id, None)

    def _unit_totals(self, unit_id: str) -> tuple[int, int]:
        committed = 0
        reserved = 0
        for record in self._reservations.values():
            if record.unit_id != unit_id:
                continue
            if record.committed:
                committed += record.size
            else:
                reserved += record.size
        return committed, reserved

    def _ordinary_total(self) -> int:
        return sum(
            record.size
            for record in self._reservations.values()
            if not self._units[record.unit_id].privileged
        )

    def _privileged_total(self) -> int:
        return sum(
            record.size
            for record in self._reservations.values()
            if self._units[record.unit_id].privileged
        )

    def _remember_now(self, text: object, value: datetime) -> None:
        self._last_now = value
        self._last_now_text = text if isinstance(text, str) else value.isoformat()

    @staticmethod
    def _validate_size(size: object) -> None:
        if not isinstance(size, int) or isinstance(size, bool) or size <= 0:
            raise MlockError("MLOCK_INVALID_REQUEST", {"field": "size"})

    @staticmethod
    def _validate_process_identity(
        pid: object,
        start_time: object,
        exe: object,
        *,
        require_exe: bool = True,
    ) -> None:
        if (not isinstance(pid, int) or isinstance(pid, bool) or pid <= 0
                or not isinstance(start_time, int)
                or isinstance(start_time, bool)
                or start_time < 0):
            raise MlockError(
                "MLOCK_INVALID_REQUEST",
                {"field": "process_identity", "pid": pid},
            )
        if require_exe and not isinstance(exe, str):
            raise MlockError("MLOCK_INVALID_REQUEST", {"field": "exe"})

    @staticmethod
    def _parse_time(value: object) -> datetime:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str) and value:
            text = value[:-1] + "+00:00" if value.endswith("Z") else value
            try:
                parsed = datetime.fromisoformat(text)
            except ValueError as error:
                raise MlockError(
                    "MLOCK_INVALID_REQUEST",
                    {"field": "now", "value": value},
                ) from error
        else:
            raise MlockError(
                "MLOCK_INVALID_REQUEST",
                {"field": "now", "value": value},
            )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    @staticmethod
    def _is_expired(record: _ReservationRecord, now_dt: datetime) -> bool:
        return MlockBudgetLedger._parse_time(record.expires_at) <= now_dt

    @staticmethod
    def _restore_int(value: object, field_name: str) -> int:
        if not isinstance(value, int) or isinstance(value, bool):
            raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": field_name})
        return value

    @classmethod
    def _restore_nonnegative_int(cls, value: object, field_name: str) -> int:
        result = cls._restore_int(value, field_name)
        if result < 0:
            raise MlockError("MLOCK_SNAPSHOT_INVALID", {"field": field_name})
        return result
