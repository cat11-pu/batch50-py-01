"""Seat access broker: session-bound device grants, active switch, crash residue sweep."""

from __future__ import annotations

import posixpath
import threading
from dataclasses import dataclass, field
from typing import NoReturn


_DEVICE_ROOT = "/dev/dri/"
_DEVICE_STATES = frozenset({"ready", "faulted"})
_COUNTER_KEYS = ("grants", "revokes", "switches", "swept", "refused")
_SNAPSHOT_KEYS = frozenset(
    {"version", "devices", "sessions", "grants", "counters", "audit"}
)


class SeatError(ValueError):
    """Raised when a seat access operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DeviceView:
    path: str
    state: str
    holder: str | None


@dataclass(frozen=True)
class SessionView:
    name: str
    seat: str
    active: bool
    alive: bool
    devices: tuple[str, ...]


@dataclass(frozen=True)
class SweepReport:
    removed: tuple[tuple[str, str], ...]
    kept: int


@dataclass(frozen=True)
class AuditEntry:
    op: str
    session: str
    device: str
    at: int


@dataclass
class _SessionRecord:
    name: str
    seat: str
    active: bool = False
    alive: bool = True
    devices: set[str] = field(default_factory=set)


def _require_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise SeatError("SEAT_INVALID_REQUEST", {"field": field_name})
    return value


def _normalize_device_path(path: object) -> str:
    if not isinstance(path, str):
        raise SeatError("SEAT_INVALID_REQUEST", {"path": path})
    normalized = posixpath.normpath(path)
    if not normalized.startswith(_DEVICE_ROOT):
        raise SeatError(
            "SEAT_INVALID_REQUEST",
            {"path": path, "normalized": normalized},
        )
    return normalized


def _require_snapshot_text(value: object, field_name: str) -> str:
    try:
        return _require_text(value, field_name)
    except SeatError as exc:
        raise SeatError("SEAT_SNAPSHOT_INVALID", exc.detail) from exc


class SeatAccessBroker:
    """Grant display device nodes to the session that currently owns a seat."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._sessions: dict[str, _SessionRecord] = {}
        self._devices: dict[str, str] = {}
        self._grants: dict[str, str] = {}
        self._audit: list[AuditEntry] = []
        self._counters = {key: 0 for key in _COUNTER_KEYS}

    def _refuse(self, code: str, detail: object = None) -> NoReturn:
        self._counters["refused"] += 1
        raise SeatError(code, detail)

    def _normalized_path_or_refuse(self, path: object) -> str:
        try:
            return _normalize_device_path(path)
        except SeatError:
            self._counters["refused"] += 1
            raise

    def register_session(self, name: str, *, seat: str, active: bool = False) -> None:
        _require_text(name, "name")
        _require_text(seat, "seat")
        with self._lock:
            if name in self._sessions:
                raise SeatError("SEAT_DUPLICATE_SESSION", {"session": name})
            self._sessions[name] = _SessionRecord(
                name=name,
                seat=seat,
                active=bool(active),
            )

    def register_device(self, path: str, *, state: str = "ready") -> None:
        normalized = _normalize_device_path(path)
        if not isinstance(state, str) or state not in _DEVICE_STATES:
            raise SeatError("SEAT_INVALID_REQUEST", {"state": state})
        with self._lock:
            if normalized in self._devices:
                raise SeatError("SEAT_DUPLICATE_DEVICE", {"device": normalized})
            self._devices[normalized] = state

    def set_device_state(self, path: str, *, state: str) -> None:
        with self._lock:
            normalized = self._normalized_path_or_refuse(path)
            if not isinstance(state, str) or state not in _DEVICE_STATES:
                self._refuse("SEAT_INVALID_REQUEST", {"state": state})
            if normalized not in self._devices:
                self._refuse("SEAT_UNKNOWN_DEVICE", {"device": normalized})
            self._devices[normalized] = state

    def set_session_alive(self, name: str, *, alive: bool) -> None:
        with self._lock:
            session = self._sessions.get(name)
            if session is None:
                self._refuse("SEAT_UNKNOWN_SESSION", {"session": name})
            session.alive = bool(alive)

    def set_session_active(self, name: str, *, active: bool) -> None:
        with self._lock:
            session = self._sessions.get(name)
            if session is None:
                self._refuse("SEAT_UNKNOWN_SESSION", {"session": name})
            session.active = bool(active)

    def attach_session(self, session: str, device: str, *, now: int) -> bool:
        with self._lock:
            path = self._normalized_path_or_refuse(device)
            record = self._sessions.get(session)
            if record is None:
                self._refuse("SEAT_UNKNOWN_SESSION", {"session": session})

            if path in record.devices:
                return False

            if not record.active:
                self._refuse("SEAT_SESSION_INACTIVE", {"session": session})
            if path not in self._devices:
                self._refuse("SEAT_UNKNOWN_DEVICE", {"device": path})

            holder = self._grants.get(path)
            if holder is not None:
                self._refuse(
                    "SEAT_DEVICE_BUSY",
                    {"device": path, "holder": holder},
                )
            if self._devices[path] == "faulted":
                self._refuse("SEAT_DEVICE_FAULTED", {"device": path})

            self._grants[path] = record.name
            record.devices.add(path)
            self._audit.append(AuditEntry("grant", record.name, path, now))
            self._counters["grants"] += 1
            return True

    def detach_session(
        self,
        session: str,
        *,
        now: int,
        device: str | None = None,
    ) -> int:
        with self._lock:
            record = self._sessions.get(session)
            if record is None:
                self._refuse("SEAT_UNKNOWN_SESSION", {"session": session})

            if device is not None:
                path = self._normalized_path_or_refuse(device)
                if path not in self._devices:
                    self._refuse("SEAT_UNKNOWN_DEVICE", {"device": path})
                paths = [path]
            else:
                paths = sorted(record.devices)

            revoked = 0
            for path in paths:
                if self._grants.get(path) != record.name:
                    continue
                del self._grants[path]
                record.devices.discard(path)
                self._audit.append(AuditEntry("revoke", record.name, path, now))
                self._counters["revokes"] += 1
                revoked += 1
            return revoked

    def switch_active(self, seat: str, session: str, *, now: int) -> dict:
        with self._lock:
            seat_sessions = [
                record
                for record in self._sessions.values()
                if record.seat == seat
            ]
            if not seat_sessions:
                self._refuse("SEAT_UNKNOWN_SEAT", {"seat": seat})

            target = self._sessions.get(session)
            if target is None:
                self._refuse("SEAT_UNKNOWN_SESSION", {"session": session})
            if target.seat != seat:
                self._refuse(
                    "SEAT_WRONG_SEAT",
                    {"seat": seat, "session": session, "session_seat": target.seat},
                )

            active_records = [record for record in seat_sessions if record.active]
            if len(active_records) == 1 and active_records[0].name == target.name:
                return {"revoked": 0, "granted": 0, "session": target.name}

            old_records = [
                record for record in active_records if record.name != target.name
            ]
            old_names = {record.name for record in old_records}
            transfers = sorted(
                (path, owner)
                for path, owner in self._grants.items()
                if owner in old_names
            )

            for path, owner in transfers:
                if self._devices.get(path) is None:
                    self._refuse("SEAT_UNKNOWN_DEVICE", {"device": path})
                if self._devices[path] == "faulted":
                    self._refuse("SEAT_DEVICE_FAULTED", {"device": path})
                if self._grants.get(path) != owner:
                    self._refuse(
                        "SEAT_DEVICE_BUSY",
                        {"device": path, "holder": self._grants.get(path)},
                    )

            revoked = 0
            for path, owner in transfers:
                owner_record = self._sessions[owner]
                if self._grants.get(path) != owner:
                    continue
                del self._grants[path]
                owner_record.devices.discard(path)
                self._audit.append(AuditEntry("revoke", owner, path, now))
                self._counters["revokes"] += 1
                revoked += 1

            for record in old_records:
                record.active = False
            target.active = True

            granted = 0
            for path, _owner in transfers:
                self._grants[path] = target.name
                target.devices.add(path)
                self._audit.append(AuditEntry("grant", target.name, path, now))
                self._counters["grants"] += 1
                granted += 1

            self._counters["switches"] += 1
            return {
                "revoked": revoked,
                "granted": granted,
                "session": target.name,
            }

    def holders(self, device: str | None = None):
        with self._lock:
            if device is None:
                return {
                    path: self._grants[path]
                    for path in sorted(self._grants)
                }
            path = self._normalized_path_or_refuse(device)
            if path not in self._devices:
                self._refuse("SEAT_UNKNOWN_DEVICE", {"device": path})
            return self._grants.get(path)

    def session_view(self, name: str) -> SessionView:
        with self._lock:
            record = self._sessions.get(name)
            if record is None:
                self._refuse("SEAT_UNKNOWN_SESSION", {"session": name})
            return SessionView(
                name=record.name,
                seat=record.seat,
                active=record.active,
                alive=record.alive,
                devices=tuple(sorted(record.devices)),
            )

    def device_view(self, path: str) -> DeviceView:
        with self._lock:
            normalized = self._normalized_path_or_refuse(path)
            state = self._devices.get(normalized)
            if state is None:
                self._refuse("SEAT_UNKNOWN_DEVICE", {"device": normalized})
            return DeviceView(
                path=normalized,
                state=state,
                holder=self._grants.get(normalized),
            )

    def sweep(self, *, now: int) -> SweepReport:
        with self._lock:
            removed = []
            for path in sorted(self._grants):
                owner = self._grants[path]
                record = self._sessions.get(owner)
                if record is None or not record.alive:
                    removed.append((path, owner))

            for path, owner in removed:
                if self._grants.get(path) == owner:
                    del self._grants[path]
                record = self._sessions.get(owner)
                if record is not None:
                    record.devices.discard(path)

            self._counters["swept"] += len(removed)
            return SweepReport(
                removed=tuple(removed),
                kept=len(self._grants),
            )

    def audit_log(self) -> tuple[AuditEntry, ...]:
        with self._lock:
            return tuple(self._audit)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "devices": {
                    path: self._devices[path]
                    for path in sorted(self._devices)
                },
                "sessions": {
                    name: {
                        "seat": record.seat,
                        "active": record.active,
                        "alive": record.alive,
                    }
                    for name, record in sorted(self._sessions.items())
                },
                "grants": {
                    path: self._grants[path]
                    for path in sorted(self._grants)
                },
                "counters": dict(self._counters),
                "audit": [
                    {
                        "op": entry.op,
                        "session": entry.session,
                        "device": entry.device,
                        "at": entry.at,
                    }
                    for entry in self._audit
                ],
            }

    @staticmethod
    def _invalid_snapshot(detail: object = None) -> NoReturn:
        raise SeatError("SEAT_SNAPSHOT_INVALID", detail)

    @classmethod
    def _parse_snapshot(
        cls, state: object
    ) -> tuple[
        dict[str, str],
        dict[str, _SessionRecord],
        dict[str, str],
        dict[str, int],
        list[AuditEntry],
    ]:
        if not isinstance(state, dict):
            cls._invalid_snapshot({"reason": "snapshot_not_object"})
        if frozenset(state) != _SNAPSHOT_KEYS:
            cls._invalid_snapshot({"reason": "top_level_keys"})

        version = state.get("version")
        if type(version) is not int or version != 1:
            cls._invalid_snapshot({"reason": "version"})

        raw_devices = state.get("devices")
        if not isinstance(raw_devices, dict):
            cls._invalid_snapshot({"field": "devices"})

        devices: dict[str, str] = {}
        for raw_path, raw_device in raw_devices.items():
            try:
                path = _normalize_device_path(raw_path)
            except SeatError:
                cls._invalid_snapshot({"field": "devices", "path": raw_path})
            if path in devices:
                cls._invalid_snapshot({"field": "devices", "duplicate": path})

            if isinstance(raw_device, str):
                device_state = raw_device
            elif isinstance(raw_device, dict):
                device_state = raw_device.get("state")
            else:
                cls._invalid_snapshot({"field": "devices", "path": path})

            if (
                not isinstance(device_state, str)
                or device_state not in _DEVICE_STATES
            ):
                cls._invalid_snapshot({"field": "device_state", "path": path})
            devices[path] = device_state

        raw_sessions = state.get("sessions")
        if not isinstance(raw_sessions, dict):
            cls._invalid_snapshot({"field": "sessions"})

        sessions: dict[str, _SessionRecord] = {}
        for raw_name, raw_session in raw_sessions.items():
            name = _require_snapshot_text(raw_name, "session")
            if not isinstance(raw_session, dict):
                cls._invalid_snapshot({"field": "sessions", "session": name})
            if not {"seat", "active", "alive"} <= frozenset(raw_session):
                cls._invalid_snapshot({"field": "session_fields", "session": name})

            seat = _require_snapshot_text(raw_session.get("seat"), "seat")
            active = raw_session.get("active")
            alive = raw_session.get("alive")
            if type(active) is not bool or type(alive) is not bool:
                cls._invalid_snapshot({"field": "session_flags", "session": name})

            sessions[name] = _SessionRecord(
                name=name,
                seat=seat,
                active=active,
                alive=alive,
            )

        raw_grants = state.get("grants")
        if not isinstance(raw_grants, dict):
            cls._invalid_snapshot({"field": "grants"})

        grants: dict[str, str] = {}
        for raw_path, owner in raw_grants.items():
            try:
                path = _normalize_device_path(raw_path)
            except SeatError:
                cls._invalid_snapshot({"field": "grants", "path": raw_path})
            if path in grants:
                cls._invalid_snapshot({"field": "grants", "duplicate": path})
            if not isinstance(owner, str) or owner not in sessions:
                cls._invalid_snapshot({"field": "grants", "owner": owner})
            if path not in devices:
                cls._invalid_snapshot({"field": "grants", "device": path})

            grants[path] = owner
            sessions[owner].devices.add(path)

        raw_counters = state.get("counters")
        if not isinstance(raw_counters, dict):
            cls._invalid_snapshot({"field": "counters"})
        if frozenset(raw_counters) != frozenset(_COUNTER_KEYS):
            cls._invalid_snapshot({"field": "counter_keys"})

        counters: dict[str, int] = {}
        for key in _COUNTER_KEYS:
            value = raw_counters.get(key)
            if type(value) is not int or value < 0:
                cls._invalid_snapshot({"field": "counter", "name": key})
            counters[key] = value

        raw_audit = state.get("audit")
        if not isinstance(raw_audit, (list, tuple)):
            cls._invalid_snapshot({"field": "audit"})

        audit: list[AuditEntry] = []
        for raw_entry in raw_audit:
            op = session_name = device = at = None
            if isinstance(raw_entry, AuditEntry):
                op = raw_entry.op
                session_name = raw_entry.session
                device = raw_entry.device
                at = raw_entry.at
            elif isinstance(raw_entry, dict):
                try:
                    op = raw_entry["op"]
                    session_name = raw_entry["session"]
                    device = raw_entry["device"]
                    at = raw_entry["at"]
                except (KeyError, TypeError):
                    cls._invalid_snapshot({"field": "audit_entry"})
            elif isinstance(raw_entry, (list, tuple)) and len(raw_entry) == 4:
                op, session_name, device, at = raw_entry
            else:
                cls._invalid_snapshot({"field": "audit_entry"})

            if (
                not isinstance(op, str)
                or not isinstance(session_name, str)
                or not isinstance(device, str)
                or type(at) is not int
            ):
                cls._invalid_snapshot({"field": "audit_entry_values"})
            audit.append(AuditEntry(op, session_name, device, at))

        return devices, sessions, grants, counters, audit

    def restore(self, state: dict) -> None:
        devices, sessions, grants, counters, audit = self._parse_snapshot(state)
        with self._lock:
            self._devices = devices
            self._sessions = sessions
            self._grants = grants
            self._counters = counters
            self._audit = audit

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)
