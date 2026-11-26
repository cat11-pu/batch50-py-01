"""Name reservation book: atomic claims, retention window and rename cooldown.

Names are owned by exactly one account at a time.  Releasing a name parks it
in a retention window during which only the previous owner can take it back;
a rename holds the new name before dropping the old one and starts a cooldown.
"""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import dataclass

__all__ = [
    "ReservationError",
    "NameState",
    "RenameResult",
    "HistoryEntry",
    "NameReservation",
]

_NAME_PATTERN = re.compile(r"^[a-z][a-z0-9_]{2,15}$")
_ACTIONS = {"reserve", "release", "rename"}
_COUNTER_KEYS = {"reserved", "released", "renamed", "expired"}
_SNAPSHOT_KEYS = {
    "version",
    "names",
    "history",
    "cooldowns",
    "requests",
    "counters",
}
_NAME_FIELDS = {"name", "status", "owner", "held_until", "last_owner"}
_RENAME_FIELDS = {
    "account",
    "old_name",
    "new_name",
    "renamed",
    "replayed",
    "cooldown_until",
}


class ReservationError(ValueError):
    """Raised when a reservation operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class NameState:
    """Immutable view of one name slot."""

    name: str
    status: str
    owner: str | None
    held_until: int | None
    last_owner: str | None


@dataclass(frozen=True)
class RenameResult:
    """Result of one rename request."""

    account: str
    old_name: str
    new_name: str
    renamed: bool
    replayed: bool
    cooldown_until: int


@dataclass(frozen=True)
class HistoryEntry:
    """One historical ownership event."""

    name: str
    account: str
    action: str
    at: int


class NameReservation:
    """Allocate names, recycle them after retention and throttle renames."""

    def __init__(self, *, retention: int = 604800,
                 rename_cooldown: int = 2592000,
                 max_history: int = 200) -> None:
        self.retention = retention
        self.rename_cooldown = rename_cooldown
        self.max_history = max_history
        self._lock = threading.RLock()
        self._names: dict[str, dict] = {}
        self._history: dict[str, list[HistoryEntry]] = {}
        self._cooldowns: dict[str, int] = {}
        self._requests: dict[object, dict] = {}
        self._counters = {
            "reserved": 0,
            "released": 0,
            "renamed": 0,
            "expired": 0,
        }

    def reserve(self, name: str, account: str, *, now: int,
                request_id: str | None = None) -> NameState:
        with self._lock:
            self._validate_name(name)
            self._validate_account(account)

            replayed = self._find_request(
                request_id, "reserve", name=name, account=account
            )
            if replayed is not None:
                return self._name_state(replayed)

            record = self._names.get(name)
            if record is not None and record["status"] == "active":
                if record["owner"] != account:
                    raise ReservationError("NAME_TAKEN", {"name": name})
                result = self._name_state(record)
                self._remember_request(request_id, {
                    "kind": "reserve",
                    "name": name,
                    "account": account,
                    "result": self._name_state_dict(result),
                })
                return result

            if record is not None and record["status"] == "retention":
                if record["last_owner"] != account:
                    raise ReservationError(
                        "NAME_RETENTION_HELD",
                        {"name": name, "held_until": record["held_until"]},
                    )
                record["status"] = "active"
                record["owner"] = account
                record["held_until"] = None
            elif record is not None:
                record["status"] = "active"
                record["owner"] = account
                record["held_until"] = None
            else:
                record = self._new_record(name, "active", owner=account)
                self._names[name] = record

            self._append_history(name, account, "reserve", now)
            self._counters["reserved"] += 1
            result = self._name_state(record)
            self._remember_request(request_id, {
                "kind": "reserve",
                "name": name,
                "account": account,
                "result": self._name_state_dict(result),
            })
            return result

    def release(self, name: str, account: str, *, now: int) -> NameState:
        with self._lock:
            self._validate_name(name)
            self._validate_account(account)

            record = self._names.get(name)
            if record is None or record["status"] != "active":
                code = ("NAME_NOT_OWNER" if record is not None
                        and record["status"] == "retention"
                        else "NAME_NOT_FOUND")
                raise ReservationError(code, {"name": name})
            if record["owner"] != account:
                raise ReservationError(
                    "NAME_NOT_OWNER", {"name": name, "owner": record["owner"]}
                )

            record["status"] = "retention"
            record["owner"] = None
            record["held_until"] = now + self.retention
            record["last_owner"] = account
            self._append_history(name, account, "release", now)
            self._counters["released"] += 1
            return self._name_state(record)

    def rename(self, account: str, new_name: str, *, now: int,
               request_id: str | None = None) -> RenameResult:
        with self._lock:
            self._validate_account(account)
            self._validate_name(new_name)

            replayed = self._find_request(
                request_id, "rename", account=account, new_name=new_name
            )
            if replayed is not None:
                return RenameResult(
                    account=replayed["account"],
                    old_name=replayed["old_name"],
                    new_name=replayed["new_name"],
                    renamed=replayed["renamed"],
                    replayed=True,
                    cooldown_until=replayed["cooldown_until"],
                )

            old_name = None
            for candidate in reversed(self._names):
                record = self._names[candidate]
                if record["status"] == "active" and record["owner"] == account:
                    old_name = candidate
                    break
            if old_name is None:
                raise ReservationError("NAME_NOT_FOUND", {"account": account})

            current_cooldown = self._cooldowns.get(account)
            if current_cooldown is not None and now < current_cooldown:
                raise ReservationError(
                    "NAME_COOLDOWN",
                    {"account": account, "ready_at": current_cooldown},
                )

            if new_name == old_name:
                result = RenameResult(
                    account=account,
                    old_name=old_name,
                    new_name=new_name,
                    renamed=False,
                    replayed=False,
                    cooldown_until=current_cooldown or 0,
                )
                self._remember_request(request_id, {
                    "kind": "rename",
                    "account": account,
                    "new_name": new_name,
                    "result": self._rename_result_dict(result),
                })
                return result

            target = self._names.get(new_name)
            if target is not None and target["status"] == "active":
                raise ReservationError("NAME_TAKEN", {"name": new_name})
            if target is not None and target["status"] == "retention":
                if target["last_owner"] != account:
                    raise ReservationError(
                        "NAME_RETENTION_HELD",
                        {"name": new_name, "held_until": target["held_until"]},
                    )

            old_record = copy.deepcopy(self._names[old_name])
            target_record = copy.deepcopy(target) if target is not None else None
            had_target_history = new_name in self._history
            had_old_history = old_name in self._history
            target_history_len = len(self._history.get(new_name, ()))
            old_history_len = len(self._history.get(old_name, ()))
            renamed_before = self._counters["renamed"]

            try:
                if target is None:
                    target = self._new_record(new_name, "active", owner=account)
                    self._names[new_name] = target
                else:
                    target["status"] = "active"
                    target["owner"] = account
                    target["held_until"] = None

                self._append_history(new_name, account, "rename", now)

                current = self._names[old_name]
                current["status"] = "retention"
                current["owner"] = None
                current["held_until"] = now + self.retention
                current["last_owner"] = account
                self._append_history(old_name, account, "rename", now)

                cooldown_until = now + self.rename_cooldown
                self._cooldowns[account] = cooldown_until
                self._counters["renamed"] += 1
                result = RenameResult(
                    account=account,
                    old_name=old_name,
                    new_name=new_name,
                    renamed=True,
                    replayed=False,
                    cooldown_until=cooldown_until,
                )
                self._remember_request(request_id, {
                    "kind": "rename",
                    "account": account,
                    "new_name": new_name,
                    "result": self._rename_result_dict(result),
                })
                return result
            except Exception as exc:
                if target_record is None:
                    self._names.pop(new_name, None)
                else:
                    self._names[new_name] = target_record
                self._names[old_name] = old_record
                self._trim_history(
                    new_name, target_history_len, had_target_history
                )
                self._trim_history(old_name, old_history_len, had_old_history)
                if current_cooldown is None:
                    self._cooldowns.pop(account, None)
                else:
                    self._cooldowns[account] = current_cooldown
                self._counters["renamed"] = renamed_before
                if isinstance(exc, ReservationError):
                    raise
                raise ReservationError(
                    "NAME_RENAME_FAILED", {"error": str(exc)}
                ) from exc

    def lookup(self, name: str) -> str:
        with self._lock:
            self._validate_name(name)
            record = self._names.get(name)
            return record["status"] if record is not None else "free"

    def owner_of(self, name: str) -> str | None:
        with self._lock:
            self._validate_name(name)
            record = self._names.get(name)
            if record is None or record["status"] != "active":
                return None
            return record["owner"]

    def expire_sweep(self, *, now: int) -> int:
        with self._lock:
            expired = 0
            for record in self._names.values():
                if (record["status"] == "retention"
                        and record["held_until"] is not None
                        and record["held_until"] <= now):
                    record["status"] = "free"
                    record["owner"] = None
                    record["held_until"] = None
                    expired += 1
            self._counters["expired"] += expired
            return expired

    def history_of(self, name: str) -> tuple[HistoryEntry, ...]:
        with self._lock:
            self._validate_name(name)
            return tuple(self._history.get(name, ()))

    def rename_ready_at(self, account: str) -> int | None:
        with self._lock:
            self._validate_account(account)
            return self._cooldowns.get(account)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "names": {
                    name: dict(record)
                    for name, record in self._names.items()
                },
                "history": {
                    name: [
                        {
                            "name": entry.name,
                            "account": entry.account,
                            "action": entry.action,
                            "at": entry.at,
                        }
                        for entry in entries
                    ]
                    for name, entries in self._history.items()
                },
                "cooldowns": dict(self._cooldowns),
                "requests": copy.deepcopy(self._requests),
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except ReservationError as exc:
                if exc.code == "NAME_SNAPSHOT_INVALID":
                    raise
                raise ReservationError(
                    "NAME_SNAPSHOT_INVALID", {"error": exc.code}
                ) from exc
            except Exception as exc:
                raise ReservationError(
                    "NAME_SNAPSHOT_INVALID", {"error": str(exc)}
                ) from exc

            names, history, cooldowns, requests, counters = parsed
            self._names = names
            self._history = history
            self._cooldowns = cooldowns
            self._requests = requests
            self._counters = counters

    def stats(self) -> dict:
        with self._lock:
            return {
                "reserved": self._counters["reserved"],
                "released": self._counters["released"],
                "renamed": self._counters["renamed"],
                "expired": self._counters["expired"],
                "active": sum(
                    record["status"] == "active"
                    for record in self._names.values()
                ),
                "retention": sum(
                    record["status"] == "retention"
                    for record in self._names.values()
                ),
            }

    @staticmethod
    def _validate_name(name: object) -> None:
        if not isinstance(name, str) or _NAME_PATTERN.fullmatch(name) is None:
            raise ReservationError("NAME_INVALID", {"name": name})

    @staticmethod
    def _validate_account(account: object) -> None:
        if not isinstance(account, str) or not account.strip():
            raise ReservationError("NAME_INVALID", {"account": account})

    @staticmethod
    def _new_record(name: str, status: str, *, owner: str | None = None,
                    held_until: int | None = None,
                    last_owner: str | None = None) -> dict:
        return {
            "name": name,
            "status": status,
            "owner": owner,
            "held_until": held_until,
            "last_owner": last_owner,
        }

    @staticmethod
    def _name_state(record: dict) -> NameState:
        return NameState(
            name=record["name"],
            status=record["status"],
            owner=record["owner"],
            held_until=record["held_until"],
            last_owner=record["last_owner"],
        )

    @staticmethod
    def _name_state_dict(state: NameState) -> dict:
        return {
            "name": state.name,
            "status": state.status,
            "owner": state.owner,
            "held_until": state.held_until,
            "last_owner": state.last_owner,
        }

    @staticmethod
    def _rename_result_dict(result: RenameResult) -> dict:
        return {
            "account": result.account,
            "old_name": result.old_name,
            "new_name": result.new_name,
            "renamed": result.renamed,
            "replayed": result.replayed,
            "cooldown_until": result.cooldown_until,
        }

    def _append_history(self, name: str, account: str, action: str,
                        at: int) -> None:
        entries = self._history.setdefault(name, [])
        entries.append(HistoryEntry(name, account, action, at))
        if self.max_history <= 0:
            entries.clear()
        elif len(entries) > self.max_history:
            del entries[:len(entries) - self.max_history]

    def _remember_request(self, request_id: object, record: dict) -> None:
        if request_id is not None:
            self._requests[request_id] = copy.deepcopy(record)

    def _find_request(self, request_id: object, kind: str,
                      **signature: object) -> dict | None:
        if request_id is None:
            return None
        record = self._requests.get(request_id)
        if record is None:
            return None
        matches = record["kind"] == kind and all(
            record.get(key) == value for key, value in signature.items()
        )
        if not matches:
            raise ReservationError(
                "NAME_REQUEST_CONFLICT", {"request_id": request_id}
            )
        return copy.deepcopy(record["result"])

    def _trim_history(self, name: str, length: int, existed: bool) -> None:
        if not existed:
            self._history.pop(name, None)
            return
        entries = self._history.get(name)
        if entries is not None:
            del entries[length:]

    @classmethod
    def _parse_snapshot(cls, state: object):
        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            raise ReservationError("NAME_SNAPSHOT_INVALID", "schema")
        if type(state["version"]) is not int or state["version"] != 1:
            raise ReservationError("NAME_SNAPSHOT_INVALID", "version")

        raw_names = state["names"]
        raw_history = state["history"]
        raw_cooldowns = state["cooldowns"]
        raw_requests = state["requests"]
        raw_counters = state["counters"]
        if not all(isinstance(value, dict) for value in (
            raw_names, raw_history, raw_cooldowns, raw_requests,
            raw_counters,
        )):
            raise ReservationError("NAME_SNAPSHOT_INVALID", "mapping")

        names = {}
        for name, record in raw_names.items():
            cls._validate_name(name)
            parsed = cls._parse_name_record(record)
            if parsed["name"] != name:
                raise ReservationError("NAME_SNAPSHOT_INVALID", "name key")
            names[name] = parsed

        history = {}
        for name, entries in raw_history.items():
            cls._validate_name(name)
            if not isinstance(entries, list):
                raise ReservationError(
                    "NAME_SNAPSHOT_INVALID", "history entries"
                )
            parsed_entries = []
            for entry in entries:
                if (not isinstance(entry, dict)
                        or set(entry) != {"name", "account", "action", "at"}):
                    raise ReservationError(
                        "NAME_SNAPSHOT_INVALID", "history entry"
                    )
                cls._validate_name(entry["name"])
                cls._validate_account(entry["account"])
                if entry["action"] not in _ACTIONS:
                    raise ReservationError(
                        "NAME_SNAPSHOT_INVALID", "history action"
                    )
                if type(entry["at"]) is not int:
                    raise ReservationError(
                        "NAME_SNAPSHOT_INVALID", "history time"
                    )
                if entry["name"] != name:
                    raise ReservationError(
                        "NAME_SNAPSHOT_INVALID", "history name key"
                    )
                parsed_entries.append(HistoryEntry(
                    entry["name"], entry["account"], entry["action"],
                    entry["at"],
                ))
            history[name] = parsed_entries

        cooldowns = {}
        for account, until in raw_cooldowns.items():
            cls._validate_account(account)
            if type(until) is not int:
                raise ReservationError(
                    "NAME_SNAPSHOT_INVALID", "cooldown"
                )
            cooldowns[account] = until

        requests = {}
        for request_id, record in raw_requests.items():
            if not isinstance(request_id, str) or not isinstance(record, dict):
                raise ReservationError(
                    "NAME_SNAPSHOT_INVALID", "request"
                )
            requests[request_id] = cls._parse_request(record)

        if set(raw_counters) != _COUNTER_KEYS:
            raise ReservationError(
                "NAME_SNAPSHOT_INVALID", "counters"
            )
        counters = {}
        for key, value in raw_counters.items():
            if type(value) is not int or value < 0:
                raise ReservationError(
                    "NAME_SNAPSHOT_INVALID", "counter value"
                )
            counters[key] = value

        return names, history, cooldowns, requests, counters

    @classmethod
    def _parse_name_record(cls, record: object) -> dict:
        if not isinstance(record, dict) or set(record) != _NAME_FIELDS:
            raise ReservationError("NAME_SNAPSHOT_INVALID", "name record")

        name = record["name"]
        status = record["status"]
        owner = record["owner"]
        held_until = record["held_until"]
        last_owner = record["last_owner"]
        cls._validate_name(name)
        if status not in {"active", "retention", "free"}:
            raise ReservationError("NAME_SNAPSHOT_INVALID", "name status")
        if owner is not None:
            cls._validate_account(owner)
        if last_owner is not None:
            cls._validate_account(last_owner)
        if held_until is not None and type(held_until) is not int:
            raise ReservationError("NAME_SNAPSHOT_INVALID", "held until")

        if status == "active":
            if owner is None or held_until is not None:
                raise ReservationError(
                    "NAME_SNAPSHOT_INVALID", "active record"
                )
        elif status == "retention":
            if owner is not None or held_until is None or last_owner is None:
                raise ReservationError(
                    "NAME_SNAPSHOT_INVALID", "retention record"
                )
        elif owner is not None or held_until is not None:
            raise ReservationError(
                "NAME_SNAPSHOT_INVALID", "free record"
            )

        return cls._new_record(
            name, status, owner=owner, held_until=held_until,
            last_owner=last_owner,
        )

    @classmethod
    def _parse_request(cls, record: dict) -> dict:
        kind = record.get("kind")
        if kind == "reserve":
            if set(record) != {"kind", "name", "account", "result"}:
                raise ReservationError(
                    "NAME_SNAPSHOT_INVALID", "reserve request"
                )
            cls._validate_name(record["name"])
            cls._validate_account(record["account"])
            result = cls._parse_name_record(record["result"])
            return {
                "kind": "reserve",
                "name": record["name"],
                "account": record["account"],
                "result": result,
            }
        if kind == "rename":
            if set(record) != {"kind", "account", "new_name", "result"}:
                raise ReservationError(
                    "NAME_SNAPSHOT_INVALID", "rename request"
                )
            cls._validate_account(record["account"])
            cls._validate_name(record["new_name"])
            result = record["result"]
            if not isinstance(result, dict) or set(result) != _RENAME_FIELDS:
                raise ReservationError(
                    "NAME_SNAPSHOT_INVALID", "rename result"
                )
            cls._validate_account(result["account"])
            cls._validate_name(result["old_name"])
            cls._validate_name(result["new_name"])
            if (type(result["renamed"]) is not bool
                    or type(result["replayed"]) is not bool
                    or type(result["cooldown_until"]) is not int):
                raise ReservationError(
                    "NAME_SNAPSHOT_INVALID", "rename result types"
                )
            if (result["account"] != record["account"]
                    or result["new_name"] != record["new_name"]):
                raise ReservationError(
                    "NAME_SNAPSHOT_INVALID", "rename request mapping"
                )
            return {
                "kind": "rename",
                "account": record["account"],
                "new_name": record["new_name"],
                "result": dict(result),
            }
        raise ReservationError("NAME_SNAPSHOT_INVALID", "request kind")
