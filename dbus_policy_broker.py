"""Session bus policy broker: credentials, names, verdicts and pending calls."""

from __future__ import annotations

import copy
import fnmatch
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


try:  # pragma: no cover - platform dependent
    import grp
    import pwd
except ImportError:  # pragma: no cover
    grp = None
    pwd = None


class DbusPolicyError(ValueError):
    """Raised when a bus policy operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


SOURCES = ("system", "site")
SUBJECT_KINDS = ("user", "group")
MESSAGE_TYPES = ("method_call", "signal", "any")
VERDICTS = ("allow", "deny")
SNAPSHOT_FORMAT = 1
MAX_RULES = 10_000


@dataclass(frozen=True)
class Connection:
    conn_id: str
    unique_name: str
    uid: int
    pid: int
    groups: tuple[str, ...]


@dataclass(frozen=True)
class PolicyRule:
    source: str
    subject: str
    subject_kind: str
    target: str
    message_type: str
    verdict: str


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str
    source: str | None


@dataclass(frozen=True)
class NameRecord:
    name: str
    owner: str | None
    queue: tuple[str, ...]


@dataclass(frozen=True)
class PendingCall:
    conn_id: str
    seq: int
    target: str
    method: str
    started_at: str
    policy_version: int


def _parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        when = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        when = datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        when = datetime.fromisoformat(text)
    else:
        raise ValueError("time must be an ISO string, number or datetime")

    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when


def _pattern_matches(pattern: Any, value: Any) -> bool:
    pattern_text = "*" if pattern is None else str(pattern)
    value_text = "" if value is None else str(value)
    if pattern_text == "*":
        return True
    return fnmatch.fnmatchcase(value_text, pattern_text)


def _message_type_matches(rule_type: str, actual_type: str) -> bool:
    return rule_type == "any" or actual_type == "any" or rule_type == actual_type


def _normalize_groups(groups: Any) -> tuple[str, ...]:
    if groups is None:
        return ()
    if isinstance(groups, str):
        return (groups,)
    return tuple(str(group) for group in groups)


def _rule_from_mapping(raw: Any) -> PolicyRule:
    if isinstance(raw, PolicyRule):
        return raw
    if not isinstance(raw, dict):
        raise ValueError("policy rule must be a PolicyRule or mapping")

    return PolicyRule(
        source=raw["source"],
        subject=raw["subject"],
        subject_kind=raw["subject_kind"],
        target=raw["target"],
        message_type=raw["message_type"],
        verdict=raw["verdict"],
    )


def _validate_rule(rule: Any, index: int | None = None) -> PolicyRule:
    validated = _rule_from_mapping(rule)

    if not isinstance(validated.source, str) or validated.source not in SOURCES:
        raise DbusPolicyError(
            "DBUS_POLICY_INVALID",
            {"index": index, "field": "source", "value": validated.source},
        )
    if (
        not isinstance(validated.subject_kind, str)
        or validated.subject_kind not in SUBJECT_KINDS
    ):
        raise DbusPolicyError(
            "DBUS_POLICY_INVALID",
            {"index": index, "field": "subject_kind",
             "value": validated.subject_kind},
        )
    if (
        not isinstance(validated.message_type, str)
        or validated.message_type not in MESSAGE_TYPES
    ):
        raise DbusPolicyError(
            "DBUS_POLICY_INVALID",
            {"index": index, "field": "message_type",
             "value": validated.message_type},
        )
    if (
        not isinstance(validated.verdict, str)
        or validated.verdict not in VERDICTS
    ):
        raise DbusPolicyError(
            "DBUS_POLICY_INVALID",
            {"index": index, "field": "verdict", "value": validated.verdict},
        )
    if not isinstance(validated.subject, str) or not validated.subject:
        raise DbusPolicyError(
            "DBUS_POLICY_INVALID",
            {"index": index, "field": "subject", "value": validated.subject},
        )
    if not isinstance(validated.target, str) or not validated.target:
        raise DbusPolicyError(
            "DBUS_POLICY_INVALID",
            {"index": index, "field": "target", "value": validated.target},
        )
    return validated


class DbusPolicyBroker:
    """Authorize bus messages, hand out names and track pending calls."""

    MAX_RULES = MAX_RULES

    def __init__(self, *, max_connections: int = 64, max_names: int = 256,
                 call_timeout: int = 30) -> None:
        self.max_connections = max_connections
        self.max_names = max_names
        self.call_timeout = call_timeout
        self._lock = threading.RLock()
        self._connections: dict[str, Connection] = {}
        self._next_unique = 1
        self._rules: tuple[PolicyRule, ...] = ()
        self._version = 0
        self._names: dict[str, dict[str, Any]] = {}
        self._pending: dict[tuple[str, int], PendingCall] = {}
        self._counters = {
            "expired": 0,
            "deduplicated": 0,
            "denied": 0,
        }

    def add_connection(self, conn_id: str, *, uid: int, pid: int, groups=(),
                       now: str) -> Connection:
        with self._lock:
            if conn_id in self._connections:
                raise DbusPolicyError(
                    "DBUS_DUPLICATE_CONNECTION",
                    {"conn_id": conn_id},
                )
            if len(self._connections) >= self.max_connections:
                raise DbusPolicyError(
                    "DBUS_CAPACITY_EXCEEDED",
                    {
                        "resource": "connections",
                        "conn_id": conn_id,
                        "limit": self.max_connections,
                    },
                )

            unique_name = f":1.{self._next_unique}"
            self._next_unique += 1
            connection = Connection(
                conn_id=conn_id,
                unique_name=unique_name,
                uid=uid,
                pid=pid,
                groups=_normalize_groups(groups),
            )
            self._connections[conn_id] = connection
            return connection

    def remove_connection(self, conn_id: str, *, now: str) -> dict:
        with self._lock:
            connection = self._require_connection_locked(conn_id)
            del self._connections[conn_id]

            released_names: list[str] = []
            unqueued_names: list[str] = []
            transfers: list[dict[str, Any]] = []
            skipped: list[dict[str, Any]] = []

            for name, record in self._names.items():
                queue = record["queue"]
                if conn_id in queue:
                    queue.remove(conn_id)
                    unqueued_names.append(name)

                if record["owner"] == conn_id:
                    record["owner"] = None
                    released_names.append(name)
                    self._transfer_name_locked(
                        name, record, now, transfers, skipped
                    )

            cancelled_calls: list[dict[str, Any]] = []
            for key in list(self._pending):
                call = self._pending[key]
                if call.conn_id == conn_id:
                    del self._pending[key]
                    cancelled_calls.append({
                        "conn_id": call.conn_id,
                        "seq": call.seq,
                        "reason": "disconnected",
                    })

            return {
                **asdict(connection),
                "released_names": released_names,
                "names": released_names,
                "released": len(released_names),
                "unqueued_names": unqueued_names,
                "transfers": transfers,
                "transferred": {
                    item["name"]: item["conn_id"] for item in transfers
                },
                "skipped": skipped,
                "denied": skipped,
                "cancelled_calls": cancelled_calls,
                "pending_cancelled": len(cancelled_calls),
                "removed_at": now,
            }

    def load_policy(self, rules, *, now: str) -> int:
        try:
            rule_iter = iter(rules)
        except TypeError as exc:
            raise DbusPolicyError(
                "DBUS_POLICY_INVALID",
                {"reason": "rules_not_iterable"},
            ) from exc

        loaded_rules = []
        for index, rule in enumerate(rule_iter):
            if index >= self.MAX_RULES:
                raise DbusPolicyError(
                    "DBUS_CAPACITY_EXCEEDED",
                    {"resource": "rules", "limit": self.MAX_RULES},
                )
            loaded_rules.append(rule)

        validated = tuple(
            _validate_rule(rule, index)
            for index, rule in enumerate(loaded_rules)
        )
        if len(validated) > self.MAX_RULES:  # pragma: no cover - defensive
            raise DbusPolicyError(
                "DBUS_CAPACITY_EXCEEDED",
                {"resource": "rules", "limit": self.MAX_RULES},
            )

        with self._lock:
            self._rules = validated
            self._version += 1
            return self._version

    def evaluate_send(self, conn_id: str, *, target: str,
                      message_type: str = "method_call",
                      eavesdrop: bool = False, now: str) -> Verdict:
        with self._lock:
            connection = self._require_connection_locked(conn_id)
            verdict = self._decide_locked(
                connection,
                peer=target,
                message_type=message_type,
                eavesdrop=eavesdrop,
            )
            if not verdict.allowed:
                self._counters["denied"] += 1
            return verdict

    def evaluate_receive(self, conn_id: str, *, sender: str,
                         message_type: str = "method_call",
                         eavesdrop: bool = False, now: str) -> Verdict:
        with self._lock:
            connection = self._require_connection_locked(conn_id)
            verdict = self._decide_locked(
                connection,
                peer=sender,
                message_type=message_type,
                eavesdrop=eavesdrop,
            )
            if not verdict.allowed:
                self._counters["denied"] += 1
            return verdict

    def request_name(self, conn_id: str, name: str, *, now: str) -> str:
        with self._lock:
            self._require_connection_locked(conn_id)
            record = self._names.get(name)

            if record is None:
                if len(self._names) >= self.max_names:
                    raise DbusPolicyError(
                        "DBUS_CAPACITY_EXCEEDED",
                        {
                            "resource": "names",
                            "name": name,
                            "limit": self.max_names,
                        },
                    )
                self._names[name] = {
                    "owner": conn_id,
                    "queue": [],
                    "requested_at": now,
                }
                return "owner"

            if record["owner"] == conn_id:
                return "owner"

            queue = record["queue"]
            if conn_id in queue:
                return f"queued:{queue.index(conn_id) + 1}"

            if record["owner"] is None:
                record["owner"] = conn_id
                queue.clear()
                record["assigned_at"] = now
                return "owner"

            queue.append(conn_id)
            return f"queued:{queue.index(conn_id) + 1}"

    def release_name(self, conn_id: str, name: str, *, now: str) -> int:
        with self._lock:
            self._require_connection_locked(conn_id)
            record = self._names.get(name)
            if record is None or record["owner"] != conn_id:
                return 0

            record["owner"] = None
            record["queue"].clear()
            record["released_at"] = now
            return 1

    def names(self) -> list[NameRecord]:
        with self._lock:
            records = []
            for name in sorted(self._names):
                record = self._names[name]
                records.append(NameRecord(
                    name=name,
                    owner=record["owner"],
                    queue=tuple(record["queue"]),
                ))
            return records

    def record_call(self, conn_id: str, *, seq: int, target: str,
                    method: str, now: str) -> PendingCall:
        _parse_time(now)
        with self._lock:
            self._require_connection_locked(conn_id)
            key = (conn_id, seq)
            existing = self._pending.get(key)
            if existing is not None:
                self._counters["deduplicated"] += 1
                return existing

            call = PendingCall(
                conn_id=conn_id,
                seq=seq,
                target=target,
                method=method,
                started_at=now,
                policy_version=self._version,
            )
            self._pending[key] = call
            return call

    def expire_calls(self, *, now: str) -> list[dict]:
        when = _parse_time(now)
        expired: list[dict] = []

        with self._lock:
            for key in list(self._pending):
                call = self._pending[key]
                started = _parse_time(call.started_at)
                age = (when - started).total_seconds()
                if age <= self.call_timeout:
                    continue

                del self._pending[key]
                self._counters["expired"] += 1
                expired.append({"seq": call.seq, "reason": "timeout"})

            return expired

    def stats(self) -> dict:
        with self._lock:
            return {
                "connections": len(self._connections),
                "names": len(self._names),
                "rules_version": self._version,
                "pending": len(self._pending),
                "expired": self._counters["expired"],
                "deduplicated": self._counters["deduplicated"],
                "denied": self._counters["denied"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "snapshot_format": SNAPSHOT_FORMAT,
                "rules_version": self._version,
                "policy_version": self._version,
                "next_unique": self._next_unique,
                "connections": [
                    asdict(connection)
                    for connection in self._connections.values()
                ],
                "rules": [asdict(rule) for rule in self._rules],
                "names": [
                    {"name": name, **copy.deepcopy(record)}
                    for name, record in self._names.items()
                ],
                "pending": [asdict(call) for call in self._pending.values()],
                "counters": copy.deepcopy(self._counters),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        try:
            restored = self._normalize_snapshot(state)
        except DbusPolicyError as exc:
            if exc.code == "DBUS_SNAPSHOT_INVALID":
                raise
            raise DbusPolicyError(
                "DBUS_SNAPSHOT_INVALID",
                {"reason": exc.code, "detail": exc.detail},
            ) from exc
        except Exception as exc:
            raise DbusPolicyError(
                "DBUS_SNAPSHOT_INVALID",
                {"reason": exc.__class__.__name__},
            ) from exc

        with self._lock:
            self._version = restored["version"]
            self._next_unique = restored["next_unique"]
            self._connections = restored["connections"]
            self._rules = restored["rules"]
            self._names = restored["names"]
            self._pending = restored["pending"]
            self._counters = restored["counters"]

    def _require_connection_locked(self, conn_id: str) -> Connection:
        connection = self._connections.get(conn_id)
        if connection is None:
            raise DbusPolicyError(
                "DBUS_UNKNOWN_CONNECTION",
                {"conn_id": conn_id},
            )
        return connection

    def _decide_locked(self, connection: Connection, *, peer: str,
                       message_type: str, eavesdrop: bool) -> Verdict:
        matching_deny: PolicyRule | None = None
        matching_allow: PolicyRule | None = None

        for rule in self._rules:
            if not self._subject_matches(connection, rule):
                continue
            if not _pattern_matches(rule.target, peer):
                continue
            if not _message_type_matches(rule.message_type, message_type):
                continue

            if rule.verdict == "deny" and matching_deny is None:
                matching_deny = rule
            elif rule.verdict == "allow" and matching_allow is None:
                matching_allow = rule

        if matching_deny is not None:
            return Verdict(False, "rule_deny", matching_deny.source)

        if matching_allow is not None:
            return Verdict(True, "rule_allow", matching_allow.source)

        if eavesdrop:
            return Verdict(False, "eavesdrop_denied", None)

        return Verdict(True, "default_allow", None)

    def _subject_matches(self, connection: Connection,
                         rule: PolicyRule) -> bool:
        if rule.subject == "*":
            return True

        if rule.subject_kind == "group":
            groups = {str(group) for group in connection.groups}
            if rule.subject in groups:
                return True
            if grp is not None:
                try:
                    group_info = grp.getgrnam(rule.subject)
                except KeyError:
                    group_info = None
                if group_info is not None and str(group_info.gr_gid) in groups:
                    return True
            return False

        if rule.subject == str(connection.uid):
            return True

        if pwd is not None:
            try:
                if pwd.getpwnam(rule.subject).pw_uid == connection.uid:
                    return True
            except (KeyError, TypeError, ValueError):
                pass
            try:
                if pwd.getpwuid(connection.uid).pw_name == rule.subject:
                    return True
            except (KeyError, TypeError, ValueError):
                pass

        return False

    def _transfer_name_locked(self, name: str, record: dict[str, Any],
                               now: str, transfers: list[dict[str, Any]],
                               skipped: list[dict[str, Any]]) -> None:
        while record["queue"]:
            candidate = record["queue"].pop(0)
            if candidate not in self._connections:
                skipped.append({
                    "name": name,
                    "conn_id": candidate,
                    "reason": "unknown_connection",
                    "source": None,
                })
                continue

            verdict = self.evaluate_send(
                candidate,
                target=name,
                message_type="method_call",
                eavesdrop=False,
                now=now,
            )
            event = {
                "name": name,
                "conn_id": candidate,
                "reason": verdict.reason,
                "source": verdict.source,
            }
            if verdict.allowed:
                record["owner"] = candidate
                transfers.append(event)
                return

            skipped.append(event)

    def _normalize_snapshot(self, state: Any) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise ValueError("snapshot must be a dict")

        raw_version = state.get(
            "rules_version",
            state.get("policy_version", state.get("version")),
        )
        if isinstance(raw_version, bool) or not isinstance(raw_version, int):
            raise ValueError("rules_version must be an integer")
        if raw_version < 0:
            raise ValueError("rules_version must be non-negative")

        raw_next_unique = state.get("next_unique", 1)
        if isinstance(raw_next_unique, bool) or not isinstance(
            raw_next_unique, int
        ) or raw_next_unique < 1:
            raise ValueError("next_unique must be a positive integer")

        connections = self._connections_from_snapshot(
            state.get("connections", state.get("connection_table"))
        )
        if len(connections) > self.max_connections:
            raise ValueError("too many connections in snapshot")

        max_suffix = max(
            (self._unique_suffix(connection.unique_name)
             for connection in connections.values()),
            default=0,
        )
        next_unique = max(raw_next_unique, max_suffix + 1)

        raw_rules = state.get("rules", ())
        rules = tuple(
            _validate_rule(rule, index)
            for index, rule in enumerate(raw_rules)
        )
        if len(rules) > self.MAX_RULES:
            raise ValueError("too many rules in snapshot")

        names = self._names_from_snapshot(
            state.get("names", state.get("name_table")), connections
        )
        if len(names) > self.max_names:
            raise ValueError("too many names in snapshot")

        pending = self._pending_from_snapshot(
            state.get(
                "pending",
                state.get("pending_calls", state.get("calls", ())),
            ),
            raw_version,
        )
        counters = self._counters_from_snapshot(state.get("counters", {}))

        return {
            "version": raw_version,
            "next_unique": next_unique,
            "connections": connections,
            "rules": rules,
            "names": names,
            "pending": pending,
            "counters": counters,
        }

    @staticmethod
    def _unique_suffix(unique_name: Any) -> int:
        if not isinstance(unique_name, str) or not unique_name.startswith(":1."):
            return 0
        try:
            return int(unique_name.rsplit(".", 1)[1])
        except (IndexError, ValueError):
            return 0

    def _connections_from_snapshot(
        self, raw_connections: Any
    ) -> dict[str, Connection]:
        if raw_connections is None:
            raise ValueError("connections are required")

        if isinstance(raw_connections, dict):
            items: list[tuple[Any, Any]] = []
            for key, value in raw_connections.items():
                if isinstance(value, Connection):
                    items.append((value.conn_id, value))
                elif isinstance(value, dict):
                    data = dict(value)
                    data.setdefault("conn_id", key)
                    items.append((key, data))
                else:
                    raise ValueError("invalid connection snapshot")
        elif isinstance(raw_connections, (list, tuple)):
            items = []
            for value in raw_connections:
                if isinstance(value, Connection):
                    items.append((value.conn_id, value))
                elif isinstance(value, dict):
                    items.append((value.get("conn_id"), value))
                else:
                    raise ValueError("invalid connection snapshot")
        else:
            raise ValueError("connections must be a list or dict")

        connections: dict[str, Connection] = {}
        for key, value in items:
            if isinstance(value, Connection):
                connection = value
            else:
                conn_id = value["conn_id"]
                if key is not None and key != conn_id:
                    raise ValueError("connection id mismatch")
                connection = Connection(
                    conn_id=conn_id,
                    unique_name=value["unique_name"],
                    uid=value["uid"],
                    pid=value["pid"],
                    groups=_normalize_groups(value.get("groups", ())),
                )

            if not isinstance(connection.conn_id, str) or not connection.conn_id:
                raise ValueError("invalid connection id")
            if connection.conn_id in connections:
                raise ValueError("duplicate connection in snapshot")
            connections[connection.conn_id] = connection

        return connections

    def _names_from_snapshot(
        self, raw_names: Any, connections: dict[str, Connection]
    ) -> dict[str, dict[str, Any]]:
        if raw_names is None:
            return {}

        if isinstance(raw_names, dict):
            items = []
            for name, value in raw_names.items():
                if isinstance(value, NameRecord):
                    items.append((value.name, {
                        "owner": value.owner,
                        "queue": list(value.queue),
                    }))
                elif isinstance(value, dict):
                    data = dict(value)
                    data.setdefault("name", name)
                    items.append((name, data))
                else:
                    raise ValueError("invalid name snapshot")
        elif isinstance(raw_names, (list, tuple)):
            items = []
            for value in raw_names:
                if isinstance(value, NameRecord):
                    items.append((value.name, {
                        "owner": value.owner,
                        "queue": list(value.queue),
                    }))
                elif isinstance(value, dict):
                    items.append((value.get("name"), dict(value)))
                else:
                    raise ValueError("invalid name snapshot")
        else:
            raise ValueError("names must be a list or dict")

        names: dict[str, dict[str, Any]] = {}
        for expected_name, value in items:
            name = value["name"]
            if expected_name is not None and expected_name != name:
                raise ValueError("name record mismatch")
            if not isinstance(name, str) or not name:
                raise ValueError("invalid bus name")
            if name in names:
                raise ValueError("duplicate name in snapshot")

            owner = value.get("owner")
            if owner is not None and owner not in connections:
                raise ValueError("name owner is not snapshotted")

            raw_queue = value.get("queue", ())
            if not isinstance(raw_queue, (list, tuple)):
                raise ValueError("name queue must be a sequence")
            queue: list[str] = []
            for conn_id in raw_queue:
                if conn_id not in connections:
                    raise ValueError("queued connection is not snapshotted")
                if conn_id == owner or conn_id in queue:
                    raise ValueError("invalid name queue")
                queue.append(conn_id)

            names[name] = {"owner": owner, "queue": queue}

        return names

    def _pending_from_snapshot(
        self, raw_pending: Any, default_version: int
    ) -> dict[tuple[str, int], PendingCall]:
        if raw_pending is None:
            return {}
        if isinstance(raw_pending, dict):
            raw_values = raw_pending.values()
        elif isinstance(raw_pending, (list, tuple)):
            raw_values = raw_pending
        else:
            raise ValueError("pending calls must be a sequence or mapping")

        pending: dict[tuple[str, int], PendingCall] = {}
        for raw_call in raw_values:
            if isinstance(raw_call, PendingCall):
                call = raw_call
            elif isinstance(raw_call, dict):
                version = raw_call.get("policy_version", default_version)
                if isinstance(version, bool) or not isinstance(version, int):
                    raise ValueError("invalid pending policy version")
                call = PendingCall(
                    conn_id=raw_call["conn_id"],
                    seq=raw_call["seq"],
                    target=raw_call["target"],
                    method=raw_call["method"],
                    started_at=raw_call["started_at"],
                    policy_version=version,
                )
            else:
                raise ValueError("invalid pending call snapshot")

            if not isinstance(call.conn_id, str) or not call.conn_id:
                raise ValueError("invalid pending connection")
            if isinstance(call.seq, bool) or not isinstance(call.seq, int):
                raise ValueError("invalid pending sequence")
            _parse_time(call.started_at)

            key = (call.conn_id, call.seq)
            if key in pending:
                raise ValueError("duplicate pending call in snapshot")
            pending[key] = call

        return pending

    @staticmethod
    def _counters_from_snapshot(raw_counters: Any) -> dict[str, int]:
        if raw_counters is None:
            raw_counters = {}
        if not isinstance(raw_counters, dict):
            raise ValueError("counters must be a mapping")

        counters = {
            "expired": 0,
            "deduplicated": 0,
            "denied": 0,
        }
        for key in counters:
            value = raw_counters.get(key, 0)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"invalid counter: {key}")
            counters[key] = value
        return counters
