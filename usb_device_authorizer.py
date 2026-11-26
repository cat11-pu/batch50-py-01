"""USB device authorization: interface rules, fingerprints and temporary grants."""

from __future__ import annotations

import copy
import hashlib
import json
import threading
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone


ERR_INVALID_REQUEST = "USB_INVALID_REQUEST"
ERR_RULE_DUPLICATE = "USB_RULE_DUPLICATE"
ERR_RULE_UNKNOWN = "USB_RULE_UNKNOWN"
ERR_DEVICE_UNKNOWN = "USB_DEVICE_UNKNOWN"
ERR_NOT_AUTHORIZED = "USB_NOT_AUTHORIZED"
ERR_HANDLE_DUPLICATE = "USB_HANDLE_DUPLICATE"
ERR_SNAPSHOT_INVALID = "USB_SNAPSHOT_INVALID"

_STATES = frozenset(
    ("pending", "authorized", "temp", "denied", "revoked", "expired")
)
_STAT_KEYS = (
    "inserts",
    "deduped",
    "prompts",
    "authorized",
    "denied",
    "revoked",
    "expired",
    "handles_opened",
)
_TERMINAL_REUSE_STATES = frozenset(("revoked", "expired"))


class UsbError(ValueError):
    """Raised when a USB authorization step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Rule:
    rule_id: str
    vid: int
    pid: object
    serial: object
    interfaces: tuple
    decision: str
    ttl: object


@dataclass(frozen=True)
class DeviceRecord:
    fingerprint: str
    vid: int
    pid: int
    serial: object
    interfaces: tuple
    port_path: str
    state: str
    expires_at: object
    matched_rule: object
    prompt: bool


@dataclass(frozen=True)
class ExpireReport:
    revoked: int
    handles_closed: int


def _invalid_request(detail: object = None) -> UsbError:
    return UsbError(ERR_INVALID_REQUEST, detail)


def _normalize_int(value, *, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise _invalid_request(f"{name} must be an integer")
    if not 0 <= value <= 0xFFFF:
        raise _invalid_request(f"{name} is out of range")
    return value


def _normalize_serial(serial):
    if serial is None:
        return None
    if isinstance(serial, str):
        return serial if serial else None
    return str(serial)


def _normalize_interfaces(interfaces) -> tuple:
    if interfaces is None:
        values = ()
    elif isinstance(interfaces, str):
        values = (interfaces,)
    else:
        try:
            values = tuple(interfaces)
        except TypeError as exc:
            raise _invalid_request("interfaces must be iterable") from exc

    if any(not isinstance(item, str) for item in values):
        raise _invalid_request("interfaces must contain strings")
    return tuple(sorted(set(values)))


def _normalize_ttl(ttl):
    if ttl is None:
        return None
    if isinstance(ttl, bool) or not isinstance(ttl, (int, float)):
        raise _invalid_request("ttl must be a number")
    if ttl < 0:
        raise _invalid_request("ttl must not be negative")
    return ttl


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _parse_time(value) -> datetime:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str) or not value:
        raise _invalid_request("now must be an ISO-8601 string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise _invalid_request("invalid ISO-8601 time") from exc


def _format_like(value, result: datetime) -> str:
    text = result.isoformat()
    if isinstance(value, str):
        if value.endswith("Z") and text.endswith("+00:00"):
            text = text[:-6] + "Z"
        if len(value) > 10 and value[10:11] == " " and "T" in text:
            text = text[:10] + " " + text[11:]
    return text


def _add_seconds(now, seconds):
    parsed = _parse_time(now)
    result = parsed + timedelta(seconds=seconds)
    return _format_like(now, result)


def _time_not_after(left, right) -> bool:
    try:
        return _parse_time(left) <= _parse_time(right)
    except UsbError:
        return str(left) <= str(right)


def _fingerprint(vid: int, pid: int, serial, port_path: str) -> str:
    if serial is not None:
        payload = ("serial", vid, pid, serial)
    else:
        payload = ("port", vid, pid, port_path)
    encoded = json.dumps(
        payload, ensure_ascii=False, separators=(",", ":")
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


class UsbDeviceAuthorizer:
    """Decide whether a hot-plugged USB device is authorized to attach."""

    def __init__(self, *, temp_window: int = 300, rules=None) -> None:
        if isinstance(temp_window, bool) or not isinstance(temp_window, int):
            raise _invalid_request("temp_window must be an integer")
        if temp_window < 0:
            raise _invalid_request("temp_window must not be negative")

        self.temp_window = temp_window
        self._lock = threading.RLock()
        self._rules: dict[str, Rule] = {}
        self._devices: dict[str, DeviceRecord] = {}
        self._handles: dict[str, str] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

        for spec in self._coerce_rule_specs(rules):
            self.add_rule(**spec)

    @staticmethod
    def _coerce_rule_specs(rules):
        if rules is None:
            return ()
        if isinstance(rules, Rule):
            return (asdict(rules),)
        if isinstance(rules, Mapping):
            if "rule_id" in rules:
                return (dict(rules),)
            specs = []
            for rule_id, spec in rules.items():
                if not isinstance(spec, Mapping):
                    raise _invalid_request("rule specifications must be mappings")
                item = dict(spec)
                item.setdefault("rule_id", rule_id)
                specs.append(item)
            return tuple(specs)
        try:
            items = tuple(rules)
        except TypeError as exc:
            raise _invalid_request("rules must be iterable") from exc

        specs = []
        for item in items:
            if isinstance(item, Rule):
                specs.append(asdict(item))
            elif isinstance(item, Mapping):
                specs.append(dict(item))
            else:
                raise _invalid_request("rule specifications must be mappings")
        return tuple(specs)

    @staticmethod
    def _build_rule(rule_id, *, vid, pid=None, serial=None, interfaces=(),
                    decision="allow", ttl=None) -> Rule:
        if not isinstance(rule_id, str) or not rule_id:
            raise _invalid_request("rule_id must be a non-empty string")
        if decision not in ("allow", "deny"):
            raise _invalid_request("decision must be allow or deny")
        return Rule(
            rule_id=rule_id,
            vid=_normalize_int(vid, name="vid"),
            pid=None if pid is None else _normalize_int(pid, name="pid"),
            serial=_normalize_serial(serial),
            interfaces=_normalize_interfaces(interfaces),
            decision=decision,
            ttl=_normalize_ttl(ttl),
        )

    def add_rule(self, rule_id: str, *, vid: int, pid=None, serial=None,
                 interfaces=(), decision: str = "allow", ttl=None) -> Rule:
        rule = self._build_rule(
            rule_id,
            vid=vid,
            pid=pid,
            serial=serial,
            interfaces=interfaces,
            decision=decision,
            ttl=ttl,
        )
        with self._lock:
            if rule_id in self._rules:
                raise UsbError(ERR_RULE_DUPLICATE)
            self._rules[rule_id] = rule
        return rule

    def remove_rule(self, rule_id: str) -> bool:
        if not isinstance(rule_id, str):
            raise _invalid_request("rule_id must be a string")
        with self._lock:
            return self._rules.pop(rule_id, None) is not None

    def _matching_rule(self, vid: int, pid: int, serial, interfaces: tuple):
        device_interfaces = set(interfaces)
        best_rule = None
        best_key = None

        for rule in self._rules.values():
            if rule.vid != vid:
                continue
            if rule.pid is not None and rule.pid != pid:
                continue
            if rule.serial is not None and rule.serial != serial:
                continue

            if rule.decision == "deny":
                if rule.interfaces and not device_interfaces.intersection(
                    rule.interfaces
                ):
                    continue
            elif rule.interfaces and not device_interfaces.issubset(
                rule.interfaces
            ):
                continue

            key = (
                rule.serial is not None,
                rule.pid is not None,
                rule.decision == "deny",
            )
            if best_key is None or key > best_key:
                best_key = key
                best_rule = rule

        return best_rule

    def _assess(self, *, vid: int, pid: int, serial, interfaces: tuple, now):
        rule = self._matching_rule(vid, pid, serial, interfaces)
        if rule is None:
            self._stats["prompts"] += 1
            return "pending", None, None, True
        if rule.decision == "deny":
            self._stats["denied"] += 1
            return "denied", None, rule.rule_id, False

        self._stats["authorized"] += 1
        if rule.ttl is None:
            return "authorized", None, rule.rule_id, False
        return "temp", _add_seconds(now, rule.ttl), rule.rule_id, False

    def _require_device(self, fingerprint: str) -> DeviceRecord:
        if not isinstance(fingerprint, str):
            raise _invalid_request("fingerprint must be a string")
        record = self._devices.get(fingerprint)
        if record is None:
            raise UsbError(ERR_DEVICE_UNKNOWN)
        return record

    def _close_handles(self, fingerprint: str) -> int:
        closed_ids = [
            handle_id
            for handle_id, owner in self._handles.items()
            if owner == fingerprint
        ]
        for handle_id in closed_ids:
            del self._handles[handle_id]
        return len(closed_ids)

    def on_insert(self, *, vid: int, pid: int, interfaces, port_path: str,
                  serial=None, now=None) -> DeviceRecord:
        vid = _normalize_int(vid, name="vid")
        pid = _normalize_int(pid, name="pid")
        serial = _normalize_serial(serial)
        interfaces = _normalize_interfaces(interfaces)
        if not isinstance(port_path, str) or not port_path:
            raise _invalid_request("port_path must be a non-empty string")
        now_value = _utc_now() if now is None else now
        _parse_time(now_value)

        fingerprint = _fingerprint(vid, pid, serial, port_path)
        with self._lock:
            self._stats["inserts"] += 1
            existing = self._devices.get(fingerprint)

            if existing is not None:
                if existing.interfaces == interfaces:
                    self._stats["deduped"] += 1
                    updated = replace(
                        existing,
                        vid=vid,
                        pid=pid,
                        serial=serial,
                        port_path=port_path,
                        prompt=False,
                    )
                    self._devices[fingerprint] = updated
                    return updated

                if existing.state in _TERMINAL_REUSE_STATES:
                    updated = replace(
                        existing,
                        vid=vid,
                        pid=pid,
                        serial=serial,
                        interfaces=interfaces,
                        port_path=port_path,
                        prompt=False,
                    )
                    self._devices[fingerprint] = updated
                    return updated

                self._close_handles(fingerprint)
                state, expires_at, matched_rule, prompt = self._assess(
                    vid=vid,
                    pid=pid,
                    serial=serial,
                    interfaces=interfaces,
                    now=now_value,
                )
                record = DeviceRecord(
                    fingerprint=fingerprint,
                    vid=vid,
                    pid=pid,
                    serial=serial,
                    interfaces=interfaces,
                    port_path=port_path,
                    state=state,
                    expires_at=expires_at,
                    matched_rule=matched_rule,
                    prompt=prompt,
                )
                self._devices[fingerprint] = record
                return record

            state, expires_at, matched_rule, prompt = self._assess(
                vid=vid,
                pid=pid,
                serial=serial,
                interfaces=interfaces,
                now=now_value,
            )
            record = DeviceRecord(
                fingerprint=fingerprint,
                vid=vid,
                pid=pid,
                serial=serial,
                interfaces=interfaces,
                port_path=port_path,
                state=state,
                expires_at=expires_at,
                matched_rule=matched_rule,
                prompt=prompt,
            )
            self._devices[fingerprint] = record
            return record

    def evaluate(self, fingerprint: str) -> str:
        with self._lock:
            record = self._devices.get(fingerprint)
            return None if record is None else record.state

    def authorize(self, fingerprint: str, *, ttl=None, now=None) -> DeviceRecord:
        ttl = _normalize_ttl(ttl)
        now_value = _utc_now() if now is None else now
        _parse_time(now_value)
        with self._lock:
            record = self._require_device(fingerprint)
            if ttl is None:
                state = "authorized"
                expires_at = None
            else:
                state = "temp"
                expires_at = _add_seconds(now_value, ttl)
            self._stats["authorized"] += 1
            updated = replace(
                record,
                state=state,
                expires_at=expires_at,
                prompt=False,
            )
            self._devices[fingerprint] = updated
            return updated

    def revoke(self, fingerprint: str, *, now=None) -> int:
        if now is not None:
            _parse_time(now)
        with self._lock:
            record = self._require_device(fingerprint)
            if record.state == "revoked":
                return 0
            closed = self._close_handles(fingerprint)
            self._stats["revoked"] += 1
            self._devices[fingerprint] = replace(
                record,
                state="revoked",
                expires_at=None,
                prompt=False,
            )
            return closed

    def expire(self, *, now=None) -> ExpireReport:
        now_value = _utc_now() if now is None else now
        _parse_time(now_value)
        revoked = 0
        handles_closed = 0
        with self._lock:
            for fingerprint, record in list(self._devices.items()):
                if (
                    record.state == "temp"
                    and record.expires_at is not None
                    and _time_not_after(record.expires_at, now_value)
                ):
                    handles_closed += self._close_handles(fingerprint)
                    self._devices[fingerprint] = replace(
                        record,
                        state="expired",
                        prompt=False,
                    )
                    self._stats["expired"] += 1
                    revoked += 1
        return ExpireReport(revoked=revoked, handles_closed=handles_closed)

    def attach(self, fingerprint: str, handle_id: str) -> int:
        if not isinstance(handle_id, str) or not handle_id:
            raise _invalid_request("handle_id must be a non-empty string")
        with self._lock:
            record = self._require_device(fingerprint)
            if record.state not in ("authorized", "temp"):
                raise UsbError(ERR_NOT_AUTHORIZED)
            if handle_id in self._handles:
                raise UsbError(ERR_HANDLE_DUPLICATE)
            self._handles[handle_id] = fingerprint
            self._stats["handles_opened"] += 1
            return self.handles(fingerprint)

    def detach(self, handle_id: str) -> int:
        if not isinstance(handle_id, str) or not handle_id:
            raise _invalid_request("handle_id must be a non-empty string")
        with self._lock:
            return 1 if self._handles.pop(handle_id, None) is not None else 0

    def handles(self, fingerprint: str) -> int:
        with self._lock:
            return sum(
                1 for owner in self._handles.values() if owner == fingerprint
            )

    def devices(self) -> list:
        with self._lock:
            return [replace(record) for record in self._devices.values()]

    def status(self) -> dict:
        with self._lock:
            result = {"devices": len(self._devices)}
            for state in ("authorized", "temp", "pending", "denied",
                          "revoked", "expired"):
                result[state] = sum(
                    1 for record in self._devices.values()
                    if record.state == state
                )
            result["handles"] = len(self._handles)
            result["rules"] = len(self._rules)
            return result

    def snapshot(self) -> dict:
        with self._lock:
            rules = [
                {
                    **asdict(rule),
                    "interfaces": list(rule.interfaces),
                }
                for rule in self._rules.values()
            ]
            devices = [
                {
                    **asdict(record),
                    "interfaces": list(record.interfaces),
                }
                for record in self._devices.values()
            ]
            return copy.deepcopy({
                "version": 1,
                "temp_window": self.temp_window,
                "rules": rules,
                "devices": devices,
                "handles": dict(self._handles),
                "stats": dict(self._stats),
            })

    def _validated_snapshot(self, state):
        if not isinstance(state, Mapping):
            raise UsbError(ERR_SNAPSHOT_INVALID)
        required = (
            "version", "temp_window", "rules", "devices", "handles", "stats"
        )
        if any(key not in state for key in required):
            raise UsbError(ERR_SNAPSHOT_INVALID)
        if isinstance(state["version"], bool) or state["version"] != 1:
            raise UsbError(ERR_SNAPSHOT_INVALID)

        temp_window = state["temp_window"]
        if isinstance(temp_window, bool) or not isinstance(temp_window, int):
            raise UsbError(ERR_SNAPSHOT_INVALID)
        if temp_window < 0:
            raise UsbError(ERR_SNAPSHOT_INVALID)

        rules_value = state["rules"]
        if not isinstance(rules_value, (list, tuple)):
            raise UsbError(ERR_SNAPSHOT_INVALID)
        rules: dict[str, Rule] = {}
        for item in rules_value:
            if not isinstance(item, Mapping):
                raise UsbError(ERR_SNAPSHOT_INVALID)
            if not all(
                key in item
                for key in (
                    "rule_id",
                    "vid",
                    "pid",
                    "serial",
                    "interfaces",
                    "decision",
                    "ttl",
                )
            ):
                raise UsbError(ERR_SNAPSHOT_INVALID)
            try:
                rule = self._build_rule(
                    item["rule_id"],
                    vid=item["vid"],
                    pid=item["pid"],
                    serial=item["serial"],
                    interfaces=item["interfaces"],
                    decision=item["decision"],
                    ttl=item["ttl"],
                )
            except (KeyError, TypeError, ValueError, UsbError) as exc:
                raise UsbError(ERR_SNAPSHOT_INVALID) from exc
            if rule.rule_id in rules:
                raise UsbError(ERR_SNAPSHOT_INVALID)
            rules[rule.rule_id] = rule

        devices_value = state["devices"]
        if not isinstance(devices_value, (list, tuple)):
            raise UsbError(ERR_SNAPSHOT_INVALID)
        devices: dict[str, DeviceRecord] = {}
        for item in devices_value:
            if not isinstance(item, Mapping):
                raise UsbError(ERR_SNAPSHOT_INVALID)
            if not all(
                key in item
                for key in (
                    "fingerprint",
                    "vid",
                    "pid",
                    "serial",
                    "interfaces",
                    "port_path",
                    "state",
                    "expires_at",
                    "matched_rule",
                    "prompt",
                )
            ):
                raise UsbError(ERR_SNAPSHOT_INVALID)
            try:
                fingerprint = item["fingerprint"]
                vid = _normalize_int(item["vid"], name="vid")
                pid = _normalize_int(item["pid"], name="pid")
                serial = _normalize_serial(item["serial"])
                interfaces = _normalize_interfaces(
                    item["interfaces"]
                )
                port_path = item["port_path"]
                device_state = item["state"]
                expires_at = item["expires_at"]
                matched_rule = item["matched_rule"]
                prompt = item["prompt"]
            except (KeyError, TypeError, ValueError, UsbError) as exc:
                raise UsbError(ERR_SNAPSHOT_INVALID) from exc

            if (
                not isinstance(fingerprint, str)
                or fingerprint in devices
                or not isinstance(port_path, str)
                or not port_path
                or device_state not in _STATES
                or not isinstance(prompt, bool)
                or (expires_at is not None and not isinstance(expires_at, str))
                or (
                    matched_rule is not None
                    and not isinstance(matched_rule, str)
                )
            ):
                raise UsbError(ERR_SNAPSHOT_INVALID)
            if fingerprint != _fingerprint(vid, pid, serial, port_path):
                raise UsbError(ERR_SNAPSHOT_INVALID)
            if expires_at is not None:
                try:
                    _parse_time(expires_at)
                except UsbError as exc:
                    raise UsbError(ERR_SNAPSHOT_INVALID) from exc

            devices[fingerprint] = DeviceRecord(
                fingerprint=fingerprint,
                vid=vid,
                pid=pid,
                serial=serial,
                interfaces=interfaces,
                port_path=port_path,
                state=device_state,
                expires_at=expires_at,
                matched_rule=matched_rule,
                prompt=prompt,
            )

        handles_value = state["handles"]
        if not isinstance(handles_value, Mapping):
            raise UsbError(ERR_SNAPSHOT_INVALID)
        handles: dict[str, str] = {}
        for handle_id, fingerprint in handles_value.items():
            if (
                not isinstance(handle_id, str)
                or not handle_id
                or not isinstance(fingerprint, str)
                or fingerprint not in devices
            ):
                raise UsbError(ERR_SNAPSHOT_INVALID)
            record = devices[fingerprint]
            if record.state not in ("authorized", "temp"):
                raise UsbError(ERR_SNAPSHOT_INVALID)
            if handle_id in handles:
                raise UsbError(ERR_SNAPSHOT_INVALID)
            handles[handle_id] = fingerprint

        stats_value = state["stats"]
        if not isinstance(stats_value, Mapping):
            raise UsbError(ERR_SNAPSHOT_INVALID)
        stats = {}
        for key in _STAT_KEYS:
            value = stats_value.get(key)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
            ):
                raise UsbError(ERR_SNAPSHOT_INVALID)
            stats[key] = value

        return temp_window, rules, devices, handles, stats

    def restore(self, state) -> None:
        with self._lock:
            try:
                validated = self._validated_snapshot(state)
            except UsbError as exc:
                if exc.code == ERR_SNAPSHOT_INVALID:
                    raise
                raise UsbError(ERR_SNAPSHOT_INVALID) from exc
            except Exception as exc:
                raise UsbError(ERR_SNAPSHOT_INVALID) from exc

            temp_window, rules, devices, handles, stats = validated
            self.temp_window = temp_window
            self._rules = rules
            self._devices = devices
            self._handles = handles
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
