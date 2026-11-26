"""TLS inspection decisions: tenant policy, pin windows and CA rotation."""

from __future__ import annotations

import copy
import math
import threading
import time
from dataclasses import dataclass
from typing import Any


class BrokerError(ValueError):
    """Raised when an inspection decision cannot be produced."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Decision:
    conn_id: str
    action: str
    reason: str
    ca_id: object
    generation: int


@dataclass(frozen=True)
class ReissueContext:
    conn_id: str
    ca_id: str
    san: tuple
    serial: int


_SNAPSHOT_VERSION = 1
_KNOWN_TRANSPORTS = frozenset({"tcp", "quic", "udp"})
_UNINSPECTABLE_TRANSPORTS = frozenset({"quic", "udp"})
_DECISION_ACTIONS = frozenset({"inspect", "bypass", "downgrade", "reject"})
_STAT_KEYS = (
    "decisions",
    "inspected",
    "bypassed",
    "downgraded",
    "rejected",
    "windows_open",
    "windows_expired",
    "reloads",
    "conflicts",
    "ca_retired",
    "reissues",
)
_ACTION_STAT_KEY = {
    "inspect": "inspected",
    "bypass": "bypassed",
    "downgrade": "downgraded",
    "reject": "rejected",
}


def _host_key(value: Any) -> str:
    if not isinstance(value, str):
        return ""
    host = value.strip().lower()
    if host.endswith("."):
        host = host[:-1]
    return host


def _pattern_key(value: Any) -> str:
    pattern = _host_key(value)
    if pattern.startswith("*."):
        pattern = pattern[2:]
    elif pattern.startswith("."):
        pattern = pattern[1:]
    return pattern


def _now_seconds(now: Any) -> float:
    if now is None:
        return time.time()
    if isinstance(now, bool) or not isinstance(now, (int, float)):
        raise BrokerError("INVALID_REQUEST", {"field": "now"})
    value = float(now)
    if not math.isfinite(value):
        raise BrokerError("INVALID_REQUEST", {"field": "now"})
    return value


def _integer(value: Any, field: str, *, minimum: int = 0) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise BrokerError("BROKER_SNAPSHOT_INVALID", {"field": field})
    if value < minimum:
        raise BrokerError("BROKER_SNAPSHOT_INVALID", {"field": field})
    return value


def _number(
    value: Any, field: str, *, allow_none: bool = False
) -> float | None:
    if value is None and allow_none:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BrokerError("BROKER_SNAPSHOT_INVALID", {"field": field})
    result = float(value)
    if not math.isfinite(result):
        raise BrokerError("BROKER_SNAPSHOT_INVALID", {"field": field})
    return result


def _validate_bundle(
    bundle: Any, *, snapshot: bool = False
) -> dict[str, tuple[str, ...]]:
    error_code = "BROKER_SNAPSHOT_INVALID" if snapshot else "CA_BUNDLE_INVALID"
    if not isinstance(bundle, dict):
        raise BrokerError(error_code, {"reason": "bundle must be a mapping"})

    normalized: dict[str, tuple[str, ...]] = {}
    for ca_id, patterns in bundle.items():
        if not isinstance(ca_id, str) or not ca_id:
            raise BrokerError(
                error_code, {"reason": "CA ids must be non-empty strings"}
            )
        if isinstance(patterns, (str, bytes)) or not isinstance(
            patterns, (list, tuple, set, frozenset)
        ):
            raise BrokerError(
                error_code,
                {"ca_id": ca_id, "reason": "patterns must be a sequence"},
            )

        checked: list[str] = []
        for pattern in patterns:
            if not isinstance(pattern, str) or not pattern.strip():
                raise BrokerError(
                    error_code, {"ca_id": ca_id, "reason": "invalid pattern"}
                )
            checked.append(pattern)
        normalized[ca_id] = tuple(checked)
    return normalized


def _validate_pinned_hosts(
    value: Any, *, snapshot: bool = False
) -> tuple[str, ...]:
    error_code = "BROKER_SNAPSHOT_INVALID" if snapshot else "INVALID_REQUEST"
    if value is None:
        return ()
    if isinstance(value, (str, bytes)) or not isinstance(
        value, (list, tuple, set, frozenset)
    ):
        raise BrokerError(error_code, {"field": "pinned_hosts"})
    hosts: list[str] = []
    for host in value:
        if not isinstance(host, str) or not host.strip():
            raise BrokerError(error_code, {"field": "pinned_hosts"})
        hosts.append(host.strip().lower())
    return tuple(hosts)


def _pin_matches(host: str, pin: str) -> bool:
    pinned = _host_key(pin)
    if not pinned:
        return False
    if pinned.startswith("*."):
        base = pinned[2:]
        if not base or host == base:
            return False
        prefix = host[: -(len(base) + 1)]
        return host.endswith("." + base) and "." not in prefix
    return host == pinned


def _san_covers_sni(san: Any, sni: str) -> bool:
    host = _host_key(sni)
    if not host:
        return False
    for item in san or ():
        candidate = _host_key(item)
        if not candidate:
            continue
        if candidate == host:
            return True
        if candidate.startswith("*."):
            base = candidate[2:]
            if not base or host == base or not host.endswith("." + base):
                continue
            prefix = host[: -(len(base) + 1)]
            if "." not in prefix:
                return True
    return False


class InspectionBroker:
    """Decide inspect or bypass for a TLS connection and pick the signing CA."""

    def __init__(
        self,
        *,
        default_ca: str = "ca-root",
        window_seconds: int = 900,
        allow_quic_downgrade: bool = True,
        max_decisions: int = 1024,
    ) -> None:
        if not isinstance(default_ca, str) or not default_ca:
            raise BrokerError("INVALID_REQUEST", {"field": "default_ca"})
        if isinstance(window_seconds, bool) or not isinstance(
            window_seconds, (int, float)
        ):
            raise BrokerError("INVALID_REQUEST", {"field": "window_seconds"})
        if window_seconds < 0 or not math.isfinite(float(window_seconds)):
            raise BrokerError("INVALID_REQUEST", {"field": "window_seconds"})
        if isinstance(max_decisions, bool) or not isinstance(max_decisions, int):
            raise BrokerError("INVALID_REQUEST", {"field": "max_decisions"})
        if max_decisions < 0:
            raise BrokerError("INVALID_REQUEST", {"field": "max_decisions"})

        self.default_ca = default_ca
        self.window_seconds = window_seconds
        self.allow_quic_downgrade = bool(allow_quic_downgrade)
        self.max_decisions = max_decisions

        self._lock = threading.RLock()
        self._generation = 1
        self._ca_bundle: dict[str, tuple[str, ...]] = {default_ca: ("*",)}
        self._previous_ca: dict[str, tuple[str, ...]] = {}
        self._previous_generation: int | None = None
        self._tenants: dict[str, dict[str, Any]] = {}
        self._decisions: dict[str, dict[str, Any]] = {}
        self._windows: dict[str, dict[str, Any]] = {}
        self._events: list[dict[str, Any]] = []
        self._serial_counter = 0
        self._counters: dict[str, int] = {key: 0 for key in _STAT_KEYS}

    def reload_ca(self, bundle: dict) -> int:
        normalized = _validate_bundle(bundle)
        with self._lock:
            retired_bundle = self._previous_ca
            self._previous_ca = self._ca_bundle
            self._previous_generation = self._generation
            self._ca_bundle = normalized
            self._generation += 1
            self._counters["reloads"] += 1
            if retired_bundle:
                self._counters["ca_retired"] += 1
            return self._generation

    def ca_for_sni(self, sni: str) -> str:
        if not isinstance(sni, str) or not sni.strip():
            raise BrokerError("INVALID_REQUEST", {"field": "sni"})
        with self._lock:
            return self._ca_for_sni_locked(sni, self._ca_bundle)

    def set_tenant_policy(
        self, tenant: str, *, mode: str, pinned_hosts: tuple = ()
    ) -> None:
        if not isinstance(tenant, str):
            raise BrokerError("INVALID_REQUEST", {"field": "tenant"})
        if mode not in ("inspect", "bypass"):
            raise BrokerError(
                "INVALID_REQUEST", {"field": "mode", "value": mode}
            )
        pinned = _validate_pinned_hosts(pinned_hosts)
        with self._lock:
            self._tenants[tenant] = {"mode": mode, "pinned_hosts": pinned}

    def decide(
        self,
        conn_id: str,
        *,
        sni: str,
        tenant: str,
        client_pinned: bool = False,
        transport: str = "tcp",
        now=None,
    ) -> Decision:
        if not isinstance(conn_id, str) or not conn_id:
            raise BrokerError("INVALID_REQUEST", {"field": "conn_id"})
        if not isinstance(sni, str) or not sni.strip():
            raise BrokerError("INVALID_REQUEST", {"field": "sni"})
        if not isinstance(tenant, str):
            raise BrokerError("INVALID_REQUEST", {"field": "tenant"})
        if (
            not isinstance(transport, str)
            or transport.strip().lower() not in _KNOWN_TRANSPORTS
        ):
            raise BrokerError(
                "INVALID_REQUEST", {"field": "transport", "value": transport}
            )
        now_ts = _now_seconds(now)
        transport_name = transport.strip().lower()
        sni_key = _host_key(sni)

        with self._lock:
            record = self._decisions.get(conn_id)
            if record is not None:
                request = record["request"]
                changed = (
                    _host_key(request["sni"]) != sni_key
                    or request["tenant"] != tenant
                    or request["transport"] != transport_name
                    or bool(request["client_pinned"]) != bool(client_pinned)
                )
                if changed:
                    self._counters["conflicts"] += 1
                    raise BrokerError(
                        "CONN_DECISION_CONFLICT",
                        {
                            "conn_id": conn_id,
                            "existing": {
                                "sni": request["sni"],
                                "tenant": request["tenant"],
                                "transport": request["transport"],
                                "client_pinned": request["client_pinned"],
                            },
                            "requested": {
                                "sni": sni,
                                "tenant": tenant,
                                "transport": transport_name,
                                "client_pinned": bool(client_pinned),
                            },
                        },
                    )
                return record["decision"]

            if len(self._decisions) >= self.max_decisions:
                raise BrokerError(
                    "DECISION_CAPACITY_EXCEEDED",
                    {
                        "conn_id": conn_id,
                        "max_decisions": self.max_decisions,
                    },
                )

            action: str
            reason: str
            ca_id: str | None = None
            host = sni_key
            policy = self._tenants.get(tenant)

            if transport_name in _UNINSPECTABLE_TRANSPORTS:
                if self.allow_quic_downgrade:
                    action = "downgrade"
                    reason = "UNINSPECTABLE_TRANSPORT_DOWNGRADE"
                else:
                    action = "reject"
                    reason = "UNINSPECTABLE_TRANSPORT_REJECTED"
            elif policy is not None and policy["mode"] == "bypass":
                action = "bypass"
                reason = "TENANT_BYPASS"
            elif self._host_is_pinned(host, policy):
                action = "bypass"
                reason = "PINNED_CERT"
                self._put_window_locked(
                    conn_id, now_ts, self.window_seconds
                )
            elif client_pinned:
                action = "bypass"
                reason = "CLIENT_PINNED"
                self._emit_locked(
                    {
                        "type": "CLIENT_PINNED",
                        "conn_id": conn_id,
                        "sni": sni,
                        "tenant": tenant,
                        "at": now_ts,
                    }
                )
            elif self._window_is_active_locked(conn_id, now_ts):
                action = "bypass"
                reason = "BYPASS_WINDOW"
            else:
                action = "inspect"
                reason = "DEFAULT_INSPECT"
                ca_id = self._ca_for_sni_locked(sni, self._ca_bundle)

            decision = Decision(
                conn_id=conn_id,
                action=action,
                reason=reason,
                ca_id=ca_id,
                generation=self._generation,
            )
            self._decisions[conn_id] = {
                "conn_id": conn_id,
                "request": {
                    "sni": sni,
                    "tenant": tenant,
                    "transport": transport_name,
                    "client_pinned": bool(client_pinned),
                },
                "decision": decision,
                "serial": None,
                "san": None,
                "context": None,
                "created_at": now_ts,
            }
            self._counters["decisions"] += 1
            self._counters[_ACTION_STAT_KEY[action]] += 1
            return decision

    def reissue_context(self, conn_id: str, *, now=None) -> ReissueContext:
        _now_seconds(now)
        with self._lock:
            record = (
                self._decisions.get(conn_id)
                if isinstance(conn_id, str)
                else None
            )
            if record is None or record["decision"].action != "inspect":
                raise BrokerError(
                    "NO_INSPECTION_DECISION",
                    {"conn_id": conn_id if isinstance(conn_id, str) else None},
                )

            existing = record.get("context")
            if isinstance(existing, ReissueContext):
                if not _san_covers_sni(existing.san, record["request"]["sni"]):
                    raise BrokerError(
                        "INVALID_DECISION",
                        {
                            "conn_id": conn_id,
                            "sni": record["request"]["sni"],
                            "san": list(existing.san),
                        },
                    )
                return existing

            stored_san = record.get("san")
            if stored_san is None:
                san = (_host_key(record["request"]["sni"]),)
            else:
                san = tuple(stored_san)
            if not _san_covers_sni(san, record["request"]["sni"]):
                raise BrokerError(
                    "INVALID_DECISION",
                    {
                        "conn_id": conn_id,
                        "sni": record["request"]["sni"],
                        "san": list(san),
                    },
                )

            serial = record.get("serial")
            if (
                not isinstance(serial, int)
                or isinstance(serial, bool)
                or serial <= 0
            ):
                self._serial_counter += 1
                serial = self._serial_counter
                self._counters["reissues"] += 1
            else:
                self._serial_counter = max(self._serial_counter, serial)
                self._counters["reissues"] += 1

            context = ReissueContext(
                conn_id=conn_id,
                ca_id=record["decision"].ca_id,
                san=tuple(san),
                serial=serial,
            )
            record["serial"] = serial
            record["san"] = tuple(san)
            record["context"] = context
            return context

    def bypass_window(
        self,
        conn_id: str,
        *,
        seconds: int | float | None = None,
        now=None,
    ) -> int:
        if not isinstance(conn_id, str) or not conn_id:
            raise BrokerError("INVALID_REQUEST", {"field": "conn_id"})
        now_ts = _now_seconds(now)
        ttl = self.window_seconds if seconds is None else seconds
        if (
            isinstance(ttl, bool)
            or not isinstance(ttl, (int, float))
            or ttl < 0
        ):
            raise BrokerError("INVALID_REQUEST", {"field": "seconds"})
        if not math.isfinite(float(ttl)):
            raise BrokerError("INVALID_REQUEST", {"field": "seconds"})

        with self._lock:
            window = self._put_window_locked(conn_id, now_ts, ttl)
            return int(window["expires_at"])

    def close_window(self, conn_id: str) -> bool:
        with self._lock:
            return self._windows.pop(conn_id, None) is not None

    def expire_windows(self, now=None) -> int:
        now_ts = _now_seconds(now)
        expired: list[str] = []
        with self._lock:
            for conn_id, window in list(self._windows.items()):
                if float(window["expires_at"]) <= now_ts:
                    expired.append(conn_id)
                    del self._windows[conn_id]
                    self._decisions.pop(conn_id, None)
            self._counters["windows_expired"] += len(expired)
            return len(expired)

    def decision_for(self, conn_id: str):
        with self._lock:
            record = (
                self._decisions.get(conn_id)
                if isinstance(conn_id, str)
                else None
            )
            return record["decision"] if record is not None else None

    def ca_ids(self) -> tuple:
        with self._lock:
            ids: list[str] = []
            for ca_id in self._ca_bundle:
                if ca_id not in ids:
                    ids.append(ca_id)
            for ca_id in self._previous_ca:
                if ca_id not in ids:
                    ids.append(ca_id)
            return tuple(ids)

    def ca_generation(self) -> int:
        with self._lock:
            return self._generation

    def events(self) -> tuple[dict[str, Any], ...]:
        with self._lock:
            return copy.deepcopy(tuple(self._events))

    def snapshot(self) -> dict:
        with self._lock:
            decisions: dict[str, dict[str, Any]] = {}
            for conn_id, record in self._decisions.items():
                decision = record["decision"]
                context = record.get("context")
                decisions[conn_id] = {
                    "conn_id": conn_id,
                    "sni": record["request"]["sni"],
                    "tenant": record["request"]["tenant"],
                    "transport": record["request"]["transport"],
                    "client_pinned": record["request"]["client_pinned"],
                    "created_at": record.get("created_at"),
                    "serial": record.get("serial"),
                    "san": (
                        list(record["san"])
                        if record.get("san") is not None
                        else None
                    ),
                    "decision": {
                        "conn_id": decision.conn_id,
                        "action": decision.action,
                        "reason": decision.reason,
                        "ca_id": decision.ca_id,
                        "generation": decision.generation,
                    },
                    "context": (
                        {
                            "conn_id": context.conn_id,
                            "ca_id": context.ca_id,
                            "san": list(context.san),
                            "serial": context.serial,
                        }
                        if isinstance(context, ReissueContext)
                        else None
                    ),
                }

            windows = {
                conn_id: copy.deepcopy(window)
                for conn_id, window in self._windows.items()
            }
            stats = copy.deepcopy(self._counters)
            stats["windows_open"] = len(self._windows)

            state = {
                "version": _SNAPSHOT_VERSION,
                "cas": {
                    "generation": self._generation,
                    "default_ca": self.default_ca,
                    "active": {
                        ca_id: list(patterns)
                        for ca_id, patterns in self._ca_bundle.items()
                    },
                    "previous": {
                        ca_id: list(patterns)
                        for ca_id, patterns in self._previous_ca.items()
                    },
                    "previous_generation": self._previous_generation,
                    "serial_counter": self._serial_counter,
                },
                "tenants": {
                    tenant: {
                        "mode": policy["mode"],
                        "pinned_hosts": list(policy["pinned_hosts"]),
                    }
                    for tenant, policy in self._tenants.items()
                },
                "decisions": decisions,
                "windows": windows,
                "stats": stats,
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        try:
            parsed = self._parse_snapshot(state)
        except BrokerError:
            raise
        except Exception as exc:
            raise BrokerError(
                "BROKER_SNAPSHOT_INVALID", {"reason": "unparseable snapshot"}
            ) from exc
        if len(parsed["decisions"]) > self.max_decisions:
            raise BrokerError(
                "BROKER_SNAPSHOT_INVALID",
                {
                    "reason": "decision capacity exceeded",
                    "decisions": len(parsed["decisions"]),
                    "max_decisions": self.max_decisions,
                },
            )
        with self._lock:
            self.default_ca = parsed["default_ca"]
            self._generation = parsed["generation"]
            self._ca_bundle = parsed["active"]
            self._previous_ca = parsed["previous"]
            self._previous_generation = parsed["previous_generation"]
            self._tenants = parsed["tenants"]
            self._decisions = parsed["decisions"]
            self._windows = parsed["windows"]
            self._counters = parsed["stats"]
            self._serial_counter = parsed["serial_counter"]
            self._events = []

    def stats(self) -> dict:
        with self._lock:
            result = copy.deepcopy(self._counters)
            result["windows_open"] = len(self._windows)
            return result

    def _ca_for_sni_locked(
        self, sni: str, bundle: dict[str, tuple[str, ...]]
    ) -> str:
        host = _host_key(sni)
        best_length = -1
        best_ca: str | None = None
        for ca_id, patterns in bundle.items():
            for raw_pattern in patterns:
                pattern = _pattern_key(raw_pattern)
                if not pattern:
                    matched = False
                elif pattern == "*":
                    matched = True
                else:
                    matched = host == pattern or host.endswith(
                        "." + pattern
                    )
                if not matched:
                    continue
                length = len(pattern)
                if length > best_length or (
                    length == best_length
                    and (best_ca is None or ca_id < best_ca)
                ):
                    best_length = length
                    best_ca = ca_id
        return best_ca if best_ca is not None else self.default_ca

    def _host_is_pinned(
        self, host: str, policy: dict[str, Any] | None
    ) -> bool:
        if policy is None:
            return False
        return any(_pin_matches(host, pin) for pin in policy["pinned_hosts"])

    def _window_is_active_locked(
        self, conn_id: str, now_ts: float
    ) -> bool:
        window = self._windows.get(conn_id)
        return (
            window is not None
            and float(window["expires_at"]) > now_ts
        )

    def _put_window_locked(
        self, conn_id: str, now_ts: float, seconds: int | float
    ) -> dict[str, Any]:
        window = {
            "opened_at": now_ts,
            "seconds": seconds,
            "expires_at": now_ts + seconds,
        }
        self._windows[conn_id] = window
        return window

    def _emit_locked(self, event: dict[str, Any]) -> None:
        event["seq"] = len(self._events) + 1
        self._events.append(event)

    @staticmethod
    def _parse_snapshot(state: Any) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise BrokerError(
                "BROKER_SNAPSHOT_INVALID",
                {"reason": "state must be a mapping"},
            )
        required = (
            "version",
            "cas",
            "tenants",
            "decisions",
            "windows",
            "stats",
        )
        missing = [key for key in required if key not in state]
        if missing:
            raise BrokerError(
                "BROKER_SNAPSHOT_INVALID", {"missing": missing}
            )
        version = state["version"]
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or version != _SNAPSHOT_VERSION
        ):
            raise BrokerError(
                "BROKER_SNAPSHOT_INVALID", {"field": "version"}
            )

        cas = InspectionBroker._parse_cas(state["cas"])
        tenants = InspectionBroker._parse_tenants(state["tenants"])
        decisions, decision_serial = InspectionBroker._parse_decisions(
            state["decisions"]
        )
        windows = InspectionBroker._parse_windows(state["windows"])
        stats = InspectionBroker._parse_stats(state["stats"])
        serial_counter = max(decision_serial, cas["serial_counter"])

        return {
            "default_ca": cas["default_ca"],
            "generation": cas["generation"],
            "active": cas["active"],
            "previous": cas["previous"],
            "previous_generation": cas["previous_generation"],
            "tenants": tenants,
            "decisions": decisions,
            "windows": windows,
            "stats": stats,
            "serial_counter": serial_counter,
        }

    @staticmethod
    def _parse_cas(value: Any) -> dict[str, Any]:
        if not isinstance(value, dict):
            raise BrokerError(
                "BROKER_SNAPSHOT_INVALID", {"field": "cas"}
            )
        generation = _integer(
            value.get("generation", 1), "cas.generation", minimum=1
        )
        default_ca = value.get("default_ca", "ca-root")
        if not isinstance(default_ca, str) or not default_ca:
            raise BrokerError(
                "BROKER_SNAPSHOT_INVALID",
                {"field": "cas.default_ca"},
            )

        active_value = value.get("active", value.get("bundles", value))
        if active_value is value:
            active_value = {
                key: item
                for key, item in value.items()
                if key
                not in {
                    "generation",
                    "default_ca",
                    "previous",
                    "previous_generation",
                    "bundles",
                    "active",
                }
            }
        active = _validate_bundle(active_value, snapshot=True)

        previous_value = value.get("previous", {})
        if previous_value is None:
            previous_value = {}
        previous = _validate_bundle(previous_value, snapshot=True)
        previous_generation = value.get("previous_generation")
        if previous_generation is not None:
            previous_generation = _integer(
                previous_generation,
                "cas.previous_generation",
                minimum=1,
            )
        serial_counter = _integer(
            value.get("serial_counter", 0),
            "cas.serial_counter",
            minimum=0,
        )

        return {
            "generation": generation,
            "default_ca": default_ca,
            "active": active,
            "previous": previous,
            "previous_generation": previous_generation,
            "serial_counter": serial_counter,
        }

    @staticmethod
    def _parse_tenants(value: Any) -> dict[str, dict[str, Any]]:
        if not isinstance(value, dict):
            raise BrokerError(
                "BROKER_SNAPSHOT_INVALID", {"field": "tenants"}
            )
        tenants: dict[str, dict[str, Any]] = {}
        for tenant, policy in value.items():
            if not isinstance(tenant, str):
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID",
                    {"field": "tenants key"},
                )
            if not isinstance(policy, dict):
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID", {"tenant": tenant}
                )
            mode = policy.get("mode")
            if mode not in ("inspect", "bypass"):
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID",
                    {"tenant": tenant, "field": "mode"},
                )
            pinned = _validate_pinned_hosts(
                policy.get("pinned_hosts", ()), snapshot=True
            )
            tenants[tenant] = {
                "mode": mode,
                "pinned_hosts": pinned,
            }
        return tenants

    @staticmethod
    def _parse_decisions(
        value: Any,
    ) -> tuple[dict[str, dict[str, Any]], int]:
        if isinstance(value, dict):
            items: list[tuple[Any, Any]] = list(value.items())
        elif isinstance(value, list):
            items = [
                (
                    item.get("conn_id") if isinstance(item, dict) else None,
                    item,
                )
                for item in value
            ]
        else:
            raise BrokerError(
                "BROKER_SNAPSHOT_INVALID", {"field": "decisions"}
            )

        decisions: dict[str, dict[str, Any]] = {}
        max_serial = 0
        for key, item in items:
            if not isinstance(item, dict):
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID",
                    {"field": "decisions item"},
                )
            conn_id = item.get("conn_id", key)
            if not isinstance(conn_id, str) or not conn_id:
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID",
                    {"field": "decision.conn_id"},
                )
            if key is not None and key != conn_id:
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID", {"conn_id": conn_id}
                )
            if conn_id in decisions:
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID", {"conn_id": conn_id}
                )

            nested = item.get("decision")
            decision_data = nested if isinstance(nested, dict) else item
            sni = item.get("sni", decision_data.get("sni"))
            tenant = item.get("tenant", decision_data.get("tenant", ""))
            if not isinstance(sni, str) or not sni.strip():
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "field": "sni"},
                )
            if not isinstance(tenant, str):
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "field": "tenant"},
                )

            transport = item.get("transport", "tcp")
            if (
                not isinstance(transport, str)
                or transport not in _KNOWN_TRANSPORTS
            ):
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "field": "transport"},
                )
            client_pinned = bool(item.get("client_pinned", False))

            action = decision_data.get("action")
            reason = decision_data.get("reason")
            if (
                action not in _DECISION_ACTIONS
                or not isinstance(reason, str)
                or not reason
            ):
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID", {"conn_id": conn_id}
                )
            ca_id = decision_data.get("ca_id")
            if ca_id == "":
                ca_id = None
            if ca_id is not None and (
                not isinstance(ca_id, str) or not ca_id
            ):
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "field": "ca_id"},
                )
            if action == "inspect" and ca_id is None:
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID",
                    {"conn_id": conn_id, "field": "ca_id"},
                )
            generation = _integer(
                decision_data.get("generation", 1),
                f"decisions.{conn_id}.generation",
                minimum=1,
            )
            decision = Decision(
                conn_id, action, reason, ca_id, generation
            )

            serial = item.get("serial")
            if serial is not None:
                serial = _integer(
                    serial,
                    f"decisions.{conn_id}.serial",
                    minimum=1,
                )
                max_serial = max(max_serial, serial)

            san_value = item.get("san")
            san: tuple[str, ...] | None = None
            if san_value is not None:
                if not isinstance(san_value, (list, tuple)) or not all(
                    isinstance(entry, str) and entry
                    for entry in san_value
                ):
                    raise BrokerError(
                        "BROKER_SNAPSHOT_INVALID",
                        {"conn_id": conn_id, "field": "san"},
                    )
                san = tuple(san_value)

            context = None
            context_data = item.get("context")
            if isinstance(context_data, dict):
                context_serial = _integer(
                    context_data.get("serial", serial),
                    f"decisions.{conn_id}.context.serial",
                    minimum=1,
                )
                context_san_value = context_data.get("san", san or ())
                if not isinstance(
                    context_san_value, (list, tuple)
                ) or not all(
                    isinstance(entry, str) and entry
                    for entry in context_san_value
                ):
                    raise BrokerError(
                        "BROKER_SNAPSHOT_INVALID",
                        {
                            "conn_id": conn_id,
                            "field": "context.san",
                        },
                    )
                context_ca = context_data.get("ca_id", ca_id)
                if not isinstance(context_ca, str) or not context_ca:
                    raise BrokerError(
                        "BROKER_SNAPSHOT_INVALID",
                        {
                            "conn_id": conn_id,
                            "field": "context.ca_id",
                        },
                    )
                serial = context_serial
                san = tuple(context_san_value)
                max_serial = max(max_serial, serial)
                context = ReissueContext(
                    conn_id, context_ca, san, context_serial
                )
            elif serial is not None and san is not None:
                context = ReissueContext(conn_id, ca_id, san, serial)

            decisions[conn_id] = {
                "conn_id": conn_id,
                "request": {
                    "sni": sni,
                    "tenant": tenant,
                    "transport": transport,
                    "client_pinned": client_pinned,
                },
                "decision": decision,
                "serial": serial,
                "san": san,
                "context": context,
                "created_at": _number(
                    item.get("created_at"),
                    "created_at",
                    allow_none=True,
                ),
            }
        return decisions, max_serial

    @staticmethod
    def _parse_windows(
        value: Any,
    ) -> dict[str, dict[str, Any]]:
        if isinstance(value, dict):
            items: list[tuple[Any, Any]] = list(value.items())
        elif isinstance(value, list):
            items = [
                (
                    item.get("conn_id") if isinstance(item, dict) else None,
                    item,
                )
                for item in value
            ]
        else:
            raise BrokerError(
                "BROKER_SNAPSHOT_INVALID", {"field": "windows"}
            )

        windows: dict[str, dict[str, Any]] = {}
        for key, item in items:
            if isinstance(item, (int, float)) and not isinstance(
                item, bool
            ):
                conn_id = key
                expires_at = float(item)
                window: dict[str, Any] = {"expires_at": expires_at}
            elif isinstance(item, dict):
                conn_id = item.get("conn_id", key)
                expires_at = _number(
                    item.get("expires_at"),
                    f"windows.{key}.expires_at",
                )
                window = copy.deepcopy(item)
                window["expires_at"] = expires_at
            else:
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID",
                    {"field": "windows item"},
                )

            if not isinstance(conn_id, str) or not conn_id:
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID",
                    {"field": "window.conn_id"},
                )
            if key is not None and key != conn_id:
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID", {"conn_id": conn_id}
                )
            if conn_id in windows:
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID", {"conn_id": conn_id}
                )
            if not math.isfinite(float(window["expires_at"])):
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID", {"conn_id": conn_id}
                )
            windows[conn_id] = window
        return windows

    @staticmethod
    def _parse_stats(value: Any) -> dict[str, int]:
        if not isinstance(value, dict):
            raise BrokerError(
                "BROKER_SNAPSHOT_INVALID", {"field": "stats"}
            )
        stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            if key not in value:
                raise BrokerError(
                    "BROKER_SNAPSHOT_INVALID",
                    {"field": f"stats.{key}"},
                )
            stats[key] = _integer(
                value[key], f"stats.{key}", minimum=0
            )
        return stats
