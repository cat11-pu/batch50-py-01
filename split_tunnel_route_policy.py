"""Split-tunnel route compilation with longest-prefix resolution and DNS ownership."""

from __future__ import annotations

import copy
import hashlib
import ipaddress
import json
import threading
from dataclasses import dataclass


SNAPSHOT_VERSION = 1
VALID_EGRESS = ("tunnel", "local")
STAT_KEYS = (
    "compiled",
    "applied",
    "removed",
    "reclaimed",
    "conflicts",
    "limit_rejected",
)


class RoutePolicyError(ValueError):
    """Raised when a route policy cannot be compiled or applied."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Route:
    cidr: str
    source: str


@dataclass(frozen=True)
class CompiledPlan:
    routes: tuple
    default_via: str
    dns: tuple
    fingerprint: str
    conflicts: int

    @property
    def version(self) -> int:
        return getattr(self, "_plan_version", 0)


@dataclass(frozen=True)
class RouteExplanation:
    destination: str
    egress: str
    matched_prefix: object
    source: str


def _invalid_request(detail: object) -> RoutePolicyError:
    return RoutePolicyError("INVALID_REQUEST", detail)


def _parse_cidr(value: object) -> ipaddress.IPv4Network | ipaddress.IPv6Network:
    if not isinstance(value, str):
        raise RoutePolicyError(
            "ROUTE_INVALID_CIDR", {"cidr": value, "reason": "CIDR must be a string"}
        )
    try:
        return ipaddress.ip_network(value.strip(), strict=False)
    except (ValueError, TypeError) as exc:
        raise RoutePolicyError("ROUTE_INVALID_CIDR", {"cidr": value}) from exc


def _cidr_tuple(values: object) -> tuple:
    if values is None:
        return ()
    if isinstance(values, str):
        raw_values = (values,)
    else:
        try:
            raw_values = tuple(values)
        except TypeError as exc:
            raise _invalid_request({"field": "cidr_list"}) from exc

    networks = tuple(_parse_cidr(value) for value in raw_values)
    return tuple(sorted(set(networks), key=_network_order))


def _network_order(network: object) -> tuple:
    return (network.version, int(network.network_address), network.prefixlen)


def _route_order(network: object) -> tuple:
    return (-network.prefixlen, network.version, int(network.network_address))


def _parse_address(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if not isinstance(value, str) or not value.strip():
        raise _invalid_request({"field": "destination"})
    try:
        return ipaddress.ip_address(value.strip())
    except (ValueError, TypeError) as exc:
        raise RoutePolicyError(
            "ROUTE_INVALID_DESTINATION", {"destination": value}
        ) from exc


def _normalize_dns_name(value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _invalid_request({"field": "dns_name"})
    name = value.strip().lower()
    while name.endswith("."):
        name = name[:-1]
    return name


def _normalize_zone(value: object) -> str:
    zone = _normalize_dns_name(value)
    if zone.startswith("*."):
        zone = zone[2:]
    elif zone.startswith("."):
        zone = zone[1:]
    if not zone:
        raise _invalid_request({"field": "dns_zones", "zone": value})
    return zone


def _zone_tuple(values: object) -> tuple:
    if values is None:
        return ()
    if isinstance(values, str):
        raw_values = (values,)
    else:
        try:
            raw_values = tuple(values)
        except TypeError as exc:
            raise _invalid_request({"field": "dns_zones"}) from exc
    zones = tuple(_normalize_zone(value) for value in raw_values)
    return tuple(sorted(set(zones)))


def _require_name(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise _invalid_request({"field": field})
    return value


def _normalize_apps(apps: object) -> tuple:
    if apps is None:
        return ()
    if isinstance(apps, str):
        values = (apps,)
    elif isinstance(apps, bytes):
        raise _invalid_request({"field": "apps"})
    else:
        try:
            values = tuple(apps)
        except TypeError as exc:
            raise _invalid_request({"field": "apps"}) from exc

    names = []
    for app in values:
        if not isinstance(app, str) or not app.strip():
            raise _invalid_request({"field": "apps", "app": app})
        names.append(app)
    return tuple(sorted(set(names)))


def _validate_egress(value: object, *, allow_none: bool = False) -> str | None:
    if allow_none and value is None:
        return None
    if value not in VALID_EGRESS:
        raise _invalid_request({"field": "default_via", "value": value})
    return value


def _validate_dns_mode(value: object) -> str:
    if value not in VALID_EGRESS:
        raise _invalid_request({"field": "dns_mode", "value": value})
    return value


def _base_data(config: dict) -> dict:
    return {
        "includes": [str(network) for network in config["includes"]],
        "excludes": [str(network) for network in config["excludes"]],
    }


class SplitTunnelPolicy:
    """Compile global, tenant and per-application route rules into one plan."""

    def __init__(self, *, max_routes: int = 512) -> None:
        if (
            not isinstance(max_routes, int)
            or isinstance(max_routes, bool)
            or max_routes < 0
        ):
            raise _invalid_request({"field": "max_routes", "value": max_routes})

        self.max_routes = max_routes
        self._lock = threading.RLock()
        self._global = {
            "includes": (),
            "excludes": (),
            "default_via": "tunnel",
        }
        self._tenants: dict = {}
        self._apps: dict = {}
        self._installed: dict = {}
        self._last_plan: CompiledPlan | None = None
        self._applied_plan: CompiledPlan | None = None
        self._plan_version = 0
        self._counters = {key: 0 for key in STAT_KEYS}

    def set_global(
        self,
        *,
        includes=(),
        excludes=(),
        default_via: str = "tunnel",
    ) -> None:
        include_networks = _cidr_tuple(includes)
        exclude_networks = _cidr_tuple(excludes)
        via = _validate_egress(default_via)
        with self._lock:
            self._global = {
                "includes": include_networks,
                "excludes": exclude_networks,
                "default_via": via,
            }

    def set_tenant(
        self,
        tenant: str,
        *,
        includes=(),
        excludes=(),
        default_via: str | None = None,
        dns_mode: str = "tunnel",
    ) -> None:
        name = _require_name(tenant, field="tenant")
        include_networks = _cidr_tuple(includes)
        exclude_networks = _cidr_tuple(excludes)
        via = _validate_egress(default_via, allow_none=True)
        mode = _validate_dns_mode(dns_mode)
        with self._lock:
            self._tenants[name] = {
                "includes": include_networks,
                "excludes": exclude_networks,
                "default_via": via,
                "dns_mode": mode,
            }

    def set_app(
        self,
        app: str,
        *,
        includes=(),
        excludes=(),
        dns_zones=(),
        dns_mode: str = "tunnel",
    ) -> None:
        name = _require_name(app, field="app")
        include_networks = _cidr_tuple(includes)
        exclude_networks = _cidr_tuple(excludes)
        zones = _zone_tuple(dns_zones)
        mode = _validate_dns_mode(dns_mode)
        with self._lock:
            self._apps[name] = {
                "includes": include_networks,
                "excludes": exclude_networks,
                "dns_zones": zones,
                "dns_mode": mode,
            }

    def compile(
        self,
        *,
        tenant: str | None = None,
        apps=(),
        now=None,
    ) -> CompiledPlan:
        del now
        app_names = _normalize_apps(apps)
        if tenant is not None:
            _require_name(tenant, field="tenant")

        with self._lock:
            tenant_config = self._tenants.get(tenant) if tenant is not None else None
            self._validate_apps_locked(app_names)
            records, default_via, dns_rules, conflicts = self._build_view_locked(
                tenant_config, app_names
            )
            route_records = [
                record for record in records if record[1] == "tunnel"
            ]

            if len(route_records) > self.max_routes:
                self._counters["limit_rejected"] += 1
                raise RoutePolicyError(
                    "ROUTE_LIMIT_EXCEEDED",
                    {
                        "limit": self.max_routes,
                        "requested": len(route_records),
                    },
                )
            route_records.sort(key=lambda record: _route_order(record[0]))

            routes = tuple(
                Route(cidr=str(network), source=source)
                for network, _action, source in route_records
            )
            fingerprint = self._fingerprint(routes, dns_rules)
            plan = CompiledPlan(
                routes=routes,
                default_via=default_via,
                dns=dns_rules,
                fingerprint=fingerprint,
                conflicts=conflicts,
            )
            self._plan_version += 1
            object.__setattr__(plan, "_plan_version", self._plan_version)
            self._last_plan = plan
            self._counters["compiled"] += 1
            self._counters["conflicts"] += conflicts
            return plan

    def apply(self, plan: CompiledPlan, *, now=None) -> int:
        del now
        with self._lock:
            if (
                not isinstance(plan, CompiledPlan)
                or plan is not self._last_plan
                or getattr(plan, "_plan_version", None) != self._plan_version
            ):
                raise RoutePolicyError(
                    "UNKNOWN_PLAN",
                    {"current_version": self._plan_version},
                )

            if self._applied_plan is plan:
                return 0

            plan_cidrs = {route.cidr for route in plan.routes}
            ordered_installed = {}
            newly_installed = 0

            for route in plan.routes:
                if route.cidr not in self._installed:
                    newly_installed += 1
                ordered_installed[route.cidr] = route.source

            for cidr, source in self._installed.items():
                if cidr not in plan_cidrs:
                    ordered_installed[cidr] = source

            self._installed = ordered_installed
            self._applied_plan = plan
            self._counters["applied"] += newly_installed
            return newly_installed

    def remove(self, *, app: str | None = None) -> int:
        if app is None:
            return 0
        name = _require_name(app, field="app")
        source = f"app:{name}"
        with self._lock:
            removed = [
                cidr
                for cidr, installed_source in self._installed.items()
                if installed_source == source
            ]
            for cidr in removed:
                del self._installed[cidr]
            self._counters["removed"] += len(removed)
            return len(removed)

    def reclaim(self) -> int:
        with self._lock:
            count = len(self._installed)
            self._installed.clear()
            self._counters["reclaimed"] += count
            return count

    def explain(
        self,
        destination: str,
        *,
        tenant: str | None = None,
        apps=(),
    ) -> RouteExplanation:
        address = _parse_address(destination)
        app_names = _normalize_apps(apps)
        if tenant is not None:
            _require_name(tenant, field="tenant")

        with self._lock:
            tenant_config = self._tenants.get(tenant) if tenant is not None else None
            self._validate_apps_locked(app_names)
            records, _default_via, _dns, _conflicts = self._build_view_locked(
                tenant_config, app_names
            )

            best_network = None
            best_action = "local"
            best_source = "default"
            for network, action, source in records:
                if network.version != address.version or address not in network:
                    continue
                if best_network is None or network.prefixlen > best_network.prefixlen:
                    best_network = network
                    best_action = action
                    best_source = source

            if best_network is None:
                return RouteExplanation(destination, "local", None, "default")
            return RouteExplanation(
                destination,
                best_action,
                str(best_network),
                best_source,
            )

    def dns_route(
        self,
        name: str,
        *,
        tenant: str | None = None,
        apps=(),
    ) -> str:
        host = _normalize_dns_name(name)
        app_names = _normalize_apps(apps)
        if tenant is not None:
            _require_name(tenant, field="tenant")

        with self._lock:
            tenant_config = self._tenants.get(tenant) if tenant is not None else None
            self._validate_apps_locked(app_names)

            matches = []
            for app_name in app_names:
                app_config = self._apps[app_name]
                for zone in app_config["dns_zones"]:
                    if host == zone or host.endswith(f".{zone}"):
                        matches.append(
                            (
                                -len(zone.split(".")),
                                -len(zone),
                                app_name,
                                app_config["dns_mode"],
                            )
                        )

            if matches:
                matches.sort()
                return matches[0][3]

            if tenant_config is not None:
                return tenant_config["dns_mode"]
            return "tunnel"

    def installed(self) -> tuple:
        with self._lock:
            return tuple(self._installed.keys())

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": SNAPSHOT_VERSION,
                "global": self._policy_snapshot(self._global, global_policy=True),
                "tenants": {
                    name: self._policy_snapshot(config)
                    for name, config in sorted(self._tenants.items())
                },
                "apps": {
                    name: self._policy_snapshot(config, app_policy=True)
                    for name, config in sorted(self._apps.items())
                },
                "stats": dict(self._counters),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        try:
            cloned = copy.deepcopy(state)
            restored = self._parse_snapshot(cloned)
        except RoutePolicyError as exc:
            if exc.code == "ROUTE_SNAPSHOT_INVALID":
                raise
            raise RoutePolicyError(
                "ROUTE_SNAPSHOT_INVALID",
                {"reason": exc.code, "detail": exc.detail},
            ) from exc
        except Exception as exc:
            raise RoutePolicyError(
                "ROUTE_SNAPSHOT_INVALID", {"reason": "unparseable_snapshot"}
            ) from exc

        with self._lock:
            self._global = restored["global"]
            self._tenants = restored["tenants"]
            self._apps = restored["apps"]
            self._counters = restored["stats"]
            self._installed = {}
            self._last_plan = None
            self._applied_plan = None
            self._plan_version = 0

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def _validate_apps_locked(self, app_names: tuple) -> None:
        unknown = sorted(name for name in app_names if name not in self._apps)
        if unknown:
            raise RoutePolicyError("ROUTE_UNKNOWN_APP", {"apps": unknown})

    def _build_view_locked(
        self,
        tenant_config: dict | None,
        app_names: tuple,
    ) -> tuple:
        default_via = self._global["default_via"]
        if (
            tenant_config is not None
            and tenant_config.get("default_via") is not None
        ):
            default_via = tenant_config["default_via"]

        entries = []
        self._append_entries(entries, self._global, "global")
        if tenant_config is not None:
            self._append_entries(entries, tenant_config, "tenant")
        for app_name in app_names:
            self._append_entries(
                entries, self._apps[app_name], f"app:{app_name}"
            )

        winners = {}
        for network, action, source in entries:
            precedence = self._rule_precedence(action, source)
            current = winners.get(network)
            if current is None or precedence < current[0]:
                winners[network] = (precedence, network, action, source)

        conflicts = self._default_conflicts_locked(tenant_config)
        records = []
        for _precedence, network, action, source in winners.values():
            if (
                default_via == "local"
                and action == "tunnel"
                and network.prefixlen == 0
            ):
                continue
            records.append((network, action, source))

        fallback_mode = (
            tenant_config["dns_mode"] if tenant_config is not None else "tunnel"
        )
        fallback_source = "tenant" if tenant_config is not None else "default"
        dns_owners = {}
        for app_name in app_names:
            app_config = self._apps[app_name]
            for zone in app_config["dns_zones"]:
                current = dns_owners.get(zone)
                if current is None or app_name < current[0]:
                    dns_owners[zone] = (app_name, app_config["dns_mode"])

        dns_rules = tuple(
            sorted(
                (
                    (zone, mode, f"app:{app_name}")
                    for zone, (app_name, mode) in dns_owners.items()
                ),
                key=lambda item: item[0],
            )
        ) + (("*", fallback_mode, fallback_source),)
        return records, default_via, dns_rules, conflicts

    @staticmethod
    def _append_entries(entries: list, config: dict, source: str) -> None:
        for network in config["includes"]:
            entries.append((network, "tunnel", source))
        for network in config["excludes"]:
            entries.append((network, "local", source))

    @staticmethod
    def _rule_precedence(action: str, source: str) -> tuple:
        if source.startswith("app:"):
            layer = 0
            owner = source.split(":", 1)[1]
        elif source == "tenant":
            layer = 1
            owner = ""
        else:
            layer = 2
            owner = ""
        return (0 if action == "local" else 1, layer, owner)

    def _default_conflicts_locked(self, tenant_config: dict | None) -> int:
        if tenant_config is None:
            return 0
        conflicts = 0
        for version in (4, 6):
            global_has_default = any(
                network.version == version and network.prefixlen == 0
                for network in self._global["includes"]
            )
            tenant_has_default = any(
                network.version == version and network.prefixlen == 0
                for network in tenant_config["includes"]
            )
            if global_has_default and tenant_has_default:
                conflicts += 1
        return conflicts

    @staticmethod
    def _fingerprint(routes: tuple, dns_rules: tuple) -> str:
        payload = {
            "routes": [(route.cidr, route.source) for route in routes],
            "dns": [list(rule) for rule in dns_rules],
        }
        encoded = json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("ascii")
        return hashlib.sha256(encoded).hexdigest()

    @staticmethod
    def _policy_snapshot(
        config: dict,
        *,
        global_policy: bool = False,
        app_policy: bool = False,
    ) -> dict:
        data = _base_data(config)
        if global_policy:
            data["default_via"] = config["default_via"]
        elif not app_policy:
            data["default_via"] = config["default_via"]
            data["dns_mode"] = config["dns_mode"]
        else:
            data["dns_zones"] = list(config["dns_zones"])
            data["dns_mode"] = config["dns_mode"]
        return data

    def _parse_snapshot(self, state: object) -> dict:
        if not isinstance(state, dict):
            raise RoutePolicyError("ROUTE_SNAPSHOT_INVALID", "snapshot must be object")

        required = {"version", "global", "tenants", "apps", "stats"}
        missing = required.difference(state)
        if missing:
            raise RoutePolicyError(
                "ROUTE_SNAPSHOT_INVALID", {"missing": sorted(missing)}
            )
        if (
            not isinstance(state["version"], int)
            or isinstance(state["version"], bool)
            or state["version"] != SNAPSHOT_VERSION
        ):
            raise RoutePolicyError("ROUTE_SNAPSHOT_INVALID", {"field": "version"})

        global_config = self._parse_policy_snapshot(
            state["global"], require_default_via=True
        )
        if global_config.get("default_via") not in VALID_EGRESS:
            raise RoutePolicyError(
                "ROUTE_SNAPSHOT_INVALID", {"field": "global.default_via"}
            )

        tenants_data = state["tenants"]
        if not isinstance(tenants_data, dict):
            raise RoutePolicyError("ROUTE_SNAPSHOT_INVALID", {"field": "tenants"})
        tenants = {}
        for name, data in tenants_data.items():
            _require_name(name, field="tenant")
            if not isinstance(data, dict):
                raise RoutePolicyError(
                    "ROUTE_SNAPSHOT_INVALID", {"tenant": name}
                )
            config = self._parse_policy_snapshot(
                data, require_default_via=True, require_dns_mode=True
            )
            if config["default_via"] not in (None, "tunnel", "local"):
                raise RoutePolicyError(
                    "ROUTE_SNAPSHOT_INVALID", {"tenant": name}
                )
            tenants[name] = config

        apps_data = state["apps"]
        if not isinstance(apps_data, dict):
            raise RoutePolicyError("ROUTE_SNAPSHOT_INVALID", {"field": "apps"})
        apps = {}
        for name, data in apps_data.items():
            _require_name(name, field="app")
            if not isinstance(data, dict):
                raise RoutePolicyError("ROUTE_SNAPSHOT_INVALID", {"app": name})
            config = self._parse_policy_snapshot(data, require_dns_mode=True)
            if "dns_zones" not in data:
                raise RoutePolicyError(
                    "ROUTE_SNAPSHOT_INVALID", {"app": name, "field": "dns_zones"}
                )
            config["dns_zones"] = _zone_tuple(data["dns_zones"])
            config.pop("default_via", None)
            apps[name] = config

        stats_data = state["stats"]
        if not isinstance(stats_data, dict):
            raise RoutePolicyError("ROUTE_SNAPSHOT_INVALID", {"field": "stats"})
        missing_stats = [key for key in STAT_KEYS if key not in stats_data]
        if missing_stats:
            raise RoutePolicyError(
                "ROUTE_SNAPSHOT_INVALID", {"missing_stats": missing_stats}
            )
        stats = {}
        for key in STAT_KEYS:
            value = stats_data[key]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise RoutePolicyError(
                    "ROUTE_SNAPSHOT_INVALID", {"stat": key, "value": value}
                )
            stats[key] = value

        return {
            "global": global_config,
            "tenants": tenants,
            "apps": apps,
            "stats": stats,
        }

    def _parse_policy_snapshot(
        self,
        data: object,
        *,
        require_default_via: bool = False,
        require_dns_mode: bool = False,
    ) -> dict:
        if not isinstance(data, dict):
            raise RoutePolicyError("ROUTE_SNAPSHOT_INVALID", "policy must be object")
        if "includes" not in data or "excludes" not in data:
            raise RoutePolicyError("ROUTE_SNAPSHOT_INVALID", "missing rule lists")

        config = {
            "includes": _cidr_tuple(data["includes"]),
            "excludes": _cidr_tuple(data["excludes"]),
        }

        if require_default_via or "default_via" in data:
            config["default_via"] = _validate_egress(
                data.get("default_via"), allow_none=True
            )
        else:
            config["default_via"] = None

        if require_dns_mode or "dns_mode" in data:
            config["dns_mode"] = _validate_dns_mode(data.get("dns_mode", "tunnel"))

        return config
