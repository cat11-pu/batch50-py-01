"""Validate inbound ICMP redirect, unreachable and fragmentation-needed messages."""

from __future__ import annotations

import copy
import ipaddress
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass


_KINDS = frozenset({"redirect", "unreachable", "frag_needed"})
_QUOTE_FIELDS = ("src", "dst", "proto", "sport", "dport")
_REQUIRED_COUNTERS = ("accepted", "rejected", "alerts", "evicted", "purged")
_SNAPSHOT_KEYS = frozenset(
    {"version", "routes", "redirects", "cache", "mtus", "counters"}
)


class IcmpGuardError(ValueError):
    """Raised when an ICMP packet or snapshot is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Verdict:
    action: str
    reason: str
    kind: str


@dataclass(frozen=True)
class Route:
    destination: str
    gateway: str
    iface: str
    metric: int = 0


def _parse_ip(value):
    if isinstance(value, (ipaddress.IPv4Address, ipaddress.IPv6Address)):
        return value
    if not isinstance(value, str):
        raise ValueError("IP address must be a string")
    return ipaddress.ip_address(value)


def _parse_network(value):
    if isinstance(value, (ipaddress.IPv4Network, ipaddress.IPv6Network)):
        return value
    if not isinstance(value, str):
        raise ValueError("network must be a string")
    return ipaddress.ip_network(value, strict=False)


def _resolve_now(now):
    return time.monotonic() if now is None else float(now)


class IcmpRedirectGuard:
    """Judge inbound ICMP control messages against local routing state."""

    def __init__(self, *, local_networks, gateways, rate_limit: int = 5,
                 rate_window: float = 1.0, cache_ttl: float = 30.0,
                 max_entries: int = 256, min_ipv4_mtu: int = 68,
                 min_ipv6_mtu: int = 1280) -> None:
        self.local_networks = tuple(local_networks)
        self.gateway_list = tuple(gateways)
        self.rate_limit = rate_limit
        self.rate_window = rate_window
        self.cache_ttl = cache_ttl
        self.max_entries = max_entries
        self.min_ipv4_mtu = min_ipv4_mtu
        self.min_ipv6_mtu = min_ipv6_mtu
        self._lock = threading.RLock()

        self._networks = tuple(
            _parse_network(network) for network in self.local_networks
        )
        self._gateway_strings = tuple(
            gateway if isinstance(gateway, str) else str(gateway)
            for gateway in self.gateway_list
        )
        self._gateway_addresses = tuple(
            _parse_ip(gateway) for gateway in self.gateway_list
        )
        self._gateway_set = frozenset(self._gateway_addresses)
        self._base_routes: list[Route] = []
        self._base_networks = []
        self._redirects: dict[str, Route] = {}
        self._cache: OrderedDict[tuple, tuple[Verdict, float]] = OrderedDict()
        self._mtus: dict[str, int] = {}
        self._rate: dict[str, dict] = {}
        self._counters = {name: 0 for name in _REQUIRED_COUNTERS}
        self._closed = False

    @staticmethod
    def _kind_of(packet) -> str:
        if not isinstance(packet, dict):
            return ""
        kind = packet.get("kind")
        if isinstance(kind, str):
            return kind
        return "" if kind is None else str(kind)

    def _drop(self, reason: str, kind: str) -> Verdict:
        self._counters["rejected"] += 1
        return Verdict("drop", reason, kind)

    def _accept(self, reason: str, kind: str) -> Verdict:
        self._counters["accepted"] += 1
        return Verdict("accept", reason, kind)

    def _parse_quote(self, packet: dict):
        quoted = packet.get("quoted")
        if not isinstance(quoted, dict):
            return None
        if any(
            field not in quoted or quoted[field] is None
            for field in _QUOTE_FIELDS
        ):
            return None
        try:
            _parse_ip(quoted["src"])
            dst_ip = _parse_ip(quoted["dst"])
        except (TypeError, ValueError):
            return None
        proto = quoted["proto"]
        sport = quoted["sport"]
        dport = quoted["dport"]
        if isinstance(proto, bool) or not isinstance(proto, (str, int)):
            return None
        if isinstance(proto, str) and not proto:
            return None
        if isinstance(proto, int) and not 0 <= proto <= 255:
            return None
        if any(
            isinstance(port, bool)
            or not isinstance(port, int)
            or not 0 <= port <= 65535
            for port in (sport, dport)
        ):
            return None
        key = (quoted["src"], quoted["dst"], proto, sport, dport)
        return key, dst_ip

    def _lookup_route(self, destination, *, allow_default=True):
        best = None
        best_prefix = -1
        best_metric = None
        for route, network in zip(self._base_routes, self._base_networks):
            if destination.version != network.version:
                continue
            if not allow_default and network.prefixlen == 0:
                continue
            if destination not in network:
                continue
            if (
                network.prefixlen > best_prefix
                or (
                    network.prefixlen == best_prefix
                    and (
                        best_metric is None
                        or route.metric < best_metric
                    )
                )
            ):
                best = route
                best_prefix = network.prefixlen
                best_metric = route.metric
        return best

    def _route_gateway_matches(self, route: Route, source) -> bool:
        try:
            return _parse_ip(route.gateway) == source
        except (TypeError, ValueError):
            return False

    def _store_cache(self, key, verdict: Verdict, now: float) -> None:
        self._cache[key] = (verdict, now)
        self._cache.move_to_end(key)
        limit = max(0, int(self.max_entries))
        while len(self._cache) > limit:
            self._cache.popitem(last=False)
            self._counters["evicted"] += 1

    def _cache_is_expired(self, created: float, now: float) -> bool:
        return now - created > self.cache_ttl

    def _lookup_cache(self, key, now: float):
        try:
            entry = self._cache.get(key)
        except TypeError:
            return None
        if entry is None:
            return None
        verdict, created = entry
        if self._cache_is_expired(created, now):
            del self._cache[key]
            self._counters["purged"] += 1
            return None
        return verdict

    def _rate_allowed(self, gateway: str, now: float) -> bool:
        state = self._rate.setdefault(
            gateway, {"times": [], "alerted": False}
        )
        cutoff = now - self.rate_window
        retained = []
        for arrived in state["times"]:
            if arrived > now or arrived > cutoff:
                retained.append(arrived)
        state["times"] = retained
        recent = sum(
            1
            for arrived in retained
            if arrived <= now and now - arrived < self.rate_window
        )
        if recent < self.rate_limit:
            state["alerted"] = False
            retained.append(now)
            return True
        if not state["alerted"]:
            state["alerted"] = True
            self._counters["alerts"] += 1
        return False

    def on_icmp(self, packet: dict, *, now: float | None = None) -> Verdict:
        current = _resolve_now(now)
        kind = self._kind_of(packet)
        with self._lock:
            if self._closed:
                return self._drop("closed", kind)
            if not isinstance(packet, dict):
                return self._drop("malformed", kind)

            try:
                source = _parse_ip(packet.get("src"))
            except (TypeError, ValueError):
                source = None
            if source is None or source not in self._gateway_set:
                return self._drop("not_gateway", kind)

            if kind not in _KINDS:
                return self._drop("unsupported", kind)

            parsed_quote = self._parse_quote(packet)
            if parsed_quote is None:
                return self._drop("malformed", kind)
            key, quoted_destination = parsed_quote

            route = self._lookup_route(
                quoted_destination, allow_default=kind != "redirect"
            )
            if route is None or not self._route_gateway_matches(route, source):
                return self._drop("quoted_mismatch", kind)

            if kind == "frag_needed":
                mtu = packet.get("mtu")
                if isinstance(mtu, bool) or not isinstance(mtu, int):
                    return self._drop("malformed", kind)
                minimum = (
                    self.min_ipv4_mtu
                    if quoted_destination.version == 4
                    else self.min_ipv6_mtu
                )
                if mtu < minimum:
                    return self._drop("mtu_too_low", kind)
                self._mtus[str(quoted_destination)] = mtu
                return self._accept("path_mtu_updated", kind)

            if kind == "unreachable":
                verdict = self._accept("ok", kind)
                self._store_cache(key, verdict, current)
                return verdict

            raw_next_hop = packet.get("gateway")
            try:
                next_hop = _parse_ip(raw_next_hop)
            except (TypeError, ValueError):
                return self._drop("malformed", kind)
            if (
                next_hop.version != quoted_destination.version
                or not any(
                    next_hop.version == network.version
                    and next_hop in network
                    for network in self._networks
                )
            ):
                return self._drop("gateway_not_local", kind)
            if not self._rate_allowed(str(source), current):
                return self._drop("rate_limited", kind)

            prefix = next_hop.max_prefixlen
            destination = f"{quoted_destination}/{prefix}"
            gateway_text = (
                raw_next_hop
                if isinstance(raw_next_hop, str)
                else str(next_hop)
            )
            self._redirects[str(quoted_destination)] = Route(
                destination, gateway_text, route.iface, route.metric
            )
            verdict = self._accept("ok", kind)
            self._store_cache(key, verdict, current)
            return verdict

    def route_changed(self, routes, *, now: float | None = None) -> int:
        del now
        parsed = []
        with self._lock:
            for route in routes:
                if not isinstance(route, Route):
                    raise IcmpGuardError("ICMP_ROUTE_INVALID", route)
                try:
                    network = _parse_network(route.destination)
                    _parse_ip(route.gateway)
                except (TypeError, ValueError) as exc:
                    raise IcmpGuardError("ICMP_ROUTE_INVALID", route) from exc
                if (
                    not isinstance(route.iface, str)
                    or isinstance(route.metric, bool)
                    or not isinstance(route.metric, int)
                ):
                    raise IcmpGuardError("ICMP_ROUTE_INVALID", route)
                parsed.append((route, network))

            removed = len(self._cache)
            self._cache.clear()
            self._redirects.clear()
            self._base_routes = [item[0] for item in parsed]
            self._base_networks = [item[1] for item in parsed]
            return removed

    def verdict(self, key, *, now: float | None = None) -> Verdict | None:
        current = _resolve_now(now)
        if isinstance(key, list):
            key = tuple(key)
        with self._lock:
            return self._lookup_cache(key, current)

    def path_mtu(self, destination: str) -> int | None:
        try:
            key = str(_parse_ip(destination))
        except (TypeError, ValueError):
            key = destination
        with self._lock:
            return self._mtus.get(key)

    def purge_expired(self, *, now: float | None = None) -> int:
        current = _resolve_now(now)
        with self._lock:
            expired = [
                key
                for key, (_verdict, created) in self._cache.items()
                if self._cache_is_expired(created, current)
            ]
            for key in expired:
                del self._cache[key]
            self._counters["purged"] += len(expired)
            return len(expired)

    def gateways(self) -> tuple[str, ...]:
        with self._lock:
            return self._gateway_strings

    def routes(self) -> tuple[Route, ...]:
        with self._lock:
            return tuple(self._base_routes) + tuple(self._redirects.values())

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._counters)

    @staticmethod
    def _route_to_state(route: Route) -> dict:
        return {
            "destination": route.destination,
            "gateway": route.gateway,
            "iface": route.iface,
            "metric": route.metric,
        }

    @classmethod
    def _route_from_state(cls, value) -> Route:
        if not isinstance(value, dict):
            raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", value)
        required = {"destination", "gateway", "iface", "metric"}
        if set(value) != required:
            raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", value)
        destination = value["destination"]
        gateway = value["gateway"]
        iface = value["iface"]
        metric = value["metric"]
        try:
            _parse_network(destination)
            _parse_ip(gateway)
        except (TypeError, ValueError) as exc:
            raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", value) from exc
        if (
            not isinstance(destination, str)
            or not isinstance(gateway, str)
            or not isinstance(iface, str)
            or isinstance(metric, bool)
            or not isinstance(metric, int)
        ):
            raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", value)
        return Route(destination, gateway, iface, metric)

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(
                {
                    "version": 1,
                    "routes": [
                        self._route_to_state(route)
                        for route in self._base_routes
                    ],
                    "redirects": {
                        destination: self._route_to_state(route)
                        for destination, route in self._redirects.items()
                    },
                    "cache": {
                        key: {
                            "action": verdict.action,
                            "reason": verdict.reason,
                            "kind": verdict.kind,
                            "created": created,
                        }
                        for key, (verdict, created) in self._cache.items()
                    },
                    "mtus": dict(self._mtus),
                    "counters": dict(self._counters),
                }
            )

    def _validated_snapshot_state(self, state):
        if not isinstance(state, dict):
            raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state)
        if set(state) != _SNAPSHOT_KEYS:
            raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state)
        if type(state["version"]) is not int or state["version"] != 1:
            raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state["version"])
        if not isinstance(state["routes"], list):
            raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state["routes"])
        if not isinstance(state["redirects"], dict):
            raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state["redirects"])
        if not isinstance(state["cache"], dict):
            raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state["cache"])
        if not isinstance(state["mtus"], dict):
            raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state["mtus"])
        if not isinstance(state["counters"], dict):
            raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state["counters"])

        routes = [self._route_from_state(item) for item in state["routes"]]

        redirects = {}
        for destination, value in state["redirects"].items():
            if not isinstance(destination, str):
                raise IcmpGuardError(
                    "ICMP_SNAPSHOT_INVALID", state["redirects"]
                )
            try:
                destination_ip = _parse_ip(destination)
            except (TypeError, ValueError) as exc:
                raise IcmpGuardError(
                    "ICMP_SNAPSHOT_INVALID", state["redirects"]
                ) from exc
            route = self._route_from_state(value)
            host = ipaddress.ip_network(
                f"{destination_ip}/{destination_ip.max_prefixlen}"
            )
            try:
                route_network = _parse_network(route.destination)
                gateway_ip = _parse_ip(route.gateway)
            except (TypeError, ValueError) as exc:
                raise IcmpGuardError(
                    "ICMP_SNAPSHOT_INVALID", state["redirects"]
                ) from exc
            if route_network != host:
                raise IcmpGuardError(
                    "ICMP_SNAPSHOT_INVALID", state["redirects"]
                )
            if (
                gateway_ip.version != destination_ip.version
                or not any(
                    gateway_ip.version == network.version
                    and gateway_ip in network
                    for network in self._networks
                )
            ):
                raise IcmpGuardError(
                    "ICMP_SNAPSHOT_INVALID", state["redirects"]
                )
            redirects[str(destination_ip)] = route

        cache = OrderedDict()
        for key, value in state["cache"].items():
            if not isinstance(key, tuple) or len(key) != len(_QUOTE_FIELDS):
                raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state["cache"])
            try:
                _parse_ip(key[0])
                _parse_ip(key[1])
            except (TypeError, ValueError) as exc:
                raise IcmpGuardError(
                    "ICMP_SNAPSHOT_INVALID", state["cache"]
                ) from exc
            proto, sport, dport = key[2], key[3], key[4]
            if (
                isinstance(proto, bool)
                or not isinstance(proto, (str, int))
                or (isinstance(proto, str) and not proto)
                or (isinstance(proto, int) and not 0 <= proto <= 255)
                or any(
                    isinstance(port, bool)
                    or not isinstance(port, int)
                    or not 0 <= port <= 65535
                    for port in (sport, dport)
                )
            ):
                raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state["cache"])
            if not isinstance(value, dict):
                raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state["cache"])
            if set(value) != {"action", "reason", "kind", "created"}:
                raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state["cache"])
            action = value["action"]
            reason = value["reason"]
            entry_kind = value["kind"]
            created = value["created"]
            if (
                not isinstance(action, str)
                or not isinstance(reason, str)
                or not isinstance(entry_kind, str)
                or isinstance(created, bool)
                or not isinstance(created, (int, float))
            ):
                raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state["cache"])
            cache[key] = (
                Verdict(action, reason, entry_kind),
                float(created),
            )

        mtus = {}
        for destination, mtu in state["mtus"].items():
            if not isinstance(destination, str):
                raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state["mtus"])
            try:
                canonical = str(_parse_ip(destination))
            except (TypeError, ValueError) as exc:
                raise IcmpGuardError(
                    "ICMP_SNAPSHOT_INVALID", state["mtus"]
                ) from exc
            if (
                isinstance(mtu, bool)
                or not isinstance(mtu, int)
                or mtu <= 0
            ):
                raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state["mtus"])
            mtus[canonical] = mtu

        counters = state["counters"]
        if any(name not in counters for name in _REQUIRED_COUNTERS):
            raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", counters)
        for name, value in counters.items():
            if (
                not isinstance(name, str)
                or isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
            ):
                raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", counters)

        base_networks = [
            _parse_network(route.destination) for route in routes
        ]
        return routes, base_networks, redirects, cache, mtus, dict(counters)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                (
                    routes,
                    base_networks,
                    redirects,
                    cache,
                    mtus,
                    counters,
                ) = self._validated_snapshot_state(state)
            except IcmpGuardError:
                raise
            except Exception as exc:
                raise IcmpGuardError("ICMP_SNAPSHOT_INVALID", state) from exc

            self._base_routes = routes
            self._base_networks = base_networks
            self._redirects = redirects
            self._cache = cache
            self._mtus = mtus
            self._counters = counters
            self._rate.clear()

    def close(self) -> None:
        with self._lock:
            self._closed = True
