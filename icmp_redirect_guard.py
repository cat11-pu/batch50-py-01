"""Validate inbound ICMP redirect, unreachable and fragmentation-needed messages."""

from __future__ import annotations

import ipaddress
import threading
from dataclasses import dataclass


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

    def on_icmp(self, packet: dict, *, now: float | None = None) -> Verdict:
        raise NotImplementedError

    def route_changed(self, routes, *, now: float | None = None) -> int:
        raise NotImplementedError

    def verdict(self, key, *, now: float | None = None) -> Verdict | None:
        raise NotImplementedError

    def path_mtu(self, destination: str) -> int | None:
        raise NotImplementedError

    def purge_expired(self, *, now: float | None = None) -> int:
        raise NotImplementedError

    def gateways(self) -> tuple[str, ...]:
        raise NotImplementedError

    def routes(self) -> tuple[Route, ...]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError
