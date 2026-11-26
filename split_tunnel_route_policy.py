"""Split-tunnel route compilation with longest-prefix resolution and DNS ownership."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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


@dataclass(frozen=True)
class RouteExplanation:
    destination: str
    egress: str
    matched_prefix: object
    source: str


class SplitTunnelPolicy:
    """Compile global, tenant and per-application route rules into one plan."""

    def __init__(self, *, max_routes: int = 512) -> None:
        self.max_routes = max_routes
        self._lock = threading.RLock()
        self._global: dict = {}
        self._tenants: dict = {}
        self._apps: dict = {}
        self._installed: dict = {}
        self._last_plan = None
        self._counters: dict = {}

    def set_global(self, *, includes=(), excludes=(),
                   default_via: str = "tunnel") -> None:
        raise NotImplementedError

    def set_tenant(self, tenant: str, *, includes=(), excludes=(),
                   default_via=None, dns_mode: str = "tunnel") -> None:
        raise NotImplementedError

    def set_app(self, app: str, *, includes=(), excludes=(),
                dns_zones=(), dns_mode: str = "tunnel") -> None:
        raise NotImplementedError

    def compile(self, *, tenant=None, apps=(), now=None) -> CompiledPlan:
        raise NotImplementedError

    def apply(self, plan: CompiledPlan, *, now=None) -> int:
        raise NotImplementedError

    def remove(self, *, app=None) -> int:
        raise NotImplementedError

    def reclaim(self) -> int:
        raise NotImplementedError

    def explain(self, destination: str, *, tenant=None,
                apps=()) -> RouteExplanation:
        raise NotImplementedError

    def dns_route(self, name: str, *, tenant=None, apps=()) -> str:
        raise NotImplementedError

    def installed(self) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
