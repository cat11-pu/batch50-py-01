"""TLS inspection decisions: per-tenant CA selection, pinned bypass, CA reload."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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


class InspectionBroker:
    """Decide inspect or bypass for a TLS connection and pick the signing CA."""

    def __init__(self, *, default_ca: str = "ca-root", window_seconds: int = 900,
                 allow_quic_downgrade: bool = True,
                 max_decisions: int = 1024) -> None:
        self.default_ca = default_ca
        self.window_seconds = window_seconds
        self.allow_quic_downgrade = allow_quic_downgrade
        self.max_decisions = max_decisions
        self._lock = threading.RLock()
        self._generation = 1
        self._ca_bundle: dict = {default_ca: ["*"]}
        self._previous_ca: dict = {}
        self._tenants: dict = {}
        self._decisions: dict = {}
        self._windows: dict = {}
        self._counters: dict = {}

    def reload_ca(self, bundle: dict) -> int:
        raise NotImplementedError

    def ca_for_sni(self, sni: str) -> str:
        raise NotImplementedError

    def set_tenant_policy(self, tenant: str, *, mode: str,
                          pinned_hosts=()) -> None:
        raise NotImplementedError

    def decide(self, conn_id: str, *, sni: str, tenant: str,
               client_pinned: bool = False, transport: str = "tcp",
               now=None) -> Decision:
        raise NotImplementedError

    def reissue_context(self, conn_id: str, *, now=None) -> ReissueContext:
        raise NotImplementedError

    def bypass_window(self, conn_id: str, *, seconds=None, now=None) -> int:
        raise NotImplementedError

    def close_window(self, conn_id: str) -> bool:
        raise NotImplementedError

    def expire_windows(self, now=None) -> int:
        raise NotImplementedError

    def decision_for(self, conn_id: str):
        raise NotImplementedError

    def ca_ids(self) -> tuple:
        raise NotImplementedError

    def ca_generation(self) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
