"""MTA-STS outbound policy cache: max-age freshness, MX matching, report caps."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class StsError(ValueError):
    """Raised when a policy cannot be fetched or parsed."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PolicyRecord:
    domain: str
    policy_id: str
    mode: str
    max_age: int
    mx: tuple
    fetched_at: int
    expires_at: int


@dataclass(frozen=True)
class DeliveryDecision:
    domain: str
    mx_host: str
    action: str
    reason: str
    policy_id: object


class MtaStsEnforcer:
    """Cache sender-domain MTA-STS policies and decide outbound delivery mode."""

    def __init__(self, *, fetcher, cache_capacity: int = 64,
                 report_capacity: int = 128) -> None:
        self._fetcher = fetcher
        self.cache_capacity = cache_capacity
        self.report_capacity = report_capacity
        self._lock = threading.RLock()
        self._policies: dict = {}
        self._reports: dict = {}
        self._failures: dict = {}
        self._counters: dict = {}

    def fetch(self, domain: str, *, now=None, force: bool = False) -> PolicyRecord:
        raise NotImplementedError

    def decide(self, domain: str, mx_host: str, *, now=None) -> DeliveryDecision:
        raise NotImplementedError

    def refresh(self, domain: str, *, now=None) -> bool:
        raise NotImplementedError

    def policy_for(self, domain: str, *, now=None):
        raise NotImplementedError

    def mx_matches(self, domain: str, host: str, *, now=None) -> bool:
        raise NotImplementedError

    def report(self) -> dict:
        raise NotImplementedError

    def purge_expired(self, now) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
