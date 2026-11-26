"""Inbound DMARC record parsing, policy caching and message evaluation."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass


class DmarcError(ValueError):
    """Raised when a record, request or snapshot is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DmarcPolicy:
    domain: str
    p: str
    sp: str
    pct: int
    adkim: str
    aspf: str
    rua: tuple[str, ...]


@dataclass(frozen=True)
class DmarcResult:
    from_domain: str
    dkim_domain: str | None
    spf_domain: str | None
    dkim_aligned: bool
    spf_aligned: bool
    result: str
    disposition: str
    policy_source: str
    sampled: bool


class DmarcPolicyEvaluator:
    """Evaluate DMARC alignment and disposition for inbound messages."""

    def __init__(self, *, resolver=None, cache_ttl: int = 300,
                 negative_ttl: int = 60, sample_salt: str = "dmarc-v1",
                 max_cache: int = 256, org_suffixes=None) -> None:
        self.resolver = resolver
        self.cache_ttl = cache_ttl
        self.negative_ttl = negative_ttl
        self.sample_salt = sample_salt
        self.max_cache = max_cache
        self.org_suffixes = tuple(
            org_suffixes or ("co.uk", "com.cn", "com.au", "co.jp")
        )
        self._lock = threading.RLock()

    def parse_record(self, domain: str, record_text: str) -> DmarcPolicy:
        raise NotImplementedError

    def organizational_domain(self, domain: str) -> str:
        raise NotImplementedError

    def cache_policy(self, domain: str, record_text: str, *, now: str) -> DmarcPolicy:
        raise NotImplementedError

    def policy_for(self, domain: str, *, now: str) -> DmarcPolicy | None:
        raise NotImplementedError

    def invalidate(self, domain: str) -> bool:
        raise NotImplementedError

    def purge_expired(self, *, now: str) -> int:
        raise NotImplementedError

    def evaluate(self, message: dict, *, now: str | None = None) -> DmarcResult:
        raise NotImplementedError

    def report_aggregate(self, *, domain: str | None = None) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
