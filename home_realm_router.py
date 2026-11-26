"""Login-domain to home-realm discovery with longest-suffix matching."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class HomeRealmError(ValueError):
    """Raised when a routing operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DomainRule:
    domain: str
    tenant: str
    realm: str
    priority: int
    revision: int
    state: str
    updated_at: str


@dataclass(frozen=True)
class Resolution:
    email: str
    domain: str
    matched_domain: str | None
    tenant: str | None
    realm: str
    source: str
    conflict: bool
    degraded: bool
    attempted_realm: str | None
    reason: str | None


class HomeRealmRouter:
    """Route an email domain to the identity source that owns it."""

    def __init__(self, *, default_realm: str = "local",
                 cache_ttl: int = 300, max_domains: int = 100) -> None:
        self.default_realm = default_realm
        self.cache_ttl = cache_ttl
        self.max_domains = max_domains
        self._lock = threading.RLock()

    def register_domain(self, domain: str, *, tenant: str, realm: str,
                        priority: int = 0,
                        now: str | None = None) -> DomainRule:
        raise NotImplementedError

    def unregister_domain(self, domain: str, *, tenant: str,
                          now: str | None = None) -> bool:
        raise NotImplementedError

    def resolve(self, email: str, *, now: str | None = None) -> Resolution:
        raise NotImplementedError

    def refresh(self, *, now: str | None = None) -> int:
        raise NotImplementedError

    def mark_unavailable(self, realm: str) -> None:
        raise NotImplementedError

    def mark_available(self, realm: str) -> None:
        raise NotImplementedError

    def fallback(self, email: str, *, reason: str = "unavailable",
                 now: str | None = None) -> Resolution:
        raise NotImplementedError

    def rules(self) -> list[DomainRule]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
