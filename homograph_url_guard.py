"""Homograph URL guard: script mixing, brand lookalikes, registrable-domain allowlists."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class UrlGuardError(ValueError):
    """Raised when a URL analysis or feedback operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class UrlVerdict:
    url: str
    host: str
    ascii_host: str
    unicode_host: str
    registrable_domain: str
    scripts: tuple[str, ...]
    brand: str | None
    similarity: float
    risk: str
    reasons: tuple[str, ...]
    redirect_chain: tuple[str, ...]
    cached: bool = False


class HomographUrlGuard:
    """Score URLs for brand impersonation before mail or browser delivery."""

    def __init__(self, *, brands=None, public_suffixes=None,
                 max_redirects: int = 5, report_threshold: int = 3) -> None:
        self._brands = dict(brands or {})
        self._suffixes = tuple(public_suffixes or (
            "com", "net", "org", "io", "test", "co.uk", "com.cn", "co.jp"))
        self.max_redirects = max_redirects
        self.report_threshold = report_threshold
        self._lock = threading.RLock()

    def add_brand(self, brand: str, *, domains=(), keywords=()) -> int:
        raise NotImplementedError

    def analyze(self, url: str, *, redirects=None,
                now: int | None = None) -> UrlVerdict:
        raise NotImplementedError

    def explain(self, url: str, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def allowlist(self, domain: str, *, ttl: int | None = None,
                  now: int | None = None) -> None:
        raise NotImplementedError

    def is_allowlisted(self, host: str, *, now: int | None = None) -> bool:
        raise NotImplementedError

    def feedback(self, url: str, *, label: str, now: int | None = None) -> dict:
        raise NotImplementedError

    def sweep(self, urls, *, now: int | None = None) -> list[UrlVerdict]:
        raise NotImplementedError

    def registrable_domain(self, host: str) -> str:
        raise NotImplementedError

    def normalize_host(self, url: str) -> str:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
