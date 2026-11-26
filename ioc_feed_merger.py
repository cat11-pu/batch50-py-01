"""Multi source IOC feed merger: weighted confidence, TTL decay, priority verdicts."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class IocError(ValueError):
    """Raised when a feed merger operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


KIND_INTEL = "intel"
KIND_WHITELIST = "whitelist"
KINDS = (KIND_INTEL, KIND_WHITELIST)

VERDICT_BLOCK = "block"
VERDICT_ALLOW = "allow"

IOC_TYPES = ("domain", "ipv4", "sha256", "url")


@dataclass(frozen=True)
class SourceRecord:
    name: str
    weight: float
    priority: int
    kind: str
    added_at: str


class IocFeedMerger:
    """Merge indicators coming from several feeds into one verdict per indicator."""

    def __init__(self, *, halflife_seconds: int = 86400,
                 batch_limit: int = 32) -> None:
        self.halflife_seconds = halflife_seconds
        self.batch_limit = batch_limit
        self._lock = threading.RLock()
        self._sources: dict[str, SourceRecord] = {}
        self._observations: dict[tuple[str, str], dict[str, dict]] = {}
        self._audit: list[dict] = []
        self._counters: dict[str, int] = {}

    def register_source(self, name: str, *, weight: float, priority: int,
                        kind: str, now: str) -> SourceRecord:
        raise NotImplementedError

    def ingest_feed(self, source: str, items: list[dict], *, now: str) -> dict:
        raise NotImplementedError

    def merge(self, *, now: str) -> list[dict]:
        raise NotImplementedError

    def lookup(self, ioc_type: str, value: str, *, now: str) -> dict:
        raise NotImplementedError

    def effective_confidence(self, ioc_type: str, value: str, *, now: str) -> float:
        raise NotImplementedError

    def expire_sweep(self, *, now: str, batch_size: int | None = None) -> list[str]:
        raise NotImplementedError

    def sources(self) -> list[SourceRecord]:
        raise NotImplementedError

    def audit(self) -> list[dict]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
