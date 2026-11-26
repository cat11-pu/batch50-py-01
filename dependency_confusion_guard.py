"""Dependency confusion guard: namespace ownership, lookalike scoring, source priority."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class DependencyGuardError(ValueError):
    """Raised when a package verdict or ledger operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Verdict:
    package: str
    ecosystem: str
    version: str
    source: str | None
    decision: str
    reasons: tuple[str, ...]
    similarity: float
    cached: bool = False


class DependencyConfusionGuard:
    """Admit dependencies by namespace, publisher history and source priority."""

    def __init__(self, *, internal_prefix: str = "corp-", similarity_threshold: float = 0.85,
                 publisher_grace_days: int = 30, max_quarantine: int = 100) -> None:
        self.internal_prefix = internal_prefix
        self.similarity_threshold = similarity_threshold
        self.publisher_grace_days = publisher_grace_days
        self.max_quarantine = max_quarantine
        self._lock = threading.RLock()

    def add_source(self, name: str, *, priority: int, kind: str = "public") -> None:
        raise NotImplementedError

    def ingest(self, metadata: dict) -> None:
        raise NotImplementedError

    def evaluate(self, package: str, *, ecosystem: str = "pypi",
                 version: str | None = None, lock_source: str | None = None,
                 now: int | None = None) -> Verdict:
        raise NotImplementedError

    def resolve_batch(self, requests, *, now: int | None = None) -> list[Verdict]:
        raise NotImplementedError

    def allowlist(self, package: str, *, ecosystem: str = "pypi",
                  note: str | None = None) -> None:
        raise NotImplementedError

    def quarantine(self, package: str, *, ecosystem: str = "pypi",
                   version: str | None = None, reason: str = "",
                   ttl: int = 86400, now: int | None = None) -> int:
        raise NotImplementedError

    def release(self, package: str, *, ecosystem: str = "pypi",
                version: str | None = None) -> bool:
        raise NotImplementedError

    def purge_expired(self, now: int | None = None) -> int:
        raise NotImplementedError

    def explain(self, package: str, *, ecosystem: str = "pypi") -> dict:
        raise NotImplementedError

    def policy(self, **changes) -> dict:
        raise NotImplementedError

    def similarity(self, left: str, right: str) -> float:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
