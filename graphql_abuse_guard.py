"""GraphQL abuse guard: depth and cost budgets, persisted allowlist, per-client quota."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class GraphqlGuardError(ValueError):
    """Raised when a GraphQL request or quota operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Admission:
    fingerprint: str
    depth: int
    cost: int
    client: str
    remaining: int


class GraphqlAbuseGuard:
    """Admit GraphQL operations against cost, depth, whitelist and quota rules."""

    def __init__(self, *, cost_budget: int = 1000, depth_limit: int = 12,
                 burst: int = 10, max_concurrent: int = 4,
                 strict_persisted: bool = True, cost_per_token: int = 100) -> None:
        self.cost_budget = cost_budget
        self.depth_limit = depth_limit
        self.burst = burst
        self.max_concurrent = max_concurrent
        self.strict_persisted = strict_persisted
        self.cost_per_token = cost_per_token
        self._lock = threading.RLock()

    def register_persisted(self, query: str | None = None, *,
                           fingerprint: str | None = None) -> str:
        raise NotImplementedError

    def revoke(self, fingerprint: str) -> bool:
        raise NotImplementedError

    def persisted(self) -> tuple[str, ...]:
        raise NotImplementedError

    def fingerprint(self, query: str) -> str:
        raise NotImplementedError

    def admit(self, query: str, *, client: str = "default",
              now: float | None = None) -> Admission:
        raise NotImplementedError

    def admit_batch(self, queries, *, client: str = "default",
                    now: float | None = None) -> list[Admission]:
        raise NotImplementedError

    def complete(self, client: str = "default") -> None:
        raise NotImplementedError

    def charge(self, client: str, cost: int, *, now: float | None = None) -> int:
        raise NotImplementedError

    def status(self, client: str | None = None) -> dict:
        raise NotImplementedError

    def policy(self, **changes) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
