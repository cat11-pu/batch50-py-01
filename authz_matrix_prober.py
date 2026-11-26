"""Authorization matrix probing: role/endpoint cartesian product, sharded progress, rate budget."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class MatrixError(ValueError):
    """Raised when a matrix operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    domain: str
    resource_kind: str
    write: bool


@dataclass(frozen=True)
class Role:
    name: str
    account_id: str
    write_allowed: bool


@dataclass(frozen=True)
class MatrixEntry:
    index: int
    fingerprint: str
    method: str
    path: str
    domain: str
    role: str
    account_id: str
    expectation: str
    marker: str
    write: bool


@dataclass(frozen=True)
class ProbeResult:
    index: int
    fingerprint: str
    verdict: str
    status_code: int
    evidence: dict


class AuthzMatrixProber:
    """Compose an authorization probe matrix and run it in resumable shards."""

    def __init__(self, *, executor=None, max_entries: int = 500,
                 rate_per_minute: int = 60, clock=None) -> None:
        self.executor = executor
        self.max_entries = max_entries
        self.rate_per_minute = rate_per_minute
        self._clock = clock
        self._lock = threading.Lock()

    def register_endpoint(self, method: str, path: str, *, domain: str,
                          resource_kind: str = "own", write: bool = False) -> Endpoint:
        raise NotImplementedError

    def register_role(self, name: str, account_id: str, *,
                      write_allowed: bool = False) -> Role:
        raise NotImplementedError

    def build_matrix(self) -> list:
        raise NotImplementedError

    def run_shard(self, shard_index: int, shard_count: int, *, now=None) -> dict:
        raise NotImplementedError

    def pause(self, reason: str) -> None:
        raise NotImplementedError

    def resume(self, now=None) -> dict:
        raise NotImplementedError

    def progress(self) -> dict:
        raise NotImplementedError

    def report(self) -> dict:
        raise NotImplementedError

    def blocked_roles(self) -> tuple:
        raise NotImplementedError

    def set_rate_budget(self, domain: str, per_minute: int) -> None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
