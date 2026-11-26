"""VEX statement ledger: status propagation, evidence expiry and product version ranges."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class VexError(ValueError):
    """Raised when a VEX statement or query operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Statement:
    statement_id: str
    product: str
    component: str
    vulnerability: str
    status: str
    justification: str | None
    evidence_ref: str | None
    introduced: str
    until: str | None
    fixed: str | None
    expires_at: str | None
    created_at: str
    revision: int


@dataclass(frozen=True)
class VexQueryResult:
    verdict: str
    statement_id: str | None
    chain: tuple
    reason: str


class VexStatementLedger:
    """Track exploitability statements and answer SBOM queries per product version."""

    def __init__(self, *, default_evidence_ttl=None, clock=None) -> None:
        self.default_evidence_ttl = default_evidence_ttl
        self._clock = clock
        self._lock = threading.RLock()

    def assert_statement(self, *, product: str, component: str, vulnerability: str,
                         status: str, justification=None, evidence_ref=None,
                         introduced: str = "0.0.0", until=None, fixed=None,
                         expires_at=None, now=None) -> Statement:
        raise NotImplementedError

    def query(self, *, product: str, component: str, version: str,
              vulnerability: str) -> VexQueryResult:
        raise NotImplementedError

    def supersede(self, statement_id: str, *, status: str, justification=None,
                  evidence_ref=None, fixed=None, until=None, now=None) -> Statement:
        raise NotImplementedError

    def expire(self, now=None) -> int:
        raise NotImplementedError

    def register_dependency(self, product: str, component: str,
                            depends_on: str) -> None:
        raise NotImplementedError

    def export(self) -> tuple:
        raise NotImplementedError

    def history(self) -> tuple:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
