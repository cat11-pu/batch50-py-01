"""Package transaction ledger: global lock, per-step intent journal, crash recovery."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class PkgError(ValueError):
    """Raised when a package transaction is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class StepRecord:
    seq: int
    op: str
    package: str
    from_version: str | None
    to_version: str | None
    state: str
    intent_at: int | None
    applied_at: int | None


@dataclass(frozen=True)
class TransactionView:
    txid: str
    owner: str
    state: str
    step_total: int
    applied: int
    lock_expires_at: int | None


class PkgTransactionLedger:
    """Serialize package changes behind one global lock and an intent journal."""

    def __init__(self, *, lock_lease_ms: int = 30000) -> None:
        self.lock_lease_ms = lock_lease_ms
        self._lock = threading.RLock()

    def seed_installed(self, package: str, version: str) -> None:
        raise NotImplementedError

    def installed(self, package: str | None = None):
        raise NotImplementedError

    def begin(self, owner: str, requests, *, now: int,
              lease_ms: int | None = None) -> str:
        raise NotImplementedError

    def stage(self, txid: str, *, now: int) -> StepRecord:
        raise NotImplementedError

    def commit(self, txid: str, *, now: int, limit: int | None = None) -> dict:
        raise NotImplementedError

    def abort(self, txid: str, *, now: int) -> int:
        raise NotImplementedError

    def recover(self, txid: str, *, now: int) -> dict:
        raise NotImplementedError

    def holders(self):
        raise NotImplementedError

    def status(self, txid: str) -> TransactionView:
        raise NotImplementedError

    def journal(self, txid: str) -> tuple[StepRecord, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
