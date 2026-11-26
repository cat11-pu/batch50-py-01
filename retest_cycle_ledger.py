"""Vulnerability retest cycle ledger: tri-state results, close gate, regressions."""

from __future__ import annotations

import threading


class LedgerError(ValueError):
    """Raised when the ledger refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


CONCLUSION_FIXED = "fixed"
CONCLUSION_STILL_PRESENT = "still_present"
CONCLUSION_NOT_REPRODUCIBLE = "not_reproducible"

CONCLUSIONS = (CONCLUSION_FIXED, CONCLUSION_STILL_PRESENT,
               CONCLUSION_NOT_REPRODUCIBLE)
REOPENABLE = (CONCLUSION_FIXED, CONCLUSION_NOT_REPRODUCIBLE)

STATE_OPEN = "open"
STATE_CLOSED = "closed"


class RetestCycleLedger:
    """Track retest batches over a fixed set of findings."""

    def __init__(self, *, max_rounds: int = 5) -> None:
        self.max_rounds = max_rounds
        self._lock = threading.RLock()
        self._batches: dict[str, dict] = {}
        self._history: dict[str, list[dict]] = {}
        self._counters: dict[str, int] = {}

    def open_batch(self, batch_id: str, *, findings: list[str],
                   now: str, owner: str = "") -> dict:
        raise NotImplementedError

    def add_findings(self, batch_id: str, findings: list[str], *, now: str) -> dict:
        raise NotImplementedError

    def record_result(self, batch_id: str, finding_id: str, *, conclusion: str,
                      evidence: str = "", note: str = "", now: str) -> dict:
        raise NotImplementedError

    def reopen(self, batch_id: str, finding_id: str, *, reason: str,
               now: str) -> dict:
        raise NotImplementedError

    def close_batch(self, batch_id: str, *, actor: str, now: str) -> dict:
        raise NotImplementedError

    def pending(self, batch_id: str) -> list[str]:
        raise NotImplementedError

    def summary(self, batch_id: str) -> dict:
        raise NotImplementedError

    def history(self, batch_id: str) -> list[dict]:
        raise NotImplementedError

    def batches(self) -> list[dict]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
