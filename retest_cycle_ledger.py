"""Vulnerability retest cycle ledger: tri-state results, close gate, regressions."""

from __future__ import annotations

import copy
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

    SNAPSHOT_VERSION = 1

    def __init__(self, *, max_rounds: int = 5) -> None:
        self.max_rounds = max_rounds
        self._lock = threading.RLock()
        self._batches: dict[str, dict] = {}

    # -- helpers ---------------------------------------------------------

    @staticmethod
    def _is_blank(value: object) -> bool:
        return not isinstance(value, str) or not value.strip()

    def _get_batch(self, batch_id: str) -> dict:
        batch = self._batches.get(batch_id)
        if batch is None:
            raise LedgerError("LEDGER_UNKNOWN_BATCH", batch_id)
        return batch

    @staticmethod
    def _validate_findings(findings: object) -> list[str]:
        if not isinstance(findings, (list, tuple)) or not findings:
            raise LedgerError("LEDGER_BAD_FINDING", findings)
        seen: set[str] = set()
        for finding_id in findings:
            if RetestCycleLedger._is_blank(finding_id):
                raise LedgerError("LEDGER_BAD_FINDING", finding_id)
            if finding_id in seen:
                raise LedgerError("LEDGER_BAD_FINDING", finding_id)
            seen.add(finding_id)
        return list(findings)

    @staticmethod
    def _counts(batch: dict) -> dict:
        counts = {name: 0 for name in CONCLUSIONS}
        for entry in batch["conclusions"].values():
            counts[entry["conclusion"]] += 1
        return counts

    @staticmethod
    def _pending(batch: dict) -> list[str]:
        concluded = batch["conclusions"]
        return sorted(fid for fid in batch["findings"] if fid not in concluded)

    def _view(self, batch: dict) -> dict:
        return {
            "batch_id": batch["batch_id"],
            "state": batch["state"],
            "owner": batch["owner"],
            "opened_at": batch["opened_at"],
            "findings": list(batch["findings"]),
            "rounds": batch["rounds"],
            "regressions": batch["regressions"],
        }

    # -- mutating operations ---------------------------------------------

    def open_batch(self, batch_id: str, *, findings: list[str],
                   now: str, owner: str = "") -> dict:
        with self._lock:
            if self._is_blank(batch_id):
                raise LedgerError("LEDGER_BAD_BATCH", batch_id)
            if batch_id in self._batches:
                raise LedgerError("LEDGER_DUPLICATE_BATCH", batch_id)
            ids = self._validate_findings(findings)
            batch = {
                "batch_id": batch_id,
                "owner": owner,
                "state": STATE_OPEN,
                "opened_at": now,
                "findings": ids,
                "conclusions": {},
                "rounds": 1,
                "regressions": 0,
                "closed_by": None,
                "closed_at": None,
                "history": [],
            }
            self._batches[batch_id] = batch
            return self._view(batch)

    def add_findings(self, batch_id: str, findings: list[str], *, now: str) -> dict:
        with self._lock:
            batch = self._get_batch(batch_id)
            if batch["state"] == STATE_CLOSED:
                raise LedgerError("LEDGER_ALREADY_CLOSED", batch_id)
            ids = self._validate_findings(findings)
            known = set(batch["findings"])
            for finding_id in ids:
                if finding_id not in known:
                    batch["findings"].append(finding_id)
                    known.add(finding_id)
            return self._view(batch)

    def record_result(self, batch_id: str, finding_id: str, *, conclusion: str,
                      evidence: str = "", note: str = "", now: str) -> dict:
        with self._lock:
            batch = self._get_batch(batch_id)
            if batch["state"] == STATE_CLOSED:
                raise LedgerError("LEDGER_ALREADY_CLOSED", batch_id)
            if finding_id not in batch["findings"]:
                raise LedgerError("LEDGER_UNKNOWN_FINDING", finding_id)
            if conclusion not in CONCLUSIONS:
                raise LedgerError("LEDGER_BAD_CONCLUSION", conclusion)
            if conclusion == CONCLUSION_STILL_PRESENT and self._is_blank(evidence):
                raise LedgerError("LEDGER_EVIDENCE_REQUIRED", finding_id)
            record = {
                "finding_id": finding_id,
                "conclusion": conclusion,
                "round": batch["rounds"],
                "at": now,
                "evidence": evidence,
                "note": note,
            }
            batch["conclusions"][finding_id] = {
                "conclusion": conclusion,
                "evidence": evidence,
                "note": note,
                "at": now,
                "round": batch["rounds"],
            }
            batch["history"].append(dict(record))
            record["batch_id"] = batch_id
            return record

    def reopen(self, batch_id: str, finding_id: str, *, reason: str,
               now: str) -> dict:
        with self._lock:
            batch = self._get_batch(batch_id)
            if batch["state"] == STATE_OPEN:
                raise LedgerError("LEDGER_BATCH_OPEN", batch_id)
            if finding_id not in batch["findings"]:
                raise LedgerError("LEDGER_UNKNOWN_FINDING", finding_id)
            current = batch["conclusions"].get(finding_id)
            if self._is_blank(reason):
                raise LedgerError("LEDGER_BAD_REOPEN", finding_id)
            if current is None or current["conclusion"] not in REOPENABLE:
                raise LedgerError("LEDGER_BAD_REOPEN", finding_id)
            if batch["rounds"] + 1 > self.max_rounds:
                raise LedgerError("LEDGER_BAD_REOPEN",
                                  {"batch_id": batch_id,
                                   "max_rounds": self.max_rounds})
            batch["state"] = STATE_OPEN
            batch["closed_by"] = None
            batch["closed_at"] = None
            batch["rounds"] += 1
            batch["regressions"] += 1
            del batch["conclusions"][finding_id]
            return {
                "batch_id": batch_id,
                "finding_id": finding_id,
                "state": batch["state"],
                "rounds": batch["rounds"],
                "regressions": batch["regressions"],
                "reason": reason,
                "at": now,
            }

    def close_batch(self, batch_id: str, *, actor: str, now: str) -> dict:
        with self._lock:
            batch = self._get_batch(batch_id)
            if batch["state"] == STATE_CLOSED:
                raise LedgerError("LEDGER_ALREADY_CLOSED", batch_id)
            missing = self._pending(batch)
            if missing:
                raise LedgerError("LEDGER_INCOMPLETE", missing)
            batch["state"] = STATE_CLOSED
            batch["closed_by"] = actor
            batch["closed_at"] = now
            return {
                "batch_id": batch_id,
                "state": batch["state"],
                "closed_by": actor,
                "closed_at": now,
                "rounds": batch["rounds"],
                "regressions": batch["regressions"],
                "counts": self._counts(batch),
            }

    # -- read-only views ---------------------------------------------------

    def pending(self, batch_id: str) -> list[str]:
        with self._lock:
            return self._pending(self._get_batch(batch_id))

    def summary(self, batch_id: str) -> dict:
        with self._lock:
            batch = self._get_batch(batch_id)
            view = self._view(batch)
            view.update({
                "findings": len(batch["findings"]),
                "pending": len(self._pending(batch)),
                "counts": self._counts(batch),
                "closed_by": batch["closed_by"],
                "closed_at": batch["closed_at"],
            })
            return view

    def history(self, batch_id: str) -> list[dict]:
        with self._lock:
            batch = self._get_batch(batch_id)
            return [dict(entry) for entry in batch["history"]]

    def batches(self) -> list[dict]:
        with self._lock:
            return [self._view(batch) for batch in self._batches.values()]

    def stats(self) -> dict:
        with self._lock:
            batches = list(self._batches.values())
            regressions = sum(batch["regressions"] for batch in batches)
            return {
                "batches": len(batches),
                "open": sum(1 for b in batches if b["state"] == STATE_OPEN),
                "closed": sum(1 for b in batches if b["state"] == STATE_CLOSED),
                "records": sum(len(b["history"]) for b in batches),
                "reopens": regressions,
                "regressions": regressions,
                "findings": sum(len(b["findings"]) for b in batches),
            }

    # -- snapshot / restore ------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self.SNAPSHOT_VERSION,
                "max_rounds": self.max_rounds,
                "batches": copy.deepcopy(self._batches),
            }

    @classmethod
    def _validate_snapshot(cls, state: object) -> dict:
        def fail(detail: object = None) -> None:
            raise LedgerError("LEDGER_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict):
            fail(state)
        if state.get("version") != cls.SNAPSHOT_VERSION:
            fail(state.get("version"))
        batches = state.get("batches")
        if not isinstance(batches, dict):
            fail("batches")
        for batch_id, batch in batches.items():
            if not isinstance(batch_id, str) or not batch_id.strip():
                fail(batch_id)
            if not isinstance(batch, dict):
                fail(batch_id)
            if batch.get("batch_id") != batch_id:
                fail(batch_id)
            if batch.get("state") not in (STATE_OPEN, STATE_CLOSED):
                fail(batch_id)
            if not isinstance(batch.get("owner"), str):
                fail(batch_id)
            findings = batch.get("findings")
            if (not isinstance(findings, list) or not findings
                    or any(cls._is_blank(fid) for fid in findings)
                    or len(set(findings)) != len(findings)):
                fail(batch_id)
            known = set(findings)
            rounds = batch.get("rounds")
            regressions = batch.get("regressions")
            for number in (rounds, regressions):
                if not isinstance(number, int) or isinstance(number, bool):
                    fail(batch_id)
            if rounds < 1 or regressions < 0:
                fail(batch_id)
            conclusions = batch.get("conclusions")
            if not isinstance(conclusions, dict):
                fail(batch_id)
            for fid, entry in conclusions.items():
                if fid not in known or not isinstance(entry, dict):
                    fail(batch_id)
                if entry.get("conclusion") not in CONCLUSIONS:
                    fail(batch_id)
                if not isinstance(entry.get("round"), int):
                    fail(batch_id)
                for key in ("evidence", "note", "at"):
                    if not isinstance(entry.get(key), str):
                        fail(batch_id)
            history = batch.get("history")
            if not isinstance(history, list):
                fail(batch_id)
            for entry in history:
                if not isinstance(entry, dict):
                    fail(batch_id)
                if entry.get("finding_id") not in known:
                    fail(batch_id)
                if entry.get("conclusion") not in CONCLUSIONS:
                    fail(batch_id)
                if not isinstance(entry.get("round"), int):
                    fail(batch_id)
                for key in ("evidence", "note", "at"):
                    if not isinstance(entry.get(key), str):
                        fail(batch_id)
            closed_by = batch.get("closed_by")
            closed_at = batch.get("closed_at")
            if batch["state"] == STATE_CLOSED:
                if cls._is_blank(closed_by) or cls._is_blank(closed_at):
                    fail(batch_id)
            elif closed_by is not None or closed_at is not None:
                fail(batch_id)
        return batches

    def restore(self, state: dict) -> None:
        with self._lock:
            batches = self._validate_snapshot(state)
            restored = copy.deepcopy(batches)
            for batch_id, current in self._batches.items():
                if current["state"] != STATE_CLOSED:
                    continue
                incoming = restored.get(batch_id)
                if incoming is None or incoming["rounds"] < current["rounds"]:
                    restored[batch_id] = copy.deepcopy(current)
            self._batches = restored
