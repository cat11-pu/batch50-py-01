"""Identity proofing case ledger: attempt budgets, review leases and decisions."""

from __future__ import annotations

import copy
import threading
import time
from dataclasses import dataclass


class ProofingError(ValueError):
    """Refused proofing operation carrying a stable machine-readable code."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


KIND_DOCUMENT = "document"
KIND_LIVENESS = "liveness"
KINDS = (KIND_DOCUMENT, KIND_LIVENESS)
RESULTS = ("pass", "fail")
DECISIONS = ("approve", "reject")

STATE_COLLECTING = "collecting"
STATE_READY = "ready"
STATE_IN_REVIEW = "in_review"
STATE_DECIDED = "decided"
STATES = (STATE_COLLECTING, STATE_READY, STATE_IN_REVIEW, STATE_DECIDED)

STAT_KEYS = (
    "opened",
    "merged",
    "attempts",
    "refused",
    "assigned",
    "reclaimed",
    "decided",
)


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    applicant: str
    document_digest: str
    state: str
    opened_at: int
    ready_at: int | None
    decision: str | None
    decided_by: str | None
    decided_at: int | None
    reason: str | None = None
    duplicate: bool = False
    duplicate_of: str | None = None
    duplicate_case_ids: tuple[str, ...] = ()

    @property
    def is_duplicate(self) -> bool:
        return self.duplicate


@dataclass(frozen=True)
class AttemptRecord:
    attempt_id: str
    case_id: str
    kind: str
    material_digest: str
    result: str
    at: int
    window: int


@dataclass(frozen=True)
class LeaseRecord:
    case_id: str
    reviewer: str
    granted_at: int
    expires_at: int
    generation: int


class ProofingCaseLedger:
    """Track applicants from document and liveness attempts to a final verdict."""

    def __init__(self, *, attempt_limit: int = 3, cooldown_seconds: int = 600,
                 lease_seconds: int = 300, clock=None) -> None:
        self.attempt_limit = attempt_limit
        self.cooldown_seconds = cooldown_seconds
        self.lease_seconds = lease_seconds
        self._clock = clock
        self._lock = threading.RLock()
        self._cases: dict[str, dict] = {}
        self._attempts: dict[str, dict] = {}
        self._leases: dict[str, dict] = {}
        self._counters: dict[str, int] = {
            "case_seq": 0,
            "attempt_seq": 0,
            **{key: 0 for key in STAT_KEYS},
        }

    def _refuse(self, code: str, detail: object = None) -> None:
        self._counters["refused"] += 1
        raise ProofingError(code, detail)

    def _now(self, now: int | None) -> int:
        if now is not None:
            try:
                return int(now)
            except (TypeError, ValueError, OverflowError):
                self._refuse("PROOF_INVALID", {"field": "now"})

        if self._clock is None:
            return int(time.time())

        try:
            clock_value = self._clock() if callable(self._clock) else self._clock.now()
            if callable(clock_value):
                clock_value = clock_value()
            return int(clock_value)
        except ProofingError:
            raise
        except Exception as exc:  # noqa: BLE001 - injected clock failure is invalid
            raise ProofingError("PROOF_INVALID", {"field": "now", "error": str(exc)}) from exc

    def _required_text(self, value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            self._refuse("PROOF_INVALID", {"field": field})
        return value.strip()

    def _optional_text(self, value: object, field: str) -> str:
        if not isinstance(value, str):
            self._refuse("PROOF_INVALID", {"field": field})
        return value.strip()

    def _enum(self, value: object, allowed: tuple[str, ...], field: str) -> str:
        cleaned = self._required_text(value, field)
        if cleaned not in allowed:
            self._refuse("PROOF_INVALID", {"field": field, "allowed": allowed})
        return cleaned

    def _case(self, case_id: object) -> dict:
        identifier = case_id.strip() if isinstance(case_id, str) else ""
        case = self._cases.get(identifier) if identifier else None
        if case is None:
            self._refuse("PROOF_UNKNOWN", {"case_id": case_id})
        return case

    @staticmethod
    def _new_window() -> dict:
        return {
            "sequence": 0,
            "failures": 0,
            "last_failure_at": None,
            "blocked_until": None,
        }

    def _refresh_window(self, window: dict, now: int) -> None:
        blocked_until = window.get("blocked_until")
        if blocked_until is not None:
            if now >= blocked_until:
                window.update(self._new_window())
            return

        failures = window.get("failures", 0)
        last_failure_at = window.get("last_failure_at")
        if (
            failures
            and last_failure_at is not None
            and now - last_failure_at >= self.cooldown_seconds
        ):
            window.update(self._new_window())

    def _budget_remaining(self, window: dict) -> int:
        if window.get("blocked_until") is not None:
            return 0
        return max(0, int(self.attempt_limit) - int(window.get("failures", 0)))

    def _case_record(self, case: dict) -> CaseRecord:
        return CaseRecord(
            case_id=case["case_id"],
            applicant=case["applicant"],
            document_digest=case["document_digest"],
            state=case["state"],
            opened_at=case["opened_at"],
            ready_at=case["ready_at"],
            decision=case["decision"],
            decided_by=case["decided_by"],
            decided_at=case["decided_at"],
            reason=case.get("reason"),
            duplicate=bool(case.get("duplicate", False)),
            duplicate_of=case.get("duplicate_of"),
            duplicate_case_ids=tuple(case.get("duplicate_case_ids", ())),
        )

    def _attempt_record(self, attempt: dict) -> AttemptRecord:
        return AttemptRecord(
            attempt_id=attempt["attempt_id"],
            case_id=attempt["case_id"],
            kind=attempt["kind"],
            material_digest=attempt["material_digest"],
            result=attempt["result"],
            at=attempt["at"],
            window=attempt["window"],
        )

    def _lease_record(self, lease: dict) -> LeaseRecord:
        return LeaseRecord(
            case_id=lease["case_id"],
            reviewer=lease["reviewer"],
            granted_at=lease["granted_at"],
            expires_at=lease["expires_at"],
            generation=lease["generation"],
        )

    def _refresh_duplicate_flags(self, document_digest: str) -> None:
        related = [
            case
            for case in self._cases.values()
            if case.get("document_digest") == document_digest
        ]
        is_duplicate = len({case.get("applicant") for case in related}) > 1
        canonical_id = related[0]["case_id"] if related else None
        related_ids = [case["case_id"] for case in related]

        for case in related:
            case["duplicate"] = is_duplicate
            case["duplicate_of"] = (
                canonical_id
                if is_duplicate and case["case_id"] != canonical_id
                else None
            )
            case["duplicate_case_ids"] = list(related_ids) if is_duplicate else []

    def open(self, applicant: str, doc_digest: str, *,
             now: int | None = None) -> CaseRecord:
        with self._lock:
            opened_at = self._now(now)
            normalized_applicant = self._required_text(applicant, "applicant")
            normalized_digest = self._required_text(doc_digest, "doc_digest")

            for case in self._cases.values():
                if (
                    case["applicant"] == normalized_applicant
                    and case["state"] != STATE_DECIDED
                ):
                    self._counters["merged"] += 1
                    return self._case_record(case)

            self._counters["case_seq"] += 1
            case_id = f"case-{self._counters['case_seq']}"
            case = {
                "case_id": case_id,
                "applicant": normalized_applicant,
                "document_digest": normalized_digest,
                "state": STATE_COLLECTING,
                "opened_at": opened_at,
                "ready_at": None,
                "decision": None,
                "decided_by": None,
                "decided_at": None,
                "reason": None,
                "passed": {KIND_DOCUMENT: False, KIND_LIVENESS: False},
                "windows": {
                    KIND_DOCUMENT: self._new_window(),
                    KIND_LIVENESS: self._new_window(),
                },
                "duplicate": False,
                "duplicate_of": None,
                "duplicate_case_ids": [],
            }
            self._cases[case_id] = case
            self._refresh_duplicate_flags(normalized_digest)
            self._counters["opened"] += 1
            return self._case_record(case)

    def attempt(self, case_id: str, kind: str, material: str, result: str, *,
                now: int | None = None) -> AttemptRecord:
        with self._lock:
            attempted_at = self._now(now)
            case = self._case(case_id)
            normalized_kind = self._enum(kind, KINDS, "kind")
            normalized_result = self._enum(result, RESULTS, "result")
            material_digest = self._optional_text(material, "material")

            if case["state"] != STATE_COLLECTING:
                self._refuse("PROOF_STATE", {
                    "case_id": case["case_id"],
                    "state": case["state"],
                })

            window = case["windows"].setdefault(normalized_kind, self._new_window())
            self._refresh_window(window, attempted_at)

            if normalized_result == "fail" and self._budget_remaining(window) <= 0:
                self._refuse("PROOF_BUDGET", {
                    "case_id": case["case_id"],
                    "kind": normalized_kind,
                    "retry_at": window.get("blocked_until"),
                })

            window["sequence"] += 1
            window_number = window["sequence"]

            if normalized_result == "fail":
                window["failures"] += 1
                window["last_failure_at"] = attempted_at
                if window["failures"] >= self.attempt_limit:
                    window["blocked_until"] = attempted_at + self.cooldown_seconds
            else:
                case["passed"][normalized_kind] = True

            self._counters["attempt_seq"] += 1
            attempt_id = f"attempt-{self._counters['attempt_seq']}"
            attempt = {
                "attempt_id": attempt_id,
                "case_id": case["case_id"],
                "kind": normalized_kind,
                "material_digest": material_digest,
                "result": normalized_result,
                "at": attempted_at,
                "window": window_number,
            }
            self._attempts[attempt_id] = attempt
            self._counters["attempts"] += 1

            if all(case["passed"].values()):
                case["state"] = STATE_READY
                case["ready_at"] = attempted_at

            return self._attempt_record(attempt)

    def budget(self, case_id: str, kind: str, *, now: int | None = None) -> int:
        with self._lock:
            checked_at = self._now(now)
            case = self._case(case_id)
            normalized_kind = self._enum(kind, KINDS, "kind")
            window = case["windows"].setdefault(normalized_kind, self._new_window())
            self._refresh_window(window, checked_at)
            return self._budget_remaining(window)

    def assign(self, case_id: str, reviewer: str, *,
               now: int | None = None) -> LeaseRecord:
        with self._lock:
            granted_at = self._now(now)
            case = self._case(case_id)
            normalized_reviewer = self._required_text(reviewer, "reviewer")
            current_lease = self._leases.get(case["case_id"])

            if case["state"] == STATE_IN_REVIEW:
                if current_lease is not None and granted_at < current_lease["expires_at"]:
                    self._refuse("PROOF_LEASE", {
                        "case_id": case["case_id"],
                        "generation": current_lease["generation"],
                    })
                self._refuse("PROOF_STATE", {
                    "case_id": case["case_id"],
                    "state": case["state"],
                })

            if case["state"] != STATE_READY:
                self._refuse("PROOF_STATE", {
                    "case_id": case["case_id"],
                    "state": case["state"],
                })

            generation = (
                int(current_lease["generation"]) + 1
                if current_lease is not None
                else 1
            )
            lease = {
                "case_id": case["case_id"],
                "reviewer": normalized_reviewer,
                "granted_at": granted_at,
                "expires_at": granted_at + self.lease_seconds,
                "generation": generation,
            }
            self._leases[case["case_id"]] = lease
            case["state"] = STATE_IN_REVIEW
            self._counters["assigned"] += 1
            return self._lease_record(lease)

    def decide(self, case_id: str, reviewer: str, decision: str, reason: str, *,
               now: int | None = None) -> CaseRecord:
        with self._lock:
            decided_at = self._now(now)
            case = self._case(case_id)
            normalized_decision = self._enum(decision, DECISIONS, "decision")
            normalized_reason = self._required_text(reason, "reason")
            normalized_reviewer = self._required_text(reviewer, "reviewer")
            lease = self._leases.get(case["case_id"])

            if case["state"] == STATE_DECIDED:
                if lease is None or lease["reviewer"] != normalized_reviewer:
                    self._refuse("PROOF_LEASE", {
                        "case_id": case["case_id"],
                        "reason": "stale_or_non_holder",
                    })
                self._refuse("PROOF_FINAL", {"case_id": case["case_id"]})

            if case["state"] != STATE_IN_REVIEW or lease is None:
                self._refuse("PROOF_LEASE", {
                    "case_id": case["case_id"],
                    "reason": "no_active_lease",
                })

            if lease["reviewer"] != normalized_reviewer or decided_at >= lease["expires_at"]:
                self._refuse("PROOF_LEASE", {
                    "case_id": case["case_id"],
                    "generation": lease.get("generation"),
                })

            if normalized_decision == "approve":
                approved_duplicate = next((
                    other["case_id"]
                    for other in self._cases.values()
                    if other["case_id"] != case["case_id"]
                    and other["document_digest"] == case["document_digest"]
                    and other["applicant"] != case["applicant"]
                    and other["decision"] == "approve"
                ), None)
                if approved_duplicate is not None:
                    self._refuse("PROOF_DUPLICATE", {
                        "case_id": case["case_id"],
                        "duplicate_of": approved_duplicate,
                    })

            case["state"] = STATE_DECIDED
            case["decision"] = normalized_decision
            case["reason"] = normalized_reason
            case["decided_by"] = normalized_reviewer
            case["decided_at"] = decided_at
            case["decided_generation"] = lease["generation"]
            self._counters["decided"] += 1
            return self._case_record(case)

    def reclaim(self, case_id: str, *, now: int | None = None) -> LeaseRecord | None:
        with self._lock:
            reclaimed_at = self._now(now)
            case = self._case(case_id)
            lease = self._leases.get(case["case_id"])

            if case["state"] != STATE_IN_REVIEW or lease is None:
                return None
            if reclaimed_at < lease["expires_at"]:
                return None

            case["state"] = STATE_READY
            case["reclaimed_at"] = reclaimed_at
            self._counters["reclaimed"] += 1
            return self._lease_record(lease)

    def view(self, case_id: str) -> CaseRecord:
        with self._lock:
            return self._case_record(self._case(case_id))

    def queue(self, *, now: int | None = None) -> list[str]:
        with self._lock:
            self._now(now)
            ready_cases = [
                case for case in self._cases.values()
                if case["state"] == STATE_READY and case["ready_at"] is not None
            ]
            ready_cases.sort(key=lambda case: (case["ready_at"], case["case_id"]))
            return [case["case_id"] for case in ready_cases]

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy({
                "cases": self._cases,
                "attempts": self._attempts,
                "leases": self._leases,
                "counters": self._counters,
            })

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                parsed = self._parse_snapshot(copy.deepcopy(state))
            except ProofingError as exc:
                if exc.code == "PROOF_SNAPSHOT":
                    raise
                raise ProofingError("PROOF_SNAPSHOT", {"cause": exc.code}) from exc
            except Exception as exc:  # noqa: BLE001 - normalize corrupt snapshots
                raise ProofingError("PROOF_SNAPSHOT", {"error": str(exc)}) from exc

            cases, attempts, leases, counters = parsed
            self._cases = cases
            self._attempts = attempts
            self._leases = leases
            self._counters = counters

    def stats(self) -> dict:
        with self._lock:
            return {key: int(self._counters[key]) for key in STAT_KEYS}

    @staticmethod
    def _snapshot_invalid(detail: object = None) -> None:
        raise ProofingError("PROOF_SNAPSHOT", detail)

    @staticmethod
    def _snapshot_int(value: object, *, minimum: int | None = None) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            ProofingCaseLedger._snapshot_invalid({"type": "integer"})
        if minimum is not None and value < minimum:
            ProofingCaseLedger._snapshot_invalid({"minimum": minimum})
        return value

    @staticmethod
    def _trailing_number(identifier: object) -> int:
        if not isinstance(identifier, str):
            return 0
        try:
            return int(identifier.rsplit("-", 1)[1])
        except (IndexError, ValueError):
            return 0

    def _parse_snapshot(self, state: object) -> tuple[dict, dict, dict, dict]:
        if not isinstance(state, dict):
            self._snapshot_invalid({"field": "state"})

        raw_cases = state.get("cases")
        raw_attempts = state.get("attempts")
        raw_leases = state.get("leases")
        raw_counters = state.get("counters")
        if not isinstance(raw_cases, dict):
            self._snapshot_invalid({"field": "cases"})
        if not isinstance(raw_attempts, dict):
            self._snapshot_invalid({"field": "attempts"})
        if not isinstance(raw_leases, dict):
            self._snapshot_invalid({"field": "leases"})
        if not isinstance(raw_counters, dict):
            self._snapshot_invalid({"field": "counters"})

        stats_source = raw_counters.get("stats", raw_counters)
        if not isinstance(stats_source, dict):
            self._snapshot_invalid({"field": "counters.stats"})
        stats_values = {
            key: self._snapshot_int(stats_source.get(key, 0), minimum=0)
            for key in STAT_KEYS
        }

        cases: dict[str, dict] = {}
        for case_id, raw_case in raw_cases.items():
            if not isinstance(case_id, str) or not case_id:
                self._snapshot_invalid({"field": "cases.key"})
            if not isinstance(raw_case, dict):
                self._snapshot_invalid({"field": "cases.item", "id": case_id})
            if raw_case.get("case_id", case_id) != case_id:
                self._snapshot_invalid({"field": "case_id", "id": case_id})

            applicant = raw_case.get("applicant")
            document_digest = raw_case.get("document_digest")
            case_state = raw_case.get("state")
            if not isinstance(applicant, str) or not applicant.strip():
                self._snapshot_invalid({"field": "applicant", "id": case_id})
            if not isinstance(document_digest, str) or not document_digest.strip():
                self._snapshot_invalid({"field": "document_digest", "id": case_id})
            if case_state not in STATES:
                self._snapshot_invalid({"field": "state", "id": case_id})

            opened_at = self._snapshot_int(raw_case.get("opened_at"))
            ready_at = raw_case.get("ready_at")
            if ready_at is not None:
                ready_at = self._snapshot_int(ready_at)

            decision = raw_case.get("decision")
            if decision is not None and decision not in DECISIONS:
                self._snapshot_invalid({"field": "decision", "id": case_id})
            decided_by = raw_case.get("decided_by")
            if decided_by is not None and not isinstance(decided_by, str):
                self._snapshot_invalid({"field": "decided_by", "id": case_id})
            decided_at = raw_case.get("decided_at")
            if decided_at is not None:
                decided_at = self._snapshot_int(decided_at)
            reason = raw_case.get("reason")
            if reason is not None and not isinstance(reason, str):
                self._snapshot_invalid({"field": "reason", "id": case_id})

            raw_passed = raw_case.get("passed", {})
            if not isinstance(raw_passed, dict):
                self._snapshot_invalid({"field": "passed", "id": case_id})
            passed = {}
            for kind in KINDS:
                value = raw_passed.get(kind, False)
                if not isinstance(value, bool):
                    self._snapshot_invalid({"field": f"passed.{kind}"})
                passed[kind] = value

            raw_windows = raw_case.get("windows", {})
            if not isinstance(raw_windows, dict):
                self._snapshot_invalid({"field": "windows", "id": case_id})
            windows = {}
            for kind in KINDS:
                raw_window = raw_windows.get(kind)
                if not isinstance(raw_window, dict):
                    self._snapshot_invalid({"field": f"windows.{kind}"})
                sequence = self._snapshot_int(raw_window.get("sequence", 0), minimum=0)
                failures = self._snapshot_int(raw_window.get("failures", 0), minimum=0)
                last_failure_at = raw_window.get("last_failure_at")
                if last_failure_at is not None:
                    last_failure_at = self._snapshot_int(last_failure_at)
                blocked_until = raw_window.get("blocked_until")
                if blocked_until is not None:
                    blocked_until = self._snapshot_int(blocked_until)
                windows[kind] = {
                    "sequence": sequence,
                    "failures": failures,
                    "last_failure_at": last_failure_at,
                    "blocked_until": blocked_until,
                }

            duplicate = raw_case.get("duplicate", False)
            if not isinstance(duplicate, bool):
                self._snapshot_invalid({"field": "duplicate", "id": case_id})
            duplicate_of = raw_case.get("duplicate_of")
            if duplicate_of is not None and not isinstance(duplicate_of, str):
                self._snapshot_invalid({"field": "duplicate_of", "id": case_id})
            raw_duplicate_ids = raw_case.get("duplicate_case_ids", [])
            if not isinstance(raw_duplicate_ids, (list, tuple)) or not all(
                isinstance(item, str) for item in raw_duplicate_ids
            ):
                self._snapshot_invalid({"field": "duplicate_case_ids", "id": case_id})

            cases[case_id] = {
                "case_id": case_id,
                "applicant": applicant.strip(),
                "document_digest": document_digest.strip(),
                "state": case_state,
                "opened_at": opened_at,
                "ready_at": ready_at,
                "decision": decision,
                "decided_by": decided_by,
                "decided_at": decided_at,
                "reason": reason.strip() if isinstance(reason, str) else None,
                "passed": passed,
                "windows": windows,
                "duplicate": duplicate,
                "duplicate_of": duplicate_of,
                "duplicate_case_ids": list(raw_duplicate_ids),
            }

        attempts: dict[str, dict] = {}
        for attempt_id, raw_attempt in raw_attempts.items():
            if not isinstance(attempt_id, str) or not attempt_id:
                self._snapshot_invalid({"field": "attempts.key"})
            if not isinstance(raw_attempt, dict):
                self._snapshot_invalid({"field": "attempts.item", "id": attempt_id})
            if raw_attempt.get("attempt_id", attempt_id) != attempt_id:
                self._snapshot_invalid({"field": "attempt_id"})
            case_id = raw_attempt.get("case_id")
            kind = raw_attempt.get("kind")
            result = raw_attempt.get("result")
            material_digest = raw_attempt.get("material_digest", "")
            if not isinstance(case_id, str) or case_id not in cases:
                self._snapshot_invalid({"field": "attempt.case_id"})
            if kind not in KINDS or result not in RESULTS:
                self._snapshot_invalid({"field": "attempt.enum"})
            if not isinstance(material_digest, str):
                self._snapshot_invalid({"field": "attempt.material"})
            at = self._snapshot_int(raw_attempt.get("at"))
            window = self._snapshot_int(raw_attempt.get("window"), minimum=1)
            attempts[attempt_id] = {
                "attempt_id": attempt_id,
                "case_id": case_id,
                "kind": kind,
                "material_digest": material_digest.strip(),
                "result": result,
                "at": at,
                "window": window,
            }

        leases: dict[str, dict] = {}
        for case_id, raw_lease in raw_leases.items():
            if not isinstance(case_id, str) or case_id not in cases:
                self._snapshot_invalid({"field": "leases.key"})
            if not isinstance(raw_lease, dict):
                self._snapshot_invalid({"field": "leases.item"})
            if raw_lease.get("case_id", case_id) != case_id:
                self._snapshot_invalid({"field": "lease.case_id"})
            reviewer = raw_lease.get("reviewer")
            if not isinstance(reviewer, str) or not reviewer.strip():
                self._snapshot_invalid({"field": "lease.reviewer"})
            granted_at = self._snapshot_int(raw_lease.get("granted_at"))
            expires_at = self._snapshot_int(raw_lease.get("expires_at"))
            generation = self._snapshot_int(raw_lease.get("generation", 1), minimum=1)
            leases[case_id] = {
                "case_id": case_id,
                "reviewer": reviewer.strip(),
                "granted_at": granted_at,
                "expires_at": expires_at,
                "generation": generation,
            }

        if "case_seq" in raw_counters:
            case_seq = self._snapshot_int(raw_counters["case_seq"], minimum=0)
        else:
            case_seq = 0
        case_seq = max(
            case_seq,
            max((self._trailing_number(cid) for cid in cases), default=0),
        )

        if "attempt_seq" in raw_counters:
            attempt_seq = self._snapshot_int(raw_counters["attempt_seq"], minimum=0)
        else:
            attempt_seq = 0
        attempt_seq = max(
            attempt_seq,
            max((self._trailing_number(aid) for aid in attempts), default=0),
        )

        counters = copy.deepcopy(raw_counters)
        if isinstance(counters.get("stats"), dict):
            counters["stats"] = stats_values
        counters.update(stats_values)
        counters["case_seq"] = case_seq
        counters["attempt_seq"] = attempt_seq

        return cases, attempts, leases, counters
