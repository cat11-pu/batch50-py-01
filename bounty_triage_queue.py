"""Bounty triage queue: root-cause dedupe, review leases, award ledger."""

from __future__ import annotations

import copy
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


class BountyError(ValueError):
    """Raised when a triage operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


SEVERITIES = ("low", "medium", "high", "critical")
SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

STATE_QUEUED = "queued"
STATE_DUPLICATE = "duplicate"
STATE_TRIAGED = "triaged"
STATE_AWARDED = "awarded"
STATE_ACKNOWLEDGED = "acknowledged"
STATE_CLOSED = "closed"
STATES = (
    STATE_QUEUED,
    STATE_DUPLICATE,
    STATE_TRIAGED,
    STATE_AWARDED,
    STATE_ACKNOWLEDGED,
    STATE_CLOSED,
)

VERDICTS = ("valid", "invalid", "duplicate")
SNAPSHOT_VERSION = 1

REPORT_FIELDS = (
    "report_id",
    "target",
    "fingerprint",
    "reporter",
    "severity",
    "state",
    "duplicate_of",
    "verdict",
    "award_amount",
    "submitted_at",
    "closed_at",
)

STATS_FIELDS = (
    "submitted",
    "duplicates",
    "verdicts",
    "awards",
    "acknowledged",
    "adjusted",
)


@dataclass(frozen=True)
class BountyReport:
    report_id: str
    target: str
    fingerprint: str
    reporter: str
    severity: str
    state: str
    duplicate_of: str | None
    verdict: str | None
    award_amount: int
    submitted_at: str
    closed_at: str | None


@dataclass(frozen=True)
class ReviewLease:
    lease_id: str
    report_id: str
    reviewer: str
    expires_at: str


class BountyTriageQueue:
    """Queue bounty reports, lease reviews and settle awards against a budget."""

    def __init__(self, *, lease_seconds: int = 900,
                 project_budget: int = 10000) -> None:
        self.lease_seconds = lease_seconds
        self.project_budget = project_budget
        self._lock = threading.RLock()
        self._reports: dict[str, dict] = {}
        self._leases: dict[str, dict] = {}
        self._ledger: list = []
        self._adjustments: list = []
        self._budget = project_budget
        self._stats = {
            "submitted": 0,
            "duplicates": 0,
            "verdicts": 0,
            "awards": 0,
            "acknowledged": 0,
            "adjusted": 0,
        }

    def submit(self, report_id: str, *, target: str, fingerprint: str,
               reporter: str, severity: str, now: str) -> BountyReport:
        self._validate_submission_fields(
            report_id, target, fingerprint, reporter, severity
        )

        with self._lock:
            if report_id in self._reports:
                raise BountyError(
                    "BOUNTY_DUPLICATE_REPORT",
                    {"report_id": report_id},
                )

            duplicate_of = None
            for existing in self._reports.values():
                if (existing["target"] == target
                        and existing["fingerprint"] == fingerprint):
                    duplicate_of = existing["report_id"]
                    break

            state = STATE_DUPLICATE if duplicate_of is not None else STATE_QUEUED
            report = {
                "report_id": report_id,
                "target": target,
                "fingerprint": fingerprint,
                "reporter": reporter,
                "severity": severity,
                "state": state,
                "duplicate_of": duplicate_of,
                "verdict": None,
                "award_amount": 0,
                "submitted_at": now,
                "closed_at": None,
            }
            self._reports[report_id] = report
            self._stats["submitted"] += 1
            if state == STATE_DUPLICATE:
                self._stats["duplicates"] += 1
            return self._report_object(report)

    def dedupe_against(self, target: str, fingerprint: str) -> tuple:
        with self._lock:
            matches = (
                report_id
                for report_id, report in self._reports.items()
                if report["target"] == target
                and report["fingerprint"] == fingerprint
            )
            return tuple(sorted(matches))

    def claim_review(self, report_id: str, *, reviewer: str,
                     now: str) -> ReviewLease:
        with self._lock:
            report = self._require_report(report_id)
            if report["state"] != STATE_QUEUED:
                raise BountyError(
                    "BOUNTY_BAD_STATE",
                    {"report_id": report_id, "state": report["state"]},
                )

            current_lease = self._leases.get(report_id)
            if current_lease is not None and self._lease_active(
                    current_lease, now):
                raise BountyError(
                    "BOUNTY_LEASE_HELD",
                    {
                        "report_id": report_id,
                        "lease_id": current_lease["lease_id"],
                        "reviewer": current_lease["reviewer"],
                        "expires_at": current_lease["expires_at"],
                    },
                )

            expires_at = self._add_lease_seconds(now, self.lease_seconds)
            lease = {
                "lease_id": uuid.uuid4().hex,
                "report_id": report_id,
                "reviewer": reviewer,
                "expires_at": expires_at,
            }
            self._leases[report_id] = lease
            return self._lease_object(lease)

    def record_verdict(self, report_id: str, *, reviewer: str, lease_id: str,
                       verdict: str, severity: str, now: str) -> BountyReport:
        if verdict not in VERDICTS:
            raise BountyError("BOUNTY_BAD_VERDICT", {"verdict": verdict})
        self._validate_severity(severity)

        with self._lock:
            report = self._require_report(report_id)
            lease = self._leases.get(report_id)
            if (lease is None
                    or lease["lease_id"] != lease_id
                    or lease["reviewer"] != reviewer
                    or not self._lease_active(lease, now)):
                raise BountyError(
                    "BOUNTY_LEASE_INVALID",
                    {"report_id": report_id, "lease_id": lease_id},
                )

            report["verdict"] = verdict
            report["severity"] = severity
            report["state"] = STATE_TRIAGED
            self._leases.pop(report_id, None)
            self._stats["verdicts"] += 1
            return self._report_object(report)

    def award(self, report_id: str, *, amount: int, now: str) -> dict:
        if not self._is_positive_int(amount):
            raise BountyError("BOUNTY_BAD_AMOUNT", {"amount": amount})

        with self._lock:
            report = self._require_report(report_id)
            if (report["state"] != STATE_TRIAGED
                    or report["verdict"] != "valid"):
                raise BountyError(
                    "BOUNTY_NOT_AWARDABLE",
                    {
                        "report_id": report_id,
                        "state": report["state"],
                        "verdict": report["verdict"],
                    },
                )

            if amount <= self._budget:
                self._budget -= amount
                entry = {
                    "report_id": report_id,
                    "amount": amount,
                    "at": now,
                    "severity": report["severity"],
                }
                self._ledger.append(entry)
                report["award_amount"] = amount
                report["state"] = STATE_AWARDED
                self._stats["awards"] += 1
                return {
                    "report_id": report_id,
                    "state": STATE_AWARDED,
                    "awarded": True,
                    "amount": amount,
                    "remaining": self._budget,
                }

            report["award_amount"] = 0
            report["state"] = STATE_ACKNOWLEDGED
            self._stats["acknowledged"] += 1
            return {
                "report_id": report_id,
                "state": STATE_ACKNOWLEDGED,
                "awarded": False,
                "amount": 0,
                "remaining": self._budget,
            }

    def adjust_severity(self, report_id: str, *, new_severity: str,
                        actor: str, now: str) -> dict:
        with self._lock:
            report = self._require_report(report_id)
            if self._is_adjusted(report_id):
                raise BountyError(
                    "BOUNTY_REVIEW_LOCKED",
                    {"report_id": report_id},
                )
            self._validate_severity(new_severity)

            old_severity = report["severity"]
            if SEVERITY_RANK[new_severity] <= SEVERITY_RANK[old_severity]:
                raise BountyError(
                    "BOUNTY_SEVERITY_DOWNGRADE",
                    {"old": old_severity, "new": new_severity},
                )

            adjustment = {
                "report_id": report_id,
                "old": old_severity,
                "new": new_severity,
                "actor": actor,
                "at": now,
            }
            self._adjustments.append(adjustment)
            report["severity"] = new_severity
            self._stats["adjusted"] += 1
            return {
                "old": old_severity,
                "new": new_severity,
                "actor": actor,
                "at": now,
            }

    def close(self, report_id: str, *, reason: str, now: str) -> BountyReport:
        with self._lock:
            report = self._require_report(report_id)
            if report["state"] == STATE_CLOSED:
                raise BountyError(
                    "BOUNTY_BAD_STATE",
                    {"report_id": report_id, "state": STATE_CLOSED},
                )

            report["state"] = STATE_CLOSED
            report["closed_at"] = now
            self._leases.pop(report_id, None)
            return self._report_object(report)

    def queue(self, *, state: str | None = None) -> list:
        with self._lock:
            reports = sorted(
                self._reports.values(),
                key=lambda report: report["report_id"],
            )
            if state is not None:
                reports = [
                    report for report in reports
                    if report["state"] == state
                ]
            return [self._report_object(report) for report in reports]

    def ledger(self) -> list:
        with self._lock:
            return copy.deepcopy(self._ledger)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "reports": [
                    copy.deepcopy(report)
                    for report in self._reports.values()
                ],
                "leases": [
                    copy.deepcopy(lease)
                    for lease in self._leases.values()
                ],
                "ledger": copy.deepcopy(self._ledger),
                "adjustments": copy.deepcopy(self._adjustments),
                "budget": self._budget,
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        candidate = self._validated_snapshot(state)
        with self._lock:
            self._reports = candidate["reports"]
            self._leases = candidate["leases"]
            self._ledger = candidate["ledger"]
            self._adjustments = candidate["adjustments"]
            self._budget = candidate["budget"]
            self._stats = candidate["stats"]

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    @staticmethod
    def _validate_submission_fields(report_id: object, target: object,
                                    fingerprint: object, reporter: object,
                                    severity: object) -> None:
        fields = {
            "report_id": report_id,
            "target": target,
            "fingerprint": fingerprint,
            "reporter": reporter,
        }
        for field_name, value in fields.items():
            if not BountyTriageQueue._is_nonempty_string(value):
                raise BountyError(
                    "BOUNTY_BAD_REQUEST",
                    {"field": field_name},
                )
        BountyTriageQueue._validate_severity(severity)

    @staticmethod
    def _validate_severity(severity: object) -> None:
        if severity not in SEVERITIES:
            raise BountyError(
                "BOUNTY_BAD_SEVERITY",
                {"severity": severity},
            )

    @staticmethod
    def _is_nonempty_string(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    @staticmethod
    def _is_positive_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

    def _require_report(self, report_id: object) -> dict:
        report = self._reports.get(report_id)
        if report is None:
            raise BountyError(
                "BOUNTY_UNKNOWN_REPORT",
                {"report_id": report_id},
            )
        return report

    def _is_adjusted(self, report_id: str) -> bool:
        return any(
            adjustment["report_id"] == report_id
            for adjustment in self._adjustments
        )

    @staticmethod
    def _parse_time(value: object) -> datetime:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, (int, float)) and not isinstance(value, bool):
            parsed = datetime.fromtimestamp(value, tz=timezone.utc)
        elif isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value)
            except ValueError as exc:
                raise BountyError(
                    "BOUNTY_BAD_REQUEST",
                    {"field": "now", "value": value},
                ) from exc
        else:
            raise BountyError(
                "BOUNTY_BAD_REQUEST",
                {"field": "now", "value": value},
            )

        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    def _add_lease_seconds(self, now: object, seconds: int | float) -> str:
        return (
            self._parse_time(now) + timedelta(seconds=seconds)
        ).isoformat()

    def _lease_active(self, lease: dict, now: object) -> bool:
        try:
            expires_at = self._parse_time(lease["expires_at"])
            current_time = self._parse_time(now)
        except (KeyError, TypeError, ValueError):
            return False
        return current_time < expires_at

    @staticmethod
    def _report_object(report: dict) -> BountyReport:
        return BountyReport(
            **{field: report[field] for field in REPORT_FIELDS}
        )

    @staticmethod
    def _lease_object(lease: dict) -> ReviewLease:
        return ReviewLease(
            lease_id=lease["lease_id"],
            report_id=lease["report_id"],
            reviewer=lease["reviewer"],
            expires_at=lease["expires_at"],
        )

    @classmethod
    def _validated_snapshot(cls, state: object) -> dict:
        try:
            if not isinstance(state, dict):
                raise cls._snapshot_invalid("snapshot must be an object")

            expected_keys = {
                "version", "reports", "leases", "ledger",
                "adjustments", "budget", "stats",
            }
            if set(state) != expected_keys:
                raise cls._snapshot_invalid("unexpected snapshot keys")
            if state["version"] != SNAPSHOT_VERSION:
                raise cls._snapshot_invalid("unsupported snapshot version")

            reports = cls._validated_reports(state["reports"])
            leases = cls._validated_leases(state["leases"], reports)
            ledger = cls._validated_ledger(state["ledger"], reports)
            adjustments = cls._validated_adjustments(
                state["adjustments"], reports
            )
            budget = cls._validated_budget(state["budget"])
            stats = cls._validated_stats(state["stats"])

            return {
                "reports": reports,
                "leases": leases,
                "ledger": ledger,
                "adjustments": adjustments,
                "budget": budget,
                "stats": stats,
            }
        except BountyError:
            raise
        except Exception as exc:
            raise cls._snapshot_invalid(str(exc)) from exc

    @staticmethod
    def _snapshot_invalid(detail: object) -> BountyError:
        return BountyError("BOUNTY_SNAPSHOT_INVALID", detail)

    @classmethod
    def _validated_reports(cls, raw_reports: object) -> dict:
        if isinstance(raw_reports, dict):
            values = list(raw_reports.values())
        elif isinstance(raw_reports, list):
            values = raw_reports
        else:
            raise cls._snapshot_invalid("reports must be a list or object")

        reports = {}
        for raw_report in values:
            if not isinstance(raw_report, dict):
                raise cls._snapshot_invalid("report must be an object")
            if set(raw_report) != set(REPORT_FIELDS):
                raise cls._snapshot_invalid("invalid report fields")

            report_id = raw_report["report_id"]
            if not cls._is_nonempty_string(report_id):
                raise cls._snapshot_invalid("invalid report_id")
            if report_id in reports:
                raise cls._snapshot_invalid("duplicate report in snapshot")

            for field_name in ("target", "fingerprint", "reporter",
                               "submitted_at"):
                if not isinstance(raw_report[field_name], str):
                    raise cls._snapshot_invalid(
                        f"invalid {field_name} type"
                    )

            severity = raw_report["severity"]
            if severity not in SEVERITIES:
                raise cls._snapshot_invalid("invalid report severity")

            state = raw_report["state"]
            if state not in STATES:
                raise cls._snapshot_invalid("invalid report state")

            duplicate_of = raw_report["duplicate_of"]
            if duplicate_of is not None and not isinstance(
                    duplicate_of, str):
                raise cls._snapshot_invalid("invalid duplicate_of")

            verdict = raw_report["verdict"]
            if verdict is not None and verdict not in VERDICTS:
                raise cls._snapshot_invalid("invalid verdict")

            award_amount = raw_report["award_amount"]
            if not cls._is_nonnegative_int(award_amount):
                raise cls._snapshot_invalid("invalid award_amount")

            closed_at = raw_report["closed_at"]
            if closed_at is not None and not isinstance(closed_at, str):
                raise cls._snapshot_invalid("invalid closed_at")

            reports[report_id] = copy.deepcopy(raw_report)

        return reports

    @classmethod
    def _validated_leases(cls, raw_leases: object,
                          reports: dict) -> dict:
        if isinstance(raw_leases, dict):
            values = list(raw_leases.values())
        elif isinstance(raw_leases, list):
            values = raw_leases
        else:
            raise cls._snapshot_invalid("leases must be a list or object")

        leases = {}
        for raw_lease in values:
            if not isinstance(raw_lease, dict):
                raise cls._snapshot_invalid("lease must be an object")
            expected_fields = {
                "lease_id", "report_id", "reviewer", "expires_at"
            }
            if set(raw_lease) != expected_fields:
                raise cls._snapshot_invalid("invalid lease fields")

            lease_id = raw_lease["lease_id"]
            report_id = raw_lease["report_id"]
            if not isinstance(lease_id, str) or not lease_id:
                raise cls._snapshot_invalid("invalid lease_id")
            if report_id not in reports:
                raise cls._snapshot_invalid("lease references unknown report")
            if not isinstance(raw_lease["reviewer"], str):
                raise cls._snapshot_invalid("invalid lease reviewer")
            if not isinstance(raw_lease["expires_at"], str):
                raise cls._snapshot_invalid("invalid lease expiry")
            try:
                cls._parse_time(raw_lease["expires_at"])
            except BountyError as exc:
                raise cls._snapshot_invalid("invalid lease expiry") from exc

            if report_id in leases:
                raise cls._snapshot_invalid("multiple leases for report")
            leases[report_id] = copy.deepcopy(raw_lease)

        return leases

    @classmethod
    def _validated_ledger(cls, raw_ledger: object,
                          reports: dict) -> list:
        if not isinstance(raw_ledger, list):
            raise cls._snapshot_invalid("ledger must be a list")

        ledger = []
        for entry in raw_ledger:
            if not isinstance(entry, dict):
                raise cls._snapshot_invalid("ledger entry must be an object")
            if set(entry) != {"report_id", "amount", "at", "severity"}:
                raise cls._snapshot_invalid("invalid ledger entry fields")

            report_id = entry["report_id"]
            if report_id not in reports:
                raise cls._snapshot_invalid("ledger references unknown report")
            if not cls._is_positive_int(entry["amount"]):
                raise cls._snapshot_invalid("invalid ledger amount")
            if not isinstance(entry["at"], str):
                raise cls._snapshot_invalid("invalid ledger time")
            if entry["severity"] not in SEVERITIES:
                raise cls._snapshot_invalid("invalid ledger severity")

            ledger.append(copy.deepcopy(entry))

        return ledger

    @classmethod
    def _validated_adjustments(cls, raw_adjustments: object,
                               reports: dict) -> list:
        if not isinstance(raw_adjustments, list):
            raise cls._snapshot_invalid("adjustments must be a list")

        adjustments = []
        adjusted_reports = set()
        for adjustment in raw_adjustments:
            if not isinstance(adjustment, dict):
                raise cls._snapshot_invalid("adjustment must be an object")
            expected_fields = {"report_id", "old", "new", "actor", "at"}
            if set(adjustment) != expected_fields:
                raise cls._snapshot_invalid("invalid adjustment fields")

            report_id = adjustment["report_id"]
            if report_id not in reports:
                raise cls._snapshot_invalid(
                    "adjustment references unknown report"
                )
            if report_id in adjusted_reports:
                raise cls._snapshot_invalid("report adjusted more than once")

            old_severity = adjustment["old"]
            new_severity = adjustment["new"]
            if old_severity not in SEVERITIES:
                raise cls._snapshot_invalid("invalid old severity")
            if new_severity not in SEVERITIES:
                raise cls._snapshot_invalid("invalid new severity")
            if SEVERITY_RANK[new_severity] <= SEVERITY_RANK[old_severity]:
                raise cls._snapshot_invalid("adjustment is not an upgrade")
            if not isinstance(adjustment["actor"], str):
                raise cls._snapshot_invalid("invalid adjustment actor")
            if not isinstance(adjustment["at"], str):
                raise cls._snapshot_invalid("invalid adjustment time")

            adjusted_reports.add(report_id)
            adjustments.append(copy.deepcopy(adjustment))

        return adjustments

    @classmethod
    def _validated_budget(cls, budget: object) -> int:
        if not cls._is_nonnegative_int(budget):
            raise cls._snapshot_invalid("invalid budget")
        return budget

    @staticmethod
    def _validated_stats(raw_stats: object) -> dict:
        if not isinstance(raw_stats, dict):
            raise BountyError(
                "BOUNTY_SNAPSHOT_INVALID",
                "stats must be an object",
            )
        if set(raw_stats) != set(STATS_FIELDS):
            raise BountyError(
                "BOUNTY_SNAPSHOT_INVALID",
                "invalid stats fields",
            )
        if any(
            not BountyTriageQueue._is_nonnegative_int(raw_stats[field])
            for field in STATS_FIELDS
        ):
            raise BountyError(
                "BOUNTY_SNAPSHOT_INVALID",
                "invalid stats value",
            )
        return {field: raw_stats[field] for field in STATS_FIELDS}

    @staticmethod
    def _is_nonnegative_int(value: object) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
        )
