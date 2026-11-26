"""Disclosure embargo clock: acknowledgement, fix deadline, extensions, lift gate."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass
from datetime import date, datetime, timedelta


class EmbargoError(ValueError):
    """Raised when an embargo operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATE_REPORTED = "reported"
STATE_ACKNOWLEDGED = "acknowledged"
STATE_LIFTED = "embargo_lifted"
SNAPSHOT_VERSION = 1

_VALID_STATES = {STATE_REPORTED, STATE_ACKNOWLEDGED, STATE_LIFTED}
_STAT_KEYS = ("opened", "acknowledged", "extended", "lifted", "extension_days")


def _is_nonempty_string(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _as_date(value: object) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    if not isinstance(value, str) or not value.strip():
        raise ValueError("invalid date")
    text = value.strip()
    try:
        return date.fromisoformat(text)
    except ValueError:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).date()


@dataclass(frozen=True)
class AdvisoryState:
    advisory_id: str
    product: str
    state: str
    reported_at: str
    acknowledged_at: str | None
    fix_due: str | None
    lifted_at: str | None
    extensions_used: int
    extension_days: int
    public_approved: bool
    public_actor: str | None


class DisclosureEmbargoClock:
    """Track coordinated disclosure deadlines, extension budgets and lift gates."""

    def __init__(self, *, max_extensions: int = 2,
                 max_total_days: int = 90) -> None:
        self.max_extensions = max_extensions
        self.max_total_days = max_total_days
        self._lock = threading.RLock()
        self._advisories: dict[str, dict] = {}
        self._holidays: set[str] = set()
        self._stats = {
            "opened": 0,
            "acknowledged": 0,
            "extended": 0,
            "lifted": 0,
            "extension_days": 0,
        }

    def set_holidays(self, days) -> int:
        if isinstance(days, str):
            days = [days]
        if days is None:
            raise EmbargoError("EMBARGO_BAD_REQUEST", "holidays must be iterable")

        try:
            normalized = set()
            for day in days:
                parsed = _as_date(day)
                normalized.add(parsed.isoformat())
        except (TypeError, ValueError) as exc:
            raise EmbargoError("EMBARGO_BAD_REQUEST", "invalid holiday date") from exc

        with self._lock:
            self._holidays.update(normalized)
            return len(self._holidays)

    def is_business_day(self, day: str) -> bool:
        try:
            parsed = _as_date(day)
        except (TypeError, ValueError) as exc:
            raise EmbargoError("EMBARGO_BAD_REQUEST", "invalid day") from exc
        with self._lock:
            return self._is_business_date(parsed)

    def open(self, advisory_id: str, *, product: str, fix_window_days: int,
             reported_at: str) -> AdvisoryState:
        if not _is_nonempty_string(advisory_id) or not _is_nonempty_string(product):
            raise EmbargoError("EMBARGO_BAD_REQUEST", "advisory_id and product are required")
        if (not isinstance(fix_window_days, int)
                or isinstance(fix_window_days, bool)
                or not 1 <= fix_window_days <= 180):
            raise EmbargoError("EMBARGO_BAD_WINDOW", "fix_window_days must be 1..180")

        with self._lock:
            if advisory_id in self._advisories:
                raise EmbargoError("EMBARGO_DUPLICATE", advisory_id)
            entry = {
                "advisory_id": advisory_id,
                "product": product,
                "state": STATE_REPORTED,
                "reported_at": reported_at,
                "acknowledged_at": None,
                "fix_due": None,
                "lifted_at": None,
                "extensions_used": 0,
                "extension_days": 0,
                "public_approved": False,
                "public_actor": None,
                "_fix_window_days": fix_window_days,
                "history": [],
            }
            self._advisories[advisory_id] = entry
            self._stats["opened"] += 1
            return self._state_from_entry(entry)

    def ack(self, advisory_id: str, *, now: str) -> AdvisoryState:
        try:
            acknowledged_on = _as_date(now)
        except (TypeError, ValueError) as exc:
            raise EmbargoError("EMBARGO_BAD_REQUEST", "invalid acknowledgement time") from exc

        with self._lock:
            entry = self._entry(advisory_id)
            if entry["state"] != STATE_REPORTED:
                raise EmbargoError("EMBARGO_BAD_STATE", entry["state"])

            due = self._advance_business_days(
                acknowledged_on, entry["_fix_window_days"])
            entry["state"] = STATE_ACKNOWLEDGED
            entry["acknowledged_at"] = now
            entry["fix_due"] = due.isoformat()
            self._append_history(
                entry, "ack", now, {"fix_due": due.isoformat()})
            self._stats["acknowledged"] += 1
            return self._state_from_entry(entry)

    def extend(self, advisory_id: str, *, days: int, now: str) -> dict:
        if (not isinstance(days, int) or isinstance(days, bool) or days <= 0):
            raise EmbargoError("EMBARGO_BAD_REQUEST", "days must be a positive integer")
        try:
            _as_date(now)
        except (TypeError, ValueError) as exc:
            raise EmbargoError("EMBARGO_BAD_REQUEST", "invalid extension time") from exc

        with self._lock:
            entry = self._entry(advisory_id)
            if entry["state"] == STATE_LIFTED:
                raise EmbargoError("EMBARGO_ALREADY_LIFTED", advisory_id)
            if entry["state"] != STATE_ACKNOWLEDGED:
                raise EmbargoError("EMBARGO_BAD_STATE", entry["state"])

            if entry["extensions_used"] >= self.max_extensions:
                raise EmbargoError("EMBARGO_EXTENSION_LIMIT", "extension count exhausted")

            remaining = self.max_total_days - entry["extension_days"]
            if remaining <= 0:
                raise EmbargoError("EMBARGO_EXTENSION_LIMIT", "extension days exhausted")

            granted = min(days, remaining)
            truncated = granted != days
            current_due = date.fromisoformat(entry["fix_due"])
            acknowledged_on = _as_date(entry["acknowledged_at"])
            already_skipped = 0
            if entry["extensions_used"] == 0:
                initial_due = self._advance_business_days(
                    acknowledged_on, entry["_fix_window_days"])
                for holiday in self._holidays:
                    holiday_date = date.fromisoformat(holiday)
                    if (acknowledged_on < holiday_date <= initial_due
                            and holiday_date.weekday() < 5):
                        already_skipped += 1
            effective_days = max(1, granted - already_skipped)
            due = self._advance_business_days(current_due, effective_days)

            entry["extensions_used"] += 1
            entry["extension_days"] += granted
            entry["fix_due"] = due.isoformat()
            detail = {
                "requested_days": days,
                "granted_days": granted,
                "extension_days": entry["extension_days"],
                "extensions_used": entry["extensions_used"],
                "fix_due": entry["fix_due"],
                "truncated": truncated,
            }
            self._append_history(entry, "extend", now, detail)
            self._stats["extended"] += 1
            self._stats["extension_days"] += granted
            return {"advisory_id": advisory_id, **detail}

    def request_public(self, advisory_id: str, *, actor: str, now: str) -> dict:
        if not _is_nonempty_string(actor):
            raise EmbargoError("EMBARGO_BAD_REQUEST", "actor is required")
        try:
            _as_date(now)
        except (TypeError, ValueError) as exc:
            raise EmbargoError("EMBARGO_BAD_REQUEST", "invalid request time") from exc

        with self._lock:
            entry = self._entry(advisory_id)
            if entry["state"] == STATE_LIFTED:
                raise EmbargoError("EMBARGO_ALREADY_LIFTED", advisory_id)
            if entry["state"] != STATE_ACKNOWLEDGED:
                raise EmbargoError("EMBARGO_BAD_STATE", entry["state"])

            entry["public_approved"] = True
            entry["public_actor"] = actor
            detail = {"actor": actor}
            self._append_history(entry, "request_public", now, detail)
            return {
                "advisory_id": advisory_id,
                "public_approved": True,
                "actor": actor,
                "at": now,
            }

    def lift(self, advisory_id: str, *, now: str) -> AdvisoryState:
        try:
            today = _as_date(now)
        except (TypeError, ValueError) as exc:
            raise EmbargoError("EMBARGO_BAD_REQUEST", "invalid lift time") from exc

        with self._lock:
            entry = self._entry(advisory_id)
            if entry["state"] == STATE_LIFTED:
                raise EmbargoError("EMBARGO_ALREADY_LIFTED", advisory_id)

            due = entry["fix_due"]
            eligible = entry["public_approved"] or (
                due is not None and today >= date.fromisoformat(due))
            if not eligible:
                raise EmbargoError("EMBARGO_NOT_ELIGIBLE", advisory_id)

            entry["state"] = STATE_LIFTED
            entry["lifted_at"] = now
            self._append_history(
                entry, "lift", now,
                {"fix_due": entry["fix_due"],
                 "public_approved": entry["public_approved"]})
            self._stats["lifted"] += 1
            return self._state_from_entry(entry)

    def state_of(self, advisory_id: str) -> AdvisoryState:
        with self._lock:
            return self._state_from_entry(self._entry(advisory_id))

    def history(self, advisory_id: str) -> tuple:
        with self._lock:
            entry = self._entry(advisory_id)
            return tuple(copy.deepcopy(entry["history"]))

    def days_remaining(self, advisory_id: str, *, now: str) -> int:
        try:
            today = _as_date(now)
        except (TypeError, ValueError) as exc:
            raise EmbargoError("EMBARGO_BAD_REQUEST", "invalid time") from exc

        with self._lock:
            entry = self._entry(advisory_id)
            if entry["fix_due"] is None:
                raise EmbargoError("EMBARGO_BAD_STATE", entry["state"])
            return (date.fromisoformat(entry["fix_due"]) - today).days

    def snapshot(self) -> dict:
        with self._lock:
            advisories = {
                advisory_id: self._entry_snapshot(entry)
                for advisory_id, entry in self._advisories.items()
            }
            return {
                "version": SNAPSHOT_VERSION,
                "advisories": advisories,
                "holidays": sorted(self._holidays),
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            advisories, holidays, stats = self._validate_snapshot(state)

            for advisory_id, live in self._advisories.items():
                if live["state"] != STATE_LIFTED:
                    continue
                candidate = advisories.get(advisory_id)
                if candidate is None or candidate["state"] != STATE_LIFTED:
                    advisories[advisory_id] = copy.deepcopy(live)

            self._advisories = advisories
            self._holidays = holidays
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _entry(self, advisory_id: str) -> dict:
        try:
            return self._advisories[advisory_id]
        except KeyError as exc:
            raise EmbargoError("EMBARGO_UNKNOWN", advisory_id) from exc

    def _is_business_date(self, day: date) -> bool:
        return day.weekday() < 5 and day.isoformat() not in self._holidays

    def _advance_business_days(self, start: date, days: int) -> date:
        current = start
        remaining = days
        while remaining:
            current += timedelta(days=1)
            if self._is_business_date(current):
                remaining -= 1
        return current

    @staticmethod
    def _append_history(entry: dict, action: str, at: object,
                        detail: object) -> None:
        entry["history"].append(
            {"action": action, "at": at, "detail": copy.deepcopy(detail)})

    @staticmethod
    def _state_from_entry(entry: dict) -> AdvisoryState:
        return AdvisoryState(
            advisory_id=entry["advisory_id"],
            product=entry["product"],
            state=entry["state"],
            reported_at=entry["reported_at"],
            acknowledged_at=entry["acknowledged_at"],
            fix_due=entry["fix_due"],
            lifted_at=entry["lifted_at"],
            extensions_used=entry["extensions_used"],
            extension_days=entry["extension_days"],
            public_approved=entry["public_approved"],
            public_actor=entry["public_actor"],
        )

    @staticmethod
    def _entry_snapshot(entry: dict) -> dict:
        return {
            "advisory_id": entry["advisory_id"],
            "product": entry["product"],
            "state": entry["state"],
            "reported_at": entry["reported_at"],
            "acknowledged_at": entry["acknowledged_at"],
            "fix_due": entry["fix_due"],
            "lifted_at": entry["lifted_at"],
            "extensions_used": entry["extensions_used"],
            "extension_days": entry["extension_days"],
            "public_approved": entry["public_approved"],
            "public_actor": entry["public_actor"],
            "fix_window_days": entry["_fix_window_days"],
            "history": copy.deepcopy(entry["history"]),
        }

    @staticmethod
    def _snapshot_invalid(detail: object) -> None:
        raise EmbargoError("EMBARGO_SNAPSHOT_INVALID", detail)

    def _validate_snapshot(self, state: object) -> tuple[dict, set[str], dict]:
        if not isinstance(state, dict):
            self._snapshot_invalid("snapshot must be an object")
        if type(state.get("version")) is not int or state.get("version") != SNAPSHOT_VERSION:
            self._snapshot_invalid("unsupported snapshot version")

        raw_advisories = state.get("advisories")
        raw_holidays = state.get("holidays")
        raw_stats = state.get("stats")
        if not isinstance(raw_stats, dict):
            self._snapshot_invalid("stats must be an object")
        if not all(key in raw_stats for key in _STAT_KEYS):
            self._snapshot_invalid("stats is incomplete")

        stats = {}
        for key in _STAT_KEYS:
            value = raw_stats[key]
            if type(value) is not int or value < 0:
                self._snapshot_invalid(f"invalid stat {key}")
            stats[key] = value

        if isinstance(raw_holidays, (list, tuple, set, frozenset)):
            holidays = set()
            for day in raw_holidays:
                try:
                    holidays.add(date.fromisoformat(day).isoformat())
                except (TypeError, ValueError):
                    self._snapshot_invalid("invalid holiday")
        else:
            self._snapshot_invalid("holidays must be a collection")

        advisories: dict[str, dict] = {}
        if isinstance(raw_advisories, dict):
            items = raw_advisories.items()
        elif isinstance(raw_advisories, (list, tuple)):
            items = ((None, item) for item in raw_advisories)
        else:
            self._snapshot_invalid("advisories must be a collection")

        for expected_id, raw_entry in items:
            entry = self._validate_snapshot_entry(raw_entry, expected_id)
            advisory_id = entry["advisory_id"]
            if advisory_id in advisories:
                self._snapshot_invalid("duplicate advisory")
            advisories[advisory_id] = entry

        return advisories, holidays, stats

    def _validate_snapshot_entry(self, raw: object,
                                 expected_id: object = None) -> dict:
        if not isinstance(raw, dict):
            self._snapshot_invalid("advisory entry must be an object")

        advisory_id = raw.get("advisory_id")
        if not _is_nonempty_string(advisory_id):
            self._snapshot_invalid("invalid advisory_id")
        if expected_id is not None and advisory_id != expected_id:
            self._snapshot_invalid("advisory_id does not match key")
        if not _is_nonempty_string(raw.get("product")):
            self._snapshot_invalid("invalid product")
        if raw.get("state") not in _VALID_STATES:
            self._snapshot_invalid("invalid advisory state")
        if not isinstance(raw.get("reported_at"), str):
            self._snapshot_invalid("invalid reported_at")

        acknowledged_at = raw.get("acknowledged_at")
        fix_due = raw.get("fix_due")
        lifted_at = raw.get("lifted_at")
        for value in (acknowledged_at, fix_due, lifted_at):
            if value is not None and not isinstance(value, str):
                self._snapshot_invalid("invalid timestamp")
        if fix_due is not None:
            try:
                date.fromisoformat(fix_due)
            except (TypeError, ValueError):
                self._snapshot_invalid("invalid fix_due")

        extensions_used = raw.get("extensions_used")
        extension_days = raw.get("extension_days")
        if type(extensions_used) is not int or extensions_used < 0:
            self._snapshot_invalid("invalid extensions_used")
        if type(extension_days) is not int or extension_days < 0:
            self._snapshot_invalid("invalid extension_days")
        if type(raw.get("public_approved")) is not bool:
            self._snapshot_invalid("invalid public_approved")
        public_actor = raw.get("public_actor")
        if public_actor is not None and not isinstance(public_actor, str):
            self._snapshot_invalid("invalid public_actor")
        if raw["public_approved"]:
            if not _is_nonempty_string(public_actor):
                self._snapshot_invalid("public approval requires an actor")
        elif public_actor is not None:
            self._snapshot_invalid("public actor without approval")
        fix_window_days = raw.get("fix_window_days")
        if (type(fix_window_days) is not int
                or not 1 <= fix_window_days <= 180):
            self._snapshot_invalid("invalid fix_window_days")

        raw_history = raw.get("history")
        if not isinstance(raw_history, (list, tuple)):
            self._snapshot_invalid("invalid history")
        history = []
        for row in raw_history:
            if not isinstance(row, dict):
                self._snapshot_invalid("invalid history row")
            if not _is_nonempty_string(row.get("action")):
                self._snapshot_invalid("invalid history action")
            if not isinstance(row.get("at"), str):
                self._snapshot_invalid("invalid history time")
            if "detail" not in row:
                self._snapshot_invalid("missing history detail")
            history.append({
                "action": row["action"],
                "at": row["at"],
                "detail": copy.deepcopy(row["detail"]),
            })

        if raw["state"] == STATE_REPORTED:
            if (acknowledged_at is not None or fix_due is not None
                    or lifted_at is not None or extensions_used != 0
                    or extension_days != 0 or raw["public_approved"]):
                self._snapshot_invalid("inconsistent reported entry")
        elif raw["state"] == STATE_ACKNOWLEDGED:
            if acknowledged_at is None or fix_due is None or lifted_at is not None:
                self._snapshot_invalid("inconsistent acknowledged entry")
        else:
            if acknowledged_at is None or fix_due is None or lifted_at is None:
                self._snapshot_invalid("inconsistent lifted entry")

        return {
            "advisory_id": advisory_id,
            "product": raw["product"],
            "state": raw["state"],
            "reported_at": raw["reported_at"],
            "acknowledged_at": acknowledged_at,
            "fix_due": fix_due,
            "lifted_at": lifted_at,
            "extensions_used": extensions_used,
            "extension_days": extension_days,
            "public_approved": raw["public_approved"],
            "public_actor": public_actor,
            "_fix_window_days": fix_window_days,
            "history": history,
        }
