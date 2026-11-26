"""VEX statement ledger: status propagation, evidence expiry and product version ranges."""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import asdict, dataclass, fields, replace
from datetime import datetime, timedelta, timezone


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


_STATUSES = frozenset(
    {"not_affected", "affected", "fixed", "under_investigation"}
)
_JUSTIFICATIONS = frozenset(
    {
        "component_not_present",
        "vulnerable_code_not_in_execute_path",
        "vulnerable_code_cannot_be_controlled_by_adversary",
        "inline_mitigations_already_exist",
    }
)
_SEVERITY = {
    "unknown": 0,
    "not_affected": 1,
    "fixed": 2,
    "under_investigation": 3,
    "affected": 4,
}
_VERSION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+)*$")
_STATEMENT_ID_PATTERN = re.compile(r"^VX-([0-9]+)$")
_SNAPSHOT_VERSION = 1
_COUNTER_KEYS = ("statements", "superseded", "downgraded", "queries")
_STATEMENT_KEYS = tuple(field.name for field in fields(Statement))
_EXPORT_KEYS = (
    "statement_id",
    "product",
    "component",
    "vulnerability",
    "status",
    "justification",
    "evidence_ref",
    "introduced",
    "until",
    "fixed",
    "expires_at",
    "revision",
)


def _version_key(value: str) -> tuple[int, ...]:
    if not isinstance(value, str) or not _VERSION_PATTERN.fullmatch(value):
        raise VexError("VEX_INVALID_VERSION", value)
    parts = [int(part) for part in value.split(".")]
    while parts and parts[-1] == 0:
        parts.pop()
    return tuple(parts)


def _valid_range(introduced: str,
                 until: str | None) -> tuple[tuple[int, ...], tuple[int, ...] | None]:
    start = _version_key(introduced)
    end = _version_key(until) if until is not None else None
    if end is not None and not start < end:
        raise VexError(
            "VEX_INVALID_REQUEST",
            {"introduced": introduced, "until": until},
        )
    return start, end


def _range_contains(version: tuple[int, ...], start: tuple[int, ...],
                    end: tuple[int, ...] | None) -> bool:
    return start <= version and (end is None or version < end)


def _ranges_overlap(first_start: tuple[int, ...],
                    first_end: tuple[int, ...] | None,
                    second_start: tuple[int, ...],
                    second_end: tuple[int, ...] | None) -> bool:
    starts_before_second_end = second_end is None or first_start < second_end
    second_starts_before_first_end = first_end is None or second_start < first_end
    return starts_before_second_end and second_starts_before_first_end


def _require_string(value: object, name: str) -> None:
    if not isinstance(value, str) or not value:
        raise VexError("VEX_INVALID_REQUEST", {name: value})


def _validate_status(status: object) -> None:
    if not isinstance(status, str) or status not in _STATUSES:
        raise VexError("VEX_INVALID_STATUS", status)


def _validate_not_affected(justification: object, evidence_ref: object) -> None:
    if not justification:
        raise VexError("VEX_MISSING_JUSTIFICATION", justification)
    if not isinstance(justification, str) or justification not in _JUSTIFICATIONS:
        raise VexError("VEX_INVALID_JUSTIFICATION", justification)
    if not evidence_ref:
        raise VexError("VEX_MISSING_EVIDENCE", evidence_ref)
    if not isinstance(evidence_ref, str):
        raise VexError("VEX_INVALID_REQUEST", {"evidence_ref": evidence_ref})


def _time_value(value: object, name: str) -> tuple[datetime, str]:
    if isinstance(value, datetime):
        parsed = value
        text = value.isoformat()
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        candidate = text[:-1] + "+00:00" if text.endswith(("Z", "z")) else text
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise VexError("VEX_INVALID_REQUEST", {name: value}) from exc
    else:
        raise VexError("VEX_INVALID_REQUEST", {name: value})
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed, text


def _ttl_delta(value: object) -> timedelta:
    if isinstance(value, timedelta):
        return value
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise VexError("VEX_INVALID_REQUEST", {"default_evidence_ttl": value})
    return timedelta(seconds=float(value))


def _statement_dict(statement: Statement) -> dict:
    return asdict(statement)


def _snapshot_invalid(detail: object) -> VexError:
    return VexError("VEX_SNAPSHOT_INVALID", detail)


class VexStatementLedger:
    """Track exploitability statements and answer SBOM queries per product version."""

    def __init__(self, *, default_evidence_ttl=None, clock=None) -> None:
        self.default_evidence_ttl = default_evidence_ttl
        self._clock = clock
        self._lock = threading.RLock()
        self._statements: dict[str, Statement] = {}
        self._history: list[Statement] = []
        self._history_rank: dict[str, int] = {}
        self._dependencies: dict[tuple[str, str], list[str]] = {}
        self._counters = {key: 0 for key in _COUNTER_KEYS}
        self._next_id = 1

    def _now_value(self, now: object = None) -> tuple[datetime, str]:
        if now is None:
            if self._clock is None:
                value = datetime.now(timezone.utc)
            else:
                if not callable(self._clock):
                    raise VexError("VEX_INVALID_REQUEST", {"clock": self._clock})
                value = self._clock()
            return _time_value(value, "now")
        return _time_value(now, "now")

    def _new_statement_id(self) -> str:
        while True:
            statement_id = f"VX-{self._next_id:04d}"
            self._next_id += 1
            if statement_id not in self._history_rank:
                return statement_id

    def _check_range_conflict(self, product: str, component: str,
                              vulnerability: str, introduced: str,
                              until: str | None,
                              exclude_id: str | None = None) -> None:
        start, end = _valid_range(introduced, until)
        for record in self._statements.values():
            if record.statement_id == exclude_id:
                continue
            if (
                record.product != product
                or record.component != component
                or record.vulnerability != vulnerability
            ):
                continue
            other_start, other_end = _valid_range(record.introduced, record.until)
            if _ranges_overlap(start, end, other_start, other_end):
                raise VexError(
                    "VEX_RANGE_CONFLICT",
                    {
                        "statement_id": record.statement_id,
                        "introduced": introduced,
                        "until": until,
                    },
                )

    def assert_statement(self, *, product: str, component: str, vulnerability: str,
                         status: str, justification=None, evidence_ref=None,
                         introduced: str = "0.0.0", until=None, fixed=None,
                         expires_at=None, now=None) -> Statement:
        _validate_status(status)
        _require_string(product, "product")
        _require_string(component, "component")
        _require_string(vulnerability, "vulnerability")
        _valid_range(introduced, until)
        if status == "fixed" and not fixed:
            raise VexError("VEX_INVALID_REQUEST", {"fixed": fixed})
        if fixed is not None:
            _version_key(fixed)
        if status == "not_affected":
            _validate_not_affected(justification, evidence_ref)
        if expires_at is not None:
            _time_value(expires_at, "expires_at")

        with self._lock:
            now_dt, now_text = self._now_value(now)
            if expires_at is None and evidence_ref and self.default_evidence_ttl is not None:
                expires_at = (now_dt + _ttl_delta(self.default_evidence_ttl)).isoformat()
            self._check_range_conflict(
                product, component, vulnerability, introduced, until
            )
            statement_id = self._new_statement_id()
            record = Statement(
                statement_id=statement_id,
                product=product,
                component=component,
                vulnerability=vulnerability,
                status=status,
                justification=justification,
                evidence_ref=evidence_ref,
                introduced=introduced,
                until=until,
                fixed=fixed,
                expires_at=expires_at,
                created_at=now_text,
                revision=1,
            )
            self._statements[statement_id] = record
            self._history.append(record)
            self._history_rank[statement_id] = len(self._history) - 1
            self._counters["statements"] += 1
            if status == "fixed":
                self._invalidate_upstream_dependents(record)
            return record

    def query(self, *, product: str, component: str, version: str,
              vulnerability: str) -> VexQueryResult:
        _require_string(product, "product")
        _require_string(component, "component")
        _require_string(vulnerability, "vulnerability")
        version_key = _version_key(version)

        with self._lock:
            self._counters["queries"] += 1
            direct = self._matching_statement(
                product, component, vulnerability, version_key
            )
            if direct is not None:
                verdict, reason = self._verdict_for(direct, version_key)
                return VexQueryResult(
                    verdict=verdict,
                    statement_id=direct.statement_id,
                    chain=(component,),
                    reason=reason,
                )

            chain = [component]
            visited = {component}
            matches: list[tuple[int, int, Statement]] = []

            def walk(current_component: str) -> None:
                for dependency in self._dependencies.get(
                    (product, current_component), ()
                ):
                    if dependency in visited:
                        continue
                    visited.add(dependency)
                    chain.append(dependency)
                    match = self._matching_statement(
                        product, dependency, vulnerability, version_key
                    )
                    if match is None:
                        match = self._matching_statement(
                            None, dependency, vulnerability, version_key
                        )
                    if match is not None:
                        verdict, _ = self._verdict_for(match, version_key)
                        matches.append(
                            (
                                _SEVERITY[verdict],
                                self._history_rank.get(match.statement_id, 0),
                                match,
                            )
                        )
                    walk(dependency)

            walk(component)
            if not matches:
                return VexQueryResult(
                    verdict="unknown",
                    statement_id=None,
                    chain=tuple(chain),
                    reason="no_match",
                )
            _, _, chosen = min(
                matches, key=lambda item: (-item[0], item[1], item[2].statement_id)
            )
            verdict, reason = self._verdict_for(chosen, version_key)
            return VexQueryResult(
                verdict=verdict,
                statement_id=chosen.statement_id,
                chain=tuple(chain),
                reason=reason,
            )

    def supersede(self, statement_id: str, *, status: str, justification=None,
                  evidence_ref=None, fixed=None, until=None, now=None) -> Statement:
        _validate_status(status)
        with self._lock:
            old = self._statements.get(statement_id)
            if old is None:
                raise VexError("VEX_STATEMENT_UNKNOWN", statement_id)

            new_justification = (
                old.justification if justification is None else justification
            )
            new_evidence_ref = (
                old.evidence_ref if evidence_ref is None else evidence_ref
            )
            new_fixed = old.fixed if fixed is None else fixed
            new_until = old.until if until is None else until

            _valid_range(old.introduced, new_until)
            if status == "fixed" and not new_fixed:
                raise VexError("VEX_INVALID_REQUEST", {"fixed": new_fixed})
            if new_fixed is not None:
                _version_key(new_fixed)
            if status == "not_affected":
                _validate_not_affected(new_justification, new_evidence_ref)

            self._check_range_conflict(
                old.product,
                old.component,
                old.vulnerability,
                old.introduced,
                new_until,
                exclude_id=statement_id,
            )
            _, now_text = self._now_value(now)
            new_id = self._new_statement_id()
            record = Statement(
                statement_id=new_id,
                product=old.product,
                component=old.component,
                vulnerability=old.vulnerability,
                status=status,
                justification=new_justification,
                evidence_ref=new_evidence_ref,
                introduced=old.introduced,
                until=new_until,
                fixed=new_fixed,
                expires_at=old.expires_at,
                created_at=now_text,
                revision=old.revision + 1,
            )
            del self._statements[statement_id]
            self._statements[new_id] = record
            self._history.append(record)
            self._history_rank[new_id] = len(self._history) - 1
            self._counters["statements"] += 1
            self._counters["superseded"] += 1
            if status == "fixed":
                self._invalidate_upstream_dependents(record)
            return record

    def expire(self, now=None) -> int:
        with self._lock:
            now_dt, _ = self._now_value(now)
            downgraded = 0
            for statement_id, record in list(self._statements.items()):
                if record.status == "under_investigation" or record.expires_at is None:
                    continue
                expires_dt, _ = _time_value(record.expires_at, "expires_at")
                if expires_dt <= now_dt:
                    self._statements[statement_id] = replace(
                        record, status="under_investigation"
                    )
                    downgraded += 1
            self._counters["downgraded"] += downgraded
            return downgraded

    def register_dependency(self, product: str, component: str,
                            depends_on: str) -> None:
        _require_string(product, "product")
        _require_string(component, "component")
        _require_string(depends_on, "depends_on")
        with self._lock:
            dependencies = self._dependencies.setdefault((product, component), [])
            if depends_on in dependencies:
                return
            dependencies.append(depends_on)
            for record in list(self._statements.values()):
                if record.component == depends_on and record.status == "fixed":
                    self._invalidate_upstream_dependents(record)
                    break

    def export(self) -> tuple:
        with self._lock:
            rows = [
                {key: getattr(record, key) for key in _EXPORT_KEYS}
                for record in self._statements.values()
            ]
            ranks = dict(self._history_rank)
        rows.sort(
            key=lambda row: (
                row["product"],
                row["component"],
                row["vulnerability"],
                _version_key(row["introduced"]),
                ranks.get(row["statement_id"], 0),
                row["statement_id"],
            )
        )
        return tuple(rows)

    def history(self) -> tuple:
        with self._lock:
            return tuple(self._history)

    def stats(self) -> dict:
        with self._lock:
            return {
                "statements": self._counters["statements"],
                "active": len(self._statements),
                "superseded": self._counters["superseded"],
                "downgraded": self._counters["downgraded"],
                "queries": self._counters["queries"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            statements = []
            for record in self._history:
                active = self._statements.get(record.statement_id)
                current = active if active is not None else record
                row = _statement_dict(current)
                row["_active"] = active is not None
                if active is not None and current != record:
                    row["_history_record"] = _statement_dict(record)
                statements.append(row)
            dependencies = {
                key: list(value) for key, value in self._dependencies.items()
            }
            counters = self.stats()
            return copy.deepcopy(
                {
                    "version": _SNAPSHOT_VERSION,
                    "statements": statements,
                    "dependencies": dependencies,
                    "counters": counters,
                }
            )

    def restore(self, state: dict) -> None:
        try:
            history, active, dependencies, counters, next_id = self._restore_parts(
                state
            )
        except VexError as exc:
            if exc.code == "VEX_SNAPSHOT_INVALID":
                raise
            raise _snapshot_invalid(exc.detail) from exc
        except (TypeError, ValueError, KeyError) as exc:
            raise _snapshot_invalid(str(exc)) from exc

        with self._lock:
            self._history = history
            self._history_rank = {
                record.statement_id: index
                for index, record in enumerate(history)
            }
            self._statements = active
            self._dependencies = dependencies
            self._counters = counters
            self._next_id = next_id

    def _restore_parts(self, state: object):
        if not isinstance(state, dict):
            raise _snapshot_invalid("state")
        required = {"version", "statements", "dependencies", "counters"}
        if not required.issubset(state):
            raise _snapshot_invalid("missing keys")
        if type(state["version"]) is not int or state["version"] != _SNAPSHOT_VERSION:
            raise _snapshot_invalid("version")
        if not isinstance(state["statements"], list):
            raise _snapshot_invalid("statements")
        if not isinstance(state["dependencies"], dict):
            raise _snapshot_invalid("dependencies")
        if not isinstance(state["counters"], dict):
            raise _snapshot_invalid("counters")

        history: list[Statement] = []
        active: dict[str, Statement] = {}
        seen_ids: set[str] = set()

        for raw in state["statements"]:
            record, active_record = self._snapshot_statement(raw)
            if record.statement_id in seen_ids:
                raise _snapshot_invalid("duplicate statement")
            seen_ids.add(record.statement_id)
            history.append(record)
            if active_record is not None:
                active[record.statement_id] = active_record

        self._check_snapshot_overlaps(active)

        dependencies: dict[tuple[str, str], list[str]] = {}
        for raw_key, raw_value in state["dependencies"].items():
            if (
                not isinstance(raw_key, (tuple, list))
                or len(raw_key) != 2
                or not all(isinstance(part, str) and part for part in raw_key)
            ):
                raise _snapshot_invalid("dependency key")
            if not isinstance(raw_value, (tuple, list)):
                raise _snapshot_invalid("dependency value")
            if not all(isinstance(part, str) and part for part in raw_value):
                raise _snapshot_invalid("dependency value")
            key = (raw_key[0], raw_key[1])
            dependencies[key] = list(raw_value)

        counters: dict[str, int] = {}
        for key in _COUNTER_KEYS:
            value = state["counters"].get(key)
            if type(value) is not int or value < 0:
                raise _snapshot_invalid(f"counter {key}")
            counters[key] = value
        if "active" in state["counters"]:
            value = state["counters"]["active"]
            if type(value) is not int or value < 0:
                raise _snapshot_invalid("counter active")
            if value != len(active):
                raise _snapshot_invalid("counter active")

        numeric_ids = [
            int(match.group(1))
            for statement_id in seen_ids
            if (match := _STATEMENT_ID_PATTERN.fullmatch(statement_id))
        ]
        next_id = max(numeric_ids + [0]) + 1
        next_id = max(next_id, counters["statements"] + 1)
        return history, active, dependencies, counters, next_id

    def _snapshot_statement(self, raw: object) -> tuple[Statement, Statement | None]:
        if isinstance(raw, Statement):
            current = raw
            raw_active = True
        elif isinstance(raw, dict):
            raw_active = raw.get("_active", True)
            current = self._parse_snapshot_statement(raw)
        else:
            raise _snapshot_invalid("statement")

        if type(raw_active) is not bool:
            raise _snapshot_invalid("_active")
        if isinstance(raw, dict) and "_history_record" in raw:
            history_data = raw["_history_record"]
            if not isinstance(history_data, dict):
                raise _snapshot_invalid("_history_record")
            history_record = self._parse_snapshot_statement(history_data)
            if history_record.statement_id != current.statement_id:
                raise _snapshot_invalid("_history_record")
        else:
            history_record = current
        if not raw_active:
            return current, None
        return history_record, current

    @staticmethod
    def _parse_snapshot_statement(data: dict) -> Statement:
        if not set(_STATEMENT_KEYS).issubset(data):
            raise _snapshot_invalid("statement keys")

        statement_id = data["statement_id"]
        if not isinstance(statement_id, str) or not statement_id:
            raise _snapshot_invalid("statement_id")
        for key in ("product", "component", "vulnerability"):
            if not isinstance(data[key], str) or not data[key]:
                raise _snapshot_invalid(key)
        _validate_status(data["status"])
        if not isinstance(data["introduced"], str):
            raise _snapshot_invalid("introduced")
        _valid_range(data["introduced"], data["until"])
        if data["until"] is not None and not isinstance(data["until"], str):
            raise _snapshot_invalid("until")
        if data["fixed"] is not None:
            if not isinstance(data["fixed"], str):
                raise _snapshot_invalid("fixed")
            _version_key(data["fixed"])
        if data["status"] == "fixed" and not data["fixed"]:
            raise _snapshot_invalid("fixed")
        for key in ("justification", "evidence_ref", "expires_at", "created_at"):
            if data[key] is not None and not isinstance(data[key], str):
                raise _snapshot_invalid(key)
        if not data["created_at"]:
            raise _snapshot_invalid("created_at")
        _time_value(data["created_at"], "created_at")
        if data["expires_at"] is not None:
            _time_value(data["expires_at"], "expires_at")
        if type(data["revision"]) is not int or data["revision"] < 1:
            raise _snapshot_invalid("revision")
        if data["status"] == "not_affected":
            if not data["justification"]:
                raise _snapshot_invalid("justification")
            if data["justification"] not in _JUSTIFICATIONS:
                raise _snapshot_invalid("justification")
            if not data["evidence_ref"]:
                raise _snapshot_invalid("evidence_ref")

        return Statement(**{key: data[key] for key in _STATEMENT_KEYS})

    @staticmethod
    def _check_snapshot_overlaps(active: dict[str, Statement]) -> None:
        records = list(active.values())
        for index, first in enumerate(records):
            first_start, first_end = _valid_range(first.introduced, first.until)
            for second in records[index + 1:]:
                if (
                    first.product != second.product
                    or first.component != second.component
                    or first.vulnerability != second.vulnerability
                ):
                    continue
                second_start, second_end = _valid_range(
                    second.introduced, second.until
                )
                if _ranges_overlap(
                    first_start, first_end, second_start, second_end
                ):
                    raise _snapshot_invalid("overlapping statements")

    def _matching_statement(self, product: str | None, component: str,
                            vulnerability: str, version: tuple[int, ...]):
        matches = []
        for record in self._statements.values():
            if record.component != component or record.vulnerability != vulnerability:
                continue
            if product is not None and record.product != product:
                continue
            start, end = _valid_range(record.introduced, record.until)
            if _range_contains(version, start, end):
                matches.append(record)
        if not matches:
            return None
        return min(
            matches,
            key=lambda record: (
                self._history_rank.get(record.statement_id, 0),
                record.statement_id,
            ),
        )

    @staticmethod
    def _verdict_for(record: Statement, version: tuple[int, ...]) -> tuple[str, str]:
        if record.status == "fixed":
            fixed = _version_key(record.fixed)
            if version < fixed:
                return "affected", "fixed_version_not_reached"
            return "fixed", "fixed_version_reached"
        return record.status, "statement"

    def _invalidate_upstream_dependents(self, fixed_record: Statement) -> None:
        reverse: dict[tuple[str, str], set[str]] = {}
        for (product, component), dependencies in self._dependencies.items():
            for dependency in dependencies:
                reverse.setdefault((product, dependency), set()).add(component)

        affected_components: set[tuple[str, str]] = set()
        pending: list[tuple[str, str]] = []
        for (product, dependency), dependents in reverse.items():
            if dependency == fixed_record.component:
                pending.extend((product, dependent) for dependent in dependents)

        while pending:
            key = pending.pop()
            if key in affected_components:
                continue
            affected_components.add(key)
            pending.extend(reverse.get(key, ()))

        if not affected_components:
            return
        for statement_id, record in list(self._statements.items()):
            if record.status != "not_affected":
                continue
            if (record.product, record.component) not in affected_components:
                continue
            self._statements[statement_id] = replace(
                record, status="under_investigation"
            )
            self._counters["downgraded"] += 1
