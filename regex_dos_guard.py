"""Detection-rule regex safety: scoring, benchmarks, quarantine and approval."""

from __future__ import annotations

import copy
import hashlib
import math
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


SNAPSHOT_VERSION = 1
COUNTER_KEYS = (
    "registered",
    "deduped",
    "quarantined",
    "approved",
    "approvals_expired",
    "loaded",
    "compile_failures",
    "timeouts",
)


class RegexSafetyError(ValueError):
    """Raised when a rule or benchmark operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Analysis:
    fingerprint: str
    score: int
    findings: tuple
    verdict: str


@dataclass(frozen=True)
class RuleRecord:
    rule_id: str
    pattern: str
    flags: int
    fingerprint: str
    score: int
    findings: tuple
    verdict: str
    state: str
    approved_by: str | None
    approved_until: str | None
    samples: int


def _invalid_request(detail: object = None) -> RegexSafetyError:
    return RegexSafetyError("REGEX_INVALID_REQUEST", detail)


def _validate_pattern(pattern: Any) -> None:
    if not isinstance(pattern, str) or pattern == "":
        raise _invalid_request({"field": "pattern"})


def _normalize_flags(flags: Any) -> int:
    if isinstance(flags, bool) or not isinstance(flags, int):
        raise _invalid_request({"field": "flags"})
    return int(flags)


def fingerprint_for(pattern: str, flags: int = 0) -> str:
    """Return the specified pattern/flag fingerprint."""
    _validate_pattern(pattern)
    flags = _normalize_flags(flags)
    digest = hashlib.sha256()
    digest.update(pattern.encode("utf-8"))
    digest.update(b"\x1f")
    digest.update(str(flags).encode("ascii"))
    return digest.hexdigest()[:16]


def _skip_character_class(pattern: str, index: int) -> int:
    """Return the index immediately after a character class at ``index``."""
    length = len(pattern)
    index += 1
    if index < length and pattern[index] == "^":
        index += 1
    # A closing bracket immediately after [ or [^ is a literal bracket.
    if index < length and pattern[index] == "]":
        index += 1
    while index < length:
        char = pattern[index]
        if char == "\\" and index + 1 < length:
            index += 2
            continue
        if char == "]":
            return index + 1
        index += 1
    return length


def _group_content_start(pattern: str, open_index: int) -> int:
    """Return the first content index after a parenthesized group opener."""
    length = len(pattern)
    index = open_index + 1
    if index >= length or pattern[index] != "?":
        return open_index + 1

    index += 1  # position after '?'
    if index >= length:
        return index

    char = pattern[index]
    if char in ":=!>":
        return index + 1

    if char == "<":
        if index + 1 < length and pattern[index + 1] in "=!":
            return index + 2
        close = pattern.find(">", index + 1)
        return close + 1 if close != -1 else length

    if char == "P":
        if index + 1 < length and pattern[index + 1] == "<":
            close = pattern.find(">", index + 2)
            return close + 1 if close != -1 else length
        if index + 1 < length and pattern[index + 1] == "=":
            return index + 2

    if char == "(":
        close = pattern.find(")", index + 1)
        return close + 1 if close != -1 else length

    # Inline flag groups such as (?i) and (?im-x:content).
    while index < length and pattern[index] not in ":)":
        index += 1
    if index < length and pattern[index] == ":":
        return index + 1
    return index


def _quantifier_end(pattern: str, index: int) -> int | None:
    """Return the end index of a quantifier starting at ``index``."""
    length = len(pattern)
    if index >= length:
        return None

    if pattern[index] in "*+?":
        end = index + 1
    elif pattern[index] == "{":
        match = re.match(r"\{(?:\d+|\d*,\d+|\d+,\d*)\}", pattern[index:])
        if match is None:
            return None
        end = index + match.end()
    else:
        return None

    # Lazy or possessive repetition modifier.
    if end < length and pattern[end] in "?+":
        end += 1
    return end


def _has_nested_quantifier(pattern: str) -> bool:
    length = len(pattern)
    groups: list[dict[str, bool]] = []
    index = 0

    while index < length:
        char = pattern[index]

        if char == "\\" and index + 1 < length:
            index += 2
            continue

        if char == "[":
            index = _skip_character_class(pattern, index)
            continue

        if char == "(":
            groups.append({"contains_quantifier": False})
            index = _group_content_start(pattern, index)
            continue

        if char == ")":
            if groups:
                group = groups.pop()
                quantifier_end = _quantifier_end(pattern, index + 1)
                if quantifier_end is not None and group["contains_quantifier"]:
                    return True
            index += 1
            continue

        quantifier_end = _quantifier_end(pattern, index)
        if quantifier_end is not None:
            for group in groups:
                group["contains_quantifier"] = True
            index = quantifier_end
            continue

        index += 1

    return False


def _branches_overlap(pattern: str, content_start: int, pipes: list[int], end: int) -> bool:
    if not pipes:
        return False

    branches: list[str] = []
    start = content_start
    for pipe in pipes:
        branches.append(pattern[start:pipe])
        start = pipe + 1
    branches.append(pattern[start:end])

    for left_index, left in enumerate(branches):
        for right in branches[left_index + 1 :]:
            if left == right or left.startswith(right) or right.startswith(left):
                return True
    return False


def _alternation_groups_overlap(pattern: str) -> bool:
    length = len(pattern)
    scopes: list[dict[str, Any]] = [{"content_start": 0, "pipes": []}]
    index = 0

    while index < length:
        char = pattern[index]

        if char == "\\" and index + 1 < length:
            index += 2
            continue

        if char == "[":
            index = _skip_character_class(pattern, index)
            continue

        if char == "(":
            content_start = _group_content_start(pattern, index)
            scopes.append({"content_start": content_start, "pipes": []})
            index = content_start
            continue

        if char == "|":
            scopes[-1]["pipes"].append(index)
            index += 1
            continue

        if char == ")":
            if len(scopes) > 1:
                scope = scopes.pop()
                if _branches_overlap(
                    pattern,
                    int(scope["content_start"]),
                    list(scope["pipes"]),
                    index,
                ):
                    return True
            index += 1
            continue

        index += 1

    scope = scopes[0]
    return _branches_overlap(
        pattern, int(scope["content_start"]), list(scope["pipes"]), length
    )


def _has_repeated_dot_atom(pattern: str) -> bool:
    length = len(pattern)
    tokens: list[tuple[int, int]] = []
    index = 0

    while index < length:
        char = pattern[index]

        if char == "\\" and index + 1 < length:
            index += 2
            continue

        if char == "[":
            index = _skip_character_class(pattern, index)
            continue

        if char == "." and index + 1 < length and pattern[index + 1] in "*+":
            end = _quantifier_end(pattern, index + 1)
            if end is not None:
                tokens.append((index, end))
                index = end
                continue

        index += 1

    for previous, current in zip(tokens, tokens[1:]):
        if previous[1] == current[0]:
            return True
    return False


def analyze_pattern(pattern: str, flags: int = 0) -> Analysis:
    _validate_pattern(pattern)
    flags = _normalize_flags(flags)

    findings: set[str] = set()
    if _has_nested_quantifier(pattern):
        findings.add("NESTED_QUANTIFIER")
    if _alternation_groups_overlap(pattern):
        findings.add("OVERLAPPING_ALTERNATION")
    if _has_repeated_dot_atom(pattern):
        findings.add("REPEATED_DOT_STAR")

    ordered_findings = tuple(sorted(findings))
    score = 0
    if "NESTED_QUANTIFIER" in findings:
        score += 70
    if "OVERLAPPING_ALTERNATION" in findings:
        score += 40
    if "REPEATED_DOT_STAR" in findings:
        score += 35
    score = min(100, score)

    if score >= 70:
        verdict = "high"
    elif score >= 40:
        verdict = "medium"
    else:
        verdict = "low"

    return Analysis(
        fingerprint=fingerprint_for(pattern, flags),
        score=score,
        findings=ordered_findings,
        verdict=verdict,
    )


def _coerce_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        try:
            text = value[:-1] + "+00:00" if value.endswith("Z") else value
            moment = datetime.fromisoformat(text)
        except ValueError as exc:
            raise _invalid_request({"field": "now", "value": value}) from exc
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        try:
            moment = datetime.fromtimestamp(float(value), tz=timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise _invalid_request({"field": "now", "value": value}) from exc
    else:
        raise _invalid_request({"field": "now", "value": value})

    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


class RegexDosGuard:
    """Score detection regexes for catastrophic backtracking and gate the set."""

    def __init__(
        self,
        *,
        max_rules: int = 200,
        budget_seconds: float = 0.05,
        max_samples: int = 8,
        clock=None,
        executor=None,
    ) -> None:
        self.max_rules = max_rules
        self.budget_seconds = budget_seconds
        self.max_samples = max_samples
        self._clock = clock
        self.executor = executor
        self._lock = threading.RLock()
        self._rules: dict[str, dict[str, Any]] = {}
        self._fingerprints: dict[str, str] = {}
        self._counters = {key: 0 for key in COUNTER_KEYS}
        self._loaded: tuple[str, ...] = ()
        self._grace: set[str] = set()
        self._compile_failures: set[str] = set()

    def register(self, pattern: str, *, flags: int = 0) -> RuleRecord:
        _validate_pattern(pattern)
        flags = _normalize_flags(flags)

        with self._lock:
            # Scoring and all registered state publish in one critical section;
            # concurrent identical registrations therefore have one winner.
            analysis = analyze_pattern(pattern, flags)
            existing_id = self._fingerprints.get(analysis.fingerprint)
            if existing_id is not None:
                self._counters["deduped"] += 1
                return self._record(self._rules[existing_id])

            if len(self._rules) >= self.max_rules:
                raise RegexSafetyError(
                    "REGEX_CAPACITY_EXCEEDED",
                    {"max_rules": self.max_rules, "registered": len(self._rules)},
                )

            rule_id = self._next_rule_id_locked()
            rule = {
                "rule_id": rule_id,
                "pattern": pattern,
                "flags": flags,
                "fingerprint": analysis.fingerprint,
                "score": analysis.score,
                "findings": list(analysis.findings),
                "verdict": analysis.verdict,
                "state": "registered",
                "approved_by": None,
                "approved_until": None,
                "samples": 0,
                "benchmark_runs": 0,
                "last_total_ms": None,
                "last_status": None,
                "quarantine_reason": None,
                "last_quarantine_reason": None,
                "compile_failed": False,
                "compile_error": None,
                "grace_active": False,
                "grace_count": 0,
            }
            self._rules[rule_id] = rule
            self._fingerprints[analysis.fingerprint] = rule_id
            self._counters["registered"] += 1
            return self._record(rule)

    def analyze(self, pattern: str, *, flags: int = 0) -> Analysis:
        return analyze_pattern(pattern, flags)

    def benchmark(
        self, rule_id: str, samples, *, budget_seconds: float | None = None
    ) -> dict:
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule is None:
                raise RegexSafetyError("REGEX_RULE_UNKNOWN", {"rule_id": rule_id})
            pattern = rule["pattern"]
            flags = rule["flags"]

        normalized_samples = self._normalize_samples(samples)
        measurements = []
        for sample in normalized_samples:
            if self.executor is not None:
                measurements.append(self.executor(pattern, sample))
            else:
                measurements.append(self._default_executor(pattern, sample, flags))

        total_ms = sum(measurements)
        budget = self.budget_seconds if budget_seconds is None else budget_seconds
        status = "exceeded" if total_ms > float(budget) * 1000.0 else "within_budget"

        with self._lock:
            rule = self._rules[rule_id]
            rule["samples"] += len(normalized_samples)
            rule["benchmark_runs"] += 1
            rule["last_total_ms"] = total_ms
            rule["last_status"] = status

            if status == "exceeded":
                self._counters["timeouts"] += 1
                if rule["state"] != "quarantined":
                    self._quarantine_locked(rule_id, "benchmark_timeout")
                else:
                    rule["last_quarantine_reason"] = "benchmark_timeout"

        return {
            "rule_id": rule_id,
            "samples": measurements,
            "total_ms": total_ms,
            "sample_count": len(normalized_samples),
            "status": status,
        }

    def quarantine(self, rule_id: str, reason: str) -> RuleRecord:
        with self._lock:
            rule = self._rules.get(rule_id)
            if rule is None:
                raise RegexSafetyError("REGEX_RULE_UNKNOWN", {"rule_id": rule_id})
            self._quarantine_locked(rule_id, reason)
            return self._record(rule)

    def approve(
        self,
        rule_id: str,
        *,
        approved_by: str,
        ttl_seconds: int,
        now=None,
    ) -> RuleRecord:
        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, (int, float))
            or not math.isfinite(float(ttl_seconds))
            or ttl_seconds <= 0
        ):
            raise RegexSafetyError(
                "REGEX_APPROVAL_TTL_INVALID", {"ttl_seconds": ttl_seconds}
            )

        with self._lock:
            moment = self._now(now)
            rule = self._rules.get(rule_id)
            if rule is None:
                raise RegexSafetyError("REGEX_RULE_UNKNOWN", {"rule_id": rule_id})

            until = moment + timedelta(seconds=float(ttl_seconds))
            rule["state"] = "approved"
            rule["approved_by"] = approved_by
            rule["approved_until"] = until.isoformat()
            rule["grace_active"] = False
            self._grace.discard(rule_id)
            self._counters["approved"] += 1
            return self._record(rule)

    def load_ruleset(self) -> dict:
        loaded: list[str] = []
        excluded: list[str] = []
        compile_failures: list[str] = []

        with self._lock:
            for rule in self._ordered_rules_locked():
                rule_id = rule["rule_id"]
                try:
                    re.compile(rule["pattern"], rule["flags"])
                except re.error as exc:
                    rule["compile_failed"] = True
                    rule["compile_error"] = str(exc)
                    compile_failures.append(rule_id)
                    self._counters["compile_failures"] += 1
                    continue

                rule["compile_failed"] = False
                rule["compile_error"] = None
                if self._is_loadable_locked(rule):
                    loaded.append(rule_id)
                else:
                    excluded.append(rule_id)

            loaded_tuple = tuple(loaded)
            self._loaded = loaded_tuple
            self._compile_failures = set(compile_failures)
            self._counters["loaded"] += len(loaded_tuple)

            for rule_id in tuple(self._grace):
                rule = self._rules.get(rule_id)
                if rule is not None:
                    rule["grace_active"] = False
            self._grace.clear()

        return {
            "loaded": loaded_tuple,
            "excluded": tuple(excluded),
            "compile_failures": tuple(compile_failures),
        }

    def effective_rules(self) -> tuple:
        with self._lock:
            effective: list[str] = []
            for rule in self._ordered_rules_locked():
                rule_id = rule["rule_id"]
                if rule_id in self._grace:
                    effective.append(rule_id)
                    continue
                if rule.get("compile_failed"):
                    continue
                try:
                    re.compile(rule["pattern"], rule["flags"])
                except re.error:
                    continue
                if self._is_loadable_locked(rule):
                    effective.append(rule_id)
            return tuple(effective)

    def expire_approvals(self, now=None) -> int:
        expired_count = 0

        with self._lock:
            moment = self._now(now)
            for rule in self._ordered_rules_locked():
                rule_id = rule["rule_id"]
                if rule["state"] != "approved" or not rule["approved_until"]:
                    continue
                until = _coerce_datetime(rule["approved_until"])
                if moment < until:
                    continue

                self._counters["approvals_expired"] += 1
                self._counters["quarantined"] += 1
                rule["state"] = "quarantined"
                expired_count += 1

                if rule_id in self._loaded:
                    rule["grace_active"] = True
                    rule["grace_count"] += 1
                    self._grace.add(rule_id)
                else:
                    rule["grace_active"] = False

        return expired_count

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": SNAPSHOT_VERSION,
                "rules": {
                    rule["rule_id"]: dict(rule)
                    for rule in self._ordered_rules_locked()
                },
                "counters": dict(self._counters),
                "loaded": self._loaded,
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        try:
            new_rules, new_counters, new_loaded = self._validate_snapshot(state)
        except RegexSafetyError:
            raise
        except Exception as exc:
            raise RegexSafetyError(
                "REGEX_SNAPSHOT_INVALID", {"reason": str(exc)}
            ) from exc

        new_fingerprints = {
            rule["fingerprint"]: rule_id for rule_id, rule in new_rules.items()
        }
        new_grace = {
            rule_id
            for rule_id, rule in new_rules.items()
            if rule.get("grace_active") and rule_id in new_loaded
        }
        new_compile_failures = {
            rule_id
            for rule_id, rule in new_rules.items()
            if rule.get("compile_failed")
        }

        with self._lock:
            self._rules = new_rules
            self._fingerprints = new_fingerprints
            self._counters = new_counters
            self._loaded = new_loaded
            self._grace = new_grace
            self._compile_failures = new_compile_failures

    def _validate_snapshot(self, state: Any):
        if not isinstance(state, dict):
            raise RegexSafetyError("REGEX_SNAPSHOT_INVALID", {"field": "state"})

        for key in ("version", "rules", "counters", "loaded"):
            if key not in state:
                raise RegexSafetyError("REGEX_SNAPSHOT_INVALID", {"missing": key})

        version = state["version"]
        if type(version) is not int or version != SNAPSHOT_VERSION:
            raise RegexSafetyError("REGEX_SNAPSHOT_INVALID", {"field": "version"})

        raw_rules = state["rules"]
        if not isinstance(raw_rules, dict):
            raise RegexSafetyError("REGEX_SNAPSHOT_INVALID", {"field": "rules"})

        raw_counters = state["counters"]
        if not isinstance(raw_counters, dict):
            raise RegexSafetyError("REGEX_SNAPSHOT_INVALID", {"field": "counters"})

        raw_loaded = state["loaded"]
        if not isinstance(raw_loaded, (tuple, list)):
            raise RegexSafetyError("REGEX_SNAPSHOT_INVALID", {"field": "loaded"})

        counters: dict[str, int] = {}
        for key in COUNTER_KEYS:
            if key not in raw_counters:
                raise RegexSafetyError(
                    "REGEX_SNAPSHOT_INVALID", {"missing_counter": key}
                )
            value = raw_counters[key]
            if type(value) is not int or value < 0:
                raise RegexSafetyError(
                    "REGEX_SNAPSHOT_INVALID", {"counter": key, "value": value}
                )
            counters[key] = value

        rules: dict[str, dict[str, Any]] = {}
        for rule_id, raw_rule in raw_rules.items():
            rule = self._validate_rule_snapshot(rule_id, raw_rule)
            rules[rule["rule_id"]] = rule

        loaded: list[str] = []
        seen_loaded: set[str] = set()
        for rule_id in raw_loaded:
            if not isinstance(rule_id, str) or rule_id not in rules:
                raise RegexSafetyError(
                    "REGEX_SNAPSHOT_INVALID", {"field": "loaded", "rule_id": rule_id}
                )
            if rule_id in seen_loaded:
                raise RegexSafetyError(
                    "REGEX_SNAPSHOT_INVALID", {"field": "loaded", "rule_id": rule_id}
                )
            seen_loaded.add(rule_id)
            loaded.append(rule_id)

        return rules, counters, tuple(loaded)

    def _validate_rule_snapshot(self, rule_id: Any, raw_rule: Any) -> dict[str, Any]:
        if not isinstance(rule_id, str) or not re.fullmatch(r"R-\d+", rule_id):
            raise RegexSafetyError("REGEX_SNAPSHOT_INVALID", {"rule_id": rule_id})
        if not isinstance(raw_rule, dict):
            raise RegexSafetyError("REGEX_SNAPSHOT_INVALID", {"rule_id": rule_id})

        def require(name: str, expected_type: type | tuple[type, ...]):
            if name not in raw_rule:
                raise RegexSafetyError(
                    "REGEX_SNAPSHOT_INVALID", {"rule_id": rule_id, "missing": name}
                )
            value = raw_rule[name]
            if not isinstance(value, expected_type):
                raise RegexSafetyError(
                    "REGEX_SNAPSHOT_INVALID", {"rule_id": rule_id, "field": name}
                )
            return value

        pattern = require("pattern", str)
        if not pattern:
            raise RegexSafetyError(
                "REGEX_SNAPSHOT_INVALID", {"rule_id": rule_id, "field": "pattern"}
            )

        flags = require("flags", int)
        if isinstance(flags, bool):
            raise RegexSafetyError(
                "REGEX_SNAPSHOT_INVALID", {"rule_id": rule_id, "field": "flags"}
            )

        fingerprint = require("fingerprint", str)
        score = require("score", int)
        if isinstance(score, bool) or not 0 <= score <= 100:
            raise RegexSafetyError(
                "REGEX_SNAPSHOT_INVALID", {"rule_id": rule_id, "field": "score"}
            )

        verdict = require("verdict", str)
        if verdict not in ("low", "medium", "high"):
            raise RegexSafetyError(
                "REGEX_SNAPSHOT_INVALID", {"rule_id": rule_id, "field": "verdict"}
            )

        state = require("state", str)
        if state not in ("registered", "approved", "quarantined"):
            raise RegexSafetyError(
                "REGEX_SNAPSHOT_INVALID", {"rule_id": rule_id, "field": "state"}
            )

        findings = require("findings", (list, tuple))
        if not all(isinstance(item, str) for item in findings):
            raise RegexSafetyError(
                "REGEX_SNAPSHOT_INVALID", {"rule_id": rule_id, "field": "findings"}
            )

        samples = require("samples", int)
        if isinstance(samples, bool) or samples < 0:
            raise RegexSafetyError(
                "REGEX_SNAPSHOT_INVALID", {"rule_id": rule_id, "field": "samples"}
            )

        approved_by = raw_rule.get("approved_by")
        if approved_by is not None and not isinstance(approved_by, str):
            raise RegexSafetyError(
                "REGEX_SNAPSHOT_INVALID", {"rule_id": rule_id, "field": "approved_by"}
            )

        approved_until = raw_rule.get("approved_until")
        if approved_until is not None:
            if not isinstance(approved_until, str):
                raise RegexSafetyError(
                    "REGEX_SNAPSHOT_INVALID",
                    {"rule_id": rule_id, "field": "approved_until"},
                )
            _coerce_datetime(approved_until)

        if raw_rule.get("rule_id", rule_id) != rule_id:
            raise RegexSafetyError(
                "REGEX_SNAPSHOT_INVALID", {"rule_id": rule_id, "field": "rule_id"}
            )

        normalized = {
            "rule_id": rule_id,
            "pattern": pattern,
            "flags": flags,
            "fingerprint": fingerprint,
            "score": score,
            "findings": list(findings),
            "verdict": verdict,
            "state": state,
            "approved_by": approved_by,
            "approved_until": approved_until,
            "samples": samples,
            "benchmark_runs": max(0, int(raw_rule.get("benchmark_runs", 0) or 0)),
            "last_total_ms": raw_rule.get("last_total_ms"),
            "last_status": raw_rule.get("last_status"),
            "quarantine_reason": raw_rule.get("quarantine_reason"),
            "last_quarantine_reason": raw_rule.get("last_quarantine_reason"),
            "compile_failed": bool(raw_rule.get("compile_failed", False)),
            "compile_error": raw_rule.get("compile_error"),
            "grace_active": bool(raw_rule.get("grace_active", False)),
            "grace_count": max(0, int(raw_rule.get("grace_count", 0) or 0)),
        }

        for field_name in (
            "quarantine_reason",
            "last_quarantine_reason",
            "compile_error",
        ):
            if normalized[field_name] is not None and not isinstance(
                normalized[field_name], str
            ):
                raise RegexSafetyError(
                    "REGEX_SNAPSHOT_INVALID",
                    {"rule_id": rule_id, "field": field_name},
                )

        return normalized

    def _next_rule_id_locked(self) -> str:
        highest = 0
        for rule_id in self._rules:
            match = re.fullmatch(r"R-(\d+)", rule_id)
            if match:
                highest = max(highest, int(match.group(1)))
        return f"R-{highest + 1:04d}"

    def _ordered_rules_locked(self) -> list[dict[str, Any]]:
        return sorted(
            self._rules.values(),
            key=lambda rule: int(str(rule["rule_id"]).split("-", 1)[1]),
        )

    def _record(self, rule: dict[str, Any]) -> RuleRecord:
        return RuleRecord(
            rule_id=rule["rule_id"],
            pattern=rule["pattern"],
            flags=rule["flags"],
            fingerprint=rule["fingerprint"],
            score=rule["score"],
            findings=tuple(rule["findings"]),
            verdict=rule["verdict"],
            state=rule["state"],
            approved_by=rule["approved_by"],
            approved_until=rule["approved_until"],
            samples=rule["samples"],
        )

    def _quarantine_locked(self, rule_id: str, reason: str) -> None:
        rule = self._rules[rule_id]
        if rule["state"] != "quarantined":
            self._counters["quarantined"] += 1
            rule["state"] = "quarantined"
            rule["quarantine_reason"] = reason
        else:
            rule["last_quarantine_reason"] = reason

    def _is_loadable_locked(self, rule: dict[str, Any]) -> bool:
        if rule["state"] == "quarantined":
            return False
        return rule["verdict"] != "high" or rule["state"] == "approved"

    def _normalize_samples(self, samples: Any) -> list:
        if samples is None:
            raise _invalid_request({"field": "samples"})
        try:
            normalized = list(samples)
        except TypeError as exc:
            raise _invalid_request({"field": "samples"}) from exc

        if not normalized:
            raise _invalid_request({"field": "samples"})
        if len(normalized) > self.max_samples:
            raise RegexSafetyError(
                "REGEX_SAMPLE_LIMIT",
                {"max_samples": self.max_samples, "sample_count": len(normalized)},
            )
        return normalized

    def _now(self, now: Any = None) -> datetime:
        if now is None and self._clock is not None:
            now = self._clock()
        if now is None:
            now = datetime.now(timezone.utc)
        return _coerce_datetime(now)

    def _default_executor(self, pattern: str, sample: str, flags: int = 0) -> float:
        started = time.perf_counter()
        re.search(re.compile(pattern, flags), sample)
        return (time.perf_counter() - started) * 1000.0
