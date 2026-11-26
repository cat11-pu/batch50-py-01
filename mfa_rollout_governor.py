"""Staged MFA rollout: stable bucketing, grace gradient and exemption expiry."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


class MfaRolloutError(ValueError):
    """Raised when a rollout operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class RolloutStage:
    tenant: str
    stage: int
    percent: int
    updated_at: str


@dataclass(frozen=True)
class MfaDecision:
    tenant: str
    user_id: str
    bucket: int
    stage: int
    percent: int
    cohort: bool
    state: str
    requires_mfa: bool
    grace_until: str | None
    exemption_until: str | None


class MfaRolloutGovernor:
    """Decide which users a tenant's MFA mandate reaches."""

    _VERSION = 1
    _STATS_KEYS = ("evaluations", "grace_started", "enforced",
                   "exemptions_granted", "stage_changes")
    _STATES = ("not_required", "grace", "enforced", "exempt", "satisfied")

    def __init__(self, *, base_grace_days: int = 7, clock=None) -> None:
        self.base_grace_days = base_grace_days
        self._clock = clock
        self._lock = threading.RLock()
        self._stages: dict[str, RolloutStage] = {}
        self._users: set[tuple[str, str]] = set()
        self._grace: dict[tuple[str, str], str] = {}
        self._enrollments: set[tuple[str, str]] = set()
        self._exemptions: dict[tuple[str, str], dict] = {}
        self._forced: set[tuple[str, str]] = set()
        self._stats = {key: 0 for key in self._STATS_KEYS}

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _parse_ts(value: object):
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value)
            except ValueError:
                return None
        else:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    def _now(self, now):
        if now is None:
            now = self._clock() if self._clock is not None else None
        if now is None:
            moment = datetime.now(timezone.utc)
            return moment, moment.isoformat()
        moment = self._parse_ts(now)
        if moment is None:
            raise MfaRolloutError("MFA_INVALID_REQUEST",
                                  {"now": now, "reason": "invalid timestamp"})
        text = now if isinstance(now, str) else moment.isoformat()
        return moment, text

    def set_stage(self, tenant: str, *, stage: int, percent: int,
                  now: str | None = None) -> RolloutStage:
        with self._lock:
            if not isinstance(tenant, str) or not tenant.strip():
                raise MfaRolloutError("MFA_INVALID_REQUEST",
                                      {"tenant": tenant})
            if not self._is_int(stage) or not 0 <= stage <= 3:
                raise MfaRolloutError("MFA_BAD_STAGE", stage)
            if not self._is_int(percent) or not 0 <= percent <= 100:
                raise MfaRolloutError("MFA_BAD_PERCENT", percent)
            _, now_text = self._now(now)
            record = RolloutStage(tenant=tenant, stage=stage,
                                  percent=percent, updated_at=now_text)
            self._stages[tenant] = record
            self._stats["stage_changes"] += 1
            return record

    def bucket_of(self, tenant: str, user_id: str) -> int:
        digest = hashlib.sha256(
            f"{tenant}\x1f{user_id}".encode("utf-8")).digest()
        return int.from_bytes(digest[:8], "big") % 100

    def _resolve(self, key, percent, cohort, now_dt, mutate):
        if key in self._enrollments:
            return "satisfied", False, self._grace.get(key), None
        exemption = self._exemptions.get(key)
        if exemption is not None:
            until_dt = self._parse_ts(exemption["until"])
            if until_dt is not None and now_dt < until_dt:
                return "exempt", False, self._grace.get(key), exemption["until"]
        if key in self._forced:
            return "enforced", True, self._grace.get(key), None
        if cohort:
            grace_until = self._grace.get(key)
            if grace_until is None:
                days = max(1, self.base_grace_days * (100 - percent) // 100)
                grace_until = (now_dt + timedelta(days=days)).isoformat()
                if mutate:
                    self._grace[key] = grace_until
                    self._stats["grace_started"] += 1
                return "grace", False, grace_until, None
            if now_dt >= self._parse_ts(grace_until):
                if mutate:
                    self._forced.add(key)
                    self._stats["enforced"] += 1
                return "enforced", True, grace_until, None
            return "grace", False, grace_until, None
        return "not_required", False, self._grace.get(key), None

    def evaluate(self, tenant: str, user_id: str, *,
                 now: str | None = None) -> MfaDecision:
        with self._lock:
            now_dt, _ = self._now(now)
            self._stats["evaluations"] += 1
            key = (tenant, user_id)
            self._users.add(key)
            record = self._stages.get(tenant)
            stage = record.stage if record else 0
            percent = record.percent if record else 0
            bucket = self.bucket_of(tenant, user_id)
            cohort = bucket < percent
            state, requires, grace_until, exemption_until = self._resolve(
                key, percent, cohort, now_dt, mutate=True)
            return MfaDecision(
                tenant=tenant, user_id=user_id, bucket=bucket, stage=stage,
                percent=percent, cohort=cohort, state=state,
                requires_mfa=requires, grace_until=grace_until,
                exemption_until=exemption_until)

    def grant_grace(self, tenant: str, user_id: str, *, days: int,
                    now: str | None = None) -> dict:
        with self._lock:
            now_dt, _ = self._now(now)
            if not self._is_int(days) or days <= 0:
                raise MfaRolloutError("MFA_INVALID_REQUEST", {"days": days})
            key = (tenant, user_id)
            record = self._stages.get(tenant)
            percent = record.percent if record else 0
            cohort = self.bucket_of(tenant, user_id) < percent
            current = self._grace.get(key)
            if (not cohort or current is None or key in self._forced
                    or key in self._enrollments):
                raise MfaRolloutError("MFA_STATE_INVALID",
                                      {"tenant": tenant, "user_id": user_id})
            base = max(self._parse_ts(current), now_dt)
            grace_until = (base + timedelta(days=days)).isoformat()
            self._grace[key] = grace_until
            return {"user_id": user_id, "grace_until": grace_until}

    def exempt(self, tenant: str, user_id: str, *, until: str, reason: str,
               now: str | None = None) -> dict:
        with self._lock:
            now_dt, _ = self._now(now)
            until_dt = self._parse_ts(until)
            if until_dt is None or until_dt <= now_dt:
                raise MfaRolloutError("MFA_INVALID_REQUEST",
                                      {"until": until})
            if not isinstance(reason, str) or not reason.strip():
                raise MfaRolloutError("MFA_INVALID_REQUEST",
                                      {"reason": reason})
            until_text = until if isinstance(until, str) else until_dt.isoformat()
            key = (tenant, user_id)
            self._users.add(key)
            self._exemptions[key] = {"until": until_text, "reason": reason}
            self._stats["exemptions_granted"] += 1
            return {"user_id": user_id, "until": until_text,
                    "reason": reason}

    def revoke_exemption(self, tenant: str, user_id: str) -> bool:
        with self._lock:
            return self._exemptions.pop((tenant, user_id), None) is not None

    def mark_enrolled(self, tenant: str, user_id: str, *,
                      now: str | None = None) -> dict:
        with self._lock:
            _, now_text = self._now(now)
            key = (tenant, user_id)
            self._users.add(key)
            self._enrollments.add(key)
            return {"user_id": user_id, "enrolled_at": now_text}

    def report(self, tenant: str, *, now: str | None = None) -> dict:
        with self._lock:
            now_dt, _ = self._now(now)
            record = self._stages.get(tenant)
            percent = record.percent if record else 0
            counts = {state: 0 for state in self._STATES}
            for key in sorted(self._users):
                if key[0] != tenant:
                    continue
                cohort = self.bucket_of(*key) < percent
                state, _, _, _ = self._resolve(key, percent, cohort,
                                               now_dt, mutate=False)
                counts[state] += 1
            return counts

    def snapshot(self) -> dict:
        with self._lock:
            stages = {tenant: {"stage": rec.stage, "percent": rec.percent,
                               "updated_at": rec.updated_at}
                      for tenant, rec in self._stages.items()}
            grace: dict[str, dict[str, str]] = {}
            for (tenant, user_id), until in self._grace.items():
                grace.setdefault(tenant, {})[user_id] = until
            exemptions: dict[str, dict[str, dict]] = {}
            for (tenant, user_id), record in self._exemptions.items():
                exemptions.setdefault(tenant, {})[user_id] = dict(record)
            return {
                "version": self._VERSION,
                "stages": stages,
                "users": sorted([list(key) for key in self._users]),
                "grace": grace,
                "enrollments": sorted([list(key)
                                       for key in self._enrollments]),
                "exemptions": exemptions,
                "forced": sorted([list(key) for key in self._forced]),
                "stats": dict(self._stats),
            }

    @staticmethod
    def _validate_pairs(value):
        return (isinstance(value, list)
                and all(isinstance(item, (list, tuple)) and len(item) == 2
                        and all(isinstance(part, str) for part in item)
                        for item in value))

    def restore(self, state: dict) -> None:
        def invalid(detail):
            raise MfaRolloutError("MFA_SNAPSHOT_INVALID", detail)

        with self._lock:
            if not isinstance(state, dict):
                invalid("snapshot must be a mapping")
            expected = {"version", "stages", "users", "grace",
                        "enrollments", "exemptions", "forced", "stats"}
            if set(state) != expected:
                invalid("snapshot keys mismatch")
            if state["version"] != self._VERSION:
                invalid("unsupported version")

            raw_stages = state["stages"]
            if not isinstance(raw_stages, dict):
                invalid("stages must be a mapping")
            stages = {}
            for tenant, entry in raw_stages.items():
                if not isinstance(tenant, str) or not isinstance(entry, dict):
                    invalid("bad stage entry")
                stage = entry.get("stage")
                percent = entry.get("percent")
                updated_at = entry.get("updated_at")
                if (not self._is_int(stage) or not 0 <= stage <= 3
                        or not self._is_int(percent)
                        or not 0 <= percent <= 100
                        or not isinstance(updated_at, str)):
                    invalid("bad stage entry")
                stages[tenant] = RolloutStage(tenant=tenant, stage=stage,
                                              percent=percent,
                                              updated_at=updated_at)

            if not self._validate_pairs(state["users"]):
                invalid("users must be pairs")
            users = {tuple(item) for item in state["users"]}

            raw_grace = state["grace"]
            if not isinstance(raw_grace, dict):
                invalid("grace must be a mapping")
            grace = {}
            for tenant, entries in raw_grace.items():
                if not isinstance(tenant, str) or not isinstance(entries, dict):
                    invalid("bad grace entry")
                for user_id, until in entries.items():
                    if (not isinstance(user_id, str)
                            or not isinstance(until, str)
                            or self._parse_ts(until) is None):
                        invalid("bad grace entry")
                    grace[(tenant, user_id)] = until

            if not self._validate_pairs(state["enrollments"]):
                invalid("enrollments must be pairs")
            enrollments = {tuple(item) for item in state["enrollments"]}

            raw_exemptions = state["exemptions"]
            if not isinstance(raw_exemptions, dict):
                invalid("exemptions must be a mapping")
            exemptions = {}
            for tenant, entries in raw_exemptions.items():
                if not isinstance(tenant, str) or not isinstance(entries, dict):
                    invalid("bad exemption entry")
                for user_id, entry in entries.items():
                    if (not isinstance(user_id, str)
                            or not isinstance(entry, dict)):
                        invalid("bad exemption entry")
                    until = entry.get("until")
                    reason = entry.get("reason")
                    if (not isinstance(until, str)
                            or self._parse_ts(until) is None
                            or not isinstance(reason, str)):
                        invalid("bad exemption entry")
                    exemptions[(tenant, user_id)] = {"until": until,
                                                     "reason": reason}

            if not self._validate_pairs(state["forced"]):
                invalid("forced must be pairs")
            forced = {tuple(item) for item in state["forced"]}

            raw_stats = state["stats"]
            if (not isinstance(raw_stats, dict)
                    or set(raw_stats) != set(self._STATS_KEYS)
                    or not all(self._is_int(value) and value >= 0
                               for value in raw_stats.values())):
                invalid("bad stats")
            stats = {key: raw_stats[key] for key in self._STATS_KEYS}

            self._stages = stages
            self._users = users
            self._grace = grace
            self._enrollments = enrollments
            self._exemptions = exemptions
            self._forced = forced
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
