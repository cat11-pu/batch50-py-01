"""Polkit style rule evaluation: layered sources, challenges, and grants."""

from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta
from typing import Any


class PolicyError(ValueError):
    """Raised when an authorization operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


SOURCES = ("admin", "vendor")
SUBJECT_KINDS = ("user", "group")
RESULTS = ("yes", "no", "auth_self", "auth_admin")


@dataclass(frozen=True)
class Rule:
    source: str
    action: str
    subject: str
    subject_kind: str
    result: str


@dataclass(frozen=True)
class Decision:
    result: str
    source: str | None
    cached: bool


@dataclass(frozen=True)
class Challenge:
    challenge_id: str
    user: str
    action: str
    rule_version: int
    expires_at: str
    attempts: int


@dataclass(frozen=True)
class Authorization:
    user: str
    action: str
    granted: bool
    source: str | None
    expires_at: str


class PolkitRuleEngine:
    """Evaluate layered rules and hand out short lived authorizations."""

    def __init__(self, *, max_attempts: int = 3, challenge_ttl: int = 300,
                 grant_ttl: int = 600, cooldown_seconds: int = 60) -> None:
        self.max_attempts = max_attempts
        self.challenge_ttl = challenge_ttl
        self.grant_ttl = grant_ttl
        self.cooldown_seconds = cooldown_seconds
        self._lock = threading.RLock()
        self._actions: dict[str, str] = {}
        self._rules: tuple[Rule, ...] = ()
        self._rules_by_version: dict[int, tuple[Rule, ...]] = {0: ()}
        self._version = 0
        self._challenges: dict[str, dict] = {}
        self._grants: dict[tuple[str, str], Authorization] = {}
        self._cooldowns: dict[tuple[str, str], datetime] = {}
        self._cache: dict[tuple[Any, ...], Decision] = {}
        self._counters = {
            "evaluations": 0, "challenges": 0, "completed": 0,
            "denied": 0, "revoked": 0, "cache_hits": 0,
        }

    def register_action(self, action: str, *, description: str = "") -> None:
        with self._lock:
            self._actions[action] = description

    def load_rules(self, rules, *, now: str) -> int:
        _parse_time(now)
        loaded_rules = _validate_rules(rules)
        with self._lock:
            self._version += 1
            self._rules = loaded_rules
            self._rules_by_version[self._version] = loaded_rules
            self._cache.clear()
            return self._version

    def evaluate(self, user: str, action: str, *, groups=(), now: str) -> Decision:
        when = _parse_time(now)
        group_set = _normalize_groups(groups)
        with self._lock:
            self._require_action(action)
            cache_key = (self._version, user, action, group_set)
            self._counters["evaluations"] += 1
            cached = self._cache.get(cache_key)
            if cached is not None:
                self._counters["cache_hits"] += 1
                return replace(cached, cached=True)

            decision = self._decide_locked(user, action, group_set)
            self._cache[cache_key] = decision
            return decision

    def challenge(self, user: str, action: str, *, groups=(), now: str) -> Challenge:
        when = _parse_time(now)
        group_set = _normalize_groups(groups)
        with self._lock:
            self._require_action(action)
            target = (user, action)
            self._raise_if_cooling_down_locked(target, when)

            decision = self.evaluate(
                user, action, groups=tuple(group_set), now=now
            )
            challenge_id = uuid.uuid4().hex
            while challenge_id in self._challenges:
                challenge_id = uuid.uuid4().hex

            record = {
                "challenge_id": challenge_id,
                "user": user,
                "action": action,
                "groups": group_set,
                "rule_version": self._version,
                "expires_at": when + timedelta(seconds=self.challenge_ttl),
                "attempts": 0,
                "status": "pending",
                "authorization": None,
                "decision_result": decision.result,
                "source": decision.source,
            }
            self._challenges[challenge_id] = record
            self._counters["challenges"] += 1
            return self._challenge_dto_locked(record)

    def complete(self, challenge_id: str, *, proof_ok: bool, now: str) -> Authorization:
        when = _parse_time(now)
        with self._lock:
            record = self._challenges.get(challenge_id)
            if record is None:
                raise PolicyError(
                    "POLICY_UNKNOWN_CHALLENGE",
                    {"challenge_id": challenge_id},
                )

            if record["status"] == "completed":
                return record["authorization"]
            if record["status"] == "expired":
                raise PolicyError(
                    "POLICY_CHALLENGE_EXPIRED",
                    {"challenge_id": challenge_id},
                )
            if record["status"] != "pending":
                raise PolicyError(
                    "POLICY_UNKNOWN_CHALLENGE",
                    {"challenge_id": challenge_id, "status": record["status"]},
                )

            if when >= record["expires_at"]:
                record["status"] = "expired"
                raise PolicyError(
                    "POLICY_CHALLENGE_EXPIRED",
                    {"challenge_id": challenge_id,
                     "expires_at": record["expires_at"].isoformat()},
                )

            target = (record["user"], record["action"])
            self._raise_if_cooling_down_locked(target, when)

            if not proof_ok:
                record["attempts"] += 1
                if record["attempts"] >= self.max_attempts:
                    self._cooldowns[target] = when + timedelta(
                        seconds=self.cooldown_seconds
                    )
                    raise PolicyError(
                        "POLICY_COOLDOWN",
                        {"user": record["user"], "action": record["action"]},
                    )
                raise PolicyError(
                    "POLICY_BAD_CREDENTIALS",
                    {"attempts": record["attempts"],
                     "max_attempts": self.max_attempts},
                )

            decision = self._decide_locked(
                record["user"],
                record["action"],
                record["groups"],
                version=record["rule_version"],
            )
            source = decision.source
            if source is None:
                source = record.get("source")

            authorization = Authorization(
                user=record["user"],
                action=record["action"],
                granted=True,
                source=source,
                expires_at=(
                    when + timedelta(seconds=self.grant_ttl)
                ).isoformat(),
            )
            record["status"] = "completed"
            record["authorization"] = authorization
            self._counters["completed"] += 1
            self._grants[target] = authorization
            self._cooldowns.pop(target, None)
            return authorization

    def authorize(self, user: str, action: str, *, groups=(), now: str) -> Authorization:
        when = _parse_time(now)
        with self._lock:
            self._require_action(action)
            target = (user, action)
            self._raise_if_cooling_down_locked(target, when)

            existing = self._grants.get(target)
            if existing is not None:
                if when < _parse_time(existing.expires_at):
                    return existing
                del self._grants[target]

            decision = self.evaluate(user, action, groups=groups, now=now)
            if decision.result == "yes":
                authorization = Authorization(
                    user=user,
                    action=action,
                    granted=True,
                    source=decision.source,
                    expires_at=(
                        when + timedelta(seconds=self.grant_ttl)
                    ).isoformat(),
                )
                self._grants[target] = authorization
                return authorization

            if decision.result == "no":
                self._counters["denied"] += 1
                raise PolicyError(
                    "POLICY_DENIED",
                    {"user": user, "action": action, "source": decision.source},
                )

            raise PolicyError(
                "POLICY_AUTH_REQUIRED",
                {"user": user, "action": action, "result": decision.result},
            )

    def revoke(self, user: str, action: str) -> int:
        with self._lock:
            removed = self._grants.pop((user, action), None)
            if removed is None:
                return 0
            self._counters["revoked"] += 1
            return 1

    def end_session(self, user: str) -> int:
        with self._lock:
            challenge_ids = [
                challenge_id
                for challenge_id, record in self._challenges.items()
                if record["user"] == user and record["status"] == "pending"
            ]
            for challenge_id in challenge_ids:
                del self._challenges[challenge_id]

            grant_keys = [
                key for key in self._grants if key[0] == user
            ]
            for key in grant_keys:
                del self._grants[key]

            return len(challenge_ids) + len(grant_keys)

    def active_challenges(self) -> list[Challenge]:
        with self._lock:
            return [
                self._challenge_dto_locked(record)
                for record in self._challenges.values()
                if record["status"] == "pending"
            ]

    def stats(self) -> dict:
        with self._lock:
            return {
                "actions": len(self._actions),
                "rules_version": self._version,
                "evaluations": self._counters["evaluations"],
                "challenges": self._counters["challenges"],
                "completed": self._counters["completed"],
                "denied": self._counters["denied"],
                "revoked": self._counters["revoked"],
                "cache_hits": self._counters["cache_hits"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            challenge_records = [
                self._challenge_state_locked(record)
                for record in self._challenges.values()
            ]
            return {
                "snapshot_format": 1,
                "rules_version": self._version,
                "actions": dict(self._actions),
                "rules": [asdict(rule) for rule in self._rules],
                "rules_by_version": {
                    str(version): [asdict(rule) for rule in rules]
                    for version, rules in self._rules_by_version.items()
                },
                "challenges": [
                    record
                    for record in challenge_records
                    if record["status"] == "pending"
                ],
                "challenge_records": challenge_records,
                "grants": [asdict(grant) for grant in self._grants.values()],
                "cooldowns": [
                    {
                        "user": user,
                        "action": action,
                        "until": until.isoformat(),
                    }
                    for (user, action), until in self._cooldowns.items()
                ],
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        try:
            restored = _normalize_snapshot(state)
        except PolicyError:
            raise PolicyError(
                "POLICY_SNAPSHOT_INVALID",
                {"reason": "invalid_snapshot"},
            ) from None
        except Exception as exc:
            raise PolicyError(
                "POLICY_SNAPSHOT_INVALID",
                {"reason": exc.__class__.__name__},
            ) from exc

        with self._lock:
            self._actions = (
                restored["actions"]
                if restored["actions"] is not None
                else dict(self._actions)
            )
            self._version = restored["rules_version"]
            self._rules_by_version = restored["rules_by_version"]
            self._rules = restored["rules"]
            self._challenges = restored["challenges"]
            self._grants = restored["grants"]
            self._cooldowns = restored["cooldowns"]
            self._counters = restored["counters"]
            self._cache.clear()

    def _require_action(self, action: str) -> None:
        if action not in self._actions:
            raise PolicyError("POLICY_UNKNOWN_ACTION", {"action": action})

    def _decide_locked(
        self,
        user: str,
        action: str,
        group_set: frozenset[str],
        *,
        version: int | None = None,
    ) -> Decision:
        self._require_action(action)
        if version is None:
            rules = self._rules
        else:
            rules = self._rules_by_version.get(version, ())

        for source in SOURCES:
            for rule in rules:
                if rule.action != action or rule.source != source:
                    continue
                if rule.subject_kind == "user":
                    matched = rule.subject == user
                else:
                    matched = rule.subject in group_set
                if matched:
                    return Decision(rule.result, rule.source, False)

        return Decision("no", None, False)

    def _cooldown_until_locked(
        self, target: tuple[str, str], when: datetime
    ) -> datetime | None:
        until = self._cooldowns.get(target)
        if until is None:
            return None
        if when >= until:
            del self._cooldowns[target]
            for record in self._challenges.values():
                if (
                    record["status"] == "pending"
                    and (record["user"], record["action"]) == target
                ):
                    record["attempts"] = 0
            return None
        return until

    def _raise_if_cooling_down_locked(
        self, target: tuple[str, str], when: datetime
    ) -> None:
        until = self._cooldown_until_locked(target, when)
        if until is not None:
            raise PolicyError(
                "POLICY_COOLDOWN",
                {"until": until.isoformat()},
            )

    @staticmethod
    def _challenge_dto_locked(record: dict) -> Challenge:
        return Challenge(
            challenge_id=record["challenge_id"],
            user=record["user"],
            action=record["action"],
            rule_version=record["rule_version"],
            expires_at=record["expires_at"].isoformat(),
            attempts=record["attempts"],
        )

    @staticmethod
    def _challenge_state_locked(record: dict) -> dict:
        state = dict(record)
        state["groups"] = sorted(record["groups"])
        state["expires_at"] = record["expires_at"].isoformat()
        authorization = record.get("authorization")
        state["authorization"] = (
            asdict(authorization) if authorization is not None else None
        )
        return state


def _parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        return value
    if not isinstance(value, str):
        raise PolicyError("POLICY_INVALID_TIME", {"value": value})
    try:
        text = value[:-1] + "+00:00" if value.endswith("Z") else value
        return datetime.fromisoformat(text)
    except ValueError as exc:
        raise PolicyError("POLICY_INVALID_TIME", {"value": value}) from exc


def _normalize_groups(groups: Any) -> frozenset[str]:
    if groups is None:
        return frozenset()
    if isinstance(groups, str):
        return frozenset((groups,))
    return frozenset(groups)


def _validate_rules(rules: Any) -> tuple[Rule, ...]:
    try:
        loaded = tuple(rules)
    except TypeError as exc:
        raise PolicyError(
            "POLICY_INVALID_RULE", {"reason": "rules_not_iterable"}
        ) from exc

    for index, rule in enumerate(loaded):
        if not isinstance(rule, Rule):
            raise PolicyError("POLICY_INVALID_RULE", {"index": index})
        if rule.source not in SOURCES:
            raise PolicyError(
                "POLICY_INVALID_RULE",
                {"index": index, "field": "source", "value": rule.source},
            )
        if rule.subject_kind not in SUBJECT_KINDS:
            raise PolicyError(
                "POLICY_INVALID_RULE",
                {"index": index, "field": "subject_kind",
                 "value": rule.subject_kind},
            )
        if rule.result not in RESULTS:
            raise PolicyError(
                "POLICY_INVALID_RULE",
                {"index": index, "field": "result", "value": rule.result},
            )
    return loaded


def _rules_from_state(raw_rules: Any) -> tuple[Rule, ...]:
    if raw_rules is None:
        return ()
    if isinstance(raw_rules, (Rule, dict)):
        raw_rules = (raw_rules,)

    rules = []
    for raw_rule in raw_rules:
        if isinstance(raw_rule, Rule):
            rules.append(raw_rule)
        elif isinstance(raw_rule, dict):
            rules.append(
                Rule(
                    source=raw_rule["source"],
                    action=raw_rule["action"],
                    subject=raw_rule["subject"],
                    subject_kind=raw_rule["subject_kind"],
                    result=raw_rule["result"],
                )
            )
        else:
            raise ValueError("invalid rule snapshot")
    return _validate_rules(rules)


def _authorization_from_state(raw: Any) -> Authorization:
    if isinstance(raw, Authorization):
        return raw
    if not isinstance(raw, dict):
        raise ValueError("invalid authorization snapshot")
    authorization = Authorization(
        user=raw["user"],
        action=raw["action"],
        granted=bool(raw["granted"]),
        source=raw.get("source"),
        expires_at=raw["expires_at"],
    )
    _parse_time(authorization.expires_at)
    return authorization


def _normalize_snapshot(state: Any) -> dict:
    if not isinstance(state, dict):
        raise ValueError("snapshot must be a dict")

    raw_version = state.get("rules_version", state.get("version"))
    if isinstance(raw_version, bool) or not isinstance(raw_version, int):
        raise ValueError("rules_version must be an integer")
    if raw_version < 0:
        raise ValueError("rules_version must be non-negative")

    if "actions" not in state:
        actions = None
    else:
        raw_actions = state["actions"]
        if not isinstance(raw_actions, dict):
            raise ValueError("actions must be a dict")
        actions = {
            str(action): str(description)
            for action, description in raw_actions.items()
        }

    rules_by_version: dict[int, tuple[Rule, ...]] = {}
    raw_versions = state.get("rules_by_version", state.get("rule_versions"))
    if isinstance(raw_versions, dict):
        for raw_version_key, raw_rules in raw_versions.items():
            version_key = int(raw_version_key)
            rules_by_version[version_key] = _rules_from_state(raw_rules)

    current_rules = _rules_from_state(state.get("rules", ()))
    if current_rules:
        rules_by_version[raw_version] = current_rules
    elif raw_version not in rules_by_version:
        raw_version_rules = state.get("version_rules")
        if raw_version_rules is not None:
            rules_by_version[raw_version] = _rules_from_state(
                raw_version_rules
            )
        else:
            rules_by_version[raw_version] = ()

    raw_challenges = state.get("challenge_records")
    if raw_challenges is None:
        raw_challenges = state.get("challenges", [])
    if isinstance(raw_challenges, dict):
        raw_challenges = list(raw_challenges.values())
    if not isinstance(raw_challenges, list):
        raise ValueError("challenges must be a list or dict")

    challenges: dict[str, dict] = {}
    for raw_challenge in raw_challenges:
        if not isinstance(raw_challenge, dict):
            raise ValueError("challenge must be a dict")
        challenge_id = raw_challenge["challenge_id"]
        user = raw_challenge["user"]
        action = raw_challenge["action"]
        expires_at = _parse_time(raw_challenge["expires_at"])
        rule_version = raw_challenge.get("rule_version", raw_version)
        if isinstance(rule_version, bool) or not isinstance(rule_version, int):
            raise ValueError("challenge rule_version must be an integer")
        attempts = raw_challenge.get("attempts", 0)
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 0:
            raise ValueError("challenge attempts must be non-negative")
        status = raw_challenge.get("status", "pending")
        if status not in {"pending", "completed", "expired", "cancelled"}:
            raise ValueError("invalid challenge status")

        authorization = None
        raw_authorization = raw_challenge.get("authorization")
        if raw_authorization is not None:
            authorization = _authorization_from_state(raw_authorization)
        if status == "completed" and authorization is None:
            raise ValueError("completed challenge is missing authorization")

        decision_result = raw_challenge.get("decision_result")
        if decision_result is not None and decision_result not in RESULTS:
            raise ValueError("invalid challenge decision result")
        source = raw_challenge.get("source")
        if source is not None and source not in SOURCES:
            raise ValueError("invalid challenge source")

        record = {
            "challenge_id": challenge_id,
            "user": user,
            "action": action,
            "groups": _normalize_groups(raw_challenge.get("groups", ())),
            "rule_version": rule_version,
            "expires_at": expires_at,
            "attempts": attempts,
            "status": status,
            "authorization": authorization,
            "decision_result": decision_result,
            "source": source,
        }
        if challenge_id in challenges:
            raise ValueError("duplicate challenge id")
        challenges[challenge_id] = record

    raw_grants = state.get("grants", [])
    if isinstance(raw_grants, dict):
        raw_grants = list(raw_grants.values())
    if not isinstance(raw_grants, list):
        raise ValueError("grants must be a list or dict")
    grants: dict[tuple[str, str], Authorization] = {}
    for raw_grant in raw_grants:
        grant = _authorization_from_state(raw_grant)
        grants[(grant.user, grant.action)] = grant

    raw_cooldowns = state.get("cooldowns", [])
    cooldowns: dict[tuple[str, str], datetime] = {}
    if isinstance(raw_cooldowns, dict):
        cooldown_items = raw_cooldowns.items()
        for target, until in cooldown_items:
            if isinstance(target, str) and "\0" in target:
                user, action = target.split("\0", 1)
            elif isinstance(target, tuple) and len(target) == 2:
                user, action = target
            else:
                raise ValueError("invalid cooldown target")
            cooldowns[(user, action)] = _parse_time(until)
    elif isinstance(raw_cooldowns, list):
        for raw_cooldown in raw_cooldowns:
            if not isinstance(raw_cooldown, dict):
                raise ValueError("cooldown must be a dict")
            cooldowns[(raw_cooldown["user"], raw_cooldown["action"])] = (
                _parse_time(raw_cooldown["until"])
            )
    else:
        raise ValueError("cooldowns must be a list or dict")

    raw_counters = state.get("counters", {})
    if not isinstance(raw_counters, dict):
        raise ValueError("counters must be a dict")
    counters = {
        "evaluations": 0,
        "challenges": 0,
        "completed": 0,
        "denied": 0,
        "revoked": 0,
        "cache_hits": 0,
    }
    for key in counters:
        value = raw_counters.get(key, 0)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise ValueError(f"invalid counter: {key}")
        counters[key] = value

    return {
        "actions": actions,
        "rules_version": raw_version,
        "rules_by_version": rules_by_version,
        "rules": rules_by_version.get(raw_version, ()),
        "challenges": challenges,
        "grants": grants,
        "cooldowns": cooldowns,
        "counters": counters,
    }
