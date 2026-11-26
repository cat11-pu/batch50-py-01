"""Polkit style rule evaluation: layered sources, auth challenges, authorization sessions."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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
        self._rules: list[Rule] = []
        self._version = 0
        self._challenges: dict[str, dict] = {}
        self._grants: dict[tuple[str, str], Authorization] = {}
        self._cache: dict[tuple, Decision] = {}
        self._counters = {
            "evaluations": 0, "challenges": 0, "completed": 0,
            "denied": 0, "revoked": 0, "cache_hits": 0,
        }

    def register_action(self, action: str, *, description: str = "") -> None:
        raise NotImplementedError

    def load_rules(self, rules, *, now: str) -> int:
        raise NotImplementedError

    def evaluate(self, user: str, action: str, *, groups=(), now: str) -> Decision:
        raise NotImplementedError

    def challenge(self, user: str, action: str, *, groups=(), now: str) -> Challenge:
        raise NotImplementedError

    def complete(self, challenge_id: str, *, proof_ok: bool, now: str) -> Authorization:
        raise NotImplementedError

    def authorize(self, user: str, action: str, *, groups=(), now: str) -> Authorization:
        raise NotImplementedError

    def revoke(self, user: str, action: str) -> int:
        raise NotImplementedError

    def end_session(self, user: str) -> int:
        raise NotImplementedError

    def active_challenges(self) -> list[Challenge]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
