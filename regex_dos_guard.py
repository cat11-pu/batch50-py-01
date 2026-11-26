"""Detection-rule regex safety: complexity scoring, timed benchmarks, quarantine and approval."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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


class RegexDosGuard:
    """Score detection regexes for catastrophic backtracking and gate the rule set."""

    def __init__(self, *, max_rules: int = 200, budget_seconds: float = 0.05,
                 max_samples: int = 8, clock=None, executor=None) -> None:
        self.max_rules = max_rules
        self.budget_seconds = budget_seconds
        self.max_samples = max_samples
        self._clock = clock
        self.executor = executor
        self._lock = threading.RLock()

    def register(self, pattern: str, *, flags: int = 0) -> RuleRecord:
        raise NotImplementedError

    def analyze(self, pattern: str, *, flags: int = 0) -> Analysis:
        raise NotImplementedError

    def benchmark(self, rule_id: str, samples, *, budget_seconds=None) -> dict:
        raise NotImplementedError

    def quarantine(self, rule_id: str, reason: str) -> RuleRecord:
        raise NotImplementedError

    def approve(self, rule_id: str, *, approved_by: str, ttl_seconds: int,
                now=None) -> RuleRecord:
        raise NotImplementedError

    def load_ruleset(self) -> dict:
        raise NotImplementedError

    def effective_rules(self) -> tuple:
        raise NotImplementedError

    def expire_approvals(self, now=None) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
