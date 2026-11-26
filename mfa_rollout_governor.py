"""Staged MFA rollout: stable bucketing, grace gradient and exemption expiry."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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

    def __init__(self, *, base_grace_days: int = 7, clock=None) -> None:
        self.base_grace_days = base_grace_days
        self._clock = clock
        self._lock = threading.RLock()

    def set_stage(self, tenant: str, *, stage: int, percent: int,
                  now: str | None = None) -> RolloutStage:
        raise NotImplementedError

    def bucket_of(self, tenant: str, user_id: str) -> int:
        raise NotImplementedError

    def evaluate(self, tenant: str, user_id: str, *,
                 now: str | None = None) -> MfaDecision:
        raise NotImplementedError

    def grant_grace(self, tenant: str, user_id: str, *, days: int,
                    now: str | None = None) -> dict:
        raise NotImplementedError

    def exempt(self, tenant: str, user_id: str, *, until: str, reason: str,
               now: str | None = None) -> dict:
        raise NotImplementedError

    def revoke_exemption(self, tenant: str, user_id: str) -> bool:
        raise NotImplementedError

    def mark_enrolled(self, tenant: str, user_id: str, *,
                      now: str | None = None) -> dict:
        raise NotImplementedError

    def report(self, tenant: str, *, now: str | None = None) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
