"""Canary token registry: issuance, hit dedup windows, batch revocation cascade."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class CanaryError(ValueError):
    """Raised when a registry operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATE_ACTIVE = "active"
STATE_TRIGGERED = "triggered"
STATE_REVOKED = "revoked"

TOKEN_STATES = (STATE_ACTIVE, STATE_TRIGGERED, STATE_REVOKED)


@dataclass(frozen=True)
class CanaryToken:
    token_id: str
    purpose: str
    placement: str
    batch_id: str
    owner: str
    issued_at: str
    state: str
    hits: int
    last_hit_at: str | None
    revoked_at: str | None
    revoke_reason: str | None
    assets: tuple


class CanaryTokenRegistry:
    """Register decoy tokens, dedupe hit reports and cascade revocations."""

    def __init__(self, *, hit_window_seconds: int = 300) -> None:
        self.hit_window_seconds = hit_window_seconds
        self._lock = threading.RLock()
        self._tokens: dict[str, dict] = {}
        self._assets: dict[str, tuple] = {}
        self._frozen: dict[str, dict] = {}
        self._stats = {
            "issued": 0,
            "hits": 0,
            "deduped": 0,
            "escalated": 0,
            "revoked": 0,
            "frozen": 0,
        }

    def issue(self, token_id: str, *, purpose: str, placement: str,
              batch_id: str, owner: str, now: str) -> CanaryToken:
        raise NotImplementedError

    def bind_asset(self, token_id: str, asset_id: str) -> tuple:
        raise NotImplementedError

    def report_hit(self, token_id: str, *, source: str, now: str) -> dict:
        raise NotImplementedError

    def revoke(self, token_id: str, *, reason: str, now: str) -> dict:
        raise NotImplementedError

    def cascade(self, batch_id: str, *, reason: str, now: str) -> dict:
        raise NotImplementedError

    def status(self, token_id: str) -> dict:
        raise NotImplementedError

    def tokens(self, *, batch_id: str | None = None) -> list:
        raise NotImplementedError

    def frozen_assets(self) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
