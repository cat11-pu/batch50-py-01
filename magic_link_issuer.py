"""Email magic-link issuance, device binding and one-time redemption."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class MagicLinkError(ValueError):
    """Raised when a magic-link operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class LinkTicket:
    token_id: str
    email: str
    purpose: str
    device_fingerprint: str
    issued_at: str
    expires_at: str
    state: str


@dataclass(frozen=True)
class RedeemResult:
    status: str
    token_id: str
    email: str
    purpose: str
    requires_confirmation: bool
    redeemed_at: str | None


class MagicLinkIssuer:
    """Issue and adjudicate one-time email login links."""

    def __init__(self, *, max_active_per_email: int = 5,
                 resend_policy: str = "keep", default_ttl: int = 900,
                 min_issue_interval: int = 0, clock=None) -> None:
        self.max_active_per_email = max_active_per_email
        self.resend_policy = resend_policy
        self.default_ttl = default_ttl
        self.min_issue_interval = min_issue_interval
        self._clock = clock
        self._lock = threading.RLock()

    def issue(self, email: str, *, device_fingerprint: str,
              purpose: str = "login", ttl: int | None = None,
              now: str | None = None) -> LinkTicket:
        raise NotImplementedError

    def redeem(self, token_id: str, *, device_fingerprint: str,
               now: str | None = None) -> RedeemResult:
        raise NotImplementedError

    def confirm(self, token_id: str, *, device_fingerprint: str,
                now: str | None = None) -> RedeemResult:
        raise NotImplementedError

    def invalidate(self, token_id: str, *, now: str | None = None) -> bool:
        raise NotImplementedError

    def invalidate_all(self, email: str, *, now: str | None = None) -> int:
        raise NotImplementedError

    def status(self, token_id: str) -> dict:
        raise NotImplementedError

    def active_links(self, email: str, *, now: str | None = None) -> list[str]:
        raise NotImplementedError

    def purge_expired(self, *, now: str | None = None) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
