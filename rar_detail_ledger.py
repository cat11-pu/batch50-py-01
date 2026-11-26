"""OAuth rich authorization request ledger.

Keeps the authorization_details set of every grant: typed validation, the
canonical consent-screen summary, the display fingerprint and the narrowing
decision taken when a refresh token asks for a new set.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = ["RarError", "GrantView", "RarDetailLedger"]


class RarError(ValueError):
    """Raised when an authorization_details operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class GrantView:
    grant_id: str
    tenant: str
    client_id: str
    version: int
    details: tuple
    fingerprint: str
    created_at: str
    updated_at: str
    status: str


class RarDetailLedger:
    """Track authorization_details sets, their versions and consent state."""

    def __init__(self, *, max_details_per_grant: int = 4,
                 max_bytes_per_grant: int = 1024,
                 max_grants_per_client: int = 8,
                 grant_ttl: int = 3600) -> None:
        self.max_details_per_grant = max_details_per_grant
        self.max_bytes_per_grant = max_bytes_per_grant
        self.max_grants_per_client = max_grants_per_client
        self.grant_ttl = grant_ttl
        self._lock = threading.RLock()

    def validate(self, details) -> tuple[dict, ...]:
        raise NotImplementedError

    def fingerprint(self, details) -> str:
        raise NotImplementedError

    def display_lines(self, details) -> tuple[str, ...]:
        raise NotImplementedError

    def submit(self, details, *, tenant: str, client_id: str,
               now: str | None = None) -> GrantView:
        raise NotImplementedError

    def merge(self, grant_id: str, details, *,
              now: str | None = None) -> GrantView:
        raise NotImplementedError

    def compare(self, grant_id: str, details) -> str:
        raise NotImplementedError

    def refresh(self, grant_id: str, details, *,
                now: str | None = None) -> GrantView:
        raise NotImplementedError

    def grant_view(self, grant_id: str) -> GrantView:
        raise NotImplementedError

    def revoke(self, grant_id: str) -> bool:
        raise NotImplementedError

    def sweep_expired(self, now: str | None = None) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
