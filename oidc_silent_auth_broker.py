"""OIDC silent authentication broker.

Tracks a prompt=none authorization round trip from ``begin`` to ``complete``:
relying-party registration, SSO session probing, pending-request TTL and the
classification of the callback outcome (success / login_required /
interaction_required).
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "SilentAuthError",
    "ClientRegistration",
    "SessionRecord",
    "PendingRequest",
    "AuthResult",
    "SilentAuthBroker",
]


class SilentAuthError(ValueError):
    """Raised when a silent authentication operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ClientRegistration:
    client_id: str
    tenant: str
    redirect_uris: tuple[str, ...]
    created_at: str


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    user: str
    tenant: str
    auth_time: str
    ended: bool


@dataclass(frozen=True)
class PendingRequest:
    state: str
    client_id: str
    tenant: str
    redirect_uri: str
    login_hint: str | None
    max_age: int | None
    session_id: str | None
    created_at: str
    expires_at: str
    status: str


@dataclass(frozen=True)
class AuthResult:
    state: str
    client_id: str
    status: str
    subject: str | None
    session_id: str | None
    reason: str
    issued_at: str


class SilentAuthBroker:
    """Coordinate prompt=none authentication requests for many relying parties."""

    def __init__(self, *, max_pending_per_client: int = 8,
                 max_pending_per_tenant: int = 32,
                 pending_ttl: int = 300) -> None:
        self.max_pending_per_client = max_pending_per_client
        self.max_pending_per_tenant = max_pending_per_tenant
        self.pending_ttl = pending_ttl
        self._lock = threading.RLock()

    def register_client(self, client_id: str, *, tenant: str,
                        redirect_uris, now: str | None = None) -> ClientRegistration:
        raise NotImplementedError

    def client_record(self, client_id: str) -> ClientRegistration:
        raise NotImplementedError

    def register_session(self, session_id: str, *, user: str, tenant: str,
                         auth_time: str, now: str | None = None) -> SessionRecord:
        raise NotImplementedError

    def end_session(self, session_id: str, *, now: str | None = None) -> bool:
        raise NotImplementedError

    def begin(self, client_id: str, *, redirect_uri: str,
              login_hint: str | None = None, max_age: int | None = None,
              session_id: str | None = None,
              now: str | None = None) -> PendingRequest:
        raise NotImplementedError

    def complete(self, state: str, *, now: str | None = None) -> AuthResult:
        raise NotImplementedError

    def cancel(self, state: str, *, now: str | None = None) -> bool:
        raise NotImplementedError

    def pending_for_session(self, session_id: str) -> list[PendingRequest]:
        raise NotImplementedError

    def state_status(self, state: str) -> str:
        raise NotImplementedError

    def expire(self, now: str | None = None) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
