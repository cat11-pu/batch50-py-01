"""JARM signed authorization response policy.

Wraps an authorization result into a JWT security response: the response is
signed with the client's registered algorithm and active key version, carries
iss / aud / exp / state, and the state is redeemed before the redirect leaves
the authorization server.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "JarmError",
    "ClientKeys",
    "SignedResponse",
    "VerifiedResponse",
    "JarmResponseSigner",
]


class JarmError(ValueError):
    """Raised when a JARM response operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ClientKeys:
    client_id: str
    tenant: str
    algorithms: tuple[str, ...]
    version: int
    active_kid: str
    kids: tuple[str, ...]


@dataclass(frozen=True)
class SignedResponse:
    client_id: str
    state: str
    kid: str
    alg: str
    token: str
    header: dict
    payload: dict


@dataclass(frozen=True)
class VerifiedResponse:
    client_id: str
    state: str
    kid: str
    alg: str
    claims: dict


class JarmResponseSigner:
    """Sign and verify JARM responses for many clients and key versions."""

    def __init__(self, *, state_ttl: int = 300) -> None:
        self.state_ttl = state_ttl
        self._lock = threading.RLock()

    def register_client(self, client_id: str, *, tenant: str, algorithms,
                        kid: str, secret: str,
                        now: str | None = None) -> ClientKeys:
        raise NotImplementedError

    def client_keys(self, client_id: str) -> ClientKeys:
        raise NotImplementedError

    def rotate_client_key(self, client_id: str, *, kid: str, secret: str,
                          now: str | None = None) -> ClientKeys:
        raise NotImplementedError

    def revoke_key(self, client_id: str, kid: str) -> bool:
        raise NotImplementedError

    def sign(self, client_id: str, *, state: str, iss: str, aud: str,
             claims: dict | None = None, ttl: int | None = None,
             now: str | None = None) -> SignedResponse:
        raise NotImplementedError

    def compensate(self, client_id: str, *, state: str, ttl: int | None = None,
                   now: str | None = None) -> SignedResponse:
        raise NotImplementedError

    def verify(self, client_id: str, token: str, *, expected_aud: str | None = None,
               expected_iss: str | None = None,
               now: str | None = None) -> VerifiedResponse:
        raise NotImplementedError

    def redeem_state(self, client_id: str, state: str, *,
                     now: str | None = None) -> str:
        raise NotImplementedError

    def state_status(self, state: str) -> str:
        raise NotImplementedError

    def sweep_expired(self, now: str | None = None) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
