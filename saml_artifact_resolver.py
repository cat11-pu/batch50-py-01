"""SAML2 artifact resolution.

Turns a SAML artifact received by a service provider into an assertion: the
artifact is bound to the issuing IdP and to one SP entityID, fetched from the
backend over a SOAP style call, checked against the registered InResponseTo and
delivered exactly once.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "SamlArtifactError",
    "SpRegistration",
    "ArtifactTicket",
    "BackendAssertion",
    "Assertion",
    "SamlArtifactResolver",
]


class SamlArtifactError(ValueError):
    """Raised when an artifact operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SpRegistration:
    entity_id: str
    tenant: str
    registered_at: str


@dataclass(frozen=True)
class ArtifactTicket:
    artifact: str
    entity_id: str
    tenant: str
    idp_entity_id: str
    subject: str
    in_response_to: str
    created_at: str
    expires_at: str
    status: str


@dataclass(frozen=True)
class BackendAssertion:
    assertion: str
    in_response_to: str
    signature_valid: bool
    subject: str
    attributes: dict


@dataclass(frozen=True)
class Assertion:
    artifact: str
    entity_id: str
    subject: str
    assertion: str
    in_response_to: str
    attributes: dict
    resolved_at: str


class SamlArtifactResolver:
    """Bind artifacts to SPs and resolve them through a backend fetcher."""

    def __init__(self, *, max_pending_per_tenant: int = 4,
                 artifact_ttl: int = 120) -> None:
        self.max_pending_per_tenant = max_pending_per_tenant
        self.artifact_ttl = artifact_ttl
        self._lock = threading.RLock()

    def register_sp(self, entity_id: str, *, tenant: str,
                    now: str | None = None) -> SpRegistration:
        raise NotImplementedError

    def sp_record(self, entity_id: str) -> SpRegistration:
        raise NotImplementedError

    def set_backend(self, fetcher) -> None:
        raise NotImplementedError

    def issue(self, entity_id: str, *, subject: str, attributes: dict | None = None,
              idp_entity_id: str = "idp-1", ttl: int | None = None,
              now: str | None = None) -> ArtifactTicket:
        raise NotImplementedError

    def resolve(self, artifact: str, entity_id: str, *,
                now: str | None = None) -> Assertion:
        raise NotImplementedError

    def revoke(self, artifact: str) -> bool:
        raise NotImplementedError

    def artifact_state(self, artifact: str) -> str:
        raise NotImplementedError

    def pending_for(self, entity_id: str) -> tuple[str, ...]:
        raise NotImplementedError

    def expire(self, now: str | None = None) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
