"""SAML2 artifact resolution.

Turns a SAML artifact received by a service provider into an assertion: the
artifact is bound to the issuing IdP and to one SP entityID, fetched from the
backend over a SOAP style call, checked against the registered InResponseTo and
delivered exactly once.
"""

from __future__ import annotations

import copy
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

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


@dataclass
class _ArtifactRecord:
    ticket: ArtifactTicket
    status: str
    attributes: dict | None = None
    result: Assertion | None = None
    backend_attempted: bool = False
    in_flight: bool = False
    fetch_seq: int = 0
    last_error_seq: int = 0
    last_error_code: str | None = None
    last_error_detail: object = None
    failure_seq: int = 0
    failure_error: SamlArtifactError | None = None


_SNAPSHOT_VERSION = 1
_SNAPSHOT_KEYS = frozenset({"version", "sps", "artifacts", "stats"})
_STAT_KEYS = (
    "issued",
    "resolved",
    "rejected",
    "expired",
    "revoked",
    "timeouts",
    "backend_calls",
)
_STATUSES = frozenset(
    {"pending", "resolved", "rejected", "expired", "revoked"}
)


class SamlArtifactResolver:
    """Bind artifacts to SPs and resolve them through a backend fetcher."""

    def __init__(self, *, max_pending_per_tenant: int = 4,
                 artifact_ttl: int = 120) -> None:
        if (isinstance(max_pending_per_tenant, bool)
                or not isinstance(max_pending_per_tenant, int)
                or max_pending_per_tenant < 0):
            raise SamlArtifactError(
                "SAML_INVALID_REQUEST",
                "max_pending_per_tenant must be a non-negative integer",
            )
        if (isinstance(artifact_ttl, bool)
                or not isinstance(artifact_ttl, (int, float))
                or artifact_ttl < 0):
            raise SamlArtifactError(
                "SAML_INVALID_REQUEST",
                "artifact_ttl must be a non-negative number",
            )
        self.max_pending_per_tenant = max_pending_per_tenant
        self.artifact_ttl = artifact_ttl
        self._lock = threading.RLock()
        self._cond = threading.Condition(self._lock)
        self._sps: dict[str, SpRegistration] = {}
        self._artifacts: dict[str, _ArtifactRecord] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}
        self._used_in_response_to: set[str] = set()
        self._backend = None

    def register_sp(self, entity_id: str, *, tenant: str,
                    now: str | None = None) -> SpRegistration:
        entity_id = self._require_text(entity_id, "entity_id")
        tenant = self._require_text(tenant, "tenant")
        now_text = self._time_text(now)
        self._parse_time(now_text, "now")
        with self._cond:
            if entity_id in self._sps:
                raise SamlArtifactError(
                    "SAML_INVALID_REQUEST",
                    f"SP already registered: {entity_id}",
                )
            record = SpRegistration(entity_id, tenant, now_text)
            self._sps[entity_id] = record
            return record

    def sp_record(self, entity_id: str) -> SpRegistration:
        entity_id = self._require_text(entity_id, "entity_id")
        with self._lock:
            record = self._sps.get(entity_id)
            if record is None:
                raise SamlArtifactError(
                    "SAML_UNKNOWN_SP", entity_id
                )
            return record

    def set_backend(self, fetcher) -> None:
        if fetcher is not None and not callable(fetcher):
            raise SamlArtifactError(
                "SAML_INVALID_REQUEST", "fetcher must be callable"
            )
        with self._cond:
            self._backend = fetcher

    def issue(self, entity_id: str, *, subject: str, attributes: dict | None = None,
              idp_entity_id: str = "idp-1", ttl: int | None = None,
              now: str | None = None) -> ArtifactTicket:
        entity_id = self._require_text(entity_id, "entity_id")
        subject = self._require_text(subject, "subject")
        idp_entity_id = self._require_text(idp_entity_id, "idp_entity_id")
        now_text = self._time_text(now)
        now_dt = self._parse_time(now_text, "now")
        if attributes is not None and not isinstance(attributes, dict):
            raise SamlArtifactError(
                "SAML_INVALID_REQUEST", "attributes must be a dict or None"
            )
        if ttl is None:
            ttl_value = self.artifact_ttl
        else:
            if (isinstance(ttl, bool)
                    or not isinstance(ttl, (int, float))
                    or ttl < 0):
                raise SamlArtifactError(
                    "SAML_INVALID_REQUEST",
                    "ttl must be a non-negative number",
                )
            ttl_value = ttl
        stored_attributes = copy.deepcopy(attributes)

        with self._cond:
            sp = self._sps.get(entity_id)
            if sp is None:
                raise SamlArtifactError("SAML_UNKNOWN_SP", entity_id)

            # An artifact that is already past its deadline must not keep
            # occupying a tenant's hard capacity slot.
            self._expire_due_locked(
                now_dt, tenant=sp.tenant, include_retryable=False
            )
            if (self._pending_count_locked(sp.tenant)
                    >= self.max_pending_per_tenant):
                raise SamlArtifactError(
                    "SAML_CAPACITY_EXCEEDED",
                    {
                        "tenant": sp.tenant,
                        "limit": self.max_pending_per_tenant,
                    },
                )

            artifact = self._new_artifact_locked()
            in_response_to = self._new_in_response_to_locked()
            expires_at = self._format_time(
                now_dt + timedelta(seconds=ttl_value)
            )
            ticket = ArtifactTicket(
                artifact=artifact,
                entity_id=entity_id,
                tenant=sp.tenant,
                idp_entity_id=idp_entity_id,
                subject=subject,
                in_response_to=in_response_to,
                created_at=now_text,
                expires_at=expires_at,
                status="pending",
            )
            self._artifacts[artifact] = _ArtifactRecord(
                ticket=ticket,
                status="pending",
                attributes=stored_attributes,
            )
            self._stats["issued"] += 1
            return ticket

    def resolve(self, artifact: str, entity_id: str, *,
                now: str | None = None) -> Assertion:
        entity_id = self._require_text(entity_id, "entity_id")
        now_text = self._time_text(now)
        now_dt = self._parse_time(now_text, "now")

        with self._cond:
            sp = self._sps.get(entity_id)
            if sp is None:
                raise SamlArtifactError("SAML_UNKNOWN_SP", entity_id)
            record = self._artifacts.get(artifact)
            if record is None:
                raise SamlArtifactError("SAML_UNKNOWN_ARTIFACT", artifact)
            if record.ticket.entity_id != entity_id:
                raise SamlArtifactError(
                    "SAML_ARTIFACT_ENTITY_MISMATCH",
                    {
                        "expected": record.ticket.entity_id,
                        "actual": entity_id,
                    },
                )

            if (record.status == "pending"
                    and not record.backend_attempted
                    and self._parse_time(record.ticket.expires_at,
                                         "expires_at") <= now_dt):
                self._mark_expired_locked(record)

            if record.status != "pending":
                self._raise_terminal_locked(record)

            if record.in_flight:
                joined_seq = record.fetch_seq
                while True:
                    if record.status == "resolved":
                        return copy.deepcopy(record.result)
                    if record.status != "pending":
                        self._raise_terminal_locked(
                            record, waiter_seq=joined_seq
                        )
                    if (record.last_error_seq == joined_seq
                            and record.last_error_code is not None):
                        raise SamlArtifactError(
                            record.last_error_code,
                            copy.deepcopy(record.last_error_detail),
                        )
                    self._cond.wait()

            fetcher = self._backend
            if fetcher is None:
                record.backend_attempted = True
                raise SamlArtifactError(
                    "SAML_BACKEND_UNAVAILABLE", "no backend configured"
                )

            record.fetch_seq += 1
            fetch_seq = record.fetch_seq
            record.in_flight = True
            record.backend_attempted = True
            self._stats["backend_calls"] += 1

        try:
            fetched = fetcher(artifact, entity_id)
        except TimeoutError as exc:
            self._finish_timeout(record, fetch_seq, exc)
        except Exception as exc:  # noqa: BLE001 - backend boundary
            self._finish_backend_error(record, fetch_seq, exc)

        return self._finish_backend_result(
            record, fetch_seq, fetched, now_text
        )

    def revoke(self, artifact: str) -> bool:
        with self._cond:
            record = self._artifacts.get(artifact)
            if record is None:
                raise SamlArtifactError(
                    "SAML_UNKNOWN_ARTIFACT", artifact
                )
            if record.status != "pending":
                return False
            record.status = "revoked"
            self._stats["revoked"] += 1
            self._cond.notify_all()
            return True

    def artifact_state(self, artifact: str) -> str:
        with self._lock:
            record = self._artifacts.get(artifact)
            if record is None:
                raise SamlArtifactError(
                    "SAML_UNKNOWN_ARTIFACT", artifact
                )
            return record.status

    def pending_for(self, entity_id: str) -> tuple[str, ...]:
        entity_id = self._require_text(entity_id, "entity_id")
        with self._lock:
            pending = (
                artifact
                for artifact, record in self._artifacts.items()
                if (record.status == "pending"
                    and record.ticket.entity_id == entity_id)
            )
            return tuple(sorted(pending))

    def expire(self, now: str | None = None) -> int:
        now_text = self._time_text(now)
        now_dt = self._parse_time(now_text, "now")
        with self._cond:
            return self._expire_due_locked(now_dt)

    def snapshot(self) -> dict:
        with self._lock:
            sps = [
                {
                    "entity_id": record.entity_id,
                    "tenant": record.tenant,
                    "registered_at": record.registered_at,
                }
                for record in (
                    self._sps[entity_id]
                    for entity_id in sorted(self._sps)
                )
            ]
            artifacts = []
            for artifact in sorted(self._artifacts):
                record = self._artifacts[artifact]
                result = None
                if record.result is not None:
                    result = {
                        "artifact": record.result.artifact,
                        "entity_id": record.result.entity_id,
                        "subject": record.result.subject,
                        "assertion": record.result.assertion,
                        "in_response_to": record.result.in_response_to,
                        "attributes": copy.deepcopy(
                            record.result.attributes
                        ),
                        "resolved_at": record.result.resolved_at,
                    }
                artifacts.append(
                    {
                        "artifact": record.ticket.artifact,
                        "entity_id": record.ticket.entity_id,
                        "tenant": record.ticket.tenant,
                        "idp_entity_id": record.ticket.idp_entity_id,
                        "subject": record.ticket.subject,
                        "in_response_to": record.ticket.in_response_to,
                        "created_at": record.ticket.created_at,
                        "expires_at": record.ticket.expires_at,
                        "status": record.status,
                        "attributes": copy.deepcopy(record.attributes),
                        "backend_attempted": record.backend_attempted,
                        "result": result,
                    }
                )
            return copy.deepcopy(
                {
                    "version": _SNAPSHOT_VERSION,
                    "sps": sps,
                    "artifacts": artifacts,
                    "stats": dict(self._stats),
                }
            )

    def restore(self, state: dict) -> None:
        def invalid() -> None:
            raise SamlArtifactError(
                "SAML_SNAPSHOT_INVALID", "invalid snapshot structure"
            )

        def snapshot_text(value, name):
            if not isinstance(value, str) or not value.strip():
                invalid()
            return value

        def snapshot_time(value, name):
            value = snapshot_text(value, name)
            try:
                self._parse_time(value, name)
            except SamlArtifactError:
                invalid()
            return value

        if not isinstance(state, dict):
            invalid()
        if not _SNAPSHOT_KEYS.issubset(state):
            invalid()
        version = state["version"]
        if type(version) is not int or version != _SNAPSHOT_VERSION:
            invalid()
        sps_raw = state["sps"]
        artifacts_raw = state["artifacts"]
        stats_raw = state["stats"]
        if not isinstance(sps_raw, list):
            invalid()
        if not isinstance(artifacts_raw, list):
            invalid()
        if not isinstance(stats_raw, dict):
            invalid()

        new_sps: dict[str, SpRegistration] = {}
        for item in sps_raw:
            if not isinstance(item, dict):
                invalid()
            entity_id = snapshot_text(item.get("entity_id"), "entity_id")
            tenant = snapshot_text(item.get("tenant"), "tenant")
            registered_at = snapshot_time(
                item.get("registered_at"), "registered_at"
            )
            if entity_id in new_sps:
                invalid()
            new_sps[entity_id] = SpRegistration(
                entity_id, tenant, registered_at
            )

        new_artifacts: dict[str, _ArtifactRecord] = {}
        used_in_response_to: set[str] = set()
        for item in artifacts_raw:
            if not isinstance(item, dict):
                invalid()
            artifact = snapshot_text(item.get("artifact"), "artifact")
            entity_id = snapshot_text(item.get("entity_id"), "entity_id")
            tenant = snapshot_text(item.get("tenant"), "tenant")
            idp_entity_id = snapshot_text(
                item.get("idp_entity_id"), "idp_entity_id"
            )
            subject = snapshot_text(item.get("subject"), "subject")
            in_response_to = snapshot_text(
                item.get("in_response_to"), "in_response_to"
            )
            created_at = snapshot_time(
                item.get("created_at"), "created_at"
            )
            expires_at = snapshot_time(
                item.get("expires_at"), "expires_at"
            )
            status = item.get("status")
            if status not in _STATUSES:
                invalid()
            sp = new_sps.get(entity_id)
            if sp is None or sp.tenant != tenant:
                invalid()
            if artifact in new_artifacts:
                invalid()
            attributes = copy.deepcopy(item.get("attributes"))
            if attributes is not None and not isinstance(attributes, dict):
                invalid()
            backend_attempted = item.get("backend_attempted", False)
            if not isinstance(backend_attempted, bool):
                invalid()

            result = None
            result_raw = item.get("result")
            if status == "resolved":
                if result_raw is not None:
                    if not isinstance(result_raw, dict):
                        invalid()
                    result_artifact = snapshot_text(
                        result_raw.get("artifact"), "result.artifact"
                    )
                    result_entity_id = snapshot_text(
                        result_raw.get("entity_id"), "result.entity_id"
                    )
                    result_subject = snapshot_text(
                        result_raw.get("subject"), "result.subject"
                    )
                    assertion = snapshot_text(
                        result_raw.get("assertion"), "result.assertion"
                    )
                    result_in_response_to = snapshot_text(
                        result_raw.get("in_response_to"),
                        "result.in_response_to",
                    )
                    resolved_at = snapshot_time(
                        result_raw.get("resolved_at"),
                        "result.resolved_at",
                    )
                    result_attributes = copy.deepcopy(
                        result_raw.get("attributes")
                    )
                    if (result_attributes is not None
                            and not isinstance(result_attributes, dict)):
                        invalid()
                    if (result_artifact != artifact
                            or result_entity_id != entity_id
                            or result_in_response_to != in_response_to):
                        invalid()
                    result = Assertion(
                        artifact=result_artifact,
                        entity_id=result_entity_id,
                        subject=result_subject,
                        assertion=assertion,
                        in_response_to=result_in_response_to,
                        attributes=result_attributes,
                        resolved_at=resolved_at,
                    )
                else:
                    # A consumed ticket stays consumed even if a snapshot
                    # carried only its lifecycle state.
                    result = None
            elif result_raw is not None:
                # A non-resolved artifact must not carry a live result;
                # this also prevents a resolved artifact being revived by
                # changing only its status.
                invalid()

            ticket = ArtifactTicket(
                artifact=artifact,
                entity_id=entity_id,
                tenant=tenant,
                idp_entity_id=idp_entity_id,
                subject=subject,
                in_response_to=in_response_to,
                created_at=created_at,
                expires_at=expires_at,
                status=status,
            )
            new_artifacts[artifact] = _ArtifactRecord(
                ticket=ticket,
                status=status,
                attributes=attributes,
                result=result,
                backend_attempted=backend_attempted,
            )
            used_in_response_to.add(in_response_to)

        new_stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            value = stats_raw.get(key)
            if type(value) is not int or value < 0:
                invalid()
            new_stats[key] = value

        with self._cond:
            self._sps = new_sps
            self._artifacts = new_artifacts
            self._stats = new_stats
            self._used_in_response_to = used_in_response_to
            self._cond.notify_all()

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    @staticmethod
    def _require_text(value, name: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise SamlArtifactError(
                "SAML_INVALID_REQUEST",
                f"{name} must be a non-empty string",
            )
        return value

    @staticmethod
    def _time_text(now: str | None) -> str:
        if now is None:
            return datetime.now(timezone.utc).isoformat()
        return SamlArtifactResolver._require_text(now, "now")

    @staticmethod
    def _parse_time(value: str, name: str = "time") -> datetime:
        if not isinstance(value, str) or not value.strip():
            raise SamlArtifactError(
                "SAML_INVALID_REQUEST",
                f"{name} must be a valid ISO timestamp",
            )
        text = value.strip()
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise SamlArtifactError(
                "SAML_INVALID_REQUEST",
                f"{name} must be a valid ISO timestamp",
            ) from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    @staticmethod
    def _format_time(value: datetime) -> str:
        return value.isoformat()

    def _new_artifact_locked(self) -> str:
        while True:
            artifact = "AA-" + secrets.token_hex(16)
            if artifact not in self._artifacts:
                return artifact

    def _new_in_response_to_locked(self) -> str:
        while True:
            value = secrets.token_hex(16)
            if value not in self._used_in_response_to:
                self._used_in_response_to.add(value)
                return value

    def _pending_count_locked(self, tenant: str) -> int:
        return sum(
            1
            for record in self._artifacts.values()
            if (record.status == "pending"
                and record.ticket.tenant == tenant)
        )

    def _expire_due_locked(self, now_dt: datetime,
                           tenant: str | None = None, *,
                           include_retryable: bool = True) -> int:
        expired = 0
        for record in list(self._artifacts.values()):
            if tenant is not None and record.ticket.tenant != tenant:
                continue
            if record.status != "pending":
                continue
            if record.backend_attempted and not include_retryable:
                continue
            if self._parse_time(
                    record.ticket.expires_at, "expires_at") <= now_dt:
                record.status = "expired"
                self._stats["expired"] += 1
                expired += 1
        if expired:
            self._cond.notify_all()
        return expired

    def _mark_expired_locked(self, record: _ArtifactRecord) -> None:
        if record.status == "pending":
            record.status = "expired"
            self._stats["expired"] += 1
            self._cond.notify_all()

    def _raise_terminal_locked(
        self, record: _ArtifactRecord, *,
        waiter_seq: int | None = None,
    ) -> None:
        if record.status == "resolved":
            raise SamlArtifactError(
                "SAML_ARTIFACT_CONSUMED", record.ticket.artifact
            )
        if record.status == "rejected":
            if (waiter_seq is not None
                    and record.failure_seq == waiter_seq
                    and record.failure_error is not None):
                raise SamlArtifactError(
                    record.failure_error.code,
                    copy.deepcopy(record.failure_error.detail),
                )
            raise SamlArtifactError(
                "SAML_ARTIFACT_REJECTED", record.ticket.artifact
            )
        if record.status == "revoked":
            raise SamlArtifactError(
                "SAML_ARTIFACT_REVOKED", record.ticket.artifact
            )
        if record.status == "expired":
            raise SamlArtifactError(
                "SAML_ARTIFACT_EXPIRED", record.ticket.artifact
            )
        raise SamlArtifactError(
            "SAML_ARTIFACT_REJECTED", record.ticket.artifact
        )

    def _finish_timeout(self, record: _ArtifactRecord, fetch_seq: int,
                        exc: TimeoutError) -> None:
        with self._cond:
            record.in_flight = False
            self._stats["timeouts"] += 1
            detail = str(exc) or "artifact resolution backend timed out"
            if record.status == "pending":
                record.last_error_seq = fetch_seq
                record.last_error_code = "SAML_BACKEND_TIMEOUT"
                record.last_error_detail = detail
                self._cond.notify_all()
                raise SamlArtifactError(
                    "SAML_BACKEND_TIMEOUT", detail
                ) from exc
            self._cond.notify_all()
            self._raise_terminal_locked(record)

    def _finish_backend_error(self, record: _ArtifactRecord,
                              fetch_seq: int, exc: Exception) -> None:
        with self._cond:
            record.in_flight = False
            detail = str(exc) or "artifact resolution backend unavailable"
            if record.status == "pending":
                record.last_error_seq = fetch_seq
                record.last_error_code = "SAML_BACKEND_UNAVAILABLE"
                record.last_error_detail = detail
                self._cond.notify_all()
                raise SamlArtifactError(
                    "SAML_BACKEND_UNAVAILABLE", detail
                ) from exc
            self._cond.notify_all()
            self._raise_terminal_locked(record)

    def _reject_locked(self, record: _ArtifactRecord, fetch_seq: int,
                       code: str, detail: object) -> None:
        record.status = "rejected"
        record.result = None
        record.failure_seq = fetch_seq
        record.failure_error = SamlArtifactError(code, detail)
        self._stats["rejected"] += 1
        self._cond.notify_all()
        raise record.failure_error

    def _finish_backend_result(self, record: _ArtifactRecord,
                               fetch_seq: int, fetched: object,
                               now_text: str) -> Assertion:
        with self._cond:
            record.in_flight = False
            if record.status != "pending":
                self._cond.notify_all()
                self._raise_terminal_locked(record)

            if not isinstance(fetched, BackendAssertion):
                self._reject_locked(
                    record,
                    fetch_seq,
                    "SAML_ARTIFACT_REJECTED",
                    "backend returned an invalid assertion",
                )

            if fetched.in_response_to != record.ticket.in_response_to:
                self._reject_locked(
                    record,
                    fetch_seq,
                    "SAML_IN_RESPONSE_TO_MISMATCH",
                    {
                        "expected": record.ticket.in_response_to,
                        "actual": fetched.in_response_to,
                    },
                )
            if not fetched.signature_valid:
                self._reject_locked(
                    record,
                    fetch_seq,
                    "SAML_SIGNATURE_INVALID",
                    record.ticket.artifact,
                )

            result = Assertion(
                artifact=record.ticket.artifact,
                entity_id=record.ticket.entity_id,
                subject=fetched.subject,
                assertion=fetched.assertion,
                in_response_to=fetched.in_response_to,
                attributes=copy.deepcopy(fetched.attributes),
                resolved_at=now_text,
            )
            record.status = "resolved"
            record.result = result
            record.failure_error = None
            self._stats["resolved"] += 1
            self._cond.notify_all()
            return copy.deepcopy(result)
