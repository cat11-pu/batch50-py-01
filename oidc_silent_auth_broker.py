"""OIDC silent authentication broker.

Tracks a prompt=none authorization round trip from ``begin`` to ``complete``:
relying-party registration, SSO session probing, pending-request TTL and the
classification of the callback outcome (success / login_required /
interaction_required).
"""

from __future__ import annotations

import copy
import secrets
import threading
from collections.abc import Iterable
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone

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

    _SNAPSHOT_VERSION = 1
    _STATS_KEYS = (
        "clients",
        "sessions",
        "begun",
        "completed",
        "login_required",
        "interaction_required",
        "cancelled",
        "expired",
        "replayed",
    )
    _REQUEST_STATUSES = frozenset(
        {"pending", "completed", "cancelled", "expired"}
    )

    def __init__(self, *, max_pending_per_client: int = 8,
                 max_pending_per_tenant: int = 32,
                 pending_ttl: int = 300) -> None:
        self.max_pending_per_client = max_pending_per_client
        self.max_pending_per_tenant = max_pending_per_tenant
        self.pending_ttl = pending_ttl
        self._lock = threading.RLock()
        self._clients: dict[str, ClientRegistration] = {}
        self._sessions: dict[str, SessionRecord] = {}
        self._requests: dict[str, PendingRequest] = {}
        self._stats = {key: 0 for key in self._STATS_KEYS}

    @staticmethod
    def _blank(value: object) -> bool:
        return not isinstance(value, str) or not value.strip()

    @staticmethod
    def _parse_iso(value: object) -> datetime:
        if not isinstance(value, str) or not value.strip():
            raise ValueError("timestamp must be a non-empty ISO8601 string")
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = f"{text[:-1]}+00:00"
        parsed = datetime.fromisoformat(text)
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @classmethod
    def _canonical_time(cls, value: object) -> str:
        return cls._parse_iso(value).isoformat()

    def _resolve_now(self, now: str | None) -> str:
        if now is None:
            return datetime.now(timezone.utc).isoformat()
        try:
            return self._canonical_time(now)
        except (TypeError, ValueError) as exc:
            raise SilentAuthError(
                "SILENT_AUTH_INVALID_REQUEST",
                f"invalid ISO8601 timestamp: {now!r}",
            ) from exc

    @classmethod
    def _is_live(cls, request: PendingRequest, now: datetime) -> bool:
        return (
            request.status == "pending"
            and cls._parse_iso(request.expires_at) > now
        )

    @staticmethod
    def _with_status(request: PendingRequest, status: str) -> PendingRequest:
        return replace(request, status=status)

    def register_client(self, client_id: str, *, tenant: str,
                        redirect_uris, now: str | None = None) -> ClientRegistration:
        moment = self._resolve_now(now)
        with self._lock:
            if self._blank(client_id):
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST", "client_id is required")
            if self._blank(tenant):
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST", "tenant is required")
            if isinstance(redirect_uris, (str, bytes)) or \
                    not isinstance(redirect_uris, Iterable):
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST",
                    "redirect_uris must be a non-empty collection")

            try:
                raw_uris = list(redirect_uris)
            except TypeError as exc:
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST",
                    "redirect_uris must be a non-empty collection",
                ) from exc

            normalized: set[str] = set()
            for uri in raw_uris:
                if self._blank(uri):
                    raise SilentAuthError(
                        "SILENT_AUTH_INVALID_REQUEST",
                        "redirect_uris must contain non-empty strings")
                normalized.add(uri.strip())
            if not normalized:
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST",
                    "redirect_uris must be a non-empty collection")
            if client_id in self._clients:
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST",
                    f"client {client_id!r} is already registered")

            record = ClientRegistration(
                client_id=client_id,
                tenant=tenant,
                redirect_uris=tuple(sorted(normalized)),
                created_at=moment,
            )
            self._clients[client_id] = record
            return record

    def client_record(self, client_id: str) -> ClientRegistration:
        with self._lock:
            record = self._clients.get(client_id)
            if record is None:
                raise SilentAuthError(
                    "SILENT_AUTH_UNKNOWN_CLIENT",
                    f"unknown client {client_id!r}")
            return record

    def register_session(self, session_id: str, *, user: str, tenant: str,
                         auth_time: str, now: str | None = None) -> SessionRecord:
        self._resolve_now(now)
        try:
            canonical_auth_time = self._canonical_time(auth_time)
        except (TypeError, ValueError) as exc:
            raise SilentAuthError(
                "SILENT_AUTH_INVALID_REQUEST",
                f"invalid auth_time: {auth_time!r}",
            ) from exc

        with self._lock:
            if self._blank(session_id):
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST", "session_id is required")
            if self._blank(user):
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST", "user is required")
            if self._blank(tenant):
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST", "tenant is required")
            if session_id in self._sessions:
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST",
                    f"session {session_id!r} is already registered")

            record = SessionRecord(
                session_id=session_id,
                user=user,
                tenant=tenant,
                auth_time=canonical_auth_time,
                ended=False,
            )
            self._sessions[session_id] = record
            return record

    def end_session(self, session_id: str, *, now: str | None = None) -> bool:
        self._resolve_now(now)
        with self._lock:
            record = self._sessions.get(session_id)
            if record is None or record.ended:
                return False
            self._sessions[session_id] = replace(record, ended=True)
            return True

    def begin(self, client_id: str, *, redirect_uri: str,
              login_hint: str | None = None, max_age: int | None = None,
              session_id: str | None = None,
              now: str | None = None) -> PendingRequest:
        moment = self._resolve_now(now)
        current = self._parse_iso(moment)
        with self._lock:
            client = self._clients.get(client_id)
            if client is None:
                raise SilentAuthError(
                    "SILENT_AUTH_UNKNOWN_CLIENT",
                    f"unknown client {client_id!r}")

            if self._blank(redirect_uri):
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST", "redirect_uri is required")
            if max_age is not None and (
                    isinstance(max_age, bool)
                    or not isinstance(max_age, int)
                    or max_age < 0):
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST",
                    "max_age must be a non-negative integer")
            if login_hint is not None and self._blank(login_hint):
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST",
                    "login_hint must be a non-empty string")
            if session_id is not None and self._blank(session_id):
                raise SilentAuthError(
                    "SILENT_AUTH_INVALID_REQUEST",
                    "session_id must be a non-empty string")

            if redirect_uri not in client.redirect_uris:
                raise SilentAuthError(
                    "SILENT_AUTH_REDIRECT_MISMATCH",
                    f"redirect_uri {redirect_uri!r} is not registered for "
                    f"client {client_id!r}")

            live_pending = [
                request for request in self._requests.values()
                if self._is_live(request, current)
            ]
            client_pending = sum(
                1 for request in live_pending
                if request.client_id == client_id
            )
            tenant_pending = sum(
                1 for request in live_pending
                if request.tenant == client.tenant
            )
            if client_pending >= self.max_pending_per_client:
                raise SilentAuthError(
                    "SILENT_AUTH_CAPACITY_EXCEEDED",
                    f"client {client_id!r} has reached its pending capacity")
            if tenant_pending >= self.max_pending_per_tenant:
                raise SilentAuthError(
                    "SILENT_AUTH_CAPACITY_EXCEEDED",
                    f"tenant {client.tenant!r} has reached its pending capacity")

            state = secrets.token_urlsafe(24)
            while state in self._requests:
                state = secrets.token_urlsafe(24)
            expires_at = (
                current + timedelta(seconds=self.pending_ttl)
            ).isoformat()
            request = PendingRequest(
                state=state,
                client_id=client_id,
                tenant=client.tenant,
                redirect_uri=redirect_uri,
                login_hint=login_hint,
                max_age=max_age,
                session_id=session_id,
                created_at=moment,
                expires_at=expires_at,
                status="pending",
            )
            self._requests[state] = request
            self._stats["begun"] += 1
            return request

    def complete(self, state: str, *, now: str | None = None) -> AuthResult:
        moment = self._resolve_now(now)
        current = self._parse_iso(moment)
        with self._lock:
            request = self._requests.get(state)
            if request is None:
                raise SilentAuthError(
                    "SILENT_AUTH_UNKNOWN_STATE", f"unknown state {state!r}")
            if request.status == "cancelled":
                raise SilentAuthError(
                    "SILENT_AUTH_STATE_CANCELLED",
                    f"state {state!r} was cancelled")
            if request.status == "completed":
                self._stats["replayed"] += 1
                raise SilentAuthError(
                    "SILENT_AUTH_STATE_REPLAYED",
                    f"state {state!r} has already been completed")
            if request.status == "expired":
                raise SilentAuthError(
                    "SILENT_AUTH_STATE_EXPIRED",
                    f"state {state!r} has expired")
            if self._parse_iso(request.expires_at) <= current:
                self._expire_request(request)
                raise SilentAuthError(
                    "SILENT_AUTH_STATE_EXPIRED",
                    f"state {state!r} has expired")

            status, reason, subject, result_session_id = self._classify(
                request, current)
            self._requests[state] = self._with_status(request, "completed")
            self._stats["completed"] += 1
            if status == "login_required":
                self._stats["login_required"] += 1
            elif status == "interaction_required":
                self._stats["interaction_required"] += 1

            return AuthResult(
                state=state,
                client_id=request.client_id,
                status=status,
                subject=subject,
                session_id=result_session_id,
                reason=reason,
                issued_at=moment,
            )

    def _classify(
        self,
        request: PendingRequest,
        now: datetime,
    ) -> tuple[str, str, str | None, str | None]:
        session = (
            self._sessions.get(request.session_id)
            if request.session_id is not None
            else None
        )
        if session is None or session.ended:
            return "login_required", "no_session", None, None
        if session.tenant != request.tenant:
            return "interaction_required", "tenant_mismatch", None, None
        if request.login_hint is not None and request.login_hint != session.user:
            return "login_required", "login_hint_mismatch", None, None
        if request.max_age is not None:
            age = (now - self._parse_iso(session.auth_time)).total_seconds()
            if age > request.max_age:
                return "interaction_required", "max_age_exceeded", None, None
        return "success", "session_reused", session.user, session.session_id

    def _expire_request(self, request: PendingRequest) -> None:
        self._requests[request.state] = self._with_status(request, "expired")
        self._stats["expired"] += 1

    def cancel(self, state: str, *, now: str | None = None) -> bool:
        moment = self._resolve_now(now)
        current = self._parse_iso(moment)
        with self._lock:
            request = self._requests.get(state)
            if request is None or request.status != "pending":
                return False
            if self._parse_iso(request.expires_at) <= current:
                self._expire_request(request)
                return False
            self._requests[state] = self._with_status(request, "cancelled")
            self._stats["cancelled"] += 1
            return True

    def pending_for_session(self, session_id: str) -> list[PendingRequest]:
        with self._lock:
            return sorted(
                (
                    request for request in self._requests.values()
                    if request.session_id == session_id
                    and request.status == "pending"
                ),
                key=lambda request: request.state,
            )

    def state_status(self, state: str) -> str:
        with self._lock:
            request = self._requests.get(state)
            if request is None:
                return "unknown"
            return request.status

    def expire(self, now: str | None = None) -> int:
        moment = self._resolve_now(now)
        current = self._parse_iso(moment)
        swept = 0
        with self._lock:
            for request in list(self._requests.values()):
                if request.status == "pending" and \
                        self._parse_iso(request.expires_at) <= current:
                    self._expire_request(request)
                    swept += 1
            return swept

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": self._SNAPSHOT_VERSION,
                "clients": [
                    asdict(record) for record in self._clients.values()
                ],
                "sessions": [
                    asdict(record) for record in self._sessions.values()
                ],
                "requests": [
                    asdict(request) for request in self._requests.values()
                ],
                "stats": copy.deepcopy(self._stats_view()),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            clients, sessions, requests, stats = self._parse_snapshot(state)
            self._clients = clients
            self._sessions = sessions
            self._requests = requests
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return self._stats_view()

    def _stats_view(self) -> dict:
        result = copy.deepcopy(self._stats)
        result["clients"] = len(self._clients)
        result["sessions"] = len(self._sessions)
        return result

    def _parse_snapshot(
        self,
        snapshot: object,
    ) -> tuple[
        dict[str, ClientRegistration],
        dict[str, SessionRecord],
        dict[str, PendingRequest],
        dict[str, int],
    ]:
        required = {"version", "clients", "sessions", "requests", "stats"}

        def fail(detail: str = "snapshot structure is invalid") -> None:
            raise SilentAuthError("SILENT_AUTH_SNAPSHOT_INVALID", detail)

        if not isinstance(snapshot, dict) or set(snapshot) != required:
            fail()
        version = snapshot["version"]
        if isinstance(version, bool) or not isinstance(version, int) or \
                version != self._SNAPSHOT_VERSION:
            fail("unsupported snapshot version")
        if not isinstance(snapshot["clients"], list) or \
                not isinstance(snapshot["sessions"], list) or \
                not isinstance(snapshot["requests"], list) or \
                not isinstance(snapshot["stats"], dict):
            fail("snapshot collections have invalid types")

        try:
            clients: dict[str, ClientRegistration] = {}
            client_fields = {
                "client_id", "tenant", "redirect_uris", "created_at",
            }
            for row in snapshot["clients"]:
                if not isinstance(row, dict) or set(row) != client_fields:
                    fail("invalid client row")
                client_id = row["client_id"]
                tenant = row["tenant"]
                if self._blank(client_id) or self._blank(tenant):
                    fail("invalid client identity")
                if not isinstance(row["created_at"], str) or \
                        self._blank(row["created_at"]):
                    fail("invalid client created_at")
                created_at = self._canonical_time(row["created_at"])

                uris = row["redirect_uris"]
                if not isinstance(uris, (list, tuple)) or not uris:
                    fail("invalid client redirect_uris")
                normalized_uris: set[str] = set()
                for uri in uris:
                    if self._blank(uri):
                        fail("invalid client redirect_uris")
                    normalized_uris.add(uri.strip())
                if not normalized_uris or client_id in clients:
                    fail("duplicate client")

                clients[client_id] = ClientRegistration(
                    client_id=client_id,
                    tenant=tenant,
                    redirect_uris=tuple(sorted(normalized_uris)),
                    created_at=created_at,
                )

            sessions: dict[str, SessionRecord] = {}
            session_fields = {
                "session_id", "user", "tenant", "auth_time", "ended",
            }
            for row in snapshot["sessions"]:
                if not isinstance(row, dict) or set(row) != session_fields:
                    fail("invalid session row")
                session_id = row["session_id"]
                user = row["user"]
                tenant = row["tenant"]
                if self._blank(session_id) or self._blank(user) or \
                        self._blank(tenant):
                    fail("invalid session identity")
                if not isinstance(row["auth_time"], str) or \
                        self._blank(row["auth_time"]):
                    fail("invalid session auth_time")
                auth_time = self._canonical_time(row["auth_time"])
                if not isinstance(row["ended"], bool) or session_id in sessions:
                    fail("invalid or duplicate session")

                sessions[session_id] = SessionRecord(
                    session_id=session_id,
                    user=user,
                    tenant=tenant,
                    auth_time=auth_time,
                    ended=row["ended"],
                )

            requests: dict[str, PendingRequest] = {}
            request_fields = {
                "state",
                "client_id",
                "tenant",
                "redirect_uri",
                "login_hint",
                "max_age",
                "session_id",
                "created_at",
                "expires_at",
                "status",
            }
            for row in snapshot["requests"]:
                if not isinstance(row, dict) or set(row) != request_fields:
                    fail("invalid request row")
                state = row["state"]
                client_id = row["client_id"]
                tenant = row["tenant"]
                redirect_uri = row["redirect_uri"]
                if not isinstance(state, str) or len(state) < 16 or \
                        state in requests:
                    fail("invalid or duplicate state")
                if self._blank(client_id) or self._blank(tenant) or \
                        self._blank(redirect_uri):
                    fail("invalid request identity")
                if row["status"] not in self._REQUEST_STATUSES:
                    fail("invalid request status")
                if row["login_hint"] is not None and \
                        self._blank(row["login_hint"]):
                    fail("invalid request login_hint")
                if row["session_id"] is not None and \
                        self._blank(row["session_id"]):
                    fail("invalid request session_id")
                if row["max_age"] is not None and (
                        isinstance(row["max_age"], bool)
                        or not isinstance(row["max_age"], int)
                        or row["max_age"] < 0):
                    fail("invalid request max_age")
                if not isinstance(row["created_at"], str) or \
                        not isinstance(row["expires_at"], str):
                    fail("invalid request timestamps")
                created_at = self._canonical_time(row["created_at"])
                expires_at = self._canonical_time(row["expires_at"])

                owner = clients.get(client_id)
                if owner is None or owner.tenant != tenant or \
                        redirect_uri not in owner.redirect_uris:
                    fail("request does not match a registered client")

                requests[state] = PendingRequest(
                    state=state,
                    client_id=client_id,
                    tenant=tenant,
                    redirect_uri=redirect_uri,
                    login_hint=row["login_hint"],
                    max_age=row["max_age"],
                    session_id=row["session_id"],
                    created_at=created_at,
                    expires_at=expires_at,
                    status=row["status"],
                )

            raw_stats = snapshot["stats"]
            if not set(self._STATS_KEYS).issubset(raw_stats):
                fail("snapshot stats are incomplete")
            stats: dict[str, int] = {}
            for key, value in raw_stats.items():
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    fail("invalid snapshot stats")
                stats[key] = value
        except SilentAuthError:
            raise
        except (TypeError, KeyError, ValueError) as exc:
            raise SilentAuthError(
                "SILENT_AUTH_SNAPSHOT_INVALID",
                "snapshot structure is invalid",
            ) from exc

        return clients, sessions, requests, stats
