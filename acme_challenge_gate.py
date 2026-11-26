"""ACME challenge gate: orders, authorizations, attempts budget and finalize."""

from __future__ import annotations

import base64
import copy
import hashlib
import re
import secrets
import threading
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any

__all__ = [
    "AcmeError",
    "AccountRecord",
    "OrderRecord",
    "AuthorizationRecord",
    "CertificateRecord",
    "ValidationResult",
    "AcmeChallengeGate",
]


class AcmeError(ValueError):
    """Raised when an order, challenge or certificate operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AccountRecord:
    account_id: str
    thumbprint: str
    created_at: str
    rotated_at: str | None


@dataclass(frozen=True)
class OrderRecord:
    order_id: str
    account_id: str
    identifiers: tuple[str, ...]
    status: str
    created_at: str
    expires_at: str
    certificate_serial: str | None


@dataclass(frozen=True)
class AuthorizationRecord:
    authorization_id: str
    order_id: str
    identifier: str
    challenge_type: str
    token: str
    status: str
    attempts: int
    next_at: str | None


@dataclass(frozen=True)
class CertificateRecord:
    serial: str
    order_id: str
    account_id: str
    identifier: str
    issued_at: str
    revoked_at: str | None


@dataclass(frozen=True)
class ValidationResult:
    order_id: str
    identifier: str
    accepted: bool
    status: str
    attempts: int
    next_at: str | None
    detail: str


_SNAPSHOT_KEYS = {
    "version",
    "accounts",
    "orders",
    "authorizations",
    "certificates",
    "counters",
    "stats",
}

_STAT_KEYS = {
    "registered",
    "orders_created",
    "authorized",
    "validated",
    "failed",
    "exhausted",
    "finalized",
    "revoked",
    "rotated",
    "nonce_replays",
}

_COUNTER_KEYS = {
    "order_seq",
    "authorization_seq",
    "used_nonces",
    "claimed_authorizations",
}

_ACCOUNT_FIELDS = {"account_id", "thumbprint", "created_at", "rotated_at"}
_ORDER_FIELDS = {
    "order_id",
    "account_id",
    "identifiers",
    "status",
    "created_at",
    "expires_at",
    "certificate_serial",
}
_AUTHORIZATION_FIELDS = {
    "authorization_id",
    "order_id",
    "identifier",
    "challenge_type",
    "token",
    "status",
    "attempts",
    "next_at",
}
_CERTIFICATE_FIELDS = {
    "serial",
    "order_id",
    "account_id",
    "identifier",
    "issued_at",
    "revoked_at",
}

_ORDER_STATES = {"pending", "ready", "valid", "invalid"}
_AUTHORIZATION_STATES = {"pending", "valid", "invalid"}
_CHALLENGE_TYPES = {"http-01", "dns-01"}
_SERIAL_RE = re.compile(r"^[0-9a-f]{40}$")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _optional_string(value: object) -> bool:
    return value is None or isinstance(value, str)


class AcmeChallengeGate:
    """Accept ACME orders and gate issuance on per-authorization validation."""

    def __init__(self, *, max_orders_per_account: int = 8, max_attempts: int = 3,
                 order_ttl: int = 3600, propagation_delay: float = 30.0,
                 clock=None) -> None:
        self.max_orders_per_account = max_orders_per_account
        self.max_attempts = max_attempts
        self.order_ttl = order_ttl
        self.propagation_delay = propagation_delay
        self._clock = clock
        self._lock = threading.RLock()
        self._state_lock = self._lock
        self._order_locks: dict[str, threading.RLock] = {}
        self._accounts: dict[str, AccountRecord] = {}
        self._orders: dict[str, OrderRecord] = {}
        self._authorizations: dict[str, AuthorizationRecord] = {}
        self._authorization_index: dict[tuple[str, str], str] = {}
        self._certificates: dict[str, CertificateRecord] = {}
        self._used_nonces: set[str] = set()
        self._claimed_authorizations: set[str] = set()
        self._order_seq = 0
        self._authorization_seq = 0
        self._stats = {key: 0 for key in _STAT_KEYS}

    @staticmethod
    def _snapshot_invalid(detail: object) -> AcmeError:
        return AcmeError("ACME_SNAPSHOT_INVALID", detail)

    def _clock_now(self) -> str:
        if self._clock is None:
            return datetime.now(timezone.utc).isoformat()
        value = self._clock()
        if isinstance(value, datetime):
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.isoformat()
        if isinstance(value, str):
            return value
        if isinstance(value, (int, float)) and not isinstance(value, bool):
            return datetime.fromtimestamp(value, timezone.utc).isoformat()
        raise AcmeError("ACME_INVALID_REQUEST", "clock returned an unsupported value")

    def _resolve_now(self, now: str | datetime | None) -> str:
        if now is None:
            return self._clock_now()
        if isinstance(now, datetime):
            if now.tzinfo is None:
                now = now.replace(tzinfo=timezone.utc)
            return now.isoformat()
        if isinstance(now, str):
            return now
        raise AcmeError("ACME_INVALID_REQUEST", "now must be an ISO timestamp")

    @staticmethod
    def _instant(value: str) -> datetime:
        try:
            parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        except (AttributeError, TypeError, ValueError) as exc:
            raise AcmeError("ACME_INVALID_REQUEST", "invalid timestamp") from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    def _add_seconds(self, value: str, seconds: float) -> str:
        return (self._instant(value) + timedelta(seconds=seconds)).isoformat()

    def _order_lock(self, order_id: str) -> threading.RLock:
        with self._state_lock:
            lock = self._order_locks.get(order_id)
            if lock is None:
                lock = threading.RLock()
                self._order_locks[order_id] = lock
            return lock

    def _authorization(self, order_id: str, identifier: str) -> AuthorizationRecord | None:
        authorization_id = self._authorization_index.get((order_id, identifier))
        if authorization_id is None:
            return None
        return self._authorizations.get(authorization_id)

    def _order_authorizations(self, order_id: str) -> list[AuthorizationRecord]:
        return [
            authorization
            for authorization in self._authorizations.values()
            if authorization.order_id == order_id
        ]

    def _next_order_id(self) -> str:
        while True:
            self._order_seq += 1
            order_id = f"order-{self._order_seq:08d}"
            if order_id not in self._orders:
                return order_id

    def _next_authorization_id(self) -> str:
        while True:
            self._authorization_seq += 1
            authorization_id = f"auth-{self._authorization_seq:08d}"
            if authorization_id not in self._authorizations:
                return authorization_id

    @staticmethod
    def _new_token() -> str:
        return secrets.token_urlsafe(32)

    def _new_serial(self) -> str:
        while True:
            serial = secrets.token_hex(20)
            if serial not in self._certificates:
                return serial

    def register_account(self, account_id: str, thumbprint: str,
                         now: str | None = None) -> AccountRecord:
        current = self._resolve_now(now)
        with self._state_lock:
            if account_id in self._accounts:
                raise AcmeError(
                    "ACME_INVALID_REQUEST",
                    f"account already registered: {account_id}",
                )
            account = AccountRecord(
                account_id=account_id,
                thumbprint=thumbprint,
                created_at=current,
                rotated_at=None,
            )
            self._accounts[account_id] = account
            self._stats["registered"] += 1
            return account

    def rotate_account_key(self, account_id: str, thumbprint: str,
                           now: str | None = None) -> AccountRecord:
        current = self._resolve_now(now)
        with self._state_lock:
            account = self._accounts.get(account_id)
            if account is None:
                raise AcmeError("ACME_UNKNOWN_ACCOUNT", account_id)
            rotated = replace(account, thumbprint=thumbprint, rotated_at=current)
            self._accounts[account_id] = rotated

            for order in list(self._orders.values()):
                if order.account_id != account_id or order.status not in {"pending", "ready"}:
                    continue
                if order.status == "ready":
                    self._orders[order.order_id] = replace(order, status="pending")
                for authorization in self._order_authorizations(order.order_id):
                    if authorization.status == "valid":
                        self._authorizations[authorization.authorization_id] = replace(
                            authorization,
                            status="pending",
                            next_at=None,
                        )

            self._stats["rotated"] += 1
            return rotated

    def account_for(self, account_id: str) -> AccountRecord:
        with self._state_lock:
            account = self._accounts.get(account_id)
            if account is None:
                raise AcmeError("ACME_UNKNOWN_ACCOUNT", account_id)
            return account

    def new_order(self, account_id: str, identifiers, now: str | None = None) -> OrderRecord:
        current = self._resolve_now(now)
        with self._state_lock:
            if account_id not in self._accounts:
                raise AcmeError("ACME_UNKNOWN_ACCOUNT", account_id)
            if isinstance(identifiers, (str, bytes)):
                raise AcmeError("ACME_INVALID_REQUEST", "identifiers must be a sequence")
            try:
                requested = list(identifiers)
            except TypeError as exc:
                raise AcmeError("ACME_INVALID_REQUEST", "identifiers must be a sequence") from exc
            if not requested:
                raise AcmeError("ACME_INVALID_REQUEST", "identifiers cannot be empty")
            if any(not isinstance(identifier, str) or not identifier for identifier in requested):
                raise AcmeError("ACME_INVALID_REQUEST", "identifiers must be non-empty strings")
            if len(set(requested)) != len(requested):
                raise AcmeError("ACME_INVALID_REQUEST", "identifiers must be unique")

            account_orders = sum(
                1 for order in self._orders.values() if order.account_id == account_id
            )
            if account_orders >= self.max_orders_per_account:
                raise AcmeError("ACME_CAPACITY_EXCEEDED", account_id)

            order_id = self._next_order_id()
            sorted_identifiers = tuple(sorted(requested))
            order = OrderRecord(
                order_id=order_id,
                account_id=account_id,
                identifiers=sorted_identifiers,
                status="pending",
                created_at=current,
                expires_at=self._add_seconds(current, self.order_ttl),
                certificate_serial=None,
            )
            self._orders[order_id] = order

            for identifier in sorted_identifiers:
                authorization_id = self._next_authorization_id()
                authorization = AuthorizationRecord(
                    authorization_id=authorization_id,
                    order_id=order_id,
                    identifier=identifier,
                    challenge_type="http-01",
                    token=self._new_token(),
                    status="pending",
                    attempts=0,
                    next_at=None,
                )
                self._authorizations[authorization_id] = authorization
                self._authorization_index[(order_id, identifier)] = authorization_id

            self._stats["orders_created"] += 1
            return order

    def authorize(self, order_id: str, identifier: str, challenge_type: str = "http-01",
                  token: str | None = None, now: str | None = None) -> AuthorizationRecord:
        self._resolve_now(now)
        with self._order_lock(order_id):
            with self._state_lock:
                order = self._orders.get(order_id)
                if order is None:
                    raise AcmeError("ACME_UNKNOWN_ORDER", order_id)
                authorization = self._authorization(order_id, identifier)
                if authorization is None:
                    raise AcmeError("ACME_UNKNOWN_AUTHORIZATION", identifier)
                if authorization.authorization_id in self._claimed_authorizations:
                    raise AcmeError("ACME_TOKEN_REUSED", identifier)
                if order.status == "valid":
                    raise AcmeError("ACME_ORDER_IMMUTABLE", order_id)
                if order.status == "invalid":
                    raise AcmeError("ACME_ORDER_INVALID", order_id)
                if challenge_type not in _CHALLENGE_TYPES:
                    raise AcmeError("ACME_INVALID_REQUEST", challenge_type)
                if token is not None:
                    if not isinstance(token, str) or len(token) < 32:
                        raise AcmeError("ACME_INVALID_REQUEST", "token must be at least 32 characters")
                else:
                    token = authorization.token

                updated = replace(
                    authorization,
                    challenge_type=challenge_type,
                    token=token,
                )
                self._authorizations[authorization.authorization_id] = updated
                self._claimed_authorizations.add(authorization.authorization_id)
                self._stats["authorized"] += 1
                return updated

    def _consume_nonce(self, nonce: str) -> None:
        if not isinstance(nonce, str) or not nonce:
            raise AcmeError("ACME_INVALID_REQUEST", "nonce must be a non-empty string")
        with self._state_lock:
            if nonce in self._used_nonces:
                self._stats["nonce_replays"] += 1
                raise AcmeError("ACME_NONCE_REPLAY", nonce)
            self._used_nonces.add(nonce)

    @staticmethod
    def _dns_observations(value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, bytes):
            return [value.decode("utf-8", errors="replace")]
        if isinstance(value, str):
            return [value]
        if isinstance(value, dict):
            observations: list[str] = []
            for item in value.values():
                observations.extend(AcmeChallengeGate._dns_observations(item))
            return observations
        try:
            observations = []
            for item in value:
                if isinstance(item, (bytes, str, dict, list, tuple, set)):
                    observations.extend(AcmeChallengeGate._dns_observations(item))
                else:
                    observations.append(str(item))
            return observations
        except TypeError:
            return [str(value)]

    @staticmethod
    def _dns_expected_values(token: str, thumbprint: str) -> set[str]:
        key_authorization = f"{token}.{thumbprint}"
        digest = base64.urlsafe_b64encode(
            hashlib.sha256(key_authorization.encode("utf-8")).digest()
        ).rstrip(b"=").decode("ascii")
        return {key_authorization, token, digest}

    def _mark_order_invalid(self, order: OrderRecord) -> OrderRecord:
        for authorization in self._order_authorizations(order.order_id):
            if authorization.status != "invalid":
                self._authorizations[authorization.authorization_id] = replace(
                    authorization,
                    status="invalid",
                    next_at=None,
                )
        invalid = replace(order, status="invalid")
        self._orders[order.order_id] = invalid
        return invalid

    def _expire_if_needed(self, order: OrderRecord, current: str) -> None:
        if order.status in {"valid", "invalid"}:
            return
        if self._instant(current) >= self._instant(order.expires_at):
            self._mark_order_invalid(order)
            raise AcmeError("ACME_ORDER_EXPIRED", order.order_id)

    def _validation_success(self, order: OrderRecord, authorization: AuthorizationRecord,
                            current: str, detail: str) -> ValidationResult:
        updated = replace(authorization, status="valid", next_at=None)
        self._authorizations[authorization.authorization_id] = updated

        authorizations = self._order_authorizations(order.order_id)
        if all(item.status == "valid" for item in authorizations):
            self._orders[order.order_id] = replace(order, status="ready")

        self._stats["validated"] += 1
        return ValidationResult(
            order_id=order.order_id,
            identifier=authorization.identifier,
            accepted=True,
            status="valid",
            attempts=updated.attempts,
            next_at=None,
            detail=detail,
        )

    def _validation_failure(self, order: OrderRecord, authorization: AuthorizationRecord,
                            current: str, detail: str) -> ValidationResult:
        attempts = authorization.attempts + 1
        self._stats["failed"] += 1

        if attempts >= self.max_attempts:
            self._authorizations[authorization.authorization_id] = replace(
                authorization,
                status="invalid",
                attempts=attempts,
                next_at=None,
            )
            self._mark_order_invalid(order)
            self._stats["exhausted"] += 1
            raise AcmeError(
                "ACME_ATTEMPTS_EXHAUSTED",
                {
                    "order_id": order.order_id,
                    "identifier": authorization.identifier,
                    "attempts": attempts,
                },
            )

        next_at = self._add_seconds(current, 2 ** attempts)
        updated = replace(
            authorization,
            status="pending",
            attempts=attempts,
            next_at=next_at,
        )
        self._authorizations[authorization.authorization_id] = updated
        return ValidationResult(
            order_id=order.order_id,
            identifier=authorization.identifier,
            accepted=False,
            status="pending",
            attempts=attempts,
            next_at=next_at,
            detail=detail,
        )

    def _dns_validation(self, order: OrderRecord, authorization: AuthorizationRecord,
                        thumbprint: str, value: object, current: str) -> ValidationResult:
        observations = set(self._dns_observations(value))
        expected = self._dns_expected_values(authorization.token, thumbprint)
        if observations & expected:
            return self._validation_success(order, authorization, current, "dns_record_propagated")

        if authorization.next_at is not None and self._instant(current) < self._instant(authorization.next_at):
            return ValidationResult(
                order_id=order.order_id,
                identifier=authorization.identifier,
                accepted=False,
                status="pending",
                attempts=authorization.attempts,
                next_at=authorization.next_at,
                detail="propagation_pending",
            )

        if authorization.next_at is None and self.propagation_delay > 0:
            deadline = self._add_seconds(current, self.propagation_delay)
            updated = replace(authorization, next_at=deadline)
            self._authorizations[authorization.authorization_id] = updated
            return ValidationResult(
                order_id=order.order_id,
                identifier=authorization.identifier,
                accepted=False,
                status="pending",
                attempts=authorization.attempts,
                next_at=deadline,
                detail="propagation_pending",
            )

        return self._validation_failure(order, authorization, current, "dns_mismatch")

    def validate(self, order_id: str, identifier: str, nonce: str, value: str,
                 now: str | None = None) -> ValidationResult:
        self._consume_nonce(nonce)
        current = self._resolve_now(now)
        with self._order_lock(order_id):
            with self._state_lock:
                order = self._orders.get(order_id)
                if order is None:
                    raise AcmeError("ACME_UNKNOWN_ORDER", order_id)
                if order.status == "valid":
                    raise AcmeError("ACME_ORDER_IMMUTABLE", order_id)
                if order.status == "invalid":
                    raise AcmeError("ACME_ORDER_INVALID", order_id)
                self._expire_if_needed(order, current)

                authorization = self._authorization(order_id, identifier)
                if authorization is None:
                    raise AcmeError("ACME_UNKNOWN_AUTHORIZATION", identifier)
                if authorization.status == "valid":
                    return ValidationResult(
                        order_id=order_id,
                        identifier=identifier,
                        accepted=True,
                        status="valid",
                        attempts=authorization.attempts,
                        next_at=None,
                        detail="already_valid",
                    )
                if authorization.status == "invalid":
                    raise AcmeError("ACME_AUTHORIZATION_INVALID", identifier)

                account = self._accounts.get(order.account_id)
                if account is None:
                    raise AcmeError("ACME_UNKNOWN_ACCOUNT", order.account_id)

                if authorization.challenge_type == "http-01":
                    expected = f"{authorization.token}.{account.thumbprint}"
                    if isinstance(value, str) and value == expected:
                        return self._validation_success(
                            order,
                            authorization,
                            current,
                            "http_record_matched",
                        )
                    return self._validation_failure(
                        order,
                        authorization,
                        current,
                        "http_record_mismatch",
                    )
                if authorization.challenge_type == "dns-01":
                    return self._dns_validation(
                        order,
                        authorization,
                        account.thumbprint,
                        value,
                        current,
                    )
                raise AcmeError("ACME_UNSUPPORTED_CHALLENGE", authorization.challenge_type)

    def finalize(self, order_id: str, csr: str, now: str | None = None) -> CertificateRecord:
        current = self._resolve_now(now)
        with self._order_lock(order_id):
            with self._state_lock:
                order = self._orders.get(order_id)
                if order is None:
                    raise AcmeError("ACME_UNKNOWN_ORDER", order_id)
                if order.status == "valid" or order.certificate_serial is not None:
                    raise AcmeError("ACME_ORDER_IMMUTABLE", order_id)
                if order.status == "invalid":
                    raise AcmeError("ACME_ORDER_NOT_READY", order_id)
                self._expire_if_needed(order, current)

                authorizations = self._order_authorizations(order_id)
                if not authorizations or any(item.status != "valid" for item in authorizations):
                    raise AcmeError("ACME_ORDER_NOT_READY", order_id)

                serial = self._new_serial()
                certificate = CertificateRecord(
                    serial=serial,
                    order_id=order_id,
                    account_id=order.account_id,
                    identifier=",".join(order.identifiers),
                    issued_at=current,
                    revoked_at=None,
                )
                self._certificates[serial] = certificate
                self._orders[order_id] = replace(
                    order,
                    status="valid",
                    certificate_serial=serial,
                )
                self._stats["finalized"] += 1
                return certificate

    def revoke(self, serial: str, reason: str | None = None,
               now: str | None = None) -> bool:
        current = self._resolve_now(now)
        with self._state_lock:
            certificate = self._certificates.get(serial)
            if certificate is None:
                raise AcmeError("ACME_UNKNOWN_CERTIFICATE", serial)
            order_id = certificate.order_id

        with self._order_lock(order_id):
            with self._state_lock:
                certificate = self._certificates.get(serial)
                if certificate is None:
                    raise AcmeError("ACME_UNKNOWN_CERTIFICATE", serial)
                if certificate.revoked_at is not None:
                    return False
                self._certificates[serial] = replace(certificate, revoked_at=current)
                order = self._orders.get(order_id)
                if order is not None:
                    self._orders[order_id] = replace(order, status="invalid")
                self._stats["revoked"] += 1
                return True

    def order_status(self, order_id: str) -> OrderRecord:
        with self._state_lock:
            order = self._orders.get(order_id)
            if order is None:
                raise AcmeError("ACME_UNKNOWN_ORDER", order_id)
            return order

    def authorization_for(self, order_id: str, identifier: str) -> AuthorizationRecord:
        with self._state_lock:
            authorization = self._authorization(order_id, identifier)
            if authorization is None:
                raise AcmeError("ACME_UNKNOWN_AUTHORIZATION", identifier)
            return authorization

    def status(self) -> dict:
        with self._state_lock:
            return {
                "accounts": len(self._accounts),
                "orders": len(self._orders),
                "authorizations": len(self._authorizations),
                "certificates": len(self._certificates),
            }

    def snapshot(self) -> dict:
        with self._state_lock:
            state = {
                "version": 1,
                "accounts": {
                    key: asdict(account) for key, account in self._accounts.items()
                },
                "orders": {
                    key: asdict(order) for key, order in self._orders.items()
                },
                "authorizations": {
                    key: asdict(authorization)
                    for key, authorization in self._authorizations.items()
                },
                "certificates": {
                    key: asdict(certificate)
                    for key, certificate in self._certificates.items()
                },
                "counters": {
                    "order_seq": self._order_seq,
                    "authorization_seq": self._authorization_seq,
                    "used_nonces": sorted(self._used_nonces),
                    "claimed_authorizations": sorted(self._claimed_authorizations),
                },
                "stats": dict(self._stats),
            }
            return copy.deepcopy(state)

    @staticmethod
    def _exact_fields(raw: object, fields: set[str], context: str) -> dict:
        if not isinstance(raw, dict) or set(raw) != fields:
            raise AcmeChallengeGate._snapshot_invalid(context)
        return raw

    def _parse_snapshot(self, state: object) -> dict[str, Any]:
        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            raise self._snapshot_invalid("snapshot keys")
        version = state.get("version")
        if not _is_int(version) or version != 1:
            raise self._snapshot_invalid("version")

        account_raw = state.get("accounts")
        order_raw = state.get("orders")
        authorization_raw = state.get("authorizations")
        certificate_raw = state.get("certificates")
        counters = state.get("counters")
        stats = state.get("stats")
        for value in (account_raw, order_raw, authorization_raw, certificate_raw, counters, stats):
            if not isinstance(value, dict):
                raise self._snapshot_invalid("mapping")
        if set(counters) != _COUNTER_KEYS:
            raise self._snapshot_invalid("counters keys")
        if set(stats) != _STAT_KEYS:
            raise self._snapshot_invalid("stats keys")
        if any(not _is_int(value) or value < 0 for value in stats.values()):
            raise self._snapshot_invalid("stats values")

        order_seq = counters.get("order_seq")
        authorization_seq = counters.get("authorization_seq")
        if not _is_int(order_seq) or order_seq < 0:
            raise self._snapshot_invalid("order_seq")
        if not _is_int(authorization_seq) or authorization_seq < 0:
            raise self._snapshot_invalid("authorization_seq")
        used_nonces = counters.get("used_nonces")
        claimed = counters.get("claimed_authorizations")
        if not isinstance(used_nonces, list) or any(
            not isinstance(nonce, str) or not nonce for nonce in used_nonces
        ):
            raise self._snapshot_invalid("used_nonces")
        if len(set(used_nonces)) != len(used_nonces):
            raise self._snapshot_invalid("used_nonces duplicate")
        if not isinstance(claimed, list) or any(
            not isinstance(item, str) for item in claimed
        ):
            raise self._snapshot_invalid("claimed_authorizations")
        if len(set(claimed)) != len(claimed):
            raise self._snapshot_invalid("claimed_authorizations duplicate")

        accounts: dict[str, AccountRecord] = {}
        for key, raw in account_raw.items():
            if not isinstance(key, str):
                raise self._snapshot_invalid("account key")
            record = self._exact_fields(raw, _ACCOUNT_FIELDS, "account fields")
            if (
                not isinstance(record["account_id"], str)
                or record["account_id"] != key
                or not isinstance(record["thumbprint"], str)
                or not isinstance(record["created_at"], str)
                or not _optional_string(record["rotated_at"])
            ):
                raise self._snapshot_invalid("account record")
            accounts[key] = AccountRecord(**record)

        orders: dict[str, OrderRecord] = {}
        for key, raw in order_raw.items():
            if not isinstance(key, str):
                raise self._snapshot_invalid("order key")
            record = self._exact_fields(raw, _ORDER_FIELDS, "order fields")
            identifiers = record["identifiers"]
            if (
                not isinstance(record["order_id"], str)
                or record["order_id"] != key
                or record["account_id"] not in accounts
                or not isinstance(identifiers, (tuple, list))
                or not identifiers
                or any(not isinstance(identifier, str) or not identifier for identifier in identifiers)
                or tuple(sorted(set(identifiers))) != tuple(identifiers)
                or record["status"] not in _ORDER_STATES
                or not isinstance(record["created_at"], str)
                or not isinstance(record["expires_at"], str)
                or not _optional_string(record["certificate_serial"])
            ):
                raise self._snapshot_invalid("order record")
            self._instant(record["created_at"])
            self._instant(record["expires_at"])
            orders[key] = OrderRecord(
                order_id=record["order_id"],
                account_id=record["account_id"],
                identifiers=tuple(identifiers),
                status=record["status"],
                created_at=record["created_at"],
                expires_at=record["expires_at"],
                certificate_serial=record["certificate_serial"],
            )

        authorizations: dict[str, AuthorizationRecord] = {}
        authorization_index: dict[tuple[str, str], str] = {}
        for key, raw in authorization_raw.items():
            if not isinstance(key, str):
                raise self._snapshot_invalid("authorization key")
            record = self._exact_fields(raw, _AUTHORIZATION_FIELDS, "authorization fields")
            order = orders.get(record["order_id"])
            if (
                not isinstance(record["authorization_id"], str)
                or record["authorization_id"] != key
                or order is None
                or not isinstance(record["identifier"], str)
                or record["identifier"] not in order.identifiers
                or record["challenge_type"] not in _CHALLENGE_TYPES
                or not isinstance(record["token"], str)
                or len(record["token"]) < 32
                or record["status"] not in _AUTHORIZATION_STATES
                or not _is_int(record["attempts"])
                or record["attempts"] < 0
                or not _optional_string(record["next_at"])
            ):
                raise self._snapshot_invalid("authorization record")
            pair = (record["order_id"], record["identifier"])
            if pair in authorization_index or key in authorization_index.values():
                raise self._snapshot_invalid("authorization duplicate")
            authorization_index[pair] = key
            authorizations[key] = AuthorizationRecord(**record)

        for order in orders.values():
            matching = [
                authorization
                for authorization in authorizations.values()
                if authorization.order_id == order.order_id
            ]
            if {item.identifier for item in matching} != set(order.identifiers):
                raise self._snapshot_invalid("order authorizations")
            all_valid = bool(matching) and all(item.status == "valid" for item in matching)
            if order.status == "ready" and not all_valid:
                raise self._snapshot_invalid("ready order authorizations")
            if order.status == "valid" and not all_valid:
                raise self._snapshot_invalid("valid order authorizations")
            if order.status == "pending" and all_valid:
                raise self._snapshot_invalid("pending order authorizations")

        certificates: dict[str, CertificateRecord] = {}
        for key, raw in certificate_raw.items():
            if not isinstance(key, str):
                raise self._snapshot_invalid("certificate key")
            record = self._exact_fields(raw, _CERTIFICATE_FIELDS, "certificate fields")
            order = orders.get(record["order_id"])
            if (
                not isinstance(record["serial"], str)
                or record["serial"] != key
                or not _SERIAL_RE.fullmatch(record["serial"])
                or order is None
                or record["account_id"] not in accounts
                or record["account_id"] != order.account_id
                or not isinstance(record["identifier"], str)
                or not isinstance(record["issued_at"], str)
                or not _optional_string(record["revoked_at"])
            ):
                raise self._snapshot_invalid("certificate record")
            self._instant(record["issued_at"])
            certificates[key] = CertificateRecord(**record)

        for order in orders.values():
            if order.certificate_serial is not None:
                certificate = certificates.get(order.certificate_serial)
                if certificate is None or certificate.order_id != order.order_id:
                    raise self._snapshot_invalid("order certificate")
                if order.status == "valid" and certificate.revoked_at is not None:
                    raise self._snapshot_invalid("revoked valid order")
            elif order.status == "valid":
                raise self._snapshot_invalid("valid order serial")

        if set(claimed) - set(authorizations):
            raise self._snapshot_invalid("claimed authorization")

        return {
            "accounts": accounts,
            "orders": orders,
            "authorizations": authorizations,
            "authorization_index": authorization_index,
            "certificates": certificates,
            "used_nonces": set(used_nonces),
            "claimed_authorizations": set(claimed),
            "order_seq": order_seq,
            "authorization_seq": authorization_seq,
            "stats": dict(stats),
        }

    def restore(self, state: dict) -> None:
        try:
            parsed = self._parse_snapshot(state)
        except AcmeError as exc:
            if exc.code == "ACME_SNAPSHOT_INVALID":
                raise
            raise AcmeError("ACME_SNAPSHOT_INVALID", exc.detail) from exc
        except Exception as exc:
            raise AcmeError("ACME_SNAPSHOT_INVALID", str(exc)) from exc
        with self._state_lock:
            self._accounts = parsed["accounts"]
            self._orders = parsed["orders"]
            self._authorizations = parsed["authorizations"]
            self._authorization_index = parsed["authorization_index"]
            self._certificates = parsed["certificates"]
            self._used_nonces = parsed["used_nonces"]
            self._claimed_authorizations = parsed["claimed_authorizations"]
            self._order_seq = parsed["order_seq"]
            self._authorization_seq = parsed["authorization_seq"]
            self._stats = parsed["stats"]
            self._order_locks = {
                order_id: threading.RLock() for order_id in self._orders
            }

    def stats(self) -> dict:
        with self._state_lock:
            return dict(self._stats)
