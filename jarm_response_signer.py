"""JARM signed authorization response policy.

Wraps an authorization result into a JWT security response: the response is
signed with the client's registered algorithm and active key version, carries
iss / aud / exp / state, and the state is redeemed before the redirect leaves
the authorization server.
"""

from __future__ import annotations

import base64
import binascii
import copy
import hashlib
import hmac
import json
import threading
import time
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import datetime, timezone

__all__ = [
    "JarmError",
    "ClientKeys",
    "SignedResponse",
    "VerifiedResponse",
    "JarmResponseSigner",
]

_SNAPSHOT_VERSION = 1
_SNAPSHOT_KEYS = frozenset({"version", "clients", "states", "stats"})
_RESERVED_CLAIMS = frozenset({"iss", "aud", "iat", "exp", "state"})
_STATE_STATUSES = frozenset({"open", "redeemed", "expired"})
_KNOWN_ALGORITHMS = frozenset(
    {
        "HS256",
        "HS384",
        "HS512",
        "RS256",
        "RS384",
        "RS512",
        "ES256",
        "ES384",
        "ES512",
        "PS256",
        "PS384",
        "PS512",
        "EDDSA",
    }
)
_REQUIRED_STATS = (
    "clients",
    "signed",
    "compensated",
    "verified",
    "redeemed",
    "swept",
)
_DEFAULT_MAX_STATES_PER_CLIENT = 1024


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


def _base64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _base64url_decode(segment: object) -> bytes:
    if not isinstance(segment, str):
        raise JarmError("JARM_RESPONSE_MALFORMED", "segment is not a string")
    try:
        padding = "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode((segment + padding).encode("ascii"))
    except (binascii.Error, ValueError, UnicodeEncodeError) as exc:
        raise JarmError(
            "JARM_RESPONSE_MALFORMED", "invalid base64url segment"
        ) from exc


def _encode_jwt_json(value: object) -> str:
    try:
        raw = json.dumps(
            value,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise JarmError(
            "JARM_INVALID_REQUEST", "JWT claims are not JSON serializable"
        ) from exc
    return _base64url_encode(raw)


class JarmResponseSigner:
    """Sign and verify JARM responses for many clients and key versions."""

    def __init__(
        self,
        *,
        state_ttl: int = 300,
        max_states_per_client: int | None = None,
        **capacity_aliases: object,
    ) -> None:
        limit = max_states_per_client
        for alias in (
            "state_limit_per_client",
            "max_state_per_client",
            "state_capacity_per_client",
            "max_states",
        ):
            if alias in capacity_aliases and limit is None:
                limit = capacity_aliases.pop(alias)  # type: ignore[assignment]
        if capacity_aliases:
            names = ", ".join(sorted(capacity_aliases))
            raise TypeError(f"unexpected keyword argument(s): {names}")
        if limit is None:
            limit = _DEFAULT_MAX_STATES_PER_CLIENT
        if (
            isinstance(state_ttl, bool)
            or not isinstance(state_ttl, int)
            or state_ttl <= 0
        ):
            raise JarmError(
                "JARM_INVALID_REQUEST", "state_ttl must be a positive integer"
            )
        if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
            raise JarmError(
                "JARM_INVALID_REQUEST",
                "max_states_per_client must be a positive integer",
            )

        self.state_ttl = state_ttl
        self.max_states_per_client = limit
        self._lock = threading.RLock()
        self._clients: dict[str, dict] = {}
        self._states: dict[str, dict] = {}
        self._stats = {key: 0 for key in _REQUIRED_STATS}

    @staticmethod
    def _is_blank(value: object) -> bool:
        return not isinstance(value, str) or not value.strip()

    @classmethod
    def _epoch_seconds(
        cls, now: str | int | float | datetime | None
    ) -> int:
        if now is None:
            return int(time.time())
        if isinstance(now, datetime):
            moment = now
        elif isinstance(now, (int, float)) and not isinstance(now, bool):
            return int(now)
        elif isinstance(now, str) and now.strip():
            text = now.strip()
            if text.endswith(("Z", "z")):
                text = text[:-1] + "+00:00"
            try:
                moment = datetime.fromisoformat(text)
            except ValueError as exc:
                raise JarmError(
                    "JARM_INVALID_REQUEST", f"invalid timestamp: {now!r}"
                ) from exc
        else:
            raise JarmError(
                "JARM_INVALID_REQUEST", f"invalid timestamp: {now!r}"
            )

        if moment.tzinfo is None:
            moment = moment.replace(tzinfo=timezone.utc)
        return int(moment.timestamp())

    @staticmethod
    def _normalize_ttl(ttl: object, default: int) -> int:
        value = default if ttl is None else ttl
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise JarmError(
                "JARM_INVALID_REQUEST", "ttl must be a positive integer"
            )
        return value

    @classmethod
    def _normalize_algorithms(cls, algorithms: object) -> list[str]:
        if isinstance(algorithms, (str, bytes)) or not isinstance(
            algorithms, Iterable
        ):
            raise JarmError(
                "JARM_INVALID_REQUEST",
                "algorithms must be a non-empty sequence",
            )
        try:
            raw_algorithms = list(algorithms)
        except TypeError as exc:
            raise JarmError(
                "JARM_INVALID_REQUEST",
                "algorithms must be a non-empty sequence",
            ) from exc

        normalized: list[str] = []
        for algorithm in raw_algorithms:
            if not isinstance(algorithm, str):
                raise JarmError(
                    "JARM_INVALID_REQUEST", "algorithm names must be strings"
                )
            name = algorithm.upper()
            if name not in _KNOWN_ALGORITHMS:
                raise JarmError(
                    "JARM_INVALID_REQUEST",
                    f"unsupported algorithm: {algorithm!r}",
                )
            if name not in normalized:
                normalized.append(name)

        if not normalized:
            raise JarmError(
                "JARM_INVALID_REQUEST", "at least one algorithm is required"
            )
        return normalized

    @staticmethod
    def _client_view(record: dict) -> ClientKeys:
        return ClientKeys(
            client_id=record["client_id"],
            tenant=record["tenant"],
            algorithms=tuple(record["algorithms"]),
            version=record["version"],
            active_kid=record["active_kid"],
            kids=tuple(record["kids"]),
        )

    def _require_client_locked(self, client_id: object) -> dict:
        record = self._clients.get(client_id)  # type: ignore[arg-type]
        if record is None:
            raise JarmError(
                "JARM_UNKNOWN_CLIENT", f"unknown client {client_id!r}"
            )
        return record

    @staticmethod
    def _validate_audience(aud: object) -> None:
        if isinstance(aud, str):
            if JarmResponseSigner._is_blank(aud):
                raise JarmError("JARM_INVALID_REQUEST", "aud is required")
            return
        if isinstance(aud, (list, tuple)) and aud:
            if all(isinstance(item, str) and item.strip() for item in aud):
                return
        raise JarmError("JARM_INVALID_REQUEST", "aud is required")

    @staticmethod
    def _audience_matches(claim: object, expected: object) -> bool:
        if isinstance(expected, (list, tuple, set, frozenset)):
            expected_values = list(expected)
            if isinstance(claim, list):
                return any(value in claim for value in expected_values)
            return claim in expected_values
        if isinstance(claim, list):
            return expected in claim
        return claim == expected

    @staticmethod
    def _derived_key(secret: str, kid: str, alg: str) -> bytes:
        return hmac.new(
            secret.encode("utf-8"),
            f"jarm-response-signing-key/v1/{kid}/{alg}".encode("utf-8"),
            hashlib.sha256,
        ).digest()

    @classmethod
    def _signature_for(
        cls, secret: str, kid: str, alg: str, signing_input: bytes
    ) -> bytes:
        key = cls._derived_key(secret, kid, alg)
        return hmac.new(key, signing_input, hashlib.sha256).digest()

    def _build_token_locked(
        self,
        client: dict,
        *,
        state: str,
        kid: str,
        alg: str,
        iss: str,
        aud: object,
        iat: int,
        ttl: int,
        claims: dict,
    ) -> tuple[str, dict, dict]:
        key_record = client["keys"].get(kid)
        if key_record is None or key_record.get("revoked"):
            raise JarmError("JARM_UNKNOWN_KEY", f"unknown key {kid!r}")

        header = {"alg": alg, "kid": kid, "typ": "JARM"}
        payload: dict = {
            "iss": iss,
            "aud": copy.deepcopy(aud),
            "iat": iat,
            "exp": iat + ttl,
            "state": state,
        }
        payload.update(copy.deepcopy(claims))

        header_segment = _encode_jwt_json(header)
        payload_segment = _encode_jwt_json(payload)
        signing_input = f"{header_segment}.{payload_segment}".encode("ascii")
        signature = self._signature_for(
            key_record["secret"], kid, alg, signing_input
        )
        signature_segment = _base64url_encode(signature)
        token = f"{header_segment}.{payload_segment}.{signature_segment}"
        return token, header, payload

    @staticmethod
    def _parse_compact_token(
        token: object,
    ) -> tuple[dict, dict, bytes, bytes]:
        if not isinstance(token, str):
            raise JarmError("JARM_RESPONSE_MALFORMED", "token must be a string")

        parts = token.split(".")
        if len(parts) != 3:
            raise JarmError(
                "JARM_RESPONSE_MALFORMED", "token must have three segments"
            )

        header_raw = _base64url_decode(parts[0])
        payload_raw = _base64url_decode(parts[1])
        provided_signature = _base64url_decode(parts[2])
        try:
            header = json.loads(header_raw)
            payload = json.loads(payload_raw)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise JarmError(
                "JARM_RESPONSE_MALFORMED", "segment JSON is invalid"
            ) from exc

        if not isinstance(header, dict) or not isinstance(payload, dict):
            raise JarmError(
                "JARM_RESPONSE_MALFORMED",
                "header and payload must be JSON objects",
            )

        try:
            signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        except UnicodeEncodeError as exc:
            raise JarmError(
                "JARM_RESPONSE_MALFORMED", "token contains non-ASCII segments"
            ) from exc
        return header, payload, provided_signature, signing_input

    @staticmethod
    def _validate_verified_payload(payload: dict) -> None:
        for key in _RESERVED_CLAIMS:
            if key not in payload:
                raise JarmError(
                    "JARM_RESPONSE_MALFORMED", f"missing claim {key!r}"
                )
        if JarmResponseSigner._is_blank(payload["iss"]):
            raise JarmError("JARM_RESPONSE_MALFORMED", "invalid iss claim")
        if JarmResponseSigner._is_blank(payload["state"]):
            raise JarmError("JARM_RESPONSE_MALFORMED", "invalid state claim")
        audience = payload["aud"]
        audience_valid = (
            (isinstance(audience, str) and bool(audience.strip()))
            or (
                isinstance(audience, list)
                and bool(audience)
                and all(
                    isinstance(item, str) and item.strip()
                    for item in audience
                )
            )
        )
        if not audience_valid:
            raise JarmError("JARM_RESPONSE_MALFORMED", "invalid aud claim")
        for key in ("iat", "exp"):
            value = payload[key]
            if isinstance(value, bool) or not isinstance(value, int):
                raise JarmError(
                    "JARM_RESPONSE_MALFORMED", f"invalid {key} claim"
                )

    def register_client(
        self,
        client_id: str,
        tenant: str | None = None,
        algorithms: object = None,
        kid: str | None = None,
        secret: str | None = None,
        now: str | int | None = None,
    ) -> ClientKeys:
        created_at = self._epoch_seconds(now)
        normalized_algorithms = self._normalize_algorithms(algorithms)

        with self._lock:
            if (
                self._is_blank(client_id)
                or self._is_blank(tenant)
                or self._is_blank(kid)
                or self._is_blank(secret)
            ):
                raise JarmError(
                    "JARM_INVALID_REQUEST",
                    "client_id, tenant, kid and secret are required",
                )
            if client_id in self._clients:
                raise JarmError(
                    "JARM_INVALID_REQUEST",
                    f"client {client_id!r} is already registered",
                )

            assert tenant is not None
            assert kid is not None
            assert secret is not None
            record = {
                "client_id": client_id,
                "tenant": tenant,
                "algorithms": normalized_algorithms,
                "version": 1,
                "active_kid": kid,
                "kids": [kid],
                "keys": {
                    kid: {
                        "kid": kid,
                        "secret": secret,
                        "version": 1,
                        "revoked": False,
                        "created_at": created_at,
                    }
                },
            }
            self._clients[client_id] = record
            return self._client_view(record)

    def client_keys(self, client_id: str) -> ClientKeys:
        with self._lock:
            return self._client_view(self._require_client_locked(client_id))

    def rotate_client_key(
        self,
        client_id: str,
        kid: str | None = None,
        secret: str | None = None,
        now: str | int | None = None,
    ) -> ClientKeys:
        created_at = self._epoch_seconds(now)
        with self._lock:
            client = self._require_client_locked(client_id)
            if self._is_blank(kid) or self._is_blank(secret):
                raise JarmError(
                    "JARM_INVALID_REQUEST", "kid and secret are required"
                )
            assert kid is not None
            assert secret is not None
            if kid in client["keys"]:
                raise JarmError(
                    "JARM_INVALID_REQUEST", f"kid {kid!r} already exists"
                )

            version = int(client["version"]) + 1
            client["version"] = version
            client["active_kid"] = kid
            client["kids"].append(kid)
            client["keys"][kid] = {
                "kid": kid,
                "secret": secret,
                "version": version,
                "revoked": False,
                "created_at": created_at,
            }
            return self._client_view(client)

    def revoke_key(self, client_id: str, kid: str) -> bool:
        with self._lock:
            client = self._clients.get(client_id)
            if client is None:
                return False
            key = client["keys"].get(kid)
            if key is None or key.get("revoked"):
                return False
            if client["active_kid"] == kid:
                raise JarmError(
                    "JARM_INVALID_REQUEST",
                    "the active signing key cannot be revoked",
                )

            key["revoked"] = True
            try:
                client["kids"].remove(kid)
            except ValueError:
                pass
            return True

    def sign(
        self,
        client_id: str,
        state: str | None = None,
        iss: str | None = None,
        aud: object = None,
        claims: dict | None = None,
        ttl: int | None = None,
        now: str | int | None = None,
    ) -> SignedResponse:
        iat = self._epoch_seconds(now)
        ttl_value = self._normalize_ttl(ttl, self.state_ttl)

        with self._lock:
            client = self._require_client_locked(client_id)
            if self._is_blank(state):
                raise JarmError("JARM_INVALID_REQUEST", "state is required")
            if self._is_blank(iss):
                raise JarmError("JARM_INVALID_REQUEST", "iss is required")
            assert state is not None
            assert iss is not None
            self._validate_audience(aud)
            if claims is not None and not isinstance(claims, dict):
                raise JarmError(
                    "JARM_INVALID_REQUEST", "claims must be a dict or None"
                )
            claim_keys = frozenset(claims or {})
            reserved_overlap = claim_keys & _RESERVED_CLAIMS
            if reserved_overlap:
                raise JarmError(
                    "JARM_INVALID_REQUEST",
                    "claims cannot override registered JWT claims: "
                    + ", ".join(sorted(reserved_overlap)),
                )

            if state in self._states:
                raise JarmError(
                    "JARM_STATE_DUPLICATE",
                    f"state {state!r} is already issued",
                )

            state_count = sum(
                1
                for row in self._states.values()
                if row.get("client_id") == client_id
            )
            if state_count >= self.max_states_per_client:
                raise JarmError(
                    "JARM_CAPACITY_EXCEEDED",
                    {
                        "client_id": client_id,
                        "limit": self.max_states_per_client,
                    },
                )

            kid = client["active_kid"]
            alg = client["algorithms"][0]
            custom_claims = copy.deepcopy(claims or {})
            token, header, payload = self._build_token_locked(
                client,
                state=state,
                kid=kid,
                alg=alg,
                iss=iss,
                aud=aud,
                iat=iat,
                ttl=ttl_value,
                claims=custom_claims,
            )

            self._states[state] = {
                "state": state,
                "client_id": client_id,
                "status": "open",
                "iat": iat,
                "exp": payload["exp"],
                "ttl": ttl_value,
                "kid": kid,
                "alg": alg,
                "iss": iss,
                "aud": copy.deepcopy(aud),
                "claims": custom_claims,
                "redeemed_at": None,
                "expired_at": None,
                "compensated": 0,
            }
            self._stats["signed"] += 1
            return SignedResponse(
                client_id=client_id,
                state=state,
                kid=kid,
                alg=alg,
                token=token,
                header=copy.deepcopy(header),
                payload=copy.deepcopy(payload),
            )

    def compensate(
        self,
        client_id: str,
        state: str | None = None,
        ttl: int | None = None,
        now: str | int | None = None,
    ) -> SignedResponse:
        iat = self._epoch_seconds(now)
        ttl_override = (
            None if ttl is None else self._normalize_ttl(ttl, self.state_ttl)
        )

        with self._lock:
            client = self._require_client_locked(client_id)
            row = self._states.get(state)  # type: ignore[arg-type]
            if row is None or row.get("client_id") != client_id:
                raise JarmError(
                    "JARM_UNKNOWN_STATE", f"unknown state {state!r}"
                )
            if row["status"] == "redeemed":
                raise JarmError(
                    "JARM_STATE_REDEEMED",
                    f"state {state!r} has already been redeemed",
                )
            if row["status"] == "expired":
                raise JarmError(
                    "JARM_STATE_EXPIRED", f"state {state!r} has expired"
                )
            if row["status"] != "open":
                raise JarmError(
                    "JARM_INVALID_REQUEST",
                    f"state {state!r} is not open",
                )
            if iat >= int(row["exp"]):
                row["status"] = "expired"
                row["expired_at"] = iat
                raise JarmError(
                    "JARM_STATE_EXPIRED", f"state {state!r} has expired"
                )

            kid = row["kid"]
            alg = row["alg"]
            key_record = client["keys"].get(kid)
            if key_record is None or key_record.get("revoked"):
                raise JarmError(
                    "JARM_UNKNOWN_KEY",
                    f"signing key {kid!r} is no longer available",
                )
            if alg not in client["algorithms"]:
                raise JarmError(
                    "JARM_INVALID_REQUEST",
                    f"algorithm {alg!r} is not registered for this client",
                )

            ttl_value = (
                ttl_override
                if ttl_override is not None
                else int(row.get("ttl", self.state_ttl))
            )
            token, header, payload = self._build_token_locked(
                client,
                state=row["state"],
                kid=kid,
                alg=alg,
                iss=row["iss"],
                aud=row["aud"],
                iat=iat,
                ttl=ttl_value,
                claims=row.get("claims", {}),
            )

            row["iat"] = iat
            row["exp"] = payload["exp"]
            row["ttl"] = ttl_value
            row["compensated"] = int(row.get("compensated", 0)) + 1
            self._stats["compensated"] += 1
            return SignedResponse(
                client_id=client_id,
                state=row["state"],
                kid=kid,
                alg=alg,
                token=token,
                header=copy.deepcopy(header),
                payload=copy.deepcopy(payload),
            )

    def verify(
        self,
        client_id: str,
        token: str | None = None,
        expected_aud: object = None,
        expected_iss: str | None = None,
        now: str | int | None = None,
    ) -> VerifiedResponse:
        moment = self._epoch_seconds(now)
        with self._lock:
            client = self._require_client_locked(client_id)
            (
                header,
                payload,
                provided_signature,
                signing_input,
            ) = self._parse_compact_token(token)

            kid = header.get("kid")
            if self._is_blank(kid):
                raise JarmError("JARM_UNKNOWN_KEY", "JWT header kid is required")
            assert isinstance(kid, str)
            key_record = client["keys"].get(kid)
            if key_record is None or key_record.get("revoked"):
                raise JarmError("JARM_UNKNOWN_KEY", f"unknown key {kid!r}")

            alg = header.get("alg")
            if not isinstance(alg, str) or alg not in client["algorithms"]:
                raise JarmError(
                    "JARM_INVALID_REQUEST",
                    f"algorithm {alg!r} is not allowed for {client_id!r}",
                )

            expected_signature = self._signature_for(
                key_record["secret"], kid, alg, signing_input
            )
            if not hmac.compare_digest(expected_signature, provided_signature):
                raise JarmError(
                    "JARM_SIGNATURE_INVALID", "JWT signature does not match"
                )

            if (
                set(header) != {"alg", "kid", "typ"}
                or header.get("typ") != "JARM"
            ):
                raise JarmError(
                    "JARM_RESPONSE_MALFORMED", "invalid JARM JWT header"
                )
            self._validate_verified_payload(payload)

            if expected_aud is not None and not self._audience_matches(
                payload["aud"], expected_aud
            ):
                raise JarmError(
                    "JARM_AUDIENCE_MISMATCH",
                    {"expected": expected_aud, "actual": payload["aud"]},
                )
            if expected_iss is not None and payload["iss"] != expected_iss:
                raise JarmError(
                    "JARM_ISSUER_MISMATCH",
                    {"expected": expected_iss, "actual": payload["iss"]},
                )
            if moment >= int(payload["exp"]):
                raise JarmError(
                    "JARM_RESPONSE_EXPIRED", "JARM response has expired"
                )

            self._stats["verified"] += 1
            return VerifiedResponse(
                client_id=client_id,
                state=payload["state"],
                kid=kid,
                alg=alg,
                claims=copy.deepcopy(payload),
            )

    def redeem_state(
        self,
        client_id: str,
        state: str,
        now: str | int | None = None,
    ) -> str:
        redeemed_at = self._epoch_seconds(now)
        with self._lock:
            row = self._states.get(state)
            if row is None or row.get("client_id") != client_id:
                raise JarmError(
                    "JARM_UNKNOWN_STATE", f"unknown state {state!r}"
                )
            if row["status"] == "redeemed":
                raise JarmError(
                    "JARM_STATE_REDEEMED",
                    f"state {state!r} has already been redeemed",
                )
            if row["status"] == "expired":
                raise JarmError(
                    "JARM_STATE_EXPIRED", f"state {state!r} has expired"
                )
            if row["status"] != "open":
                raise JarmError(
                    "JARM_INVALID_REQUEST",
                    f"state {state!r} cannot be redeemed",
                )
            if redeemed_at >= int(row["exp"]):
                row["status"] = "expired"
                row["expired_at"] = redeemed_at
                raise JarmError(
                    "JARM_STATE_EXPIRED", f"state {state!r} has expired"
                )

            row["status"] = "redeemed"
            row["redeemed_at"] = redeemed_at
            self._stats["redeemed"] += 1
            return "redeemed"

    def state_status(self, state: str) -> str:
        with self._lock:
            row = self._states.get(state)
            if row is None:
                return "unknown"
            status = row.get("status")
            return status if status in _STATE_STATUSES else "unknown"

    def sweep_expired(self, now: str | int | None = None) -> int:
        moment = self._epoch_seconds(now)
        swept = 0
        with self._lock:
            for row in self._states.values():
                if row.get("status") != "open":
                    continue
                if moment < int(row["exp"]):
                    continue
                row["status"] = "expired"
                row["expired_at"] = moment
                swept += 1
            self._stats["swept"] += swept
            return swept

    def snapshot(self) -> dict:
        with self._lock:
            stats = copy.deepcopy(self._stats)
            stats["clients"] = len(self._clients)
            snapshot = {
                "version": _SNAPSHOT_VERSION,
                "clients": list(copy.deepcopy(self._clients).values()),
                "states": list(copy.deepcopy(self._states).values()),
                "stats": stats,
            }
            return copy.deepcopy(snapshot)

    def restore(self, state: dict) -> None:
        clients, states, stats = self._parse_snapshot(state)
        with self._lock:
            self._clients = clients
            self._states = states
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            result = copy.deepcopy(self._stats)
            result["clients"] = len(self._clients)
            for key in _REQUIRED_STATS:
                result.setdefault(key, 0)
            return result

    @classmethod
    def _parse_snapshot(
        cls, snapshot: object
    ) -> tuple[dict[str, dict], dict[str, dict], dict[str, int]]:
        def invalid(
            detail: object = "snapshot structure is invalid",
        ) -> JarmError:
            return JarmError("JARM_SNAPSHOT_INVALID", detail)

        try:
            if not isinstance(snapshot, dict):
                raise invalid()
            if set(snapshot) != _SNAPSHOT_KEYS:
                raise invalid("snapshot must contain exactly four keys")

            data = copy.deepcopy(snapshot)
            version = data["version"]
            if (
                isinstance(version, bool)
                or not isinstance(version, int)
                or version != _SNAPSHOT_VERSION
            ):
                raise invalid("unsupported snapshot version")

            raw_clients = data["clients"]
            raw_states = data["states"]
            raw_stats = data["stats"]
            if not isinstance(raw_clients, list):
                raise invalid("clients must be a list")
            if not isinstance(raw_states, list):
                raise invalid("states must be a list")
            if not isinstance(raw_stats, dict):
                raise invalid("stats must be an object")

            clients: dict[str, dict] = {}
            for client_row in raw_clients:
                if not isinstance(client_row, dict):
                    raise invalid("client rows must be objects")
                client_id = client_row.get("client_id")
                tenant = client_row.get("tenant")
                active_kid = client_row.get("active_kid")
                if (
                    cls._is_blank(client_id)
                    or cls._is_blank(tenant)
                    or cls._is_blank(active_kid)
                ):
                    raise invalid("client identity is invalid")
                assert isinstance(client_id, str)
                assert isinstance(tenant, str)
                assert isinstance(active_kid, str)
                if client_id in clients:
                    raise invalid(f"duplicate client {client_id!r}")

                version_value = client_row.get("version")
                if (
                    isinstance(version_value, bool)
                    or not isinstance(version_value, int)
                    or version_value < 1
                ):
                    raise invalid("client version is invalid")

                algorithms = cls._normalize_algorithms(
                    client_row.get("algorithms")
                )
                raw_kids = client_row.get("kids")
                raw_keys = client_row.get("keys")
                if not isinstance(raw_kids, list) or not all(
                    isinstance(kid, str) and kid.strip() for kid in raw_kids
                ):
                    raise invalid("client kids are invalid")
                if not isinstance(raw_keys, dict):
                    raise invalid("client keys are invalid")

                keys: dict[str, dict] = {}
                for kid, key_row in raw_keys.items():
                    if not isinstance(kid, str) or not kid.strip():
                        raise invalid("key id is invalid")
                    if not isinstance(key_row, dict):
                        raise invalid("key row is invalid")
                    secret = key_row.get("secret")
                    key_version = key_row.get("version", 1)
                    revoked = key_row.get("revoked", False)
                    if cls._is_blank(secret):
                        raise invalid("key secret is invalid")
                    if (
                        isinstance(key_version, bool)
                        or not isinstance(key_version, int)
                        or key_version < 1
                    ):
                        raise invalid("key version is invalid")
                    if not isinstance(revoked, bool):
                        raise invalid("key revoked flag is invalid")
                    keys[kid] = {
                        "kid": kid,
                        "secret": secret,
                        "version": key_version,
                        "revoked": revoked,
                        "created_at": key_row.get("created_at"),
                    }

                if active_kid not in keys or keys[active_kid]["revoked"]:
                    raise invalid("active kid is invalid")
                expected_kids = [
                    kid
                    for kid, key_row in keys.items()
                    if not key_row["revoked"]
                ]
                if raw_kids != expected_kids or active_kid not in raw_kids:
                    raise invalid("client kids order is invalid")

                clients[client_id] = {
                    "client_id": client_id,
                    "tenant": tenant,
                    "algorithms": algorithms,
                    "version": version_value,
                    "active_kid": active_kid,
                    "kids": list(raw_kids),
                    "keys": keys,
                }

            states: dict[str, dict] = {}
            for state_row in raw_states:
                if not isinstance(state_row, dict):
                    raise invalid("state rows must be objects")
                state = state_row.get("state")
                client_id = state_row.get("client_id")
                if cls._is_blank(state) or cls._is_blank(client_id):
                    raise invalid("state identity is invalid")
                assert isinstance(state, str)
                assert isinstance(client_id, str)
                if state in states:
                    raise invalid(f"duplicate state {state!r}")
                client = clients.get(client_id)
                if client is None:
                    raise invalid("state references an unknown client")

                status = state_row.get("status")
                if status not in _STATE_STATUSES:
                    raise invalid("state status is invalid")

                iat = state_row.get("iat")
                exp = state_row.get("exp")
                ttl = state_row.get("ttl")
                if (
                    isinstance(iat, bool)
                    or not isinstance(iat, int)
                    or isinstance(exp, bool)
                    or not isinstance(exp, int)
                    or exp < iat
                ):
                    raise invalid("state time range is invalid")
                if ttl is not None and (
                    isinstance(ttl, bool)
                    or not isinstance(ttl, int)
                    or ttl <= 0
                ):
                    raise invalid("state ttl is invalid")

                kid = state_row.get("kid")
                alg = state_row.get("alg")
                iss = state_row.get("iss")
                if (
                    cls._is_blank(kid)
                    or cls._is_blank(alg)
                    or cls._is_blank(iss)
                ):
                    raise invalid("state signing reference is invalid")
                assert isinstance(kid, str)
                assert isinstance(alg, str)
                assert isinstance(iss, str)
                if kid not in client["keys"]:
                    raise invalid("state signing kid is invalid")
                if alg not in client["algorithms"]:
                    raise invalid("state signing algorithm is invalid")
                if "aud" not in state_row:
                    raise invalid("state audience is missing")
                claims = state_row.get("claims", {})
                if not isinstance(claims, dict):
                    raise invalid("state claims must be an object")
                if frozenset(claims) & _RESERVED_CLAIMS:
                    raise invalid("state claims contain reserved keys")

                compensated = state_row.get("compensated", 0)
                redeemed_at = state_row.get("redeemed_at")
                expired_at = state_row.get("expired_at")
                if (
                    isinstance(compensated, bool)
                    or not isinstance(compensated, int)
                    or compensated < 0
                ):
                    raise invalid("compensation count is invalid")
                for timestamp in (redeemed_at, expired_at):
                    if timestamp is not None and (
                        isinstance(timestamp, bool)
                        or not isinstance(timestamp, int)
                    ):
                        raise invalid("state timestamp is invalid")

                states[state] = {
                    "state": state,
                    "client_id": client_id,
                    "status": status,
                    "iat": iat,
                    "exp": exp,
                    "ttl": ttl if ttl is not None else max(1, exp - iat),
                    "kid": kid,
                    "alg": alg,
                    "iss": iss,
                    "aud": copy.deepcopy(state_row["aud"]),
                    "claims": copy.deepcopy(claims),
                    "redeemed_at": redeemed_at,
                    "expired_at": expired_at,
                    "compensated": compensated,
                }

            stats = {key: 0 for key in _REQUIRED_STATS}
            for key, value in raw_stats.items():
                if not isinstance(key, str):
                    raise invalid("stats keys must be strings")
                if (
                    isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0
                ):
                    raise invalid(
                        f"stat {key!r} must be a non-negative integer"
                    )
                stats[key] = value

            return clients, states, stats
        except JarmError as exc:
            if exc.code == "JARM_SNAPSHOT_INVALID":
                raise
            raise JarmError("JARM_SNAPSHOT_INVALID", exc.detail) from exc
        except Exception as exc:
            raise JarmError(
                "JARM_SNAPSHOT_INVALID", "snapshot structure is invalid"
            ) from exc
