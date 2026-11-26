"""OAuth rich authorization request ledger.

Keeps the authorization_details set of every grant: typed validation, the
canonical consent-screen summary, the display fingerprint and the narrowing
decision taken when a refresh token asks for a new set.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

__all__ = ["RarError", "GrantView", "RarDetailLedger"]


_SNAPSHOT_VERSION = 1
_DETAIL_TYPES = ("account_info", "payment", "region")
_STAT_KEYS = (
    "submitted",
    "merged",
    "deduped",
    "refreshed",
    "revoked",
    "expired",
)
_GRANT_KEYS = {
    "grant_id",
    "tenant",
    "client_id",
    "version",
    "details",
    "fingerprint",
    "created_at",
    "updated_at",
    "status",
}
_CURRENCY_RE = re.compile(r"[A-Z]{3}\Z")
_COUNTRY_RE = re.compile(r"[A-Z]{2}\Z")


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


def _request_error(detail: object) -> RarError:
    return RarError("RAR_INVALID_REQUEST", detail)


def _detail_error(field: str) -> RarError:
    return RarError("RAR_INVALID_DETAIL", field)


def _capacity_error(detail: str) -> RarError:
    return RarError("RAR_CAPACITY_EXCEEDED", detail)


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise _request_error("now")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise _request_error("now") from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _resolve_now(now: str | None) -> tuple[str, datetime]:
    if now is None:
        parsed = datetime.now(timezone.utc)
        return parsed.isoformat(), parsed
    return now, _parse_time(now)


def _canonicalize(details: object, *, allow_empty: bool = False) -> tuple[dict, ...]:
    if not isinstance(details, (list, tuple)):
        raise _request_error("details")
    if not details:
        if allow_empty:
            return ()
        raise _detail_error("details")

    actions: set[str] = set()
    countries: set[str] = set()
    payments: set[tuple[str, str, int]] = set()
    has_region = False

    for item in details:
        if not isinstance(item, dict):
            raise _detail_error("details")

        detail_type = item.get("type")
        if detail_type not in _DETAIL_TYPES:
            raise _detail_error("type")

        if detail_type == "payment":
            amount = item.get("amount_max")
            if (
                not isinstance(amount, int)
                or isinstance(amount, bool)
                or amount <= 0
            ):
                raise _detail_error("amount_max")

            currency = item.get("currency")
            if not isinstance(currency, str) or not _CURRENCY_RE.fullmatch(currency):
                raise _detail_error("currency")

            payee = item.get("payee")
            if not isinstance(payee, str) or not payee.strip():
                raise _detail_error("payee")

            payments.add((currency, payee, amount))

        elif detail_type == "account_info":
            raw_actions = item.get("actions")
            if not isinstance(raw_actions, (list, tuple, set, frozenset)) or not raw_actions:
                raise _detail_error("actions")

            normalized_actions: set[str] = set()
            for action in raw_actions:
                if action not in ("read", "write"):
                    raise _detail_error("actions")
                normalized_actions.add(action)
            actions.update(normalized_actions)

        else:
            has_region = True
            raw_countries = item.get("countries")
            if not isinstance(raw_countries, (list, tuple, set, frozenset)):
                raise _detail_error("countries")

            normalized_countries: set[str] = set()
            for country in raw_countries:
                if not isinstance(country, str) or not _COUNTRY_RE.fullmatch(country):
                    raise _detail_error("countries")
                normalized_countries.add(country)
            countries.update(normalized_countries)

    canonical: list[dict] = []
    if actions:
        canonical.append({"type": "account_info", "actions": sorted(actions)})

    for currency, payee, amount in sorted(payments):
        canonical.append(
            {
                "type": "payment",
                "amount_max": amount,
                "currency": currency,
                "payee": payee,
            }
        )

    if has_region:
        canonical.append({"type": "region", "countries": sorted(countries)})

    return tuple(sorted(canonical, key=lambda item: item["type"]))


def _canonical_bytes(details: tuple[dict, ...]) -> bytes:
    return json.dumps(
        details,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _fingerprint(details: tuple[dict, ...]) -> str:
    digest = hashlib.sha256(_canonical_bytes(details)).hexdigest()
    return f"sha256:{digest}"


def _display_lines(details: tuple[dict, ...]) -> tuple[str, ...]:
    lines: list[str] = []
    for detail in details:
        detail_type = detail["type"]
        if detail_type == "account_info":
            lines.append(f"account_info: {', '.join(detail['actions'])}")
        elif detail_type == "payment":
            whole, fraction = divmod(detail["amount_max"], 100)
            lines.append(
                "payment: "
                f"{whole}.{fraction:02d} {detail['currency']} -> {detail['payee']}"
            )
        else:
            lines.append(f"region: {', '.join(detail['countries'])}")
    return tuple(lines)


def _index_details(details: tuple[dict, ...]) -> tuple[set[str], set[str], dict]:
    actions: set[str] = set()
    countries: set[str] = set()
    payments: dict[tuple[str, str], int] = {}
    for detail in details:
        if detail["type"] == "account_info":
            actions.update(detail["actions"])
        elif detail["type"] == "region":
            countries.update(detail["countries"])
        else:
            payments[(detail["currency"], detail["payee"])] = detail["amount_max"]
    return actions, countries, payments


def _compare_details(old: tuple[dict, ...], new: tuple[dict, ...]) -> str:
    if old == new:
        return "same"

    old_actions, old_countries, old_payments = _index_details(old)
    new_actions, new_countries, new_payments = _index_details(new)

    expands = bool(new_actions - old_actions) or bool(new_countries - old_countries)
    narrows = bool(old_actions - new_actions) or bool(old_countries - new_countries)
    different = False

    for payment_key, new_amount in new_payments.items():
        old_amount = old_payments.get(payment_key)
        if old_amount is None:
            different = True
        elif new_amount > old_amount:
            expands = True
        elif new_amount < old_amount:
            narrows = True

    for payment_key in old_payments:
        if payment_key not in new_payments:
            narrows = True

    if different or (expands and narrows):
        return "different"
    if expands:
        return "expanded"
    if narrows:
        return "narrower"
    return "different"


class RarDetailLedger:
    """Track authorization_details sets, their versions and consent state."""

    def __init__(
        self,
        *,
        max_details_per_grant: int = 4,
        max_bytes_per_grant: int = 1024,
        max_grants_per_client: int = 8,
        grant_ttl: int = 3600,
    ) -> None:
        self.max_details_per_grant = max_details_per_grant
        self.max_bytes_per_grant = max_bytes_per_grant
        self.max_grants_per_client = max_grants_per_client
        self.grant_ttl = grant_ttl
        self._lock = threading.RLock()
        self._grants: dict[str, dict] = {}
        self._stats: dict[str, int] = {key: 0 for key in _STAT_KEYS}

    @staticmethod
    def _validate_identity(tenant: object, client_id: object) -> None:
        if not isinstance(tenant, str) or not tenant.strip():
            raise _request_error("tenant")
        if not isinstance(client_id, str) or not client_id.strip():
            raise _request_error("client_id")

    def validate(self, details) -> tuple[dict, ...]:
        if not isinstance(details, (list, tuple)):
            raise _request_error("details")
        if not details:
            raise _detail_error("details")
        if len(details) > self.max_details_per_grant:
            raise _capacity_error("details")

        canonical = _canonicalize(details)
        self._enforce_byte_limit(canonical)
        return canonical

    def _enforce_byte_limit(self, details: tuple[dict, ...]) -> None:
        if len(_canonical_bytes(details)) > self.max_bytes_per_grant:
            raise _capacity_error("details")

    def _enforce_candidate_limits(self, details: tuple[dict, ...]) -> None:
        if len(details) > self.max_details_per_grant:
            raise _capacity_error("details")
        self._enforce_byte_limit(details)

    def fingerprint(self, details) -> str:
        canonical = _canonicalize(details, allow_empty=True)
        return _fingerprint(canonical)

    def display_lines(self, details) -> tuple[str, ...]:
        canonical = _canonicalize(details, allow_empty=True)
        return _display_lines(canonical)

    def submit(
        self,
        details,
        tenant: str | None = None,
        client_id: str | None = None,
        now: str | None = None,
    ) -> GrantView:
        self._validate_identity(tenant, client_id)
        now_text, now_dt = _resolve_now(now)
        canonical = self.validate(details)
        fingerprint = _fingerprint(canonical)

        with self._lock:
            self._expire_due(now_dt)
            active_for_client = sum(
                1
                for grant in self._grants.values()
                if grant["client_id"] == client_id and grant["status"] == "active"
            )
            if active_for_client >= self.max_grants_per_client:
                raise _capacity_error("client_id")

            grant_id = f"rar-{uuid.uuid4().hex}"
            while grant_id in self._grants:
                grant_id = f"rar-{uuid.uuid4().hex}"

            record = {
                "grant_id": grant_id,
                "tenant": tenant,
                "client_id": client_id,
                "version": 1,
                "details": canonical,
                "fingerprint": fingerprint,
                "created_at": now_text,
                "updated_at": now_text,
                "status": "active",
            }
            self._grants[grant_id] = record
            self._stats["submitted"] += 1
            return self._view(record)

    def _is_due(self, record: dict, now_dt: datetime) -> bool:
        expires_at = _parse_time(record["created_at"]) + timedelta(
            seconds=self.grant_ttl
        )
        return now_dt >= expires_at

    def _expire_due(self, now_dt: datetime) -> int:
        expired = 0
        for record in self._grants.values():
            if record["status"] == "active" and self._is_due(record, now_dt):
                record["status"] = "expired"
                self._stats["expired"] += 1
                expired += 1
        return expired

    def _require_active(self, grant_id: str, now_dt: datetime) -> dict:
        record = self._grants.get(grant_id)
        if record is None:
            raise RarError("RAR_UNKNOWN_GRANT", grant_id)
        if record["status"] == "revoked":
            raise RarError("RAR_GRANT_REVOKED", grant_id)
        if record["status"] == "expired":
            raise RarError("RAR_GRANT_EXPIRED", grant_id)
        if self._is_due(record, now_dt):
            record["status"] = "expired"
            self._stats["expired"] += 1
            raise RarError("RAR_GRANT_EXPIRED", grant_id)
        return record

    def merge(self, grant_id: str, details, now: str | None = None) -> GrantView:
        now_text, now_dt = _resolve_now(now)

        with self._lock:
            record = self._require_active(grant_id, now_dt)
            incoming = self.validate(details)
            candidate = _canonicalize(list(record["details"]) + list(incoming))
            self._enforce_candidate_limits(candidate)

            if candidate == record["details"]:
                self._stats["deduped"] += 1
                return self._view(record)

            record["details"] = candidate
            record["fingerprint"] = _fingerprint(candidate)
            record["version"] += 1
            record["updated_at"] = now_text
            self._stats["merged"] += 1
            return self._view(record)

    def compare(self, grant_id: str, details) -> str:
        with self._lock:
            record = self._grants.get(grant_id)
            if record is None:
                raise RarError("RAR_UNKNOWN_GRANT", grant_id)
            candidate = _canonicalize(details, allow_empty=False)
            return _compare_details(record["details"], candidate)

    def refresh(self, grant_id: str, details, now: str | None = None) -> GrantView:
        now_text, now_dt = _resolve_now(now)

        with self._lock:
            record = self._require_active(grant_id, now_dt)
            candidate = self.validate(details)
            verdict = _compare_details(record["details"], candidate)

            if verdict == "same":
                return self._view(record)

            if verdict == "narrower":
                record["details"] = candidate
                record["fingerprint"] = _fingerprint(candidate)
                record["version"] += 1
                record["updated_at"] = now_text
                self._stats["refreshed"] += 1
                return self._view(record)

            raise RarError("RAR_CONSENT_REQUIRED", "details")

    def _view(self, record: dict) -> GrantView:
        return GrantView(
            grant_id=record["grant_id"],
            tenant=record["tenant"],
            client_id=record["client_id"],
            version=record["version"],
            details=copy.deepcopy(record["details"]),
            fingerprint=record["fingerprint"],
            created_at=record["created_at"],
            updated_at=record["updated_at"],
            status=record["status"],
        )

    def grant_view(self, grant_id: str) -> GrantView:
        with self._lock:
            record = self._grants.get(grant_id)
            if record is None:
                raise RarError("RAR_UNKNOWN_GRANT", grant_id)
            return self._view(record)

    def revoke(self, grant_id: str) -> bool:
        with self._lock:
            record = self._grants.get(grant_id)
            if record is None:
                raise RarError("RAR_UNKNOWN_GRANT", grant_id)
            if record["status"] != "active":
                return False
            record["status"] = "revoked"
            self._stats["revoked"] += 1
            return True

    def sweep_expired(self, now: str | None = None) -> int:
        _, now_dt = _resolve_now(now)
        with self._lock:
            return self._expire_due(now_dt)

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(
                {
                    "version": _SNAPSHOT_VERSION,
                    "grants": self._grants,
                    "stats": self._stats,
                }
            )

    def _parse_snapshot(self, state: object) -> tuple[dict, dict]:
        if not isinstance(state, dict):
            raise RarError("RAR_SNAPSHOT_INVALID", "snapshot")
        if set(state) != {"version", "grants", "stats"}:
            raise RarError("RAR_SNAPSHOT_INVALID", "snapshot")
        if (
            type(state.get("version")) is not int
            or state["version"] != _SNAPSHOT_VERSION
        ):
            raise RarError("RAR_SNAPSHOT_INVALID", "version")

        raw_grants = state["grants"]
        raw_stats = state["stats"]
        if not isinstance(raw_grants, dict):
            raise RarError("RAR_SNAPSHOT_INVALID", "grants")
        if not isinstance(raw_stats, dict):
            raise RarError("RAR_SNAPSHOT_INVALID", "stats")

        stats: dict = {}
        for key in _STAT_KEYS:
            value = raw_stats.get(key)
            if type(value) is not int or value < 0:
                raise RarError("RAR_SNAPSHOT_INVALID", f"stats.{key}")
            stats[key] = value
        for key, value in raw_stats.items():
            if key not in stats:
                stats[key] = copy.deepcopy(value)

        grants: dict[str, dict] = {}
        for grant_id, raw_grant in raw_grants.items():
            if not isinstance(grant_id, str) or not grant_id:
                raise RarError("RAR_SNAPSHOT_INVALID", "grants")
            if not isinstance(raw_grant, dict) or set(raw_grant) != _GRANT_KEYS:
                raise RarError("RAR_SNAPSHOT_INVALID", grant_id)
            if raw_grant.get("grant_id") != grant_id:
                raise RarError("RAR_SNAPSHOT_INVALID", "grant_id")
            if (
                type(raw_grant.get("version")) is not int
                or raw_grant["version"] < 1
            ):
                raise RarError("RAR_SNAPSHOT_INVALID", "version")
            if raw_grant.get("status") not in ("active", "revoked", "expired"):
                raise RarError("RAR_SNAPSHOT_INVALID", "status")
            if (
                not isinstance(raw_grant.get("tenant"), str)
                or not raw_grant["tenant"]
            ):
                raise RarError("RAR_SNAPSHOT_INVALID", "tenant")
            if (
                not isinstance(raw_grant.get("client_id"), str)
                or not raw_grant["client_id"]
            ):
                raise RarError("RAR_SNAPSHOT_INVALID", "client_id")
            if not isinstance(raw_grant.get("created_at"), str):
                raise RarError("RAR_SNAPSHOT_INVALID", "created_at")
            if not isinstance(raw_grant.get("updated_at"), str):
                raise RarError("RAR_SNAPSHOT_INVALID", "updated_at")

            try:
                _parse_time(raw_grant["created_at"])
                _parse_time(raw_grant["updated_at"])
                raw_details = raw_grant["details"]
                if not isinstance(raw_details, (list, tuple)):
                    raise RarError("RAR_SNAPSHOT_INVALID", "details")
                details = _canonicalize(raw_details)
                fingerprint = raw_grant["fingerprint"]
                if not isinstance(fingerprint, str):
                    raise RarError("RAR_SNAPSHOT_INVALID", "fingerprint")
            except RarError as exc:
                if exc.code == "RAR_SNAPSHOT_INVALID":
                    raise
                raise RarError("RAR_SNAPSHOT_INVALID", grant_id) from exc
            fingerprint = _fingerprint(details)

            grants[grant_id] = {
                "grant_id": grant_id,
                "tenant": raw_grant["tenant"],
                "client_id": raw_grant["client_id"],
                "version": raw_grant["version"],
                "details": details,
                "fingerprint": fingerprint,
                "created_at": raw_grant["created_at"],
                "updated_at": raw_grant["updated_at"],
                "status": raw_grant["status"],
            }

        return grants, stats

    def restore(self, state: dict) -> None:
        with self._lock:
            grants, stats = self._parse_snapshot(state)
            self._grants = grants
            self._stats = stats
