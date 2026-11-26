"""Email magic-link issuance, device binding and one-time redemption."""

from __future__ import annotations

import copy
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any


_STAT_KEYS = (
    "issued",
    "redeemed",
    "consumed",
    "revoked",
    "expired",
    "rate_limited",
)
_LINK_STATES = ("pending", "consumed", "revoked", "expired")
_SNAPSHOT_VERSION = 1


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


@dataclass
class _Link:
    token_id: str
    email: str
    purpose: str
    device_fingerprint: str
    issued_at: str
    expires_at: str
    state: str = "pending"
    redeemed_at: str | None = None
    pending_device: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "token_id": self.token_id,
            "email": self.email,
            "purpose": self.purpose,
            "device_fingerprint": self.device_fingerprint,
            "issued_at": self.issued_at,
            "expires_at": self.expires_at,
            "state": self.state,
            "redeemed_at": self.redeemed_at,
            "pending_device": self.pending_device,
        }


def _parse_time(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("empty timestamp")
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    else:
        raise ValueError("timestamp must be a string or datetime")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _invalid_snapshot(detail: object = None) -> MagicLinkError:
    return MagicLinkError("MAGIC_LINK_SNAPSHOT_INVALID", detail)


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
        self._links: dict[str, _Link] = {}
        self._last_issue: dict[str, str] = {}
        self._stats: dict[str, int] = {key: 0 for key in _STAT_KEYS}

    def _now(self, now: Any = None) -> datetime:
        if now is None:
            if self._clock is not None:
                now = self._clock()
            else:
                return datetime.now(timezone.utc)
        return _parse_time(now)

    @staticmethod
    def _normalize_email(email: Any) -> str:
        if not isinstance(email, str):
            raise MagicLinkError("MAGIC_LINK_INVALID_EMAIL", email)
        normalized = email.strip().lower()
        if normalized.count("@") != 1:
            raise MagicLinkError("MAGIC_LINK_INVALID_EMAIL", email)
        local, domain = normalized.split("@", 1)
        if not local or not domain:
            raise MagicLinkError("MAGIC_LINK_INVALID_EMAIL", email)
        return normalized

    @staticmethod
    def _validate_purpose(purpose: Any) -> None:
        if not isinstance(purpose, str) or not purpose.strip():
            raise MagicLinkError("MAGIC_LINK_BAD_PURPOSE", purpose)

    @staticmethod
    def _validate_ttl(ttl: Any) -> int:
        if type(ttl) is not int or not 1 <= ttl <= 86400:
            raise MagicLinkError("MAGIC_LINK_BAD_TTL", ttl)
        return ttl

    @staticmethod
    def _is_expired(link: _Link, now: datetime) -> bool:
        return _parse_time(link.expires_at) <= now

    def _result(self, status: str, link: _Link, *,
                requires_confirmation: bool,
                redeemed_at: str | None) -> RedeemResult:
        return RedeemResult(
            status=status,
            token_id=link.token_id,
            email=link.email,
            purpose=link.purpose,
            requires_confirmation=requires_confirmation,
            redeemed_at=redeemed_at,
        )

    def _consume(self, link: _Link, now: datetime) -> RedeemResult:
        redeemed_at = _format_time(now)
        link.state = "consumed"
        link.redeemed_at = redeemed_at
        link.pending_device = None
        self._stats["redeemed"] += 1
        return self._result(
            "redeemed",
            link,
            requires_confirmation=False,
            redeemed_at=redeemed_at,
        )

    def issue(self, email: str, *, device_fingerprint: str,
              purpose: str = "login", ttl: int | None = None,
              now: str | None = None) -> LinkTicket:
        normalized_email = self._normalize_email(email)
        self._validate_purpose(purpose)
        effective_ttl = self._validate_ttl(
            self.default_ttl if ttl is None else ttl
        )
        issued_dt = self._now(now)
        issued_at = _format_time(issued_dt)
        expires_at = _format_time(issued_dt + timedelta(seconds=effective_ttl))

        with self._lock:
            previous_issue = self._last_issue.get(normalized_email)
            if previous_issue is not None and self.min_issue_interval > 0:
                elapsed = (issued_dt - _parse_time(previous_issue)).total_seconds()
                if elapsed < self.min_issue_interval:
                    self._stats["rate_limited"] += 1
                    raise MagicLinkError(
                        "MAGIC_LINK_RATE_LIMITED", normalized_email
                    )

            active = [
                link
                for link in self._links.values()
                if link.email == normalized_email
                and link.state == "pending"
                and not self._is_expired(link, issued_dt)
            ]

            revoke_old = self.resend_policy == "revoke"
            if revoke_old:
                active = [
                    link for link in active if link.purpose != purpose
                ]

            if len(active) >= self.max_active_per_email:
                raise MagicLinkError(
                    "MAGIC_LINK_TOO_MANY_ACTIVE", normalized_email
                )

            if revoke_old:
                for link in self._links.values():
                    if (
                        link.email == normalized_email
                        and link.purpose == purpose
                        and link.state == "pending"
                    ):
                        link.state = "revoked"
                        link.pending_device = None
                        self._stats["revoked"] += 1

            token_id = self._new_token_id()
            link = _Link(
                token_id=token_id,
                email=normalized_email,
                purpose=purpose,
                device_fingerprint=device_fingerprint,
                issued_at=issued_at,
                expires_at=expires_at,
                state="pending",
            )
            self._links[token_id] = link
            self._last_issue[normalized_email] = issued_at
            self._stats["issued"] += 1

            return LinkTicket(
                token_id=token_id,
                email=normalized_email,
                purpose=purpose,
                device_fingerprint=device_fingerprint,
                issued_at=issued_at,
                expires_at=expires_at,
                state="pending",
            )

    def _new_token_id(self) -> str:
        while True:
            token_id = "ml_" + secrets.token_hex(8)
            if token_id not in self._links:
                return token_id

    def redeem(self, token_id: str, *, device_fingerprint: str,
               now: str | None = None) -> RedeemResult:
        redeemed_dt = self._now(now)
        with self._lock:
            link = self._links.get(token_id)
            if link is None:
                raise MagicLinkError("MAGIC_LINK_UNKNOWN", token_id)
            if link.state == "consumed":
                self._stats["consumed"] += 1
                return self._result(
                    "consumed",
                    link,
                    requires_confirmation=False,
                    redeemed_at=link.redeemed_at,
                )
            if link.state == "revoked":
                raise MagicLinkError("MAGIC_LINK_REVOKED", token_id)
            if link.state == "expired" or self._is_expired(link, redeemed_dt):
                raise MagicLinkError("MAGIC_LINK_EXPIRED", token_id)

            if device_fingerprint != link.device_fingerprint:
                link.pending_device = device_fingerprint
                return self._result(
                    "confirmation_required",
                    link,
                    requires_confirmation=True,
                    redeemed_at=None,
                )

            return self._consume(link, redeemed_dt)

    def confirm(self, token_id: str, *, device_fingerprint: str,
                now: str | None = None) -> RedeemResult:
        confirmed_dt = self._now(now)
        with self._lock:
            link = self._links.get(token_id)
            if link is None:
                raise MagicLinkError("MAGIC_LINK_UNKNOWN", token_id)
            if link.state == "consumed":
                raise MagicLinkError("MAGIC_LINK_CONSUMED", token_id)
            if link.state == "revoked":
                raise MagicLinkError("MAGIC_LINK_REVOKED", token_id)
            if link.state == "expired" or self._is_expired(link, confirmed_dt):
                raise MagicLinkError("MAGIC_LINK_EXPIRED", token_id)
            if link.pending_device is None:
                raise MagicLinkError("MAGIC_LINK_NO_PENDING", token_id)
            if device_fingerprint != link.pending_device:
                raise MagicLinkError("MAGIC_LINK_DEVICE_MISMATCH", token_id)
            return self._consume(link, confirmed_dt)

    def invalidate(self, token_id: str, *, now: str | None = None) -> bool:
        with self._lock:
            link = self._links.get(token_id)
            if link is None or link.state != "pending":
                return False
            link.state = "revoked"
            link.pending_device = None
            self._stats["revoked"] += 1
            return True

    def invalidate_all(self, email: str, *, now: str | None = None) -> int:
        normalized_email = self._normalize_email(email)
        with self._lock:
            revoked = 0
            for link in self._links.values():
                if link.email == normalized_email and link.state == "pending":
                    link.state = "revoked"
                    link.pending_device = None
                    self._stats["revoked"] += 1
                    revoked += 1
            return revoked

    def status(self, token_id: str) -> dict:
        with self._lock:
            link = self._links.get(token_id)
            if link is None:
                raise MagicLinkError("MAGIC_LINK_UNKNOWN", token_id)
            return {
                "token_id": link.token_id,
                "email": link.email,
                "purpose": link.purpose,
                "state": link.state,
                "expires_at": link.expires_at,
                "pending_device": link.pending_device,
            }

    def active_links(self, email: str, *, now: str | None = None) -> list[str]:
        normalized_email = self._normalize_email(email)
        current = self._now(now)
        with self._lock:
            return sorted(
                link.token_id
                for link in self._links.values()
                if link.email == normalized_email
                and link.state == "pending"
                and not self._is_expired(link, current)
            )

    def purge_expired(self, *, now: str | None = None) -> int:
        current = self._now(now)
        with self._lock:
            purged = 0
            for link in self._links.values():
                if link.state == "pending" and self._is_expired(link, current):
                    link.state = "expired"
                    link.pending_device = None
                    self._stats["expired"] += 1
                    purged += 1
            return purged

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "links": [
                    copy.deepcopy(link.as_dict())
                    for link in sorted(
                        self._links.values(), key=lambda item: item.token_id
                    )
                ],
                "counters": {
                    "last_issue": copy.deepcopy(self._last_issue),
                },
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        try:
            links, last_issue, stats = self._parse_snapshot(state)
        except MagicLinkError:
            raise
        except Exception as exc:
            raise _invalid_snapshot(exc) from exc

        with self._lock:
            self._links = links
            self._last_issue = last_issue
            self._stats = stats

    @staticmethod
    def _parse_snapshot(state: Any):
        if not isinstance(state, dict):
            raise _invalid_snapshot("snapshot must be a mapping")
        if set(state.keys()) != {"version", "links", "counters", "stats"}:
            raise _invalid_snapshot("snapshot keys are invalid")
        if type(state["version"]) is not int or state["version"] != _SNAPSHOT_VERSION:
            raise _invalid_snapshot("unsupported snapshot version")

        raw_links = state["links"]
        if not isinstance(raw_links, list):
            raise _invalid_snapshot("links must be a list")
        links: dict[str, _Link] = {}
        required = {
            "token_id",
            "email",
            "purpose",
            "device_fingerprint",
            "issued_at",
            "expires_at",
            "state",
        }
        for entry in raw_links:
            if not isinstance(entry, dict) or not required.issubset(entry):
                raise _invalid_snapshot("link entry is invalid")
            token_id = entry["token_id"]
            email = entry["email"]
            purpose = entry["purpose"]
            fingerprint = entry["device_fingerprint"]
            issued_at = entry["issued_at"]
            expires_at = entry["expires_at"]
            link_state = entry["state"]
            redeemed_at = entry.get("redeemed_at")
            pending_device = entry.get("pending_device")

            if not isinstance(token_id, str) or not token_id:
                raise _invalid_snapshot("token_id is invalid")
            if token_id in links:
                raise _invalid_snapshot("duplicate token_id")
            if not isinstance(email, str) or not email:
                raise _invalid_snapshot("email is invalid")
            if not isinstance(purpose, str) or not purpose:
                raise _invalid_snapshot("purpose is invalid")
            if not isinstance(fingerprint, str):
                raise _invalid_snapshot("device_fingerprint is invalid")
            if not isinstance(issued_at, str) or not isinstance(expires_at, str):
                raise _invalid_snapshot("timestamps are invalid")
            _parse_time(issued_at)
            _parse_time(expires_at)
            if link_state not in _LINK_STATES:
                raise _invalid_snapshot("link state is invalid")
            if redeemed_at is not None:
                if not isinstance(redeemed_at, str):
                    raise _invalid_snapshot("redeemed_at is invalid")
                _parse_time(redeemed_at)
            if pending_device is not None and not isinstance(pending_device, str):
                raise _invalid_snapshot("pending_device is invalid")
            if link_state == "consumed":
                if not isinstance(redeemed_at, str):
                    raise _invalid_snapshot("consumed link needs redeemed_at")
            elif redeemed_at is not None:
                raise _invalid_snapshot("unconsumed link has redeemed_at")

            links[token_id] = _Link(
                token_id=token_id,
                email=email,
                purpose=purpose,
                device_fingerprint=fingerprint,
                issued_at=issued_at,
                expires_at=expires_at,
                state=link_state,
                redeemed_at=redeemed_at,
                pending_device=pending_device,
            )

        raw_counters = state["counters"]
        if not isinstance(raw_counters, dict):
            raise _invalid_snapshot("counters must be a mapping")
        raw_last_issue = raw_counters.get("last_issue", {})
        if not isinstance(raw_last_issue, dict):
            raise _invalid_snapshot("last_issue must be a mapping")
        last_issue: dict[str, str] = {}
        for email, issued_at in raw_last_issue.items():
            if not isinstance(email, str) or not isinstance(issued_at, str):
                raise _invalid_snapshot("last_issue entry is invalid")
            _parse_time(issued_at)
            last_issue[email] = issued_at

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict) or set(raw_stats.keys()) != set(_STAT_KEYS):
            raise _invalid_snapshot("stats are invalid")
        stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            value = raw_stats[key]
            if type(value) is not int or value < 0:
                raise _invalid_snapshot("stats values are invalid")
            stats[key] = value

        return links, last_issue, stats

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)
