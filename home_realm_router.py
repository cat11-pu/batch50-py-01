"""Login-domain to home-realm discovery with longest-suffix matching."""

from __future__ import annotations

import copy
import threading
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any


class HomeRealmError(ValueError):
    """Raised when a routing operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DomainRule:
    domain: str
    tenant: str
    realm: str
    priority: int
    revision: int
    state: str
    updated_at: str


@dataclass(frozen=True)
class Resolution:
    email: str
    domain: str
    matched_domain: str | None
    tenant: str | None
    realm: str
    source: str
    conflict: bool
    degraded: bool
    attempted_realm: str | None
    reason: str | None


class HomeRealmRouter:
    """Route an email domain to the identity source that owns it."""

    _VERSION = 1
    _TOP_LEVEL_KEYS = frozenset({"version", "rules", "health", "cache", "stats"})
    _STAT_KEYS = frozenset(
        {"registered", "resolved", "cache_hits", "defaults", "degraded"}
    )
    _RULE_KEYS = frozenset(
        {
            "domain",
            "tenant",
            "realm",
            "priority",
            "revision",
            "state",
            "updated_at",
        }
    )
    _RESOLUTION_KEYS = frozenset(
        {
            "email",
            "domain",
            "matched_domain",
            "tenant",
            "realm",
            "source",
            "conflict",
            "degraded",
            "attempted_realm",
            "reason",
        }
    )

    def __init__(self, *, default_realm: str = "local",
                 cache_ttl: int = 300, max_domains: int = 100) -> None:
        self.default_realm = default_realm
        self.cache_ttl = cache_ttl
        self.max_domains = max_domains
        self._lock = threading.RLock()
        self._rules: dict[str, list[DomainRule]] = {}
        self._unavailable: set[str] = set()
        self._cache: dict[str, dict[str, Any]] = {}
        self._stats = {
            "registered": 0,
            "resolved": 0,
            "cache_hits": 0,
            "defaults": 0,
            "degraded": 0,
        }

    def register_domain(self, domain: str, *, tenant: str, realm: str,
                        priority: int = 0,
                        now: str | None = None) -> DomainRule:
        normalized_domain = _normalize_domain(domain)
        normalized_tenant = _require_value(tenant, "tenant")
        normalized_realm = _require_value(realm, "realm")
        updated_at = _timestamp(now)

        with self._lock:
            rows = self._rules.get(normalized_domain)
            if rows is None:
                if len(self._rules) >= self.max_domains:
                    raise HomeRealmError(
                        "ROUTER_CAPACITY",
                        {
                            "domain": normalized_domain,
                            "max_domains": self.max_domains,
                        },
                    )
                rule = DomainRule(
                    domain=normalized_domain,
                    tenant=normalized_tenant,
                    realm=normalized_realm,
                    priority=priority,
                    revision=1,
                    state="active",
                    updated_at=updated_at,
                )
                self._rules[normalized_domain] = [rule]
                self._stats["registered"] += 1
                return rule

            for index, existing in enumerate(rows):
                if existing.tenant == normalized_tenant:
                    state = "conflict" if len(rows) > 1 else "active"
                    updated = replace(
                        existing,
                        realm=normalized_realm,
                        priority=priority,
                        revision=existing.revision + 1,
                        state=state,
                        updated_at=updated_at,
                    )
                    rows[index] = updated
                    return updated

            rule = DomainRule(
                domain=normalized_domain,
                tenant=normalized_tenant,
                realm=normalized_realm,
                priority=priority,
                revision=1,
                state="conflict",
                updated_at=updated_at,
            )
            rows.append(rule)
            for index, existing in enumerate(rows):
                rows[index] = replace(existing, state="conflict")
            self._stats["registered"] += 1
            return rows[-1]

    def unregister_domain(self, domain: str, *, tenant: str,
                          now: str | None = None) -> bool:
        normalized_domain = _lenient_domain(domain)
        normalized_tenant = tenant.strip() if isinstance(tenant, str) else tenant
        if not normalized_domain or not isinstance(normalized_tenant, str):
            return False

        with self._lock:
            rows = self._rules.get(normalized_domain)
            if rows is None:
                return False

            for index, rule in enumerate(rows):
                if rule.tenant != normalized_tenant:
                    continue

                rows.pop(index)
                self._stats["registered"] = max(
                    0, self._stats["registered"] - 1
                )
                if not rows:
                    del self._rules[normalized_domain]
                elif len(rows) == 1:
                    rows[0] = replace(rows[0], state="active")
                return True

            return False

    def resolve(self, email: str, *, now: str | None = None) -> Resolution:
        normalized_email, email_domain, lookup_domain = _normalize_email(email)
        current_time = _parse_time(now)

        with self._lock:
            self._stats["resolved"] += 1

            cached = self._cache.get(lookup_domain)
            if cached is not None and _cache_is_active(cached, current_time):
                self._stats["cache_hits"] += 1
                result = _resolution_from_cache(
                    cached, normalized_email, email_domain
                )
                self._count_outcome(result)
                return result

            if cached is not None:
                self._cache.pop(lookup_domain, None)

            matched_domain, rows = self._match(lookup_domain)
            if matched_domain is None:
                result = Resolution(
                    email=normalized_email,
                    domain=email_domain,
                    matched_domain=None,
                    tenant=None,
                    realm=self.default_realm,
                    source="default",
                    conflict=False,
                    degraded=False,
                    attempted_realm=None,
                    reason=None,
                )
            else:
                tenants = {rule.tenant for rule in rows}
                if len(tenants) > 1:
                    result = Resolution(
                        email=normalized_email,
                        domain=email_domain,
                        matched_domain=matched_domain,
                        tenant=None,
                        realm=self.default_realm,
                        source="registry",
                        conflict=True,
                        degraded=False,
                        attempted_realm=None,
                        reason=None,
                    )
                else:
                    rule = rows[0]
                    if rule.realm in self._unavailable:
                        result = Resolution(
                            email=normalized_email,
                            domain=email_domain,
                            matched_domain=matched_domain,
                            tenant=rule.tenant,
                            realm=self.default_realm,
                            source="registry",
                            conflict=False,
                            degraded=True,
                            attempted_realm=rule.realm,
                            reason="unavailable",
                        )
                    else:
                        result = Resolution(
                            email=normalized_email,
                            domain=email_domain,
                            matched_domain=matched_domain,
                            tenant=rule.tenant,
                            realm=rule.realm,
                            source="registry",
                            conflict=False,
                            degraded=False,
                            attempted_realm=None,
                            reason=None,
                        )

            self._cache[lookup_domain] = {
                "resolution": asdict(result),
                "cached_at": current_time.isoformat(),
                "expires_at": (
                    current_time + timedelta(seconds=self.cache_ttl)
                ).isoformat(),
            }
            self._count_outcome(result)
            return result

    def refresh(self, *, now: str | None = None) -> int:
        with self._lock:
            cleared = len(self._cache)
            self._cache.clear()
            return cleared

    def mark_unavailable(self, realm: str) -> None:
        with self._lock:
            if realm not in self._unavailable:
                self._unavailable.add(realm)
                self._cache.clear()

    def mark_available(self, realm: str) -> None:
        with self._lock:
            if realm in self._unavailable:
                self._unavailable.remove(realm)
                self._cache.clear()

    def fallback(self, email: str, *, reason: str = "unavailable",
                 now: str | None = None) -> Resolution:
        normalized_email, email_domain, lookup_domain = _normalize_email(email)
        _parse_time(now)

        with self._lock:
            matched_domain, rows = self._match(lookup_domain)
            tenant = None
            attempted_realm = None
            conflict = False

            if matched_domain is not None:
                tenants = {rule.tenant for rule in rows}
                conflict = len(tenants) > 1
                if not conflict:
                    rule = rows[0]
                    tenant = rule.tenant
                    attempted_realm = rule.realm

            result = Resolution(
                email=normalized_email,
                domain=email_domain,
                matched_domain=matched_domain,
                tenant=tenant,
                realm=self.default_realm,
                source="fallback",
                conflict=conflict,
                degraded=True,
                attempted_realm=attempted_realm,
                reason=reason,
            )
            self._stats["resolved"] += 1
            self._count_outcome(result)
            return result

    def rules(self) -> list[DomainRule]:
        with self._lock:
            return [
                rule
                for rows in self._rules.values()
                for rule in rows
            ]

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": self._VERSION,
                "rules": [asdict(rule) for rule in self.rules()],
                "health": {
                    realm: "unavailable"
                    for realm in sorted(self._unavailable)
                },
                "cache": copy.deepcopy(self._cache),
                "stats": dict(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            parsed = _parse_snapshot(state, self._VERSION)
            self._rules = parsed["rules"]
            self._unavailable = parsed["health"]
            self._cache = parsed["cache"]
            self._stats = parsed["stats"]

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _match(self, lookup_domain: str) -> tuple[str | None, list[DomainRule]]:
        if not lookup_domain:
            return None, []

        labels = lookup_domain.split(".")
        for start in range(len(labels)):
            candidate = ".".join(labels[start:])
            rows = self._rules.get(candidate)
            if rows:
                return candidate, list(rows)
        return None, []

    def _count_outcome(self, result: Resolution) -> None:
        if result.matched_domain is None:
            self._stats["defaults"] += 1
        if result.degraded:
            self._stats["degraded"] += 1


def _require_value(value: str, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise HomeRealmError(
            "ROUTER_INVALID_REQUEST", {"field": field}
        )
    return value.strip()


def _normalize_domain(domain: object) -> str:
    if not isinstance(domain, str):
        raise HomeRealmError("ROUTER_BAD_DOMAIN", {"domain": domain})

    normalized = domain.strip().lower().rstrip(".")
    if not normalized:
        raise HomeRealmError("ROUTER_BAD_DOMAIN", {"domain": domain})

    labels = normalized.split(".")
    if len(labels) < 2:
        raise HomeRealmError("ROUTER_BAD_DOMAIN", {"domain": domain})

    for label in labels:
        if (
            not label
            or label.startswith("-")
            or label.endswith("-")
            or any(not (char.isalnum() or char == "-") for char in label)
        ):
            raise HomeRealmError("ROUTER_BAD_DOMAIN", {"domain": domain})

    return normalized


def _lenient_domain(domain: object) -> str:
    if not isinstance(domain, str):
        return ""
    return domain.strip().lower().rstrip(".")


def _normalize_email(email: object) -> tuple[str, str, str]:
    if not isinstance(email, str):
        raise HomeRealmError("ROUTER_INVALID_EMAIL", {"email": email})

    normalized = email.strip().lower()
    if (
        not normalized
        or any(char.isspace() for char in normalized)
        or normalized.count("@") != 1
    ):
        raise HomeRealmError("ROUTER_INVALID_EMAIL", {"email": email})

    local_part, domain_part = normalized.split("@", 1)
    if not local_part or not domain_part:
        raise HomeRealmError("ROUTER_INVALID_EMAIL", {"email": email})

    return normalized, domain_part, _lenient_domain(domain_part)


def _parse_time(value: object) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        return datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    else:
        raise HomeRealmError("ROUTER_INVALID_REQUEST", {"field": "now"})

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed


def _timestamp(value: object) -> str:
    if value is None:
        return _parse_time(None).isoformat()
    if isinstance(value, str):
        _parse_time(value)
        return value
    return _parse_time(value).isoformat()


def _cache_is_active(entry: dict[str, Any], current_time: datetime) -> bool:
    try:
        expires_at = _parse_time(entry["expires_at"])
    except (KeyError, TypeError, ValueError, HomeRealmError):
        return False
    return current_time < expires_at


def _resolution_from_cache(
    entry: dict[str, Any], email: str, domain: str
) -> Resolution:
    data = dict(entry["resolution"])
    data["email"] = email
    data["domain"] = domain
    data["source"] = "cache"
    return Resolution(**data)


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_snapshot(state: object, version: int) -> dict[str, Any]:
    try:
        if not isinstance(state, dict):
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
        if set(state.keys()) != HomeRealmRouter._TOP_LEVEL_KEYS:
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
        if not _is_integer(state["version"]) or state["version"] != version:
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")

        rules = _parse_snapshot_rules(state["rules"])
        unavailable = _parse_snapshot_health(state["health"])
        cache = _parse_snapshot_cache(state["cache"])
        stats = _parse_snapshot_stats(state["stats"])

        return {
            "rules": rules,
            "health": unavailable,
            "cache": cache,
            "stats": stats,
        }
    except HomeRealmError as error:
        if error.code == "ROUTER_SNAPSHOT_INVALID":
            raise
        raise HomeRealmError(
            "ROUTER_SNAPSHOT_INVALID", {"cause": error.code}
        ) from error
    except (KeyError, TypeError, ValueError) as error:
        raise HomeRealmError("ROUTER_SNAPSHOT_INVALID") from error


def _parse_snapshot_rules(value: object) -> dict[str, list[DomainRule]]:
    if not isinstance(value, list):
        raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")

    rules: dict[str, list[DomainRule]] = {}
    seen: set[tuple[str, str]] = set()

    for item in value:
        if not isinstance(item, dict):
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
        if set(item.keys()) != HomeRealmRouter._RULE_KEYS:
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")

        domain = _normalize_domain(item["domain"])
        tenant = _require_value(item["tenant"], "tenant")
        realm = _require_value(item["realm"], "realm")
        priority = item["priority"]
        revision = item["revision"]
        rule_state = item["state"]
        updated_at = item["updated_at"]

        if (
            not _is_integer(priority)
            or not _is_integer(revision)
            or revision < 1
            or rule_state not in {"active", "conflict"}
            or not isinstance(updated_at, str)
            or not updated_at
        ):
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")

        identity = (domain, tenant)
        if identity in seen:
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
        seen.add(identity)

        rule = DomainRule(
            domain=domain,
            tenant=tenant,
            realm=realm,
            priority=priority,
            revision=revision,
            state=rule_state,
            updated_at=updated_at,
        )
        rules.setdefault(domain, []).append(rule)

    return rules


def _parse_snapshot_health(value: object) -> set[str]:
    if not isinstance(value, dict):
        raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")

    unavailable: set[str] = set()
    wrapped = value.get("unavailable")
    if isinstance(wrapped, list) and len(value) == 1:
        for realm in wrapped:
            if not isinstance(realm, str) or not realm:
                raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
            unavailable.add(realm)
        return unavailable

    for realm, status in value.items():
        if not isinstance(realm, str) or not realm:
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
        if isinstance(status, bool):
            if not status:
                unavailable.add(realm)
        elif isinstance(status, str):
            normalized_status = status.strip().lower()
            if normalized_status in {"unavailable", "down", "disabled", "false", "0"}:
                unavailable.add(realm)
            elif normalized_status not in {
                "available", "active", "healthy", "up", "true", "1"
            }:
                raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
        else:
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
    return unavailable


def _parse_snapshot_cache(value: object) -> dict[str, dict[str, Any]]:
    if not isinstance(value, dict):
        raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")

    cache: dict[str, dict[str, Any]] = {}
    for key, entry in value.items():
        if not isinstance(key, str) or not key or not isinstance(entry, dict):
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
        if set(entry.keys()) != {"resolution", "cached_at", "expires_at"}:
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")

        resolution = entry["resolution"]
        if not isinstance(resolution, dict):
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
        if set(resolution.keys()) != HomeRealmRouter._RESOLUTION_KEYS:
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")

        for field_name in ("email", "domain", "realm", "source"):
            if not isinstance(resolution[field_name], str) or not resolution[field_name]:
                raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
        for field_name in ("matched_domain", "tenant", "attempted_realm", "reason"):
            field_value = resolution[field_name]
            if field_value is not None and not isinstance(field_value, str):
                raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
        for field_name in ("conflict", "degraded"):
            if not isinstance(resolution[field_name], bool):
                raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")

        cached_at = entry["cached_at"]
        expires_at = entry["expires_at"]
        if not isinstance(cached_at, str) or not cached_at:
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
        if not isinstance(expires_at, str) or not expires_at:
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
        _parse_time(cached_at)
        _parse_time(expires_at)

        cache[_lenient_domain(key)] = copy.deepcopy(entry)

    return cache


def _parse_snapshot_stats(value: object) -> dict[str, int]:
    if not isinstance(value, dict) or set(value.keys()) != HomeRealmRouter._STAT_KEYS:
        raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")

    stats: dict[str, int] = {}
    for key in HomeRealmRouter._STAT_KEYS:
        item = value[key]
        if not _is_integer(item) or item < 0:
            raise HomeRealmError("ROUTER_SNAPSHOT_INVALID")
        stats[key] = item
    return stats
