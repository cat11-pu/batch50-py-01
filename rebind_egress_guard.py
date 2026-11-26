"""Outbound DNS rebinding guard: pin resolved addresses per tenant before connecting."""

from __future__ import annotations

import copy
import ipaddress
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Iterable

__all__ = [
    "RebindError",
    "TenantPolicy",
    "PinRecord",
    "ConnectDecision",
    "RebindEgressGuard",
]


_SNAPSHOT_VERSION = 1
_STAT_KEYS = (
    "resolved",
    "reused",
    "address_shifts",
    "peer_rejections",
    "pin_expired",
    "released",
    "purged",
    "rate_limited",
)
_METADATA_ADDRESSES = frozenset(
    {
        ipaddress.ip_address("169.254.169.254"),
        ipaddress.ip_address("::ffff:169.254.169.254"),
    }
)


class RebindError(ValueError):
    """Raised when an egress resolution or connection is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TenantPolicy:
    tenant: str
    allow_private: bool
    allow_metadata: bool
    max_addresses: int


@dataclass(frozen=True)
class PinRecord:
    tenant: str
    host: str
    addresses: tuple[str, ...]
    created_at: str
    expires_at: str
    hops: tuple[str, ...]


@dataclass(frozen=True)
class ConnectDecision:
    tenant: str
    host: str
    peer_address: str
    accepted: bool
    reason: str
    pinned_addresses: tuple[str, ...]


def _invalid_request(detail: object = None) -> RebindError:
    return RebindError("REBIND_INVALID_REQUEST", detail)


def _snapshot_invalid(detail: object = None) -> RebindError:
    return RebindError("REBIND_SNAPSHOT_INVALID", detail)


def _parse_time(value: Any, *, snapshot: bool = False) -> datetime:
    error_factory = _snapshot_invalid if snapshot else _invalid_request

    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise error_factory({"time": value}) from exc
    elif not snapshot and isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = datetime.fromtimestamp(value, tz=timezone.utc)
    else:
        raise error_factory({"time": value})

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _isoformat(value: datetime) -> str:
    return value.isoformat()


def _encode_key(tenant: str, host: str) -> str:
    return f"{tenant}\u0000{host}"


def _key_from_parts(tenant: Any, host: Any) -> tuple[str, str]:
    if not isinstance(tenant, str) or not tenant:
        raise _snapshot_invalid({"key": "tenant"})
    if not isinstance(host, str) or not host:
        raise _snapshot_invalid({"key": "host"})
    return tenant, host


def _identity_from_key(key: Any) -> tuple[str, str] | None:
    if isinstance(key, tuple) and len(key) == 2:
        return _key_from_parts(key[0], key[1])
    if isinstance(key, list) and len(key) == 2:
        return _key_from_parts(key[0], key[1])
    if isinstance(key, str) and "\u0000" in key:
        tenant, host = key.split("\u0000", 1)
        return _key_from_parts(tenant, host)
    return None


class RebindEgressGuard:
    """Pin DNS answers per tenant and refuse connections that leave the pin set."""

    def __init__(self, *, default_ttl: int = 60, max_pins_per_tenant: int = 32,
                 max_addresses_per_pin: int = 8, reject_window: float = 60.0,
                 max_rejects_per_host: int = 5, clock=None) -> None:
        self.default_ttl = default_ttl
        self.max_pins_per_tenant = max_pins_per_tenant
        self.max_addresses_per_pin = max_addresses_per_pin
        self.reject_window = reject_window
        self.max_rejects_per_host = max_rejects_per_host
        self._clock = clock
        self._lock = threading.RLock()
        self._tenants: dict[str, TenantPolicy] = {}
        self._pins: dict[tuple[str, str], PinRecord] = {}
        self._rejections: dict[tuple[str, str], list[str]] = {}
        self._stats: dict[str, int] = {key: 0 for key in _STAT_KEYS}
        self._counters = self._stats

    def register_tenant(self, tenant: str, *, allow_private: bool = False,
                        allow_metadata: bool = False,
                        max_addresses: int | None = None) -> TenantPolicy:
        with self._lock:
            if not isinstance(tenant, str) or not tenant:
                raise _invalid_request({"field": "tenant", "value": tenant})
            if not isinstance(allow_private, bool) or not isinstance(allow_metadata, bool):
                raise _invalid_request({"field": "policy_flags"})
            if max_addresses is not None and (
                not isinstance(max_addresses, int)
                or isinstance(max_addresses, bool)
                or max_addresses <= 0
            ):
                raise _invalid_request({"field": "max_addresses", "value": max_addresses})

            effective_max_addresses = (
                self.max_addresses_per_pin if max_addresses is None else max_addresses
            )
            policy = TenantPolicy(
                tenant=tenant,
                allow_private=allow_private,
                allow_metadata=allow_metadata,
                max_addresses=effective_max_addresses,
            )
            self._tenants[tenant] = policy
            return policy

    def policy_for(self, tenant: str) -> TenantPolicy:
        with self._lock:
            return self._require_tenant_locked(tenant)

    def resolve(self, tenant: str, host: str, addresses, ttl: int | None = None,
                now: str | None = None, hops: Iterable[str] = ()) -> PinRecord:
        with self._lock:
            policy = self._require_tenant_locked(tenant)
            self._validate_host(host)
            ordered_addresses = self._normalize_addresses(addresses)
            self._authorize_addresses(ordered_addresses, policy)
            hop_tuple = self._normalize_hops(hops)
            created_at = self._current_time(now)
            key = (tenant, host)
            existing = self._pins.get(key)

            if existing is not None and not self._is_expired(existing, created_at):
                if self._same_addresses(existing, ordered_addresses):
                    self._stats["reused"] += 1
                    return existing

                self._stats["address_shifts"] += 1
                raise RebindError(
                    "REBIND_ADDRESS_SHIFT",
                    {
                        "tenant": tenant,
                        "host": host,
                        "pinned": list(existing.addresses),
                        "observed": [raw for raw, _ in ordered_addresses],
                    },
                )

            if existing is None:
                self._ensure_pin_capacity_locked(tenant)
            self._ensure_address_capacity(ordered_addresses, policy)

            record = self._build_record(
                tenant, host, ordered_addresses, created_at, ttl, hop_tuple
            )
            self._pins[key] = record
            self._stats["resolved"] += 1
            return record

    def pin(self, tenant: str, host: str, addresses, ttl: int | None = None,
            now: str | None = None, hops: Iterable[str] = ()) -> PinRecord:
        with self._lock:
            policy = self._require_tenant_locked(tenant)
            self._validate_host(host)
            ordered_addresses = self._normalize_addresses(addresses)
            self._authorize_addresses(ordered_addresses, policy)
            hop_tuple = self._normalize_hops(hops)
            created_at = self._current_time(now)
            key = (tenant, host)

            if key not in self._pins:
                self._ensure_pin_capacity_locked(tenant)
            self._ensure_address_capacity(ordered_addresses, policy)

            record = self._build_record(
                tenant, host, ordered_addresses, created_at, ttl, hop_tuple
            )
            self._pins[key] = record
            return record

    def check_connect(self, tenant: str, host: str, peer_address: str,
                      sni: str | None = None, cert_subject: str | None = None,
                      now: str | None = None) -> ConnectDecision:
        with self._lock:
            self._require_tenant_locked(tenant)
            self._validate_host(host)
            peer_ip = self._parse_single_address(peer_address)

            if sni is not None and sni != host:
                raise RebindError(
                    "REBIND_SNI_MISMATCH",
                    {"host": host, "sni": sni, "field": "sni"},
                )
            if cert_subject is not None and cert_subject != host:
                raise RebindError(
                    "REBIND_SNI_MISMATCH",
                    {"host": host, "cert_subject": cert_subject, "field": "cert_subject"},
                )

            key = (tenant, host)
            record = self._pins.get(key)
            if record is None:
                raise RebindError(
                    "REBIND_PIN_MISSING",
                    {"tenant": tenant, "host": host},
                )

            checked_at = self._current_time(now)
            pinned_addresses = record.addresses

            if self._is_expired(record, checked_at):
                self._stats["pin_expired"] += 1
                return ConnectDecision(
                    tenant=tenant,
                    host=host,
                    peer_address=peer_address,
                    accepted=False,
                    reason="pin_expired",
                    pinned_addresses=pinned_addresses,
                )

            if self._is_pinned_peer(record, peer_ip):
                return ConnectDecision(
                    tenant=tenant,
                    host=host,
                    peer_address=peer_address,
                    accepted=True,
                    reason="ok",
                    pinned_addresses=pinned_addresses,
                )

            events = self._rejections.setdefault(key, [])
            self._prune_rejections(events, checked_at)
            if len(events) >= self.max_rejects_per_host:
                self._stats["rate_limited"] += 1
                raise RebindError(
                    "REBIND_REJECT_LIMIT",
                    {
                        "tenant": tenant,
                        "host": host,
                        "rejections": len(events),
                        "limit": self.max_rejects_per_host,
                    },
                )

            events.append(_isoformat(checked_at))
            self._stats["peer_rejections"] += 1
            return ConnectDecision(
                tenant=tenant,
                host=host,
                peer_address=peer_address,
                accepted=False,
                reason="peer_not_pinned",
                pinned_addresses=pinned_addresses,
            )

    def release(self, tenant: str, host: str) -> int:
        with self._lock:
            self._require_tenant_locked(tenant)
            self._validate_host(host)
            removed = self._pins.pop((tenant, host), None) is not None
            if removed:
                self._stats["released"] += 1
                return 1
            return 0

    def purge(self, now: str | None = None) -> int:
        with self._lock:
            checked_at = self._current_time(now)
            expired_keys = [
                key for key, record in self._pins.items()
                if self._is_expired(record, checked_at)
            ]
            for key in expired_keys:
                del self._pins[key]

            removed = len(expired_keys)
            self._stats["purged"] += removed
            return removed

    def blocked_address(self, address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except (ValueError, TypeError):
            return True
        return self._address_kind(ip) != "public"

    def status(self) -> dict:
        with self._lock:
            return {
                "tenants": len(self._tenants),
                "pins": len(self._pins),
                "addresses": sum(len(record.addresses) for record in self._pins.values()),
                "rejections": sum(len(events) for events in self._rejections.values()),
            }

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": _SNAPSHOT_VERSION,
                "tenants": {
                    tenant: {
                        "tenant": policy.tenant,
                        "allow_private": policy.allow_private,
                        "allow_metadata": policy.allow_metadata,
                        "max_addresses": policy.max_addresses,
                    }
                    for tenant, policy in self._tenants.items()
                },
                "pins": {
                    _encode_key(tenant, host): {
                        "tenant": record.tenant,
                        "host": record.host,
                        "addresses": list(record.addresses),
                        "created_at": record.created_at,
                        "expires_at": record.expires_at,
                        "hops": list(record.hops),
                    }
                    for (tenant, host), record in self._pins.items()
                },
                "rejections": {
                    _encode_key(tenant, host): list(events)
                    for (tenant, host), events in self._rejections.items()
                },
                "counters": copy.deepcopy(self._counters),
                "stats": copy.deepcopy(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            if not isinstance(state, dict):
                raise _snapshot_invalid({"type": type(state).__name__})

            required = {"version", "tenants", "pins", "rejections", "counters", "stats"}
            if set(state) != required:
                raise _snapshot_invalid({"keys": sorted(state.keys())})

            version = state["version"]
            if isinstance(version, bool) or not isinstance(version, int):
                raise _snapshot_invalid({"version": version})
            if version != _SNAPSHOT_VERSION:
                raise _snapshot_invalid({"version": version})

            for key in ("tenants", "pins", "rejections", "counters", "stats"):
                if not isinstance(state[key], dict):
                    raise _snapshot_invalid({"field": key})

            new_tenants = self._restore_tenants(state["tenants"])
            new_pins = self._restore_pins(state["pins"], new_tenants)
            new_rejections = self._restore_rejections(state["rejections"], new_tenants)
            new_stats = self._restore_stats(state["stats"])

            self._tenants = new_tenants
            self._pins = new_pins
            self._rejections = new_rejections
            self._stats = new_stats
            self._counters = new_stats

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

    def _require_tenant_locked(self, tenant: Any) -> TenantPolicy:
        if not isinstance(tenant, str) or tenant not in self._tenants:
            raise RebindError("REBIND_UNKNOWN_TENANT", {"tenant": tenant})
        return self._tenants[tenant]

    @staticmethod
    def _validate_host(host: Any) -> None:
        if not isinstance(host, str) or not host:
            raise _invalid_request({"field": "host", "value": host})

    @staticmethod
    def _parse_single_address(address: Any) -> ipaddress._BaseAddress:
        if not isinstance(address, str):
            raise _invalid_request({"field": "address", "value": address})
        try:
            return ipaddress.ip_address(address)
        except ValueError as exc:
            raise _invalid_request({"address": address}) from exc

    def _normalize_addresses(
        self, addresses: Any
    ) -> list[tuple[str, ipaddress._BaseAddress]]:
        if addresses is None or isinstance(addresses, (str, bytes)):
            raise _invalid_request({"field": "addresses"})
        try:
            raw_addresses = list(addresses)
        except TypeError as exc:
            raise _invalid_request({"field": "addresses"}) from exc

        if not raw_addresses:
            raise _invalid_request({"field": "addresses"})

        unique: dict[str, tuple[str, ipaddress._BaseAddress]] = {}
        for raw_address in raw_addresses:
            ip = self._parse_single_address(raw_address)
            canonical = str(ip)
            if canonical not in unique:
                unique[canonical] = (raw_address, ip)

        return sorted(unique.values(), key=lambda item: int(item[1]))

    @staticmethod
    def _normalize_hops(hops: Any) -> tuple[str, ...]:
        if hops is None:
            return ()
        if isinstance(hops, str):
            return (hops,)
        try:
            raw_hops = list(hops)
        except TypeError as exc:
            raise _invalid_request({"field": "hops"}) from exc
        if not all(isinstance(hop, str) for hop in raw_hops):
            raise _invalid_request({"field": "hops"})
        return tuple(raw_hops)

    def _current_time(self, now: Any) -> datetime:
        if now is not None:
            return _parse_time(now)
        if self._clock is not None:
            return _parse_time(self._clock())
        return datetime.now(timezone.utc)

    @staticmethod
    def _is_metadata(ip: ipaddress._BaseAddress) -> bool:
        return ip in _METADATA_ADDRESSES

    @classmethod
    def _address_kind(cls, ip: ipaddress._BaseAddress) -> str:
        if cls._is_metadata(ip):
            return "metadata"
        if ip.is_loopback:
            return "loopback"
        if ip.is_unspecified:
            return "unspecified"
        if ip.is_multicast:
            return "multicast"
        if ip.is_link_local:
            return "link_local"
        if ip.is_private or not ip.is_global:
            return "private"
        return "public"

    def _authorize_addresses(
        self,
        addresses: list[tuple[str, ipaddress._BaseAddress]],
        policy: TenantPolicy,
    ) -> None:
        always_forbidden = {"loopback", "unspecified", "multicast", "link_local"}
        for raw_address, ip in addresses:
            kind = self._address_kind(ip)
            if kind == "metadata":
                if not policy.allow_metadata:
                    raise RebindError(
                        "REBIND_FORBIDDEN_ADDRESS",
                        {"address": raw_address, "classification": kind},
                    )
            elif kind in always_forbidden:
                raise RebindError(
                    "REBIND_FORBIDDEN_ADDRESS",
                    {"address": raw_address, "classification": kind},
                )
            elif kind == "private" and not policy.allow_private:
                raise RebindError(
                    "REBIND_FORBIDDEN_ADDRESS",
                    {"address": raw_address, "classification": kind},
                )

    def _address_limit(self, policy: TenantPolicy) -> int:
        tenant_limit = (
            policy.max_addresses
            if policy.max_addresses is not None
            else self.max_addresses_per_pin
        )
        return min(self.max_addresses_per_pin, tenant_limit)

    def _ensure_address_capacity(
        self,
        addresses: list[tuple[str, ipaddress._BaseAddress]],
        policy: TenantPolicy,
    ) -> None:
        limit = self._address_limit(policy)
        if len(addresses) > limit:
            raise RebindError(
                "REBIND_CAPACITY_EXCEEDED",
                {
                    "tenant": policy.tenant,
                    "addresses": len(addresses),
                    "max_addresses": limit,
                    "scope": "addresses",
                },
            )

    def _ensure_pin_capacity_locked(self, tenant: str) -> None:
        pin_count = sum(1 for pin_tenant, _ in self._pins if pin_tenant == tenant)
        if pin_count >= self.max_pins_per_tenant:
            raise RebindError(
                "REBIND_CAPACITY_EXCEEDED",
                {
                    "tenant": tenant,
                    "pins": pin_count,
                    "max_pins_per_tenant": self.max_pins_per_tenant,
                    "scope": "pins",
                },
            )

    def _build_record(
        self,
        tenant: str,
        host: str,
        addresses: list[tuple[str, ipaddress._BaseAddress]],
        created_at: datetime,
        ttl: int | float | None,
        hops: tuple[str, ...],
    ) -> PinRecord:
        ttl_value = self.default_ttl if ttl is None else ttl
        if isinstance(ttl_value, bool) or not isinstance(ttl_value, (int, float)):
            raise _invalid_request({"field": "ttl", "value": ttl})

        expires_at = created_at + timedelta(seconds=float(ttl_value))
        return PinRecord(
            tenant=tenant,
            host=host,
            addresses=tuple(raw_address for raw_address, _ in addresses),
            created_at=_isoformat(created_at),
            expires_at=_isoformat(expires_at),
            hops=hops,
        )

    @staticmethod
    def _is_expired(record: PinRecord, at: datetime) -> bool:
        expires_at = _parse_time(record.expires_at)
        return at >= expires_at

    @staticmethod
    def _same_addresses(
        existing: PinRecord,
        observed: list[tuple[str, ipaddress._BaseAddress]],
    ) -> bool:
        existing_keys = {
            str(ipaddress.ip_address(address)) for address in existing.addresses
        }
        observed_keys = {canonical for canonical, _ in observed}
        return existing_keys == observed_keys

    @staticmethod
    def _is_pinned_peer(record: PinRecord, peer_ip: ipaddress._BaseAddress) -> bool:
        peer_key = str(peer_ip)
        return any(
            str(ipaddress.ip_address(address)) == peer_key
            for address in record.addresses
        )

    def _prune_rejections(self, events: list[str], at: datetime) -> None:
        window = timedelta(seconds=float(self.reject_window))
        active: list[str] = []
        for event in events:
            event_at = _parse_time(event)
            if at - event_at < window:
                active.append(event)
        events[:] = active

    def _restore_tenants(self, raw_tenants: dict) -> dict[str, TenantPolicy]:
        tenants: dict[str, TenantPolicy] = {}
        for raw_key, raw_policy in raw_tenants.items():
            if not isinstance(raw_key, str) or not raw_key:
                raise _snapshot_invalid({"tenant_key": raw_key})

            if isinstance(raw_policy, TenantPolicy):
                policy = raw_policy
            elif isinstance(raw_policy, dict):
                tenant = raw_policy.get("tenant", raw_key)
                if tenant != raw_key or not isinstance(tenant, str) or not tenant:
                    raise _snapshot_invalid({"tenant": raw_policy.get("tenant")})

                allow_private = raw_policy.get("allow_private")
                allow_metadata = raw_policy.get("allow_metadata")
                if not isinstance(allow_private, bool) or not isinstance(
                    allow_metadata, bool
                ):
                    raise _snapshot_invalid({"tenant_policy": raw_key})

                max_addresses = raw_policy.get(
                    "max_addresses", self.max_addresses_per_pin
                )
                if max_addresses is None:
                    max_addresses = self.max_addresses_per_pin
                if (
                    isinstance(max_addresses, bool)
                    or not isinstance(max_addresses, int)
                    or max_addresses <= 0
                ):
                    raise _snapshot_invalid({"max_addresses": max_addresses})

                policy = TenantPolicy(
                    tenant=tenant,
                    allow_private=allow_private,
                    allow_metadata=allow_metadata,
                    max_addresses=max_addresses,
                )
            else:
                raise _snapshot_invalid({"tenant_policy": raw_key})

            tenants[raw_key] = policy
        return tenants

    def _restore_pins(
        self,
        raw_pins: dict,
        tenants: dict[str, TenantPolicy],
    ) -> dict[tuple[str, str], PinRecord]:
        pins: dict[tuple[str, str], PinRecord] = {}

        for raw_key, raw_value in raw_pins.items():
            entries: list[tuple[Any, Any, Any]]
            if isinstance(raw_value, PinRecord):
                entries = [(raw_value.tenant, raw_value.host, raw_value)]
            elif isinstance(raw_value, dict) and (
                "addresses" in raw_value or "expires_at" in raw_value
            ):
                identity = _identity_from_key(raw_key)
                tenant = raw_value.get("tenant", identity[0] if identity else None)
                host = raw_value.get("host", identity[1] if identity else None)
                entries = [(tenant, host, raw_value)]
            elif isinstance(raw_value, dict):
                identity = _identity_from_key(raw_key)
                if identity is not None:
                    tenant, _host = identity
                    entries = [
                        (tenant, host, record_value)
                        for host, record_value in raw_value.items()
                    ]
                else:
                    entries = [
                        (raw_key, host, record_value)
                        for host, record_value in raw_value.items()
                    ]
            else:
                raise _snapshot_invalid({"pin": raw_key})

            for tenant, host, raw_record in entries:
                key = _key_from_parts(tenant, host)
                if key in pins:
                    raise _snapshot_invalid({"duplicate_pin": list(key)})
                if tenant not in tenants:
                    raise _snapshot_invalid({"unknown_tenant": tenant})
                if not isinstance(raw_record, (PinRecord, dict)):
                    raise _snapshot_invalid({"pin_record": list(key)})

                if isinstance(raw_record, PinRecord):
                    record = raw_record
                else:
                    addresses = self._restore_addresses(
                        raw_record.get("addresses"), key
                    )
                    created_at = raw_record.get("created_at")
                    expires_at = raw_record.get("expires_at")
                    if not isinstance(created_at, str) or not isinstance(
                        expires_at, str
                    ):
                        raise _snapshot_invalid({"pin_time": list(key)})
                    created_dt = _parse_time(created_at, snapshot=True)
                    expires_dt = _parse_time(expires_at, snapshot=True)
                    hops = self._restore_hops(raw_record.get("hops", ()), key)
                    record = PinRecord(
                        tenant=tenant,
                        host=host,
                        addresses=addresses,
                        created_at=_isoformat(created_dt),
                        expires_at=_isoformat(expires_dt),
                        hops=hops,
                    )

                if record.tenant != tenant or record.host != host:
                    raise _snapshot_invalid({"pin_identity": list(key)})
                pins[key] = record

        return pins

    @staticmethod
    def _restore_addresses(
        raw_addresses: Any, key: tuple[str, str]
    ) -> tuple[str, ...]:
        if not isinstance(raw_addresses, (list, tuple)) or not raw_addresses:
            raise _snapshot_invalid({"addresses": list(key)})
        unique: dict[str, tuple[str, ipaddress._BaseAddress]] = {}
        for raw_address in raw_addresses:
            if not isinstance(raw_address, str):
                raise _snapshot_invalid({"address": raw_address})
            try:
                ip = ipaddress.ip_address(raw_address)
            except ValueError as exc:
                raise _snapshot_invalid({"address": raw_address}) from exc
            canonical = str(ip)
            if canonical not in unique:
                unique[canonical] = (raw_address, ip)
        ordered = sorted(unique.values(), key=lambda item: int(item[1]))
        return tuple(raw_address for raw_address, _ in ordered)

    @staticmethod
    def _restore_hops(raw_hops: Any, key: tuple[str, str]) -> tuple[str, ...]:
        if raw_hops is None:
            return ()
        if not isinstance(raw_hops, (list, tuple)):
            raise _snapshot_invalid({"hops": list(key)})
        if not all(isinstance(hop, str) for hop in raw_hops):
            raise _snapshot_invalid({"hops": list(key)})
        return tuple(raw_hops)

    def _restore_rejections(
        self,
        raw_rejections: dict,
        tenants: dict[str, TenantPolicy],
    ) -> dict[tuple[str, str], list[str]]:
        rejections: dict[tuple[str, str], list[str]] = {}

        for raw_key, raw_value in raw_rejections.items():
            entries: list[tuple[Any, Any]]
            identity = _identity_from_key(raw_key)

            nested_events = None
            if isinstance(raw_value, dict):
                if "events" in raw_value or "timestamps" in raw_value:
                    nested_events = raw_value.get(
                        "events", raw_value.get("timestamps")
                    )
                elif all(
                    isinstance(value, (list, tuple)) for value in raw_value.values()
                ):
                    tenant_prefix = identity[0] if identity is not None else raw_key
                    entries = [
                        ((tenant_prefix, host), events)
                        for host, events in raw_value.items()
                    ]
                else:
                    entries = [(raw_key, raw_value)]
            else:
                entries = [(raw_key, raw_value)]

            if nested_events is not None:
                entries = [(raw_key, nested_events)]

            for entry_key, raw_events in entries:
                if isinstance(entry_key, tuple) and len(entry_key) == 2:
                    tenant, host = _key_from_parts(entry_key[0], entry_key[1])
                else:
                    event_identity = _identity_from_key(entry_key)
                    if event_identity is None:
                        raise _snapshot_invalid({"rejection_key": entry_key})
                    tenant, host = event_identity

                if tenant not in tenants:
                    raise _snapshot_invalid({"unknown_tenant": tenant})

                key = (tenant, host)
                events = self._restore_rejection_events(raw_events, key)
                rejections.setdefault(key, []).extend(events)

        return rejections

    @staticmethod
    def _restore_rejection_events(
        raw_events: Any, key: tuple[str, str]
    ) -> list[str]:
        if isinstance(raw_events, bool):
            raise _snapshot_invalid({"rejections": list(key)})

        if isinstance(raw_events, int):
            now = datetime.now(timezone.utc)
            stamp = _isoformat(now)
            return [stamp for _ in range(max(0, raw_events))]

        if isinstance(raw_events, dict):
            raw_events = raw_events.get("events", raw_events.get("timestamps"))

        if not isinstance(raw_events, (list, tuple)):
            raise _snapshot_invalid({"rejections": list(key)})

        events: list[str] = []
        for raw_event in raw_events:
            if not isinstance(raw_event, str):
                raise _snapshot_invalid({"rejection_time": raw_event})
            parsed = _parse_time(raw_event, snapshot=True)
            events.append(_isoformat(parsed))
        return events

    @staticmethod
    def _restore_stats(raw_stats: dict) -> dict[str, int]:
        stats = {key: 0 for key in _STAT_KEYS}
        for key in _STAT_KEYS:
            if key not in raw_stats:
                raise _snapshot_invalid({"stats_missing": key})
            value = raw_stats[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise _snapshot_invalid({"stat": key, "value": value})
            stats[key] = value

        for key, value in raw_stats.items():
            if key in _STAT_KEYS:
                continue
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise _snapshot_invalid({"stat": key, "value": value})
            stats[key] = value

        return stats
