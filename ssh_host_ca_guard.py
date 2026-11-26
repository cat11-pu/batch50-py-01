"""SSH host certificate trust guard: CA anchors, revocation versions, known_hosts migration."""

from __future__ import annotations

import copy
import threading
import time
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone

__all__ = [
    "HostTrustError",
    "CaRecord",
    "HostCertificate",
    "HostVerdict",
    "MigrationEntry",
    "SshHostCaGuard",
]


class HostTrustError(ValueError):
    """Raised when a trust-anchor, revocation or migration operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_SNAPSHOT_VERSION = 1
_SNAPSHOT_KEYS = frozenset({
    "version", "anchors", "revocations", "known_hosts",
    "cache", "counters", "stats",
})
_STAT_KEYS = (
    "trusted_cas",
    "untrusted_cas",
    "verified",
    "rejected_expired",
    "rejected_unknown_ca",
    "rejected_principal",
    "revoked",
    "stale_revocations",
    "migrated",
    "migration_skipped",
)
_ANCHOR_FIELDS = frozenset({
    "name", "public_key", "valid_from", "valid_to", "retired_at",
})
_HOST_ENTRY_FIELDS = frozenset({
    "host", "port", "fingerprint", "key_type", "migrated_at",
})
_VERDICT_FIELDS = frozenset({
    "host", "port", "accepted", "reason", "ca_name", "serial",
})
_CACHE_ENTRY_FIELDS = frozenset({
    "host", "port", "ca_name", "serial", "valid_from", "valid_to",
    "principals", "verdict", "cached_at", "evaluated_now",
    "revocation_version",
})


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _is_blank(value: object) -> bool:
    return not isinstance(value, str) or not value.strip()


def _as_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    else:
        raise TypeError("timestamp must be a string or datetime")
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _timestamp(value: object | None) -> str:
    if value is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(value, str):
        return value
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).isoformat()
    raise HostTrustError("HOST_INVALID_REQUEST", "now must be an ISO timestamp")


def _valid_timestamp(value: object) -> bool:
    if not isinstance(value, str):
        return False
    try:
        _as_datetime(value)
    except (TypeError, ValueError):
        return False
    return True


@dataclass(frozen=True)
class CaRecord:
    name: str
    public_key: str
    valid_from: str
    valid_to: str
    retired_at: str | None


@dataclass(frozen=True)
class HostCertificate:
    ca_name: str
    serial: str
    principals: tuple[str, ...]
    valid_from: str
    valid_to: str


@dataclass(frozen=True)
class HostVerdict:
    host: str
    port: int
    accepted: bool
    reason: str
    ca_name: str | None
    serial: str | None


@dataclass(frozen=True)
class MigrationEntry:
    host: str
    port: int
    fingerprint: str
    key_type: str
    migrated_at: str


class SshHostCaGuard:
    """Validate SSH host certificates against trusted CAs and revocation state."""

    def __init__(self, *, max_cas: int = 8, max_revocations: int = 256,
                 max_migration_entries: int = 64, cache_ttl: float = 300.0,
                 clock=None) -> None:
        self.max_cas = max_cas
        self.max_revocations = max_revocations
        self.max_migration_entries = max_migration_entries
        self.cache_ttl = cache_ttl
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()
        self._anchors: dict[str, CaRecord] = {}
        self._revocations: dict[str, set[str]] = {}
        self._known_hosts: dict[tuple[str, int], MigrationEntry] = {}
        self._cache: dict[tuple[object, ...], dict[str, object]] = {}
        self._revocation_version = 0
        self._stats = {key: 0 for key in _STAT_KEYS}

    def trust_ca(self, name: str, public_key: str, valid_from: str, valid_to: str,
                 now: str | None = None) -> CaRecord:
        current_time = _timestamp(now)
        with self._lock:
            if _is_blank(name) or _is_blank(public_key):
                raise HostTrustError("HOST_INVALID_REQUEST", "name and public_key are required")
            if not _valid_timestamp(valid_from) or not _valid_timestamp(valid_to):
                raise HostTrustError("HOST_INVALID_REQUEST", "invalid CA validity window")

            starts_at = _as_datetime(valid_from)
            expires_at = _as_datetime(valid_to)
            if expires_at <= starts_at:
                raise HostTrustError("HOST_INVALID_REQUEST", "valid_to must be after valid_from")
            if name in self._anchors:
                raise HostTrustError("HOST_CA_CONFLICT", name)
            if len(self._anchors) >= self.max_cas:
                raise HostTrustError("HOST_CAPACITY_EXCEEDED", "max_cas")

            record = CaRecord(
                name=name,
                public_key=public_key,
                valid_from=valid_from,
                valid_to=valid_to,
                retired_at=None,
            )
            self._anchors[name] = record
            self._stats["trusted_cas"] += 1
            self._cache.clear()
            return record

    def untrust_ca(self, name: str, now: str | None = None) -> bool:
        retired_at = _timestamp(now)
        with self._lock:
            record = self._anchors.get(name)
            if record is None or record.retired_at is not None:
                return False
            self._anchors[name] = replace(record, retired_at=retired_at)
            self._stats["untrusted_cas"] += 1
            self._cache.clear()
            return True

    def verify_host(self, host: str, port: int, certificate: HostCertificate,
                    now: str | None = None) -> HostVerdict:
        current_time = _timestamp(now)
        try:
            evaluated_at = _as_datetime(current_time)
        except (TypeError, ValueError) as exc:
            raise HostTrustError("HOST_INVALID_REQUEST", "invalid now timestamp") from exc
        self._validate_certificate_request(host, port, certificate)

        principals = tuple(certificate.principals)
        cache_key = (
            host,
            port,
            certificate.ca_name,
            certificate.serial,
            certificate.valid_from,
            certificate.valid_to,
            principals,
        )

        with self._lock:
            verdict = self._cached_verdict(cache_key, evaluated_at)
            if verdict is None:
                verdict = self._evaluate_host(
                    host, port, certificate, principals, evaluated_at
                )
                self._store_verdict(cache_key, verdict, evaluated_at)
            self._count_verdict(verdict)
            return verdict

    def revoke(self, serial: str, ca_name: str, version: int,
               now: str | None = None) -> int:
        _timestamp(now)
        with self._lock:
            if _is_blank(serial) or _is_blank(ca_name):
                raise HostTrustError("HOST_INVALID_REQUEST", "serial and ca_name are required")
            if not _is_int(version) or version < 0:
                raise HostTrustError("HOST_INVALID_REQUEST", "version must be a non-negative integer")
            if version < self._revocation_version:
                self._stats["stale_revocations"] += 1
                raise HostTrustError(
                    "HOST_REVOCATION_STALE",
                    {"requested": version, "current": self._revocation_version},
                )

            serials = self._revocations.get(ca_name)
            already_revoked = serials is not None and serial in serials
            if not already_revoked:
                total = sum(len(items) for items in self._revocations.values())
                if total >= self.max_revocations:
                    raise HostTrustError("HOST_CAPACITY_EXCEEDED", "max_revocations")
                if serials is None:
                    serials = set()
                    self._revocations[ca_name] = serials
                serials.add(serial)
                self._stats["revoked"] += 1

            if version > self._revocation_version:
                self._revocation_version = version
            self._cache.clear()
            return version

    def revocation_version(self) -> int:
        with self._lock:
            return self._revocation_version

    def migrate_known_hosts(self, entries, now: str | None = None) -> tuple[MigrationEntry, ...]:
        migrated_at = _timestamp(now)
        with self._lock:
            try:
                raw_entries = list(entries)
            except TypeError as exc:
                raise HostTrustError("HOST_INVALID_REQUEST", "entries must be iterable") from exc

            staged: dict[tuple[str, int], MigrationEntry] = {}
            migrated = 0
            skipped = 0

            for index, item in enumerate(raw_entries):
                host, port, fingerprint, key_type = self._parse_migration_item(item, index)
                key = (host, port)
                existing = self._known_hosts.get(key)
                pending = staged.get(key)

                if existing is not None:
                    if existing.fingerprint != fingerprint:
                        raise HostTrustError(
                            "HOST_MIGRATION_CONFLICT",
                            {"host": host, "port": port, "index": index},
                        )
                    skipped += 1
                    continue

                if pending is not None:
                    if pending.fingerprint != fingerprint:
                        raise HostTrustError(
                            "HOST_MIGRATION_CONFLICT",
                            {"host": host, "port": port, "index": index},
                        )
                    skipped += 1
                    continue

                if len(self._known_hosts) + len(staged) >= self.max_migration_entries:
                    raise HostTrustError("HOST_CAPACITY_EXCEEDED", "max_migration_entries")

                staged[key] = MigrationEntry(
                    host=host,
                    port=port,
                    fingerprint=fingerprint,
                    key_type=key_type,
                    migrated_at=migrated_at,
                )
                migrated += 1

            self._known_hosts.update(staged)
            self._stats["migrated"] += migrated
            self._stats["migration_skipped"] += skipped
            return self.known_hosts_entries()

    def known_hosts_entries(self) -> tuple[MigrationEntry, ...]:
        with self._lock:
            return tuple(sorted(
                self._known_hosts.values(),
                key=lambda entry: (entry.host, entry.port),
            ))

    def status(self) -> dict:
        with self._lock:
            return {
                "cas": len(self._anchors),
                "revocations": sum(len(serials) for serials in self._revocations.values()),
                "known_hosts": len(self._known_hosts),
                "revocation_version": self._revocation_version,
            }

    def snapshot(self) -> dict:
        with self._lock:
            cache = {}
            for key, entry in self._cache.items():
                host, port, ca_name, serial, valid_from, valid_to, principals = key
                cache[self._cache_map_key(key)] = {
                    "host": host,
                    "port": port,
                    "ca_name": ca_name,
                    "serial": serial,
                    "valid_from": valid_from,
                    "valid_to": valid_to,
                    "principals": list(principals),
                    "verdict": asdict(entry["verdict"]),
                    "cached_at": entry["cached_at"],
                    "evaluated_now": entry["evaluated_at"].isoformat(),
                    "revocation_version": entry["revocation_version"],
                }

            state = {
                "version": _SNAPSHOT_VERSION,
                "anchors": {
                    name: asdict(record) for name, record in self._anchors.items()
                },
                "revocations": {
                    ca_name: sorted(serials)
                    for ca_name, serials in self._revocations.items()
                },
                "known_hosts": {
                    f"{entry.host}\x1f{entry.port}": asdict(entry)
                    for entry in self._known_hosts.values()
                },
                "cache": cache,
                "counters": {
                    "revocation_version": self._revocation_version,
                },
                "stats": dict(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        parsed = self._parse_snapshot(state)
        with self._lock:
            if parsed["revocation_version"] < self._revocation_version:
                raise HostTrustError(
                    "HOST_REVOCATION_STALE",
                    {
                        "requested": parsed["revocation_version"],
                        "current": self._revocation_version,
                    },
                )
            self._anchors = parsed["anchors"]
            self._revocations = parsed["revocations"]
            self._known_hosts = parsed["known_hosts"]
            self._cache = parsed["cache"]
            self._revocation_version = parsed["revocation_version"]
            self._stats = parsed["stats"]

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    @staticmethod
    def _validate_certificate_request(host: str, port: int,
                                       certificate: HostCertificate) -> None:
        if _is_blank(host):
            raise HostTrustError("HOST_INVALID_REQUEST", "host is required")
        if not _is_int(port) or not 0 <= port <= 65535:
            raise HostTrustError("HOST_INVALID_REQUEST", "port is invalid")
        if not isinstance(certificate, HostCertificate):
            raise HostTrustError("HOST_INVALID_REQUEST", "certificate must be a HostCertificate")
        if _is_blank(certificate.ca_name) or _is_blank(certificate.serial):
            raise HostTrustError("HOST_INVALID_REQUEST", "ca_name and serial are required")
        if not _valid_timestamp(certificate.valid_from) or not _valid_timestamp(certificate.valid_to):
            raise HostTrustError("HOST_INVALID_REQUEST", "invalid certificate validity window")
        if not isinstance(certificate.principals, (tuple, list)) or any(
            not isinstance(principal, str) for principal in certificate.principals
        ):
            raise HostTrustError("HOST_INVALID_REQUEST", "principals must be strings")

    def _evaluate_host(self, host: str, port: int, certificate: HostCertificate,
                       principals: tuple[str, ...], at: datetime) -> HostVerdict:
        record = self._anchors.get(certificate.ca_name)
        if record is None or record.retired_at is not None or not self._record_is_active(record, at):
            return self._verdict(host, port, False, "unknown_ca", certificate)

        starts_at = _as_datetime(certificate.valid_from)
        expires_at = _as_datetime(certificate.valid_to)
        if at < starts_at or at >= expires_at:
            return self._verdict(host, port, False, "certificate_expired", certificate)

        if not any(self._principal_matches(principal, host, port) for principal in principals):
            return self._verdict(host, port, False, "principal_mismatch", certificate)

        if certificate.serial in self._revocations.get(certificate.ca_name, set()):
            return self._verdict(host, port, False, "revoked", certificate)

        return self._verdict(host, port, True, "ok", certificate)

    @staticmethod
    def _record_is_active(record: CaRecord, at: datetime) -> bool:
        try:
            return _as_datetime(record.valid_from) <= at < _as_datetime(record.valid_to)
        except (TypeError, ValueError):
            return False

    @staticmethod
    def _principal_matches(principal: object, host: str, port: int) -> bool:
        if not isinstance(principal, str) or not principal:
            return False

        pattern_host = principal
        pattern_port: int | None = None
        if ":" in principal:
            host_part, separator, port_part = principal.rpartition(":")
            looks_like_port = separator and port_part.isascii() and port_part.isdigit() and (
                ":" not in host_part
                or (host_part.startswith("[") and host_part.endswith("]"))
            )
            if looks_like_port:
                try:
                    pattern_port = int(port_part)
                except ValueError:
                    pattern_port = None
                else:
                    pattern_host = host_part[1:-1] if (
                        host_part.startswith("[") and host_part.endswith("]")
                    ) else host_part

        if pattern_port is not None:
            if pattern_port != port:
                return False
        elif port != 22:
            return False

        if pattern_host == host:
            return True

        if pattern_host.startswith("*."):
            pattern_labels = pattern_host.split(".")
            host_labels = host.split(".")
            return (
                len(pattern_labels) >= 3
                and len(host_labels) == len(pattern_labels)
                and host_labels[1:] == pattern_labels[1:]
            )
        return False

    @staticmethod
    def _verdict(host: str, port: int, accepted: bool, reason: str,
                 certificate: HostCertificate) -> HostVerdict:
        return HostVerdict(
            host=host,
            port=port,
            accepted=accepted,
            reason=reason,
            ca_name=certificate.ca_name,
            serial=certificate.serial,
        )

    def _count_verdict(self, verdict: HostVerdict) -> None:
        if verdict.accepted:
            self._stats["verified"] += 1
        elif verdict.reason == "certificate_expired":
            self._stats["rejected_expired"] += 1
        elif verdict.reason == "unknown_ca":
            self._stats["rejected_unknown_ca"] += 1
        elif verdict.reason == "principal_mismatch":
            self._stats["rejected_principal"] += 1

    def _cached_verdict(self, key: tuple[object, ...],
                        evaluated_at: datetime) -> HostVerdict | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        if entry.get("revocation_version") != self._revocation_version:
            self._cache.pop(key, None)
            return None
        if entry.get("evaluated_at") != evaluated_at:
            return None

        ttl_is_valid = True
        try:
            age = float(self._clock()) - float(entry["cached_at"])
            ttl_is_valid = age < self.cache_ttl
        except Exception:
            ttl_is_valid = False
        if not ttl_is_valid:
            self._cache.pop(key, None)
            return None
        return entry.get("verdict")

    def _store_verdict(self, key: tuple[object, ...], verdict: HostVerdict,
                       evaluated_at: datetime) -> None:
        try:
            cached_at = float(self._clock())
        except Exception:
            cached_at = 0.0
        self._cache[key] = {
            "verdict": verdict,
            "cached_at": cached_at,
            "evaluated_at": evaluated_at,
            "revocation_version": self._revocation_version,
        }

    @staticmethod
    def _cache_map_key(key: tuple[object, ...]) -> str:
        host, port, ca_name, serial, valid_from, valid_to, principals = key
        principal_text = "\x1f".join(principals)
        return f"{host}\x1e{port}\x1e{ca_name}\x1e{serial}\x1e{valid_from}\x1e{valid_to}\x1e{principal_text}"

    @staticmethod
    def _parse_migration_item(item: object, index: int) -> tuple[str, int, str, str]:
        if not isinstance(item, (tuple, list)) or len(item) != 4:
            raise HostTrustError("HOST_INVALID_REQUEST", {"index": index})
        host, port, fingerprint, key_type = item
        if _is_blank(host) or _is_blank(fingerprint) or _is_blank(key_type):
            raise HostTrustError("HOST_INVALID_REQUEST", {"index": index})
        if not _is_int(port) or not 0 <= port <= 65535:
            raise HostTrustError("HOST_INVALID_REQUEST", {"index": index})
        return host, port, fingerprint, key_type

    def _parse_snapshot(self, state: object) -> dict[str, object]:
        def invalid(detail: object) -> None:
            raise HostTrustError("HOST_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            invalid("snapshot keys")
            raise AssertionError("unreachable")
        if not _is_int(state.get("version")) or state["version"] != _SNAPSHOT_VERSION:
            invalid("version")
        for field in ("anchors", "revocations", "known_hosts", "cache", "counters", "stats"):
            if not isinstance(state[field], dict):
                invalid(field)

        stats_raw = state["stats"]
        if any(key not in stats_raw for key in _STAT_KEYS):
            invalid("stats keys")
        stats = {}
        for key in _STAT_KEYS:
            value = stats_raw[key]
            if not _is_int(value) or value < 0:
                invalid(f"stats.{key}")
            stats[key] = value

        counters = state["counters"]
        revocation_version = counters.get("revocation_version")
        if not _is_int(revocation_version) or revocation_version < 0:
            invalid("counters.revocation_version")

        anchors: dict[str, CaRecord] = {}
        for map_name, raw_record in state["anchors"].items():
            data = self._snapshot_fields(raw_record, _ANCHOR_FIELDS, invalid)
            name = data.get("name")
            if not isinstance(map_name, str) or _is_blank(map_name):
                invalid("anchors key")
            if _is_blank(name) or name != map_name or _is_blank(data.get("public_key")):
                invalid("anchor identity")
            if not _valid_timestamp(data.get("valid_from")) or not _valid_timestamp(data.get("valid_to")):
                invalid("anchor validity")
            if _as_datetime(data["valid_to"]) <= _as_datetime(data["valid_from"]):
                invalid("anchor validity window")
            retired_at = data.get("retired_at")
            if retired_at is not None and not _valid_timestamp(retired_at):
                invalid("anchor retired_at")
            anchors[name] = CaRecord(**data)

        revocations: dict[str, set[str]] = {}
        for ca_name, raw_serials in state["revocations"].items():
            if _is_blank(ca_name):
                invalid("revocations key")
            if not isinstance(raw_serials, (list, tuple, set, frozenset)):
                invalid("revocation list")
            serials: set[str] = set()
            for serial in raw_serials:
                if not isinstance(serial, str) or not serial:
                    invalid("revocation serial")
                serials.add(serial)
            if serials:
                revocations[ca_name] = serials

        known_hosts: dict[tuple[str, int], MigrationEntry] = {}
        for raw_entry in state["known_hosts"].values():
            data = self._snapshot_fields(raw_entry, _HOST_ENTRY_FIELDS, invalid)
            host = data.get("host")
            port = data.get("port")
            if _is_blank(host) or not _is_int(port) or not 0 <= port <= 65535:
                invalid("known_host identity")
            if _is_blank(data.get("fingerprint")) or _is_blank(data.get("key_type")):
                invalid("known_host key")
            if not _valid_timestamp(data.get("migrated_at")):
                invalid("known_host migrated_at")
            key = (host, port)
            if key in known_hosts:
                invalid("known_host duplicate")
            known_hosts[key] = MigrationEntry(**data)

        cache: dict[tuple[object, ...], dict[str, object]] = {}
        for raw_entry in state["cache"].values():
            data = self._snapshot_fields(raw_entry, _CACHE_ENTRY_FIELDS, invalid)
            host = data.get("host")
            port = data.get("port")
            ca_name = data.get("ca_name")
            serial = data.get("serial")
            if _is_blank(host) or not _is_int(port) or _is_blank(ca_name) or _is_blank(serial):
                invalid("cache identity")
            if not _valid_timestamp(data.get("valid_from")) or not _valid_timestamp(data.get("valid_to")):
                invalid("cache validity")
            principals_raw = data.get("principals")
            if not isinstance(principals_raw, (list, tuple)) or any(
                not isinstance(principal, str) for principal in principals_raw
            ):
                invalid("cache principals")
            verdict_data = self._snapshot_fields(
                data.get("verdict"), _VERDICT_FIELDS, invalid
            )
            if (
                verdict_data.get("host") != host
                or verdict_data.get("port") != port
                or not isinstance(verdict_data.get("accepted"), bool)
                or _is_blank(verdict_data.get("reason"))
                or verdict_data.get("ca_name") != ca_name
                or verdict_data.get("serial") != serial
            ):
                invalid("cache verdict")
            if not _is_number(data.get("cached_at")):
                invalid("cache cached_at")
            if not _valid_timestamp(data.get("evaluated_now")):
                invalid("cache evaluated_now")
            if not _is_int(data.get("revocation_version")) or data["revocation_version"] < 0:
                invalid("cache revocation_version")

            verdict = HostVerdict(**verdict_data)
            evaluated_at = _as_datetime(data["evaluated_now"])
            principals = tuple(principals_raw)
            key = (
                host, port, ca_name, serial,
                data["valid_from"], data["valid_to"], principals,
            )
            cache[key] = {
                "verdict": verdict,
                "cached_at": float(data["cached_at"]),
                "evaluated_at": evaluated_at,
                "revocation_version": data["revocation_version"],
            }

        return {
            "anchors": anchors,
            "revocations": revocations,
            "known_hosts": known_hosts,
            "cache": cache,
            "revocation_version": revocation_version,
            "stats": stats,
        }

    @staticmethod
    def _snapshot_fields(raw: object, fields: frozenset[str], invalid) -> dict:
        if hasattr(raw, "__dataclass_fields__"):
            data = asdict(raw)
        elif isinstance(raw, dict):
            data = raw
        else:
            invalid("snapshot record")
            raise AssertionError("unreachable")
        if set(data) != fields:
            invalid("snapshot fields")
        return data
