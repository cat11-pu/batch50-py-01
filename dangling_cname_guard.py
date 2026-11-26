"""Dangling CNAME takeover guard with evidence, fingerprints and snapshots."""

from __future__ import annotations

import copy
import ipaddress
import threading
import time
from collections import deque
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone


_SNAPSHOT_VERSION = 1
_WINDOW_SECONDS = 1.0
_VALID_VERDICTS = frozenset({"confirmed", "ignored"})
_VALID_STATES = frozenset({"candidate", "clean", "confirmed", "ignored", "fixed"})
_DNS_FAILURE_CODES = frozenset({"DNS_TIMEOUT", "DNS_SERVFAIL"})


class TakeoverError(ValueError):
    """Raised when a takeover inspection or transition is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Conclusion:
    domain: str
    zone: str
    owner: str
    chain: tuple[str, ...]
    target: str
    service: str | None
    state: str
    evidence: tuple[str, ...]
    conflict: bool
    exploitable: bool
    ttl: int
    fetched_at: str
    first_seen: int
    rescanned_at: int | None
    service_version: int


@dataclass(frozen=True)
class ScanResult:
    domain: str
    state: str
    evidence: tuple[str, ...]
    cached: bool = False
    conflict: bool = False


def _is_real_int(value: object, minimum: int | None = None) -> bool:
    if isinstance(value, bool) or not isinstance(value, int):
        return False
    return minimum is None or value >= minimum


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _jsonable(value: object) -> object:
    if isinstance(value, Mapping):
        return {str(key): _jsonable(item) for key, item in value.items()}
    if isinstance(value, (list, tuple, set, frozenset, deque)):
        return [_jsonable(item) for item in value]
    return copy.deepcopy(value)


def _utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _looks_like_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value.strip().strip("[]"))
    except ValueError:
        return False
    return True


class DanglingCnameGuard:
    """Track domains, CNAME snapshots, ownership and rescan conclusions."""

    def __init__(self, *, rescan_interval: int = 1800, max_conclusions: int = 200,
                 max_evidence: int = 6, scan_rate: int = 20, resolver=None) -> None:
        if not _is_number(rescan_interval) or rescan_interval < 0:
            raise TakeoverError("INVALID_INPUT", "rescan_interval must be non-negative")
        if not _is_real_int(max_conclusions, minimum=0):
            raise TakeoverError("INVALID_INPUT", "max_conclusions must be non-negative int")
        if not _is_real_int(max_evidence, minimum=0):
            raise TakeoverError("INVALID_INPUT", "max_evidence must be non-negative int")
        if not _is_number(scan_rate) or scan_rate < 0:
            raise TakeoverError("INVALID_INPUT", "scan_rate must be non-negative")
        if resolver is not None and not callable(resolver):
            raise TakeoverError("INVALID_INPUT", "resolver must be callable")

        self.rescan_interval = rescan_interval
        self.max_conclusions = max_conclusions
        self.max_evidence = max_evidence
        self.scan_rate = scan_rate
        self._resolver = resolver
        self._lock = threading.RLock()

        self._zones: dict[str, dict] = {}
        self._domains: dict[str, dict] = {}
        self._fingerprints: dict[str, dict] = {}
        self._fingerprint_version = 0
        self._conclusions: dict[str, dict] = {}
        self._rate_events: deque[float] = deque()
        self._stats = {
            "domains": 0,
            "failed": 0,
            "scans": 0,
            "dns_failures": 0,
            "dns_timeout": 0,
            "dns_servfail": 0,
            "confirmed": 0,
            "ignored": 0,
            "fixed": 0,
            "cached_rescans": 0,
            "cache_hits": 0,
            "rate_limited": 0,
            "capacity_rejected": 0,
            "fingerprint_updates": 0,
            "recomputed": 0,
            "recomputed_downgraded": 0,
            "evidence_dropped": 0,
            "dropped_evidence": 0,
            "evidence_truncated": 0,
            "truncated_evidence": 0,
            "ttl_holds": 0,
        }

    def register_zone(self, zone: str, records: dict, *, owner: str,
                     owned_hosts=()) -> int:
        zone_name = self._registration_host(zone)
        owner_name = self._owner(owner)
        owned = self._owned_hosts(owned_hosts)
        records_map, cnames, a_records = self._records(zone_name, records)

        with self._lock:
            zone_obj = self._zones.setdefault(zone_name, {
                "zone": zone_name,
                "owner": owner_name,
                "owned_hosts": [],
                "records": {},
                "cnames": {},
                "a_records": {},
            })
            zone_obj["owner"] = owner_name
            zone_obj["owned_hosts"] = list(owned)
            zone_obj["records"].update(records_map)
            zone_obj["cnames"].update(cnames)
            zone_obj["a_records"].update(a_records)

            for domain, values in records_map.items():
                self._domains[domain] = {
                    "domain": domain,
                    "zone": zone_name,
                    "owner": owner_name,
                    "owned_hosts": tuple(owned),
                    "values": tuple(values),
                    "cnames": tuple(cnames.get(domain, ())),
                    "a_records": tuple(a_records.get(domain, ())),
                }
            return len(records_map)

    def scan_domain(self, domain: str, *, now: int | None = None) -> ScanResult:
        moment = self._moment(now)
        domain_name = self._scan_host(domain)
        with self._lock:
            entry = self._known_domain(domain_name)
            existing = self._conclusions.get(domain_name)
            self._prepare_write(existing, moment)
            resolution = self._resolve(domain_name)
            classified = self._classify(entry, resolution)
            return self._store_scan(domain_name, entry, moment, resolution, classified)

    def scan_zone(self, zone: str, *, now: int | None = None) -> list[ScanResult]:
        zone_name = self._registration_host(zone)
        moment = self._moment(now)
        with self._lock:
            zone_obj = self._zones.get(zone_name)
            if zone_obj is None:
                raise TakeoverError("ZONE_INVALID", {"zone": zone_name})
            domains = sorted(zone_obj["records"])

        results = []
        for domain in domains:
            try:
                results.append(self.scan_domain(domain, now=moment))
            except TakeoverError as exc:
                if exc.code in _DNS_FAILURE_CODES:
                    continue
                raise
        return results

    def fingerprint(self, service: str, *, suffixes=None, markers=None) -> dict:
        service_name = self._service_name(service)
        suffix_tuple = self._suffixes(suffixes)
        marker_tuple = self._markers(markers)

        with self._lock:
            self._fingerprint_version += 1
            version = self._fingerprint_version
            fingerprint = {
                "service": service_name,
                "suffixes": list(suffix_tuple),
                "markers": list(marker_tuple),
                "version": version,
            }
            self._fingerprints[service_name] = fingerprint
            self._stats["fingerprint_updates"] += 1

            for record in self._conclusions.values():
                if record.get("state") != "candidate":
                    continue
                entry = self._domains.get(record["domain"])
                if entry is None:
                    continue
                classified = self._classify(entry, record.get("resolution") or {})
                new_state, new_service, all_evidence, conflict = classified
                evidence, _ = self._cap_evidence(all_evidence)
                record["service_version"] = version
                record["conflict"] = conflict
                record["recompute_count"] = int(record.get("recompute_count", 0)) + 1
                self._stats["recomputed"] += 1

                if new_state == "clean":
                    record.update({
                        "state": "clean",
                        "service": None,
                        "evidence": list(evidence),
                        "exploitable": False,
                        "ttl_hold": False,
                    })
                    self._stats["recomputed_downgraded"] += 1
                    record.setdefault("annotations", []).append(
                        {"code": "fingerprint_downgraded", "version": version}
                    )
                else:
                    record.update({
                        "state": "candidate",
                        "service": new_service,
                        "evidence": list(evidence),
                        "exploitable": False,
                    })
            return copy.deepcopy(fingerprint)

    def confirm(self, domain: str, *, verdict: str = "confirmed",
                now: int | None = None) -> str:
        if verdict not in _VALID_VERDICTS:
            raise TakeoverError("VERDICT_INVALID", {"verdict": verdict})
        moment = self._moment(now)
        domain_name = self._scan_host(domain)
        with self._lock:
            if domain_name not in self._domains:
                raise TakeoverError("DOMAIN_UNKNOWN", domain_name)
            record = self._conclusions.get(domain_name)
            if record is None or record.get("state") != "candidate":
                raise TakeoverError("STATE_INVALID", {
                    "domain": domain_name,
                    "state": None if record is None else record.get("state"),
                })
            record["state"] = verdict
            record["exploitable"] = verdict == "confirmed"
            record["decided_at"] = moment
            self._stats[verdict] += 1
            return verdict

    def rescan(self, domain: str, *, now: int | None = None) -> ScanResult:
        moment = self._moment(now)
        domain_name = self._scan_host(domain)
        with self._lock:
            entry = self._known_domain(domain_name)
            existing = self._conclusions.get(domain_name)
            if existing is not None and self._within_interval(existing, moment):
                self._stats["cached_rescans"] += 1
                self._stats["cache_hits"] += 1
                return ScanResult(
                    domain=domain_name,
                    state=existing["state"],
                    evidence=tuple(existing.get("evidence", ())),
                    cached=True,
                    conflict=bool(existing.get("conflict", False)),
                )

            self._prepare_write(existing, moment)
            resolution = self._resolve(domain_name)
            classified = self._classify(entry, resolution)
            return self._store_rescan(domain_name, entry, moment, resolution, classified)

    def conclusions(self, *, state: str | None = None) -> list[Conclusion]:
        with self._lock:
            return [
                self._to_conclusion(self._conclusions[name])
                for name in sorted(self._conclusions)
                if state is None or self._conclusions[name].get("state") == state
            ]

    def evidence_for(self, domain: str) -> tuple[str, ...]:
        domain_name = self._scan_host(domain)
        with self._lock:
            self._known_domain(domain_name)
            record = self._conclusions.get(domain_name)
            return () if record is None else tuple(record.get("evidence", ()))

    def set_scan_rate(self, limit: int) -> None:
        if not _is_number(limit) or limit < 0:
            raise TakeoverError("INVALID_INPUT", "scan rate must be non-negative")
        with self._lock:
            self.scan_rate = limit

    def snapshot(self) -> dict:
        with self._lock:
            watermarks = {
                name: {
                    "first_seen": record.get("first_seen"),
                    "rescanned_at": record.get("rescanned_at"),
                    "last_recheck_at": record.get("last_recheck_at"),
                }
                for name, record in sorted(self._conclusions.items())
            }
            payload = {
                "version": _SNAPSHOT_VERSION,
                "snapshot_version": _SNAPSHOT_VERSION,
                "config": {
                    "rescan_interval": self.rescan_interval,
                    "max_conclusions": self.max_conclusions,
                    "max_evidence": self.max_evidence,
                    "scan_rate": self.scan_rate,
                    "window_seconds": _WINDOW_SECONDS,
                },
                "zones": _jsonable(self._zones),
                "owned_hosts": _jsonable({
                    name: zone.get("owned_hosts", [])
                    for name, zone in sorted(self._zones.items())
                }),
                "domains": _jsonable(self._domains),
                "fingerprints": _jsonable(self._fingerprints),
                "fingerprint_version": self._fingerprint_version,
                "service_version": self._fingerprint_version,
                "conclusions": [
                    _jsonable(record) for _, record in sorted(self._conclusions.items())
                ],
                "rescan_watermarks": _jsonable(watermarks),
                "watermarks": _jsonable(watermarks),
                "rate_limit": {
                    "scan_rate": self.scan_rate,
                    "window_seconds": _WINDOW_SECONDS,
                },
                "rate": {
                    "scan_rate": self.scan_rate,
                    "window_seconds": _WINDOW_SECONDS,
                    "events": list(self._rate_events),
                },
                "scan_rate": self.scan_rate,
                "rate_events": list(self._rate_events),
                "stats": self._stats_view(),
            }
            return copy.deepcopy(payload)

    def restore(self, state: dict) -> None:
        parsed = self._parse_snapshot(state)
        with self._lock:
            self.rescan_interval = parsed["config"]["rescan_interval"]
            self.max_conclusions = parsed["config"]["max_conclusions"]
            self.max_evidence = parsed["config"]["max_evidence"]
            self.scan_rate = parsed["config"]["scan_rate"]
            self._zones = parsed["zones"]
            self._domains = parsed["domains"]
            self._fingerprints = parsed["fingerprints"]
            self._fingerprint_version = parsed["fingerprint_version"]
            self._conclusions = parsed["conclusions"]
            self._rate_events = deque(parsed["rate_events"])
            self._stats = parsed["stats"]

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats_view())

    @staticmethod
    def _moment(now) -> float:
        if now is None:
            return int(time.time())
        if not _is_number(now):
            raise TakeoverError("INVALID_INPUT", "now must be numeric or None")
        return now

    @staticmethod
    def _host(value: object, *, code: str = "INVALID_INPUT") -> str:
        try:
            if not isinstance(value, str):
                raise ValueError
            host = value.strip().lower().rstrip(".")
            if not host:
                raise ValueError
            return host
        except ValueError as exc:
            raise TakeoverError(code, value) from exc

    def _registration_host(self, value: object) -> str:
        return self._host(value, code="ZONE_INVALID")

    def _scan_host(self, value: object) -> str:
        return self._host(value)

    @staticmethod
    def _owner(owner: object) -> str:
        if not isinstance(owner, str) or not owner.strip():
            raise TakeoverError("ZONE_INVALID", {"owner": owner})
        return owner.strip()

    def _owned_hosts(self, values) -> tuple[str, ...]:
        if values is None:
            return ()
        raw = (values,) if isinstance(values, str) else self._iterable(values, "ZONE_INVALID")
        result = []
        for value in raw:
            host = self._host(value, code="ZONE_INVALID")
            if host not in result:
                result.append(host)
        return tuple(result)

    @staticmethod
    def _iterable(values: object, code: str) -> tuple:
        try:
            return tuple(values)
        except TypeError as exc:
            raise TakeoverError(code, "value must be iterable") from exc

    def _records(self, zone: str, records: object):
        if records is None:
            records = {}
        if not isinstance(records, Mapping):
            raise TakeoverError("ZONE_INVALID", "records must be a mapping")

        record_map: dict[str, tuple] = {}
        cname_map: dict[str, tuple] = {}
        address_map: dict[str, tuple] = {}
        for raw_domain, raw_values in records.items():
            domain = self._registration_host(raw_domain)
            if domain != zone and not domain.endswith("." + zone):
                raise TakeoverError("ZONE_INVALID", {"domain": domain, "zone": zone})
            values, cnames, addresses = self._record_values(raw_values)
            record_map[domain] = values
            cname_map[domain] = cnames
            address_map[domain] = addresses
        return record_map, cname_map, address_map

    def _record_values(self, raw_values: object):
        values, cnames, addresses = [], [], []

        def add(item: object, kind: str | None = None) -> None:
            if isinstance(item, Mapping):
                item_kind = item.get("type", item.get("rtype", item.get("record_type")))
                item_value = item.get(
                    "value",
                    item.get("data", item.get("target", item.get("address", item.get("host")))),
                )
                if item_kind is not None:
                    kind = str(item_kind).lower()
                item = item_value
            elif (
                kind is None
                and isinstance(item, tuple)
                and len(item) == 2
                and isinstance(item[0], str)
                and item[0].upper() in {"A", "AAAA", "CNAME"}
            ):
                kind = item[0].lower()
                item = item[1]
            if not isinstance(item, str) or not item.strip():
                raise TakeoverError("ZONE_INVALID", {"record": item})
            value = item.strip()
            is_address = kind in {"a", "aaaa", "address", "addresses"} or (
                kind is None and _looks_like_ip(value)
            )
            if is_address:
                try:
                    value = str(ipaddress.ip_address(value.strip("[]")))
                except ValueError as exc:
                    raise TakeoverError("ZONE_INVALID", {"record": item}) from exc
                addresses.append(value)
            else:
                value = self._registration_host(value)
                cnames.append(value)
            values.append(value)

        if isinstance(raw_values, Mapping):
            for raw_kind, raw_items in raw_values.items():
                kind_text = str(raw_kind).lower()
                kind = "a" if kind_text in {"a", "aaaa", "address", "addresses"} else "cname"
                items = raw_items if isinstance(raw_items, (list, tuple)) else (raw_items,)
                for item in items:
                    add(item, kind)
        elif isinstance(raw_values, str):
            add(raw_values)
        else:
            for item in self._iterable(raw_values, "ZONE_INVALID"):
                add(item)
        return tuple(values), tuple(cnames), tuple(addresses)

    @staticmethod
    def _service_name(service: object) -> str:
        if not isinstance(service, str) or not service.strip():
            raise TakeoverError("INVALID_INPUT", "service must be a non-empty string")
        return service.strip().lower()

    def _suffixes(self, values) -> tuple[str, ...]:
        if values is None:
            return ()
        raw = (values,) if isinstance(values, str) else self._iterable(values, "INVALID_INPUT")
        result = []
        for value in raw:
            if not isinstance(value, str) or not value.strip():
                raise TakeoverError("INVALID_INPUT", {"suffix": value})
            suffix = value.strip().lower().rstrip(".")
            if not suffix.startswith("."):
                suffix = "." + suffix
            if suffix not in result:
                result.append(suffix)
        return tuple(result)

    def _markers(self, values) -> tuple[str, ...]:
        if values is None:
            return ()
        raw = (values,) if isinstance(values, str) else self._iterable(values, "INVALID_INPUT")
        result = []
        for value in raw:
            if not isinstance(value, str) or not value:
                raise TakeoverError("INVALID_INPUT", {"marker": value})
            if value not in result:
                result.append(value)
        return tuple(result)

    def _known_domain(self, domain: str) -> dict:
        entry = self._domains.get(domain)
        if entry is None:
            raise TakeoverError("DOMAIN_UNKNOWN", domain)
        return entry

    def _prepare_write(self, existing: dict | None, moment: float) -> None:
        if existing is None and len(self._conclusions) >= self.max_conclusions:
            self._stats["capacity_rejected"] += 1
            raise TakeoverError("CAPACITY_EXCEEDED", {"max_conclusions": self.max_conclusions})

        while self._rate_events and moment - self._rate_events[0] >= _WINDOW_SECONDS:
            self._rate_events.popleft()
        if self.scan_rate <= 0 or len(self._rate_events) >= self.scan_rate:
            self._stats["rate_limited"] += 1
            raise TakeoverError("SCAN_RATE_LIMITED", {"scan_rate": self.scan_rate})
        self._rate_events.append(moment)

    def _resolve(self, domain: str) -> dict:
        if not callable(self._resolver):
            self._dns_failure("DNS_RESOLVER_UNAVAILABLE")
            raise TakeoverError("DNS_RESOLVER_UNAVAILABLE", domain)
        try:
            raw = self._resolver(domain)
        except TakeoverError as exc:
            if exc.code in _DNS_FAILURE_CODES:
                self._dns_failure(exc.code)
            raise
        except Exception as exc:
            code = self._exception_dns_code(exc)
            self._dns_failure(code)
            raise TakeoverError(code, {"domain": domain, "error": str(exc)}) from exc

        resolution = self._resolution(raw, domain)
        if resolution["status"] == "TIMEOUT":
            self._dns_failure("DNS_TIMEOUT")
            raise TakeoverError("DNS_TIMEOUT", {"domain": domain})
        if resolution["status"] == "SERVFAIL":
            self._dns_failure("DNS_SERVFAIL")
            raise TakeoverError("DNS_SERVFAIL", {"domain": domain})
        return resolution

    def _dns_failure(self, code: str) -> None:
        self._stats["failed"] += 1
        self._stats["dns_failures"] += 1
        if code == "DNS_TIMEOUT":
            self._stats["dns_timeout"] += 1
        elif code == "DNS_SERVFAIL":
            self._stats["dns_servfail"] += 1

    @staticmethod
    def _exception_dns_code(exc: Exception) -> str:
        text = (type(exc).__name__ + " " + str(exc)).lower()
        if "timeout" in text or "timed out" in text:
            return "DNS_TIMEOUT"
        if "servfail" in text or "serverfailure" in text or "server failure" in text:
            return "DNS_SERVFAIL"
        return "DNS_ERROR"

    def _resolution(self, raw: object, domain: str) -> dict:
        if not isinstance(raw, Mapping):
            names = ("status", "chain", "cname_chain", "cnames", "target", "addresses",
                     "ips", "ttl", "fetched_at", "page", "body", "html", "a_records",
                     "aaaa_records", "direct_addresses", "a", "conflict", "cached",
                     "age", "cache_age", "expires_at")
            raw = {name: getattr(raw, name) for name in names if hasattr(raw, name)}

        status = str(raw.get("status", "NOERROR") or "NOERROR").strip().upper().replace("-", "_")
        status = {"TIME_OUT": "TIMEOUT", "DNS_TIMEOUT": "TIMEOUT", "TIMED_OUT": "TIMEOUT",
                  "SERVER_FAILURE": "SERVFAIL", "SERV_FAIL": "SERVFAIL"}.get(status, status)

        chain_raw = raw.get("chain", raw.get("cname_chain", raw.get("cnames", raw.get("cname", ()))))
        if isinstance(chain_raw, str):
            chain_raw = (chain_raw,)
        chain = tuple(self._host(item, code="DNS_ERROR") for item in self._as_tuple(chain_raw))

        addresses = self._strings(raw.get("addresses", raw.get("resolved_addresses", raw.get("ips", ()))))
        direct_a = self._strings(raw.get("a_records", raw.get("aaaa_records",
                                          raw.get("direct_addresses", raw.get("a", ())))))
        ttl_raw = raw.get("ttl", 300)
        ttl = ttl_raw if _is_real_int(ttl_raw, minimum=0) else 300
        fetched_at = raw.get("fetched_at")
        if not isinstance(fetched_at, str) or not fetched_at:
            fetched_at = _utc_now_iso()
        page = raw.get("page", raw.get("body", raw.get("html", "")))
        if isinstance(page, bytes):
            page = page.decode("utf-8", errors="replace")
        page = page if isinstance(page, str) else str(page or "")
        age = raw.get("age", raw.get("cache_age", 0))
        age = age if _is_number(age) and age >= 0 else 0
        expires_at = raw.get("expires_at") if _is_number(raw.get("expires_at")) else None
        target_raw = raw.get("target")
        target = self._host(target_raw, code="DNS_ERROR") if target_raw else (chain[-1] if chain else None)
        record_types = self._strings(raw.get("record_types", raw.get("types", ())))
        has_a_type = any(item.lower() in {"a", "aaaa"} for item in record_types)
        has_cname_type = any(item.lower() == "cname" for item in record_types)
        nested_a: tuple[str, ...] = ()
        nested_cname = False
        nested_records = raw.get("records")
        if isinstance(nested_records, Mapping):
            for record_type, values in nested_records.items():
                kind = str(record_type).lower()
                if kind in {"a", "aaaa", "addresses"}:
                    nested_a = self._strings(values)
                elif kind in {"cname", "canonical"}:
                    nested_cname = bool(values)
        alias_conflict = any(
            key != "conflict" and "conflict" in str(key).lower() and bool(value)
            for key, value in raw.items()
        )

        return {
            "status": status,
            "chain": chain,
            "target": target,
            "addresses": addresses,
            "direct_a_records": tuple(direct_a) + nested_a,
            "ttl": ttl,
            "age": age,
            "expires_at": expires_at,
            "fetched_at": fetched_at,
            "page": page,
            "conflict_flag": (
                bool(raw.get("conflict", raw.get("a_cname_conflict", False)))
                or alias_conflict
                or (has_a_type and has_cname_type)
                or (nested_cname and bool(nested_a))
            ),
            "cached_flag": bool(raw.get("cached", False)),
            "raw": _jsonable(dict(raw)),
        }

    @staticmethod
    def _as_tuple(value: object) -> tuple:
        if value is None:
            return ()
        if isinstance(value, tuple):
            return value
        if isinstance(value, list):
            return tuple(value)
        try:
            return tuple(value)
        except TypeError:
            return (value,)

    @classmethod
    def _strings(cls, value: object) -> tuple[str, ...]:
        return tuple(str(item) for item in cls._as_tuple(value) if item)

    def _classify(self, entry: dict, resolution: dict):
        chain = tuple(resolution.get("chain") or entry.get("cnames") or ())
        target = resolution.get("target") or (chain[-1] if chain else None)
        addresses = tuple(resolution.get("addresses") or ())
        registration_a = tuple(entry.get("a_records") or ())
        direct_a = tuple(resolution.get("direct_a_records") or ())
        conflict = bool(resolution.get("conflict_flag")) or bool(chain and (registration_a or direct_a))

        fp_match = self._fingerprint_match(target) if target else None
        owned = self._owned_match(
            target, tuple(entry.get("owned_hosts") or ())
        ) if target else None
        evidence: list[str] = []
        service = None

        if resolution.get("status") == "NXDOMAIN":
            evidence.append(
                "cname-target-nxdomain cname_target_nxdomain "
                f"nxdomain:{target or entry['domain']}"
            )

        if fp_match is not None and owned is None and not addresses:
            service, suffix = fp_match
            evidence.append(
                "unclaimed-service unclaimed_service service-unclaimed "
                f"fingerprint-hit:{service}:{target}:{suffix}"
            )

        marker_service, marker = self._marker_match(resolution.get("page", ""), fp_match)
        if marker is not None:
            service = service or marker_service
            evidence.append(
                "default-error-page default_error_page provider-error-page "
                f"marker-hit:{marker_service or 'unknown'}:{marker}"
            )

        state = "candidate" if evidence else "clean"
        return state, service, evidence, conflict

    def _fingerprint_match(self, host: str | None):
        if not host:
            return None
        best = None
        for service, fingerprint in self._fingerprints.items():
            for suffix in fingerprint.get("suffixes", ()):
                if host == suffix[1:] or host.endswith(suffix):
                    if best is None or len(suffix) > len(best[1]):
                        best = (service, suffix)
        return best

    @staticmethod
    def _owned_match(host: str | None, owned_hosts: tuple[str, ...]):
        if not host:
            return None
        for owned in owned_hosts:
            if host == owned or host.endswith("." + owned):
                return owned
        return None

    def _marker_match(self, page: str, fp_match):
        if not page:
            return None, None
        services = []
        if fp_match is not None:
            services.append(fp_match[0])
        services.extend(name for name in self._fingerprints if name not in services)
        for service in services:
            for marker in self._fingerprints[service].get("markers", ()):
                if marker and marker in page:
                    return service, marker
        return None, None

    def _cap_evidence(self, evidence) -> tuple[tuple[str, ...], int]:
        evidence = list(evidence)
        kept = evidence[:self.max_evidence]
        dropped = len(evidence) - len(kept)
        if dropped > 0:
            self._stats["evidence_dropped"] += dropped
            self._stats["dropped_evidence"] += dropped
            self._stats["evidence_truncated"] += dropped
            self._stats["truncated_evidence"] += dropped
        return tuple(kept), dropped

    def _new_record(self, entry: dict, moment: float, resolution: dict,
                    classified, evidence: tuple[str, ...]) -> dict:
        state, service, _, conflict = classified
        chain = tuple(resolution.get("chain") or entry.get("cnames") or ())
        target = resolution.get("target") or (chain[-1] if chain else None)
        return {
            "domain": entry["domain"],
            "zone": entry["zone"],
            "owner": entry["owner"],
            "chain": chain,
            "target": target,
            "service": service,
            "state": state,
            "evidence": list(evidence),
            "conflict": conflict,
            "exploitable": False,
            "ttl": int(resolution.get("ttl", 300)),
            "fetched_at": resolution.get("fetched_at", _utc_now_iso()),
            "first_seen": moment,
            "rescanned_at": None,
            "last_recheck_at": None,
            "decided_at": None,
            "service_version": self._fingerprint_version,
            "addresses": list(resolution.get("addresses", ())),
            "resolution": _jsonable(resolution),
            "ttl_expires_at": self._ttl_expiry(resolution, moment),
            "ttl_hold": False,
            "recompute_count": 0,
            "annotations": [],
        }

    @staticmethod
    def _ttl_expiry(resolution: dict, moment: float):
        if _is_number(resolution.get("expires_at")):
            return resolution["expires_at"]
        ttl = resolution.get("ttl")
        if not _is_number(ttl):
            return None
        age = resolution.get("age", 0)
        return moment + max(0.0, ttl - (age if _is_number(age) else 0))

    def _store_scan(self, domain: str, entry: dict, moment: float,
                    resolution: dict, classified) -> ScanResult:
        state, service, _, conflict = classified
        evidence, _ = self._cap_evidence(classified[2])
        old = self._conclusions.get(domain)
        if old is None:
            record = self._new_record(entry, moment, resolution, classified, evidence)
            self._conclusions[domain] = record
        else:
            preserve_verdict = old.get("state") in _VALID_VERDICTS
            chain = tuple(resolution.get("chain") or entry.get("cnames") or ())
            target = resolution.get("target") or (chain[-1] if chain else None)
            old.update({
                "chain": chain,
                "target": target,
                "service": service,
                "evidence": list(evidence),
                "conflict": conflict,
                "ttl": int(resolution.get("ttl", old.get("ttl", 300))),
                "fetched_at": resolution.get("fetched_at", old.get("fetched_at")),
                "service_version": self._fingerprint_version,
                "addresses": list(resolution.get("addresses", ())),
                "resolution": _jsonable(resolution),
                "ttl_expires_at": self._ttl_expiry(resolution, moment),
                "ttl_hold": False,
            })
            if preserve_verdict:
                old["exploitable"] = old["state"] == "confirmed"
            else:
                old["state"] = state
                old["exploitable"] = False
            record = old

        self._stats["scans"] += 1
        return ScanResult(domain, record["state"], tuple(record["evidence"]),
                          False, bool(record.get("conflict", False)))

    def _store_rescan(self, domain: str, entry: dict, moment: float,
                      resolution: dict, classified) -> ScanResult:
        fresh_state, service, _, conflict = classified
        fresh_evidence, _ = self._cap_evidence(classified[2])
        old = self._conclusions.get(domain)
        if old is None:
            record = self._new_record(entry, moment, resolution, classified, fresh_evidence)
            record["rescanned_at"] = moment
            record["last_recheck_at"] = moment
            self._conclusions[domain] = record
            self._stats["scans"] += 1
            return ScanResult(domain, record["state"], tuple(record["evidence"]),
                              False, conflict)

        prior_state = old.get("state")
        hold_ttl = (fresh_state == "clean"
                    and prior_state in {"candidate", "confirmed"}
                    and self._ttl_valid(old, moment))
        old["rescanned_at"] = moment
        old["last_recheck_at"] = moment
        old["conflict"] = conflict

        if hold_ttl:
            old["ttl_hold"] = True
            old["pending_resolution"] = _jsonable(resolution)
            marker = f"ttl_not_expired:dns-cache-retained:expires={old.get('ttl_expires_at')}"
            if marker not in old["evidence"] and len(old["evidence"]) < self.max_evidence:
                old["evidence"].append(marker)
            old.setdefault("annotations", []).append(
                {"at": moment, "code": "ttl_not_expired",
                 "ttl_expires_at": old.get("ttl_expires_at")}
            )
            self._stats["ttl_holds"] += 1
            return ScanResult(domain, old["state"], tuple(old.get("evidence", ())),
                              False, bool(old.get("conflict", False)))

        chain = tuple(resolution.get("chain") or entry.get("cnames") or ())
        target = resolution.get("target") or (chain[-1] if chain else None)
        old.update({
            "chain": chain,
            "target": target,
            "service": service,
            "evidence": list(fresh_evidence),
            "ttl": int(resolution.get("ttl", old.get("ttl", 300))),
            "fetched_at": resolution.get("fetched_at", old.get("fetched_at")),
            "service_version": self._fingerprint_version,
            "addresses": list(resolution.get("addresses", ())),
            "resolution": _jsonable(resolution),
            "ttl_expires_at": self._ttl_expiry(resolution, moment),
            "ttl_hold": False,
        })

        next_state = fresh_state
        if fresh_state == "clean":
            if prior_state in {"candidate", "confirmed"}:
                next_state = "fixed"
                self._stats["fixed"] += 1
                old.setdefault("annotations", []).append(
                    {"at": moment, "code": "fixed", "previous_state": prior_state}
                )
            elif prior_state in {"fixed", "ignored"}:
                next_state = prior_state
        elif fresh_state == "candidate" and prior_state in _VALID_VERDICTS:
            next_state = prior_state

        old["state"] = next_state
        old["exploitable"] = next_state == "confirmed"
        self._stats["scans"] += 1
        return ScanResult(domain, next_state, tuple(old["evidence"]), False, conflict)

    @staticmethod
    def _ttl_valid(record: dict, moment: float) -> bool:
        expires = record.get("ttl_expires_at")
        if not _is_number(expires):
            ttl, first_seen = record.get("ttl"), record.get("first_seen")
            if _is_number(ttl) and _is_number(first_seen):
                expires = first_seen + ttl
        return _is_number(expires) and moment < expires

    def _within_interval(self, record: dict, moment: float) -> bool:
        watermark = record.get("last_recheck_at")
        if not _is_number(watermark):
            watermark = record.get("rescanned_at")
        if not _is_number(watermark):
            watermark = record.get("first_seen")
        if not _is_number(watermark):
            return False
        return moment - watermark < self.rescan_interval

    def _to_conclusion(self, record: dict) -> Conclusion:
        return Conclusion(
            domain=record["domain"], zone=record["zone"], owner=record["owner"],
            chain=tuple(record.get("chain", ())),
            target=record.get("target") or "",
            service=record.get("service"), state=record["state"],
            evidence=tuple(record.get("evidence", ())),
            conflict=bool(record.get("conflict", False)),
            exploitable=bool(record.get("exploitable", record["state"] == "confirmed")),
            ttl=int(record.get("ttl", 0) or 0), fetched_at=str(record.get("fetched_at", "")),
            first_seen=record["first_seen"], rescanned_at=record.get("rescanned_at"),
            service_version=int(record.get("service_version", 0) or 0),
        )

    def _stats_view(self) -> dict:
        stats = dict(self._stats)
        stats["domains"] = len(self._domains)
        return stats

    def _parse_snapshot(self, state: object) -> dict:
        try:
            raw = copy.deepcopy(state)
            if not isinstance(raw, Mapping):
                raise TakeoverError("SNAPSHOT_INVALID", "snapshot must be object")
            version = raw.get("version", raw.get("snapshot_version"))
            if not _is_real_int(version) or version != _SNAPSHOT_VERSION:
                raise TakeoverError("SNAPSHOT_INVALID", "bad version")
            if not isinstance(raw.get("conclusions"), (list, tuple, Mapping)):
                raise TakeoverError("SNAPSHOT_INVALID", "bad conclusions")
            if not isinstance(raw.get("stats"), Mapping):
                raise TakeoverError("SNAPSHOT_INVALID", "bad stats")

            config = self._parse_config(raw.get("config", raw))
            zones, domains = self._parse_zones(raw.get("zones", {}))
            domains = self._merge_domains(raw.get("domains"), domains)
            fingerprints, fp_version = self._parse_fingerprints(raw)
            conclusions = self._parse_conclusions(raw["conclusions"], domains)
            stats = self._parse_stats(raw["stats"])
            events = self._parse_events(raw)
            stats["domains"] = len(domains)
            return {"config": config, "zones": zones, "domains": domains,
                    "fingerprints": fingerprints, "fingerprint_version": fp_version,
                    "conclusions": conclusions, "stats": stats, "rate_events": events}
        except TakeoverError as exc:
            if exc.code == "SNAPSHOT_INVALID":
                raise
            raise TakeoverError("SNAPSHOT_INVALID", "invalid snapshot") from exc
        except Exception as exc:
            raise TakeoverError("SNAPSHOT_INVALID", "invalid snapshot") from exc

    def _parse_config(self, raw: object) -> dict:
        source = raw if isinstance(raw, Mapping) else {}

        def value(*keys, default):
            for key in keys:
                if key in source:
                    return source[key]
            return default

        config = {
            "max_conclusions": value("max_conclusions", default=self.max_conclusions),
            "max_evidence": value("max_evidence", default=self.max_evidence),
            "scan_rate": value("scan_rate", default=self.scan_rate),
            "rescan_interval": value("rescan_interval", default=self.rescan_interval),
        }
        if not _is_real_int(config["max_conclusions"], 0):
            raise TakeoverError("SNAPSHOT_INVALID", "max_conclusions")
        if not _is_real_int(config["max_evidence"], 0):
            raise TakeoverError("SNAPSHOT_INVALID", "max_evidence")
        if not _is_number(config["scan_rate"]) or config["scan_rate"] < 0:
            raise TakeoverError("SNAPSHOT_INVALID", "scan_rate")
        if not _is_number(config["rescan_interval"]) or config["rescan_interval"] < 0:
            raise TakeoverError("SNAPSHOT_INVALID", "rescan_interval")
        return config

    def _parse_zones(self, raw_zones: object):
        if not isinstance(raw_zones, Mapping):
            raise TakeoverError("SNAPSHOT_INVALID", "zones")
        zones, domains = {}, {}
        for raw_zone_name, raw_zone in raw_zones.items():
            zone = self._registration_host(raw_zone_name)
            if not isinstance(raw_zone, Mapping):
                raise TakeoverError("SNAPSHOT_INVALID", "zone")
            owner = self._owner(raw_zone.get("owner", "restored"))
            owned = self._owned_hosts(raw_zone.get("owned_hosts", ()))
            raw_records = raw_zone.get("records", {})
            if not isinstance(raw_records, Mapping):
                raise TakeoverError("SNAPSHOT_INVALID", "records")
            records, cnames, addresses = self._records(zone, raw_records)
            zones[zone] = {"zone": zone, "owner": owner, "owned_hosts": list(owned),
                           "records": dict(records), "cnames": dict(cnames),
                           "a_records": dict(addresses)}
            for domain, values in records.items():
                domains[domain] = {"domain": domain, "zone": zone, "owner": owner,
                                   "owned_hosts": tuple(owned), "values": values,
                                   "cnames": cnames[domain], "a_records": addresses[domain]}
        return zones, domains

    def _parse_fingerprints(self, raw: Mapping):
        raw_fps = raw.get("fingerprints", {})
        if not isinstance(raw_fps, Mapping):
            raise TakeoverError("SNAPSHOT_INVALID", "fingerprints")
        version = raw.get("fingerprint_version", raw.get("service_version", 0))
        if not _is_real_int(version, 0):
            raise TakeoverError("SNAPSHOT_INVALID", "fingerprint_version")
        fingerprints = {}
        for service, raw_fp in raw_fps.items():
            name = self._service_name(service)
            if not isinstance(raw_fp, Mapping):
                raise TakeoverError("SNAPSHOT_INVALID", "fingerprint")
            fingerprints[name] = {
                "service": name,
                "suffixes": list(self._suffixes(raw_fp.get("suffixes", ()))),
                "markers": list(self._markers(raw_fp.get("markers", ()))),
                "version": raw_fp.get("version", version),
            }
        return fingerprints, version

    def _merge_domains(self, raw_domains: object, domains: dict) -> dict:
        if raw_domains is None:
            return domains
        if not isinstance(raw_domains, Mapping):
            raise TakeoverError("SNAPSHOT_INVALID", "domains")
        for raw_domain, raw_entry in raw_domains.items():
            domain = self._host(raw_domain, code="SNAPSHOT_INVALID")
            if not isinstance(raw_entry, Mapping):
                raise TakeoverError("SNAPSHOT_INVALID", "domain entry")
            entry = domains.get(domain)
            if entry is None:
                zone_value = raw_entry.get("zone")
                if zone_value:
                    zone = self._registration_host(zone_value)
                else:
                    zone = ""
                owner_value = raw_entry.get("owner", "restored")
                entry = {
                    "domain": domain,
                    "zone": zone,
                    "owner": self._owner(owner_value),
                    "owned_hosts": (),
                    "values": (),
                    "cnames": (),
                    "a_records": (),
                }
                domains[domain] = entry
            if "owned_hosts" in raw_entry:
                entry["owned_hosts"] = tuple(self._owned_hosts(raw_entry["owned_hosts"]))
            if isinstance(raw_entry.get("owner"), str) and raw_entry["owner"].strip():
                entry["owner"] = raw_entry["owner"].strip()
            if isinstance(raw_entry.get("zone"), str) and raw_entry["zone"].strip():
                entry["zone"] = self._registration_host(raw_entry["zone"])
            for field in ("values", "cnames", "a_records"):
                if field in raw_entry:
                    entry[field] = tuple(self._strings(raw_entry[field]))
        return domains

    def _parse_conclusions(self, raw_collection: object, domains: dict) -> dict:
        raw_records = list(raw_collection.values()) if isinstance(raw_collection, Mapping) else list(raw_collection)
        conclusions = {}
        for raw_record in raw_records:
            if not isinstance(raw_record, Mapping):
                raise TakeoverError("SNAPSHOT_INVALID", "conclusion")
            domain = self._host(raw_record.get("domain"), code="SNAPSHOT_INVALID")
            if domain in conclusions:
                raise TakeoverError("SNAPSHOT_INVALID", "duplicate")
            if domain not in domains:
                zone = raw_record.get("zone")
                owner = raw_record.get("owner")
                if not isinstance(zone, str) or not isinstance(owner, str) or not owner.strip():
                    raise TakeoverError("SNAPSHOT_INVALID", "unknown conclusion domain")
                zone = self._registration_host(zone)
                domains[domain] = {"domain": domain, "zone": zone, "owner": owner,
                                   "owned_hosts": (), "values": (), "cnames": (),
                                   "a_records": ()}
            if raw_record.get("state") not in _VALID_STATES:
                raise TakeoverError("SNAPSHOT_INVALID", "state")
            if not _is_number(raw_record.get("first_seen")):
                raise TakeoverError("SNAPSHOT_INVALID", "first_seen")
            if not _is_real_int(raw_record.get("service_version", 0), 0):
                raise TakeoverError("SNAPSHOT_INVALID", "service_version")
            if not _is_real_int(raw_record.get("ttl", 0), 0):
                raise TakeoverError("SNAPSHOT_INVALID", "ttl")
            for timestamp_field in (
                "rescanned_at", "last_recheck_at", "decided_at", "ttl_expires_at"
            ):
                timestamp = raw_record.get(timestamp_field)
                if timestamp is not None and not _is_number(timestamp):
                    raise TakeoverError("SNAPSHOT_INVALID", timestamp_field)
            recompute_count = raw_record.get("recompute_count", 0)
            if not _is_real_int(recompute_count, 0):
                raise TakeoverError("SNAPSHOT_INVALID", "recompute_count")
            if "conflict" in raw_record and not isinstance(raw_record["conflict"], bool):
                raise TakeoverError("SNAPSHOT_INVALID", "conflict")

            record = dict(copy.deepcopy(raw_record))
            record["domain"] = domain
            record["state"] = raw_record["state"]
            record["exploitable"] = raw_record["state"] == "confirmed"
            record["chain"] = tuple(self._strings(raw_record.get("chain", ())))
            record["evidence"] = list(self._strings(raw_record.get("evidence", ())))
            record.setdefault("zone", domains[domain]["zone"])
            record.setdefault("owner", domains[domain]["owner"])
            record.setdefault("target", record["chain"][-1] if record["chain"] else None)
            record.setdefault("service", None)
            record.setdefault("conflict", False)
            record.setdefault("fetched_at", _utc_now_iso())
            record.setdefault("rescanned_at", None)
            record.setdefault("last_recheck_at", record.get("rescanned_at"))
            record.setdefault("decided_at", None)
            record.setdefault("addresses", [])
            record.setdefault("resolution", {})
            record.setdefault("ttl_expires_at", None)
            record.setdefault("ttl_hold", False)
            record.setdefault("recompute_count", 0)
            record.setdefault("annotations", [])
            conclusions[domain] = record
        return conclusions

    @staticmethod
    def _parse_stats(raw_stats: Mapping) -> dict:
        stats = {}
        for key, value in raw_stats.items():
            if not _is_real_int(value, 0):
                raise TakeoverError("SNAPSHOT_INVALID", f"stat {key}")
            stats[str(key)] = value
        if "domains" not in stats or "failed" not in stats:
            raise TakeoverError("SNAPSHOT_INVALID", "domains/failed stats")
        return stats

    @staticmethod
    def _parse_events(raw: Mapping) -> list:
        events_raw = raw.get("rate_events")
        if events_raw is None and isinstance(raw.get("rate"), Mapping):
            events_raw = raw["rate"].get("events", ())
        if events_raw is None:
            events_raw = ()
        if not isinstance(events_raw, (list, tuple)):
            raise TakeoverError("SNAPSHOT_INVALID", "events")
        if any(not _is_number(event) for event in events_raw):
            raise TakeoverError("SNAPSHOT_INVALID", "event")
        return list(events_raw)
