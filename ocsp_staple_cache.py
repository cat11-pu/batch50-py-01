"""Reverse-proxy OCSP staple cache: nextUpdate refresh, must-staple and revocation."""

from __future__ import annotations

import copy
import threading
import time
import uuid
from dataclasses import dataclass


class StapleError(ValueError):
    """Raised when a staple lookup or refresh operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CertRecord:
    site: str
    fingerprint: str
    issuer: str
    serial: int
    must_staple: bool
    registered_at: int


@dataclass(frozen=True)
class StapleView:
    site: str
    available: bool
    body: bytes | None
    state: str
    this_update: int | None
    next_update: int | None
    issuer: str


@dataclass(frozen=True)
class RefreshLease:
    site: str
    fingerprint: str
    issuer: str
    acquired_at: int
    expires_at: int
    lease_id: str


@dataclass(frozen=True)
class RefreshResult:
    site: str
    fingerprint: str
    issuer: str
    state: str
    body_size: int
    this_update: int
    next_update: int


@dataclass(frozen=True)
class SweepReport:
    due: int
    expired: int
    evicted: int


class OcspStapleCache:
    """Hold one OCSP response per site and keep handshakes supplied with fresh bytes."""

    SNAPSHOT_VERSION = 1
    SNAPSHOT_KEYS = frozenset({"version", "sites", "cache", "leases", "counters"})
    STAT_KEYS = (
        "registrations",
        "refreshes",
        "cache_hits",
        "cache_misses",
        "invalidated",
        "revoked",
        "sweeps",
        "refresh_failures",
    )
    MAX_RETRY_BACKOFF = 300

    def __init__(self, *, max_bytes: int = 65536, max_fingerprints: int = 16,
                 refresh_ratio: float = 0.75, retry_backoff: int = 30,
                 lease_ttl: int = 10, clock=None) -> None:
        self.max_bytes = max_bytes
        self.max_fingerprints = max_fingerprints
        self.refresh_ratio = refresh_ratio
        self.retry_backoff = retry_backoff
        self.lease_ttl = lease_ttl
        self._clock = clock
        self._lock = threading.RLock()
        self._sites: dict[str, dict] = {}
        self._cache: dict[str, dict] = {}
        self._leases: dict[str, dict] = {}
        self._counters = {key: 0 for key in self.STAT_KEYS}
        self._high_water: float | int | None = None

    def register(self, site: str, *, fingerprint: str, issuer: str, serial: int,
                 must_staple: bool = False, now: int | None = None) -> CertRecord:
        with self._lock:
            now_value = self._resolve_now(now)
            self._advance_clock(now_value)
            self._require_text(site, "STAPLE_INVALID_SITE")
            if site in self._sites:
                raise StapleError("STAPLE_SITE_EXISTS", {"site": site})
            self._require_text(fingerprint, "STAPLE_INVALID_FINGERPRINT")
            self._require_text(issuer, "STAPLE_INVALID_ISSUER")
            if isinstance(serial, bool) or not isinstance(serial, int):
                raise StapleError("STAPLE_INVALID_SERIAL", {"serial": serial})
            if not isinstance(must_staple, bool):
                raise StapleError("STAPLE_INVALID_MUST_STAPLE",
                                 {"must_staple": must_staple})

            known_fingerprints = {
                record["fingerprint"] for record in self._sites.values()
            }
            if (fingerprint not in known_fingerprints
                    and len(known_fingerprints) >= self.max_fingerprints):
                raise StapleError(
                    "STAPLE_FINGERPRINT_LIMIT",
                    {"limit": self.max_fingerprints},
                )

            record = {
                "site": site,
                "fingerprint": fingerprint,
                "issuer": issuer,
                "serial": serial,
                "must_staple": must_staple,
                "registered_at": now_value,
                "revoked_at": None,
                "failure_count": 0,
                "backoff_until": None,
            }
            self._sites[site] = record
            self._counters["registrations"] += 1
            return self._cert_record(record)

    def get_staple(self, site: str, *, now: int | None = None) -> StapleView:
        with self._lock:
            now_value = self._resolve_now(now)
            self._advance_clock(now_value)
            record = self._site_record(site)
            view = self._view_locked(record, now_value)
            if view.available:
                self._counters["cache_hits"] += 1
            else:
                self._counters["cache_misses"] += 1
            if record["must_staple"] and not view.available \
                    and view.state != "revoked":
                raise StapleError(
                    "MUST_STAPLE_UNAVAILABLE",
                    {"site": site, "state": view.state},
                )
            return view

    def acquire_refresh(self, site: str, *, now: int | None = None) -> RefreshLease:
        with self._lock:
            now_value = self._resolve_now(now)
            self._advance_clock(now_value)
            record = self._site_record(site)
            self._discard_expired_leases_locked(now_value)
            existing = self._active_lease_for_fingerprint(
                record["fingerprint"], now_value
            )
            if existing is not None:
                raise StapleError(
                    "REFRESH_IN_PROGRESS",
                    {"site": site, "holder": existing["site"]},
                )

            lease = {
                "site": site,
                "fingerprint": record["fingerprint"],
                "issuer": record["issuer"],
                "acquired_at": now_value,
                "expires_at": now_value + self.lease_ttl,
                "lease_id": uuid.uuid4().hex,
                "mono_at": self._monotonic_now(),
            }
            self._leases[site] = lease
            return self._lease_record(lease)

    def release_refresh(self, site: str, *, now: int | None = None) -> bool:
        with self._lock:
            now_value = self._resolve_now(now)
            self._advance_clock(now_value)
            self._site_record(site)
            lease = self._leases.pop(site, None)
            return lease is not None and self._lease_active(lease, now_value)

    def refresh(self, site: str, *, body: bytes, this_update: int, next_update: int,
                status: str = "good", serial: int | None = None,
                issuer: str | None = None, signature_ok: bool = True,
                lease: RefreshLease | None = None,
                now: int | None = None) -> RefreshResult:
        with self._lock:
            now_value = self._resolve_now(now)
            self._advance_clock(now_value)
            record = self._site_record(site)
            self._discard_expired_leases_locked(now_value)
            active_lease = self._active_lease_for_fingerprint(
                record["fingerprint"], now_value
            )
            if active_lease is not None:
                if (not isinstance(lease, RefreshLease)
                        or lease.lease_id != active_lease["lease_id"]
                        or lease.site != site):
                    raise StapleError(
                        "REFRESH_IN_PROGRESS",
                        {"site": site, "holder": active_lease["site"]},
                    )

            try:
                if serial is not None and serial != record["serial"]:
                    raise StapleError(
                        "STAPLE_SERIAL_MISMATCH",
                        {"expected": record["serial"], "received": serial},
                    )
                response_issuer = record["issuer"] if issuer is None else issuer
                if response_issuer != record["issuer"]:
                    raise StapleError(
                        "STAPLE_ISSUER_MISMATCH",
                        {"expected": record["issuer"], "received": response_issuer},
                    )
                if not signature_ok:
                    raise StapleError("STAPLE_BAD_SIGNATURE", {"site": site})
                if not self._is_number(this_update) or not self._is_number(next_update):
                    raise StapleError(
                        "STAPLE_WINDOW_INVALID",
                        {"this_update": this_update, "next_update": next_update},
                    )
                if this_update >= next_update:
                    raise StapleError(
                        "STAPLE_WINDOW_INVALID",
                        {"this_update": this_update, "next_update": next_update},
                    )
                if not isinstance(body, bytes):
                    raise StapleError(
                        "STAPLE_INVALID_BODY", {"body_type": type(body).__name__}
                    )
                self._require_text(status, "STAPLE_INVALID_STATUS")

                old_entry = self._cache.get(site)
                old_size = self._body_size(old_entry)
                total_bytes = sum(
                    self._body_size(entry) for entry in self._cache.values()
                )
                new_total = total_bytes - old_size + len(body)
                if new_total > self.max_bytes:
                    raise StapleError(
                        "STAPLE_CAPACITY_EXCEEDED",
                        {"bytes": new_total, "limit": self.max_bytes},
                    )
            except StapleError:
                self._record_failure_locked(record, now_value)
                self._counters["refresh_failures"] += 1
                raise

            entry = {
                "site": site,
                "fingerprint": record["fingerprint"],
                "issuer": record["issuer"],
                "serial": record["serial"],
                "body": body,
                "state": status,
                "this_update": this_update,
                "next_update": next_update,
                "refreshed_at": now_value,
                "time_anchor": now_value,
                "high_water": max(now_value, this_update),
                "mono_at": self._monotonic_now(),
                "invalidated": False,
            }
            self._cache[site] = entry
            record["failure_count"] = 0
            record["backoff_until"] = None
            self._counters["refreshes"] += 1
            if status == "revoked":
                self._counters["revoked"] += 1
            return RefreshResult(
                site=site,
                fingerprint=record["fingerprint"],
                issuer=record["issuer"],
                state=status,
                body_size=len(body),
                this_update=this_update,
                next_update=next_update,
            )

    def invalidate(self, fingerprint: str, *, issuer: str | None = None,
                   status: str = "revoked", now: int | None = None) -> int:
        with self._lock:
            now_value = self._resolve_now(now)
            self._advance_clock(now_value)
            self._require_text(fingerprint, "STAPLE_INVALID_FINGERPRINT")
            self._require_text(status, "STAPLE_INVALID_STATUS")
            if issuer is not None:
                self._require_text(issuer, "STAPLE_INVALID_ISSUER")

            affected = [
                site for site, record in self._sites.items()
                if record["fingerprint"] == fingerprint
                and (issuer is None or record["issuer"] == issuer)
            ]
            for site in affected:
                record = self._sites[site]
                self._cache[site] = self._marker_entry(record, status, now_value)
            self._counters["invalidated"] += len(affected)
            return len(affected)

    def mark_revoked(self, issuer: str, serial: int, *,
                     now: int | None = None) -> int:
        with self._lock:
            now_value = self._resolve_now(now)
            self._advance_clock(now_value)
            self._require_text(issuer, "STAPLE_INVALID_ISSUER")

            affected = [
                record for record in self._sites.values()
                if record["issuer"] == issuer and record["serial"] == serial
            ]
            for record in affected:
                record["revoked_at"] = now_value
                site = record["site"]
                entry = self._cache.get(site)
                if not (isinstance(entry, dict)
                        and entry.get("state") == "revoked"
                        and isinstance(entry.get("body"), bytes)):
                    self._cache[site] = self._marker_entry(
                        record, "revoked", now_value
                    )
            self._counters["revoked"] += len(affected)
            return len(affected)

    def status(self, site: str | None = None) -> dict:
        with self._lock:
            now_value = self._status_now_locked()
            if site is not None:
                record = self._site_record(site)
                view = self._view_locked(record, now_value)
                in_flight = self._active_lease_for_fingerprint(
                    record["fingerprint"], now_value
                ) is not None
                return {
                    "available": view.available,
                    "body_size": len(view.body) if view.body is not None else 0,
                    "in_flight": in_flight,
                    "issuer": record["issuer"],
                }

            cached = 0
            revoked = 0
            total_bytes = 0
            for record in self._sites.values():
                view = self._view_locked(record, now_value)
                if view.body is not None:
                    cached += 1
                    total_bytes += len(view.body)
                if record.get("revoked_at") is not None or view.state == "revoked":
                    revoked += 1

            in_flight = sum(
                1 for lease_site in self._leases
                if self._lease_active_for_site(lease_site, now_value)
            )
            return {
                "sites": len(self._sites),
                "cached": cached,
                "revoked": revoked,
                "in_flight": in_flight,
                "bytes": total_bytes,
            }

    def sweep(self, *, now: int | None = None) -> SweepReport:
        with self._lock:
            now_value = self._resolve_now(now)
            self._advance_clock(now_value)
            due = 0
            expired = 0
            evicted = 0

            for site in list(self._cache):
                entry = self._cache.get(site)
                record = self._sites.get(site)
                if not isinstance(entry, dict) or record is None:
                    self._cache.pop(site, None)
                    continue
                if self._apply_expiry(entry, now_value, record):
                    expired += 1
                    self._cache.pop(site, None)
                    continue
                next_update = entry.get("next_update")
                this_update = entry.get("this_update")
                if next_update is None or this_update is None:
                    continue
                try:
                    window = float(next_update) - float(this_update)
                    threshold = float(this_update) + self.refresh_ratio * window
                except (TypeError, ValueError):
                    continue
                if window > 0 and self._effective_time(entry, now_value) >= threshold:
                    due += 1

            self._discard_expired_leases_locked(now_value)
            self._counters["sweeps"] += 1
            return SweepReport(due=due, expired=expired, evicted=evicted)

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._counters)

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy({
                "version": self.SNAPSHOT_VERSION,
                "sites": self._sites,
                "cache": self._cache,
                "leases": self._leases,
                "counters": self._counters,
            })

    def restore(self, state: dict) -> None:
        try:
            cloned = copy.deepcopy(state)
            restored = self._parse_snapshot(cloned)
        except StapleError:
            raise
        except Exception as exc:
            raise StapleError(
                "STAPLE_SNAPSHOT_INVALID", {"reason": str(exc)}
            ) from exc

        with self._lock:
            self._sites = restored["sites"]
            self._cache = restored["cache"]
            self._leases = restored["leases"]
            self._counters = restored["counters"]
            self._high_water = restored["high_water"]

    def _parse_snapshot(self, state: object) -> dict:
        if not isinstance(state, dict):
            raise StapleError("STAPLE_SNAPSHOT_INVALID", {"reason": "not_object"})
        if set(state.keys()) != self.SNAPSHOT_KEYS:
            raise StapleError("STAPLE_SNAPSHOT_INVALID", {"reason": "keys"})
        if state.get("version") != self.SNAPSHOT_VERSION:
            raise StapleError("STAPLE_SNAPSHOT_INVALID", {"reason": "version"})

        sites = self._parse_sites(state["sites"])
        cache = self._parse_cache(state["cache"], sites)
        leases = self._parse_leases(state["leases"], sites)
        counters = self._parse_counters(state["counters"])
        high_water = None
        for record in sites.values():
            high_water = self._max_time(high_water, record.get("registered_at"))
            high_water = self._max_time(high_water, record.get("revoked_at"))
        for entry in cache.values():
            high_water = self._max_time(high_water, entry.get("high_water"))
            high_water = self._max_time(high_water, entry.get("refreshed_at"))
            high_water = self._max_time(high_water, entry.get("this_update"))
        for lease in leases.values():
            high_water = self._max_time(high_water, lease.get("acquired_at"))
        return {
            "sites": sites,
            "cache": cache,
            "leases": leases,
            "counters": counters,
            "high_water": high_water,
        }

    def _parse_sites(self, raw_sites: object) -> dict[str, dict]:
        if isinstance(raw_sites, list):
            items = []
            for item in raw_sites:
                if not isinstance(item, dict):
                    raise StapleError("STAPLE_SNAPSHOT_INVALID")
                items.append((item.get("site"), item))
        elif isinstance(raw_sites, dict):
            items = []
            for key, item in raw_sites.items():
                if not isinstance(item, dict):
                    raise StapleError("STAPLE_SNAPSHOT_INVALID")
                items.append((item.get("site", key), item))
        else:
            raise StapleError("STAPLE_SNAPSHOT_INVALID")

        sites: dict[str, dict] = {}
        for site, item in items:
            if not self._is_text(site) or site in sites:
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            fingerprint = item.get("fingerprint")
            issuer = item.get("issuer")
            serial = item.get("serial")
            registered_at = item.get("registered_at")
            if not self._is_text(fingerprint) or not self._is_text(issuer):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            if isinstance(serial, bool) or not isinstance(serial, int):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            if not self._is_time(registered_at):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            must_staple = item.get("must_staple", False)
            if not isinstance(must_staple, bool):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            revoked_at = item.get("revoked_at")
            if revoked_at is not None and not self._is_time(revoked_at):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            failure_count = item.get("failure_count", 0)
            if isinstance(failure_count, bool) or not isinstance(failure_count, int) \
                    or failure_count < 0:
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            backoff_until = item.get("backoff_until")
            if backoff_until is not None and not self._is_time(backoff_until):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            sites[site] = {
                "site": site,
                "fingerprint": fingerprint,
                "issuer": issuer,
                "serial": serial,
                "must_staple": must_staple,
                "registered_at": registered_at,
                "revoked_at": revoked_at,
                "failure_count": failure_count,
                "backoff_until": backoff_until,
            }
        return sites

    def _parse_cache(self, raw_cache: object,
                     sites: dict[str, dict]) -> dict[str, dict]:
        if isinstance(raw_cache, list):
            items = []
            for item in raw_cache:
                if not isinstance(item, dict):
                    raise StapleError("STAPLE_SNAPSHOT_INVALID")
                items.append((item.get("site"), item))
        elif isinstance(raw_cache, dict):
            items = []
            for key, item in raw_cache.items():
                if not isinstance(item, dict):
                    raise StapleError("STAPLE_SNAPSHOT_INVALID")
                items.append((item.get("site", key), item))
        else:
            raise StapleError("STAPLE_SNAPSHOT_INVALID")

        cache: dict[str, dict] = {}
        for site, item in items:
            if not self._is_text(site) or site not in sites or site in cache:
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            record = sites[site]
            fingerprint = item.get("fingerprint", record["fingerprint"])
            issuer = item.get("issuer", record["issuer"])
            if fingerprint != record["fingerprint"] or issuer != record["issuer"]:
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            body = item.get("body")
            if body is not None and not isinstance(body, bytes):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            state = item.get("state", "empty" if body is None else "good")
            if not self._is_text(state):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            this_update = item.get("this_update")
            next_update = item.get("next_update")
            if this_update is not None and not self._is_time(this_update):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            if next_update is not None and not self._is_time(next_update):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            if this_update is not None and next_update is not None \
                    and this_update >= next_update and state != "expired":
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            refreshed_at = item.get(
                "refreshed_at",
                item.get("time_anchor", record["registered_at"]),
            )
            if not self._is_time(refreshed_at):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            high_water = item.get("high_water", refreshed_at)
            if not self._is_time(high_water):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            cache[site] = {
                "site": site,
                "fingerprint": fingerprint,
                "issuer": issuer,
                "serial": record["serial"],
                "body": body,
                "state": state,
                "this_update": this_update,
                "next_update": next_update,
                "refreshed_at": refreshed_at,
                "time_anchor": refreshed_at,
                "high_water": high_water,
                "mono_at": self._monotonic_now(),
                "invalidated": bool(item.get("invalidated", False)),
                "expired_latched": bool(
                    item.get("expired_latched", state == "expired")
                ),
            }
        return cache

    def _parse_leases(self, raw_leases: object,
                      sites: dict[str, dict]) -> dict[str, dict]:
        if isinstance(raw_leases, list):
            items = []
            for item in raw_leases:
                if not isinstance(item, dict):
                    raise StapleError("STAPLE_SNAPSHOT_INVALID")
                items.append((item.get("site"), item))
        elif isinstance(raw_leases, dict):
            items = []
            for key, item in raw_leases.items():
                if not isinstance(item, dict):
                    raise StapleError("STAPLE_SNAPSHOT_INVALID")
                items.append((item.get("site", key), item))
        else:
            raise StapleError("STAPLE_SNAPSHOT_INVALID")

        leases: dict[str, dict] = {}
        for site, item in items:
            if not self._is_text(site) or site not in sites or site in leases:
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            record = sites[site]
            lease_id = item.get("lease_id")
            acquired_at = item.get("acquired_at")
            expires_at = item.get("expires_at")
            if not self._is_text(lease_id):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            if not self._is_time(acquired_at) or not self._is_time(expires_at):
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            if expires_at <= acquired_at:
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            fingerprint = item.get("fingerprint", record["fingerprint"])
            issuer = item.get("issuer", record["issuer"])
            if fingerprint != record["fingerprint"] or issuer != record["issuer"]:
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            leases[site] = {
                "site": site,
                "fingerprint": fingerprint,
                "issuer": issuer,
                "acquired_at": acquired_at,
                "expires_at": expires_at,
                "lease_id": lease_id,
                "mono_at": self._monotonic_now(),
            }
        return leases

    def _parse_counters(self, raw_counters: object) -> dict[str, int]:
        if not isinstance(raw_counters, dict):
            raise StapleError("STAPLE_SNAPSHOT_INVALID")
        if set(raw_counters.keys()) != set(self.STAT_KEYS):
            raise StapleError("STAPLE_SNAPSHOT_INVALID")
        counters = {}
        for key in self.STAT_KEYS:
            value = raw_counters[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise StapleError("STAPLE_SNAPSHOT_INVALID")
            counters[key] = value
        return counters

    def _view_locked(self, record: dict, now_value: float | int) -> StapleView:
        site = record["site"]
        issuer = record["issuer"]
        entry = self._cache.get(site)
        if isinstance(entry, dict):
            if self._apply_expiry(entry, now_value, record):
                return StapleView(
                    site=site,
                    available=False,
                    body=None,
                    state="expired",
                    this_update=entry.get("this_update"),
                    next_update=entry.get("next_update"),
                    issuer=issuer,
                )
            if record.get("revoked_at") is not None \
                    and entry.get("state") != "revoked":
                self._cache[site] = self._marker_entry(record, "revoked", now_value)
                entry = self._cache[site]
        elif record.get("revoked_at") is not None:
            entry = self._marker_entry(record, "revoked", now_value)
            self._cache[site] = entry

        if not isinstance(entry, dict):
            return StapleView(
                site=site,
                available=False,
                body=None,
                state="empty",
                this_update=None,
                next_update=None,
                issuer=issuer,
            )

        body = entry.get("body")
        state = entry.get("state", "empty")
        available = isinstance(body, bytes) and len(body) > 0
        return StapleView(
            site=site,
            available=available,
            body=body if available else None,
            state=state,
            this_update=entry.get("this_update"),
            next_update=entry.get("next_update"),
            issuer=issuer,
        )

    def _apply_expiry(self, entry: dict, now_value: float | int,
                      record: dict | None = None) -> bool:
        if entry.get("expired_latched") is True:
            return True
        next_update = entry.get("next_update")
        if next_update is None:
            return False
        effective_now = self._effective_time(entry, now_value)
        entry["high_water"] = max(
            self._as_number(entry.get("high_water"), now_value),
            effective_now,
        )
        if effective_now <= next_update:
            return False

        if record is not None and record.get("revoked_at") is not None:
            self._cache[record["site"]] = self._marker_entry(
                record, "revoked", effective_now
            )
            return False

        entry["expired_latched"] = True
        entry["state"] = "expired"
        entry["body"] = None
        return True

    def _active_lease_for_fingerprint(self, fingerprint: str,
                                      now_value: float | int) -> dict | None:
        self._discard_expired_leases_locked(now_value)
        for lease in self._leases.values():
            if lease.get("fingerprint") == fingerprint \
                    and self._lease_active(lease, now_value):
                return lease
        return None

    def _lease_active_for_site(self, site: str,
                               now_value: float | int) -> bool:
        lease = self._leases.get(site)
        return lease is not None and self._lease_active(lease, now_value)

    def _discard_expired_leases_locked(self, now_value: float | int) -> None:
        for site in list(self._leases):
            if not self._lease_active(self._leases[site], now_value):
                self._leases.pop(site, None)

    def _lease_active(self, lease: dict, now_value: float | int) -> bool:
        try:
            expires_at = float(lease["expires_at"])
            acquired_at = float(lease["acquired_at"])
        except (KeyError, TypeError, ValueError):
            return False
        mono_elapsed = 0.0
        mono_at = lease.get("mono_at")
        if mono_at is not None:
            try:
                mono_elapsed = max(0.0, self._monotonic_now() - float(mono_at))
            except (TypeError, ValueError):
                mono_elapsed = 0.0
        monotonic_now = acquired_at + mono_elapsed
        high_water = self._as_number(self._high_water, now_value)
        reference_now = max(float(now_value), high_water, monotonic_now)
        return reference_now < expires_at

    def _effective_time(self, entry: dict, now_value: float | int) -> float:
        anchor = self._as_number(
            entry.get("time_anchor", entry.get("refreshed_at")),
            now_value,
        )
        mono_at = entry.get("mono_at")
        mono_elapsed = 0.0
        if mono_at is not None:
            try:
                mono_elapsed = max(0.0, self._monotonic_now() - float(mono_at))
            except (TypeError, ValueError):
                mono_elapsed = 0.0
        monotonic_time = anchor + mono_elapsed
        high_water = self._as_number(entry.get("high_water"), anchor)
        return max(float(now_value), high_water, monotonic_time)

    def _record_failure_locked(self, record: dict,
                               now_value: float | int) -> None:
        failures = int(record.get("failure_count", 0)) + 1
        record["failure_count"] = failures
        record["backoff_until"] = now_value + self._retry_delay(failures)

    def _retry_delay(self, failures: int) -> int:
        base = max(0, int(self.retry_backoff))
        exponent = min(max(0, failures - 1), 4)
        cap = max(base, self.MAX_RETRY_BACKOFF)
        return min(base * (2 ** exponent), cap)

    def _marker_entry(self, record: dict, state: str,
                      now_value: float | int) -> dict:
        return {
            "site": record["site"],
            "fingerprint": record["fingerprint"],
            "issuer": record["issuer"],
            "serial": record["serial"],
            "body": None,
            "state": state,
            "this_update": None,
            "next_update": None,
            "refreshed_at": now_value,
            "time_anchor": now_value,
            "high_water": now_value,
            "mono_at": self._monotonic_now(),
            "invalidated": True,
        }

    def _cert_record(self, record: dict) -> CertRecord:
        return CertRecord(
            site=record["site"],
            fingerprint=record["fingerprint"],
            issuer=record["issuer"],
            serial=record["serial"],
            must_staple=record["must_staple"],
            registered_at=record["registered_at"],
        )

    def _lease_record(self, lease: dict) -> RefreshLease:
        return RefreshLease(
            site=lease["site"],
            fingerprint=lease["fingerprint"],
            issuer=lease["issuer"],
            acquired_at=lease["acquired_at"],
            expires_at=lease["expires_at"],
            lease_id=lease["lease_id"],
        )

    def _site_record(self, site: object) -> dict:
        if not self._is_text(site) or site not in self._sites:
            raise StapleError("STAPLE_UNKNOWN_SITE", {"site": site})
        return self._sites[site]

    def _status_now_locked(self) -> float | int:
        if self._high_water is not None:
            return self._high_water
        now_value = self._resolve_now(None)
        self._advance_clock(now_value)
        return now_value

    def _resolve_now(self, now: int | float | None) -> float | int:
        if now is not None:
            if not self._is_time(now):
                raise StapleError("STAPLE_INVALID_TIME", {"now": now})
            return now
        if self._clock is not None:
            try:
                if callable(self._clock):
                    value = self._clock()
                elif hasattr(self._clock, "time"):
                    value = self._clock.time()
                else:
                    value = self._clock()
            except Exception as exc:
                raise StapleError("STAPLE_INVALID_CLOCK") from exc
            if not self._is_time(value):
                raise StapleError("STAPLE_INVALID_CLOCK", {"value": value})
            return value
        return time.time()

    def _monotonic_now(self) -> float:
        clock = self._clock
        monotonic = getattr(clock, "monotonic", None) if clock is not None else None
        if callable(monotonic):
            try:
                return float(monotonic())
            except (TypeError, ValueError):
                pass
        return time.monotonic()

    def _advance_clock(self, now_value: float | int) -> None:
        if self._high_water is None or now_value > self._high_water:
            self._high_water = now_value

    @staticmethod
    def _body_size(entry: object) -> int:
        if isinstance(entry, dict):
            body = entry.get("body")
            if isinstance(body, bytes):
                return len(body)
        return 0

    @staticmethod
    def _require_text(value: object, code: str) -> str:
        if not OcspStapleCache._is_text(value):
            raise StapleError(code, {"value": value})
        return value

    @staticmethod
    def _is_text(value: object) -> bool:
        return isinstance(value, str) and bool(value)

    @staticmethod
    def _is_number(value: object) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)

    @classmethod
    def _is_time(cls, value: object) -> bool:
        return cls._is_number(value)

    @classmethod
    def _as_number(cls, value: object, default: float | int) -> float:
        if cls._is_number(value):
            return float(value)
        return float(default)

    @classmethod
    def _max_time(cls, current: float | int | None,
                  value: object) -> float | int | None:
        if not cls._is_time(value):
            return current
        if current is None or value > current:
            return value
        return current
