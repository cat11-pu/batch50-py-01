"""Authoritative zone-transfer governance: authorization, budgets and recovery."""

from __future__ import annotations

import copy
import threading
import time
from dataclasses import dataclass

SERIAL_MOD = 2 ** 32
SERIAL_HALF = 2 ** 31
SERIAL_MAX = SERIAL_MOD - 1

_COUNTER_KEYS = (
    "zones_loaded",
    "authorizations",
    "transfers_started",
    "transfers_completed",
    "transfers_aborted",
    "budget_aborted",
    "messages_sent",
    "bytes_sent",
    "denied",
)

_SNAPSHOT_KEYS = {
    "version",
    "zones",
    "keys",
    "auths",
    "active",
    "aborted",
    "watermarks",
    "counters",
}


def serial_is_newer(candidate: int, reference: int) -> bool:
    """Return True when candidate is newer than reference under RFC 1982."""
    if not isinstance(candidate, int) or not isinstance(reference, int):
        return False
    if isinstance(candidate, bool) or isinstance(reference, bool):
        return False
    distance = (candidate - reference) % SERIAL_MOD
    return 0 < distance < SERIAL_HALF


class TransferDenied(ValueError):
    """Raised when an authorization or transfer step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ZoneState:
    zone: str
    serial: int
    digest: str
    records: tuple[str, ...]
    history: tuple[int, ...]
    loaded_at: int


@dataclass(frozen=True)
class AuthGrant:
    zone: str
    secondary: str
    source: str
    key_name: str
    expires_at: int
    state: str


@dataclass(frozen=True)
class TransferPlan:
    zone: str
    secondary: str
    mode: str
    since: int | None
    serial: int
    messages: int
    digest: str


@dataclass(frozen=True)
class ProgressReport:
    zone: str
    secondary: str
    mode: str
    messages: int
    bytes_sent: int
    remaining_messages: int
    remaining_bytes: int
    last_soa: int | None


@dataclass(frozen=True)
class TransferReceipt:
    zone: str
    secondary: str
    mode: str
    serial: int
    digest: str
    messages: int
    bytes_sent: int
    state: str


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_serial(value: object) -> bool:
    return _is_int(value) and 0 <= value <= SERIAL_MAX


class ZoneTransferGovernor:
    """Decide who may transfer a zone and how much of it may be sent."""

    def __init__(self, *, max_messages: int = 64, max_bytes: int = 1048576,
                 auth_ttl: int = 300, clock=None) -> None:
        if not _is_int(max_messages) or max_messages < 0:
            raise ValueError("max_messages must be a non-negative integer")
        if not _is_int(max_bytes) or max_bytes < 0:
            raise ValueError("max_bytes must be a non-negative integer")
        if not _is_int(auth_ttl) or auth_ttl < 0:
            raise ValueError("auth_ttl must be a non-negative integer")
        self.max_messages = max_messages
        self.max_bytes = max_bytes
        self.auth_ttl = auth_ttl
        self._clock = clock
        self._lock = threading.RLock()

        self._zones: dict[str, ZoneState] = {}
        self._keys: dict[str, set[str]] = {}
        self._auths: dict[tuple[str, str], dict] = {}
        self._active: dict[tuple[str, str], dict] = {}
        self._aborted: dict[tuple[str, str], dict] = {}
        self._watermarks: dict[tuple[str, str], int] = {}
        self._counters: dict[str, int] = {key: 0 for key in _COUNTER_KEYS}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _now(self, now: int | None) -> int:
        if now is None:
            if self._clock is not None:
                return int(self._clock())
            return int(time.monotonic())
        if not _is_int(now):
            self._deny("INVALID_REQUEST", "now must be an integer")
        return int(now)

    def _deny(self, code: str, detail: object = None):
        self._counters["denied"] += 1
        raise TransferDenied(code, detail)

    @staticmethod
    def _snapshot_invalid(detail: object = None):
        raise TransferDenied("SNAPSHOT_INVALID", detail)

    def _require_text(self, value: object, field: str) -> str:
        if not isinstance(value, str) or not value:
            self._deny("INVALID_REQUEST", f"{field} must be a non-empty string")
        return value

    def _require_zone(self, zone: str, *, auth_error: bool = False):
        if zone not in self._zones:
            if auth_error:
                self._deny("NOT_AUTHORIZED", f"zone {zone!r} is not loaded")
            self._deny("INVALID_REQUEST", f"zone {zone!r} is not loaded")
        return self._zones[zone]

    def _check_authorization(self, zone: str, secondary: str, source: str,
                             key_name: str, now: int) -> dict:
        if zone not in self._zones:
            self._deny("NOT_AUTHORIZED", "zone is not loaded")
        if not isinstance(key_name, str) or key_name not in self._keys.get(zone, set()):
            self._deny("NOT_AUTHORIZED", f"TSIG key {key_name!r} is not registered")
        grant = self._auths.get((zone, secondary))
        if grant is None:
            self._deny("NOT_AUTHORIZED", f"secondary {secondary!r} is not authorized")
        if grant.get("state") != "active" or now >= grant["expires_at"]:
            self._deny("NOT_AUTHORIZED", "authorization is expired")
        if source != grant["source"] or key_name != grant["key_name"]:
            self._deny("AUTH_MISMATCH", "source or TSIG key does not match the grant")
        return grant

    @staticmethod
    def _journal_connects(history: tuple[int, ...], since: int,
                          current: int) -> bool:
        """Whether the journal has a connected, forward chain from since to current."""
        if since == current:
            return True
        try:
            start = history.index(since)
        except ValueError:
            return False
        try:
            end = history.index(current)
        except ValueError:
            return False
        if start > end:
            return False

        previous = history[start]
        for serial in history[start + 1:end + 1]:
            if not serial_is_newer(serial, previous):
                return False
            previous = serial
        return previous == current

    def _plan_locked(self, state: ZoneState, secondary: str, mode: str,
                     since: int | None) -> tuple[str, int | None, int]:
        current = state.serial
        if mode == "axfr":
            if since is not None and serial_is_newer(since, current):
                self._deny(
                    "SERIAL_REGRESSION",
                    f"requested since={since} is newer than zone serial={current}",
                )
            return "axfr", None, len(state.records) + 2

        baseline = since
        if baseline is None:
            baseline = self._watermarks.get((state.zone, secondary))

        if baseline is None:
            return "axfr", None, len(state.records) + 2
        if baseline == current:
            return "nochange", current, 1
        if not serial_is_newer(current, baseline):
            self._deny(
                "SERIAL_REGRESSION",
                f"requested since={baseline} is not older than zone serial={current}",
            )

        if self._journal_connects(state.history, baseline, current):
            difference = (current - baseline) % SERIAL_MOD
            return "ixfr", baseline, difference * 2 + 2

        # A journal gap must never be bridged by splicing two unrelated ranges.
        return "axfr", None, len(state.records) + 2

    def _start_active(self, state: ZoneState, secondary: str, source: str,
                      key_name: str, mode: str, since: int | None,
                      messages: int, now: int) -> TransferPlan:
        plan = TransferPlan(
            zone=state.zone,
            secondary=secondary,
            mode=mode,
            since=since,
            serial=state.serial,
            messages=messages,
            digest=state.digest,
        )
        self._active[(state.zone, secondary)] = {
            "zone": state.zone,
            "secondary": secondary,
            "source": source,
            "key_name": key_name,
            "mode": mode,
            "since": since,
            "serial": state.serial,
            "digest": state.digest,
            "target_messages": messages,
            "messages": 0,
            "bytes_sent": 0,
            "last_soa": since,
            "started_at": now,
        }
        self._counters["transfers_started"] += 1
        return plan

    def _archive_aborted(self, active: dict, reason: str, now: int) -> dict:
        record = {
            "zone": active["zone"],
            "secondary": active["secondary"],
            "source": active["source"],
            "key_name": active["key_name"],
            "mode": active["mode"],
            "since": active["since"],
            "serial": active["serial"],
            "digest": active["digest"],
            "last_soa": active.get("last_soa"),
            "messages": active["messages"],
            "bytes_sent": active["bytes_sent"],
            "reason": reason,
            "at": now,
        }
        self._aborted[(active["zone"], active["secondary"])] = record
        return record

    def _abort_active_locked(self, active: dict, reason: str, now: int,
                             *, budget: bool = False) -> dict:
        key = (active["zone"], active["secondary"])
        self._active.pop(key, None)
        record = self._archive_aborted(active, reason, now)
        self._counters["transfers_aborted"] += 1
        if budget:
            self._counters["budget_aborted"] += 1
        return record

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def load_zone(self, zone: str, *, serial: int, digest: str, records,
                  history=(), now: int | None = None) -> ZoneState:
        with self._lock:
            self._require_text(zone, "zone")
            self._require_text(digest, "digest")
            if not _is_serial(serial):
                self._deny("INVALID_REQUEST", "serial must be a 32-bit unsigned integer")
            if isinstance(records, (str, bytes)):
                self._deny("INVALID_REQUEST", "records must be a non-empty collection")
            try:
                records_tuple = tuple(records)
            except TypeError:
                self._deny("INVALID_REQUEST", "records must be iterable")
            if not records_tuple:
                self._deny("INVALID_REQUEST", "records must not be empty")
            if any(not isinstance(record, str) or not record
                   for record in records_tuple):
                self._deny("INVALID_REQUEST", "records must contain non-empty strings")
            if isinstance(history, (str, bytes)):
                self._deny("INVALID_REQUEST", "history must be an iterable of serials")
            try:
                history_tuple = tuple(history)
            except TypeError:
                self._deny("INVALID_REQUEST", "history must be iterable")
            if any(not _is_serial(item) for item in history_tuple):
                self._deny("INVALID_REQUEST", "history contains an invalid serial")

            timestamp = self._now(now)
            state = ZoneState(
                zone=zone,
                serial=serial,
                digest=digest,
                records=records_tuple,
                history=history_tuple,
                loaded_at=timestamp,
            )
            self._zones[zone] = state
            self._counters["zones_loaded"] += 1
            return state

    def register_key(self, zone: str, key_name: str) -> tuple[str, ...]:
        with self._lock:
            self._require_text(zone, "zone")
            self._require_text(key_name, "key_name")
            self._keys.setdefault(zone, set()).add(key_name)
            return tuple(sorted(self._keys[zone]))

    def authorize(self, zone: str, *, secondary: str, source: str,
                  key_name: str, now: int | None = None) -> AuthGrant:
        with self._lock:
            self._require_text(zone, "zone")
            self._require_text(secondary, "secondary")
            self._require_text(source, "source")
            self._require_text(key_name, "key_name")
            timestamp = self._now(now)
            if zone not in self._zones:
                self._deny("NOT_AUTHORIZED", "zone is not loaded")
            if key_name not in self._keys.get(zone, set()):
                self._deny("NOT_AUTHORIZED", f"TSIG key {key_name!r} is not registered")

            expires_at = timestamp + self.auth_ttl
            grant = {
                "zone": zone,
                "secondary": secondary,
                "source": source,
                "key_name": key_name,
                "expires_at": expires_at,
                "state": "active",
            }
            self._auths[(zone, secondary)] = grant
            self._counters["authorizations"] += 1
            return AuthGrant(
                zone=zone,
                secondary=secondary,
                source=source,
                key_name=key_name,
                expires_at=expires_at,
                state="active",
            )

    def remove_secondary(self, zone: str, secondary: str) -> int:
        with self._lock:
            self._require_text(zone, "zone")
            self._require_text(secondary, "secondary")
            removed = 1 if (zone, secondary) in self._auths else 0
            self._auths.pop((zone, secondary), None)
            return removed

    def begin_transfer(self, zone: str, *, secondary: str, source: str,
                       key_name: str, mode: str = "auto", since: int | None = None,
                       now: int | None = None) -> TransferPlan:
        with self._lock:
            self._require_text(zone, "zone")
            self._require_text(secondary, "secondary")
            if not isinstance(mode, str) or mode not in {"auto", "axfr", "ixfr"}:
                self._deny("INVALID_REQUEST", "mode must be auto, axfr or ixfr")
            if since is not None and not _is_serial(since):
                self._deny("INVALID_REQUEST", "since must be a 32-bit unsigned integer")
            timestamp = self._now(now)

            state = self._require_zone(zone, auth_error=True)
            self._check_authorization(zone, secondary, source, key_name, timestamp)
            if (zone, secondary) in self._active:
                self._deny(
                    "TRANSFER_IN_PROGRESS",
                    f"a transfer for secondary {secondary!r} is already active",
                )

            plan_mode, plan_since, messages = self._plan_locked(
                state, secondary, mode, since,
            )
            self._aborted.pop((zone, secondary), None)
            return self._start_active(
                state, secondary, source, key_name,
                plan_mode, plan_since, messages, timestamp,
            )

    def record_progress(self, zone: str, secondary: str, *, messages: int = 0,
                        bytes_: int = 0, last_soa: int | None = None,
                        now: int | None = None) -> ProgressReport:
        with self._lock:
            self._require_text(zone, "zone")
            self._require_text(secondary, "secondary")
            if not _is_int(messages) or messages < 0:
                self._deny("INVALID_REQUEST", "messages must be a non-negative integer")
            if not _is_int(bytes_) or bytes_ < 0:
                self._deny("INVALID_REQUEST", "bytes_ must be a non-negative integer")
            if last_soa is not None and not _is_serial(last_soa):
                self._deny("INVALID_REQUEST", "last_soa must be a 32-bit unsigned integer")
            timestamp = self._now(now)

            active = self._active.get((zone, secondary))
            if active is None:
                self._deny(
                    "TRANSFER_NOT_ACTIVE",
                    f"no transfer is active for secondary {secondary!r}",
                )

            new_messages = active["messages"] + messages
            new_bytes = active["bytes_sent"] + bytes_
            if new_messages > self.max_messages or new_bytes > self.max_bytes:
                self._abort_active_locked(active, "budget exceeded", timestamp,
                                          budget=True)
                self._deny(
                    "BUDGET_EXCEEDED",
                    {
                        "messages": new_messages,
                        "bytes_sent": new_bytes,
                        "max_messages": self.max_messages,
                        "max_bytes": self.max_bytes,
                    },
                )

            active["messages"] = new_messages
            active["bytes_sent"] = new_bytes
            if last_soa is not None:
                active["last_soa"] = last_soa
            self._counters["messages_sent"] += messages
            self._counters["bytes_sent"] += bytes_

            return ProgressReport(
                zone=zone,
                secondary=secondary,
                mode=active["mode"],
                messages=active["messages"],
                bytes_sent=active["bytes_sent"],
                remaining_messages=max(0, self.max_messages - active["messages"]),
                remaining_bytes=max(0, self.max_bytes - active["bytes_sent"]),
                last_soa=active["last_soa"],
            )

    def complete(self, zone: str, secondary: str, *, digest: str,
                 now: int | None = None) -> TransferReceipt:
        with self._lock:
            self._require_text(zone, "zone")
            self._require_text(secondary, "secondary")
            timestamp = self._now(now)

            active = self._active.get((zone, secondary))
            if active is None:
                self._deny(
                    "TRANSFER_NOT_ACTIVE",
                    f"no transfer is active for secondary {secondary!r}",
                )
            state = self._zones.get(zone)
            if state is None:
                self._deny("INVALID_REQUEST", f"zone {zone!r} is not loaded")
            if not isinstance(digest, str) or digest != state.digest:
                self._deny("DIGEST_MISMATCH", "digest does not match the zone")

            serial = active["serial"]
            self._watermarks[(zone, secondary)] = serial
            self._active.pop((zone, secondary), None)
            self._aborted.pop((zone, secondary), None)
            self._counters["transfers_completed"] += 1
            return TransferReceipt(
                zone=zone,
                secondary=secondary,
                mode=active["mode"],
                serial=serial,
                digest=state.digest,
                messages=active["messages"],
                bytes_sent=active["bytes_sent"],
                state="completed",
            )

    def abort(self, zone: str, secondary: str, *, reason: str = "",
              now: int | None = None) -> dict:
        with self._lock:
            self._require_text(zone, "zone")
            self._require_text(secondary, "secondary")
            if not isinstance(reason, str):
                self._deny("INVALID_REQUEST", "reason must be a string")
            timestamp = self._now(now)

            active = self._active.get((zone, secondary))
            if active is None:
                self._deny(
                    "TRANSFER_NOT_ACTIVE",
                    f"no transfer is active for secondary {secondary!r}",
                )
            record = self._abort_active_locked(active, reason, timestamp)
            return {**copy.deepcopy(record), "state": "aborted"}

    def resume(self, zone: str, secondary: str, *, source: str, key_name: str,
               now: int | None = None) -> TransferPlan:
        with self._lock:
            self._require_text(zone, "zone")
            self._require_text(secondary, "secondary")
            timestamp = self._now(now)
            state = self._require_zone(zone, auth_error=True)
            self._check_authorization(zone, secondary, source, key_name, timestamp)
            if (zone, secondary) in self._active:
                self._deny(
                    "TRANSFER_IN_PROGRESS",
                    f"a transfer for secondary {secondary!r} is already active",
                )
            record = self._aborted.get((zone, secondary))
            if record is None:
                self._deny(
                    "TRANSFER_NOT_ACTIVE",
                    f"no aborted transfer is available for secondary {secondary!r}",
                )

            baseline = record.get("last_soa")
            if baseline is None:
                baseline = record.get("since")
            if baseline is None:
                baseline = self._watermarks.get((zone, secondary))

            plan_mode, plan_since, messages = self._plan_locked(
                state, secondary, "auto", baseline,
            )
            self._aborted.pop((zone, secondary), None)
            return self._start_active(
                state, secondary, source, key_name,
                plan_mode, plan_since, messages, timestamp,
            )

    def zone_status(self, zone: str) -> dict:
        with self._lock:
            self._require_text(zone, "zone")
            state = self._zones.get(zone)
            if state is None:
                self._deny("INVALID_REQUEST", f"zone {zone!r} is not loaded")
            watermarks = tuple(sorted(
                (secondary, serial)
                for (wm_zone, secondary), serial in self._watermarks.items()
                if wm_zone == zone
            ))
            active = tuple(sorted(
                secondary
                for (active_zone, secondary) in self._active
                if active_zone == zone
            ))
            return {
                "zone": zone,
                "serial": state.serial,
                "digest": state.digest,
                "records": len(state.records),
                "watermarks": watermarks,
                "active": active,
            }

    def stats(self) -> dict:
        with self._lock:
            return {key: self._counters[key] for key in _COUNTER_KEYS}

    # ------------------------------------------------------------------
    # Snapshots
    # ------------------------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            zones = {
                zone: {
                    "zone": state.zone,
                    "serial": state.serial,
                    "digest": state.digest,
                    "records": list(state.records),
                    "history": list(state.history),
                    "loaded_at": state.loaded_at,
                }
                for zone, state in self._zones.items()
            }
            keys = {zone: sorted(names) for zone, names in self._keys.items()}
            return copy.deepcopy({
                "version": 1,
                "zones": zones,
                "keys": keys,
                "auths": self._auths,
                "active": self._active,
                "aborted": self._aborted,
                "watermarks": self._watermarks,
                "counters": self._counters,
            })

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                zones, keys, auths, active, aborted, watermarks, counters = (
                    self._restore_validate(state)
                )
            except TransferDenied:
                raise
            except (TypeError, ValueError, KeyError, OverflowError) as exc:
                self._snapshot_invalid(str(exc))

            # Commit all state only after the entire snapshot has validated.
            self._zones = zones
            self._keys = keys
            self._auths = auths
            self._active = active
            self._aborted = aborted
            self._watermarks = watermarks
            self._counters = counters

    def _restore_validate(self, state: dict):
        if not isinstance(state, dict):
            self._snapshot_invalid("snapshot must be a dictionary")
        if set(state) != _SNAPSHOT_KEYS:
            self._snapshot_invalid("snapshot must contain exactly the eight required keys")
        if state.get("version") != 1 or not _is_int(state.get("version")):
            self._snapshot_invalid("unsupported snapshot version")

        raw_zones = state["zones"]
        raw_keys = state["keys"]
        raw_auths = state["auths"]
        raw_active = state["active"]
        raw_aborted = state["aborted"]
        raw_watermarks = state["watermarks"]
        raw_counters = state["counters"]
        if not all(isinstance(item, dict) for item in (
            raw_zones, raw_keys, raw_auths, raw_active,
            raw_aborted, raw_watermarks, raw_counters,
        )):
            self._snapshot_invalid("all snapshot sections must be dictionaries")

        zones: dict[str, ZoneState] = {}
        for zone, entry in raw_zones.items():
            if not isinstance(zone, str) or not zone or not isinstance(entry, dict):
                self._snapshot_invalid("invalid zone entry")
            required = {"zone", "serial", "digest", "records", "history", "loaded_at"}
            if set(entry) != required:
                self._snapshot_invalid(f"invalid zone fields for {zone!r}")
            if entry["zone"] != zone or not isinstance(entry["digest"], str) \
                    or not entry["digest"]:
                self._snapshot_invalid(f"invalid zone identity for {zone!r}")
            if not _is_serial(entry["serial"]) or not _is_int(entry["loaded_at"]):
                self._snapshot_invalid(f"invalid zone metadata for {zone!r}")
            records = entry["records"]
            history = entry["history"]
            if not isinstance(records, (list, tuple)) or not records:
                self._snapshot_invalid(f"invalid records for {zone!r}")
            if not isinstance(history, (list, tuple)):
                self._snapshot_invalid(f"invalid history for {zone!r}")
            if any(not _is_serial(item) for item in history):
                self._snapshot_invalid(f"invalid serial in history for {zone!r}")
            if any(not isinstance(item, str) or not item for item in records):
                self._snapshot_invalid(f"invalid record in {zone!r}")
            zones[zone] = ZoneState(
                zone=zone,
                serial=entry["serial"],
                digest=entry["digest"],
                records=tuple(records),
                history=tuple(history),
                loaded_at=entry["loaded_at"],
            )

        keys: dict[str, set[str]] = {}
        for zone, names in raw_keys.items():
            if not isinstance(zone, str) or not zone:
                self._snapshot_invalid("invalid key zone")
            if not isinstance(names, (list, tuple, set)):
                self._snapshot_invalid(f"invalid key list for {zone!r}")
            if any(not isinstance(name, str) or not name for name in names):
                self._snapshot_invalid(f"invalid key name for {zone!r}")
            keys[zone] = set(names)

        def pair(raw_key: object, label: str) -> tuple[str, str]:
            if not isinstance(raw_key, tuple) or len(raw_key) != 2:
                self._snapshot_invalid(f"invalid {label} key")
            zone, secondary = raw_key
            if not isinstance(zone, str) or not zone \
                    or not isinstance(secondary, str) or not secondary:
                self._snapshot_invalid(f"invalid {label} key")
            if zone not in zones:
                self._snapshot_invalid(f"{label} references unknown zone {zone!r}")
            return zone, secondary

        auths: dict[tuple[str, str], dict] = {}
        auth_fields = {"zone", "secondary", "source", "key_name",
                       "expires_at", "state"}
        for raw_key, entry in raw_auths.items():
            key = pair(raw_key, "authorization")
            if not isinstance(entry, dict) or set(entry) != auth_fields:
                self._snapshot_invalid(f"invalid authorization for {key!r}")
            if entry["zone"] != key[0] or entry["secondary"] != key[1]:
                self._snapshot_invalid(f"authorization identity mismatch for {key!r}")
            if any(not isinstance(entry[field], str) or not entry[field]
                   for field in ("source", "key_name", "state")):
                self._snapshot_invalid(f"invalid authorization fields for {key!r}")
            if not _is_int(entry["expires_at"]):
                self._snapshot_invalid(f"invalid authorization expiry for {key!r}")
            auths[key] = {
                "zone": entry["zone"],
                "secondary": entry["secondary"],
                "source": entry["source"],
                "key_name": entry["key_name"],
                "expires_at": entry["expires_at"],
                "state": entry["state"],
            }

        active_fields = {
            "zone", "secondary", "source", "key_name", "mode", "since",
            "serial", "digest", "target_messages", "messages", "bytes_sent",
            "last_soa", "started_at",
        }
        active: dict[tuple[str, str], dict] = {}
        for raw_key, entry in raw_active.items():
            key = pair(raw_key, "active transfer")
            if not isinstance(entry, dict) or set(entry) != active_fields:
                self._snapshot_invalid(f"invalid active transfer for {key!r}")
            if entry["zone"] != key[0] or entry["secondary"] != key[1]:
                self._snapshot_invalid(f"active transfer identity mismatch for {key!r}")
            for field in ("source", "key_name", "digest"):
                if not isinstance(entry[field], str) or not entry[field]:
                    self._snapshot_invalid(f"invalid {field} for active transfer {key!r}")
            if entry["mode"] not in {"nochange", "ixfr", "axfr"}:
                self._snapshot_invalid(f"invalid mode for active transfer {key!r}")
            if not _is_serial(entry["serial"]) or not _is_int(entry["started_at"]):
                self._snapshot_invalid(f"invalid metadata for active transfer {key!r}")
            if entry["since"] is not None and not _is_serial(entry["since"]):
                self._snapshot_invalid(f"invalid since for active transfer {key!r}")
            if entry["last_soa"] is not None and not _is_serial(entry["last_soa"]):
                self._snapshot_invalid(f"invalid last_soa for active transfer {key!r}")
            for field in ("target_messages", "messages", "bytes_sent"):
                if not _is_int(entry[field]) or entry[field] < 0:
                    self._snapshot_invalid(f"invalid {field} for active transfer {key!r}")
            active[key] = {field: entry[field] for field in active_fields}

        aborted_fields = {
            "zone", "secondary", "source", "key_name", "mode", "since",
            "serial", "digest", "last_soa", "messages", "bytes_sent",
            "reason", "at",
        }
        aborted: dict[tuple[str, str], dict] = {}
        for raw_key, entry in raw_aborted.items():
            key = pair(raw_key, "aborted transfer")
            if not isinstance(entry, dict) or set(entry) != aborted_fields:
                self._snapshot_invalid(f"invalid aborted transfer for {key!r}")
            if entry["zone"] != key[0] or entry["secondary"] != key[1]:
                self._snapshot_invalid(f"aborted transfer identity mismatch for {key!r}")
            if any(not isinstance(entry[field], str) or not entry[field]
                   for field in ("source", "key_name")):
                self._snapshot_invalid(f"invalid aborted identity for {key!r}")
            if entry["mode"] not in {"nochange", "ixfr", "axfr"}:
                self._snapshot_invalid(f"invalid mode for aborted transfer {key!r}")
            if not _is_serial(entry["serial"]) or not _is_int(entry["at"]):
                self._snapshot_invalid(f"invalid metadata for aborted transfer {key!r}")
            if entry["since"] is not None and not _is_serial(entry["since"]):
                self._snapshot_invalid(f"invalid since for aborted transfer {key!r}")
            if entry["last_soa"] is not None and not _is_serial(entry["last_soa"]):
                self._snapshot_invalid(f"invalid last_soa for aborted transfer {key!r}")
            for field in ("messages", "bytes_sent"):
                if not _is_int(entry[field]) or entry[field] < 0:
                    self._snapshot_invalid(f"invalid {field} for aborted transfer {key!r}")
            if not isinstance(entry["digest"], str) or not entry["digest"] \
                    or not isinstance(entry["reason"], str):
                self._snapshot_invalid(f"invalid aborted fields for {key!r}")
            aborted[key] = {field: entry[field] for field in aborted_fields}

        watermarks: dict[tuple[str, str], int] = {}
        for raw_key, serial in raw_watermarks.items():
            key = pair(raw_key, "watermark")
            if not _is_serial(serial):
                self._snapshot_invalid(f"invalid watermark for {key!r}")
            watermarks[key] = serial

        if set(raw_counters) != set(_COUNTER_KEYS):
            self._snapshot_invalid("counters must contain exactly the required keys")
        counters: dict[str, int] = {}
        for key, value in raw_counters.items():
            if not _is_int(value) or value < 0:
                self._snapshot_invalid(f"invalid counter {key!r}")
            counters[key] = value

        return (
            zones,
            keys,
            auths,
            active,
            aborted,
            watermarks,
            counters,
        )
