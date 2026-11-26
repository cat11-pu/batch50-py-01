"""Blind XSS payload leases and callback correlation."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import secrets
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


class CallbackError(ValueError):
    """Raised when a payload or callback operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


SNAPSHOT_VERSION = 1
SNAPSHOT_KEYS = frozenset(
    {"version", "leases", "events", "dedupe", "counters", "seq"}
)
COUNTER_KEYS = (
    "issued",
    "reused",
    "callbacks",
    "duplicates",
    "throttled",
    "expired",
    "revoked",
    "abuse",
    "active",
)
CONCLUSION_KEYS = ("confirmed", "probable", "orphan")
LEASE_STATUSES = frozenset({"active", "expired", "revoked"})


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return _is_int(value) or isinstance(value, float)


def _require_text(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CallbackError(
            "CALLBACK_INVALID_REQUEST",
            {"field": field_name, "reason": "must be a non-empty string"},
        )
    return value


def _parse_iso(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty ISO-8601 string")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="seconds")


def _coerce_datetime(value: object, clock: object = None) -> datetime:
    if value is None and clock is not None:
        if hasattr(clock, "now"):
            now_value = clock.now
            value = now_value() if callable(now_value) else now_value
        elif callable(clock):
            value = clock()

    if value is None:
        parsed = datetime.now(timezone.utc)
    elif isinstance(value, datetime):
        parsed = value
    elif _is_int(value) or isinstance(value, float):
        parsed = datetime.fromtimestamp(value, tz=timezone.utc)
    else:
        parsed = _parse_iso(value)

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _ttl_delta(ttl: object, default_ttl: object) -> tuple[timedelta, int | float]:
    value = default_ttl if ttl is None else ttl
    if isinstance(value, timedelta):
        delta = value
    elif _is_number(value):
        if isinstance(value, bool):
            raise CallbackError(
                "CALLBACK_INVALID_REQUEST", {"field": "ttl", "reason": "invalid ttl"}
            )
        delta = timedelta(seconds=float(value))
    else:
        raise CallbackError(
            "CALLBACK_INVALID_REQUEST", {"field": "ttl", "reason": "ttl must be numeric"}
        )

    seconds = delta.total_seconds()
    if seconds < 0:
        raise CallbackError(
            "CALLBACK_INVALID_REQUEST", {"field": "ttl", "reason": "ttl must be non-negative"}
        )
    stored_ttl: int | float = int(seconds) if seconds.is_integer() else seconds
    return delta, stored_ttl


@dataclass(frozen=True)
class PayloadLease:
    payload_id: str
    target: str
    injection_point: str
    tenant: str
    issued_at: str
    expires_at: str
    signature: str
    status: str
    reuse_count: int = 0
    ttl: int | float | None = None
    last_reused_at: str | None = None
    expired_at: str | None = None
    revoked_at: str | None = None
    revoke_reason: str | None = None
    first_source_ip: str | None = None
    first_callback_at: str | None = None
    callback_count: int = 0
    distinct_source_count: int = 0
    events: tuple = ()


@dataclass(frozen=True)
class CallbackEvent:
    payload_id: str
    source_ip: str
    ua: str
    received_at: str
    dedupe_key: str
    seq: int = 0
    conclusion: str | None = None
    reason: str | None = None


@dataclass(frozen=True)
class Correlation:
    payload_id: str
    conclusion: str
    tenant: str
    evidence: dict


class XssCallbackCorrelator:
    """Issue payload leases per injection point and correlate returning callbacks."""

    def __init__(self, *, secret: str = "corr-secret", max_payloads: int = 200,
                 default_ttl: int = 1800, per_source_limit: int = 10,
                 per_payload_limit: int = 3, clock=None) -> None:
        self.secret = secret
        self.max_payloads = max_payloads
        self.default_ttl = default_ttl
        self.per_source_limit = per_source_limit
        self.per_payload_limit = per_payload_limit
        self._clock = clock
        self._lock = threading.RLock()
        self._reset_state()

    def _reset_state(self) -> None:
        self._version = SNAPSHOT_VERSION
        self._leases: list[dict] = []
        self._leases_by_id: dict[str, dict] = {}
        self._events: list[dict] = []
        self._events_by_seq: dict[int, dict] = {}
        self._dedupe: dict[str, dict] = {}
        self._seq = 0
        self._counters = {key: 0 for key in COUNTER_KEYS}
        self._counters["conclusions"] = {key: 0 for key in CONCLUSION_KEYS}

    def _refresh_active_count(self) -> int:
        active = sum(1 for record in self._leases if record["status"] == "active")
        self._counters["active"] = active
        return active

    def _now(self, value: object) -> datetime:
        try:
            return _coerce_datetime(value, self._clock)
        except CallbackError:
            raise
        except Exception as exc:
            raise CallbackError(
                "CALLBACK_INVALID_REQUEST", {"field": "now", "reason": "invalid timestamp"}
            ) from exc

    def _signature_for(self, payload_id: str) -> str:
        material = f"{self.secret}:{payload_id}".encode("utf-8")
        return hashlib.sha256(material).hexdigest()[:16]

    def _new_payload_id(self) -> str:
        while True:
            payload_id = "PL-" + secrets.token_hex(6)
            if payload_id not in self._leases_by_id:
                return payload_id

    @staticmethod
    def _dedupe_key(payload_id: str, source_ip: str, ua: str) -> str:
        material = json.dumps(
            [payload_id, source_ip, ua], ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    @staticmethod
    def _lease_expiry(record: dict) -> datetime:
        issued_at = _parse_iso(record["issued_at"])
        ttl = record.get("ttl")
        if _is_number(ttl):
            return issued_at + timedelta(seconds=float(ttl))
        return _parse_iso(record["expires_at"])

    def issue_payload(self, target: str, injection_point: str, *,
                      tenant: str = "t1", ttl=None, now=None) -> PayloadLease:
        target = _require_text(target, "target")
        injection_point = _require_text(injection_point, "injection_point")
        tenant = _require_text(tenant, "tenant")
        ttl_delta, stored_ttl = _ttl_delta(ttl, self.default_ttl)

        with self._lock:
            issued_at = self._now(now)
            issued_text = _iso(issued_at)

            for record in reversed(self._leases):
                same_scope = (
                    record["tenant"] == tenant
                    and record["target"] == target
                    and record["injection_point"] == injection_point
                )
                if not same_scope or record["status"] != "active":
                    continue
                if self._lease_expiry(record) <= issued_at:
                    continue

                record["reuse_count"] = int(record.get("reuse_count", 0)) + 1
                record["last_reused_at"] = issued_text
                self._counters["reused"] += 1
                self._refresh_active_count()
                return self._to_lease(record)

            active_count = sum(
                1
                for record in self._leases
                if record["status"] == "active"
                and self._lease_expiry(record) > issued_at
            )
            if active_count >= self.max_payloads:
                raise CallbackError(
                    "CALLBACK_CAPACITY_EXCEEDED",
                    {"max_payloads": self.max_payloads, "active": active_count},
                )

            self._seq += 1
            payload_id = self._new_payload_id()
            expires_at = issued_at + ttl_delta
            record = {
                "seq": self._seq,
                "payload_id": payload_id,
                "target": target,
                "injection_point": injection_point,
                "tenant": tenant,
                "issued_at": issued_text,
                "ttl": stored_ttl,
                "expires_at": _iso(expires_at),
                "signature": self._signature_for(payload_id),
                "status": "active",
                "reuse_count": 0,
                "last_reused_at": None,
                "expired_at": None,
                "revoked_at": None,
                "revoke_reason": None,
            }
            self._leases.append(record)
            self._leases_by_id[payload_id] = record
            self._counters["issued"] += 1
            self._refresh_active_count()
            return self._to_lease(record)

    def handle_callback(self, payload_id: str, *, signature: str,
                        source_ip: str, ua: str, now=None) -> Correlation:
        with self._lock:
            record = (
                self._leases_by_id.get(payload_id)
                if isinstance(payload_id, str)
                else None
            )
            if record is None:
                raise CallbackError(
                    "CALLBACK_UNKNOWN_PAYLOAD", {"payload_id": payload_id}
                )

            expected_signature = self._signature_for(payload_id)
            if not isinstance(signature, str) or not hmac.compare_digest(
                expected_signature, signature
            ):
                self._counters["abuse"] += 1
                raise CallbackError(
                    "CALLBACK_SIGNATURE_INVALID", {"payload_id": payload_id}
                )

            if record["status"] == "revoked":
                raise CallbackError(
                    "CALLBACK_PAYLOAD_REVOKED", {"payload_id": payload_id}
                )

            received_at = self._now(now)
            received_text = _iso(received_at)
            dedupe_key = self._dedupe_key(payload_id, source_ip, ua)
            dedupe_record = self._dedupe.get(dedupe_key)

            if dedupe_record is not None:
                dedupe_record["count"] = int(dedupe_record.get("count", 1)) + 1
                dedupe_record["last_received_at"] = received_text
                self._counters["duplicates"] += 1
                event = self._events_by_seq[dedupe_record["event_seq"]]
                return self._correlation(event, record, True, dedupe_record)

            source_count = sum(
                1 for event in self._events if event["source_ip"] == source_ip
            )
            payload_count = sum(
                1 for event in self._events if event["payload_id"] == payload_id
            )
            if (source_count >= self.per_source_limit
                    or payload_count >= self.per_payload_limit):
                self._counters["throttled"] += 1
                raise CallbackError(
                    "CALLBACK_RATE_LIMITED",
                    {
                        "payload_id": payload_id,
                        "source_ip": source_ip,
                        "source_count": source_count,
                        "payload_count": payload_count,
                        "per_source_limit": self.per_source_limit,
                        "per_payload_limit": self.per_payload_limit,
                    },
                )

            payload_events = [
                event for event in self._events if event["payload_id"] == payload_id
            ]
            expired = self._lease_expiry(record) <= received_at
            if expired:
                conclusion = "orphan"
                reason = "callback_at_or_after_lease_expiry"
            elif not payload_events:
                conclusion = "confirmed"
                reason = "first_callback_for_payload"
            elif source_ip == payload_events[0]["source_ip"]:
                conclusion = "confirmed"
                reason = "same_source_as_first_callback"
            else:
                conclusion = "probable"
                reason = "source_differs_from_first_callback"

            self._seq += 1
            event = {
                "seq": self._seq,
                "payload_id": payload_id,
                "source_ip": source_ip,
                "ua": ua,
                "received_at": received_text,
                "dedupe_key": dedupe_key,
                "conclusion": conclusion,
                "reason": reason,
            }
            self._events.append(event)
            self._events_by_seq[self._seq] = event
            self._dedupe[dedupe_key] = {
                "dedupe_key": dedupe_key,
                "event_seq": self._seq,
                "payload_id": payload_id,
                "source_ip": source_ip,
                "ua": ua,
                "first_received_at": received_text,
                "last_received_at": received_text,
                "count": 1,
            }
            self._counters["callbacks"] += 1
            self._counters["conclusions"][conclusion] += 1
            return self._correlation(event, record, False, self._dedupe[dedupe_key])

    def lookup(self, payload_id: str):
        with self._lock:
            record = (
                self._leases_by_id.get(payload_id)
                if isinstance(payload_id, str)
                else None
            )
            if record is None:
                raise CallbackError(
                    "CALLBACK_UNKNOWN_PAYLOAD", {"payload_id": payload_id}
                )
            return self._to_lease(record, include_events=True)

    def expire(self, now=None) -> int:
        with self._lock:
            expires_as_of = self._now(now)
            changed = 0
            expired_text = _iso(expires_as_of)
            for record in self._leases:
                if record["status"] != "active":
                    continue
                if self._lease_expiry(record) <= expires_as_of:
                    record["status"] = "expired"
                    record["expired_at"] = expired_text
                    changed += 1
            self._counters["expired"] += changed
            self._refresh_active_count()
            return changed

    def revoke_payload(self, payload_id: str, reason: str) -> PayloadLease:
        with self._lock:
            record = (
                self._leases_by_id.get(payload_id)
                if isinstance(payload_id, str)
                else None
            )
            if record is None:
                raise CallbackError(
                    "CALLBACK_UNKNOWN_PAYLOAD", {"payload_id": payload_id}
                )
            if record["status"] != "revoked":
                record["status"] = "revoked"
                record["revoked_at"] = self._now(None).isoformat(timespec="seconds")
                record["revoke_reason"] = reason
                self._counters["revoked"] += 1
            self._refresh_active_count()
            return self._to_lease(record)

    def list_payloads(self, target=None) -> tuple:
        with self._lock:
            records = [
                record
                for record in self._leases
                if target is None or record["target"] == target
            ]
            records.sort(key=lambda record: (record["issued_at"], record["payload_id"]))
            return tuple(self._to_lease(record) for record in records)

    def set_rate_limit(self, *, per_source=None, per_payload=None) -> None:
        if per_source is not None and (not _is_int(per_source) or per_source < 0):
            raise CallbackError(
                "CALLBACK_INVALID_REQUEST", {"field": "per_source_limit"}
            )
        if per_payload is not None and (not _is_int(per_payload) or per_payload < 0):
            raise CallbackError(
                "CALLBACK_INVALID_REQUEST", {"field": "per_payload_limit"}
            )
        with self._lock:
            if per_source is not None:
                self.per_source_limit = per_source
            if per_payload is not None:
                self.per_payload_limit = per_payload

    def report(self) -> dict:
        with self._lock:
            active = self._refresh_active_count()
            return {
                "issued": self._counters["issued"],
                "reused": self._counters["reused"],
                "callbacks": self._counters["callbacks"],
                "duplicates": self._counters["duplicates"],
                "throttled": self._counters["throttled"],
                "expired": self._counters["expired"],
                "revoked": self._counters["revoked"],
                "abuse": self._counters["abuse"],
                "active": active,
                "conclusions": dict(self._counters["conclusions"]),
            }

    def snapshot(self) -> dict:
        with self._lock:
            self._refresh_active_count()
            state = {
                "version": self._version,
                "leases": copy.deepcopy(self._leases),
                "events": copy.deepcopy(self._events),
                "dedupe": copy.deepcopy(self._dedupe),
                "counters": copy.deepcopy(self._counters),
                "seq": self._seq,
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            restored = self._validated_snapshot(state)
            self._version = restored["version"]
            self._leases = restored["leases"]
            self._events = restored["events"]
            self._dedupe = restored["dedupe"]
            self._counters = restored["counters"]
            self._seq = restored["seq"]
            self._leases_by_id = {
                record["payload_id"]: record for record in self._leases
            }
            self._events_by_seq = {
                event["seq"]: event for event in self._events if _is_int(event.get("seq"))
            }
            self._refresh_active_count()

    def _events_for_payload(self, payload_id: str) -> list[dict]:
        return [event for event in self._events if event["payload_id"] == payload_id]

    def _event_view(self, event: dict) -> CallbackEvent:
        return CallbackEvent(
            payload_id=event["payload_id"],
            source_ip=event["source_ip"],
            ua=event["ua"],
            received_at=event["received_at"],
            dedupe_key=event["dedupe_key"],
            seq=event.get("seq", 0),
            conclusion=event.get("conclusion"),
            reason=event.get("reason"),
        )

    def _to_lease(self, record: dict, *, include_events: bool = False) -> PayloadLease:
        event_records = self._events_for_payload(record["payload_id"])
        first_event = event_records[0] if event_records else None
        return PayloadLease(
            payload_id=record["payload_id"],
            target=record["target"],
            injection_point=record["injection_point"],
            tenant=record["tenant"],
            issued_at=record["issued_at"],
            expires_at=record["expires_at"],
            signature=record["signature"],
            status=record["status"],
            reuse_count=int(record.get("reuse_count", 0)),
            ttl=record.get("ttl"),
            last_reused_at=record.get("last_reused_at"),
            expired_at=record.get("expired_at"),
            revoked_at=record.get("revoked_at"),
            revoke_reason=record.get("revoke_reason"),
            first_source_ip=first_event["source_ip"] if first_event else None,
            first_callback_at=first_event["received_at"] if first_event else None,
            callback_count=len(event_records),
            distinct_source_count=len(
                {event["source_ip"] for event in event_records}
            ),
            events=tuple(self._event_view(event) for event in event_records)
            if include_events
            else (),
        )

    def _correlation(self, event: dict, record: dict, duplicate: bool,
                     dedupe_record: dict) -> Correlation:
        payload_events = self._events_for_payload(record["payload_id"])
        first_event = payload_events[0] if payload_events else event
        evidence = {
            "event_seq": event.get("seq"),
            "reason": event.get("reason"),
            "basis": event.get("reason"),
            "duplicate": duplicate,
            "duplicate_count": int(dedupe_record.get("count", 1)),
            "payload_id": record["payload_id"],
            "tenant_source": "lease",
            "source_ip": event["source_ip"],
            "ua": event["ua"],
            "received_at": event["received_at"],
            "dedupe_key": event["dedupe_key"],
            "first_source_ip": first_event["source_ip"],
            "first_callback_at": first_event["received_at"],
            "event_count": len(payload_events),
            "distinct_source_count": len(
                {item["source_ip"] for item in payload_events}
            ),
            "issued_at": record["issued_at"],
            "expires_at": record["expires_at"],
            "ttl": record.get("ttl"),
        }
        if duplicate:
            evidence["first_received_at"] = dedupe_record.get("first_received_at")
            evidence["last_received_at"] = dedupe_record.get("last_received_at")
        return Correlation(
            payload_id=record["payload_id"],
            conclusion=event["conclusion"],
            tenant=record["tenant"],
            evidence=evidence,
        )

    def _validated_snapshot(self, state: object) -> dict:
        invalid = CallbackError("CALLBACK_SNAPSHOT_INVALID", "malformed snapshot")
        try:
            if not isinstance(state, dict) or not SNAPSHOT_KEYS.issubset(state.keys()):
                raise invalid
            data = copy.deepcopy(state)

            if not _is_int(data["version"]) or data["version"] != SNAPSHOT_VERSION:
                raise invalid
            if not isinstance(data["leases"], list):
                raise invalid
            if not isinstance(data["events"], list):
                raise invalid
            if not isinstance(data["dedupe"], dict):
                raise invalid
            if not isinstance(data["counters"], dict):
                raise invalid
            if not _is_int(data["seq"]) or data["seq"] < 0:
                raise invalid

            leases: list[dict] = []
            lease_ids: set[str] = set()
            max_seq = 0
            for raw_lease in data["leases"]:
                if not isinstance(raw_lease, dict):
                    raise invalid
                payload_id = raw_lease.get("payload_id")
                target = raw_lease.get("target")
                injection_point = raw_lease.get("injection_point")
                tenant = raw_lease.get("tenant")
                issued_at = raw_lease.get("issued_at")
                expires_at = raw_lease.get("expires_at")
                signature = raw_lease.get("signature")
                status = raw_lease.get("status")
                if (not isinstance(payload_id, str) or not payload_id
                        or payload_id in lease_ids):
                    raise invalid
                for text_value in (target, injection_point, tenant, signature):
                    if not isinstance(text_value, str) or not text_value:
                        raise invalid
                if status not in LEASE_STATUSES:
                    raise invalid
                try:
                    _parse_iso(issued_at)
                    _parse_iso(expires_at)
                except (TypeError, ValueError):
                    raise invalid from None

                seq = raw_lease.get("seq", 0)
                reuse_count = raw_lease.get("reuse_count", 0)
                ttl = raw_lease.get("ttl")
                if not _is_int(seq) or seq < 0:
                    raise invalid
                if not _is_int(reuse_count) or reuse_count < 0:
                    raise invalid
                if ttl is not None and (not _is_number(ttl) or ttl < 0):
                    raise invalid
                for key in ("last_reused_at", "expired_at", "revoked_at"):
                    value = raw_lease.get(key)
                    if value is not None:
                        try:
                            _parse_iso(value)
                        except (TypeError, ValueError):
                            raise invalid from None
                revoke_reason = raw_lease.get("revoke_reason")
                if revoke_reason is not None and not isinstance(revoke_reason, str):
                    raise invalid

                lease = {
                    "seq": seq,
                    "payload_id": payload_id,
                    "target": target,
                    "injection_point": injection_point,
                    "tenant": tenant,
                    "issued_at": issued_at,
                    "ttl": ttl,
                    "expires_at": expires_at,
                    "signature": signature,
                    "status": status,
                    "reuse_count": reuse_count,
                    "last_reused_at": raw_lease.get("last_reused_at"),
                    "expired_at": raw_lease.get("expired_at"),
                    "revoked_at": raw_lease.get("revoked_at"),
                    "revoke_reason": revoke_reason,
                }
                leases.append(lease)
                lease_ids.add(payload_id)
                max_seq = max(max_seq, seq)

            events: list[dict] = []
            events_by_seq: dict[int, dict] = {}
            event_dedupe_keys: set[str] = set()
            for raw_event in data["events"]:
                if not isinstance(raw_event, dict):
                    raise invalid
                seq = raw_event.get("seq")
                payload_id = raw_event.get("payload_id")
                source_ip = raw_event.get("source_ip")
                ua = raw_event.get("ua")
                received_at = raw_event.get("received_at")
                dedupe_key = raw_event.get("dedupe_key")
                conclusion = raw_event.get("conclusion")
                reason = raw_event.get("reason")
                if not _is_int(seq) or seq <= 0 or seq in events_by_seq:
                    raise invalid
                if not isinstance(payload_id, str) or payload_id not in lease_ids:
                    raise invalid
                if not isinstance(source_ip, str) or not source_ip:
                    raise invalid
                if not isinstance(ua, str):
                    raise invalid
                try:
                    _parse_iso(received_at)
                except (TypeError, ValueError):
                    raise invalid from None
                if not isinstance(dedupe_key, str) or not dedupe_key:
                    raise invalid
                if dedupe_key in event_dedupe_keys:
                    raise invalid
                if conclusion not in CONCLUSION_KEYS:
                    raise invalid
                if reason is not None and not isinstance(reason, str):
                    raise invalid

                event = {
                    "seq": seq,
                    "payload_id": payload_id,
                    "source_ip": source_ip,
                    "ua": ua,
                    "received_at": received_at,
                    "dedupe_key": dedupe_key,
                    "conclusion": conclusion,
                    "reason": reason,
                }
                events.append(event)
                events_by_seq[seq] = event
                event_dedupe_keys.add(dedupe_key)
                max_seq = max(max_seq, seq)

            dedupe: dict[str, dict] = {}
            for key, raw_dedupe in data["dedupe"].items():
                if not isinstance(key, str) or not key:
                    raise invalid
                if _is_int(raw_dedupe):
                    event_seq = raw_dedupe
                    count = 1
                    raw_ref = {}
                elif isinstance(raw_dedupe, dict):
                    event_seq = raw_dedupe.get("event_seq", raw_dedupe.get("seq"))
                    count = raw_dedupe.get("count", 1)
                    raw_ref = raw_dedupe
                    if not _is_int(count) or count < 1:
                        raise invalid
                else:
                    raise invalid

                event = events_by_seq.get(event_seq)
                if event is None or event["dedupe_key"] != key:
                    raise invalid
                first_at = raw_ref.get("first_received_at", event["received_at"])
                last_at = raw_ref.get("last_received_at", event["received_at"])
                try:
                    _parse_iso(first_at)
                    _parse_iso(last_at)
                except (TypeError, ValueError):
                    raise invalid from None
                dedupe[key] = {
                    "dedupe_key": key,
                    "event_seq": event_seq,
                    "payload_id": event["payload_id"],
                    "source_ip": event["source_ip"],
                    "ua": event["ua"],
                    "first_received_at": first_at,
                    "last_received_at": last_at,
                    "count": count,
                }

            if event_dedupe_keys != set(data["dedupe"].keys()):
                raise invalid

            raw_counters = data["counters"]
            expected_counter_keys = frozenset(COUNTER_KEYS) | {"conclusions"}
            if frozenset(raw_counters.keys()) != expected_counter_keys:
                raise invalid
            counters = {key: raw_counters[key] for key in COUNTER_KEYS}
            if not all(_is_int(value) and value >= 0 for value in counters.values()):
                raise invalid
            raw_conclusions = raw_counters["conclusions"]
            if not isinstance(raw_conclusions, dict):
                raise invalid
            if frozenset(raw_conclusions.keys()) != frozenset(CONCLUSION_KEYS):
                raise invalid
            if not all(
                _is_int(raw_conclusions[key]) and raw_conclusions[key] >= 0
                for key in CONCLUSION_KEYS
            ):
                raise invalid
            counters["conclusions"] = {
                key: raw_conclusions[key] for key in CONCLUSION_KEYS
            }

            if data["seq"] < max_seq:
                raise invalid

            return {
                "version": SNAPSHOT_VERSION,
                "leases": leases,
                "events": events,
                "dedupe": dedupe,
                "counters": counters,
                "seq": data["seq"],
            }
        except CallbackError:
            raise
        except Exception as exc:
            raise invalid from exc
