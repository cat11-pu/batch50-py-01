"""Sample quarantine vault: hash based dedup, reference protection, tombstones."""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from typing import Any


class VaultError(ValueError):
    """Raised when the vault refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATUS_ACTIVE = "active"
STATUS_TOMBSTONE = "tombstone"

RECORD_STATES = (STATUS_ACTIVE, STATUS_TOMBSTONE)

_HASH_RE = re.compile(r"[0-9a-f]{64}\Z")
_SNAPSHOT_VERSION = 1
_COUNTER_KEYS = (
    "admitted",
    "duplicates",
    "evicted",
    "purged",
    "destroyed",
    "denied",
)
_RECORD_FIELDS = frozenset(
    (
        "content_hash",
        "size_bytes",
        "source",
        "admitted_at",
        "retain_until",
        "priority",
        "refcount",
        "admissions",
        "status",
    )
)
_TOMBSTONE_FIELDS = _RECORD_FIELDS | frozenset(
    ("actor", "destroyed_at", "tombstones_until")
)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_hash(value: object) -> bool:
    return isinstance(value, str) and _HASH_RE.fullmatch(value) is not None


def _is_nonempty_text(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _parse_utc(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    else:
        raise ValueError("timestamp must be an ISO-8601 string")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


@dataclass(frozen=True)
class SampleRecord:
    content_hash: str
    size_bytes: int
    source: str
    admitted_at: str
    retain_until: str
    priority: int
    refcount: int
    admissions: int
    status: str


class SampleQuarantineVault:
    """Hold quarantined samples by content hash with case references."""

    def __init__(self, *, quota_bytes: int = 100000000,
                 retention_days: int = 30,
                 tombstone_days: int = 7) -> None:
        self.quota_bytes = quota_bytes
        self.retention_days = retention_days
        self.tombstone_days = tombstone_days
        self._lock = threading.RLock()
        self._records: dict[str, SampleRecord] = {}
        self._cases: dict[str, list[str]] = {}
        self._tombstones: dict[str, dict[str, Any]] = {}
        self._audit: list[dict[str, Any]] = []
        self._counters: dict[str, int] = {
            key: 0 for key in _COUNTER_KEYS
        }

    def _deny(self, code: str, detail: object = None) -> None:
        self._counters["denied"] += 1
        raise VaultError(code, detail)

    def _validate_hash(self, content_hash: object) -> str:
        if not _is_hash(content_hash):
            self._deny("VAULT_BAD_HASH", content_hash)
        return content_hash

    def _validate_size(self, size_bytes: object) -> int:
        if not _is_int(size_bytes) or size_bytes <= 0:
            self._deny("VAULT_BAD_SIZE", size_bytes)
        return size_bytes

    def _validate_retention(self, retention_days: object) -> int:
        if (not _is_int(retention_days)
                or not 1 <= retention_days <= 3650):
            self._deny("VAULT_BAD_RETENTION", retention_days)
        return retention_days

    def _validate_source(self, source: object) -> str:
        if not _is_nonempty_text(source):
            self._deny("VAULT_BAD_SOURCE", source)
        return source

    def _validate_priority(self, priority: object) -> int:
        if not _is_int(priority) or not 0 <= priority <= 9:
            self._deny("VAULT_BAD_PRIORITY", priority)
        return priority

    def _validate_case_id(self, case_id: object) -> str:
        if not _is_nonempty_text(case_id):
            self._deny("VAULT_BAD_REQUEST", "case_id must be a non-empty string")
        return case_id

    def _parse_now(self, now: object) -> datetime:
        try:
            return _parse_utc(now)
        except (TypeError, ValueError) as exc:
            self._deny("VAULT_BAD_REQUEST", f"invalid timestamp: {exc}")
        raise AssertionError("unreachable")

    def _active_record(self, content_hash: str) -> SampleRecord:
        record = self._records.get(content_hash)
        if record is None:
            if content_hash in self._tombstones:
                self._deny("VAULT_DESTROYED", content_hash)
            self._deny("VAULT_UNKNOWN", content_hash)
        return record

    def _used_bytes(self) -> int:
        return sum(record.size_bytes for record in self._records.values())

    def _audit_event(self, action: str, content_hash: str,
                     **details: Any) -> None:
        event: dict[str, Any] = {
            "action": action,
            "content_hash": content_hash,
        }
        event.update(details)
        self._audit.append(event)

    def _record_dict(self, record: SampleRecord) -> dict[str, Any]:
        result = asdict(record)
        result["cases"] = list(self._cases.get(record.content_hash, ()))
        return result

    def admit(self, content_hash: str, *, size_bytes: int, source: str,
              now: str, priority: int = 0,
              retention_days: int | None = None) -> SampleRecord:
        with self._lock:
            content_hash = self._validate_hash(content_hash)
            size_bytes = self._validate_size(size_bytes)
            source = self._validate_source(source)
            priority = self._validate_priority(priority)
            effective_retention = self._validate_retention(
                self.retention_days if retention_days is None
                else retention_days
            )
            admitted_at = self._parse_now(now)
            admitted_iso = _format_utc(admitted_at)

            existing = self._records.get(content_hash)
            if existing is not None:
                updated = replace(
                    existing,
                    admissions=existing.admissions + 1,
                )
                self._records[content_hash] = updated
                self._counters["admitted"] += 1
                self._counters["duplicates"] += 1
                self._audit_event(
                    "admit",
                    content_hash,
                    duplicate=True,
                    admissions=updated.admissions,
                )
                return updated

            tombstone = self._tombstones.get(content_hash)
            revived = False
            if tombstone is not None:
                tombstones_until = _parse_utc(tombstone["tombstones_until"])
                if admitted_at <= tombstones_until:
                    effective_size = tombstone["size_bytes"]
                    if self._used_bytes() + effective_size > self.quota_bytes:
                        self._deny(
                            "VAULT_QUOTA_EXCEEDED",
                            {
                                "needed_bytes": effective_size,
                                "free_bytes": (
                                    self.quota_bytes - self._used_bytes()
                                ),
                            },
                        )
                    retain_until = admitted_at + timedelta(
                        days=effective_retention
                    )
                    updated = SampleRecord(
                        content_hash=content_hash,
                        size_bytes=effective_size,
                        source=tombstone["source"],
                        admitted_at=tombstone["admitted_at"],
                        retain_until=_format_utc(retain_until),
                        priority=tombstone["priority"],
                        refcount=0,
                        admissions=tombstone["admissions"] + 1,
                        status=STATUS_ACTIVE,
                    )
                    del self._tombstones[content_hash]
                    self._records[content_hash] = updated
                    self._cases[content_hash] = []
                    self._counters["admitted"] += 1
                    self._counters["duplicates"] += 1
                    self._audit_event(
                        "admit",
                        content_hash,
                        duplicate=True,
                        revived=True,
                        admissions=updated.admissions,
                    )
                    return updated
                revived = True

            if self._used_bytes() + size_bytes > self.quota_bytes:
                self._deny(
                    "VAULT_QUOTA_EXCEEDED",
                    {
                        "needed_bytes": size_bytes,
                        "free_bytes": self.quota_bytes - self._used_bytes(),
                    },
                )

            retain_until = admitted_at + timedelta(days=effective_retention)
            record = SampleRecord(
                content_hash=content_hash,
                size_bytes=size_bytes,
                source=source,
                admitted_at=admitted_iso,
                retain_until=_format_utc(retain_until),
                priority=priority,
                refcount=0,
                admissions=1,
                status=STATUS_ACTIVE,
            )
            if revived:
                del self._tombstones[content_hash]
            self._records[content_hash] = record
            self._cases[content_hash] = []
            self._counters["admitted"] += 1
            self._audit_event(
                "admit",
                content_hash,
                duplicate=False,
                admissions=1,
            )
            return record

    def lookup(self, content_hash: str) -> dict:
        with self._lock:
            content_hash = self._validate_hash(content_hash)
            record = self._active_record(content_hash)
            return self._record_dict(record)

    def tag(self, content_hash: str, case_id: str) -> int:
        with self._lock:
            content_hash = self._validate_hash(content_hash)
            case_id = self._validate_case_id(case_id)
            record = self._active_record(content_hash)
            cases = self._cases.setdefault(content_hash, [])
            if case_id not in cases:
                cases.append(case_id)
                self._records[content_hash] = replace(
                    record,
                    refcount=len(cases),
                )
                self._audit_event(
                    "tag",
                    content_hash,
                    case_id=case_id,
                    refcount=len(cases),
                )
            return len(cases)

    def untag(self, content_hash: str, case_id: str) -> int:
        with self._lock:
            content_hash = self._validate_hash(content_hash)
            case_id = self._validate_case_id(case_id)
            record = self._active_record(content_hash)
            cases = self._cases.setdefault(content_hash, [])
            if case_id not in cases:
                self._deny("VAULT_UNKNOWN_CASE", case_id)
            cases.remove(case_id)
            self._records[content_hash] = replace(
                record,
                refcount=len(cases),
            )
            self._audit_event(
                "untag",
                content_hash,
                case_id=case_id,
                refcount=len(cases),
            )
            return len(cases)

    def evict(self, *, needed_bytes: int, now: str) -> list[str]:
        with self._lock:
            if not _is_int(needed_bytes) or needed_bytes <= 0:
                self._deny(
                    "VAULT_BAD_REQUEST",
                    "needed_bytes must be a positive integer",
                )
            self._parse_now(now)

            candidates = [
                record for record in self._records.values()
                if not self._cases.get(record.content_hash)
            ]
            candidates.sort(
                key=lambda record: (
                    record.priority,
                    _parse_utc(record.admitted_at),
                    record.content_hash,
                )
            )

            selected: list[SampleRecord] = []
            reclaimed = 0
            for record in candidates:
                selected.append(record)
                reclaimed += record.size_bytes
                if reclaimed >= needed_bytes:
                    break

            if reclaimed < needed_bytes:
                self._deny(
                    "VAULT_QUOTA_EXCEEDED",
                    {
                        "needed_bytes": needed_bytes,
                        "available_bytes": reclaimed,
                    },
                )

            removed: list[str] = []
            for record in selected:
                del self._records[record.content_hash]
                self._cases.pop(record.content_hash, None)
                removed.append(record.content_hash)
                self._audit_event(
                    "evict",
                    record.content_hash,
                    size_bytes=record.size_bytes,
                    now=now,
                )
            self._counters["evicted"] += len(removed)
            return removed

    def purge_expired(self, *, now: str) -> list[str]:
        with self._lock:
            current = self._parse_now(now)
            removed: list[str] = []
            for content_hash, record in list(self._records.items()):
                if self._cases.get(content_hash):
                    continue
                if _parse_utc(record.retain_until) > current:
                    continue
                del self._records[content_hash]
                self._cases.pop(content_hash, None)
                removed.append(content_hash)
                self._audit_event(
                    "purge",
                    content_hash,
                    size_bytes=record.size_bytes,
                    now=now,
                )
            self._counters["purged"] += len(removed)
            return removed

    def destroy(self, content_hash: str, *, actor: str, now: str) -> dict:
        with self._lock:
            content_hash = self._validate_hash(content_hash)
            if not _is_nonempty_text(actor):
                self._deny(
                    "VAULT_BAD_REQUEST",
                    "actor must be a non-empty string",
                )
            destroyed_at = self._parse_now(now)
            record = self._active_record(content_hash)
            if record.refcount or self._cases.get(content_hash):
                self._deny("VAULT_PROTECTED", content_hash)

            destroyed_iso = _format_utc(destroyed_at)
            tombstones_until = destroyed_at + timedelta(
                days=self.tombstone_days
            )
            receipt = {
                "content_hash": record.content_hash,
                "size_bytes": record.size_bytes,
                "source": record.source,
                "admitted_at": record.admitted_at,
                "retain_until": record.retain_until,
                "priority": record.priority,
                "refcount": 0,
                "admissions": record.admissions,
                "status": STATUS_TOMBSTONE,
                "actor": actor,
                "destroyed_at": destroyed_iso,
                "tombstones_until": _format_utc(tombstones_until),
            }
            del self._records[content_hash]
            self._cases.pop(content_hash, None)
            self._tombstones[content_hash] = receipt
            self._counters["destroyed"] += 1
            self._audit_event(
                "destroy",
                content_hash,
                actor=actor,
                destroyed_at=destroyed_iso,
            )
            return copy.deepcopy(receipt)

    def samples(self) -> list[SampleRecord]:
        with self._lock:
            return list(self._records.values())

    def tombstones(self) -> list[dict]:
        with self._lock:
            return [
                copy.deepcopy(tombstone)
                for tombstone in self._tombstones.values()
            ]

    def capacity_report(self) -> dict:
        with self._lock:
            used = self._used_bytes()
            protected = sum(
                1 for record in self._records.values() if record.refcount
            )
            active = len(self._records)
            return {
                "quota_bytes": self.quota_bytes,
                "used_bytes": used,
                "free_bytes": self.quota_bytes - used,
                "active": active,
                "protected": protected,
                "evictable": active - protected,
            }

    def stats(self) -> dict:
        with self._lock:
            return {
                "active": len(self._records),
                "protected": sum(
                    1 for record in self._records.values()
                    if record.refcount
                ),
                "tombstoned": len(self._tombstones),
                "admitted": self._counters["admitted"],
                "duplicates": self._counters["duplicates"],
                "evicted": self._counters["evicted"],
                "purged": self._counters["purged"],
                "destroyed": self._counters["destroyed"],
                "denied": self._counters["denied"],
                "total_bytes": self._used_bytes(),
            }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "quota_bytes": self.quota_bytes,
                "retention_days": self.retention_days,
                "tombstone_days": self.tombstone_days,
                "records": [
                    asdict(record) for record in self._records.values()
                ],
                "cases": {
                    content_hash: list(cases)
                    for content_hash, cases in self._cases.items()
                    if content_hash in self._records
                },
                "tombstones": [
                    copy.deepcopy(tombstone)
                    for tombstone in self._tombstones.values()
                ],
                "counters": dict(self._counters),
                "audit": copy.deepcopy(self._audit),
            }

    @staticmethod
    def _snapshot_invalid(detail: object) -> None:
        raise VaultError("VAULT_SNAPSHOT_INVALID", detail)

    @staticmethod
    def _valid_snapshot_time(value: object) -> bool:
        try:
            _parse_utc(value)
        except (TypeError, ValueError):
            return False
        return True

    def restore(self, state: dict) -> None:
        with self._lock:
            if not isinstance(state, dict):
                self._snapshot_invalid("state must be a dict")
            if (not _is_int(state.get("version"))
                    or state.get("version") != _SNAPSHOT_VERSION):
                self._snapshot_invalid("unsupported snapshot version")

            required = {
                "quota_bytes",
                "retention_days",
                "tombstone_days",
                "records",
                "cases",
                "tombstones",
                "counters",
            }
            if not required.issubset(state):
                self._snapshot_invalid("snapshot is missing required fields")

            quota_bytes = state["quota_bytes"]
            retention_days = state["retention_days"]
            tombstone_days = state["tombstone_days"]
            raw_records = state["records"]
            raw_cases = state["cases"]
            raw_tombstones = state["tombstones"]
            raw_counters = state["counters"]

            if (not _is_int(quota_bytes) or quota_bytes < 0
                    or not _is_int(retention_days)
                    or not 1 <= retention_days <= 3650
                    or not _is_int(tombstone_days)
                    or tombstone_days < 0):
                self._snapshot_invalid("invalid vault configuration")
            if not isinstance(raw_records, list):
                self._snapshot_invalid("records must be a list")
            if not isinstance(raw_cases, dict):
                self._snapshot_invalid("cases must be a dict")
            if not isinstance(raw_tombstones, list):
                self._snapshot_invalid("tombstones must be a list")
            if not isinstance(raw_counters, dict):
                self._snapshot_invalid("counters must be a dict")
            if any(
                    not _is_int(raw_counters.get(key))
                    or raw_counters[key] < 0
                    for key in _COUNTER_KEYS
            ):
                self._snapshot_invalid("invalid counters")

            records: dict[str, SampleRecord] = {}
            for raw in raw_records:
                if not isinstance(raw, dict):
                    self._snapshot_invalid("record must be a dict")
                if not _RECORD_FIELDS.issubset(raw):
                    self._snapshot_invalid("record is missing fields")
                content_hash = raw["content_hash"]
                if not _is_hash(content_hash) or content_hash in records:
                    self._snapshot_invalid("invalid or duplicate record hash")
                if (not _is_int(raw["size_bytes"]) or raw["size_bytes"] <= 0
                        or not _is_nonempty_text(raw["source"])
                        or not self._valid_snapshot_time(raw["admitted_at"])
                        or not self._valid_snapshot_time(raw["retain_until"])
                        or not _is_int(raw["priority"])
                        or not 0 <= raw["priority"] <= 9
                        or not _is_int(raw["refcount"])
                        or raw["refcount"] < 0
                        or not _is_int(raw["admissions"])
                        or raw["admissions"] <= 0
                        or raw["status"] != STATUS_ACTIVE):
                    self._snapshot_invalid("invalid record values")
                records[content_hash] = SampleRecord(
                    content_hash=content_hash,
                    size_bytes=raw["size_bytes"],
                    source=raw["source"],
                    admitted_at=raw["admitted_at"],
                    retain_until=raw["retain_until"],
                    priority=raw["priority"],
                    refcount=raw["refcount"],
                    admissions=raw["admissions"],
                    status=raw["status"],
                )

            cases: dict[str, list[str]] = {
                content_hash: [] for content_hash in records
            }
            for content_hash, raw_case_list in raw_cases.items():
                if (not _is_hash(content_hash)
                        or content_hash not in records
                        or not isinstance(raw_case_list, list)):
                    self._snapshot_invalid("invalid cases entry")
                if any(
                        not _is_nonempty_text(case_id)
                        for case_id in raw_case_list
                ):
                    self._snapshot_invalid("invalid case id")
                if len(set(raw_case_list)) != len(raw_case_list):
                    self._snapshot_invalid("duplicate case id")
                cases[content_hash] = list(raw_case_list)
            for content_hash, record in records.items():
                if record.refcount != len(cases[content_hash]):
                    self._snapshot_invalid("record refcount mismatch")

            tombstones: dict[str, dict[str, Any]] = {}
            for raw in raw_tombstones:
                if not isinstance(raw, dict):
                    self._snapshot_invalid("tombstone must be a dict")
                if not _TOMBSTONE_FIELDS.issubset(raw):
                    self._snapshot_invalid("tombstone is missing fields")
                content_hash = raw["content_hash"]
                if (not _is_hash(content_hash)
                        or content_hash in tombstones
                        or content_hash in records):
                    self._snapshot_invalid(
                        "invalid, duplicate, or active tombstone hash"
                    )
                if (not _is_int(raw["size_bytes"]) or raw["size_bytes"] <= 0
                        or not _is_nonempty_text(raw["source"])
                        or not self._valid_snapshot_time(raw["admitted_at"])
                        or not self._valid_snapshot_time(raw["retain_until"])
                        or not _is_int(raw["priority"])
                        or not 0 <= raw["priority"] <= 9
                        or not _is_int(raw["refcount"])
                        or not 0 <= raw["refcount"]
                        or not _is_int(raw["admissions"])
                        or raw["admissions"] <= 0
                        or raw["status"] != STATUS_TOMBSTONE
                        or not _is_nonempty_text(raw["actor"])
                        or not self._valid_snapshot_time(raw["destroyed_at"])
                        or not self._valid_snapshot_time(
                            raw["tombstones_until"]
                        )):
                    self._snapshot_invalid("invalid tombstone values")
                tombstones[content_hash] = copy.deepcopy(raw)

            if sum(record.size_bytes for record in records.values()) > quota_bytes:
                self._snapshot_invalid("records exceed quota")

            raw_audit = state.get("audit", [])
            if (not isinstance(raw_audit, list)
                    or any(not isinstance(event, dict) for event in raw_audit)):
                self._snapshot_invalid("audit must be a list of dicts")

            counters = {
                key: raw_counters[key] for key in _COUNTER_KEYS
            }
            audit = copy.deepcopy(raw_audit)

            self.quota_bytes = quota_bytes
            self.retention_days = retention_days
            self.tombstone_days = tombstone_days
            self._records = records
            self._cases = cases
            self._tombstones = tombstones
            self._counters = counters
            self._audit = audit
