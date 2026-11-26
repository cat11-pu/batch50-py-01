"""Backup immutability warden: retention locks, monotonic extension, canary freeze."""

from __future__ import annotations

import copy
import math
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone
from numbers import Number
from typing import Any


class WardenError(ValueError):
    """Raised when a warden operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATUS_LOCKED = "locked"
STATUS_RELEASED = "released"
STATUS_VERIFIED = "verified"
STATUS_UNUSABLE = "unusable"

SNAPSHOT_VERSION = 1
COUNTER_KEYS = ("locked", "extended", "released", "frozen", "integrity_failed")
LOCK_FIELDS = (
    "restore_point",
    "size_gb",
    "min_retention_days",
    "locked_at",
    "expires_at",
    "extensions",
    "status",
)
VERDICT_FIELDS = (
    "restore_point",
    "status",
    "total_chunks",
    "ok_chunks",
    "usable",
)


def _parse_datetime(value: object) -> datetime:
    """Parse an ISO timestamp without consulting the host local timezone."""
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("timestamp is empty")
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    else:
        raise TypeError("timestamp must be an ISO string or datetime")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _utc_datetime(value: object, *, field: str = "now") -> datetime:
    try:
        return _parse_datetime(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise WardenError(
            "WARDEN_BAD_REQUEST", {"field": field, "value": value}
        ) from exc


def _strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _finite_number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, Number):
        return None
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    if not math.isfinite(number):
        return None
    return number


@dataclass(frozen=True)
class LockRecord:
    restore_point: str
    size_gb: float
    min_retention_days: int
    locked_at: str
    expires_at: str
    extensions: int
    status: str


@dataclass(frozen=True)
class RestoreVerdict:
    restore_point: str
    status: str
    total_chunks: int
    ok_chunks: int
    usable: bool


class BackupImmutabilityWarden:
    """Hold restore points immutable, freeze the repository on canary drift."""

    def __init__(self, *, quota_gb: float = 1000.0) -> None:
        quota = _finite_number(quota_gb)
        if quota is None or quota < 0:
            raise WardenError("WARDEN_BAD_SIZE", {"quota_gb": quota_gb})
        self.quota_gb = quota
        self._lock = threading.RLock()
        self._locks: dict[str, LockRecord] = {}
        self._released: dict[str, dict[str, Any]] = {}
        self._canaries: dict[str, str] = {}
        self._frozen: str = ""
        self._verdicts: dict[str, RestoreVerdict] = {}
        self._audit: list[dict[str, Any]] = []
        self._counters: dict[str, int] = {key: 0 for key in COUNTER_KEYS}

    def _require_restore_point(self, restore_point: object) -> str:
        if not isinstance(restore_point, str) or not restore_point:
            raise WardenError(
                "WARDEN_BAD_REQUEST", {"restore_point": restore_point}
            )
        return restore_point

    def _active_size(self) -> float:
        return sum(
            record.size_gb
            for record in self._locks.values()
            if record.status == STATUS_LOCKED
        )

    def _quota_exceeded(self, additional: float = 0.0) -> bool:
        quota = _finite_number(self.quota_gb)
        if quota is None or quota < 0:
            raise WardenError("WARDEN_BAD_SIZE", {"quota_gb": self.quota_gb})
        used = self._active_size() + additional
        return used > quota and not math.isclose(
            used, quota, rel_tol=1e-12, abs_tol=1e-12
        )

    def _record_event(
        self,
        action: str,
        *,
        restore_point: str | None = None,
        actor: str | None = None,
        now: object = None,
        **detail: Any,
    ) -> None:
        try:
            timestamp = _format_utc(_parse_datetime(now))
        except (TypeError, ValueError, OverflowError):
            timestamp = now if isinstance(now, str) else repr(now)
        event: dict[str, Any] = {"action": action, "at": timestamp}
        if restore_point is not None:
            event["restore_point"] = restore_point
        if actor is not None:
            event["actor"] = actor
        if detail:
            event["detail"] = detail
        self._audit.append(event)

    def _get_active_lock(self, restore_point: str) -> LockRecord:
        record = self._locks.get(restore_point)
        if record is None or record.status == STATUS_RELEASED:
            raise WardenError(
                "WARDEN_NOT_LOCKED", {"restore_point": restore_point}
            )
        return record

    def register_canary(self, path: str, digest: str) -> None:
        if not isinstance(path, str) or not path:
            raise WardenError("WARDEN_BAD_REQUEST", {"path": path})
        if not isinstance(digest, str) or not digest:
            raise WardenError("WARDEN_BAD_REQUEST", {"digest": digest})
        with self._lock:
            self._canaries[path] = digest
            self._record_event("register_canary", detail={"path": path})

    def lock(
        self,
        restore_point: str,
        *,
        size_gb: float,
        min_retention_days: int,
        now: str,
    ) -> LockRecord:
        restore_point = self._require_restore_point(restore_point)
        with self._lock:
            if self._frozen:
                raise WardenError(
                    "WARDEN_REPO_FROZEN",
                    {"restore_point": restore_point, "reason": self._frozen},
                )
            if restore_point in self._locks:
                raise WardenError(
                    "WARDEN_ALREADY_LOCKED", {"restore_point": restore_point}
                )
            if not _strict_int(min_retention_days) or not (
                1 <= min_retention_days <= 3650
            ):
                raise WardenError(
                    "WARDEN_BAD_RETENTION",
                    {"min_retention_days": min_retention_days},
                )
            size = _finite_number(size_gb)
            if size is None or size <= 0:
                raise WardenError("WARDEN_BAD_SIZE", {"size_gb": size_gb})
            locked_at = _utc_datetime(now)
            if self._quota_exceeded(size):
                raise WardenError(
                    "WARDEN_QUOTA_EXCEEDED",
                    {"quota_gb": self.quota_gb, "size_gb": size},
                )
            try:
                expires = locked_at + timedelta(days=min_retention_days)
            except OverflowError as exc:
                raise WardenError(
                    "WARDEN_BAD_RETENTION",
                    {"min_retention_days": min_retention_days},
                ) from exc

            record = LockRecord(
                restore_point=restore_point,
                size_gb=size,
                min_retention_days=min_retention_days,
                locked_at=_format_utc(locked_at),
                expires_at=_format_utc(expires),
                extensions=0,
                status=STATUS_LOCKED,
            )
            self._locks[restore_point] = record
            self._counters["locked"] += 1
            self._record_event(
                "lock",
                restore_point=restore_point,
                now=now,
                size_gb=size,
                min_retention_days=min_retention_days,
            )
            return record

    def extend(
        self, restore_point: str, *, extra_days: int, now: str
    ) -> LockRecord:
        restore_point = self._require_restore_point(restore_point)
        with self._lock:
            record = self._get_active_lock(restore_point)
            if not _strict_int(extra_days):
                raise WardenError(
                    "WARDEN_BAD_RETENTION", {"extra_days": extra_days}
                )
            if extra_days < 0:
                raise WardenError(
                    "WARDEN_LOCK_SHRINK", {"extra_days": extra_days}
                )
            if extra_days == 0:
                raise WardenError(
                    "WARDEN_BAD_RETENTION", {"extra_days": extra_days}
                )
            _utc_datetime(now)
            if self._quota_exceeded():
                raise WardenError(
                    "WARDEN_QUOTA_EXCEEDED",
                    {"quota_gb": self.quota_gb, "size_gb": record.size_gb},
                )
            current_expiry = _parse_datetime(record.expires_at)
            try:
                new_expiry = current_expiry + timedelta(days=extra_days)
            except OverflowError as exc:
                raise WardenError(
                    "WARDEN_BAD_RETENTION", {"extra_days": extra_days}
                ) from exc
            if new_expiry <= current_expiry:
                raise WardenError(
                    "WARDEN_LOCK_SHRINK",
                    {"restore_point": restore_point, "extra_days": extra_days},
                )

            updated = LockRecord(
                restore_point=record.restore_point,
                size_gb=record.size_gb,
                min_retention_days=record.min_retention_days,
                locked_at=record.locked_at,
                expires_at=_format_utc(new_expiry),
                extensions=record.extensions + 1,
                status=record.status,
            )
            self._locks[restore_point] = updated
            self._counters["extended"] += 1
            self._record_event(
                "extend",
                restore_point=restore_point,
                now=now,
                extra_days=extra_days,
            )
            return updated

    def release(
        self, restore_point: str, *, actor: str, now: str
    ) -> dict[str, Any]:
        restore_point = self._require_restore_point(restore_point)
        with self._lock:
            record = self._locks.get(restore_point)
            if record is None:
                raise WardenError(
                    "WARDEN_NOT_LOCKED", {"restore_point": restore_point}
                )
            if (
                record.status == STATUS_RELEASED
                or restore_point in self._released
            ):
                raise WardenError(
                    "WARDEN_ALREADY_RELEASED",
                    {"restore_point": restore_point},
                )
            if record.status != STATUS_LOCKED:
                raise WardenError(
                    "WARDEN_NOT_LOCKED", {"restore_point": restore_point}
                )

            released_at = _utc_datetime(now)
            expires_at = _parse_datetime(record.expires_at)
            if released_at < expires_at:
                raise WardenError(
                    "WARDEN_LOCK_HELD",
                    {
                        "restore_point": restore_point,
                        "expires_at": record.expires_at,
                    },
                )

            receipt = {
                "restore_point": restore_point,
                "actor": actor,
                "status": STATUS_RELEASED,
                "released_at": _format_utc(released_at),
            }
            self._locks[restore_point] = LockRecord(
                restore_point=record.restore_point,
                size_gb=record.size_gb,
                min_retention_days=record.min_retention_days,
                locked_at=record.locked_at,
                expires_at=record.expires_at,
                extensions=record.extensions,
                status=STATUS_RELEASED,
            )
            self._released[restore_point] = receipt
            self._counters["released"] += 1
            self._record_event(
                "release",
                restore_point=restore_point,
                actor=actor,
                now=now,
            )
            return copy.deepcopy(receipt)

    def on_lock_file_missing(
        self, restore_point: str, *, actor: str, now: str
    ) -> dict[str, Any]:
        restore_point = self._require_restore_point(restore_point)
        with self._lock:
            self._frozen = f"lock_file_missing:{restore_point}"
            self._counters["frozen"] += 1
            self._record_event(
                "lock_file_missing",
                restore_point=restore_point,
                actor=actor,
                now=now,
            )
            raise WardenError(
                "WARDEN_TAMPER_DETECTED",
                {"restore_point": restore_point, "actor": actor},
            )

    def check_canary(
        self, path: str, *, observed_digest: str, now: str
    ) -> dict[str, Any]:
        with self._lock:
            if path not in self._canaries:
                raise WardenError(
                    "WARDEN_CANARY_UNKNOWN", {"path": path}
                )
            _utc_datetime(now)
            matches = observed_digest == self._canaries[path]
            if not matches:
                self._frozen = f"canary_mismatch:{path}"
                self._counters["frozen"] += 1
                self._record_event(
                    "canary_mismatch",
                    now=now,
                    path=path,
                )
            return {
                "path": path,
                "ok": matches,
                "frozen": bool(self._frozen),
            }

    def verify_restore(
        self,
        restore_point: str,
        *,
        total_chunks: int,
        ok_chunks: int,
        now: str,
    ) -> RestoreVerdict:
        restore_point = self._require_restore_point(restore_point)
        with self._lock:
            self._get_active_lock(restore_point)
            if (
                not _strict_int(total_chunks)
                or not _strict_int(ok_chunks)
                or total_chunks < 1
                or ok_chunks < 0
                or ok_chunks > total_chunks
            ):
                raise WardenError(
                    "WARDEN_BAD_REQUEST",
                    {
                        "total_chunks": total_chunks,
                        "ok_chunks": ok_chunks,
                    },
                )
            _utc_datetime(now)
            usable = ok_chunks == total_chunks
            verdict = RestoreVerdict(
                restore_point=restore_point,
                status=STATUS_VERIFIED if usable else STATUS_UNUSABLE,
                total_chunks=total_chunks,
                ok_chunks=ok_chunks,
                usable=usable,
            )
            self._verdicts[restore_point] = verdict
            if not usable:
                self._counters["integrity_failed"] += 1
            self._record_event(
                "verify_restore",
                restore_point=restore_point,
                now=now,
                total_chunks=total_chunks,
                ok_chunks=ok_chunks,
            )
            return verdict

    def can_backup(self) -> bool:
        with self._lock:
            return not bool(self._frozen)

    def restore_allowed(self, restore_point: str) -> bool:
        with self._lock:
            record = self._locks.get(restore_point)
            if record is None or record.status == STATUS_RELEASED:
                return False
            verdict = self._verdicts.get(restore_point)
            return verdict is None or verdict.usable

    def retention(self, restore_point: str, *, now: str) -> dict[str, Any]:
        restore_point = self._require_restore_point(restore_point)
        with self._lock:
            record = self._get_active_lock(restore_point)
            current = _utc_datetime(now)
            expires = _parse_datetime(record.expires_at)
            remaining_days = (expires - current).days
            return {
                "restore_point": restore_point,
                "expires_at": record.expires_at,
                "remaining_days": remaining_days,
            }

    def locks(self) -> list[LockRecord]:
        with self._lock:
            return list(self._locks.values())

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            counters = {
                key: self._counters.get(key, 0) for key in COUNTER_KEYS
            }
            state = {
                "version": SNAPSHOT_VERSION,
                "quota_gb": self.quota_gb,
                "locks": {
                    restore_point: asdict(record)
                    for restore_point, record in self._locks.items()
                },
                "released": copy.deepcopy(self._released),
                "canaries": copy.deepcopy(self._canaries),
                "frozen": self._frozen,
                "verdicts": {
                    restore_point: asdict(verdict)
                    for restore_point, verdict in self._verdicts.items()
                },
                "audit": copy.deepcopy(self._audit),
                "counters": copy.deepcopy(counters),
                "stats": copy.deepcopy(counters),
            }
            return copy.deepcopy(state)

    @staticmethod
    def _validate_snapshot(
        state: object,
    ) -> tuple[
        float,
        dict[str, LockRecord],
        dict[str, dict[str, Any]],
        dict[str, str],
        str,
        dict[str, RestoreVerdict],
        list[dict[str, Any]],
        dict[str, int],
    ]:
        def invalid(detail: object = None) -> None:
            raise WardenError("WARDEN_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict):
            invalid("snapshot must be an object")
        required = {
            "version",
            "quota_gb",
            "locks",
            "released",
            "canaries",
            "frozen",
            "verdicts",
            "audit",
            "counters",
            "stats",
        }
        if not required.issubset(state):
            invalid({"missing": sorted(required.difference(state))})
        if not _strict_int(state["version"]) or state["version"] != SNAPSHOT_VERSION:
            invalid({"version": state["version"]})

        quota = _finite_number(state["quota_gb"])
        if quota is None or quota < 0:
            invalid({"quota_gb": state["quota_gb"]})

        raw_locks = state["locks"]
        if not isinstance(raw_locks, dict):
            invalid("locks must be an object")
        locks: dict[str, LockRecord] = {}
        for restore_point, raw in raw_locks.items():
            if not isinstance(restore_point, str) or not restore_point:
                invalid("invalid restore point key")
            if not isinstance(raw, dict) or any(
                field not in raw for field in LOCK_FIELDS
            ):
                invalid({"restore_point": restore_point, "lock": raw})
            if raw["restore_point"] != restore_point:
                invalid({"restore_point": restore_point, "lock": raw})
            size = _finite_number(raw["size_gb"])
            if size is None or size <= 0:
                invalid({"restore_point": restore_point, "size_gb": raw["size_gb"]})
            min_days = raw["min_retention_days"]
            if not _strict_int(min_days) or not 1 <= min_days <= 3650:
                invalid(
                    {
                        "restore_point": restore_point,
                        "min_retention_days": min_days,
                    }
                )
            extensions = raw["extensions"]
            if not _strict_int(extensions) or extensions < 0:
                invalid(
                    {"restore_point": restore_point, "extensions": extensions}
                )
            if raw["status"] not in (STATUS_LOCKED, STATUS_RELEASED):
                invalid(
                    {"restore_point": restore_point, "status": raw["status"]}
                )
            try:
                locked_dt = _parse_datetime(raw["locked_at"])
                expires_dt = _parse_datetime(raw["expires_at"])
            except (TypeError, ValueError, OverflowError):
                invalid({"restore_point": restore_point, "timestamps": raw})
            base_expiry = locked_dt + timedelta(days=min_days)
            if expires_dt <= locked_dt:
                invalid(
                    {
                        "restore_point": restore_point,
                        "expires_at": raw["expires_at"],
                    }
                )
            if extensions == 0 and expires_dt != base_expiry:
                invalid(
                    {
                        "restore_point": restore_point,
                        "expires_at": raw["expires_at"],
                    }
                )
            if extensions > 0 and expires_dt <= base_expiry:
                invalid(
                    {
                        "restore_point": restore_point,
                        "expires_at": raw["expires_at"],
                    }
                )
            locks[restore_point] = LockRecord(
                restore_point=restore_point,
                size_gb=size,
                min_retention_days=min_days,
                locked_at=_format_utc(locked_dt),
                expires_at=_format_utc(expires_dt),
                extensions=extensions,
                status=raw["status"],
            )

        raw_released = state["released"]
        if not isinstance(raw_released, dict):
            invalid("released must be an object")
        released: dict[str, dict[str, Any]] = {}
        for restore_point, raw in raw_released.items():
            if not isinstance(restore_point, str) or restore_point not in locks:
                invalid({"released": restore_point})
            if locks[restore_point].status != STATUS_RELEASED:
                invalid({"released_without_lock": restore_point})
            if not isinstance(raw, dict):
                invalid({"released": restore_point})
            if (
                raw.get("restore_point") != restore_point
                or raw.get("status") != STATUS_RELEASED
                or not isinstance(raw.get("actor"), str)
                or "released_at" not in raw
            ):
                invalid({"released": restore_point})
            try:
                released_dt = _parse_datetime(raw["released_at"])
            except (TypeError, ValueError, OverflowError):
                invalid(
                    {
                        "released": restore_point,
                        "released_at": raw.get("released_at"),
                    }
                )
            released[restore_point] = {
                "restore_point": restore_point,
                "actor": raw["actor"],
                "status": STATUS_RELEASED,
                "released_at": _format_utc(released_dt),
            }
        for restore_point, record in locks.items():
            if record.status == STATUS_RELEASED and restore_point not in released:
                invalid({"released_without_receipt": restore_point})

        raw_canaries = state["canaries"]
        if not isinstance(raw_canaries, dict):
            invalid("canaries must be an object")
        canaries: dict[str, str] = {}
        for path, digest in raw_canaries.items():
            if not isinstance(path, str) or not isinstance(digest, str):
                invalid({"canary": path})
            canaries[path] = digest

        frozen = state["frozen"]
        if not isinstance(frozen, str):
            invalid({"frozen": frozen})

        raw_verdicts = state["verdicts"]
        if not isinstance(raw_verdicts, dict):
            invalid("verdicts must be an object")
        verdicts: dict[str, RestoreVerdict] = {}
        for restore_point, raw in raw_verdicts.items():
            if restore_point not in locks:
                invalid({"verdict": restore_point})
            if not isinstance(raw, dict) or any(
                field not in raw for field in VERDICT_FIELDS
            ):
                invalid({"verdict": restore_point})
            total = raw["total_chunks"]
            ok = raw["ok_chunks"]
            if (
                raw["restore_point"] != restore_point
                or not _strict_int(total)
                or not _strict_int(ok)
                or total < 1
                or ok < 0
                or ok > total
                or not isinstance(raw["usable"], bool)
            ):
                invalid({"verdict": restore_point})
            expected_status = (
                STATUS_VERIFIED if ok == total else STATUS_UNUSABLE
            )
            expected_usable = ok == total
            if (
                raw["status"] != expected_status
                or raw["usable"] is not expected_usable
            ):
                invalid({"verdict": restore_point})
            verdicts[restore_point] = RestoreVerdict(
                restore_point=restore_point,
                status=expected_status,
                total_chunks=total,
                ok_chunks=ok,
                usable=expected_usable,
            )

        raw_audit = state["audit"]
        if not isinstance(raw_audit, list) or any(
            not isinstance(entry, dict) for entry in raw_audit
        ):
            invalid("audit must be a list of objects")
        audit = copy.deepcopy(raw_audit)

        raw_counters = state["counters"]
        raw_stats = state["stats"]
        if not isinstance(raw_counters, dict) or not isinstance(raw_stats, dict):
            invalid("counters and stats must be objects")
        counters: dict[str, int] = {}
        for key in COUNTER_KEYS:
            counter = raw_counters.get(key)
            stat = raw_stats.get(key)
            if (
                not _strict_int(counter)
                or counter < 0
                or not _strict_int(stat)
                or stat < 0
                or counter != stat
            ):
                invalid({"counter": key})
            counters[key] = counter

        return (
            quota,
            locks,
            released,
            canaries,
            frozen,
            verdicts,
            audit,
            counters,
        )

    def restore(self, state: dict[str, Any]) -> None:
        with self._lock:
            try:
                detached = copy.deepcopy(state)
                (
                    quota,
                    locks,
                    released,
                    canaries,
                    frozen,
                    verdicts,
                    audit,
                    counters,
                ) = self._validate_snapshot(detached)
            except WardenError:
                raise
            except Exception as exc:
                raise WardenError(
                    "WARDEN_SNAPSHOT_INVALID", str(exc)
                ) from exc

            for restore_point, receipt in self._released.items():
                current = self._locks.get(restore_point)
                if current is None or current.status != STATUS_RELEASED:
                    continue
                locks[restore_point] = current
                released[restore_point] = copy.deepcopy(receipt)

            if self._frozen:
                frozen = self._frozen

            counters["released"] = max(
                counters["released"], self._counters.get("released", 0)
            )
            if self._frozen:
                counters["frozen"] = max(
                    counters["frozen"], self._counters.get("frozen", 0)
                )

            self.quota_gb = quota
            self._locks = locks
            self._released = released
            self._canaries = canaries
            self._frozen = frozen
            self._verdicts = verdicts
            self._audit = audit
            self._counters = counters

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {
                key: self._counters.get(key, 0) for key in COUNTER_KEYS
            }
