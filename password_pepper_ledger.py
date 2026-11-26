"""Password pepper version ledger.

Keeps tenant level pepper versions and the version / salt / parameters of every
stored password record: verification accepts the current and the previous
version, a successful login lazily rehashes an old record, and a leaked version
can be disabled outright.
"""

from __future__ import annotations

import copy
import hashlib
import hmac
import os
import threading
from collections.abc import Mapping
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from typing import Any

__all__ = [
    "PepperError",
    "PasswordRecord",
    "VerifyResult",
    "PasswordPepperLedger",
]

_ALGORITHM = "pbkdf2_sha256"
_HASH_NAME = "sha256"
_SNAPSHOT_KEYS = frozenset(
    {"version", "versions", "records", "pending", "force_reset", "stats"}
)
_STAT_KEYS = (
    "versions",
    "hashed",
    "verified",
    "invalid",
    "unknown",
    "reset_required",
    "rehash_queued",
    "rehash_deferred",
    "rehashed",
    "rehash_failed",
    "disabled_versions",
)


class PepperError(ValueError):
    """Raised when a pepper ledger operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PasswordRecord:
    account_id: str
    version: int
    algorithm: str
    iterations: int
    salt_hex: str
    digest_hex: str
    updated_at: str


@dataclass(frozen=True)
class VerifyResult:
    account_id: str
    status: str
    version: int | None
    rehash_queued: bool


def _now_value(now: str | None) -> str:
    return now if now is not None else datetime.now(timezone.utc).isoformat()


def _positive_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _non_negative_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _snapshot_invalid(detail: object = None) -> None:
    raise PepperError("PEPPER_SNAPSHOT_INVALID", detail)


def _strict_int(value: Any, field: str, *, positive: bool = False,
                 non_negative: bool = False) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        _snapshot_invalid({"field": field, "reason": "type"})
    if positive and value <= 0:
        _snapshot_invalid({"field": field, "reason": "must_be_positive"})
    if non_negative and value < 0:
        _snapshot_invalid({"field": field, "reason": "must_be_non_negative"})
    return value


def _non_empty_string(value: Any, field: str) -> str:
    if not isinstance(value, str) or value == "":
        _snapshot_invalid({"field": field, "reason": "must_be_non_empty_string"})
    return value


def _version_key(value: Any) -> int:
    if _positive_int(value):
        return value
    if isinstance(value, str):
        try:
            parsed = int(value)
        except ValueError as exc:
            _snapshot_invalid({"field": "version", "reason": "type"})
            raise AssertionError("unreachable") from exc
        if str(parsed) != value or parsed <= 0:
            _snapshot_invalid({"field": "version", "reason": "invalid_key"})
        return parsed
    _snapshot_invalid({"field": "version", "reason": "type"})
    raise AssertionError("unreachable")


def _parse_record(value: Any) -> PasswordRecord:
    if isinstance(value, PasswordRecord):
        return value
    if not isinstance(value, Mapping):
        _snapshot_invalid({"field": "record", "reason": "type"})

    required = {field.name for field in PasswordRecord.__dataclass_fields__.values()}
    missing = required.difference(value)
    if missing:
        _snapshot_invalid({"field": "record", "missing": sorted(missing)})

    account_id = _non_empty_string(value["account_id"], "account_id")
    version = _strict_int(value["version"], "version", positive=True)
    algorithm = _non_empty_string(value["algorithm"], "algorithm")
    if algorithm != _ALGORITHM:
        _snapshot_invalid({"field": "algorithm", "reason": "unsupported"})
    iterations = _strict_int(value["iterations"], "iterations", positive=True)
    salt_hex = _non_empty_string(value["salt_hex"], "salt_hex")
    digest_hex = _non_empty_string(value["digest_hex"], "digest_hex")
    updated_at = _non_empty_string(value["updated_at"], "updated_at")

    try:
        bytes.fromhex(salt_hex)
        bytes.fromhex(digest_hex)
    except ValueError as exc:
        _snapshot_invalid({"field": "hex", "reason": "invalid_hex"})
        raise AssertionError("unreachable") from exc

    return PasswordRecord(
        account_id=account_id,
        version=version,
        algorithm=algorithm,
        iterations=iterations,
        salt_hex=salt_hex,
        digest_hex=digest_hex,
        updated_at=updated_at,
    )


def _parse_versions(raw: Any, current_version: int) -> dict[int, dict[str, Any]]:
    entries: list[tuple[Any, Any]] = []
    if isinstance(raw, Mapping):
        entries = list(raw.items())
    elif isinstance(raw, list):
        for entry in raw:
            if not isinstance(entry, Mapping) or "version" not in entry:
                _snapshot_invalid({"field": "versions", "reason": "entry_type"})
            entries.append((entry["version"], entry))
    else:
        _snapshot_invalid({"field": "versions", "reason": "type"})

    versions: dict[int, dict[str, Any]] = {}
    for raw_version, raw_info in entries:
        version = _version_key(raw_version)
        if version in versions:
            _snapshot_invalid({"field": "versions", "reason": "duplicate_version"})

        registered_at: str | None = None
        disabled_at: str | None = None
        if isinstance(raw_info, str):
            pepper = raw_info
            enabled = True
        elif isinstance(raw_info, Mapping):
            pepper = raw_info.get("pepper")
            enabled = raw_info.get("enabled", True)
            registered_at = raw_info.get("registered_at")
            disabled_at = raw_info.get("disabled_at")
            if "registered_at" in raw_info and registered_at is not None:
                _non_empty_string(registered_at, "registered_at")
            if "disabled_at" in raw_info and disabled_at is not None:
                _non_empty_string(disabled_at, "disabled_at")
        else:
            _snapshot_invalid({"field": "versions", "reason": "info_type"})

        if not isinstance(pepper, str) or not pepper.strip():
            _snapshot_invalid({"field": "pepper", "reason": "empty"})
        if not isinstance(enabled, bool):
            _snapshot_invalid({"field": "enabled", "reason": "type"})

        versions[version] = {
            "pepper": pepper,
            "enabled": enabled,
            "registered_at": registered_at,
            "disabled_at": disabled_at,
        }

    if current_version == 0:
        if versions:
            _snapshot_invalid({"field": "version", "reason": "inconsistent"})
    elif current_version not in versions or current_version != max(versions):
        _snapshot_invalid({"field": "version", "reason": "missing_current"})

    return versions


def _parse_records(raw: Any, versions: Mapping[int, Any]) -> dict[str, PasswordRecord]:
    records: dict[str, PasswordRecord] = {}
    entries: list[Any]

    if isinstance(raw, list):
        entries = raw
    elif isinstance(raw, Mapping):
        entries = []
        for account_id, raw_record in raw.items():
            if isinstance(raw_record, Mapping) and "account_id" not in raw_record:
                raw_record = {**dict(raw_record), "account_id": account_id}
            entries.append(raw_record)
    else:
        _snapshot_invalid({"field": "records", "reason": "type"})

    for raw_record in entries:
        record = _parse_record(raw_record)
        if record.account_id in records:
            _snapshot_invalid({"field": "records", "reason": "duplicate_account"})
        if record.version not in versions:
            _snapshot_invalid({"field": "records", "reason": "unknown_version"})
        records[record.account_id] = record

    return records


def _parse_pending(
    raw: Any,
    records: Mapping[str, PasswordRecord],
    versions: Mapping[int, dict[str, Any]],
    current_version: int,
) -> tuple[list[str], dict[str, dict[str, Any]]]:
    raw_entries: list[tuple[Any, Mapping[str, Any]]] = []

    if isinstance(raw, list):
        for item in raw:
            if isinstance(item, str):
                raw_entries.append((item, {}))
            elif isinstance(item, Mapping):
                account_id = item.get("account_id", item.get("account"))
                raw_entries.append((account_id, item))
            elif (
                isinstance(item, (list, tuple))
                and len(item) == 2
                and isinstance(item[0], str)
            ):
                account_id, value = item
                if isinstance(value, str):
                    data: Mapping[str, Any] = {"password": value}
                elif isinstance(value, Mapping):
                    data = value
                else:
                    _snapshot_invalid({"field": "pending", "reason": "entry_type"})
                    raise AssertionError("unreachable")
                raw_entries.append((account_id, data))
            else:
                _snapshot_invalid({"field": "pending", "reason": "entry_type"})
    elif isinstance(raw, Mapping):
        for account_id, value in raw.items():
            if isinstance(value, str):
                raw_entries.append((account_id, {"password": value}))
            elif isinstance(value, Mapping):
                raw_entries.append((account_id, value))
            else:
                _snapshot_invalid({"field": "pending", "reason": "entry_type"})
    else:
        _snapshot_invalid({"field": "pending", "reason": "type"})

    queue: list[str] = []
    pending: dict[str, dict[str, Any]] = {}

    for raw_account_id, data in raw_entries:
        account_id = _non_empty_string(raw_account_id, "pending.account_id")
        if account_id in pending:
            _snapshot_invalid({"field": "pending", "reason": "duplicate_account"})
        record = records.get(account_id)
        if record is None:
            _snapshot_invalid({"field": "pending", "reason": "missing_record"})

        password = data.get("password", data.get("plaintext_password"))
        if password is not None and (not isinstance(password, str) or password == ""):
            _snapshot_invalid({"field": "pending.password", "reason": "type"})

        target_raw = data.get("target", data.get("record", data.get("new_record")))
        if target_raw is None and "digest_hex" in data:
            target_raw = data
        target = None if target_raw is None else _parse_record(target_raw)
        if target is not None:
            if target.account_id != account_id:
                _snapshot_invalid({"field": "pending.target", "reason": "account_mismatch"})
            if target.version not in versions or target.version != current_version:
                _snapshot_invalid({"field": "pending.target", "reason": "version"})

        base_version = data.get("base_version")
        if base_version is not None:
            base_version = _strict_int(
                base_version, "base_version", positive=True
            )
            if base_version != record.version:
                _snapshot_invalid({"field": "base_version", "reason": "mismatch"})

        base_digest = data.get("base_digest_hex", data.get("base_digest"))
        if base_digest is not None:
            _non_empty_string(base_digest, "base_digest_hex")
            if base_digest != record.digest_hex:
                _snapshot_invalid({"field": "base_digest_hex", "reason": "mismatch"})

        queued_at = data.get("queued_at")
        if queued_at is not None:
            _non_empty_string(queued_at, "queued_at")

        queue.append(account_id)
        pending[account_id] = {
            "password": password,
            "target": target,
            "base_version": base_version if base_version is not None else record.version,
            "base_digest_hex": base_digest if base_digest is not None else record.digest_hex,
            "queued_at": queued_at,
        }

    return queue, pending


def _parse_force_reset(raw: Any) -> set[str]:
    if isinstance(raw, (list, tuple, set, frozenset)):
        accounts = set(raw)
    else:
        _snapshot_invalid({"field": "force_reset", "reason": "type"})
        raise AssertionError("unreachable")

    for account_id in accounts:
        _non_empty_string(account_id, "force_reset.account_id")
    return accounts


def _parse_stats(raw: Any) -> dict[str, Any]:
    if not isinstance(raw, Mapping):
        _snapshot_invalid({"field": "stats", "reason": "type"})

    stats = {key: 0 for key in _STAT_KEYS}
    for key in _STAT_KEYS:
        if key in raw:
            stats[key] = _strict_int(raw[key], f"stats.{key}", non_negative=True)

    for key, value in raw.items():
        if key not in _STAT_KEYS:
            stats[key] = value
    return stats


def _parse_snapshot_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict) or set(payload) != _SNAPSHOT_KEYS:
        _snapshot_invalid({"reason": "missing_or_extra_keys"})

    current_version = _strict_int(
        payload["version"], "version", non_negative=True
    )
    versions = _parse_versions(payload["versions"], current_version)
    records = _parse_records(payload["records"], versions)
    queue, pending = _parse_pending(
        payload["pending"], records, versions, current_version
    )
    force_reset = _parse_force_reset(payload["force_reset"])
    stats = _parse_stats(payload["stats"])

    return {
        "version": current_version,
        "versions": versions,
        "records": records,
        "queue": queue,
        "pending": pending,
        "force_reset": force_reset,
        "stats": stats,
    }


class PasswordPepperLedger:
    """Track pepper versions, password records and the lazy rehash queue."""

    def __init__(self, *, iterations: int = 60000, max_pending: int = 64,
                 salt_bytes: int = 16) -> None:
        if not _positive_int(iterations):
            raise PepperError(
                "PEPPER_INVALID_REQUEST", {"field": "iterations"}
            )
        if not _non_negative_int(max_pending):
            raise PepperError(
                "PEPPER_INVALID_REQUEST", {"field": "max_pending"}
            )
        if not _positive_int(salt_bytes):
            raise PepperError(
                "PEPPER_INVALID_REQUEST", {"field": "salt_bytes"}
            )

        self.iterations = iterations
        self.max_pending = max_pending
        self.salt_bytes = salt_bytes
        self._lock = threading.RLock()
        self._current_version = 0
        self._versions: dict[int, dict[str, Any]] = {}
        self._records: dict[str, PasswordRecord] = {}
        self._queue: list[str] = []
        self._pending: dict[str, dict[str, Any]] = {}
        self._force_reset: set[str] = set()
        self._stats: dict[str, Any] = {key: 0 for key in _STAT_KEYS}

    def register_version(self, version: int, pepper: str | None = None,
                         now: str | None = None) -> int:
        if not _positive_int(version):
            raise PepperError(
                "PEPPER_INVALID_REQUEST", {"field": "version", "value": version}
            )
        if not isinstance(pepper, str) or not pepper.strip():
            raise PepperError(
                "PEPPER_INVALID_REQUEST", {"field": "pepper"}
            )

        timestamp = _now_value(now)
        with self._lock:
            if version <= self._current_version:
                raise PepperError(
                    "PEPPER_VERSION_REGRESSION",
                    {"version": version, "current_version": self._current_version},
                )
            self._versions[version] = {
                "pepper": pepper,
                "enabled": True,
                "registered_at": timestamp,
                "disabled_at": None,
            }
            self._current_version = version
            return version

    def current_version(self) -> int:
        with self._lock:
            return self._current_version

    def version_enabled(self, version: int) -> bool:
        if not _positive_int(version):
            return False
        with self._lock:
            info = self._versions.get(version)
            return bool(info is not None and info.get("enabled"))

    def hash_record(self, account_id: str, password: str,
                    now: str | None = None) -> PasswordRecord:
        self._validate_account_password(account_id, password)
        timestamp = _now_value(now)

        with self._lock:
            info = self._current_version_info_locked()
            if info is None:
                raise PepperError(
                    "PEPPER_NO_VERSION",
                    {"current_version": self._current_version},
                )
            if not info.get("enabled"):
                raise PepperError(
                    "PEPPER_VERSION_DISABLED",
                    {"version": self._current_version},
                )

            record = self._build_record_locked(
                account_id, password, self._current_version, timestamp
            )
            self._records[account_id] = record
            self._force_reset.discard(account_id)
            self._stats["hashed"] += 1
            return record

    def verify(self, account_id: str, password: str,
               now: str | None = None) -> VerifyResult:
        self._validate_account_password(account_id, password)
        timestamp = _now_value(now)

        with self._lock:
            record = self._records.get(account_id)
            if record is None:
                self._stats["unknown"] += 1
                return VerifyResult(account_id, "unknown", None, False)

            if not self._matches_record_locked(record, password):
                self._stats["invalid"] += 1
                return VerifyResult(
                    account_id, "invalid", record.version, False
                )

            self._stats["verified"] += 1

            if self._needs_reset_locked(account_id, record):
                self._force_reset.add(account_id)
                self._stats["reset_required"] += 1
                return VerifyResult(
                    account_id, "reset_required", record.version, False
                )

            if record.version == self._current_version:
                return VerifyResult(account_id, "ok", record.version, False)

            rehash_queued = False
            if account_id not in self._pending:
                if len(self._queue) >= self.max_pending:
                    self._stats["rehash_deferred"] += 1
                else:
                    self._queue.append(account_id)
                    self._pending[account_id] = {
                        "password": password,
                        "target": None,
                        "base_version": record.version,
                        "base_digest_hex": record.digest_hex,
                        "queued_at": timestamp,
                    }
                    self._stats["rehash_queued"] += 1
                    rehash_queued = True
            else:
                pending_item = self._pending[account_id]
                pending_item["password"] = password
                pending_item["base_version"] = record.version
                pending_item["base_digest_hex"] = record.digest_hex

            return VerifyResult(
                account_id, "ok", record.version, rehash_queued
            )

    def rehash_pending(self, limit: int | None = None,
                       now: str | None = None) -> int:
        if limit is not None and (
            not isinstance(limit, int) or isinstance(limit, bool) or limit < 0
        ):
            raise PepperError("PEPPER_INVALID_REQUEST", {"field": "limit"})

        timestamp = _now_value(now)
        completed = 0
        examined = 0

        with self._lock:
            while self._queue:
                if limit is not None and examined >= limit:
                    break

                account_id = self._queue[0]
                examined += 1

                try:
                    record = self._records.get(account_id)
                    item = self._pending.get(account_id)
                    if record is None or item is None:
                        self._discard_pending_locked(account_id)
                        self._stats["rehash_failed"] += 1
                        continue

                    if record.version == self._current_version:
                        self._discard_pending_locked(account_id)
                        continue

                    if self._needs_reset_locked(account_id, record):
                        self._force_reset.add(account_id)
                        self._discard_pending_locked(account_id)
                        continue

                    current_info = self._current_version_info_locked()
                    if current_info is None or not current_info.get("enabled"):
                        break

                    base_version = item.get("base_version")
                    base_digest = item.get("base_digest_hex")
                    if (
                        base_version is not None
                        and base_version != record.version
                    ) or (
                        base_digest is not None
                        and not hmac.compare_digest(
                            str(base_digest), record.digest_hex
                        )
                    ):
                        raise PepperError(
                            "PEPPER_INVALID_REQUEST",
                            {"account_id": account_id, "reason": "stale_pending"},
                        )

                    target = self._target_record_locked(
                        account_id, item, timestamp
                    )
                    if (
                        target.account_id != account_id
                        or target.version != self._current_version
                    ):
                        raise PepperError(
                            "PEPPER_INVALID_REQUEST",
                            {"account_id": account_id, "reason": "bad_target"},
                        )

                    self._records[account_id] = target
                    self._discard_pending_locked(account_id)
                    self._stats["rehashed"] += 1
                    completed += 1
                except Exception:
                    self._stats["rehash_failed"] += 1
                    break

            return completed

    def disable_version(self, version: int, now: str | None = None) -> int:
        if not _positive_int(version):
            raise PepperError(
                "PEPPER_INVALID_REQUEST", {"field": "version", "value": version}
            )

        timestamp = _now_value(now)
        with self._lock:
            info = self._versions.get(version)
            if info is None:
                raise PepperError(
                    "PEPPER_UNKNOWN_VERSION", {"version": version}
                )
            if not info.get("enabled"):
                return 0

            info["enabled"] = False
            info["disabled_at"] = timestamp

            affected = [
                account_id
                for account_id, record in self._records.items()
                if record.version == version
            ]
            for account_id in affected:
                self._force_reset.add(account_id)
                self._discard_pending_locked(account_id)

            return len(affected)

    def force_reset_required(self, account_id: str) -> bool:
        with self._lock:
            return account_id in self._force_reset

    def pending_count(self) -> int:
        with self._lock:
            return len(self._queue)

    def record_for(self, account_id: str) -> PasswordRecord | None:
        with self._lock:
            return self._records.get(account_id)

    def records(self) -> list[PasswordRecord]:
        with self._lock:
            return [
                self._records[account_id]
                for account_id in sorted(self._records)
            ]

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            pending = []
            for account_id in self._queue:
                item = self._pending[account_id]
                target = item.get("target")
                password = item.get("password")
                if isinstance(password, str) and password != "":
                    target = self._build_record_locked(
                        account_id,
                        password,
                        self._current_version,
                        item.get("queued_at") or _now_value(None),
                    )

                pending.append(
                    {
                        "account_id": account_id,
                        "queued_at": item.get("queued_at"),
                        "base_version": item.get("base_version"),
                        "base_digest_hex": item.get("base_digest_hex"),
                        "target": asdict(target) if target is not None else None,
                    }
                )

            state = {
                "version": self._current_version,
                "versions": [
                    {
                        "version": version,
                        "pepper": self._versions[version]["pepper"],
                        "enabled": self._versions[version]["enabled"],
                        "registered_at": self._versions[version].get(
                            "registered_at"
                        ),
                        "disabled_at": self._versions[version].get("disabled_at"),
                    }
                    for version in sorted(self._versions)
                ],
                "records": [
                    asdict(self._records[account_id])
                    for account_id in sorted(self._records)
                ],
                "pending": pending,
                "force_reset": sorted(self._force_reset),
                "stats": self.stats(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict[str, Any]) -> None:
        try:
            payload = copy.deepcopy(state)
            parsed = _parse_snapshot_payload(payload)
        except PepperError:
            raise
        except Exception as exc:
            raise PepperError(
                "PEPPER_SNAPSHOT_INVALID", {"reason": "unreadable"}
            ) from exc

        with self._lock:
            self._current_version = parsed["version"]
            self._versions = parsed["versions"]
            self._records = parsed["records"]
            self._queue = parsed["queue"]
            self._pending = parsed["pending"]
            self._force_reset = parsed["force_reset"]
            self._stats = parsed["stats"]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            result = copy.deepcopy(self._stats)
            result["versions"] = len(self._versions)
            result["disabled_versions"] = sum(
                1 for info in self._versions.values() if not info.get("enabled")
            )
            for key in _STAT_KEYS:
                result.setdefault(key, 0)
            return result

    @staticmethod
    def _validate_account_password(account_id: str, password: str) -> None:
        if not isinstance(account_id, str) or account_id == "":
            raise PepperError(
                "PEPPER_INVALID_REQUEST", {"field": "account_id"}
            )
        if not isinstance(password, str) or password == "":
            raise PepperError("PEPPER_INVALID_REQUEST", {"field": "password"})

    def _current_version_info_locked(self) -> dict[str, Any] | None:
        if self._current_version <= 0:
            return None
        return self._versions.get(self._current_version)

    def _derive_digest(self, password: str, salt_hex: str, pepper: str,
                       iterations: int) -> str:
        salt = bytes.fromhex(salt_hex)
        peppered_password = password.encode("utf-8") + pepper.encode("utf-8")
        return hashlib.pbkdf2_hmac(
            _HASH_NAME,
            peppered_password,
            salt,
            iterations,
        ).hex()

    def _build_record_locked(self, account_id: str, password: str,
                             version: int, now: str) -> PasswordRecord:
        pepper = self._versions[version]["pepper"]
        salt = os.urandom(self.salt_bytes)
        digest = self._derive_digest(
            password, salt.hex(), pepper, self.iterations
        )
        return PasswordRecord(
            account_id=account_id,
            version=version,
            algorithm=_ALGORITHM,
            iterations=self.iterations,
            salt_hex=salt.hex(),
            digest_hex=digest,
            updated_at=now,
        )

    def _matches_record_locked(self, record: PasswordRecord,
                               password: str) -> bool:
        info = self._versions.get(record.version)
        if info is None:
            raise PepperError(
                "PEPPER_UNKNOWN_VERSION", {"version": record.version}
            )
        digest = self._derive_digest(
            password,
            record.salt_hex,
            info["pepper"],
            record.iterations,
        )
        return hmac.compare_digest(digest, record.digest_hex)

    def _previous_version_locked(self) -> int | None:
        versions = sorted(self._versions)
        if len(versions) < 2:
            return None
        return versions[-2]

    def _needs_reset_locked(self, account_id: str,
                            record: PasswordRecord) -> bool:
        if account_id in self._force_reset:
            return True
        info = self._versions.get(record.version)
        if info is None or not info.get("enabled"):
            return True
        return (
            record.version != self._current_version
            and record.version != self._previous_version_locked()
        )

    def _discard_pending_locked(self, account_id: str) -> None:
        try:
            self._queue.remove(account_id)
        except ValueError:
            pass
        self._pending.pop(account_id, None)

    def _target_record_locked(self, account_id: str, item: dict[str, Any],
                              now: str) -> PasswordRecord:
        password = item.get("password")
        if isinstance(password, str) and password != "":
            return self._build_record_locked(
                account_id, password, self._current_version, now
            )

        target = item.get("target")
        if not isinstance(target, PasswordRecord):
            raise PepperError(
                "PEPPER_SNAPSHOT_INVALID",
                {"account_id": account_id, "reason": "missing_pending_target"},
            )
        return replace(target, updated_at=now)
