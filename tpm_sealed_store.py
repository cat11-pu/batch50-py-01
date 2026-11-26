"""TPM sealed data store: PCR policy binding, lockout accounting, bounded object table."""

from __future__ import annotations

import base64
import copy
import hashlib
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

DIGEST_LEN = 64
PCR_LIMIT = 24
ZERO_DIGEST = "0" * DIGEST_LEN
_HEX_DIGITS = frozenset("0123456789abcdef")
_STAT_KEYS = (
    "sealed",
    "duplicates",
    "unsealed_ok",
    "unsealed_failed",
    "resealed",
    "evicted",
    "denied",
    "locked_events",
)


class SealError(ValueError):
    """Raised when a sealed-object operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SealedRecord:
    name: str
    pcr_indexes: tuple = ()
    expected: tuple = ()
    policy: str | None = None
    policy_history: tuple = ()
    version: int = 1
    reseal_count: int = 0
    sealed_at: str = ""


@dataclass
class _SealedObject:
    name: str
    data: str
    pcr_indexes: tuple
    expected: tuple
    policy: str | None
    policy_history: tuple
    version: int
    reseal_count: int
    sealed_at: str
    failure_count: int = 0
    locked_until: str | None = None
    lock_anchor: datetime | None = None
    held: int = 0


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_digest(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == DIGEST_LEN
        and all(char in _HEX_DIGITS for char in value)
    )


def _as_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        result = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        result = datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if not text:
            raise ValueError("empty timestamp")
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        result = datetime.fromisoformat(text)
    else:
        raise ValueError("unsupported timestamp")
    if result.tzinfo is None:
        result = result.replace(tzinfo=timezone.utc)
    return result


def _format_time(value: datetime) -> str:
    return value.isoformat()


def _validate_name(name: object) -> str:
    if not isinstance(name, str) or not name or any(char.isspace() for char in name):
        raise SealError("SEAL_BAD_NAME", {"name": name})
    return name


def _validate_pcr_indexes(pcr_indexes: object) -> tuple:
    if isinstance(pcr_indexes, (str, bytes, bytearray)):
        raise SealError("SEAL_BAD_PCR", {"pcr_indexes": pcr_indexes})
    try:
        values = list(pcr_indexes)
    except TypeError:
        raise SealError("SEAL_BAD_PCR", {"pcr_indexes": pcr_indexes}) from None
    if not values:
        raise SealError("SEAL_BAD_PCR", {"pcr_indexes": pcr_indexes})
    if any(not _is_int(index) or index < 0 or index >= PCR_LIMIT for index in values):
        raise SealError("SEAL_BAD_PCR", {"pcr_indexes": pcr_indexes})
    if len(set(values)) != len(values):
        raise SealError("SEAL_BAD_PCR", {"pcr_indexes": pcr_indexes})
    return tuple(sorted(values))


def _expected_items(expected: object) -> list:
    if hasattr(expected, "items"):
        try:
            return list(expected.items())
        except Exception:
            raise SealError("SEAL_BAD_EXPECTED", {"expected": expected}) from None
    if isinstance(expected, (str, bytes, bytearray)):
        raise SealError("SEAL_BAD_EXPECTED", {"expected": expected})
    try:
        pairs = list(expected)
    except TypeError:
        raise SealError("SEAL_BAD_EXPECTED", {"expected": expected}) from None
    result = []
    for pair in pairs:
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise SealError("SEAL_BAD_EXPECTED", {"expected": expected})
        result.append((pair[0], pair[1]))
    return result


def _validate_expected(expected: object, indexes: tuple) -> tuple:
    pairs = _expected_items(expected)
    values: dict[int, str] = {}
    for index, digest in pairs:
        if not _is_int(index) or index in values or not _is_digest(digest):
            raise SealError("SEAL_BAD_EXPECTED", {"expected": expected})
        values[index] = digest
    if set(values) != set(indexes):
        raise SealError("SEAL_BAD_EXPECTED", {"expected": expected})
    return tuple((index, values[index]) for index in sorted(indexes))


class TpmSealedStore:
    """Keep sealed objects, their PCR expectations and lockout state in memory."""

    def __init__(self, *, max_objects: int = 16, max_failures: int = 3,
                 lock_seconds: int = 60, clock=None) -> None:
        self.max_objects = max_objects
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self._clock = clock
        self._lock = threading.RLock()
        self._objects: dict[str, _SealedObject] = {}
        self._pcr_bank: dict[int, str] = {
            index: ZERO_DIGEST for index in range(PCR_LIMIT)
        }
        self._pcr_events: list[dict] = []
        self._stats = {key: 0 for key in _STAT_KEYS}
        self._now: datetime | None = None
        self._now_wall = time.monotonic()

    # -- internal helpers -------------------------------------------------

    def _resolve_now(self, now: object = None) -> tuple:
        if now is not None:
            current = _as_datetime(now)
        elif self._clock is not None:
            current = _as_datetime(self._clock())
        elif self._now is not None:
            current = self._now + timedelta(
                seconds=time.monotonic() - self._now_wall
            )
        else:
            current = datetime.now(timezone.utc)
        self._now = current
        self._now_wall = time.monotonic()
        return current, _format_time(current)

    def _get(self, name: str) -> _SealedObject:
        item = self._objects.get(name)
        if item is None:
            raise SealError("SEAL_NOT_FOUND", {"name": name})
        return item

    def _decay_lock(self, item: _SealedObject, now: datetime) -> None:
        """Subtract one failure for each completed lock interval.

        The anchor is advanced as time is consumed so repeated calls at the
        same instant cannot drain the counter more than once.
        """
        if item.lock_anchor is None:
            return
        interval = max(1, self.lock_seconds)
        elapsed = (now - item.lock_anchor).total_seconds()
        if elapsed < interval:
            return
        periods = int(elapsed // interval)
        if periods <= 0:
            return
        item.failure_count = max(0, item.failure_count - periods)
        item.lock_anchor = item.lock_anchor + timedelta(seconds=periods * interval)
        if item.failure_count == 0:
            item.lock_anchor = None
            item.locked_until = None
        elif item.locked_until is not None:
            try:
                locked_until = _as_datetime(item.locked_until)
            except ValueError:
                locked_until = now
            if now >= locked_until and item.failure_count < self.max_failures:
                item.locked_until = None

    def _is_locked(self, item: _SealedObject, now: datetime) -> bool:
        if item.locked_until is None:
            return False
        try:
            locked_until = _as_datetime(item.locked_until)
        except ValueError:
            return False
        return now < locked_until

    def _record(self, item: _SealedObject) -> SealedRecord:
        return SealedRecord(
            name=item.name,
            pcr_indexes=tuple(item.pcr_indexes),
            expected=tuple(item.expected),
            policy=item.policy,
            policy_history=tuple(item.policy_history),
            version=item.version,
            reseal_count=item.reseal_count,
            sealed_at=item.sealed_at,
        )

    def _status_for(self, item: _SealedObject, now: datetime) -> dict:
        return {
            "pcr_indexes": tuple(item.pcr_indexes),
            "version": item.version,
            "policy": item.policy,
            "failure_count": item.failure_count,
            "locked": self._is_locked(item, now),
            "locked_until": item.locked_until,
            "held": item.held,
        }

    @staticmethod
    def _encode_payload(data: str) -> str:
        return base64.b64encode(data.encode("utf-8")).decode("ascii")

    @staticmethod
    def _decode_payload(value: object) -> str:
        if not isinstance(value, str):
            raise ValueError("payload is not text")
        return base64.b64decode(value.encode("ascii"), validate=True).decode("utf-8")

    # -- public API -------------------------------------------------------

    def seal(self, name: str, data: str, *, pcr_indexes, expected,
             policy: str | None = None, now: str | None = None) -> SealedRecord:
        with self._lock:
            _, stamp = self._resolve_now(now)
            try:
                name = _validate_name(name)
                indexes = _validate_pcr_indexes(pcr_indexes)
                expected_values = _validate_expected(expected, indexes)
                if not isinstance(data, str):
                    raise SealError("SEAL_BAD_DATA", {"name": name})
            except SealError:
                self._stats["denied"] += 1
                raise

            if name in self._objects:
                self._stats["duplicates"] += 1
                self._stats["denied"] += 1
                raise SealError("SEAL_DUPLICATE", {"name": name})
            if len(self._objects) >= self.max_objects:
                self._stats["denied"] += 1
                raise SealError("SEAL_STORE_FULL", {"max_objects": self.max_objects})

            item = _SealedObject(
                name=name,
                data=data,
                pcr_indexes=indexes,
                expected=expected_values,
                policy=policy,
                policy_history=(policy,),
                version=1,
                reseal_count=0,
                sealed_at=stamp,
            )
            self._objects[name] = item
            self._stats["sealed"] += 1
            return self._record(item)

    def unseal(self, name: str, *, pcr_values, now: str | None = None) -> str:
        with self._lock:
            current, _ = self._resolve_now(now)
            item = self._get(name)
            self._decay_lock(item, current)

            if self._is_locked(item, current):
                raise SealError(
                    "SEAL_LOCKED",
                    {"name": name, "locked_until": item.locked_until},
                )

            if hasattr(pcr_values, "keys"):
                try:
                    keys = set(pcr_values.keys())
                except Exception:
                    keys = set()
            else:
                keys = set()
            missing = [
                index for index, _ in item.expected if index not in keys
            ]
            if missing:
                self._stats["denied"] += 1
                raise SealError("SEAL_BAD_PCR", {"missing": missing})

            try:
                mismatch = next(
                    (
                        (index, digest, pcr_values[index])
                        for index, digest in item.expected
                        if pcr_values[index] != digest
                    ),
                    None,
                )
            except Exception:
                self._stats["denied"] += 1
                raise SealError("SEAL_BAD_PCR", {"missing": [
                    index for index, _ in item.expected if index not in keys
                ]}) from None

            if mismatch is not None:
                index = mismatch[0]
                self._stats["unsealed_failed"] += 1
                item.failure_count += 1
                if item.failure_count >= self.max_failures:
                    item.lock_anchor = current
                    item.locked_until = _format_time(
                        current + timedelta(seconds=self.lock_seconds)
                    )
                    self._stats["locked_events"] += 1
                raise SealError("SEAL_POLICY_FAILED", {"index": index})

            item.failure_count = 0
            item.locked_until = None
            item.lock_anchor = None
            self._stats["unsealed_ok"] += 1
            return item.data

    def reseal(self, name: str, *, pcr_indexes=None, expected=None,
               policy: str | None = None, now: str | None = None) -> SealedRecord:
        with self._lock:
            _, stamp = self._resolve_now(now)
            item = self._get(name)
            try:
                if pcr_indexes is None:
                    indexes = tuple(item.pcr_indexes)
                else:
                    indexes = _validate_pcr_indexes(pcr_indexes)

                if expected is None:
                    old_expected = dict(item.expected)
                    if not all(index in old_expected for index in indexes):
                        raise SealError(
                            "SEAL_BAD_EXPECTED",
                            {"expected": expected, "pcr_indexes": indexes},
                        )
                    expected_values = tuple(
                        (index, old_expected[index]) for index in indexes
                    )
                else:
                    expected_values = _validate_expected(expected, indexes)
            except SealError:
                self._stats["denied"] += 1
                raise

            if policy is not None and policy != item.policy:
                item.policy_history = tuple(item.policy_history) + (policy,)
            item.policy = policy if policy is not None else item.policy
            item.pcr_indexes = indexes
            item.expected = expected_values
            item.version += 1
            item.reseal_count += 1
            item.sealed_at = stamp
            self._stats["resealed"] += 1
            return self._record(item)

    def evict(self, name: str) -> None:
        with self._lock:
            item = self._get(name)
            if item.held:
                raise SealError("SEAL_IN_USE", {"name": name, "held": item.held})
            del self._objects[name]
            self._stats["evicted"] += 1

    def hold(self, name: str) -> int:
        with self._lock:
            item = self._get(name)
            item.held += 1
            return item.held

    def release(self, name: str) -> int:
        with self._lock:
            item = self._get(name)
            if item.held > 0:
                item.held -= 1
            return item.held

    def pcr_extend(self, index: int, digest: str, *,
                   now: str | None = None) -> tuple:
        with self._lock:
            _, stamp = self._resolve_now(now)
            if not _is_int(index) or index < 0 or index >= PCR_LIMIT:
                raise SealError("SEAL_BAD_PCR", {"index": index})
            if not _is_digest(digest):
                raise SealError("SEAL_BAD_EXPECTED", {"index": index})

            previous = self._pcr_bank.get(index, ZERO_DIGEST)
            value = hashlib.sha256(
                bytes.fromhex(previous) + bytes.fromhex(digest)
            ).hexdigest()
            self._pcr_bank[index] = value
            self._pcr_events.append({
                "index": index,
                "digest": digest,
                "previous": previous,
                "value": value,
                "at": stamp,
            })
            return index, value

    def pcr_bank(self) -> dict:
        with self._lock:
            return {
                index: self._pcr_bank.get(index, ZERO_DIGEST)
                for index in range(PCR_LIMIT)
            }

    def status(self, name: str) -> dict:
        with self._lock:
            current, _ = self._resolve_now(None)
            item = self._get(name)
            self._decay_lock(item, current)
            return self._status_for(item, current)

    def objects(self) -> list:
        with self._lock:
            return sorted(self._objects)

    def lock_state(self) -> dict:
        with self._lock:
            current, _ = self._resolve_now(None)
            result = {}
            for name in sorted(self._objects):
                item = self._objects[name]
                self._decay_lock(item, current)
                result[name] = {
                    "failure_count": item.failure_count,
                    "locked": self._is_locked(item, current),
                    "locked_until": item.locked_until,
                }
            return result

    def snapshot(self) -> dict:
        with self._lock:
            current, _ = self._resolve_now(None)
            objects = []
            locks = {}
            for name in sorted(self._objects):
                item = self._objects[name]
                self._decay_lock(item, current)
                objects.append({
                    "name": item.name,
                    "pcr_indexes": tuple(item.pcr_indexes),
                    "expected": tuple(item.expected),
                    "policy": item.policy,
                    "policy_history": tuple(item.policy_history),
                    "version": item.version,
                    "reseal_count": item.reseal_count,
                    "sealed_at": item.sealed_at,
                    "failure_count": item.failure_count,
                    "locked": self._is_locked(item, current),
                    "locked_until": item.locked_until,
                    "lock_anchor": (
                        _format_time(item.lock_anchor)
                        if item.lock_anchor is not None else None
                    ),
                    "held": item.held,
                    "payload_b64": self._encode_payload(item.data),
                })
                locks[name] = {
                    "failure_count": item.failure_count,
                    "locked": self._is_locked(item, current),
                    "locked_until": item.locked_until,
                }
            return {
                "format": 1,
                "max_objects": self.max_objects,
                "max_failures": self.max_failures,
                "lock_seconds": self.lock_seconds,
                "now": _format_time(current),
                "objects": objects,
                "locks": locks,
                "pcr_bank": dict(self._pcr_bank),
                "pcr_events": copy.deepcopy(self._pcr_events),
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except Exception:
                raise SealError("SEAL_SNAPSHOT_INVALID") from None

            self.max_objects = parsed["max_objects"]
            self.max_failures = parsed["max_failures"]
            self.lock_seconds = parsed["lock_seconds"]
            self._now = parsed["now"]
            self._now_wall = time.monotonic()
            self._objects = parsed["objects"]
            self._pcr_bank = parsed["pcr_bank"]
            self._pcr_events = parsed["pcr_events"]
            self._stats = parsed["stats"]

    def _parse_snapshot(self, state: object) -> dict:
        if not isinstance(state, dict):
            raise ValueError("snapshot must be a mapping")
        raw_objects = state.get("objects")
        if not isinstance(raw_objects, (list, tuple)):
            raise ValueError("objects must be a list")

        max_objects = state.get("max_objects", self.max_objects)
        max_failures = state.get("max_failures", self.max_failures)
        lock_seconds = state.get("lock_seconds", self.lock_seconds)
        if not _is_int(max_objects) or max_objects < 0:
            raise ValueError("bad max_objects")
        if not _is_int(max_failures) or max_failures < 0:
            raise ValueError("bad max_failures")
        if not _is_int(lock_seconds) or lock_seconds < 0:
            raise ValueError("bad lock_seconds")

        raw_now = state.get("now")
        restored_now = None if raw_now is None else _as_datetime(raw_now)

        raw_stats = state.get("stats", {})
        if not isinstance(raw_stats, dict):
            raise ValueError("stats must be a mapping")
        stats = {}
        for key in _STAT_KEYS:
            value = raw_stats.get(key, 0)
            if not _is_int(value) or value < 0:
                raise ValueError("bad statistic")
            stats[key] = value

        raw_bank = state.get("pcr_bank", {})
        if not isinstance(raw_bank, dict):
            raise ValueError("pcr_bank must be a mapping")
        pcr_bank = {index: ZERO_DIGEST for index in range(PCR_LIMIT)}
        for raw_index, digest in raw_bank.items():
            if isinstance(raw_index, str):
                try:
                    index = int(raw_index, 10)
                except ValueError:
                    raise ValueError("bad pcr index") from None
            else:
                index = raw_index
            if not _is_int(index) or index < 0 or index >= PCR_LIMIT:
                raise ValueError("bad pcr index")
            if not _is_digest(digest):
                raise ValueError("bad pcr digest")
            pcr_bank[index] = digest

        raw_events = state.get("pcr_events", [])
        if not isinstance(raw_events, (list, tuple)):
            raise ValueError("pcr_events must be a list")
        events = copy.deepcopy(list(raw_events))

        top_locks = state.get("locks")
        if top_locks is None:
            top_locks = state.get("lock_state", {})
        if top_locks is None:
            top_locks = {}
        if not isinstance(top_locks, dict):
            raise ValueError("locks must be a mapping")

        objects: dict[str, _SealedObject] = {}
        lock_flags: dict[str, tuple] = {}
        for entry in raw_objects:
            if not isinstance(entry, dict):
                raise ValueError("object entry must be a mapping")
            if "data" in entry:
                raise ValueError("plaintext data field")

            name = _validate_name(entry.get("name"))
            if name in objects:
                raise ValueError("duplicate object")
            indexes = _validate_pcr_indexes(entry.get("pcr_indexes"))
            expected = _validate_expected(entry.get("expected"), indexes)

            policy = entry.get("policy")
            if policy is not None and not isinstance(policy, str):
                raise ValueError("bad policy")
            history = entry.get("policy_history", [policy])
            if not isinstance(history, (list, tuple)):
                raise ValueError("bad policy history")
            history = tuple(history)
            if any(value is not None and not isinstance(value, str)
                   for value in history):
                raise ValueError("bad policy history")

            version = entry.get("version", 1)
            reseal_count = entry.get("reseal_count", 0)
            failure_count = entry.get("failure_count", 0)
            held = entry.get("held", 0)
            if not _is_int(version) or version < 1:
                raise ValueError("bad version")
            if not _is_int(reseal_count) or reseal_count < 0:
                raise ValueError("bad reseal count")
            if not _is_int(failure_count) or failure_count < 0:
                raise ValueError("bad failure count")
            if not _is_int(held) or held < 0:
                raise ValueError("bad held count")

            sealed_at = entry.get("sealed_at", "")
            if not isinstance(sealed_at, str):
                raise ValueError("bad sealed_at")

            has_failure_count = "failure_count" in entry
            has_locked_until = "locked_until" in entry
            has_lock_anchor = "lock_anchor" in entry
            locked_until = entry.get("locked_until")
            if locked_until is not None:
                _as_datetime(locked_until)
                if not isinstance(locked_until, str):
                    locked_until = _format_time(_as_datetime(locked_until))

            raw_anchor = entry.get("lock_anchor")
            if raw_anchor is not None:
                lock_anchor = _as_datetime(raw_anchor)
            elif locked_until is not None:
                lock_anchor = (
                    _as_datetime(locked_until)
                    - timedelta(seconds=max(0, lock_seconds))
                )
            else:
                lock_anchor = None

            payload = entry.get("payload_b64")
            if payload is None:
                for alias in ("payload", "sealed_b64", "data_b64"):
                    if alias in entry:
                        payload = entry[alias]
                        break
            data = "" if payload is None else self._decode_payload(payload)

            objects[name] = _SealedObject(
                name=name,
                data=data,
                pcr_indexes=indexes,
                expected=expected,
                policy=policy,
                policy_history=history,
                version=version,
                reseal_count=reseal_count,
                sealed_at=sealed_at,
                failure_count=failure_count,
                locked_until=locked_until,
                lock_anchor=lock_anchor,
                held=held,
            )
            lock_flags[name] = (
                has_failure_count,
                has_locked_until,
                has_lock_anchor,
            )

        if len(objects) > max_objects:
            raise ValueError("too many objects")

        for name, lock in top_locks.items():
            if not isinstance(lock, dict):
                raise ValueError("bad lock entry")
            item = objects.get(name)
            if item is None:
                continue
            has_failure_count, has_locked_until, has_lock_anchor = lock_flags[name]
            if "failure_count" in lock and not has_failure_count:
                value = lock["failure_count"]
                if not _is_int(value) or value < 0:
                    raise ValueError("bad lock failure count")
                item.failure_count = value
            if "locked_until" in lock and not has_locked_until:
                value = lock["locked_until"]
                if value is not None:
                    _as_datetime(value)
                    if not isinstance(value, str):
                        value = _format_time(_as_datetime(value))
                item.locked_until = value
                if value is not None and "lock_anchor" in lock:
                    item.lock_anchor = _as_datetime(lock["lock_anchor"])
                elif value is not None and not has_lock_anchor:
                    item.lock_anchor = (
                        _as_datetime(value)
                        - timedelta(seconds=max(0, lock_seconds))
                    )

        return {
            "max_objects": max_objects,
            "max_failures": max_failures,
            "lock_seconds": lock_seconds,
            "now": restored_now,
            "objects": objects,
            "pcr_bank": pcr_bank,
            "pcr_events": events,
            "stats": stats,
        }

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
