"""System V shared-memory quota governance: ownership, attach accounting, reaping."""

from __future__ import annotations

import copy
import math
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class ShmError(ValueError):
    """Raised when a shared-memory operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SegmentRecord:
    namespace: str
    key: int
    owner: str
    size: int
    segment_id: str
    state: str = "live"
    refcount: int = 0
    created_at: str = ""
    last_attach_at: str | None = None


_KEY_MIN = 0
_KEY_MAX = 2_147_483_647
_SNAPSHOT_VERSION = 1
_COUNTER_KEYS = ("created", "attached", "detached", "removed", "swept", "denied")


def _is_real_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_identifier(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _timestamp_seconds(value: object) -> float:
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, str):
        text = value[:-1] + "+00:00" if value.endswith("Z") else value
        return datetime.fromisoformat(text).timestamp()
    if isinstance(value, bool):
        raise TypeError("boolean is not a timestamp")
    return float(value)  # type: ignore[arg-type]


class ShmQuotaWarden:
    """Own segment lifecycle and per-user / per-namespace quota watermarks."""

    def __init__(self, *, user_bytes: int = 1048576, user_segments: int = 8,
                 ns_bytes: int = 2097152, ns_segments: int = 12,
                 clock=None) -> None:
        self.user_bytes = user_bytes
        self.user_segments = user_segments
        self.ns_bytes = ns_bytes
        self.ns_segments = ns_segments
        self._clock = clock
        self._lock = threading.RLock()
        self._segments: dict[tuple[str, int], dict[str, Any]] = {}
        self._user_bytes: dict[str, int] = {}
        self._user_segments: dict[str, int] = {}
        self._ns_bytes: dict[str, int] = {}
        self._ns_segments: dict[str, int] = {}
        self._next_number = 1
        self._counters = {name: 0 for name in _COUNTER_KEYS}

    def create(self, namespace: str, key: int, *, owner: str, size: int,
               now: str | None = None) -> SegmentRecord:
        with self._lock:
            self._require_namespace(namespace)
            self._require_key(key)
            self._require_owner(owner)
            self._require_size(size)

            identity = (namespace, key)
            existing = self._segments.get(identity)
            if existing is not None:
                if existing["owner"] != owner:
                    self._deny("SHM_KEY_OWNED", {
                        "namespace": namespace,
                        "key": key,
                        "owner": owner,
                    })
                return self._record(existing)

            used_user_bytes = self._user_bytes.get(owner, 0)
            if used_user_bytes + size > self.user_bytes:
                self._deny("SHM_USER_QUOTA", {
                    "owner": owner,
                    "used": used_user_bytes,
                    "requested": size,
                    "limit": self.user_bytes,
                })

            used_user_segments = self._user_segments.get(owner, 0)
            if used_user_segments + 1 > self.user_segments:
                self._deny("SHM_USER_SEGMENTS", {
                    "owner": owner,
                    "used": used_user_segments,
                    "limit": self.user_segments,
                })

            used_ns_bytes = self._ns_bytes.get(namespace, 0)
            if used_ns_bytes + size > self.ns_bytes:
                self._deny("SHM_NS_QUOTA", {
                    "namespace": namespace,
                    "used": used_ns_bytes,
                    "requested": size,
                    "limit": self.ns_bytes,
                })

            used_ns_segments = self._ns_segments.get(namespace, 0)
            if used_ns_segments + 1 > self.ns_segments:
                self._deny("SHM_NS_SEGMENTS", {
                    "namespace": namespace,
                    "used": used_ns_segments,
                    "limit": self.ns_segments,
                })

            timestamp = self._current_time(now)
            number = self._next_number
            self._next_number += 1
            segment = {
                "namespace": namespace,
                "key": key,
                "owner": owner,
                "size": size,
                "segment_id": f"shm-{number}",
                "state": "live",
                "refcount": 0,
                "created_at": timestamp,
                "last_attach_at": None,
                "attachments": {},
            }
            self._segments[identity] = segment

            self._user_bytes[owner] = used_user_bytes + size
            self._user_segments[owner] = used_user_segments + 1
            self._ns_bytes[namespace] = used_ns_bytes + size
            self._ns_segments[namespace] = used_ns_segments + 1
            self._counters["created"] += 1
            return self._record(segment)

    def attach(self, namespace: str, key: int, pid: int, *,
               now: str | None = None) -> int:
        with self._lock:
            self._require_namespace(namespace)
            self._require_key(key)
            self._require_pid(pid)
            segment = self._require_segment(namespace, key)
            if segment["state"] == "pending_delete":
                self._deny("SHM_PENDING_DELETE", {
                    "namespace": namespace,
                    "key": key,
                    "pid": pid,
                })

            attachments = segment["attachments"]
            attachments[pid] = attachments.get(pid, 0) + 1
            segment["refcount"] += 1
            segment["last_attach_at"] = self._current_time(now)
            self._counters["attached"] += 1
            return int(segment["refcount"])

    def detach(self, namespace: str, key: int, pid: int, *,
               now: str | None = None) -> int:
        with self._lock:
            self._require_namespace(namespace)
            self._require_key(key)
            segment = self._require_segment(namespace, key)
            attachments = segment["attachments"]
            held = attachments.get(pid, 0)
            if held <= 0:
                self._deny("SHM_NOT_ATTACHED", {
                    "namespace": namespace,
                    "key": key,
                    "pid": pid,
                })

            if held == 1:
                del attachments[pid]
            else:
                attachments[pid] = held - 1
            segment["refcount"] -= 1
            self._counters["detached"] += 1
            refcount = int(segment["refcount"])

            if refcount == 0 and segment["state"] == "pending_delete":
                self._delete_segment(segment)
            return refcount

    def remove(self, namespace: str, key: int, *,
               now: str | None = None) -> int:
        with self._lock:
            self._require_namespace(namespace)
            self._require_key(key)
            segment = self._require_segment(namespace, key)

            self._counters["removed"] += 1
            refcount = int(segment["refcount"])
            if refcount == 0:
                self._delete_segment(segment)
            else:
                segment["state"] = "pending_delete"
            return refcount

    def sweep(self, *, stale_after: int = 3600, now: str | None = None,
              whitelist=()) -> list:
        with self._lock:
            if (isinstance(stale_after, bool)
                    or not isinstance(stale_after, (int, float))
                    or stale_after <= 0
                    or (isinstance(stale_after, float)
                        and not math.isfinite(stale_after))):
                self._deny("SHM_BAD_STALE", stale_after)

            if whitelist is None:
                protected: set[str] = set()
            elif isinstance(whitelist, str):
                protected = {whitelist}
            else:
                try:
                    protected = set(whitelist)
                except TypeError:
                    self._deny("SHM_BAD_STALE", {"whitelist": whitelist})

            current_time = _timestamp_seconds(self._current_time(now))
            candidates = [
                segment for segment in self._segments.values()
                if segment["refcount"] == 0
                and segment["owner"] not in protected
            ]
            candidates.sort(key=lambda item: (item["namespace"], item["key"]))

            removed = []
            for segment in candidates:
                last_active = segment["last_attach_at"] or segment["created_at"]
                age = current_time - _timestamp_seconds(last_active)
                if age < stale_after:
                    continue
                identity = (segment["namespace"], segment["key"])
                if self._segments.get(identity) is not segment:
                    continue
                removed.append(identity)
                self._delete_segment(segment)
                self._counters["swept"] += 1
            return removed

    def reap(self, pid: int, *, now: str | None = None) -> int:
        with self._lock:
            affected = 0
            for segment in list(self._segments.values()):
                attachments = segment["attachments"]
                held = attachments.pop(pid, 0)
                if held == 0:
                    continue

                segment["refcount"] -= held
                self._counters["detached"] += held
                affected += 1
                if segment["refcount"] == 0 and segment["state"] == "pending_delete":
                    self._delete_segment(segment)
            return affected

    def drop_namespace(self, namespace: str) -> int:
        with self._lock:
            self._require_namespace(namespace)
            identities = [
                identity for identity in list(self._segments)
                if identity[0] == namespace
            ]
            for identity in identities:
                self._delete_segment(self._segments[identity])

            self._ns_bytes.pop(namespace, None)
            self._ns_segments.pop(namespace, None)
            return len(identities)

    def status(self, namespace: str, key: int) -> dict:
        with self._lock:
            self._require_namespace(namespace)
            self._require_key(key)
            segment = self._require_segment(namespace, key)
            return {
                "state": segment["state"],
                "refcount": int(segment["refcount"]),
                "attached_pids": tuple(sorted(segment["attachments"])),
                "last_attach_at": segment["last_attach_at"],
                "size": int(segment["size"]),
            }

    def segments(self, namespace: str | None = None) -> list:
        with self._lock:
            if namespace is not None:
                self._require_namespace(namespace)
            records = [
                self._record(segment)
                for segment in self._segments.values()
                if namespace is None or segment["namespace"] == namespace
            ]
            records.sort(key=lambda record: (record.namespace, record.key))
            return records

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": _SNAPSHOT_VERSION,
                "next_segment_number": self._next_number,
                "segments": copy.deepcopy(list(self._segments.values())),
                "quotas": {
                    "user_bytes": copy.deepcopy(self._user_bytes),
                    "user_segments": copy.deepcopy(self._user_segments),
                    "namespace_bytes": copy.deepcopy(self._ns_bytes),
                    "namespace_segments": copy.deepcopy(self._ns_segments),
                },
                "stats": self.stats(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except ShmError:
                self._counters["denied"] += 1
                raise
            except Exception as exc:
                self._counters["denied"] += 1
                raise ShmError("SHM_SNAPSHOT_INVALID", state) from exc

            self._segments = parsed["segments"]
            self._user_bytes = parsed["user_bytes"]
            self._user_segments = parsed["user_segments"]
            self._ns_bytes = parsed["namespace_bytes"]
            self._ns_segments = parsed["namespace_segments"]
            self._next_number = parsed["next_number"]
            self._counters = parsed["counters"]

    def stats(self) -> dict:
        with self._lock:
            live = sum(1 for segment in self._segments.values()
                       if segment["state"] == "live")
            pending = sum(1 for segment in self._segments.values()
                          if segment["state"] == "pending_delete")
            attached_refs = sum(int(segment["refcount"])
                                for segment in self._segments.values())
            return {
                "segments": len(self._segments),
                "live": live,
                "pending_delete": pending,
                "attached_refs": attached_refs,
                "quota_bytes": sum(self._user_bytes.values()),
                "quota_segments": sum(self._user_segments.values()),
                "created": self._counters["created"],
                "attached": self._counters["attached"],
                "detached": self._counters["detached"],
                "removed": self._counters["removed"],
                "swept": self._counters["swept"],
                "denied": self._counters["denied"],
            }

    def _current_time(self, now: object | None) -> object:
        if now is not None:
            return now
        clock = self._clock
        if clock is None:
            return datetime.now(timezone.utc).isoformat()
        if callable(clock):
            value = clock()
        else:
            now_method = getattr(clock, "now", None)
            value = now_method() if callable(now_method) else clock
        if value is None:
            return datetime.now(timezone.utc).isoformat()
        return value

    def _deny(self, code: str, detail: object = None) -> None:
        self._counters["denied"] += 1
        raise ShmError(code, detail)

    def _require_namespace(self, namespace: object) -> None:
        if not _valid_identifier(namespace):
            self._deny("SHM_BAD_NAMESPACE", namespace)

    def _require_key(self, key: object) -> None:
        if not _is_real_int(key) or not (_KEY_MIN <= key <= _KEY_MAX):
            self._deny("SHM_BAD_KEY", key)

    def _require_owner(self, owner: object) -> None:
        if not _valid_identifier(owner):
            self._deny("SHM_BAD_OWNER", owner)

    def _require_size(self, size: object) -> None:
        if not _is_real_int(size) or size <= 0:
            self._deny("SHM_BAD_SIZE", size)

    def _require_pid(self, pid: object) -> None:
        if not _is_real_int(pid) or pid <= 0:
            self._deny("SHM_BAD_PID", pid)

    def _require_segment(self, namespace: str, key: int) -> dict[str, Any]:
        segment = self._segments.get((namespace, key))
        if segment is None:
            raise ShmError("SHM_NOT_FOUND", {"namespace": namespace, "key": key})
        return segment

    @staticmethod
    def _record(segment: dict[str, Any]) -> SegmentRecord:
        return SegmentRecord(
            namespace=segment["namespace"],
            key=segment["key"],
            owner=segment["owner"],
            size=segment["size"],
            segment_id=segment["segment_id"],
            state=segment["state"],
            refcount=int(segment["refcount"]),
            created_at=segment["created_at"],
            last_attach_at=segment["last_attach_at"],
        )

    def _delete_segment(self, segment: dict[str, Any]) -> None:
        identity = (segment["namespace"], segment["key"])
        if self._segments.get(identity) is not segment:
            return
        del self._segments[identity]

        owner = segment["owner"]
        namespace = segment["namespace"]
        size = int(segment["size"])
        self._release_watermark(self._user_bytes, owner, size)
        self._release_watermark(self._user_segments, owner, 1)
        self._release_watermark(self._ns_bytes, namespace, size)
        self._release_watermark(self._ns_segments, namespace, 1)

    @staticmethod
    def _release_watermark(watermarks: dict[str, int], name: str, amount: int) -> None:
        value = watermarks.get(name, 0) - amount
        if value <= 0:
            watermarks.pop(name, None)
        else:
            watermarks[name] = value

    @classmethod
    def _parse_snapshot(cls, state: object) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise ShmError("SHM_SNAPSHOT_INVALID", state)

        raw_segments = state.get("segments")
        if not isinstance(raw_segments, list):
            raise ShmError("SHM_SNAPSHOT_INVALID", state)

        segments: dict[tuple[str, int], dict[str, Any]] = {}
        user_bytes: dict[str, int] = {}
        user_segments: dict[str, int] = {}
        ns_bytes: dict[str, int] = {}
        ns_segments: dict[str, int] = {}
        max_number = 0

        for raw in raw_segments:
            if not isinstance(raw, dict):
                raise ShmError("SHM_SNAPSHOT_INVALID", raw)

            namespace = raw.get("namespace")
            key = raw.get("key")
            owner = raw.get("owner")
            size = raw.get("size")
            if (not _valid_identifier(namespace) or not _valid_identifier(owner)
                    or not cls._valid_snapshot_key(key)
                    or not _is_real_int(size) or size <= 0):
                raise ShmError("SHM_SNAPSHOT_INVALID", raw)

            segment_id = raw.get("segment_id")
            if not isinstance(segment_id, str) or not segment_id.startswith("shm-"):
                raise ShmError("SHM_SNAPSHOT_INVALID", raw)
            suffix = segment_id[4:]
            if not suffix.isdigit():
                raise ShmError("SHM_SNAPSHOT_INVALID", raw)
            number = int(suffix)
            if number <= 0 or segment_id != f"shm-{number}":
                raise ShmError("SHM_SNAPSHOT_INVALID", raw)
            max_number = max(max_number, number)

            lifecycle_state = raw.get("state", "live")
            if lifecycle_state not in ("live", "pending_delete"):
                raise ShmError("SHM_SNAPSHOT_INVALID", raw)

            created_at = raw.get("created_at")
            last_attach_at = raw.get("last_attach_at")
            if not cls._valid_time_value(created_at):
                raise ShmError("SHM_SNAPSHOT_INVALID", raw)
            if last_attach_at is not None and not cls._valid_time_value(last_attach_at):
                raise ShmError("SHM_SNAPSHOT_INVALID", raw)

            attachments = cls._parse_attachments(raw)
            refcount = raw.get("refcount")
            attachment_refs = sum(attachments.values())
            if not _is_real_int(refcount) or refcount < 0 or refcount != attachment_refs:
                raise ShmError("SHM_SNAPSHOT_INVALID", raw)
            if lifecycle_state == "pending_delete" and refcount == 0:
                raise ShmError("SHM_SNAPSHOT_INVALID", raw)

            identity = (namespace, key)
            if identity in segments:
                raise ShmError("SHM_SNAPSHOT_INVALID", raw)

            segments[identity] = {
                "namespace": namespace,
                "key": key,
                "owner": owner,
                "size": size,
                "segment_id": segment_id,
                "state": lifecycle_state,
                "refcount": refcount,
                "created_at": created_at,
                "last_attach_at": last_attach_at,
                "attachments": attachments,
            }

            user_bytes[owner] = user_bytes.get(owner, 0) + size
            user_segments[owner] = user_segments.get(owner, 0) + 1
            ns_bytes[namespace] = ns_bytes.get(namespace, 0) + size
            ns_segments[namespace] = ns_segments.get(namespace, 0) + 1

        cls._validate_raw_quota_block(
            state.get("quotas", state.get("quota_watermarks"))
        )
        counters = cls._parse_snapshot_stats(state.get("stats", state.get("counters")))

        raw_next = state.get("next_segment_number", state.get("next_id"))
        next_number = max(max_number + 1, counters["created"] + 1, 1)
        if raw_next is not None:
            if not _is_real_int(raw_next) or raw_next <= 0:
                raise ShmError("SHM_SNAPSHOT_INVALID", raw_next)
            next_number = max(next_number, raw_next)

        return {
            "segments": segments,
            "user_bytes": user_bytes,
            "user_segments": user_segments,
            "namespace_bytes": ns_bytes,
            "namespace_segments": ns_segments,
            "next_number": next_number,
            "counters": counters,
        }

    @staticmethod
    def _valid_snapshot_key(key: object) -> bool:
        return _is_real_int(key) and _KEY_MIN <= key <= _KEY_MAX

    @staticmethod
    def _valid_time_value(value: object) -> bool:
        if isinstance(value, bool):
            return False
        if isinstance(value, (int, float)):
            return math.isfinite(value)
        try:
            _timestamp_seconds(value)
        except (TypeError, ValueError, OverflowError):
            return False
        return True

    @classmethod
    def _parse_attachments(cls, raw_segment: dict[str, Any]) -> dict[int, int]:
        attachments: dict[int, int] = {}
        raw_attachments = raw_segment.get("attachments")
        if raw_attachments is None:
            raw_attachments = raw_segment.get("attached_pids", [])

        if isinstance(raw_attachments, dict):
            items = list(raw_attachments.items())
        elif isinstance(raw_attachments, list):
            items = []
            for item in raw_attachments:
                if _is_real_int(item):
                    items.append((item, 1))
                elif isinstance(item, dict):
                    items.append((item.get("pid"), item.get("count", 1)))
                elif isinstance(item, (list, tuple)) and len(item) == 2:
                    items.append((item[0], item[1]))
                else:
                    raise ShmError("SHM_SNAPSHOT_INVALID", raw_segment)
        else:
            raise ShmError("SHM_SNAPSHOT_INVALID", raw_segment)

        for raw_pid, raw_count in items:
            pid = cls._snapshot_pid(raw_pid)
            if pid is None or not _is_real_int(raw_count) or raw_count <= 0:
                raise ShmError("SHM_SNAPSHOT_INVALID", raw_segment)
            if pid in attachments:
                raise ShmError("SHM_SNAPSHOT_INVALID", raw_segment)
            attachments[pid] = raw_count
        return attachments

    @staticmethod
    def _snapshot_pid(raw_pid: object) -> int | None:
        if _is_real_int(raw_pid) and raw_pid > 0:
            return int(raw_pid)
        if isinstance(raw_pid, str) and raw_pid.isdigit():
            pid = int(raw_pid)
            return pid if pid > 0 else None
        return None

    @staticmethod
    def _validate_raw_quota_block(raw_quotas: object) -> None:
        if raw_quotas is None:
            return
        if not isinstance(raw_quotas, dict):
            raise ShmError("SHM_SNAPSHOT_INVALID", raw_quotas)
        for name in ("user_bytes", "user_segments",
                     "namespace_bytes", "namespace_segments"):
            block = raw_quotas.get(name, {})
            if not isinstance(block, dict):
                raise ShmError("SHM_SNAPSHOT_INVALID", block)
            for quota_name, value in block.items():
                if not isinstance(quota_name, str):
                    raise ShmError("SHM_SNAPSHOT_INVALID", block)
                if not _is_real_int(value) or value < 0:
                    raise ShmError("SHM_SNAPSHOT_INVALID", value)

    @staticmethod
    def _parse_snapshot_stats(raw_stats: object) -> dict[str, int]:
        if raw_stats is None:
            raw_stats = {}
        if not isinstance(raw_stats, dict):
            raise ShmError("SHM_SNAPSHOT_INVALID", raw_stats)
        counters = {}
        for name in _COUNTER_KEYS:
            value = raw_stats.get(name, 0)
            if not _is_real_int(value) or value < 0:
                raise ShmError("SHM_SNAPSHOT_INVALID", {name: value})
            counters[name] = value
        return counters
