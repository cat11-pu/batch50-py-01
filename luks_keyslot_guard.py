"""LUKS keyslot governance with resumable rotation and auditable recovery."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable


class KeyslotError(ValueError):
    """Raised when a keyslot operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


KEY_TYPES = ("luks1", "luks2")
SNAPSHOT_VERSION = 1
HEADER_FORMAT = "luks-keyslot-guard-header/v1"
MAX_PASSPHRASE_BYTES = 512


@dataclass(frozen=True)
class Keyslot:
    slot: int
    key_type: str
    label: str
    fingerprint: str
    added_at: str


@dataclass(frozen=True)
class VolumeInfo:
    volume_id: str
    uuid: str
    device_path: str
    header_version: int
    header_checksum: str
    slots: tuple[Keyslot, ...]


@dataclass(frozen=True)
class HeaderBackup:
    volume_id: str
    uuid: str
    version: int
    checksum: str
    payload: str
    created_at: str


def _sha256_hex(value: str | bytes) -> str:
    raw = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    return hashlib.sha256(raw).hexdigest()


def _passphrase_bytes(passphrase: Any) -> bytes:
    if isinstance(passphrase, str):
        raw = passphrase.encode("utf-8")
    elif isinstance(passphrase, (bytes, bytearray, memoryview)):
        raw = bytes(passphrase)
    else:
        raise KeyslotError(
            "KEYSLOT_INVALID_PASSPHRASE",
            {"reason": "passphrase must be a string"},
        )

    if len(raw) > MAX_PASSPHRASE_BYTES:
        raise KeyslotError(
            "KEYSLOT_INVALID_PASSPHRASE",
            {"length": len(raw), "max_bytes": MAX_PASSPHRASE_BYTES},
        )
    return raw


def _fingerprint(passphrase: Any) -> str:
    return hashlib.sha256(_passphrase_bytes(passphrase)).hexdigest()


def _is_real_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _backup_to_dict(backup: HeaderBackup) -> dict[str, Any]:
    return {
        "volume_id": backup.volume_id,
        "uuid": backup.uuid,
        "version": backup.version,
        "checksum": backup.checksum,
        "payload": backup.payload,
        "created_at": backup.created_at,
    }


def _backup_data(backup: Any) -> dict[str, Any]:
    if isinstance(backup, HeaderBackup):
        return _backup_to_dict(backup)
    if isinstance(backup, dict):
        return copy.deepcopy(backup)
    raise KeyslotError("KEYSLOT_BACKUP_CORRUPT", {"reason": "backup is invalid"})


def _backup_uuid(backup: Any) -> str | None:
    if isinstance(backup, HeaderBackup):
        return backup.uuid
    if isinstance(backup, dict):
        uuid = backup.get("uuid")
        return uuid if isinstance(uuid, str) else None
    uuid = getattr(backup, "uuid", None)
    return uuid if isinstance(uuid, str) else None


def _encode_header(uuid: str, version: int, slots: dict[int, dict[str, Any]]) -> str:
    slot_documents = []
    for slot_number in sorted(slots):
        slot = slots[slot_number]
        slot_documents.append(
            {
                "slot": slot_number,
                "key_type": slot["key_type"],
                "label": slot["label"],
                "fingerprint": slot["fingerprint"],
                "added_at": slot["added_at"],
            }
        )

    document = {
        "format": HEADER_FORMAT,
        "uuid": uuid,
        "version": version,
        "slots": slot_documents,
    }
    return json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _parse_header_payload(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, str):
        raise KeyslotError("KEYSLOT_BACKUP_CORRUPT", {"reason": "payload is not text"})
    try:
        document = json.loads(payload)
    except (json.JSONDecodeError, TypeError) as exc:
        raise KeyslotError(
            "KEYSLOT_BACKUP_CORRUPT", {"reason": "payload is not valid JSON"}
        ) from exc

    if not isinstance(document, dict):
        raise KeyslotError("KEYSLOT_BACKUP_CORRUPT", {"reason": "payload is invalid"})
    if document.get("format") != HEADER_FORMAT:
        raise KeyslotError("KEYSLOT_BACKUP_CORRUPT", {"reason": "unknown header format"})
    if not isinstance(document.get("uuid"), str) or not document["uuid"]:
        raise KeyslotError("KEYSLOT_BACKUP_CORRUPT", {"reason": "uuid is invalid"})
    if not _is_real_int(document.get("version")) or document["version"] < 1:
        raise KeyslotError("KEYSLOT_BACKUP_CORRUPT", {"reason": "version is invalid"})
    if not isinstance(document.get("slots"), list):
        raise KeyslotError("KEYSLOT_BACKUP_CORRUPT", {"reason": "slots are invalid"})
    return document


class LuksKeyslotGuard:
    """Track keyslots, header backups and the audit trail of each volume."""

    def __init__(self, *, max_slots: int = 8, clock: Callable[[], str] | None = None) -> None:
        self.max_slots = max_slots
        self._clock = clock
        self._global_lock = threading.RLock()
        self._lock = self._global_lock
        self._volume_locks: dict[str, threading.RLock] = {}
        self._volumes: dict[str, dict[str, Any]] = {}
        self._backups: dict[str, list[dict[str, Any]]] = {}
        self._audit: dict[str, list[dict[str, Any]]] = {}
        self._pending: dict[str, dict[str, Any] | None] = {}
        self._counters = {"changes": 0, "restores": 0}

    def _timestamp(self, now: str | None) -> str:
        if now is not None:
            return now
        if callable(self._clock):
            return self._clock()
        return datetime.now(timezone.utc).isoformat()

    def _resolve_reference_locked(self, reference: Any, backup: Any = None) -> str:
        if not isinstance(reference, str) or not reference:
            raise KeyslotError("KEYSLOT_UNKNOWN_VOLUME", {"volume_id": reference})

        if reference in self._volumes:
            return reference

        for volume_id, volume in sorted(self._volumes.items()):
            if volume.get("uuid") == reference:
                return volume_id

        path_matches = sorted(
            volume_id
            for volume_id, volume in self._volumes.items()
            if volume.get("device_path") == reference
        )
        if len(path_matches) == 1:
            return path_matches[0]

        backup_uuid = _backup_uuid(backup)
        if backup_uuid is not None:
            uuid_matches = sorted(
                volume_id
                for volume_id, volume in self._volumes.items()
                if volume.get("uuid") == backup_uuid
            )
            if len(uuid_matches) == 1:
                return uuid_matches[0]

        raise KeyslotError("KEYSLOT_UNKNOWN_VOLUME", {"volume_id": reference})

    def _with_volume(self, reference: str, operation: Callable[[str, dict[str, Any]], Any],
                     backup: Any = None) -> Any:
        while True:
            with self._global_lock:
                volume_id = self._resolve_reference_locked(reference, backup)
                volume_lock = self._volume_locks.setdefault(volume_id, threading.RLock())

            with volume_lock:
                with self._global_lock:
                    still_present = volume_id in self._volumes
                if not still_present:
                    continue
                return operation(volume_id, self._volumes[volume_id])

    def _append_audit(self, volume_id: str, action: str, slot: int | None,
                      at: str, result: str = "ok", **extra: Any) -> None:
        entry: dict[str, Any] = {
            "at": at,
            "action": action,
            "slot": slot,
            "result": result,
        }
        entry.update(extra)
        self._audit.setdefault(volume_id, []).append(entry)

    def _keyslot_view(self, record: dict[str, Any]) -> Keyslot:
        return Keyslot(
            slot=record["slot"],
            key_type=record["key_type"],
            label=record["label"],
            fingerprint=record["fingerprint"],
            added_at=record["added_at"],
        )

    def _volume_info(self, volume: dict[str, Any]) -> VolumeInfo:
        slots = tuple(
            self._keyslot_view(volume["slots"][slot_number])
            for slot_number in sorted(volume["slots"])
        )
        return VolumeInfo(
            volume_id=volume["volume_id"],
            uuid=volume["uuid"],
            device_path=volume["device_path"],
            header_version=volume["header_version"],
            header_checksum=volume["header_checksum"],
            slots=slots,
        )

    def _touch_header(self, volume: dict[str, Any]) -> None:
        volume["header_payload"] = _encode_header(
            volume["uuid"], volume["header_version"], volume["slots"]
        )
        volume["header_checksum"] = _sha256_hex(volume["header_payload"])

    def _increment_header(self, volume: dict[str, Any]) -> None:
        volume["header_version"] += 1
        self._touch_header(volume)

    def _require_slot(self, volume: dict[str, Any], slot: Any) -> int:
        if (
            not _is_real_int(slot)
            or slot < 0
            or slot >= self.max_slots
            or slot not in volume["slots"]
        ):
            raise KeyslotError("KEYSLOT_INVALID_SLOT", {"slot": slot})
        return slot

    def _find_fingerprint_slot(self, volume: dict[str, Any], fingerprint: str) -> int | None:
        for slot_number in sorted(volume["slots"]):
            if hmac.compare_digest(
                volume["slots"][slot_number]["fingerprint"], fingerprint
            ):
                return slot_number
        return None

    def _lowest_free_slot(self, volume: dict[str, Any]) -> int:
        for slot_number in range(self.max_slots):
            if slot_number not in volume["slots"]:
                return slot_number
        raise KeyslotError(
            "KEYSLOT_EXHAUSTED",
            {"max_slots": self.max_slots, "occupied": len(volume["slots"])},
        )

    @staticmethod
    def _validate_key_type(key_type: Any) -> str:
        if key_type not in KEY_TYPES:
            raise KeyslotError("KEYSLOT_INVALID_KEY_TYPE", {"key_type": key_type})
        return key_type

    def register_volume(self, volume_id: str, *, uuid: str, device_path: str,
                        now: str) -> VolumeInfo:
        timestamp = self._timestamp(now)
        with self._global_lock:
            if volume_id in self._volumes:
                raise KeyslotError(
                    "KEYSLOT_DUPLICATE_VOLUME", {"volume_id": volume_id}
                )
            for existing_id, volume in self._volumes.items():
                if volume["uuid"] == uuid:
                    raise KeyslotError(
                        "KEYSLOT_DUPLICATE_VOLUME",
                        {"volume_id": existing_id, "uuid": uuid},
                    )

            payload = _encode_header(uuid, 1, {})
            self._volumes[volume_id] = {
                "volume_id": volume_id,
                "uuid": uuid,
                "device_path": device_path,
                "header_version": 1,
                "header_payload": payload,
                "header_checksum": _sha256_hex(payload),
                "slots": {},
            }
            self._backups[volume_id] = []
            self._audit[volume_id] = []
            self._pending[volume_id] = None
            self._volume_locks.setdefault(volume_id, threading.RLock())
            self._append_audit(volume_id, "register", None, timestamp)
            return self._volume_info(self._volumes[volume_id])

    def add_key(self, volume_id: str, *, passphrase: str, label: str = "",
                key_type: str = "luks2", now: str) -> Keyslot:
        timestamp = self._timestamp(now)

        def operation(volume_id: str, volume: dict[str, Any]) -> Keyslot:
            fingerprint = _fingerprint(passphrase)
            validated_key_type = self._validate_key_type(key_type)
            duplicate_slot = self._find_fingerprint_slot(volume, fingerprint)
            if duplicate_slot is not None:
                raise KeyslotError(
                    "KEYSLOT_DUPLICATE_KEY", {"slot": duplicate_slot}
                )

            slot_number = self._lowest_free_slot(volume)
            self._append_audit(volume_id, "add_key", slot_number, timestamp)
            volume["slots"][slot_number] = {
                "slot": slot_number,
                "key_type": validated_key_type,
                "label": label,
                "fingerprint": fingerprint,
                "added_at": timestamp,
            }
            self._increment_header(volume)
            return self._keyslot_view(volume["slots"][slot_number])

        return self._with_volume(volume_id, operation)

    def _resume_or_prepare_change(
        self,
        volume_id: str,
        volume: dict[str, Any],
        requested_slot: Any,
        old_fingerprint: str,
        new_fingerprint: str,
        timestamp: str,
    ) -> dict[str, Any]:
        pending = self._pending.get(volume_id)

        if pending is not None:
            old_slot = pending.get("old_slot", pending.get("slot", requested_slot))
            if not _is_real_int(old_slot):
                old_slot = requested_slot

            pending_new_fingerprint = pending.get("new_fingerprint")
            if (
                isinstance(pending_new_fingerprint, str)
                and not hmac.compare_digest(pending_new_fingerprint, new_fingerprint)
            ):
                raise KeyslotError(
                    "KEYSLOT_CHANGE_CONFLICT",
                    {"old_slot": old_slot, "new_slot": pending.get("new_slot")},
                )

            if old_slot in volume["slots"]:
                self._require_slot(volume, old_slot)
                if not hmac.compare_digest(
                    volume["slots"][old_slot]["fingerprint"], old_fingerprint
                ):
                    raise KeyslotError("KEYSLOT_WRONG_PASSPHRASE", {"slot": old_slot})
            else:
                recorded_old_fingerprint = pending.get("old_fingerprint")
                if (
                    isinstance(recorded_old_fingerprint, str)
                    and not hmac.compare_digest(
                        recorded_old_fingerprint, old_fingerprint
                    )
                ):
                    raise KeyslotError("KEYSLOT_WRONG_PASSPHRASE", {"slot": old_slot})

            if requested_slot not in (old_slot, pending.get("new_slot")):
                raise KeyslotError(
                    "KEYSLOT_CHANGE_CONFLICT",
                    {"requested_slot": requested_slot, "old_slot": old_slot},
                )

            pending["old_slot"] = old_slot
            pending["slot"] = old_slot
            pending["new_fingerprint"] = new_fingerprint
            pending.setdefault("volume_id", volume_id)
            pending.setdefault("created_at", timestamp)
            pending["updated_at"] = timestamp
            return pending

        old_slot = self._require_slot(volume, requested_slot)
        if not hmac.compare_digest(
            volume["slots"][old_slot]["fingerprint"], old_fingerprint
        ):
            raise KeyslotError("KEYSLOT_WRONG_PASSPHRASE", {"slot": old_slot})

        duplicate_slot = self._find_fingerprint_slot(volume, new_fingerprint)
        if duplicate_slot is not None:
            raise KeyslotError("KEYSLOT_DUPLICATE_KEY", {"slot": duplicate_slot})

        old_record = volume["slots"][old_slot]
        new_slot = self._lowest_free_slot(volume)
        pending = {
            "volume_id": volume_id,
            "slot": old_slot,
            "old_slot": old_slot,
            "new_slot": None,
            "old_fingerprint": old_fingerprint,
            "new_fingerprint": new_fingerprint,
            "key_type": old_record["key_type"],
            "label": old_record["label"],
            "stage": "prepared",
            "created_at": timestamp,
            "updated_at": timestamp,
        }
        self._pending[volume_id] = pending

        pending["new_slot"] = new_slot
        pending["stage"] = "new_slot_written"
        volume["slots"][new_slot] = {
            "slot": new_slot,
            "key_type": old_record["key_type"],
            "label": old_record["label"],
            "fingerprint": new_fingerprint,
            "added_at": timestamp,
        }
        self._increment_header(volume)
        return pending

    def change_key(self, volume_id: str, *, slot: int, old_passphrase: str,
                   new_passphrase: str, now: str) -> Keyslot:
        timestamp = self._timestamp(now)

        def operation(volume_id: str, volume: dict[str, Any]) -> Keyslot:
            old_fingerprint = _fingerprint(old_passphrase)
            new_fingerprint = _fingerprint(new_passphrase)
            pending = self._resume_or_prepare_change(
                volume_id,
                volume,
                slot,
                old_fingerprint,
                new_fingerprint,
                timestamp,
            )
            old_slot = pending["old_slot"]
            new_slot = pending["new_slot"]

            if not _is_real_int(new_slot) or new_slot not in volume["slots"]:
                new_slot = self._lowest_free_slot(volume)
                pending["new_slot"] = new_slot
                pending["stage"] = "new_slot_written"
                volume["slots"][new_slot] = {
                    "slot": new_slot,
                    "key_type": pending.get("key_type", "luks2"),
                    "label": pending.get("label", ""),
                    "fingerprint": new_fingerprint,
                    "added_at": timestamp,
                }
                self._increment_header(volume)
            elif not hmac.compare_digest(
                volume["slots"][new_slot]["fingerprint"], new_fingerprint
            ):
                raise KeyslotError("KEYSLOT_DUPLICATE_KEY", {"slot": new_slot})

            if old_slot in volume["slots"] and old_slot != new_slot:
                del volume["slots"][old_slot]

            pending["stage"] = "old_slot_removed"
            pending["updated_at"] = timestamp
            self._append_audit(
                volume_id,
                "change_key",
                old_slot,
                timestamp,
                new_slot=new_slot,
            )
            self._pending[volume_id] = None
            self._increment_header(volume)
            with self._global_lock:
                self._counters["changes"] += 1
            return self._keyslot_view(volume["slots"][new_slot])

        return self._with_volume(volume_id, operation)

    def remove_key(self, volume_id: str, *, slot: int, passphrase: str,
                   now: str) -> int:
        timestamp = self._timestamp(now)

        def operation(volume_id: str, volume: dict[str, Any]) -> int:
            fingerprint = _fingerprint(passphrase)
            slot_number = self._require_slot(volume, slot)
            if not hmac.compare_digest(
                volume["slots"][slot_number]["fingerprint"], fingerprint
            ):
                raise KeyslotError("KEYSLOT_WRONG_PASSPHRASE", {"slot": slot_number})

            if len(volume["slots"]) <= 1:
                raise KeyslotError(
                    "KEYSLOT_LAST_SLOT",
                    {"slot": slot_number, "remaining": 0},
                )

            pending = self._pending.get(volume_id)
            if pending is not None and slot_number in (
                pending.get("old_slot", pending.get("slot")),
                pending.get("new_slot"),
            ):
                self._pending[volume_id] = None

            self._append_audit(volume_id, "remove_key", slot_number, timestamp)
            del volume["slots"][slot_number]
            self._increment_header(volume)
            return len(volume["slots"])

        return self._with_volume(volume_id, operation)

    def backup_header(self, volume_id: str, *, now: str) -> HeaderBackup:
        timestamp = self._timestamp(now)

        def operation(volume_id: str, volume: dict[str, Any]) -> HeaderBackup:
            backup = HeaderBackup(
                volume_id=volume_id,
                uuid=volume["uuid"],
                version=volume["header_version"],
                checksum=volume["header_checksum"],
                payload=volume["header_payload"],
                created_at=timestamp,
            )
            self._append_audit(volume_id, "backup", None, timestamp)
            self._backups.setdefault(volume_id, []).append(_backup_to_dict(backup))
            return backup

        return self._with_volume(volume_id, operation)

    def _validated_backup(self, backup: Any, volume: dict[str, Any]) -> dict[str, Any]:
        data = _backup_data(backup)
        required = ("volume_id", "uuid", "version", "checksum", "payload", "created_at")
        if any(key not in data for key in required):
            raise KeyslotError("KEYSLOT_BACKUP_CORRUPT", {"reason": "backup is incomplete"})
        if not isinstance(data["uuid"], str) or not data["uuid"]:
            raise KeyslotError("KEYSLOT_BACKUP_CORRUPT", {"reason": "uuid is invalid"})
        if not _is_real_int(data["version"]) or data["version"] < 1:
            raise KeyslotError("KEYSLOT_BACKUP_CORRUPT", {"reason": "version is invalid"})
        if not isinstance(data["checksum"], str) or len(data["checksum"]) != 64:
            raise KeyslotError("KEYSLOT_BACKUP_CORRUPT", {"reason": "checksum is invalid"})
        if not isinstance(data["payload"], str):
            raise KeyslotError("KEYSLOT_BACKUP_CORRUPT", {"reason": "payload is invalid"})

        actual_checksum = _sha256_hex(data["payload"])
        if not hmac.compare_digest(actual_checksum, data["checksum"]):
            raise KeyslotError("KEYSLOT_BACKUP_CORRUPT", {"reason": "checksum mismatch"})

        document = _parse_header_payload(data["payload"])
        if document["uuid"] != data["uuid"] or document["version"] != data["version"]:
            raise KeyslotError(
                "KEYSLOT_BACKUP_CORRUPT", {"reason": "backup metadata does not match payload"}
            )
        if data["uuid"] != volume["uuid"]:
            raise KeyslotError(
                "KEYSLOT_BACKUP_UUID_MISMATCH",
                {"backup_uuid": data["uuid"], "volume_uuid": volume["uuid"]},
            )
        return data

    def restore_header(self, volume_id: str, backup: HeaderBackup, *,
                       now: str) -> VolumeInfo:
        timestamp = self._timestamp(now)

        def operation(resolved_id: str, volume: dict[str, Any]) -> VolumeInfo:
            data = self._validated_backup(backup, volume)
            if data["version"] < volume["header_version"]:
                raise KeyslotError(
                    "KEYSLOT_BACKUP_STALE",
                    {
                        "backup_version": data["version"],
                        "current_version": volume["header_version"],
                    },
                )

            document = _parse_header_payload(data["payload"])
            restored_slots: dict[int, dict[str, Any]] = {}
            for item in document["slots"]:
                if not isinstance(item, dict):
                    raise KeyslotError(
                        "KEYSLOT_BACKUP_CORRUPT", {"reason": "slot record is invalid"}
                    )
                slot_number = item.get("slot")
                if (
                    not _is_real_int(slot_number)
                    or slot_number < 0
                    or slot_number >= self.max_slots
                    or slot_number in restored_slots
                ):
                    raise KeyslotError(
                        "KEYSLOT_BACKUP_CORRUPT", {"reason": "slot number is invalid"}
                    )
                fingerprint = item.get("fingerprint")
                if not isinstance(fingerprint, str) or len(fingerprint) != 64:
                    raise KeyslotError(
                        "KEYSLOT_BACKUP_CORRUPT", {"reason": "fingerprint is invalid"}
                    )
                key_type = item.get("key_type")
                if key_type not in KEY_TYPES:
                    raise KeyslotError(
                        "KEYSLOT_BACKUP_CORRUPT", {"reason": "key type is invalid"}
                    )
                restored_slots[slot_number] = {
                    "slot": slot_number,
                    "key_type": key_type,
                    "label": item.get("label", ""),
                    "fingerprint": fingerprint,
                    "added_at": item.get("added_at", timestamp),
                }

            if (
                isinstance(volume_id, str)
                and volume_id.startswith("/")
                and volume_id != resolved_id
            ):
                volume["device_path"] = volume_id

            self._append_audit(resolved_id, "restore", None, timestamp)
            volume["slots"] = restored_slots
            volume["header_version"] = data["version"]
            volume["header_payload"] = data["payload"]
            volume["header_checksum"] = data["checksum"]
            self._pending[resolved_id] = None
            with self._global_lock:
                self._counters["restores"] += 1
            return self._volume_info(volume)

        return self._with_volume(volume_id, operation, backup=backup)

    def verify_header(self, volume_id: str, backup: HeaderBackup) -> bool:
        def operation(_volume_id: str, volume: dict[str, Any]) -> bool:
            try:
                data = self._validated_backup(backup, volume)
            except KeyslotError:
                return False
            return data["uuid"] == volume["uuid"]

        return self._with_volume(volume_id, operation, backup=backup)

    def keyslots(self, volume_id: str) -> list[Keyslot]:
        def operation(_volume_id: str, volume: dict[str, Any]) -> list[Keyslot]:
            return [
                self._keyslot_view(volume["slots"][slot_number])
                for slot_number in sorted(volume["slots"])
            ]

        return self._with_volume(volume_id, operation)

    def pending_change(self, volume_id: str) -> dict | None:
        def operation(volume_id: str, _volume: dict[str, Any]) -> dict | None:
            pending = self._pending.get(volume_id)
            if pending is None:
                return None
            view = copy.deepcopy(pending)
            new_slot = view.get("new_slot")
            new_slot_written = (
                _is_real_int(new_slot) and new_slot in _volume["slots"]
            )
            stage = view.get("stage")
            if not isinstance(stage, str):
                stage = "new_slot_written" if new_slot_written else "prepared"
            view.setdefault("stage", stage)
            view.setdefault("status", stage)
            view.setdefault("state", stage)
            view["new_slot_written"] = new_slot_written
            view["reuse_slot"] = new_slot if new_slot_written else None
            return view

        return self._with_volume(volume_id, operation)

    def audit_log(self, volume_id: str) -> list[dict]:
        def operation(volume_id: str, _volume: dict[str, Any]) -> list[dict]:
            return copy.deepcopy(self._audit.get(volume_id, []))

        return self._with_volume(volume_id, operation)

    def stats(self) -> dict[str, int]:
        state = self.snapshot()
        return {
            "volumes": len(state["volumes"]),
            "keyslots": sum(len(volume["slots"]) for volume in state["volumes"].values()),
            "backups": sum(len(items) for items in state["backups"].values()),
            "changes": int(state["counters"].get("changes", 0)),
            "restores": int(state["counters"].get("restores", 0)),
        }

    def snapshot(self) -> dict[str, Any]:
        while True:
            with self._global_lock:
                volume_ids = sorted(self._volumes)
                locks = [
                    self._volume_locks.setdefault(volume_id, threading.RLock())
                    for volume_id in volume_ids
                ]

            retry = False
            for volume_lock in locks:
                volume_lock.acquire()
            try:
                with self._global_lock:
                    if sorted(self._volumes) != volume_ids:
                        retry = True
                    else:
                        return {
                            "version": SNAPSHOT_VERSION,
                            "max_slots": self.max_slots,
                            "volumes": copy.deepcopy(self._volumes),
                            "backups": copy.deepcopy(self._backups),
                            "audit": copy.deepcopy(self._audit),
                            "pending": copy.deepcopy(self._pending),
                            "counters": copy.deepcopy(self._counters),
                        }
            finally:
                for volume_lock in reversed(locks):
                    volume_lock.release()
            if retry:
                continue

    def _validate_snapshot(self, state: Any) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"reason": "snapshot is not an object"})
        if state.get("version") != SNAPSHOT_VERSION:
            raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"reason": "version is unsupported"})
        raw_volumes = state.get("volumes")
        if isinstance(raw_volumes, dict):
            volume_entries = list(raw_volumes.items())
        elif isinstance(raw_volumes, list):
            volume_entries = []
            for raw_volume in raw_volumes:
                if not isinstance(raw_volume, dict):
                    raise KeyslotError(
                        "KEYSLOT_SNAPSHOT_INVALID", {"reason": "volume is invalid"}
                    )
                volume_entries.append((raw_volume.get("volume_id"), raw_volume))
        else:
            raise KeyslotError(
                "KEYSLOT_SNAPSHOT_INVALID", {"reason": "volumes must be an object or list"}
            )

        max_slots = state.get("max_slots", self.max_slots)
        if not _is_real_int(max_slots) or max_slots < 1:
            raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"reason": "max_slots is invalid"})

        volumes: dict[str, dict[str, Any]] = {}
        for volume_id, raw_volume in volume_entries:
            if not isinstance(volume_id, str) or not volume_id:
                raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"reason": "volume id is invalid"})
            if not isinstance(raw_volume, dict):
                raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"volume_id": volume_id})
            if not isinstance(raw_volume.get("uuid"), str) or not raw_volume["uuid"]:
                raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"volume_id": volume_id})
            if not isinstance(raw_volume.get("device_path"), str):
                raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"volume_id": volume_id})
            version = raw_volume.get("header_version")
            if not _is_real_int(version) or version < 1:
                raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"volume_id": volume_id})

            raw_slots = raw_volume.get("slots", {})
            if isinstance(raw_slots, dict):
                slot_items = raw_slots.items()
            elif isinstance(raw_slots, (list, tuple)):
                slot_items = [
                    (item.get("slot") if isinstance(item, dict) else index, item)
                    for index, item in enumerate(raw_slots)
                ]
            else:
                raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"volume_id": volume_id})

            slots: dict[int, dict[str, Any]] = {}
            fingerprints: set[str] = set()
            for raw_key, raw_slot in slot_items:
                if not isinstance(raw_slot, dict):
                    raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"volume_id": volume_id})
                try:
                    slot_number = int(raw_key)
                except (TypeError, ValueError) as exc:
                    raise KeyslotError(
                        "KEYSLOT_SNAPSHOT_INVALID", {"volume_id": volume_id}
                    ) from exc
                if _is_real_int(raw_slot.get("slot")):
                    slot_number = raw_slot["slot"]
                if (
                    not _is_real_int(slot_number)
                    or slot_number < 0
                    or slot_number >= max_slots
                    or slot_number in slots
                ):
                    raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"volume_id": volume_id})

                fingerprint = raw_slot.get("fingerprint")
                if not isinstance(fingerprint, str) or len(fingerprint) != 64:
                    raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"volume_id": volume_id})
                if fingerprint in fingerprints:
                    raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"volume_id": volume_id})
                fingerprints.add(fingerprint)

                key_type = raw_slot.get("key_type", "luks2")
                if key_type not in KEY_TYPES:
                    raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"volume_id": volume_id})
                label = raw_slot.get("label", "")
                added_at = raw_slot.get("added_at", "")
                if not isinstance(label, str) or not isinstance(added_at, str):
                    raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"volume_id": volume_id})

                slots[slot_number] = {
                    "slot": slot_number,
                    "key_type": key_type,
                    "label": label,
                    "fingerprint": fingerprint,
                    "added_at": added_at,
                }

            payload = _encode_header(raw_volume["uuid"], version, slots)
            volumes[volume_id] = {
                "volume_id": volume_id,
                "uuid": raw_volume["uuid"],
                "device_path": raw_volume["device_path"],
                "header_version": version,
                "header_payload": payload,
                "header_checksum": _sha256_hex(payload),
                "slots": slots,
            }

        backups = self._validate_snapshot_collection(
            state.get("backups", {}), volumes, "backups"
        )
        audit = self._validate_snapshot_collection(
            state.get("audit", {}), volumes, "audit"
        )
        pending = self._validate_snapshot_collection(
            state.get("pending", {}), volumes, "pending"
        )

        counters = state.get("counters", state.get("stats", {}))
        if not isinstance(counters, dict):
            raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"reason": "counters are invalid"})
        normalized_counters = copy.deepcopy(self._counters)
        for key in ("changes", "restores"):
            value = counters.get(key, 0)
            if not _is_real_int(value) or value < 0:
                raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"counter": key})
            normalized_counters[key] = value
        for key, value in counters.items():
            if key not in ("changes", "restores") and _is_real_int(value):
                normalized_counters[key] = value

        return {
            "max_slots": max_slots,
            "volumes": volumes,
            "backups": backups,
            "audit": audit,
            "pending": pending,
            "counters": normalized_counters,
        }

    def _validate_snapshot_collection(
        self, collection: Any, volumes: dict[str, dict[str, Any]], kind: str
    ) -> dict[str, Any]:
        if not isinstance(collection, dict):
            raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"collection": kind})

        normalized: dict[str, Any] = {}
        for volume_id, items in collection.items():
            if volume_id not in volumes:
                raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"orphan": volume_id})
            if kind in ("backups", "audit"):
                if not isinstance(items, list):
                    raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"collection": kind})
                normalized[volume_id] = copy.deepcopy(items)
            elif items is not None and not isinstance(items, dict):
                raise KeyslotError("KEYSLOT_SNAPSHOT_INVALID", {"collection": kind})
            else:
                normalized[volume_id] = copy.deepcopy(items)

        for volume_id in volumes:
            normalized.setdefault(volume_id, [] if kind in ("backups", "audit") else None)
        return normalized

    def restore(self, state: dict) -> None:
        candidate = self._validate_snapshot(state)
        candidate_ids = set(candidate["volumes"])

        while True:
            with self._global_lock:
                needed_ids = sorted(set(self._volumes) | candidate_ids)
                locks = {
                    volume_id: self._volume_locks.setdefault(volume_id, threading.RLock())
                    for volume_id in needed_ids
                }

            acquired = [locks[volume_id] for volume_id in needed_ids]
            for volume_lock in acquired:
                volume_lock.acquire()

            retry = False
            try:
                with self._global_lock:
                    if not set(self._volumes).issubset(set(locks)):
                        retry = True
                    else:
                        self.max_slots = candidate["max_slots"]
                        self._volumes = candidate["volumes"]
                        self._backups = candidate["backups"]
                        self._audit = candidate["audit"]
                        self._pending = candidate["pending"]
                        self._counters = candidate["counters"]
                        for volume_id in candidate_ids:
                            self._volume_locks.setdefault(volume_id, threading.RLock())
                        return None
            finally:
                for volume_lock in reversed(acquired):
                    volume_lock.release()
            if retry:
                continue
