"""LUKS keyslot governance: two phase passphrase change, header backups, slot reclamation."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class KeyslotError(ValueError):
    """Raised when a keyslot operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


KEY_TYPES = ("luks1", "luks2")


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


class LuksKeyslotGuard:
    """Track keyslots, header backups and the audit trail of each volume."""

    def __init__(self, *, max_slots: int = 8, clock=None) -> None:
        self.max_slots = max_slots
        self._clock = clock
        self._lock = threading.RLock()
        self._volumes: dict[str, dict] = {}
        self._backups: dict[str, list[HeaderBackup]] = {}
        self._audit: dict[str, list[dict]] = {}
        self._pending: dict[str, dict] = {}
        self._counters = {"changes": 0, "restores": 0}

    def register_volume(self, volume_id: str, *, uuid: str, device_path: str,
                        now: str) -> VolumeInfo:
        raise NotImplementedError

    def add_key(self, volume_id: str, *, passphrase: str, label: str = "",
                key_type: str = "luks2", now: str) -> Keyslot:
        raise NotImplementedError

    def change_key(self, volume_id: str, *, slot: int, old_passphrase: str,
                   new_passphrase: str, now: str) -> Keyslot:
        raise NotImplementedError

    def remove_key(self, volume_id: str, *, slot: int, passphrase: str,
                   now: str) -> int:
        raise NotImplementedError

    def backup_header(self, volume_id: str, *, now: str) -> HeaderBackup:
        raise NotImplementedError

    def restore_header(self, volume_id: str, backup: HeaderBackup, *,
                       now: str) -> VolumeInfo:
        raise NotImplementedError

    def verify_header(self, volume_id: str, backup: HeaderBackup) -> bool:
        raise NotImplementedError

    def keyslots(self, volume_id: str) -> list[Keyslot]:
        raise NotImplementedError

    def pending_change(self, volume_id: str) -> dict | None:
        raise NotImplementedError

    def audit_log(self, volume_id: str) -> list[dict]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
