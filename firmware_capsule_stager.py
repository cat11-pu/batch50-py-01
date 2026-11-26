"""Firmware capsule staging: signature gate, A/B slots, resumable writes."""

from __future__ import annotations

import threading
from dataclasses import dataclass


ERR_INVALID_REQUEST = "FIRMWARE_INVALID_REQUEST"
ERR_MODEL_NOT_ALLOWED = "FIRMWARE_MODEL_NOT_ALLOWED"
ERR_SIGNATURE_INVALID = "FIRMWARE_SIGNATURE_INVALID"
ERR_KEY_UNKNOWN = "FIRMWARE_KEY_UNKNOWN"
ERR_KEY_CONFLICT = "FIRMWARE_KEY_CONFLICT"
ERR_PAYLOAD_TOO_LARGE = "FIRMWARE_PAYLOAD_TOO_LARGE"
ERR_VERSION_ROLLBACK = "FIRMWARE_VERSION_ROLLBACK"
ERR_VERSION_CONFLICT = "FIRMWARE_VERSION_CONFLICT"
ERR_NO_FREE_SLOT = "FIRMWARE_NO_FREE_SLOT"
ERR_STAGE_NOT_OPEN = "FIRMWARE_STAGE_NOT_OPEN"
ERR_STAGE_OVERFLOW = "FIRMWARE_STAGE_OVERFLOW"
ERR_STAGE_INCOMPLETE = "FIRMWARE_STAGE_INCOMPLETE"
ERR_NOT_VERIFIED = "FIRMWARE_NOT_VERIFIED"
ERR_NO_CAPSULE = "FIRMWARE_NO_CAPSULE"
ERR_CHECKSUM_MISMATCH = "FIRMWARE_CHECKSUM_MISMATCH"
ERR_NO_ROLLBACK_TARGET = "FIRMWARE_NO_ROLLBACK_TARGET"


class FirmwareStagerError(ValueError):
    """Raised when a capsule operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class StageReport:
    capsule_id: str
    slot: str
    state: str
    written: int
    total: int
    digest: str
    already_staged: bool


@dataclass(frozen=True)
class VerificationReport:
    capsule_id: str
    valid: bool
    code: str
    digest: str
    bytes_checked: int


@dataclass(frozen=True)
class TransitionReport:
    active: str
    previous: object
    version: int
    idempotent: bool


@dataclass(frozen=True)
class CapsuleInfo:
    capsule_id: str
    version: int
    slot: str
    path: str
    state: str
    written: int
    verified: bool
    digest: str


class FirmwareCapsuleStager:
    """Accept signed capsules, write the inactive slot and drive the boot switch."""

    def __init__(self, storage_dir, *, model: str, allowed_models=(),
                 trusted_keys=None, chunk_size: int = 32,
                 max_payload_bytes: int = 4096) -> None:
        self.storage_dir = str(storage_dir)
        self.model = model
        self.allowed_models = tuple(allowed_models) or (model,)
        self.trusted_keys = dict(trusted_keys or {})
        self.chunk_size = int(chunk_size)
        self.max_payload_bytes = int(max_payload_bytes)
        self._lock = threading.RLock()

    def add_trusted_key(self, key_id: str, secret) -> None:
        raise NotImplementedError

    def revoke_trusted_key(self, key_id: str) -> bool:
        raise NotImplementedError

    def begin_stage(self, *, capsule_id: str, model: str, version: int,
                    payload, key_id: str, signature: str) -> StageReport:
        raise NotImplementedError

    def append_chunk(self, capsule_id: str, data) -> StageReport:
        raise NotImplementedError

    def finish_stage(self, capsule_id: str) -> StageReport:
        raise NotImplementedError

    def stage(self, *, capsule_id: str, model: str, version: int,
              payload, key_id: str, signature: str) -> StageReport:
        raise NotImplementedError

    def verify(self, capsule_id: str) -> VerificationReport:
        raise NotImplementedError

    def commit(self, capsule_id=None) -> TransitionReport:
        raise NotImplementedError

    def rollback(self) -> TransitionReport:
        raise NotImplementedError

    def resume(self) -> tuple:
        raise NotImplementedError

    def capsules(self) -> list:
        raise NotImplementedError

    def status(self) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
