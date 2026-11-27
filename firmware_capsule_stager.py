"""Firmware capsule staging: signature gate, A/B slots, resumable writes."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

try:  # pragma: no cover - platform import guard
    import fcntl
except ImportError:  # pragma: no cover
    fcntl = None


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

VERIFICATION_OK = "FIRMWARE_VERIFIED"


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

    _slots = ("A", "B")
    _stats_keys = (
        "staged",
        "verified",
        "committed",
        "rolled_back",
        "rejected",
        "resumed",
    )

    def __init__(self, storage_dir, *, model: str, allowed_models=(),
                 trusted_keys=None, chunk_size: int = 32,
                 max_payload_bytes: int = 4096) -> None:
        if not isinstance(model, str) or not model:
            raise FirmwareStagerError(ERR_INVALID_REQUEST)
        try:
            chunk_size = int(chunk_size)
            max_payload_bytes = int(max_payload_bytes)
        except (TypeError, ValueError) as exc:
            raise FirmwareStagerError(ERR_INVALID_REQUEST) from exc
        if chunk_size <= 0 or max_payload_bytes < 0:
            raise FirmwareStagerError(ERR_INVALID_REQUEST)

        self.storage_dir = str(storage_dir)
        self.model = model
        allowed = tuple(allowed_models)
        self.allowed_models = allowed or (model,)
        self.trusted_keys = dict(trusted_keys or {})
        self.chunk_size = chunk_size
        self.max_payload_bytes = max_payload_bytes

        storage_path = Path(storage_dir)
        self.slot_dir = storage_path / "slots"
        self.payload_dir = storage_path / "payloads"
        self.state_path = storage_path / "stager-state.json"
        self.lock_path = storage_path / "stager.lock"
        storage_path.mkdir(parents=True, exist_ok=True)
        self.slot_dir.mkdir(parents=True, exist_ok=True)
        self.payload_dir.mkdir(parents=True, exist_ok=True)

        self._thread_lock = threading.RLock()
        self._lock_depth = threading.local()
        self._state: dict = {}

        with self._locked():
            pass

    def add_trusted_key(self, key_id: str, secret) -> None:
        with self._locked():
            if not isinstance(key_id, str) or not key_id or secret is None:
                raise self._reject(ERR_INVALID_REQUEST)
            if key_id in self.trusted_keys:
                raise self._reject(ERR_KEY_CONFLICT)
            self.trusted_keys[key_id] = secret

    def revoke_trusted_key(self, key_id: str) -> bool:
        with self._locked():
            return self.trusted_keys.pop(key_id, None) is not None

    def begin_stage(self, *, capsule_id: str, model: str, version: int,
                    payload, key_id: str, signature: str) -> StageReport:
        with self._locked():
            if not isinstance(capsule_id, str) or not capsule_id:
                raise self._reject(ERR_INVALID_REQUEST)
            if not isinstance(model, str) or not model:
                raise self._reject(ERR_INVALID_REQUEST)
            if isinstance(version, bool) or not isinstance(version, int):
                raise self._reject(ERR_INVALID_REQUEST)
            payload = self._as_bytes(payload)
            if payload is None:
                raise self._reject(ERR_INVALID_REQUEST)
            if model not in self.allowed_models:
                raise self._reject(ERR_MODEL_NOT_ALLOWED)
            if len(payload) > self.max_payload_bytes:
                raise self._reject(ERR_PAYLOAD_TOO_LARGE)

            digest = hashlib.sha256(payload).hexdigest()
            secret = self.trusted_keys.get(key_id)
            if secret is None:
                raise self._reject(ERR_KEY_UNKNOWN)
            if not self._signature_matches(model, version, digest, secret, signature):
                raise self._reject(ERR_SIGNATURE_INVALID)
            if version < int(self._state["min_version"]):
                raise self._reject(ERR_VERSION_ROLLBACK)

            known_digest = self._known_version_digest(model, version)
            if known_digest is not None and not hmac.compare_digest(
                    known_digest, digest):
                raise self._reject(ERR_VERSION_CONFLICT)

            existing = self._state["capsules"].get(capsule_id)
            if existing is not None:
                if (existing.get("model") != model or
                        int(existing.get("version", -1)) != version or
                        existing.get("digest") != digest):
                    raise self._reject(ERR_VERSION_CONFLICT)
                self._ensure_source_payload(existing, payload)
                return self._stage_report(existing)

            slot = self._allocate_slot()
            source_name = f"payload-{hashlib.sha256(capsule_id.encode('utf-8')).hexdigest()}.bin"
            source_path = self.payload_dir / source_name
            slot_path = self._slot_path(slot)
            self._atomic_write_bytes(source_path, payload)

            for old_id, old_cap in list(self._state["capsules"].items()):
                if old_cap.get("slot") == slot:
                    del self._state["capsules"][old_id]

            if self._state.get("rollback_slot") == slot:
                self._state["rollback_slot"] = None

            order = int(self._state.get("next_order", 0))
            self._state["next_order"] = order + 1
            capsule = {
                "capsule_id": capsule_id,
                "model": model,
                "version": version,
                "slot": slot,
                "state": "writing",
                "written": 0,
                "total": len(payload),
                "digest": digest,
                "verified": False,
                "source": source_name,
                "order": order,
            }
            self._remember_version_digest(model, version, digest)
            self._state["capsules"][capsule_id] = capsule
            self._state["slots"][slot].update({
                "state": "writing",
                "version": version,
                "digest": digest,
                "written": 0,
                "total": len(payload),
                "capsule_id": capsule_id,
            })
            self._save_state()
            self._atomic_write_bytes(slot_path, b"")
            return self._stage_report(capsule, already_staged=False)

    def append_chunk(self, capsule_id: str, data) -> StageReport:
        with self._locked():
            capsule = self._get_capsule(capsule_id)
            if capsule.get("state") != "writing":
                raise self._reject(ERR_STAGE_NOT_OPEN)
            chunk = self._as_bytes(data)
            if chunk is None:
                raise self._reject(ERR_INVALID_REQUEST)

            written = int(capsule.get("written", 0))
            total = int(capsule.get("total", 0))
            if written + len(chunk) > total:
                raise self._reject(ERR_STAGE_OVERFLOW)

            slot_path = self._slot_path(capsule["slot"])
            slot_path.parent.mkdir(parents=True, exist_ok=True)
            if not slot_path.exists():
                slot_path.touch()
            with slot_path.open("r+b") as handle:
                handle.seek(written)
                handle.write(chunk)
                handle.flush()
                os.fsync(handle.fileno())

            written += len(chunk)
            capsule["written"] = written
            self._state["slots"][capsule["slot"]]["written"] = written
            self._save_state()
            return self._stage_report(capsule, already_staged=False)

    def finish_stage(self, capsule_id: str) -> StageReport:
        with self._locked():
            capsule = self._get_capsule(capsule_id)
            if capsule.get("state") in ("staged", "committed"):
                return self._stage_report(capsule, already_staged=True)
            if capsule.get("state") != "writing":
                raise self._reject(ERR_STAGE_NOT_OPEN)

            written = int(capsule.get("written", 0))
            total = int(capsule.get("total", 0))
            if written < total:
                raise self._reject(ERR_STAGE_INCOMPLETE)
            if written > total:
                raise self._reject(ERR_STAGE_OVERFLOW)

            capsule["state"] = "staged"
            capsule["verified"] = False
            capsule["written"] = total
            slot = self._state["slots"][capsule["slot"]]
            slot.update({
                "state": "staged",
                "written": total,
                "version": capsule["version"],
                "digest": capsule["digest"],
            })
            self._state["stats"]["staged"] += 1
            self._save_state()
            return self._stage_report(capsule, already_staged=False)

    def stage(self, *, capsule_id: str, model: str, version: int,
              payload, key_id: str, signature: str) -> StageReport:
        with self._locked():
            payload = self._as_bytes(payload)
            if payload is None:
                raise self._reject(ERR_INVALID_REQUEST)
            report = self.begin_stage(
                capsule_id=capsule_id,
                model=model,
                version=version,
                payload=payload,
                key_id=key_id,
                signature=signature,
            )
            if report.already_staged:
                return report

            active_id = report.capsule_id
            for offset in range(report.written, len(payload), self.chunk_size):
                report = self.append_chunk(
                    active_id, payload[offset:offset + self.chunk_size]
                )
            return self.finish_stage(active_id)

    def verify(self, capsule_id: str) -> VerificationReport:
        with self._locked():
            capsule = self._get_capsule(capsule_id)
            valid, code, digest, bytes_checked = self._verify_capsule(capsule)
            self._save_state()
            return VerificationReport(
                capsule_id=capsule_id,
                valid=valid,
                code=code,
                digest=digest,
                bytes_checked=bytes_checked,
            )

    def commit(self, capsule_id=None) -> TransitionReport:
        with self._locked():
            capsule = None
            if capsule_id is None:
                staged = [
                    item for item in self._state["capsules"].values()
                    if item.get("state") == "staged"
                ]
                if staged:
                    capsule = max(
                        staged,
                        key=lambda item: (
                            int(item.get("version", 0)),
                            int(item.get("order", 0)),
                        ),
                    )
                elif any(
                    item.get("state") == "writing"
                    for item in self._state["capsules"].values()
                ):
                    raise self._reject(ERR_NOT_VERIFIED)
                else:
                    last_commit = self._state.get("last_commit")
                    if (last_commit and
                            last_commit.get("active") == self._state["active"]):
                        return TransitionReport(
                            active=last_commit["active"],
                            previous=last_commit["previous"],
                            version=int(last_commit["version"]),
                            idempotent=True,
                        )
                    raise self._reject(ERR_NOT_VERIFIED)
            else:
                capsule = self._get_capsule(capsule_id)

            if (capsule.get("state") == "committed" and
                    capsule.get("slot") == self._state["active"]):
                last_commit = self._state.get("last_commit") or {}
                previous = last_commit.get(
                    "previous", self._state.get("previous")
                )
                return TransitionReport(
                    active=self._state["active"],
                    previous=previous,
                    version=int(capsule["version"]),
                    idempotent=True,
                )

            if not capsule.get("verified"):
                raise self._reject(ERR_NOT_VERIFIED)

            valid, code, _, _ = self._verify_capsule(capsule, count=False)
            if not valid:
                self._save_state()
                raise self._reject(code)

            old_active = self._state["active"]
            target_slot = capsule["slot"]
            version = int(capsule["version"])

            capsule["state"] = "committed"
            capsule["verified"] = True
            self._state["active"] = target_slot
            self._state["previous"] = old_active
            self._state["rollback_slot"] = old_active
            self._state["last_rollback"] = None
            self._state["min_version"] = max(
                int(self._state["min_version"]), version
            )
            self._state["last_commit"] = {
                "capsule_id": capsule["capsule_id"],
                "active": target_slot,
                "previous": old_active,
                "version": version,
            }

            target = self._state["slots"][target_slot]
            target.update({
                "state": "active",
                "version": version,
                "digest": capsule["digest"],
                "written": capsule["written"],
                "total": capsule["total"],
                "capsule_id": capsule["capsule_id"],
            })
            if old_active != target_slot:
                self._state["slots"][old_active]["state"] = "previous"
            self._state["stats"]["committed"] += 1
            self._save_state()
            return TransitionReport(
                active=target_slot,
                previous=old_active,
                version=version,
                idempotent=False,
            )

    def rollback(self) -> TransitionReport:
        with self._locked():
            target_slot = self._state.get("rollback_slot")
            if target_slot is None:
                last_rollback = self._state.get("last_rollback")
                if last_rollback:
                    return TransitionReport(
                        active=last_rollback["active"],
                        previous=last_rollback["previous"],
                        version=int(last_rollback["version"]),
                        idempotent=True,
                    )
                raise self._reject(ERR_NO_ROLLBACK_TARGET)

            slot = self._state["slots"][target_slot]
            target_capsule = None
            target_capsule_id = slot.get("capsule_id")
            if target_capsule_id:
                target_capsule = self._state["capsules"].get(target_capsule_id)

            if target_capsule is not None and target_capsule.get("digest"):
                if not target_capsule.get("verified"):
                    raise self._reject(ERR_NOT_VERIFIED)
                valid, code, _, _ = self._verify_capsule(
                    target_capsule, count=False
                )
                if not valid:
                    self._save_state()
                    raise self._reject(code)

            old_active = self._state["active"]
            version = int(slot.get("version", 1) or 1)
            self._state["active"] = target_slot
            self._state["previous"] = old_active
            self._state["rollback_slot"] = None
            self._state["last_rollback"] = {
                "active": target_slot,
                "previous": old_active,
                "version": version,
            }
            self._state["slots"][target_slot]["state"] = "active"
            if old_active != target_slot:
                self._state["slots"][old_active]["state"] = "previous"
            self._state["stats"]["rolled_back"] += 1
            self._save_state()
            return TransitionReport(
                active=target_slot,
                previous=old_active,
                version=version,
                idempotent=False,
            )

    def resume(self) -> tuple:
        with self._locked():
            interrupted = [
                item for item in self._state["capsules"].values()
                if item.get("state") == "writing"
            ]
            interrupted.sort(key=lambda item: (
                int(item.get("order", 0)),
                item.get("capsule_id", ""),
            ))

            resumed = []
            for capsule in interrupted:
                capsule_id = capsule["capsule_id"]
                source_path = self.payload_dir / capsule.get("source", "")
                if not source_path.exists():
                    raise self._reject(ERR_STAGE_INCOMPLETE)
                payload = source_path.read_bytes()
                if hashlib.sha256(payload).hexdigest() != capsule.get("digest"):
                    raise self._reject(ERR_CHECKSUM_MISMATCH)

                for offset in range(
                        int(capsule.get("written", 0)),
                        len(payload),
                        self.chunk_size):
                    self.append_chunk(
                        capsule_id,
                        payload[offset:offset + self.chunk_size],
                    )

                valid, code, _, _ = self._verify_capsule(
                    capsule, count=False
                )
                if not valid:
                    self._save_state()
                    raise self._reject(code)

                total = int(capsule.get("total", 0))
                capsule["state"] = "staged"
                capsule["verified"] = True
                capsule["written"] = total
                slot = self._state["slots"][capsule["slot"]]
                slot.update({
                    "state": "staged",
                    "written": total,
                    "version": capsule["version"],
                    "digest": capsule["digest"],
                })
                self._state["stats"]["staged"] += 1
                self._state["stats"]["resumed"] += 1
                resumed.append(capsule_id)

            if resumed:
                self._save_state()
            return tuple(resumed)

    def capsules(self) -> list:
        with self._locked():
            items = sorted(
                self._state["capsules"].values(),
                key=lambda item: (
                    int(item.get("version", 0)),
                    int(item.get("order", 0)),
                    item.get("capsule_id", ""),
                ),
            )
            return [self._capsule_info(item) for item in items]

    def status(self) -> dict:
        with self._locked():
            slots = {}
            for slot in self._slots:
                record = self._state["slots"][slot]
                slots[slot] = {
                    "state": record.get("state", "free"),
                    "version": record.get("version"),
                    "digest": record.get("digest") or None,
                    "written": int(record.get("written", 0)),
                    "path": str(self._slot_path(slot)),
                }
            return {
                "model": self._state.get("model", self.model),
                "active": self._state["active"],
                "min_version": int(self._state["min_version"]),
                "slots": slots,
                "capsules": len(self._state["capsules"]),
            }

    def stats(self) -> dict:
        with self._locked():
            return {
                key: int(self._state["stats"].get(key, 0))
                for key in self._stats_keys
            }

    @contextmanager
    def _locked(self):
        with self._thread_lock:
            depth = int(getattr(self._lock_depth, "depth", 0))
            outer = depth == 0
            lock_fd = None
            if outer:
                lock_fd = os.open(str(self.lock_path),
                                  os.O_RDWR | os.O_CREAT, 0o600)
                try:
                    if fcntl is not None:
                        fcntl.flock(lock_fd, fcntl.LOCK_EX)
                    self._lock_depth.depth = 1
                    self._load_state()
                except BaseException:
                    self._lock_depth.depth = 0
                    os.close(lock_fd)
                    raise
            else:
                self._lock_depth.depth = depth + 1

            try:
                yield
            finally:
                self._lock_depth.depth = int(
                    getattr(self._lock_depth, "depth", 1)
                ) - 1
                if outer:
                    try:
                        if fcntl is not None and lock_fd is not None:
                            fcntl.flock(lock_fd, fcntl.LOCK_UN)
                    finally:
                        if lock_fd is not None:
                            os.close(lock_fd)

    def _default_state(self) -> dict:
        return {
            "schema_version": 1,
            "model": self.model,
            "active": "A",
            "previous": None,
            "rollback_slot": None,
            "last_commit": None,
            "last_rollback": None,
            "min_version": 1,
            "next_order": 0,
            "capsules": {},
            "version_index": {},
            "slots": {
                "A": {
                    "state": "active",
                    "version": 1,
                    "digest": None,
                    "written": 0,
                    "total": 0,
                    "capsule_id": None,
                },
                "B": {
                    "state": "free",
                    "version": None,
                    "digest": None,
                    "written": 0,
                    "total": 0,
                    "capsule_id": None,
                },
            },
            "stats": {key: 0 for key in self._stats_keys},
        }

    def _load_state(self) -> None:
        if not self.state_path.exists():
            self._state = self._default_state()
            self._save_state()
            return

        try:
            with self.state_path.open("r", encoding="utf-8") as handle:
                loaded = json.load(handle)
        except (OSError, json.JSONDecodeError) as exc:
            raise FirmwareStagerError(ERR_INVALID_REQUEST) from exc

        state = self._default_state()
        if isinstance(loaded, dict):
            state.update({
                key: value for key, value in loaded.items()
                if key not in ("slots", "stats", "capsules")
            })
            if isinstance(loaded.get("stats"), dict):
                state["stats"].update(loaded["stats"])
            if isinstance(loaded.get("slots"), dict):
                for slot in self._slots:
                    if isinstance(loaded["slots"].get(slot), dict):
                        state["slots"][slot].update(loaded["slots"][slot])
            if isinstance(loaded.get("capsules"), dict):
                state["capsules"] = loaded["capsules"]
        if not isinstance(state.get("version_index"), dict):
            state["version_index"] = {}
        for capsule in state["capsules"].values():
            if not isinstance(capsule, dict):
                continue
            model = capsule.get("model")
            version = capsule.get("version")
            digest = capsule.get("digest")
            if model and version is not None and digest:
                self._remember_version_digest(
                    model, int(version), str(digest), state=state
                )

        for key in self._stats_keys:
            try:
                state["stats"][key] = int(state["stats"].get(key, 0))
            except (TypeError, ValueError):
                state["stats"][key] = 0
        state["min_version"] = max(1, int(state.get("min_version", 1) or 1))
        if state.get("active") not in self._slots:
            state["active"] = "A"
        self._state = state
        self._reconcile_writing_files()

    def _save_state(self) -> None:
        fd, temporary_name = tempfile.mkstemp(
            prefix=".stager-state.",
            suffix=".tmp",
            dir=str(self.storage_dir),
        )
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(self._state, handle, sort_keys=True,
                          separators=(",", ":"))
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, self.state_path)
            self._fsync_directory(self.storage_dir)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise

    def _reconcile_writing_files(self) -> None:
        for capsule in self._state["capsules"].values():
            if capsule.get("state") != "writing":
                continue
            slot = capsule.get("slot")
            if slot not in self._slots:
                continue
            path = self._slot_path(slot)
            written = max(0, int(capsule.get("written", 0)))
            actual = path.stat().st_size if path.exists() else 0
            if actual < written:
                written = actual
                capsule["written"] = written
            elif actual > written:
                try:
                    with path.open("r+b") as handle:
                        handle.truncate(written)
                        handle.flush()
                        os.fsync(handle.fileno())
                except OSError:
                    pass
            self._state["slots"][slot]["written"] = written

    def _atomic_write_bytes(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        fd, temporary_name = tempfile.mkstemp(
            prefix=f".{path.name}.",
            suffix=".tmp",
            dir=str(path.parent),
        )
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary_name, path)
            self._fsync_directory(path.parent)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except OSError:
                pass
            raise

    @staticmethod
    def _fsync_directory(directory: Path) -> None:
        try:
            descriptor = os.open(str(directory), os.O_RDONLY)
        except OSError:
            return
        try:
            os.fsync(descriptor)
        except OSError:
            pass
        finally:
            os.close(descriptor)

    def _slot_path(self, slot: str) -> Path:
        return self.slot_dir / f"{slot}.bin"

    @staticmethod
    def _as_bytes(value):
        if isinstance(value, bytes):
            return value
        if isinstance(value, (bytearray, memoryview)):
            return bytes(value)
        return None

    def _signature_matches(self, model: str, version: int, digest: str,
                           secret, signature) -> bool:
        secret_bytes = self._secret_material(secret)
        if secret_bytes is None:
            return False
        body = f"{model}:{version}:{digest}".encode("utf-8")
        expected = hmac.new(
            secret_bytes, body, hashlib.sha256
        ).hexdigest().encode("ascii")
        if isinstance(signature, str):
            provided = signature.strip().lower().encode(
                "ascii", errors="ignore"
            )
        elif isinstance(signature, bytes):
            provided = signature.strip().lower()
        else:
            return False
        return hmac.compare_digest(expected, provided)

    @staticmethod
    def _secret_material(secret):
        if isinstance(secret, str):
            return secret.encode("utf-8")
        try:
            return bytes(secret)
        except (TypeError, ValueError):
            return None

    def _reject(self, code: str) -> FirmwareStagerError:
        self._state["stats"]["rejected"] += 1
        self._save_state()
        return FirmwareStagerError(code)

    def _get_capsule(self, capsule_id: str) -> dict:
        capsule = self._state["capsules"].get(capsule_id)
        if capsule is None:
            raise self._reject(ERR_NO_CAPSULE)
        return capsule

    def _known_version_digest(self, model: str, version: int, *,
                              state: dict | None = None):
        state = state or self._state
        index = state.get("version_index", {})
        by_model = index.get(model)
        if not isinstance(by_model, dict):
            return None
        digest = by_model.get(str(version))
        return str(digest) if digest else None

    def _remember_version_digest(self, model: str, version: int, digest: str,
                                 *, state: dict | None = None) -> None:
        state = state or self._state
        index = state.setdefault("version_index", {})
        by_model = index.setdefault(model, {})
        if isinstance(by_model, dict):
            by_model.setdefault(str(version), digest)

    def _allocate_slot(self) -> str:
        active = self._state["active"]
        for slot in self._slots:
            if slot == active:
                continue
            occupied = any(
                capsule.get("slot") == slot and
                capsule.get("state") in ("writing", "staged")
                for capsule in self._state["capsules"].values()
            )
            if not occupied:
                return slot
        raise self._reject(ERR_NO_FREE_SLOT)

    def _ensure_source_payload(self, capsule: dict, payload: bytes) -> None:
        source = capsule.get("source")
        if not source:
            source_name = (
                "payload-"
                + hashlib.sha256(
                    capsule["capsule_id"].encode("utf-8")
                ).hexdigest()
                + ".bin"
            )
            capsule["source"] = source_name
        source_path = self.payload_dir / capsule["source"]
        if not source_path.exists():
            self._atomic_write_bytes(source_path, payload)

    def _hash_slot(self, slot: str):
        path = self._slot_path(slot)
        digest = hashlib.sha256()
        checked = 0
        try:
            with path.open("rb") as handle:
                while True:
                    block = handle.read(max(65536, self.chunk_size))
                    if not block:
                        break
                    digest.update(block)
                    checked += len(block)
        except OSError:
            return "", checked
        return digest.hexdigest(), checked

    def _verify_capsule(self, capsule: dict, *, count: bool = True):
        actual_digest, bytes_checked = self._hash_slot(capsule["slot"])
        total = int(capsule.get("total", 0))
        valid = (
            bytes_checked == total and
            bool(actual_digest) and
            hmac.compare_digest(
                actual_digest, str(capsule.get("digest", ""))
            )
        )
        if valid:
            capsule["verified"] = True
            if count:
                self._state["stats"]["verified"] += 1
            return True, VERIFICATION_OK, actual_digest, bytes_checked

        capsule["verified"] = False
        return False, ERR_CHECKSUM_MISMATCH, actual_digest, bytes_checked

    def _stage_report(self, capsule: dict, *,
                      already_staged: bool | None = None):
        if already_staged is None:
            already_staged = capsule.get("state") in ("staged", "committed")
        return StageReport(
            capsule_id=capsule["capsule_id"],
            slot=capsule["slot"],
            state=capsule["state"],
            written=int(capsule.get("written", 0)),
            total=int(capsule.get("total", 0)),
            digest=str(capsule.get("digest", "")),
            already_staged=bool(already_staged),
        )

    def _capsule_info(self, capsule: dict) -> CapsuleInfo:
        return CapsuleInfo(
            capsule_id=capsule["capsule_id"],
            version=int(capsule["version"]),
            slot=capsule["slot"],
            path=str(self._slot_path(capsule["slot"])),
            state=capsule["state"],
            written=int(capsule.get("written", 0)),
            verified=bool(capsule.get("verified", False)),
            digest=str(capsule.get("digest", "")),
        )
