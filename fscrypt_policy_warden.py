"""Directory encryption policy governance: inheritance, key slots, locking and rotation."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

MODES = ("aes128-cts", "aes256-cts", "aes256-xts")
MODE_RANK = {name: rank for rank, name in enumerate(MODES, start=1)}


class FscryptError(ValueError):
    """Raised when an encryption policy operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PolicyRecord:
    path: str
    policy_id: str
    mode: str
    key_desc: str
    key_state: str = "locked"
    rotation_state: str = "idle"
    rotation_pending: int = 0
    rotation_total: int = 0


class FscryptPolicyWarden:
    """Own per-directory policies, the volume keyring and rotation progress."""

    def __init__(self, *, volume: str = "v1", max_policies: int = 16,
                 key_slots: int = 6, clock=None) -> None:
        self.volume = volume
        self.max_policies = max_policies
        self.key_slots = key_slots
        self._clock = clock
        self._lock = threading.Lock()

    def mkdir(self, path: str) -> None:
        raise NotImplementedError

    def register_file(self, path: str, name: str, size: int = 4096) -> int:
        raise NotImplementedError

    def set_policy(self, path: str, *, mode: str, key_desc: str,
                   policy_id: str | None = None,
                   recursive: bool = False) -> PolicyRecord:
        raise NotImplementedError

    def unlock(self, path: str, key_desc: str) -> int:
        raise NotImplementedError

    def lock(self, path: str) -> int:
        raise NotImplementedError

    def read_file(self, path: str, name: str) -> str:
        raise NotImplementedError

    def write_file(self, path: str, name: str, data: str = "") -> str:
        raise NotImplementedError

    def file_key(self, path: str, name: str) -> str:
        raise NotImplementedError

    def rotate(self, path: str, new_key_desc: str, *,
               interrupt_after: int | None = None) -> dict:
        raise NotImplementedError

    def resume_rotation(self, path: str) -> dict:
        raise NotImplementedError

    def add_key(self, key_desc: str, *, policy_id: str) -> int:
        raise NotImplementedError

    def drop_key(self, key_desc: str, *, policy_id: str) -> int:
        raise NotImplementedError

    def keys(self) -> tuple:
        raise NotImplementedError

    def policies(self) -> list:
        raise NotImplementedError

    def status(self, path: str) -> dict:
        raise NotImplementedError

    def rename(self, old: str, new: str) -> PolicyRecord:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
