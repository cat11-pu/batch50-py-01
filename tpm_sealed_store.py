"""TPM sealed data store: PCR policy binding, lockout accounting, bounded object table."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

DIGEST_LEN = 64
PCR_LIMIT = 24


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


class TpmSealedStore:
    """Keep sealed objects, their PCR expectations and lockout state in memory."""

    def __init__(self, *, max_objects: int = 16, max_failures: int = 3,
                 lock_seconds: int = 60, clock=None) -> None:
        self.max_objects = max_objects
        self.max_failures = max_failures
        self.lock_seconds = lock_seconds
        self._clock = clock
        self._lock = threading.Lock()

    def seal(self, name: str, data: str, *, pcr_indexes, expected,
             policy: str | None = None, now: str | None = None) -> SealedRecord:
        raise NotImplementedError

    def unseal(self, name: str, *, pcr_values, now: str | None = None) -> str:
        raise NotImplementedError

    def reseal(self, name: str, *, pcr_indexes=None, expected=None,
               policy: str | None = None, now: str | None = None) -> SealedRecord:
        raise NotImplementedError

    def evict(self, name: str) -> None:
        raise NotImplementedError

    def hold(self, name: str) -> int:
        raise NotImplementedError

    def release(self, name: str) -> int:
        raise NotImplementedError

    def pcr_extend(self, index: int, digest: str, *,
                   now: str | None = None) -> tuple:
        raise NotImplementedError

    def pcr_bank(self) -> dict:
        raise NotImplementedError

    def status(self, name: str) -> dict:
        raise NotImplementedError

    def objects(self) -> list:
        raise NotImplementedError

    def lock_state(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
