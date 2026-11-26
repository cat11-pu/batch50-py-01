"""Password pepper version ledger.

Keeps tenant level pepper versions and the version / salt / parameters of every
stored password record: verification accepts the current and the previous
version, a successful login lazily rehashes an old record, and a leaked version
can be disabled outright.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "PepperError",
    "PasswordRecord",
    "VerifyResult",
    "PasswordPepperLedger",
]


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


class PasswordPepperLedger:
    """Track pepper versions, password records and the lazy rehash queue."""

    def __init__(self, *, iterations: int = 60000, max_pending: int = 64,
                 salt_bytes: int = 16) -> None:
        self.iterations = iterations
        self.max_pending = max_pending
        self.salt_bytes = salt_bytes
        self._lock = threading.RLock()

    def register_version(self, version: int, *, pepper: str,
                         now: str | None = None) -> int:
        raise NotImplementedError

    def current_version(self) -> int:
        raise NotImplementedError

    def version_enabled(self, version: int) -> bool:
        raise NotImplementedError

    def hash_record(self, account_id: str, password: str, *,
                    now: str | None = None) -> PasswordRecord:
        raise NotImplementedError

    def verify(self, account_id: str, password: str, *,
               now: str | None = None) -> VerifyResult:
        raise NotImplementedError

    def rehash_pending(self, *, limit: int | None = None,
                       now: str | None = None) -> int:
        raise NotImplementedError

    def disable_version(self, version: int, *, now: str | None = None) -> int:
        raise NotImplementedError

    def force_reset_required(self, account_id: str) -> bool:
        raise NotImplementedError

    def pending_count(self) -> int:
        raise NotImplementedError

    def record_for(self, account_id: str) -> PasswordRecord | None:
        raise NotImplementedError

    def records(self) -> list[PasswordRecord]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
