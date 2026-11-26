"""Local account database transactions: fixed lock order, atomic replacement, NSS cache."""

from __future__ import annotations

import threading
from dataclasses import dataclass

FILES = ("passwd", "shadow", "group", "gshadow")
LOCK_ORDER = ("passwd", "shadow", "group", "gshadow")
RESERVED_IDS = (0, 1, 2, 65534)
KINDS = ("add_user", "delete_user", "add_group", "join_group", "set_shell")


class AccountDbError(ValueError):
    """Raised when an account database transaction is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AccountChange:
    kind: str
    name: str
    fields: dict


@dataclass(frozen=True)
class ChangePlan:
    plan_id: str
    changes: tuple[AccountChange, ...]
    files: tuple[str, ...]
    lock_order: tuple[str, ...]
    version: int


@dataclass(frozen=True)
class CommitResult:
    plan_id: str
    files_written: tuple[str, ...]
    cache_invalidated: int
    version: int
    committed_at: str


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    duplicate_uids: tuple[str, ...]
    dangling_gids: tuple[str, ...]
    duplicate_names: tuple[str, ...]


class AccountDbTransaction:
    """Apply batched changes to the four local account database files."""

    def __init__(self, *, uid_floor: int = 1000, uid_ceiling: int = 60000,
                 gid_floor: int = 1000, gid_ceiling: int = 60000) -> None:
        self.uid_floor = uid_floor
        self.uid_ceiling = uid_ceiling
        self.gid_floor = gid_floor
        self.gid_ceiling = gid_ceiling
        self._lock = threading.RLock()
        self._files = {name: "" for name in FILES}
        self._versions = {name: 1 for name in FILES}
        self._plans: dict[str, dict] = {}
        self._version = 0
        self._journal: list[dict] = []
        self._counters = {
            "plans": 0, "commits": 0, "rollbacks": 0,
            "cache_invalidations": 0, "recovered": 0,
        }

    def load(self, files: dict) -> dict:
        raise NotImplementedError

    def files(self) -> dict:
        raise NotImplementedError

    def users(self) -> list[dict]:
        raise NotImplementedError

    def groups(self) -> list[dict]:
        raise NotImplementedError

    def allocate_uid(self, name: str) -> int:
        raise NotImplementedError

    def allocate_gid(self, name: str) -> int:
        raise NotImplementedError

    def plan(self, changes) -> ChangePlan:
        raise NotImplementedError

    def apply(self, plan_id: str, *, now: str) -> CommitResult:
        raise NotImplementedError

    def rollback(self, plan_id: str, *, now: str) -> int:
        raise NotImplementedError

    def recover(self, *, now: str) -> dict:
        raise NotImplementedError

    def verify(self) -> VerifyReport:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
