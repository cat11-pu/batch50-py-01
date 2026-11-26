"""Anonymous identity upgrade: resource migration, conflict merge and rollback."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class AnonymousBindError(ValueError):
    """Raised when an anonymous identity operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AnonSession:
    anon_id: str
    device_id: str
    state: str
    created_at: str
    resource_count: int


@dataclass(frozen=True)
class BindResult:
    bind_id: str
    anon_id: str
    account_id: str
    status: str
    migrated: int
    added: int
    conflicts: int
    overwritten: int
    bound_at: str


class AnonymousIdentityBinder:
    """Carry an anonymous session's resources into a real account."""

    def __init__(self, *, conflict_policy: str = "account_wins",
                 max_resources_per_anon: int = 64) -> None:
        self.conflict_policy = conflict_policy
        self.max_resources_per_anon = max_resources_per_anon
        self._lock = threading.RLock()

    def create_anon(self, *, device_id: str,
                    now: str | None = None) -> AnonSession:
        raise NotImplementedError

    def attach_resource(self, anon_id: str, *, kind: str, key: str,
                        value: str, now: str | None = None) -> dict:
        raise NotImplementedError

    def detach_resource(self, anon_id: str, *, kind: str, key: str) -> bool:
        raise NotImplementedError

    def merge_state(self, anon_id: str, *, account_id: str,
                    now: str | None = None) -> dict:
        raise NotImplementedError

    def bind_to_account(self, anon_id: str, *, account_id: str,
                        now: str | None = None) -> BindResult:
        raise NotImplementedError

    def rollback(self, account_id: str, *, now: str | None = None) -> dict:
        raise NotImplementedError

    def freeze_account(self, account_id: str) -> None:
        raise NotImplementedError

    def status(self, anon_id: str) -> dict:
        raise NotImplementedError

    def anon_resources(self, anon_id: str) -> list[dict]:
        raise NotImplementedError

    def account_resources(self, account_id: str) -> list[dict]:
        raise NotImplementedError

    def list_anonymous(self) -> list[str]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
