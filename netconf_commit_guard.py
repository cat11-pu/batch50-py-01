"""Confirmed-commit guard: rollback timer, one-shot persist-id and datastore locks."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class NetconfError(ValueError):
    """Raised when a confirmed-commit operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CommitTicket:
    commit_id: int
    datastore: str
    session_id: str
    version: int
    expires_at: int
    persist_id: object


class ConfirmedCommitGuard:
    """Serialise unconfirmed commits per datastore and own their rollback timers."""

    def __init__(self, *, default_timeout: int = 60) -> None:
        self.default_timeout = default_timeout
        self._lock = threading.RLock()
        self._stores: dict = {}
        self._pendings: dict = {}
        self._locks: dict = {}
        self._next_commit_id = 1
        self._counters: dict = {}

    def commit(self, session_id: str, candidate: dict, *,
               datastore: str = "running", timeout=None,
               persist_id=None, now=None) -> CommitTicket:
        raise NotImplementedError

    def confirm(self, session_id: str, *, datastore: str = "running",
                commit_id=None, persist_id=None, now=None) -> int:
        raise NotImplementedError

    def rollback(self, session_id=None, *, datastore: str = "running",
                 commit_id=None, now=None) -> int:
        raise NotImplementedError

    def persist(self, session_id: str, *, datastore: str = "running",
                persist_id=None) -> str:
        raise NotImplementedError

    def adopt(self, session_id: str, persist_id: str, *,
              datastore: str = "running") -> CommitTicket:
        raise NotImplementedError

    def lock_datastore(self, session_id: str, datastore: str = "running") -> None:
        raise NotImplementedError

    def unlock_datastore(self, session_id: str, datastore: str = "running") -> None:
        raise NotImplementedError

    def close_session(self, session_id: str, *, now=None) -> int:
        raise NotImplementedError

    def expire(self, now) -> int:
        raise NotImplementedError

    def pending_for(self, datastore: str = "running"):
        raise NotImplementedError

    def version_for(self, datastore: str = "running") -> int:
        raise NotImplementedError

    def config_for(self, datastore: str = "running") -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
