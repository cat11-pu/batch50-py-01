"""Session bus policy broker: connection credentials, name ownership, message filtering."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class DbusPolicyError(ValueError):
    """Raised when a bus policy operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


SOURCES = ("system", "site")
SUBJECT_KINDS = ("user", "group")
MESSAGE_TYPES = ("method_call", "signal", "any")
VERDICTS = ("allow", "deny")


@dataclass(frozen=True)
class Connection:
    conn_id: str
    unique_name: str
    uid: int
    pid: int
    groups: tuple[str, ...]


@dataclass(frozen=True)
class PolicyRule:
    source: str
    subject: str
    subject_kind: str
    target: str
    message_type: str
    verdict: str


@dataclass(frozen=True)
class Verdict:
    allowed: bool
    reason: str
    source: str | None


@dataclass(frozen=True)
class NameRecord:
    name: str
    owner: str | None
    queue: tuple[str, ...]


@dataclass(frozen=True)
class PendingCall:
    conn_id: str
    seq: int
    target: str
    method: str
    started_at: str
    policy_version: int


class DbusPolicyBroker:
    """Authorize bus messages, hand out well known names and track pending calls."""

    def __init__(self, *, max_connections: int = 64, max_names: int = 256,
                 call_timeout: int = 30) -> None:
        self.max_connections = max_connections
        self.max_names = max_names
        self.call_timeout = call_timeout
        self._lock = threading.RLock()
        self._connections: dict[str, Connection] = {}
        self._next_unique = 1
        self._rules: list[PolicyRule] = []
        self._version = 0
        self._names: dict[str, dict] = {}
        self._pending: dict[tuple[str, int], PendingCall] = {}
        self._counters = {
            "expired": 0, "deduplicated": 0, "denied": 0,
            "sent": 0, "received": 0,
        }

    def add_connection(self, conn_id: str, *, uid: int, pid: int, groups=(),
                       now: str) -> Connection:
        raise NotImplementedError

    def remove_connection(self, conn_id: str, *, now: str) -> dict:
        raise NotImplementedError

    def load_policy(self, rules, *, now: str) -> int:
        raise NotImplementedError

    def evaluate_send(self, conn_id: str, *, target: str,
                      message_type: str = "method_call", eavesdrop: bool = False,
                      now: str) -> Verdict:
        raise NotImplementedError

    def evaluate_receive(self, conn_id: str, *, sender: str,
                         message_type: str = "method_call",
                         eavesdrop: bool = False, now: str) -> Verdict:
        raise NotImplementedError

    def request_name(self, conn_id: str, name: str, *, now: str) -> str:
        raise NotImplementedError

    def release_name(self, conn_id: str, name: str, *, now: str) -> int:
        raise NotImplementedError

    def names(self) -> list[NameRecord]:
        raise NotImplementedError

    def record_call(self, conn_id: str, *, seq: int, target: str, method: str,
                    now: str) -> PendingCall:
        raise NotImplementedError

    def expire_calls(self, *, now: str) -> list[dict]:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
