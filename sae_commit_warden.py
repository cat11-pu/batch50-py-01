"""SAE commit/confirm pairing, anti-clogging tokens and PMF association gate."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SaeError(ValueError):
    """Raised when an SAE operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CommitOutcome:
    status: str
    mac: str
    handshake_id: int
    token_consumed: bool


@dataclass(frozen=True)
class ConfirmOutcome:
    status: str
    mac: str
    handshake_id: int


@dataclass(frozen=True)
class AssocDecision:
    mac: str
    allowed: bool
    protected: bool
    reason: str


class SaeCommitWarden:
    """Track SAE handshakes per peer MAC and gate association on PMF."""

    def __init__(self, *, commit_threshold: int = 3, token_ttl: int = 30,
                 handshake_ttl: int = 120, max_pending: int = 256,
                 transition_mode: bool = False) -> None:
        self.commit_threshold = commit_threshold
        self.token_ttl = token_ttl
        self.handshake_ttl = handshake_ttl
        self.max_pending = max_pending
        self.transition_mode = transition_mode
        self._lock = threading.RLock()
        self._peers: dict = {}
        self._tokens: dict = {}
        self._counters: dict = {}

    def on_commit(self, mac: str, scalar, token=None, now=None) -> CommitOutcome:
        raise NotImplementedError

    def on_confirm(self, mac: str, send_confirm, now=None) -> ConfirmOutcome:
        raise NotImplementedError

    def issue_token(self, mac: str, now=None) -> str:
        raise NotImplementedError

    def authorize_assoc(self, mac: str, *, pmf_negotiated: bool,
                        wpa2_client: bool = False) -> AssocDecision:
        raise NotImplementedError

    def handshake_state(self, mac: str) -> str:
        raise NotImplementedError

    def purge_expired(self, now=None) -> int:
        raise NotImplementedError

    def pending_peers(self) -> tuple:
        raise NotImplementedError

    def close_association(self, mac: str) -> bool:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
