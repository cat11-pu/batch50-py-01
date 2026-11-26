"""Diameter peer lifecycle, capability exchange and credit-control reservation guard."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class DiameterError(ValueError):
    """Raised when a peer, session or credit-control operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PeerRecord:
    peer: str
    origin_host: str
    state: str
    applications: tuple[str, ...]
    opened_at: str


@dataclass(frozen=True)
class CapabilityReport:
    peer: str
    state: str
    granted: tuple[str, ...]
    rejected: tuple[str, ...]


@dataclass(frozen=True)
class CcrTicket:
    session_id: str
    hop_by_hop: str
    end_to_end: str
    peer: str
    requested: int
    reserved: int
    state: str


@dataclass(frozen=True)
class Settlement:
    session_id: str
    peer: str
    state: str
    requested: int
    used: int
    returned: int


class DiameterPeerGuard:
    """Track peers, applications, credit-control sessions and reservations."""

    def __init__(self, *, max_peers: int = 8, max_applications: int = 6,
                 max_sessions: int = 32, dedup_window: int = 128,
                 max_retransmit: int = 3, clock=None) -> None:
        self.max_peers = max_peers
        self.max_applications = max_applications
        self.max_sessions = max_sessions
        self.dedup_window = dedup_window
        self.max_retransmit = max_retransmit
        self._clock = clock
        self._lock = threading.RLock()

    def open_peer(self, peer: str, *, origin_host: str, now: str | None = None) -> PeerRecord:
        raise NotImplementedError

    def exchange_capabilities(self, peer: str, *, offered, wanted,
                              now: str | None = None) -> CapabilityReport:
        raise NotImplementedError

    def peer_state(self, peer: str) -> str:
        raise NotImplementedError

    def routes(self, application: str) -> tuple[str, ...]:
        raise NotImplementedError

    def send_ccr(self, session_id: str, *, subscriber: str, peer: str,
                 requested: int, hop_by_hop: str | None = None,
                 end_to_end: str | None = None,
                 now: str | None = None) -> CcrTicket:
        raise NotImplementedError

    def handle_answer(self, session_id: str, *, hop_by_hop: str, result: str,
                      granted: int = 0, now: str | None = None) -> Settlement:
        raise NotImplementedError

    def reclaim(self, session_id: str, *, now: str | None = None) -> Settlement:
        raise NotImplementedError

    def close_peer(self, peer: str, *, now: str | None = None) -> PeerRecord:
        raise NotImplementedError

    def session_status(self, session_id: str) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
