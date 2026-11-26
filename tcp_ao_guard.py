"""TCP-AO guard: per-connection key chains, segment MACs and sequence windows."""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "TcpAoError",
    "KeyEntry",
    "ConnectionBinding",
    "SignedSegment",
    "SegmentResult",
    "TcpAoGuard",
]


class TcpAoError(ValueError):
    """Raised when a key-chain or segment operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class KeyEntry:
    chain_id: str
    key_id: str
    generation: int
    fingerprint: str
    send: bool
    recv: bool
    created_at: str
    retired_at: str | None


@dataclass(frozen=True)
class ConnectionBinding:
    conn_id: str
    chain_id: str
    peer: str
    src_port: int
    dst_port: int
    bound_at: str
    rebinds: int


@dataclass(frozen=True)
class SignedSegment:
    conn_id: str
    seq: int
    key_id: str
    mac: str


@dataclass(frozen=True)
class SegmentResult:
    conn_id: str
    seq: int
    accepted: bool
    reason: str
    key_id: str | None
    window_floor: int


class TcpAoGuard:
    """Govern TCP-AO key chains and per-connection segment verification."""

    def __init__(self, *, max_chains: int = 8, max_keys_per_chain: int = 8,
                 max_connections: int = 64, window_size: int = 64) -> None:
        self.max_chains = max_chains
        self.max_keys_per_chain = max_keys_per_chain
        self.max_connections = max_connections
        self.window_size = window_size
        self._lock = threading.RLock()

    def install_key(self, chain_id: str, key_id: str, secret: str, *,
                    send: bool = True, recv: bool = True,
                    now: str | None = None) -> KeyEntry:
        raise NotImplementedError

    def remove_key(self, chain_id: str, key_id: str, now: str | None = None) -> bool:
        raise NotImplementedError

    def key_chain(self, chain_id: str) -> tuple[KeyEntry, ...]:
        raise NotImplementedError

    def bind_connection(self, conn_id: str, chain_id: str, peer: str,
                        src_port: int, dst_port: int,
                        now: str | None = None) -> ConnectionBinding:
        raise NotImplementedError

    def rebind_connection(self, conn_id: str, src_port: int, dst_port: int,
                          now: str | None = None) -> ConnectionBinding:
        raise NotImplementedError

    def unbind_connection(self, conn_id: str) -> bool:
        raise NotImplementedError

    def sign_segment(self, conn_id: str, seq: int, payload: bytes,
                     key_id: str | None = None) -> SignedSegment:
        raise NotImplementedError

    def verify_segment(self, conn_id: str, seq: int, payload: bytes,
                       mac: str) -> SegmentResult:
        raise NotImplementedError

    def rollover(self, chain_id: str, key_id: str,
                 now: str | None = None) -> KeyEntry:
        raise NotImplementedError

    def status(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
