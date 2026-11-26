"""Bind SDP fingerprint attributes to DTLS certificate material per media section."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass


class SrtpError(ValueError):
    """Raised when SDP binding or certificate verification is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class MediaSection:
    mid: str
    media: str
    port: int
    protocol: str
    fingerprint_algorithm: str | None
    fingerprint_value: str | None
    setup: str | None


@dataclass(frozen=True)
class Binding:
    mid: str
    algorithm: str
    fingerprint: str
    role: str
    context_id: int
    verified: bool


class SrtpFingerprintBinder:
    """Track one DTLS-SRTP fingerprint binding per negotiated media section."""

    def __init__(self, *, allowed_algorithms=("sha-256", "sha-384", "sha-512"),
                 max_bindings: int = 16) -> None:
        self.allowed_algorithms = tuple(allowed_algorithms)
        self.max_bindings = max_bindings
        self._lock = threading.RLock()

    def parse_sdp(self, sdp: str) -> tuple[MediaSection, ...]:
        raise NotImplementedError

    def bind_offer(self, sdp: str) -> dict[str, Binding]:
        raise NotImplementedError

    def accept_answer(self, sdp: str) -> dict[str, Binding]:
        raise NotImplementedError

    def verify_peer(self, mid: str, cert_der: bytes) -> bool:
        raise NotImplementedError

    def renegotiate(self, sdp: str) -> dict:
        raise NotImplementedError

    def key_material(self, mid: str) -> bytes:
        raise NotImplementedError

    def release(self, mid: str) -> bool:
        raise NotImplementedError

    def bindings(self) -> tuple[Binding, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError
