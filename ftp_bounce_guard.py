"""FTP control channel bounce protection for active and passive transfers."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class FtpGuardError(ValueError):
    """Raised when a data connection request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Reply:
    code: int
    text: str


@dataclass(frozen=True)
class DataTarget:
    ip: str
    port: int
    mode: str
    mapped: bool


class FtpBounceGuard:
    """Track one FTP control session and police data connection targets."""

    def __init__(self, *, control_peer: str, pasv_port_range=(40000, 40100),
                 active_peer_port: int = 20, max_line: int = 512,
                 users=None, pasv_advertised_ip: str = "192.168.10.20") -> None:
        self.control_peer = control_peer
        self.pasv_port_range = tuple(pasv_port_range)
        self.active_peer_port = active_peer_port
        self.max_line = max_line
        self.users = dict(users or {"ftpuser": "s3cret"})
        self.pasv_advertised_ip = pasv_advertised_ip
        self._lock = threading.RLock()

    def authenticate(self, user: str, password: str) -> bool:
        raise NotImplementedError

    def feed(self, chunk) -> list[Reply]:
        raise NotImplementedError

    def on_command(self, line: str) -> Reply:
        raise NotImplementedError

    def authorize_data(self, peer_ip: str, peer_port: int) -> DataTarget:
        raise NotImplementedError

    def rewrite_pasv(self, advertised_ip: str, port: int) -> tuple[str, int]:
        raise NotImplementedError

    def pending_data(self) -> DataTarget | None:
        raise NotImplementedError

    def release_data(self) -> bool:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError
