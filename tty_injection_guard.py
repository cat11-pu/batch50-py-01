"""Pseudo-terminal guard: ioctl admission, escape-sequence filtering, segmented recording."""

from __future__ import annotations

import threading
from dataclasses import dataclass


TIOCSTI = 0x5412
TIOCLINUX = 0x541C

IOCTL_ALLOWED = "IOCTL_ALLOWED"
IOCTL_BLOCKED_TIOCSTI = "IOCTL_BLOCKED_TIOCSTI"
IOCTL_BLOCKED_TIOCLINUX = "IOCTL_BLOCKED_TIOCLINUX"

ERR_INVALID_CHUNK = "TTY_INVALID_CHUNK"
ERR_INVALID_ARGUMENT = "TTY_INVALID_ARGUMENT"
ERR_SESSION_REQUIRED = "TTY_SESSION_REQUIRED"
ERR_SESSION_CLOSED = "TTY_SESSION_CLOSED"
ERR_ALREADY_RECORDING = "TTY_ALREADY_RECORDING"
ERR_SEGMENT_TOO_LARGE = "TTY_SEGMENT_TOO_LARGE"
ERR_RULE_INVALID = "TTY_RULE_INVALID"


class TtyGuardError(ValueError):
    """Raised when a tty operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class IoctlVerdict:
    """Outcome of one ioctl request seen on a tty."""

    allowed: bool
    code: str
    request: int


@dataclass(frozen=True)
class OutputVerdict:
    """Outcome of filtering one output chunk."""

    emitted: str
    pending: str
    blocked: tuple


@dataclass(frozen=True)
class SegmentInfo:
    """Metadata of one recording segment."""

    tty: str
    session: str
    seq: int
    path: str
    status: str
    bytes_written: int
    sha256: object


class TtyInjectionGuard:
    """Guard ioctl calls, sanitize terminal output and record sessions by segment."""

    def __init__(self, record_dir, *, max_segment_bytes: int = 1048576,
                 blocked_osc=(52,), blocked_private_modes=("?25",)) -> None:
        self.record_dir = str(record_dir)
        self.max_segment_bytes = int(max_segment_bytes)
        self._blocked_osc = tuple(blocked_osc)
        self._blocked_private_modes = tuple(blocked_private_modes)
        self._lock = threading.RLock()

    def on_ioctl(self, tty_id: str, request: int, arg=None) -> IoctlVerdict:
        raise NotImplementedError

    def open_session(self, tty_id: str, session_id: str) -> None:
        raise NotImplementedError

    def filter_output(self, tty_id: str, chunk: str) -> OutputVerdict:
        raise NotImplementedError

    def record(self, tty_id: str, data) -> SegmentInfo:
        raise NotImplementedError

    def flush(self, tty_id: str):
        raise NotImplementedError

    def close(self, tty_id: str):
        raise NotImplementedError

    def update_rules(self, *, blocked_osc=None, blocked_private_modes=None) -> None:
        raise NotImplementedError

    def recover(self) -> int:
        raise NotImplementedError

    def segments(self, tty_id: str) -> list:
        raise NotImplementedError

    def status(self, tty_id: str) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
