"""PTP domain candidate tracking and best master clock selection."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class PtpError(ValueError):
    """Raised when a PTP message or snapshot is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class MasterInfo:
    domain: int
    clock_identity: str
    priority1: int
    clock_class: int
    clock_accuracy: int
    variance: int
    priority2: int
    steps_removed: int
    source_port: str
    sequence: int


class PtpDomainWarden:
    """Maintain PTP domain ports and elect the best master clock."""

    def __init__(self, *, domain: int = 0, announce_timeout: float = 3.0,
                 max_foreign: int = 16) -> None:
        self.domain = domain
        self.announce_timeout = announce_timeout
        self.max_foreign = max_foreign
        self._lock = threading.RLock()

    def on_announce(self, message: dict, *, now: float) -> bool:
        raise NotImplementedError

    def on_sync(self, message: dict, *, now: float) -> bool:
        raise NotImplementedError

    def tick(self, now: float) -> list[str]:
        raise NotImplementedError

    def elected(self) -> MasterInfo | None:
        raise NotImplementedError

    def state(self) -> str:
        raise NotImplementedError

    def time_trusted(self, *, now: float | None = None) -> bool:
        raise NotImplementedError

    def foreign_records(self) -> tuple[MasterInfo, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def close(self) -> None:
        raise NotImplementedError
