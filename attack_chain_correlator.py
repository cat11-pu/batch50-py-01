"""Attack chain correlator: keyed aggregation, watermark, reorder window, stale close."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class ChainError(ValueError):
    """Raised when a correlator operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STAGES = (
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "exfiltration",
    "impact",
)

STATE_OPEN = "open"
STATE_CLOSED = "closed"


@dataclass(frozen=True)
class Chain:
    chain_id: str
    src: str
    dst: str
    stage: str
    stages: tuple
    events: int
    state: str
    isolated: bool
    opened_at: str
    last_event_at: str
    closed_at: str | None
    close_reason: str | None


class AttackChainCorrelator:
    """Correlate stage-tagged events into chains keyed by source and target."""

    def __init__(self, *, reorder_window: int = 120,
                 silence_timeout: int = 600) -> None:
        self.reorder_window = reorder_window
        self.silence_timeout = silence_timeout
        self._lock = threading.RLock()
        self._chains: dict[str, dict] = {}
        self._events: dict[str, str] = {}
        self._watermark: str | None = None
        self._stats = {
            "ingested": 0,
            "opened": 0,
            "isolated": 0,
            "closed": 0,
        }

    def ingest(self, event_id: str, *, src: str, dst: str, stage: str,
               ts: str) -> dict:
        raise NotImplementedError

    def advance_watermark(self, *, ts: str) -> str:
        raise NotImplementedError

    def watermark(self) -> str | None:
        raise NotImplementedError

    def close_stale(self, *, now: str) -> tuple:
        raise NotImplementedError

    def close_chain(self, chain_id: str, *, reason: str, now: str) -> Chain:
        raise NotImplementedError

    def chain_of(self, chain_id: str) -> Chain:
        raise NotImplementedError

    def chains(self, *, state: str | None = None) -> list:
        raise NotImplementedError

    def chain_for_event(self, event_id: str) -> str:
        raise NotImplementedError

    def stages(self) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
