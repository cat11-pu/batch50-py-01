"""Time trial ledger: checkpoint order, splits, ghosts and leaderboard.

One active run at a time per ledger records the checkpoint it expects
next, the cumulative time at each checkpoint and a sampling of the ghost
recording.  Finished laps are submitted with their checkpoint mask and the
leaderboard keeps only the fastest legal lap per player and track.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "TrialError",
    "LapRecord",
    "TimeTrialLedger",
]


class TrialError(ValueError):
    """Raised when a run or submission is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class LapRecord:
    """One finished lap as stored by the ledger."""

    lap_id: str
    player: str
    track_id: str
    total_ms: int
    splits_ms: tuple[int, ...]
    checkpoint_mask: int
    valid: bool
    finished_seq: int


class TimeTrialLedger:
    """Validate checkpoint order and keep the ghost and leaderboard data."""

    def __init__(self, *, checkpoint_count: int = 8, max_samples: int = 64,
                 max_laps_per_player: int = 5) -> None:
        self.checkpoint_count = checkpoint_count
        self.max_samples = max_samples
        self.max_laps_per_player = max_laps_per_player
        self._lock = threading.RLock()

    def start_run(self, player: str, *, track_id: str = "default",
                  start_ms: int = 0) -> dict:
        """Open a new run for *player* on *track_id*."""
        raise NotImplementedError

    def checkpoint(self, index: int, *, at_ms: int) -> dict:
        """Record passing checkpoint *index* at *at_ms*."""
        raise NotImplementedError

    def finish_run(self, *, at_ms: int) -> LapRecord:
        """Close the active run and return the finished lap."""
        raise NotImplementedError

    def validate(self, lap_id: str) -> dict:
        """Report whether a stored lap is legal."""
        raise NotImplementedError

    def submit(self, lap) -> dict:
        """Submit a lap to the leaderboard of its track."""
        raise NotImplementedError

    def ghost_samples(self, lap_id: str,
                      *, max_samples: int | None = None) -> tuple[tuple[int, int], ...]:
        """Return the compressed ghost samples of a stored lap."""
        raise NotImplementedError

    def leaderboard(self, *, track_id: str | None = None,
                    limit: int = 10) -> tuple[dict, ...]:
        """Return the fastest legal laps of a track."""
        raise NotImplementedError

    def elapsed_ms(self) -> int:
        """Return the running time of the active run."""
        raise NotImplementedError

    def checkpoint_mask(self) -> int:
        """Return the checkpoint bitmask of the active run."""
        raise NotImplementedError

    def current_run(self) -> dict | None:
        """Return a description of the active run, or ``None``."""
        raise NotImplementedError

    def best_of(self, player: str) -> dict | None:
        """Return the fastest submitted lap of *player*."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached copy of the active run, laps and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Load a snapshot after validating its structure."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative counters for runs, laps and submissions."""
        raise NotImplementedError
