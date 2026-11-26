"""Weiqi rule arbiter: liberties, captures, ko history and dual clocks.

The arbiter owns one board, validates every move against turn order,
suicide and repeated-position rules, records what each move captured and
keeps two independent clocks (main time plus byo-yomi periods) for the
referee console.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "WeiqiError",
    "MoveRecord",
    "WeiqiRuleArbiter",
]


class WeiqiError(ValueError):
    """Raised when a move or clock operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class MoveRecord:
    """One move as written into the game record."""

    move_no: int
    color: str
    kind: str
    coord: tuple[int, int] | None
    captured: tuple[tuple[int, int], ...]
    position_hash: str


class WeiqiRuleArbiter:
    """Arbitrate a single game: board, captures, ko history and clocks."""

    def __init__(self, *, size: int = 9, komi: float = 6.5,
                 main_time: int = 300, byo_yomi: int = 30,
                 byo_yomi_periods: int = 3) -> None:
        self.size = size
        self.komi = komi
        self.main_time = main_time
        self.byo_yomi = byo_yomi
        self.byo_yomi_periods = byo_yomi_periods
        self._lock = threading.RLock()

    def place_stone(self, color: str, coord: tuple[int, int]) -> MoveRecord:
        """Play one stone, capturing enemy groups left without liberties."""
        raise NotImplementedError

    def pass_turn(self, color: str) -> MoveRecord:
        """Pass; two consecutive passes end the game."""
        raise NotImplementedError

    def resign(self, color: str) -> dict:
        """Resign the game, returning the final result summary."""
        raise NotImplementedError

    def undo_request(self, color: str) -> dict:
        """Withdraw the most recent move on behalf of its owner."""
        raise NotImplementedError

    def tick_clock(self, color: str, seconds: int) -> dict:
        """Charge *seconds* to one side's clock."""
        raise NotImplementedError

    def pause_clock(self, color: str) -> dict:
        """Freeze one side's clock, leaving the other running."""
        raise NotImplementedError

    def resume_clock(self, color: str) -> dict:
        """Release a pause previously taken on one side's clock."""
        raise NotImplementedError

    def clock_state(self, color: str | None = None) -> dict:
        """Report remaining main time and byo-yomi state."""
        raise NotImplementedError

    def score(self) -> dict:
        """Area-score the current position (stones plus surrounded points)."""
        raise NotImplementedError

    def stone_at(self, coord: tuple[int, int]) -> str | None:
        """Return the colour on *coord*, or ``None`` when empty."""
        raise NotImplementedError

    def captures_of(self, color: str) -> int:
        """Return how many stones *color* has captured so far."""
        raise NotImplementedError

    def stones_of(self, color: str) -> tuple[tuple[int, int], ...]:
        """Return the sorted coordinates occupied by *color*."""
        raise NotImplementedError

    def move_log(self) -> tuple[MoveRecord, ...]:
        """Return every move in the order it was played."""
        raise NotImplementedError

    def position_hash(self) -> str:
        """Return a stable digest of the current board position."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached copy of the board, history, clocks and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Load a snapshot after validating its structure."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative counters for moves, captures and refusals."""
        raise NotImplementedError
