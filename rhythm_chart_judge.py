"""Rhythm chart judge: timing windows, holds and calibration offset.

The judge holds one chart, converts raw input timestamps with the player
calibration offset and grades taps and holds into perfect, great or miss
while tracking combo and accuracy.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "RhythmError",
    "NoteState",
    "RhythmChartJudge",
]


class RhythmError(ValueError):
    """Raised when a chart or input operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class NoteState:
    """Judgement state of one chart note."""

    note_id: str
    status: str
    judgement: str | None
    delta_ms: int | None


class RhythmChartJudge:
    """Grade chart notes against timestamped press and release input."""

    def __init__(self, *, perfect_ms: int = 40, great_ms: int = 80) -> None:
        self.perfect_ms = perfect_ms
        self.great_ms = great_ms
        self._lock = threading.RLock()

    def load_chart(self, notes) -> dict:
        """Load the note list in chart order."""
        raise NotImplementedError

    def calibrate(self, offset_ms: int) -> dict:
        """Apply the player timing offset used for every later input."""
        raise NotImplementedError

    def press(self, time_ms: int, lane: int) -> dict:
        """Grade a press against the earliest matching pending note."""
        raise NotImplementedError

    def release(self, time_ms: int, lane: int) -> dict:
        """Grade the tail of a hold currently being held in *lane*."""
        raise NotImplementedError

    def tick(self, time_ms: int) -> tuple[str, ...]:
        """Miss every note whose window has passed at *time_ms*."""
        raise NotImplementedError

    def pause(self) -> None:
        """Freeze judgement until :meth:`resume`."""
        raise NotImplementedError

    def resume(self) -> None:
        """Leave the paused state."""
        raise NotImplementedError

    def judge(self, note_id: str) -> NoteState:
        """Return the judgement state of one note."""
        raise NotImplementedError

    def combo(self) -> int:
        """Return the current combo."""
        raise NotImplementedError

    def max_combo(self) -> int:
        """Return the highest combo reached in this run."""
        raise NotImplementedError

    def accuracy(self) -> float:
        """Return the weighted accuracy in percent."""
        raise NotImplementedError

    def results(self) -> dict:
        """Return per-grade counts plus combo and note totals."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached copy of chart, states, combo and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Load a snapshot after validating its structure."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative counters for input and ticks."""
        raise NotImplementedError
