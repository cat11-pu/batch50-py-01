"""Domination point scoring: signed capture meter, locks, mercy gap and overtime."""

from __future__ import annotations

import threading


class DominationError(ValueError):
    """Raised when a scoreboard operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class DominationScoreboard:
    """Track point control, settle scores, mercy gap and overtime for one round."""

    def __init__(self, *, teams=("red", "blue"), mercy_gap: int = 200,
                 tick_points: int = 10, round_seconds: int = 120,
                 overtime_seconds: int = 30, lock_ticks: int = 3) -> None:
        self.teams = tuple(teams)
        self.mercy_gap = mercy_gap
        self.tick_points = tick_points
        self.round_seconds = round_seconds
        self.overtime_seconds = overtime_seconds
        self.lock_ticks = lock_ticks
        self._lock = threading.RLock()

    def register_point(self, point_id: str) -> dict:
        raise NotImplementedError

    def point_state(self, point_id: str) -> dict:
        raise NotImplementedError

    def capture_tick(self, point_id: str, team: str, amount: int) -> dict:
        raise NotImplementedError

    def settle(self, seconds: int = 1) -> dict:
        raise NotImplementedError

    def score_of(self, team: str) -> int:
        raise NotImplementedError

    def points_held(self, team: str) -> int:
        raise NotImplementedError

    def overtime(self) -> dict:
        raise NotImplementedError

    def mercy_check(self) -> dict:
        raise NotImplementedError

    def finalize(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
