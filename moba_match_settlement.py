"""MOBA match settlement: MVP scoring, streak bonuses, AFK flags and idempotency.

One report describes a finished match: per-player combat lines, the winning side
and the match mode.  Settlement computes an integer performance score for every
player, picks the MVP from the winning side, awards rating points with a capped
win-streak bonus and keeps per-player history for the leaderboard.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "MobaError",
    "PlayerLine",
    "SettlementResult",
    "PlayerSummary",
    "MobaMatchSettlement",
]


class MobaError(ValueError):
    """Raised when a settlement operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PlayerLine:
    """One player's combat line in a finished match."""

    player_id: str
    team: str
    kills: int
    deaths: int
    assists: int
    damage_dealt: int
    damage_taken: int
    vision_score: int
    active_ratio: float


@dataclass(frozen=True)
class SettlementResult:
    """Immutable outcome of one match report."""

    match_id: str
    mode: str
    winner: str | None
    mvp: str | None
    duration: int
    scores: dict
    rating_delta: dict
    streak_bonus: dict
    afk: tuple


@dataclass(frozen=True)
class PlayerSummary:
    """Immutable per-player ladder record."""

    player_id: str
    rating: int
    matches: int
    wins: int
    losses: int
    streak: int
    best_streak: int
    mvp_count: int


class MobaMatchSettlement:
    """Settle MOBA matches into ratings, win streaks and an MVP pick."""

    def __init__(self, *, win_points: int = 20, loss_points: int = 12,
                 mvp_bonus: int = 30, streak_step: int = 5,
                 streak_cap: int = 5, afk_ratio: float = 0.3,
                 max_players: int = 10) -> None:
        self.win_points = win_points
        self.loss_points = loss_points
        self.mvp_bonus = mvp_bonus
        self.streak_step = streak_step
        self.streak_cap = streak_cap
        self.afk_ratio = afk_ratio
        self.max_players = max_players
        self._lock = threading.RLock()

    def mvp_score(self, line: PlayerLine) -> int:
        raise NotImplementedError

    def report_match(self, match_id: str, *, duration: int, players,
                     winner, mode: str = "normal", now: int = 0) -> SettlementResult:
        raise NotImplementedError

    def settlement(self, match_id: str) -> SettlementResult:
        raise NotImplementedError

    def player_summary(self, player_id: str) -> PlayerSummary:
        raise NotImplementedError

    def leaderboard(self, *, limit: int | None = None) -> tuple[PlayerSummary, ...]:
        raise NotImplementedError

    def afk_players(self, match_id: str) -> tuple[str, ...]:
        raise NotImplementedError

    def mvp_of(self, match_id: str) -> str | None:
        raise NotImplementedError

    def streak_bonus(self, player_id: str) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
