"""Rank ladder promotion series.

Manages a player rank ladder: promotion to the next rank is earned through a
series with a win quota, a remaining match budget and an expiry timestamp;
protection charges absorb one demotion before the rank actually drops.  Match
reports are idempotent per match id and a season reset clears series state
while keeping the recorded history.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "RankError",
    "SeriesRecord",
    "RankLadderSeries",
]


class RankError(ValueError):
    """Raised when a rank ladder operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SeriesRecord:
    """State of one promotion series."""

    player_id: str
    current_rank: str
    target_rank: str
    wins: int
    losses: int
    matches_left: int
    status: str
    started_at: int
    expires_at: int


class RankLadderSeries:
    """Run promotion series, protection charges and demotion decisions."""

    def __init__(self, *, ranks: tuple[str, ...], wins_needed: int = 2,
                 losses_allowed: int = 2, series_timeout: int = 3600,
                 protection_charges: int = 1) -> None:
        self.ranks = ranks
        self.wins_needed = wins_needed
        self.losses_allowed = losses_allowed
        self.series_timeout = series_timeout
        self.protection_charges = protection_charges
        self._lock = threading.RLock()

    def register_player(self, player_id: str, *,
                        rank_index: int = 0) -> dict:
        """Add a player to the ladder at *rank_index*."""
        raise NotImplementedError

    def start_series(self, player_id: str, *,
                     now: int | None = None) -> SeriesRecord:
        """Open a promotion series towards the next rank."""
        raise NotImplementedError

    def report_match(self, player_id: str, *, match_id: str, result: str,
                     now: int | None = None) -> SeriesRecord:
        """Record one series match, idempotent per *match_id*."""
        raise NotImplementedError

    def promote(self, player_id: str, *, now: int | None = None) -> dict:
        """Promote a player whose series is complete."""
        raise NotImplementedError

    def demote(self, player_id: str, *, now: int | None = None) -> dict:
        """Apply a demotion, spending a protection charge when one is left."""
        raise NotImplementedError

    def series_of(self, player_id: str) -> SeriesRecord | None:
        """Return the active series of a player, or ``None``."""
        raise NotImplementedError

    def expire_series(self, player_id: str, *,
                      now: int | None = None) -> SeriesRecord | None:
        """Expire a series that ran past its timeout."""
        raise NotImplementedError

    def standings(self, player_id: str) -> dict:
        """Return rank, counters, series state and history of a player."""
        raise NotImplementedError

    def reset_season(self, *, now: int | None = None) -> int:
        """Clear series state for everyone while keeping recorded history."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a deep copy of players, series and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace ladder state with a snapshot, validating its structure."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative counters for matches, promotions and demotions."""
        raise NotImplementedError
