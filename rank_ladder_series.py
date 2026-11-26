"""Rank ladder promotion series.

Manages a player rank ladder: promotion to the next rank is earned through a
series with a win quota, a remaining match budget and an expiry timestamp;
protection charges absorb one demotion before the rank actually drops.  Match
reports are idempotent per match id and a season reset clears series state
while keeping the recorded history.
"""

from __future__ import annotations

import copy
import threading
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Any

__all__ = [
    "RankError",
    "SeriesRecord",
    "RankLadderSeries",
]

_MAX_HISTORY_ENTRIES = 1024
_MAX_SEEN_MATCHES = 16384
_SERIES_STATUSES = frozenset({"active", "won", "lost", "expired"})
_COUNTER_NAMES = (
    "series_started",
    "matches_reported",
    "wins",
    "losses",
    "duplicates",
    "promotions",
    "demotions",
    "expired",
    "season_resets",
    "protection_used",
)


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


@dataclass
class _SeriesState:
    player_id: str
    current_rank: str
    target_rank: str
    wins: int
    losses: int
    matches_left: int
    status: str
    started_at: int
    expires_at: int


@dataclass
class _PlayerState:
    player_id: str
    rank_index: int
    protection_charges: int
    promotions: int = 0
    demotions: int = 0
    matches_played: int = 0
    series: _SeriesState | None = None
    history: deque[dict[str, object]] = field(
        default_factory=lambda: deque(maxlen=_MAX_HISTORY_ENTRIES)
    )
    seen_matches: deque[str] = field(default_factory=deque)
    seen_match_ids: set[str] = field(default_factory=set)


class RankLadderSeries:
    """Run promotion series, protection charges and demotion decisions."""

    def __init__(self, *, ranks: tuple[str, ...], wins_needed: int = 2,
                 losses_allowed: int = 2, series_timeout: int = 3600,
                 protection_charges: int = 1) -> None:
        if isinstance(ranks, (str, bytes)):
            raise RankError("RANK_INVALID_CONFIG", "ranks must be a sequence")
        try:
            ranks_tuple = tuple(ranks)
        except TypeError as exc:
            raise RankError("RANK_INVALID_CONFIG", "ranks must be a sequence") from exc
        if (len(ranks_tuple) < 2
                or any(not isinstance(rank, str) or not rank
                       for rank in ranks_tuple)
                or len(set(ranks_tuple)) != len(ranks_tuple)):
            raise RankError("RANK_INVALID_CONFIG", "ranks must contain at least two distinct names")
        if not _is_int(wins_needed) or wins_needed <= 0:
            raise RankError("RANK_INVALID_CONFIG", "wins_needed must be positive")
        if not _is_int(losses_allowed) or losses_allowed <= 0:
            raise RankError("RANK_INVALID_CONFIG", "losses_allowed must be positive")
        if not _is_int(series_timeout) or series_timeout <= 0:
            raise RankError("RANK_INVALID_CONFIG", "series_timeout must be positive")
        if not _is_int(protection_charges) or protection_charges < 0:
            raise RankError("RANK_INVALID_CONFIG", "protection_charges cannot be negative")

        self.ranks = ranks_tuple
        self.wins_needed = wins_needed
        self.losses_allowed = losses_allowed
        self.series_timeout = series_timeout
        self.protection_charges = protection_charges
        self._lock = threading.RLock()
        self._players: dict[str, _PlayerState] = {}
        self._counters = {name: 0 for name in _COUNTER_NAMES}

    def register_player(self, player_id: str, *,
                        rank_index: int = 0) -> dict:
        """Add a player to the ladder at *rank_index*."""
        if not isinstance(player_id, str) or not player_id:
            raise RankError("RANK_INVALID_REQUEST", "player_id must be a non-empty string")
        with self._lock:
            if player_id in self._players:
                raise RankError("RANK_DUPLICATE_PLAYER", player_id)
            if (not _is_int(rank_index)
                    or rank_index < 0
                    or rank_index >= len(self.ranks)):
                raise RankError("RANK_INVALID_REQUEST", rank_index)
            player = _PlayerState(
                player_id=player_id,
                rank_index=rank_index,
                protection_charges=self.protection_charges,
            )
            self._players[player_id] = player
            return self._standing(player)

    def start_series(self, player_id: str, *,
                     now: int | None = None) -> SeriesRecord:
        """Open a promotion series towards the next rank."""
        timestamp = _timestamp(now)
        with self._lock:
            player = self._require_player(player_id)
            if player.rank_index >= len(self.ranks) - 1:
                raise RankError("RANK_TOP_RANK", self.ranks[player.rank_index])

            series = player.series
            if series is not None and series.status == "active":
                if timestamp >= series.expires_at:
                    self._expire_active(player, series)
                    series = player.series
                else:
                    raise RankError("RANK_SERIES_ACTIVE", player_id)

            if series is not None and series.status == "won":
                raise RankError("RANK_SERIES_ACTIVE", player_id)
            if series is not None:
                player.series = None

            current_rank = self.ranks[player.rank_index]
            new_series = _SeriesState(
                player_id=player_id,
                current_rank=current_rank,
                target_rank=self.ranks[player.rank_index + 1],
                wins=0,
                losses=0,
                matches_left=self.wins_needed + self.losses_allowed,
                status="active",
                started_at=timestamp,
                expires_at=timestamp + self.series_timeout,
            )
            player.series = new_series
            self._counters["series_started"] += 1
            return self._series_record(new_series)

    def report_match(self, player_id: str, *, match_id: str, result: str,
                     now: int | None = None) -> SeriesRecord:
        """Record one series match, idempotent per *match_id*."""
        timestamp = _timestamp(now)
        if not isinstance(match_id, str) or not match_id:
            raise RankError("RANK_INVALID_REQUEST", "match_id must be a non-empty string")
        if result not in {"win", "loss"}:
            raise RankError("RANK_INVALID_REQUEST", result)

        with self._lock:
            player = self._require_player(player_id)
            if match_id in player.seen_match_ids:
                self._counters["duplicates"] += 1
                raise RankError("RANK_DUPLICATE_MATCH", match_id)

            series = player.series
            if series is None:
                raise RankError("RANK_NO_SERIES", player_id)
            if series.status == "active" and timestamp >= series.expires_at:
                self._expire_active(player, series)
            if series.status != "active":
                raise RankError("RANK_SERIES_CLOSED", series.status)

            if result == "win":
                series.wins += 1
                self._counters["wins"] += 1
            else:
                series.losses += 1
                self._counters["losses"] += 1

            player.matches_played += 1
            self._counters["matches_reported"] += 1
            series.matches_left = max(
                0,
                self.wins_needed + self.losses_allowed
                - series.wins - series.losses,
            )

            if series.wins >= self.wins_needed:
                series.status = "won"
                self._append_series_history(player, series, "won")
            elif series.losses >= self.losses_allowed:
                series.status = "lost"
                self._append_series_history(player, series, "lost")

            self._remember_match(player, match_id)
            return self._series_record(series)

    def promote(self, player_id: str, *, now: int | None = None) -> dict:
        """Promote a player whose series is complete."""
        _timestamp(now)
        with self._lock:
            player = self._require_player(player_id)
            series = player.series
            if series is None or series.status != "won":
                raise RankError("RANK_NOT_ELIGIBLE", player_id)
            if player.rank_index >= len(self.ranks) - 1:
                raise RankError("RANK_TOP_RANK", self.ranks[player.rank_index])

            player.rank_index += 1
            player.promotions += 1
            self._counters["promotions"] += 1
            player.series = None
            self._append_history(
                player,
                {"kind": "promoted", "rank": self.ranks[player.rank_index]},
            )
            return self._standing(player)

    def demote(self, player_id: str, *, now: int | None = None) -> dict:
        """Apply a demotion, spending a protection charge when one is left."""
        _timestamp(now)
        with self._lock:
            player = self._require_player(player_id)
            if player.rank_index == 0:
                raise RankError("RANK_BOTTOM_RANK", self.ranks[0])

            if player.protection_charges > 0:
                player.protection_charges -= 1
                self._counters["protection_used"] += 1
                return self._standing(player)

            player.rank_index -= 1
            player.demotions += 1
            self._counters["demotions"] += 1
            self._append_history(
                player,
                {"kind": "demoted", "rank": self.ranks[player.rank_index]},
            )
            return self._standing(player)

    def series_of(self, player_id: str) -> SeriesRecord | None:
        """Return the active series of a player, or ``None``."""
        with self._lock:
            player = self._require_player(player_id)
            if player.series is None:
                return None
            return self._series_record(player.series)

    def expire_series(self, player_id: str, *,
                      now: int | None = None) -> SeriesRecord | None:
        """Expire a series that ran past its timeout."""
        timestamp = _timestamp(now)
        with self._lock:
            player = self._require_player(player_id)
            series = player.series
            if series is None:
                raise RankError("RANK_NO_SERIES", player_id)
            if series.status == "active" and timestamp >= series.expires_at:
                self._expire_active(player, series)
            return self._series_record(series)

    def standings(self, player_id: str) -> dict:
        """Return rank, counters, series state and history of a player."""
        with self._lock:
            return self._standing(self._require_player(player_id))

    def reset_season(self, *, now: int | None = None) -> int:
        """Clear series state for everyone while keeping recorded history."""
        _timestamp(now)
        with self._lock:
            cleared = 0
            for player in self._players.values():
                series = player.series
                if series is None:
                    continue
                cleared += 1
                if series.status == "active":
                    self._append_series_history(player, series, "reset")
                player.series = None
            self._counters["season_resets"] += 1
            return cleared

    def snapshot(self) -> dict:
        """Return a deep copy of players, series and counters."""
        with self._lock:
            players: dict[str, dict[str, Any]] = {}
            series_by_player: dict[str, dict[str, Any]] = {}
            for player_id, player in self._players.items():
                players[player_id] = {
                    "player_id": player.player_id,
                    "rank_index": player.rank_index,
                    "protection_charges": player.protection_charges,
                    "promotions": player.promotions,
                    "demotions": player.demotions,
                    "matches_played": player.matches_played,
                    "history": [copy.deepcopy(entry) for entry in player.history],
                    "seen_matches": list(player.seen_matches),
                }
                if player.series is not None:
                    series_by_player[player_id] = self._series_dict(player.series)
            return {
                "players": players,
                "series": series_by_player,
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        """Replace ladder state with a snapshot, validating its structure."""
        with self._lock:
            try:
                players, series_by_player, counters = self._parse_snapshot(state)
            except RankError as exc:
                raise RankError("RANK_SNAPSHOT_INVALID", exc.detail) from exc
            except Exception as exc:
                raise RankError("RANK_SNAPSHOT_INVALID", str(exc)) from exc
            self._players = players
            self._counters = counters

    def stats(self) -> dict:
        """Return cumulative counters for matches, promotions and demotions."""
        with self._lock:
            result = {"players": len(self._players)}
            result.update(self._counters)
            return result

    def _require_player(self, player_id: str) -> _PlayerState:
        if not isinstance(player_id, str) or not player_id:
            raise RankError("RANK_INVALID_REQUEST", "player_id must be a non-empty string")
        player = self._players.get(player_id)
        if player is None:
            raise RankError("RANK_UNKNOWN_PLAYER", player_id)
        return player

    def _series_record(self, series: _SeriesState) -> SeriesRecord:
        return SeriesRecord(
            player_id=series.player_id,
            current_rank=series.current_rank,
            target_rank=series.target_rank,
            wins=series.wins,
            losses=series.losses,
            matches_left=series.matches_left,
            status=series.status,
            started_at=series.started_at,
            expires_at=series.expires_at,
        )

    def _series_dict(self, series: _SeriesState) -> dict[str, Any]:
        return {
            "player_id": series.player_id,
            "current_rank": series.current_rank,
            "target_rank": series.target_rank,
            "wins": series.wins,
            "losses": series.losses,
            "matches_left": series.matches_left,
            "status": series.status,
            "started_at": series.started_at,
            "expires_at": series.expires_at,
        }

    def _standing(self, player: _PlayerState) -> dict:
        return {
            "player_id": player.player_id,
            "rank": self.ranks[player.rank_index],
            "rank_index": player.rank_index,
            "protection_charges": player.protection_charges,
            "promotions": player.promotions,
            "demotions": player.demotions,
            "matches_played": player.matches_played,
            "series": (
                None if player.series is None
                else self._series_dict(player.series)
            ),
            "history": tuple(copy.deepcopy(entry) for entry in player.history),
        }

    def _expire_active(self, player: _PlayerState,
                       series: _SeriesState) -> None:
        series.status = "expired"
        self._append_series_history(player, series, "expired")
        series.wins = 0
        self._counters["expired"] += 1

    def _append_series_history(self, player: _PlayerState,
                               series: _SeriesState, result: str) -> None:
        self._append_history(
            player,
            {
                "kind": "series",
                "result": result,
                "wins": series.wins,
                "losses": series.losses,
                "rank": series.current_rank,
            },
        )

    @staticmethod
    def _append_history(player: _PlayerState,
                        entry: dict[str, object]) -> None:
        player.history.append(entry)

    @staticmethod
    def _remember_match(player: _PlayerState, match_id: str) -> None:
        player.seen_matches.append(match_id)
        player.seen_match_ids.add(match_id)
        while len(player.seen_matches) > _MAX_SEEN_MATCHES:
            old_match_id = player.seen_matches.popleft()
            player.seen_match_ids.discard(old_match_id)

    def _parse_snapshot(
        self, state: dict,
    ) -> tuple[dict[str, _PlayerState], dict[str, _SeriesState],
               dict[str, int]]:
        if not isinstance(state, dict):
            raise RankError("RANK_SNAPSHOT_INVALID", "state must be a dict")
        players_data = state.get("players")
        series_data = state.get("series")
        counters_data = state.get("counters")
        if not isinstance(players_data, dict):
            raise RankError("RANK_SNAPSHOT_INVALID", "players must be a dict")
        if not isinstance(series_data, dict):
            raise RankError("RANK_SNAPSHOT_INVALID", "series must be a dict")
        if not isinstance(counters_data, dict):
            raise RankError("RANK_SNAPSHOT_INVALID", "counters must be a dict")

        players: dict[str, _PlayerState] = {}
        for player_id, payload in players_data.items():
            if not isinstance(player_id, str) or not player_id:
                raise RankError("RANK_SNAPSHOT_INVALID", "invalid player id")
            if not isinstance(payload, dict):
                raise RankError("RANK_SNAPSHOT_INVALID", player_id)
            if payload.get("player_id") != player_id:
                raise RankError("RANK_SNAPSHOT_INVALID", player_id)

            rank_index = payload.get("rank_index")
            if (not _is_int(rank_index)
                    or rank_index < 0
                    or rank_index >= len(self.ranks)):
                raise RankError("RANK_SNAPSHOT_INVALID", "rank_index")
            protection_charges = _snapshot_count(
                payload, "protection_charges"
            )
            promotions = _snapshot_count(payload, "promotions")
            demotions = _snapshot_count(payload, "demotions")
            matches_played = _snapshot_count(payload, "matches_played")

            history_data = payload.get("history")
            if not isinstance(history_data, (list, tuple)):
                raise RankError("RANK_SNAPSHOT_INVALID", "history")
            history: deque[dict[str, object]] = deque(maxlen=_MAX_HISTORY_ENTRIES)
            for entry in history_data:
                if not isinstance(entry, dict):
                    raise RankError("RANK_SNAPSHOT_INVALID", "history entry")
                if not isinstance(entry.get("kind"), str):
                    raise RankError("RANK_SNAPSHOT_INVALID", "history kind")
                history.append(copy.deepcopy(entry))

            seen_data = payload.get("seen_matches")
            if not isinstance(seen_data, (list, tuple)):
                raise RankError("RANK_SNAPSHOT_INVALID", "seen_matches")
            seen_matches: deque[str] = deque()
            seen_match_ids: set[str] = set()
            for match_id in seen_data:
                if not isinstance(match_id, str) or not match_id:
                    raise RankError("RANK_SNAPSHOT_INVALID", "seen match id")
                if match_id in seen_match_ids:
                    continue
                seen_matches.append(match_id)
                seen_match_ids.add(match_id)
                while len(seen_matches) > _MAX_SEEN_MATCHES:
                    old_match_id = seen_matches.popleft()
                    seen_match_ids.discard(old_match_id)

            players[player_id] = _PlayerState(
                player_id=player_id,
                rank_index=rank_index,
                protection_charges=protection_charges,
                promotions=promotions,
                demotions=demotions,
                matches_played=matches_played,
                history=history,
                seen_matches=seen_matches,
                seen_match_ids=seen_match_ids,
            )

        series_by_player: dict[str, _SeriesState] = {}
        for player_id, payload in series_data.items():
            if player_id not in players or not isinstance(payload, dict):
                raise RankError("RANK_SNAPSHOT_INVALID", player_id)
            if payload.get("player_id") != player_id:
                raise RankError("RANK_SNAPSHOT_INVALID", player_id)

            current_rank = payload.get("current_rank")
            target_rank = payload.get("target_rank")
            if current_rank not in self.ranks or target_rank not in self.ranks:
                raise RankError("RANK_SNAPSHOT_INVALID", "series rank")
            status = payload.get("status")
            if status not in _SERIES_STATUSES:
                raise RankError("RANK_SNAPSHOT_INVALID", "series status")
            wins = _snapshot_count(payload, "wins")
            losses = _snapshot_count(payload, "losses")
            matches_left = _snapshot_count(payload, "matches_left")
            started_at = _snapshot_int(payload, "started_at")
            expires_at = _snapshot_int(payload, "expires_at")
            total_matches = self.wins_needed + self.losses_allowed
            if status == "active":
                if (wins >= self.wins_needed
                        or losses >= self.losses_allowed
                        or matches_left != total_matches - wins - losses):
                    raise RankError("RANK_SNAPSHOT_INVALID", "series counters")

            series = _SeriesState(
                player_id=player_id,
                current_rank=current_rank,
                target_rank=target_rank,
                wins=wins,
                losses=losses,
                matches_left=matches_left,
                status=status,
                started_at=started_at,
                expires_at=expires_at,
            )
            series_by_player[player_id] = series
            players[player_id].series = series

        counters: dict[str, int] = {}
        for name in _COUNTER_NAMES:
            counters[name] = _snapshot_count(counters_data, name)
        return players, series_by_player, counters


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _timestamp(now: int | None) -> int:
    if now is None:
        return int(time.time())
    if not _is_int(now):
        raise RankError("RANK_INVALID_REQUEST", "now must be an integer")
    return now


def _snapshot_count(payload: dict, name: str) -> int:
    value = payload.get(name)
    if not _is_int(value) or value < 0:
        raise RankError("RANK_SNAPSHOT_INVALID", name)
    return value


def _snapshot_int(payload: dict, name: str) -> int:
    value = payload.get(name)
    if not _is_int(value):
        raise RankError("RANK_SNAPSHOT_INVALID", name)
    return value
