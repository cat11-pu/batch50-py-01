"""MOBA match settlement: MVP scoring, streak bonuses, AFK flags and idempotency.

One report describes a finished match: per-player combat lines, the winning side
and the match mode.  Settlement computes an integer performance score for every
player, picks the MVP from the winning side, awards rating points with a capped
win-streak bonus and keeps per-player history for the leaderboard.
"""

from __future__ import annotations

import copy
import math
import threading
from dataclasses import dataclass

__all__ = [
    "MobaError",
    "PlayerLine",
    "SettlementResult",
    "PlayerSummary",
    "MobaMatchSettlement",
]


SNAPSHOT_VERSION = 1
TEAMS = ("blue", "red")
MODES = ("normal", "remake")
STAT_KEYS = (
    "matches",
    "players",
    "mvps",
    "afk_flags",
    "top_streak",
    "rating_awards",
    "streak_awards",
    "refused_reports",
)
PLAYER_SNAPSHOT_KEYS = (
    "player_id",
    "rating",
    "matches",
    "wins",
    "losses",
    "streak",
    "best_streak",
    "mvp_count",
    "streak_bonus",
)
MATCH_SNAPSHOT_KEYS = (
    "match_id",
    "mode",
    "winner",
    "duration",
    "now",
    "seq",
    "mvp",
    "scores",
    "rating_delta",
    "streak_bonus",
    "afk",
)
NON_NEGATIVE_LINE_FIELDS = (
    "kills",
    "deaths",
    "assists",
    "damage_dealt",
    "damage_taken",
    "vision_score",
)


class MobaError(ValueError):
    """Raised when a settlement operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _next_report_seq(counters: dict, matches: dict) -> int:
    current = counters.get("report_seq", len(matches))
    if not _is_integer(current) or current < 0:
        current = len(matches)
    return max(int(current), len(matches)) + 1


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
        self._players: dict[str, dict] = {}
        self._matches: dict[str, dict] = {}
        self._counters = {"report_seq": 0}
        self._stats = {key: 0 for key in STAT_KEYS}

    @staticmethod
    def _invalid_request(detail: object = None) -> MobaError:
        return MobaError("MATCH_INVALID_REQUEST", detail)

    @staticmethod
    def _unknown(detail: object = None) -> MobaError:
        return MobaError("MATCH_UNKNOWN", detail)

    @staticmethod
    def _invalid_snapshot(detail: object = None) -> MobaError:
        return MobaError("MATCH_SNAPSHOT_INVALID", detail)

    @staticmethod
    def _new_player(player_id: str) -> dict:
        return {
            "player_id": player_id,
            "rating": 0,
            "matches": 0,
            "wins": 0,
            "losses": 0,
            "streak": 0,
            "best_streak": 0,
            "mvp_count": 0,
            "streak_bonus": 0,
        }

    def mvp_score(self, line: PlayerLine) -> int:
        if not isinstance(line, PlayerLine):
            raise self._invalid_request("line must be a PlayerLine")
        return (
            line.kills * 3
            + line.assists * 2
            - line.deaths * 2
            + line.damage_dealt // 1000
            + line.damage_taken // 1500
            + line.vision_score // 10
        )

    def _validate_report(
        self,
        match_id: str,
        *,
        duration: int,
        players,
        winner,
        mode: str,
        now: int,
    ) -> list[PlayerLine]:
        if not isinstance(match_id, str) or not match_id:
            raise self._invalid_request("match_id must be a non-empty string")
        if not _is_integer(duration) or duration <= 0:
            raise self._invalid_request("duration must be a positive integer")
        if not _is_integer(now):
            raise self._invalid_request("now must be an integer millisecond value")
        if not isinstance(mode, str) or mode not in MODES:
            raise self._invalid_request("mode is not supported")
        if winner is not None and (
            not isinstance(winner, str) or winner not in TEAMS
        ):
            raise self._invalid_request("winner must be blue, red, or None")
        if mode == "normal" and winner not in TEAMS:
            raise self._invalid_request("normal matches require a winner")

        if isinstance(players, (str, bytes, bytearray)):
            raise self._invalid_request("players must be a sequence of PlayerLine")
        try:
            lines = list(players)
        except TypeError as exc:
            raise self._invalid_request("players must be a sequence of PlayerLine") from exc

        if len(lines) < 2 or len(lines) > self.max_players:
            raise self._invalid_request("player count is outside the allowed range")

        seen_player_ids: set[str] = set()
        teams: set[str] = set()
        for line in lines:
            if not isinstance(line, PlayerLine):
                raise self._invalid_request("every player must be a PlayerLine")

            player_id = line.player_id
            if not isinstance(player_id, str):
                raise self._invalid_request("player_id must be a string")
            if player_id in seen_player_ids:
                raise self._invalid_request("player_id values must be unique")
            seen_player_ids.add(player_id)

            if line.team not in TEAMS:
                raise self._invalid_request("team must be blue or red")
            teams.add(line.team)

            for field in NON_NEGATIVE_LINE_FIELDS:
                value = getattr(line, field)
                if not _is_integer(value) or value < 0:
                    raise self._invalid_request(f"{field} must be a non-negative integer")

            active_ratio = line.active_ratio
            if (
                isinstance(active_ratio, bool)
                or not isinstance(active_ratio, (int, float))
                or not math.isfinite(active_ratio)
                or not 0 <= active_ratio <= 1
            ):
                raise self._invalid_request("active_ratio must be between 0 and 1")

        if len(teams) < len(TEAMS):
            raise self._invalid_request("both teams must have a player")

        return lines

    def report_match(self, match_id: str, *, duration: int, players,
                     winner=None, mode: str = "normal",
                     now: int = 0) -> SettlementResult:
        with self._lock:
            try:
                lines = self._validate_report(
                    match_id,
                    duration=duration,
                    players=players,
                    winner=winner,
                    mode=mode,
                    now=now,
                )
            except MobaError:
                self._stats["refused_reports"] += 1
                raise
            except Exception as exc:
                self._stats["refused_reports"] += 1
                raise self._invalid_request("invalid match report") from exc

            existing = self._matches.get(match_id)
            if existing is not None:
                return self._result_from_record(existing)

            scores = {line.player_id: self.mvp_score(line) for line in lines}
            afk_ids = [
                line.player_id
                for line in lines
                if line.active_ratio < self.afk_ratio
            ]
            afk_set = set(afk_ids)

            mvp_id = None
            if mode == "normal":
                candidates = [
                    line
                    for line in lines
                    if line.team == winner and line.player_id not in afk_set
                ]
                if candidates:
                    mvp_line = min(
                        candidates,
                        key=lambda line: (
                            -scores[line.player_id],
                            line.deaths,
                            line.player_id,
                        ),
                    )
                    mvp_id = mvp_line.player_id

            seq = _next_report_seq(self._counters, self._matches)
            self._counters["report_seq"] = seq

            for line in lines:
                self._players.setdefault(
                    line.player_id, self._new_player(line.player_id)
                )

            rating_delta = {line.player_id: 0 for line in lines}
            streak_bonus = {line.player_id: 0 for line in lines}

            self._stats["matches"] += 1
            self._stats["players"] = len(self._players)
            self._stats["afk_flags"] += len(afk_ids)
            if mvp_id is not None:
                self._stats["mvps"] += 1

            for line in lines:
                player_id = line.player_id
                player = self._players[player_id]

                if player_id in afk_set or mode == "remake":
                    player["streak_bonus"] = 0
                    continue

                player["matches"] += 1
                self._stats["rating_awards"] += 1

                if line.team == winner:
                    player["wins"] += 1
                    player["streak"] += 1
                    if player["streak"] > player["best_streak"]:
                        player["best_streak"] = player["streak"]

                    capped_streak = min(player["streak"], self.streak_cap)
                    bonus = capped_streak * self.streak_step
                    streak_bonus[player_id] = bonus
                    player["streak_bonus"] = bonus

                    delta = self.win_points + bonus
                    if player_id == mvp_id:
                        delta += self.mvp_bonus
                        player["mvp_count"] += 1

                    player["rating"] += delta
                    rating_delta[player_id] = delta
                    self._stats["streak_awards"] += 1
                    self._stats["top_streak"] = max(
                        self._stats["top_streak"], player["best_streak"]
                    )
                else:
                    player["losses"] += 1
                    player["streak"] = 0
                    player["streak_bonus"] = 0
                    player["rating"] -= self.loss_points
                    rating_delta[player_id] = -self.loss_points

            record = {
                "match_id": match_id,
                "mode": mode,
                "winner": winner if mode == "normal" else None,
                "duration": duration,
                "now": now,
                "seq": seq,
                "mvp": mvp_id,
                "scores": scores,
                "rating_delta": rating_delta,
                "streak_bonus": streak_bonus,
                "afk": afk_ids,
            }
            self._matches[match_id] = record
            return self._result_from_record(record)

    @staticmethod
    def _result_from_record(record: dict) -> SettlementResult:
        return SettlementResult(
            match_id=record["match_id"],
            mode=record["mode"],
            winner=record["winner"],
            mvp=record["mvp"],
            duration=record["duration"],
            scores=dict(record["scores"]),
            rating_delta=dict(record["rating_delta"]),
            streak_bonus=dict(record["streak_bonus"]),
            afk=tuple(record["afk"]),
        )

    def _record_or_unknown(self, match_id: str) -> dict:
        try:
            record = self._matches.get(match_id)
        except TypeError as exc:
            raise self._unknown(match_id) from exc
        if record is None:
            raise self._unknown(match_id)
        return record

    def settlement(self, match_id: str) -> SettlementResult:
        with self._lock:
            return self._result_from_record(self._record_or_unknown(match_id))

    def player_summary(self, player_id: str) -> PlayerSummary:
        with self._lock:
            player = self._players.get(player_id)
            if player is None:
                raise self._unknown(player_id)
            return self._summary_from_player(player)

    @staticmethod
    def _summary_from_player(player: dict) -> PlayerSummary:
        return PlayerSummary(
            player_id=player["player_id"],
            rating=player["rating"],
            matches=player["matches"],
            wins=player["wins"],
            losses=player["losses"],
            streak=player["streak"],
            best_streak=player["best_streak"],
            mvp_count=player["mvp_count"],
        )

    def leaderboard(self, *, limit: int | None = None) -> tuple[PlayerSummary, ...]:
        if limit is not None and (not _is_integer(limit) or limit <= 0):
            raise self._invalid_request("limit must be a positive integer or None")
        with self._lock:
            ordered = sorted(
                self._players.values(),
                key=lambda player: (-player["rating"], player["player_id"]),
            )
            if limit is not None:
                ordered = ordered[:limit]
            return tuple(self._summary_from_player(player) for player in ordered)

    def afk_players(self, match_id: str) -> tuple[str, ...]:
        with self._lock:
            record = self._record_or_unknown(match_id)
            return tuple(record["afk"])

    def mvp_of(self, match_id: str) -> str | None:
        with self._lock:
            return self._record_or_unknown(match_id)["mvp"]

    def streak_bonus(self, player_id: str) -> int:
        with self._lock:
            player = self._players.get(player_id)
            if player is None:
                raise self._unknown(player_id)
            return player["streak_bonus"]

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": SNAPSHOT_VERSION,
                "players": self._players,
                "matches": self._matches,
                "counters": self._counters,
                "stats": self._stats,
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                candidate = copy.deepcopy(state)
                self._validate_snapshot(candidate)
            except MobaError:
                raise
            except Exception as exc:
                raise self._invalid_snapshot("snapshot could not be copied") from exc

            self._players = candidate["players"]
            self._matches = candidate["matches"]
            self._counters = candidate["counters"]
            self._stats = candidate["stats"]

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _validate_snapshot(self, state: object) -> None:
        if not isinstance(state, dict):
            raise self._invalid_snapshot("snapshot must be a dict")
        if set(state) != {
            "version",
            "players",
            "matches",
            "counters",
            "stats",
        }:
            raise self._invalid_snapshot("snapshot has an invalid top-level structure")
        if not _is_integer(state["version"]) or state["version"] != SNAPSHOT_VERSION:
            raise self._invalid_snapshot("unsupported snapshot version")

        for key in ("players", "matches", "counters", "stats"):
            if not isinstance(state[key], dict):
                raise self._invalid_snapshot(f"snapshot {key} must be a dict")

        counters = state["counters"]
        for key, value in counters.items():
            if not isinstance(key, str) or not _is_integer(value) or value < 0:
                raise self._invalid_snapshot("snapshot counters have an invalid structure")

        stats = state["stats"]
        if set(stats) != set(STAT_KEYS):
            raise self._invalid_snapshot("snapshot stats have an invalid structure")
        for key in STAT_KEYS:
            if not _is_integer(stats[key]) or stats[key] < 0:
                raise self._invalid_snapshot(f"stat {key} must be a non-negative integer")

        players = state["players"]
        for player_id, player in players.items():
            if not isinstance(player_id, str) or not isinstance(player, dict):
                raise self._invalid_snapshot("player snapshot entry is invalid")
            if set(player) != set(PLAYER_SNAPSHOT_KEYS):
                raise self._invalid_snapshot("player snapshot fields are invalid")
            if not isinstance(player["player_id"], str):
                raise self._invalid_snapshot("player_id must be a string")
            if player["player_id"] != player_id:
                raise self._invalid_snapshot("player snapshot key mismatch")
            if not _is_integer(player["rating"]):
                raise self._invalid_snapshot("player rating must be an integer")
            for field in (
                "matches",
                "wins",
                "losses",
                "streak",
                "best_streak",
                "mvp_count",
                "streak_bonus",
            ):
                if not _is_integer(player[field]) or player[field] < 0:
                    raise self._invalid_snapshot(f"player {field} is invalid")

        matches = state["matches"]
        for match_id, match in matches.items():
            if not isinstance(match_id, str) or not isinstance(match, dict):
                raise self._invalid_snapshot("match snapshot entry is invalid")
            if set(match) != set(MATCH_SNAPSHOT_KEYS):
                raise self._invalid_snapshot("match snapshot fields are invalid")
            if match["match_id"] != match_id:
                raise self._invalid_snapshot("match snapshot key mismatch")
            if not isinstance(match["mode"], str) or match["mode"] not in MODES:
                raise self._invalid_snapshot("match mode is invalid")
            if match["winner"] is not None and match["winner"] not in TEAMS:
                raise self._invalid_snapshot("match winner is invalid")
            if match["mode"] == "normal" and match["winner"] not in TEAMS:
                raise self._invalid_snapshot("normal match winner is invalid")
            if not _is_integer(match["duration"]) or match["duration"] <= 0:
                raise self._invalid_snapshot("match duration is invalid")
            if not _is_integer(match["now"]):
                raise self._invalid_snapshot("match now is invalid")
            if not _is_integer(match["seq"]) or match["seq"] < 0:
                raise self._invalid_snapshot("match seq is invalid")
            if match["mvp"] is not None and not isinstance(match["mvp"], str):
                raise self._invalid_snapshot("match mvp is invalid")

            map_keys = None
            for field, non_negative in (
                ("scores", False),
                ("rating_delta", False),
                ("streak_bonus", True),
            ):
                value_map = match[field]
                if not isinstance(value_map, dict):
                    raise self._invalid_snapshot(f"match {field} must be a dict")
                current_keys = set(value_map)
                if map_keys is None:
                    map_keys = current_keys
                elif current_keys != map_keys:
                    raise self._invalid_snapshot("match score maps must cover the same players")
                for player_id, value in value_map.items():
                    if not isinstance(player_id, str) or not _is_integer(value):
                        raise self._invalid_snapshot(f"match {field} entry is invalid")
                    if non_negative and value < 0:
                        raise self._invalid_snapshot(f"match {field} values must be non-negative")

            if map_keys is None:
                raise self._invalid_snapshot("match score maps are missing")
            for player_id in map_keys:
                if player_id not in players:
                    raise self._invalid_snapshot("match references an unknown player")

            if not isinstance(match["afk"], list) or not all(
                isinstance(player_id, str) for player_id in match["afk"]
            ):
                raise self._invalid_snapshot("match afk list is invalid")
            if len(set(match["afk"])) != len(match["afk"]):
                raise self._invalid_snapshot("match afk list contains duplicates")
            if any(player_id not in map_keys for player_id in match["afk"]):
                raise self._invalid_snapshot("afk player is missing from score maps")
            if match["mvp"] is not None and match["mvp"] not in map_keys:
                raise self._invalid_snapshot("mvp is missing from score maps")
