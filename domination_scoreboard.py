"""Domination point scoring: signed capture meter, locks, mercy gap and overtime."""

from __future__ import annotations

import copy
import threading


class DominationError(ValueError):
    """Raised when a scoreboard operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_SNAPSHOT_VERSION = 1
_SNAPSHOT_KEYS = frozenset(
    {"version", "points", "scores", "clock", "overtime", "mercy", "stats"}
)
_POINT_KEYS = frozenset({"point_id", "controller", "progress", "locked"})
_OVERTIME_KEYS = frozenset({"active", "remaining", "trailing"})
_MERCY_KEYS = frozenset({"triggered", "gap", "leader"})
_STAT_KEYS = (
    "points",
    "captures",
    "flips",
    "ignored",
    "ticks",
    "mercies",
    "finalized",
)


def _is_strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _positive_int(value: object) -> bool:
    return _is_strict_int(value) and value > 0


def _non_negative_int(value: object) -> bool:
    return _is_strict_int(value) and value >= 0


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
        self._points: dict[str, dict] = {}
        self._scores = {team: 0 for team in self.teams}
        self._clock = round_seconds
        self._overtime = {"active": False, "remaining": 0, "trailing": None}
        self._mercy = {"triggered": False, "gap": 0, "leader": None}
        self._stats = {key: 0 for key in _STAT_KEYS}
        self._trailing_capture_pending = False
        self._last_flip_team = None

    def register_point(self, point_id: str) -> dict:
        with self._lock:
            if not isinstance(point_id, str) or not point_id.strip():
                raise DominationError(
                    "DOMINATION_INVALID_REQUEST",
                    "point_id must be a non-empty string after stripping whitespace",
                )
            if point_id in self._points:
                raise DominationError(
                    "DOMINATION_INVALID_REQUEST",
                    f"point {point_id!r} is already registered",
                )

            record = {
                "point_id": point_id,
                "controller": None,
                "progress": 0,
                "locked": 0,
            }
            self._points[point_id] = record
            self._stats["points"] += 1
            return dict(record)

    def point_state(self, point_id: str) -> dict:
        with self._lock:
            return dict(self._point_locked(point_id))

    def capture_tick(self, point_id: str, team: str, amount: int) -> dict:
        with self._lock:
            if not isinstance(team, str) or team not in self.teams:
                raise DominationError(
                    "DOMINATION_INVALID_REQUEST", f"unknown team {team!r}"
                )
            if not _positive_int(amount):
                raise DominationError(
                    "DOMINATION_INVALID_REQUEST",
                    "amount must be a positive integer",
                )

            point = self._point_locked(point_id)

            if point["locked"] > 0:
                self._stats["ignored"] += 1
                return dict(point)

            self._stats["captures"] += 1
            if (
                self._overtime["active"]
                and team == self._overtime["trailing"]
            ):
                self._trailing_capture_pending = True
            direction = 1 if team == self.teams[0] else -1
            next_progress = point["progress"] + direction * amount
            next_progress = max(-100, min(100, next_progress))
            if direction == 1:
                reached_full = next_progress == 100
            else:
                reached_full = next_progress == -100

            if reached_full:
                if point["controller"] != team:
                    point["controller"] = team
                    point["locked"] = self.lock_ticks
                    self._stats["flips"] += 1
                    self._last_flip_team = team

                    point_id_value = point["point_id"]
                    record = self._points.pop(point_id_value)
                    self._points = {point_id_value: record, **self._points}

                point["progress"] = 0
            else:
                point["progress"] = next_progress

            return dict(point)

    def settle(self, seconds: int = 1) -> dict:
        if not _positive_int(seconds):
            raise DominationError(
                "DOMINATION_INVALID_REQUEST",
                "seconds must be a positive integer",
            )

        awarded = {team: 0 for team in self.teams}
        ticks = 0

        with self._lock:
            for _ in range(seconds):
                if self._finished_locked():
                    break

                ticks += 1
                self._stats["ticks"] += 1

                was_overtime = self._overtime["active"]
                trailing_capture = (
                    self._trailing_capture_pending if was_overtime else False
                )
                self._trailing_capture_pending = False

                for team in self.teams:
                    gain = self._count_held_locked(team) * self.tick_points
                    self._scores[team] += gain
                    awarded[team] += gain

                for point in self._points.values():
                    if point["locked"] > 0:
                        point["locked"] -= 1

                if was_overtime:
                    if trailing_capture:
                        self._overtime["remaining"] = max(
                            0, self._overtime["remaining"] - 1
                        )
                    if self._overtime["remaining"] <= 0:
                        self._overtime["active"] = False
                        self._overtime["remaining"] = 0
                        self._overtime["trailing"] = None
                else:
                    self._clock = max(0, self._clock - 1)
                    if self._clock == 0:
                        trailing = self._trailing_team_locked()
                        if trailing is not None:
                            self._overtime = {
                                "active": True,
                                "remaining": self.overtime_seconds,
                                "trailing": trailing,
                            }
                            self._trailing_capture_pending = False

                mercy = self._refresh_mercy_locked()
                if mercy["triggered"]:
                    break

                if was_overtime and not self._overtime["active"]:
                    break
                if (
                    not was_overtime
                    and self._clock == 0
                    and not self._overtime["active"]
                ):
                    break

            return {
                "ticks": ticks,
                "awarded": awarded,
                "clock": self._clock,
                "overtime": self._overtime_view_locked(),
            }

    def score_of(self, team: str) -> int:
        with self._lock:
            if not isinstance(team, str) or team not in self._scores:
                raise DominationError(
                    "DOMINATION_INVALID_REQUEST", f"unknown team {team!r}"
                )
            return self._scores[team]

    def points_held(self, team: str) -> int:
        with self._lock:
            if not isinstance(team, str) or team not in self._scores:
                raise DominationError(
                    "DOMINATION_INVALID_REQUEST", f"unknown team {team!r}"
                )
            return self._count_held_locked(team)

    def overtime(self) -> dict:
        with self._lock:
            return self._overtime_view_locked()

    def mercy_check(self) -> dict:
        with self._lock:
            return self._mercy_view_locked()

    def finalize(self) -> dict:
        with self._lock:
            reason = self._finish_reason_locked()
            if reason is None:
                raise DominationError(
                    "DOMINATION_ROUND_ACTIVE",
                    "round is neither mercy-stopped nor time-complete",
                )

            self._stats["finalized"] += 1
            winner = self._score_leader_locked()
            scores = dict(self._scores)

            if winner is None and reason == "overtime":
                winner = self._overtime_tiebreak_winner_locked()

            return {
                "winner": winner,
                "scores": scores,
                "reason": reason,
            }

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": _SNAPSHOT_VERSION,
                "points": {
                    point_id: dict(record)
                    for point_id, record in self._points.items()
                },
                "scores": dict(self._scores),
                "clock": self._clock,
                "overtime": self._overtime_view_locked(),
                "mercy": self._mercy_view_locked(),
                "stats": dict(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            self._validate_snapshot(state)
            try:
                restored = copy.deepcopy(state)
            except Exception as exc:
                raise DominationError(
                    "DOMINATION_SNAPSHOT_INVALID",
                    "snapshot could not be deep-copied",
                ) from exc

            self._points = restored["points"]
            self._scores = restored["scores"]
            self._clock = restored["clock"]
            self._overtime = restored["overtime"]
            self._mercy = restored["mercy"]
            restored_stats = restored["stats"]
            self._stats = {
                key: restored_stats[key] for key in _STAT_KEYS
            }
            self._trailing_capture_pending = False

            if self._stats["flips"] > 0 and self._points:
                latest_record = next(iter(self._points.values()))
                self._last_flip_team = latest_record["controller"]
            else:
                self._last_flip_team = None

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _point_locked(self, point_id: str) -> dict:
        try:
            point = self._points.get(point_id)
        except TypeError:
            point = None
        if point is None:
            raise DominationError(
                "DOMINATION_UNKNOWN_POINT", f"unknown point {point_id!r}"
            )
        return point

    def _count_held_locked(self, team: str) -> int:
        return sum(
            1 for point in self._points.values()
            if point["controller"] == team
        )

    def _score_leader_locked(self):
        leader = None
        best_score = None
        tied = False
        for team in self.teams:
            score = self._scores[team]
            if best_score is None or score > best_score:
                best_score = score
                leader = team
                tied = False
            elif score == best_score:
                tied = True
        return None if tied else leader

    def _trailing_team_locked(self):
        trailing = None
        worst_score = None
        tied = False
        for team in self.teams:
            score = self._scores[team]
            if worst_score is None or score < worst_score:
                worst_score = score
                trailing = team
                tied = False
            elif score == worst_score:
                tied = True
        return None if tied else trailing

    def _mercy_view_locked(self) -> dict:
        leader = self._score_leader_locked()
        if len(self.teams) >= 2:
            gap = abs(
                self._scores[self.teams[0]] - self._scores[self.teams[1]]
            )
        else:
            gap = 0

        previously_triggered = bool(self._mercy.get("triggered"))
        triggered = previously_triggered or gap >= self.mercy_gap
        if previously_triggered and leader is None:
            leader = self._mercy.get("leader")

        return {"triggered": triggered, "gap": gap, "leader": leader}

    def _refresh_mercy_locked(self) -> dict:
        mercy = self._mercy_view_locked()
        if mercy["triggered"] and not self._mercy.get("triggered"):
            self._stats["mercies"] += 1
        self._mercy = dict(mercy)
        return mercy

    def _overtime_view_locked(self) -> dict:
        return {
            "active": bool(self._overtime["active"]),
            "remaining": self._overtime["remaining"],
            "trailing": self._overtime["trailing"],
        }

    def _finished_locked(self) -> bool:
        if self._mercy.get("triggered"):
            return True
        return self._clock <= 0 and not self._overtime["active"]

    def _finish_reason_locked(self):
        if self._mercy.get("triggered"):
            return "mercy"
        if self._clock <= 0 and not self._overtime["active"]:
            if self._stats["ticks"] > self.round_seconds:
                return "overtime"
            return "time"
        return None

    def _overtime_tiebreak_winner_locked(self):
        if self._last_flip_team not in self._scores:
            return None
        if not self._points:
            return None
        if not all(
            point["controller"] is not None
            for point in self._points.values()
        ):
            return None
        return self._last_flip_team

    def _validate_snapshot(self, state: object) -> None:
        def invalid(detail: str) -> None:
            raise DominationError("DOMINATION_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict):
            invalid("snapshot must be a dict")

        if frozenset(state.keys()) != _SNAPSHOT_KEYS:
            invalid("snapshot keys do not match the fixed schema")

        version = state["version"]
        if not _is_strict_int(version) or version != _SNAPSHOT_VERSION:
            invalid("unsupported snapshot version")

        points = state["points"]
        if not isinstance(points, dict):
            invalid("points must be a dict")

        for point_id, record in points.items():
            if not isinstance(point_id, str) or not point_id.strip():
                invalid("point ids must be non-empty strings")
            if (
                not isinstance(record, dict)
                or frozenset(record.keys()) != _POINT_KEYS
            ):
                invalid("point record must contain exactly the fixed fields")
            if not isinstance(record["point_id"], str):
                invalid("point_id must be a string")
            if record["point_id"] != point_id:
                invalid("point record id does not match its snapshot key")

            controller = record["controller"]
            if controller is not None and (
                not isinstance(controller, str)
                or controller not in self._scores
            ):
                invalid("point controller must be a configured team or None")

            progress = record["progress"]
            if not _is_strict_int(progress) or not -100 <= progress <= 100:
                invalid("point progress must be an integer in [-100, 100]")

            locked = record["locked"]
            if not _non_negative_int(locked):
                invalid("point locked must be a non-negative integer")
            if _non_negative_int(self.lock_ticks):
                if locked > self.lock_ticks:
                    invalid("point locked exceeds lock_ticks")

        scores = state["scores"]
        if not isinstance(scores, dict):
            invalid("scores must be a dict")
        if frozenset(scores.keys()) != frozenset(self.teams):
            invalid("scores must contain exactly the configured teams")
        for team in self.teams:
            if not _non_negative_int(scores[team]):
                invalid("score values must be non-negative integers")

        if not _non_negative_int(state["clock"]):
            invalid("clock must be a non-negative integer")

        overtime = state["overtime"]
        if (
            not isinstance(overtime, dict)
            or frozenset(overtime.keys()) != _OVERTIME_KEYS
        ):
            invalid("overtime must contain active, remaining and trailing")
        if not isinstance(overtime["active"], bool):
            invalid("overtime.active must be a bool")
        if not _non_negative_int(overtime["remaining"]):
            invalid("overtime.remaining must be a non-negative integer")
        trailing = overtime["trailing"]
        if trailing is not None and (
            not isinstance(trailing, str)
            or trailing not in self._scores
        ):
            invalid("overtime.trailing must be a configured team or None")

        mercy = state["mercy"]
        if (
            not isinstance(mercy, dict)
            or frozenset(mercy.keys()) != _MERCY_KEYS
        ):
            invalid("mercy must contain triggered, gap and leader")
        if not isinstance(mercy["triggered"], bool):
            invalid("mercy.triggered must be a bool")
        if not _non_negative_int(mercy["gap"]):
            invalid("mercy.gap must be a non-negative integer")
        leader = mercy["leader"]
        if leader is not None and (
            not isinstance(leader, str) or leader not in self._scores
        ):
            invalid("mercy.leader must be a configured team or None")

        stats = state["stats"]
        if not isinstance(stats, dict):
            invalid("stats must be a dict")
        for key in _STAT_KEYS:
            if key not in stats:
                invalid(f"stats is missing {key}")
            if not _non_negative_int(stats[key]):
                invalid(f"stats.{key} must be a non-negative integer")
        if stats["points"] != len(points):
            invalid("stats.points must equal the number of snapshots points")
