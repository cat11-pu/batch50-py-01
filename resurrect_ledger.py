"""Death and resurrection ledger: costs, cooldowns, soul penalties and requests."""

from __future__ import annotations

import copy
import math
import threading
import time
from datetime import datetime


MODES = ("in_place", "town", "teammate")
SNAPSHOT_VERSION = 1
FRAME_ARBITRATION_SECONDS = 0.05


def _now_value(now=None):
    if now is None:
        value = time.time()
        return value, float(value)
    return now, _time_seconds(now)


def _time_seconds(value) -> float:
    if value is None:
        return time.time()
    if isinstance(value, bool):
        raise ResurrectError("RESURRECT_INVALID_REQUEST", {"now": value})
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, datetime):
        return value.timestamp()
    if isinstance(value, str):
        text = value.strip()
        try:
            return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
        except ValueError:
            try:
                return float(text)
            except ValueError as exc:
                raise ResurrectError(
                    "RESURRECT_INVALID_REQUEST", {"now": value}
                ) from exc
    raise ResurrectError("RESURRECT_INVALID_REQUEST", {"now": value})


def _finite_number(value) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _non_negative_number(value) -> bool:
    return _finite_number(value) and value >= 0


def _remaining_seconds(deadline, now: float) -> int:
    if deadline is None:
        return 0
    remaining = float(deadline) - now
    if remaining <= 0:
        return 0
    return max(1, int(math.ceil(remaining - 1e-9)))


class ResurrectError(ValueError):
    """Raised when a resurrection operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class ResurrectLedger:
    """Track character death state, resurrection payments and soul penalties."""

    def __init__(self, *, penalty_window: int = 60, max_stacks: int = 5,
                 costs=None, cooldowns=None) -> None:
        self.penalty_window = penalty_window
        self.max_stacks = max_stacks
        self.costs = {"in_place": 50, "town": 10, "teammate": 0}
        self.costs.update(costs or {})
        self.cooldowns = {"in_place": 20, "town": 5, "teammate": 0}
        self.cooldowns.update(cooldowns or {})
        self._lock = threading.RLock()
        self._frame_condition = threading.Condition(self._lock)
        self._frame_ballots = {}
        self._characters = {}
        self._stats = {
            "registered": 0,
            "deaths": 0,
            "resurrected": 0,
            "requests": 0,
            "expired": 0,
            "cancelled": 0,
        }

    def register_character(self, character: str, *, gold: int = 0, now=None) -> dict:
        name = self._valid_name(character)
        _, now_seconds = _now_value(now)
        with self._lock:
            if name in self._characters:
                raise ResurrectError(
                    "RESURRECT_INVALID_REQUEST",
                    {"character": name, "reason": "already_registered"},
                )
            record = {
                "character": name,
                "state": "alive",
                "gold": gold,
                "stacks": 0,
                "deaths": 0,
                "penalty_since": now_seconds,
                "penalty_due": None,
                "penalty_settled_at": None,
                "penalty_late": None,
                "cooldown_until": {mode: None for mode in MODES},
                "online": True,
                "offline_since": None,
                "request": None,
            }
            self._characters[name] = record
            self._stats["registered"] += 1
            return self._public_state(record)

    def state_of(self, character: str) -> dict:
        with self._lock:
            _, record = self._character_record(character)
            return self._public_state(record)

    def die(self, character: str, now=None) -> dict:
        _, now_seconds = _now_value(now)
        with self._lock:
            _, record = self._character_record(character)
            if record["state"] != "alive":
                raise ResurrectError(
                    "RESURRECT_ALREADY_DEAD",
                    {"character": record["character"], "state": record["state"]},
                )

            record["state"] = "soul"
            record["deaths"] += 1
            record["stacks"] = min(
                int(self.max_stacks), int(record["stacks"]) + 1
            )
            record["penalty_since"] = now_seconds
            record["penalty_due"] = (
                now_seconds + float(self.penalty_window)
                if record["stacks"] > 0
                else None
            )
            record["penalty_settled_at"] = None
            record["penalty_late"] = None
            record["request"] = None
            self._stats["deaths"] += 1
            return self._public_state(record)

    def resurrect(self, character: str, mode: str, now=None) -> dict:
        _, now_seconds = _now_value(now)
        with self._frame_condition:
            name, record = self._character_record(character)
            if mode not in MODES:
                raise ResurrectError(
                    "RESURRECT_INVALID_REQUEST", {"mode": mode}
                )

            self._ensure_resurrectable(record, mode, now_seconds)
            frame_key = (name, now_seconds)
            ballot = self._frame_ballots.get(frame_key)
            if ballot is None:
                ballot = {
                    "entries": {},
                    "winner": None,
                    "deadline": time.monotonic() + FRAME_ARBITRATION_SECONDS,
                    "sequence": 0,
                }
                self._frame_ballots[frame_key] = ballot

            ballot["sequence"] += 1
            token = ballot["sequence"]
            ballot["entries"][token] = mode
            try:
                while ballot["winner"] is None:
                    self._ensure_resurrectable(record, mode, now_seconds)
                    best_token = min(
                        ballot["entries"],
                        key=lambda candidate: (
                            self.costs[ballot["entries"][candidate]],
                            MODES.index(ballot["entries"][candidate]),
                            candidate,
                        ),
                    )
                    best_mode = ballot["entries"][best_token]
                    timed_out = time.monotonic() >= ballot["deadline"]
                    can_win_now = (
                        best_token == token
                        and not self._has_lower_eligible_mode(
                            record, mode, now_seconds
                        )
                    )

                    if timed_out or can_win_now:
                        ballot["winner"] = best_token
                        self._frame_condition.notify_all()
                        if best_token != token:
                            raise ResurrectError(
                                "RESURRECT_NOT_DEAD",
                                {
                                    "character": name,
                                    "reason": "same_frame_lower_cost_winner",
                                    "winner_mode": best_mode,
                                },
                            )
                        break

                    wait_seconds = max(
                        0.0, ballot["deadline"] - time.monotonic()
                    )
                    self._frame_condition.wait(wait_seconds)

                if ballot["winner"] != token:
                    raise ResurrectError(
                        "RESURRECT_NOT_DEAD",
                        {
                            "character": name,
                            "reason": "same_frame_lower_cost_winner",
                        },
                    )

                self._ensure_resurrectable(record, mode, now_seconds)
                cost = self.costs[mode]
                record["gold"] -= cost
                record["state"] = "alive"
                record["cooldown_until"][mode] = (
                    now_seconds + float(self.cooldowns[mode])
                )
                if mode == "teammate":
                    record["request"] = None
                self._stats["resurrected"] += 1
                self._frame_ballots.pop(frame_key, None)

                return {
                    "character": record["character"],
                    "mode": mode,
                    "state": record["state"],
                    "gold": record["gold"],
                    "cost": cost,
                    "stacks": record["stacks"],
                    "deaths": record["deaths"],
                }
            finally:
                ballot["entries"].pop(token, None)
                if not ballot["entries"]:
                    self._frame_ballots.pop(frame_key, None)

    def request_help(self, target: str, helper: str, now=None) -> dict:
        target_name = self._lookup_name(target)
        helper_name = self._lookup_name(helper)
        if target_name == helper_name:
            raise ResurrectError(
                "RESURRECT_INVALID_REQUEST",
                {"target": target_name, "helper": helper_name},
            )
        raw_now, _ = _now_value(now)

        with self._lock:
            target_name, target_record = self._character_record(target_name)
            helper_name, _ = self._character_record(helper_name)
            request = {
                "target": target_name,
                "helper": helper_name,
                "issued_at": raw_now,
            }
            target_record["request"] = request
            self._stats["requests"] += 1
            return copy.deepcopy(request)

    def pending_request(self, target: str):
        with self._lock:
            name = self._lookup_name(target)
            record = self._characters.get(name)
            if record is None or record["request"] is None:
                return None
            return copy.deepcopy(record["request"])

    def cancel_request(self, target: str) -> bool:
        with self._lock:
            name = self._lookup_name(target)
            record = self._characters.get(name)
            if record is None or record["request"] is None:
                return False
            record["request"] = None
            self._stats["cancelled"] += 1
            return True

    def penalty_of(self, character: str, now=None) -> dict:
        _, now_seconds = _now_value(now)
        with self._lock:
            _, record = self._character_record(character)
            return {
                "stacks": record["stacks"],
                "remaining": self._penalty_remaining(record, now_seconds),
            }

    def cooldown_of(self, character: str, mode: str, now=None) -> int:
        _, now_seconds = _now_value(now)
        with self._lock:
            _, record = self._character_record(character)
            if mode not in MODES:
                raise ResurrectError("RESURRECT_INVALID_REQUEST", {"mode": mode})
            return _remaining_seconds(
                record["cooldown_until"].get(mode), now_seconds
            )

    def expire_penalty(self, now=None) -> int:
        _, now_seconds = _now_value(now)
        changed = 0
        with self._lock:
            for record in self._characters.values():
                if record["stacks"] <= 0 or record["penalty_due"] is None:
                    continue
                if record["penalty_due"] > now_seconds:
                    continue

                previous_due = float(record["penalty_due"])
                record["stacks"] -= 1
                self._stats["expired"] += 1
                changed += 1
                record["penalty_settled_at"] = now_seconds
                record["penalty_late"] = max(
                    0.0, now_seconds - previous_due
                )

                if record["stacks"] <= 0:
                    record["stacks"] = 0
                    record["penalty_due"] = None
                    record["penalty_since"] = None
                else:
                    next_due = previous_due + float(self.penalty_window)
                    while next_due <= now_seconds:
                        next_due += float(self.penalty_window)
                    record["penalty_due"] = next_due
                    record["penalty_since"] = (
                        next_due - float(self.penalty_window)
                    )
                    record["penalty_late"] = max(
                        0.0,
                        now_seconds - float(record["penalty_since"]),
                    )
            return changed

    def mark_offline(self, character: str, now=None) -> dict:
        raw_now, now_seconds = _now_value(now)
        with self._lock:
            name, record = self._character_record(character)
            record["online"] = False
            record["offline_since"] = now_seconds
            return {
                "character": name,
                "online": False,
                "offline_at": raw_now,
            }

    def mark_online(self, character: str, now=None) -> dict:
        raw_now, now_seconds = _now_value(now)
        with self._lock:
            name, record = self._character_record(character)
            self._apply_offline_decay(record, now_seconds)
            record["online"] = True
            record["offline_since"] = None
            return {
                "character": name,
                "online": True,
                "online_at": raw_now,
            }

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(
                {
                    "version": SNAPSHOT_VERSION,
                    "characters": self._characters,
                    "stats": self._stats,
                }
            )

    def restore(self, state: dict) -> None:
        characters, stats = self._validated_snapshot(state)
        with self._lock:
            self._characters = characters
            self._stats = stats
            self._frame_ballots.clear()

    def stats(self) -> dict:
        with self._lock:
            return {key: self._stats[key] for key in (
                "registered",
                "deaths",
                "resurrected",
                "requests",
                "expired",
                "cancelled",
            )}

    @staticmethod
    def _valid_name(character) -> str:
        if not isinstance(character, str) or not character.strip():
            raise ResurrectError(
                "RESURRECT_INVALID_REQUEST", {"character": character}
            )
        return character.strip()

    @staticmethod
    def _lookup_name(character) -> str:
        if isinstance(character, str) and character.strip():
            return character.strip()
        return character if isinstance(character, str) else ""

    def _character_record(self, character):
        name = self._lookup_name(character)
        record = self._characters.get(name)
        if record is None:
            raise ResurrectError(
                "RESURRECT_UNKNOWN_CHARACTER", {"character": character}
            )
        return name, record

    @staticmethod
    def _public_state(record: dict) -> dict:
        return {
            "character": record["character"],
            "state": record["state"],
            "gold": record["gold"],
            "stacks": record["stacks"],
            "deaths": record["deaths"],
        }

    def _ensure_resurrectable(self, record: dict, mode: str, now_seconds: float):
        if record["state"] == "alive":
            raise ResurrectError(
                "RESURRECT_NOT_DEAD",
                {"character": record["character"], "state": record["state"]},
            )

        remaining = _remaining_seconds(
            record["cooldown_until"].get(mode), now_seconds
        )
        if remaining > 0:
            raise ResurrectError(
                "RESURRECT_COOLDOWN_ACTIVE",
                {
                    "character": record["character"],
                    "mode": mode,
                    "remaining": remaining,
                },
            )

        if mode == "teammate" and record["request"] is None:
            raise ResurrectError(
                "RESURRECT_REQUEST_MISSING",
                {"character": record["character"], "mode": mode},
            )

        cost = self.costs[mode]
        if record["gold"] < cost:
            raise ResurrectError(
                "RESURRECT_INSUFFICIENT_FUNDS",
                {
                    "character": record["character"],
                    "gold": record["gold"],
                    "cost": cost,
                },
            )

    def _has_lower_eligible_mode(
        self, record: dict, mode: str, now_seconds: float
    ) -> bool:
        current_cost = self.costs[mode]
        for candidate_mode in MODES:
            if candidate_mode == mode:
                continue
            try:
                self._ensure_resurrectable(
                    record, candidate_mode, now_seconds
                )
            except ResurrectError:
                continue
            if self.costs[candidate_mode] < current_cost:
                return True
        return False

    def _penalty_remaining(self, record: dict, now_seconds: float) -> int:
        if record["stacks"] <= 0 or record["penalty_due"] is None:
            return 0
        settled_at = record.get("penalty_settled_at")
        late = record.get("penalty_late")
        if (
            settled_at is not None
            and abs(float(settled_at) - now_seconds) < 1e-9
            and _non_negative_number(late)
            and late > 0
        ):
            return max(1, int(math.ceil(float(late) - 1e-9)))
        return _remaining_seconds(record["penalty_due"], now_seconds)

    def _apply_offline_decay(self, record: dict, now_seconds: float) -> None:
        offline_since = record.get("offline_since")
        if (
            record["state"] != "soul"
            or record["online"]
            or offline_since is None
            or record["stacks"] <= 0
        ):
            return

        offline_seconds = max(0.0, now_seconds - float(offline_since))
        if offline_seconds <= float(self.penalty_window):
            return

        effective_seconds = offline_seconds / 2.0
        decayed_layers = int(
            effective_seconds // float(self.penalty_window)
        )
        removable_layers = min(
            record["stacks"], max(0, record["stacks"] - 1)
        )
        decayed_layers = min(decayed_layers, removable_layers)
        if decayed_layers > 0:
            record["stacks"] -= decayed_layers
            self._stats["expired"] += decayed_layers

        record["penalty_since"] = now_seconds
        record["penalty_due"] = now_seconds + float(self.penalty_window)
        record["penalty_settled_at"] = None
        record["penalty_late"] = None

    def _validated_snapshot(self, state):
        if not isinstance(state, dict):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID", {"reason": "state_not_object"}
            )
        if set(state.keys()) != {"version", "characters", "stats"}:
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID", {"reason": "top_level_keys"}
            )
        if type(state["version"]) is not int or state["version"] != SNAPSHOT_VERSION:
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID", {"reason": "version"}
            )
        if not isinstance(state["characters"], dict):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID", {"reason": "characters_type"}
            )
        if not isinstance(state["stats"], dict):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID", {"reason": "stats_type"}
            )

        try:
            characters = copy.deepcopy(state["characters"])
            stats = copy.deepcopy(state["stats"])
            normalized_characters = {}
            for key, raw_record in characters.items():
                record = self._validated_character(key, raw_record)
                normalized_characters[record["character"]] = record
            normalized_stats = self._validated_stats(stats)
        except ResurrectError:
            raise
        except Exception as exc:
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID", {"reason": "character_schema"}
            ) from exc

        return normalized_characters, normalized_stats

    def _validated_character(self, key, record):
        if not isinstance(key, str) or not key.strip():
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID", {"reason": "character_key"}
            )
        key = key.strip()
        if not isinstance(record, dict):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID", {"character": key}
            )

        required = (
            "character",
            "state",
            "gold",
            "stacks",
            "deaths",
            "penalty_since",
            "penalty_due",
            "penalty_settled_at",
            "penalty_late",
            "cooldown_until",
            "online",
            "offline_since",
            "request",
        )
        if any(field not in record for field in required):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID",
                {"character": key, "reason": "missing_field"},
            )
        if record["character"] != key:
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID",
                {"character": key, "reason": "character_name_mismatch"},
            )
        if record["state"] not in ("alive", "soul"):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID", {"character": key, "field": "state"}
            )
        if not _finite_number(record["gold"]):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID", {"character": key, "field": "gold"}
            )
        for field in ("stacks", "deaths"):
            value = record[field]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ResurrectError(
                    "RESURRECT_SNAPSHOT_INVALID",
                    {"character": key, "field": field},
                )
        for field in (
            "penalty_since",
            "penalty_due",
            "penalty_settled_at",
            "offline_since",
        ):
            value = record[field]
            if value is not None and not _finite_number(value):
                raise ResurrectError(
                    "RESURRECT_SNAPSHOT_INVALID",
                    {"character": key, "field": field},
                )
        if record["penalty_late"] is not None and not _non_negative_number(
            record["penalty_late"]
        ):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID",
                {"character": key, "field": "penalty_late"},
            )
        if not isinstance(record["online"], bool):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID",
                {"character": key, "field": "online"},
            )
        if not isinstance(record["cooldown_until"], dict):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID",
                {"character": key, "field": "cooldown_until"},
            )

        cooldown_until = {mode: None for mode in MODES}
        for mode, deadline in record["cooldown_until"].items():
            if mode not in MODES:
                raise ResurrectError(
                    "RESURRECT_SNAPSHOT_INVALID",
                    {"character": key, "field": "cooldown_until"},
                )
            if deadline is not None and not _finite_number(deadline):
                raise ResurrectError(
                    "RESURRECT_SNAPSHOT_INVALID",
                    {"character": key, "field": f"cooldown_until.{mode}"},
                )
            cooldown_until[mode] = (
                None if deadline is None else float(deadline)
            )

        request = self._validated_request(key, record["request"])
        return {
            "character": key,
            "state": record["state"],
            "gold": record["gold"],
            "stacks": int(record["stacks"]),
            "deaths": int(record["deaths"]),
            "penalty_since": (
                None
                if record["penalty_since"] is None
                else float(record["penalty_since"])
            ),
            "penalty_due": (
                None
                if record["penalty_due"] is None
                else float(record["penalty_due"])
            ),
            "penalty_settled_at": (
                None
                if record["penalty_settled_at"] is None
                else float(record["penalty_settled_at"])
            ),
            "penalty_late": (
                None
                if record["penalty_late"] is None
                else float(record["penalty_late"])
            ),
            "cooldown_until": cooldown_until,
            "online": record["online"],
            "offline_since": (
                None
                if record["offline_since"] is None
                else float(record["offline_since"])
            ),
            "request": request,
        }

    @staticmethod
    def _validated_request(character, request):
        if request is None:
            return None
        if not isinstance(request, dict):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID",
                {"character": character, "field": "request"},
            )
        if set(request.keys()) != {"target", "helper", "issued_at"}:
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID",
                {"character": character, "field": "request"},
            )
        if (
            not isinstance(request["target"], str)
            or not request["target"].strip()
            or not isinstance(request["helper"], str)
            or not request["helper"].strip()
            or request["target"] != character
        ):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID",
                {"character": character, "field": "request"},
            )
        issued_at = request["issued_at"]
        if issued_at is None or isinstance(issued_at, bool):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID",
                {"character": character, "field": "request.issued_at"},
            )
        if not isinstance(issued_at, (str, int, float)):
            raise ResurrectError(
                "RESURRECT_SNAPSHOT_INVALID",
                {"character": character, "field": "request.issued_at"},
            )
        return copy.deepcopy(request)

    @staticmethod
    def _validated_stats(stats):
        required = (
            "registered",
            "deaths",
            "resurrected",
            "requests",
            "expired",
            "cancelled",
        )
        normalized = {}
        for field in required:
            value = stats.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ResurrectError(
                    "RESURRECT_SNAPSHOT_INVALID", {"field": f"stats.{field}"}
                )
            normalized[field] = value
        for field, value in stats.items():
            if field not in required:
                normalized[field] = copy.deepcopy(value)
        return normalized
