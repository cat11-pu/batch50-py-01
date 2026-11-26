"""Dungeon key affixer: weekly affix rotation, time bonus and downgrade flow.

A key belongs to one party and one weekly cycle.  Its affix triple is derived
deterministically from (week, party, level), so re-entering the same level in
the same week always shows the same affixes.  Completion inside the time
budget extends the key, completion past it downgrades the key, and a weekly
reset downgrades unused keys while re-rolling their affixes.
"""

from __future__ import annotations

import copy
import hashlib
import threading
from dataclasses import dataclass

__all__ = [
    "DungeonKeyError",
    "KeyRecord",
    "CompletionOutcome",
    "DungeonKeyAffixer",
]


class DungeonKeyError(ValueError):
    """Raised when a key operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class KeyRecord:
    """Immutable view of one dungeon key."""

    key_id: str
    party: str
    level: int
    week: int
    affixes: tuple[str, ...]
    time_limit: int
    time_spent: int
    attempts_left: int
    completions: int
    status: str


@dataclass(frozen=True)
class CompletionOutcome:
    """Result of one completion report."""

    key_id: str
    level: int
    within_limit: bool
    bonus_granted: int
    downgraded: bool
    affixes: tuple[str, ...]
    completions: int


class DungeonKeyAffixer:
    """Generate dungeon keys, run their lifecycle and rotate affixes weekly."""

    SNAPSHOT_VERSION = 1
    _STATUSES = ("fresh", "active", "depleted")

    def __init__(self, *, affix_pool=("raging", "bolstering", "bursting"),
                 affixes_per_key: int = 3, min_level: int = 1,
                 max_level: int = 15, base_time: int = 600,
                 bonus_time: int = 90, attempts: int = 5,
                 weekly_floor: int = 1, start_week: int = 1) -> None:
        self.affix_pool = tuple(affix_pool)
        self.affixes_per_key = affixes_per_key
        self.min_level = min_level
        self.max_level = max_level
        self.base_time = base_time
        self.bonus_time = bonus_time
        self.attempts = attempts
        self.weekly_floor = weekly_floor
        self.week = start_week
        self._lock = threading.RLock()
        self._keys: dict[str, dict] = {}
        self._counters = {
            "entered": 0,
            "clears": 0,
            "failures": 0,
            "resets": 0,
        }

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _require_identifier(cls, value: object, field: str) -> str:
        if not isinstance(value, str) or value == "":
            raise DungeonKeyError("KEY_INVALID_REQUEST", {"field": field})
        return value

    @classmethod
    def _require_level(cls, level: object, min_level: int,
                       max_level: int) -> int:
        if not cls._is_int(level):
            raise DungeonKeyError("KEY_LEVEL_OUT_OF_RANGE", level)
        if level < min_level or level > max_level:
            raise DungeonKeyError("KEY_LEVEL_OUT_OF_RANGE", level)
        return level

    @classmethod
    def _require_week_value(cls, week: object) -> int:
        if not cls._is_int(week):
            raise DungeonKeyError("KEY_WEEK_INVALID", week)
        return week

    def _affix_choices(self) -> tuple[str, ...]:
        try:
            return tuple(sorted(dict.fromkeys(self.affix_pool)))
        except TypeError as exc:
            raise DungeonKeyError(
                "KEY_INVALID_REQUEST", {"field": "affix_pool"}
            ) from exc

    def _select_affixes(self, party: str, level: int, week: int,
                        count: int) -> tuple[str, ...]:
        choices = self._affix_choices()
        if not self._is_int(count) or count < 0 or count > len(choices):
            raise DungeonKeyError(
                "KEY_INVALID_REQUEST",
                {"field": "affixes_per_key", "value": count},
            )

        if count == 0:
            return ()

        seed = hashlib.sha256(
            "\x1f".join((
                "dungeon-key-affixes-v1",
                str(week),
                party,
                str(level),
            )).encode("utf-8")
        ).digest()

        remaining = list(range(len(choices)))
        selected: list[int] = []
        round_no = 0
        while len(selected) < count:
            digest = hashlib.sha256(
                seed + round_no.to_bytes(8, "big", signed=False)
            ).digest()
            pick = int.from_bytes(digest[:8], "big") % len(remaining)
            selected.append(remaining.pop(pick))
            round_no += 1

        return tuple(sorted(choices[index] for index in selected))

    def _view(self, record: dict) -> KeyRecord:
        return KeyRecord(
            key_id=record["key_id"],
            party=record["party"],
            level=record["level"],
            week=record["week"],
            affixes=tuple(record["affixes"]),
            time_limit=record["time_limit"],
            time_spent=record["time_spent"],
            attempts_left=record["attempts_left"],
            completions=record["completions"],
            status=record["status"],
        )

    def _get_record(self, key_id: object) -> dict:
        if not isinstance(key_id, str) or key_id == "":
            raise DungeonKeyError("KEY_INVALID_REQUEST", {"field": "key_id"})
        try:
            return self._keys[key_id]
        except KeyError as exc:
            raise DungeonKeyError("KEY_NOT_FOUND", key_id) from exc

    def roll_key(self, key_id: str, party: str, level: int, *,
                 week: int | None = None) -> KeyRecord:
        key_id = self._require_identifier(key_id, "key_id")
        party = self._require_identifier(party, "party")
        level = self._require_level(level, self.min_level, self.max_level)
        if week is None:
            week = self.week
        week = self._require_week_value(week)
        affixes = self._select_affixes(
            party, level, week, self.affixes_per_key
        )

        with self._lock:
            if key_id in self._keys:
                raise DungeonKeyError("KEY_DUPLICATE", key_id)

            record = {
                "key_id": key_id,
                "party": party,
                "level": level,
                "week": week,
                "affixes": affixes,
                "time_limit": self.base_time,
                "time_spent": 0,
                "attempts_left": self.attempts,
                "completions": 0,
                "status": "fresh",
                "deferred": False,
            }
            self._keys[key_id] = record
            return self._view(record)

    def enter(self, key_id: str) -> KeyRecord:
        with self._lock:
            record = self._get_record(key_id)
            if record["status"] == "depleted" or record["attempts_left"] <= 0:
                raise DungeonKeyError("KEY_ATTEMPTS_EXHAUSTED", key_id)
            if record["status"] != "fresh":
                raise DungeonKeyError("KEY_STATE_CONFLICT", {
                    "key_id": key_id,
                    "status": record["status"],
                })

            record["status"] = "active"
            record["time_spent"] = 0
            self._counters["entered"] += 1
            return self._view(record)

    def complete(self, key_id: str, *, elapsed: int) -> CompletionOutcome:
        with self._lock:
            record = self._get_record(key_id)
            if record["status"] != "active":
                raise DungeonKeyError("KEY_STATE_CONFLICT", {
                    "key_id": key_id,
                    "status": record["status"],
                })
            if (
                not isinstance(elapsed, (int, float))
                or isinstance(elapsed, bool)
                or elapsed < 0
            ):
                raise DungeonKeyError("KEY_INVALID_REQUEST", {
                    "field": "elapsed",
                    "value": elapsed,
                })

            remaining = record["time_limit"] - record["time_spent"]
            within_limit = elapsed <= remaining
            bonus_granted = 0
            downgraded = False

            record["completions"] += 1
            self._counters["clears"] += 1

            if within_limit:
                record["time_limit"] += self.bonus_time
                bonus_granted = self.bonus_time
            else:
                new_level = max(self.min_level, record["level"] - 1)
                downgraded = new_level < record["level"]
                record["level"] = new_level

            record["time_spent"] = 0
            record["status"] = "fresh"

            return CompletionOutcome(
                key_id=key_id,
                level=record["level"],
                within_limit=within_limit,
                bonus_granted=bonus_granted,
                downgraded=downgraded,
                affixes=tuple(record["affixes"]),
                completions=record["completions"],
            )

    def fail(self, key_id: str) -> KeyRecord:
        with self._lock:
            record = self._get_record(key_id)
            if record["status"] != "active":
                raise DungeonKeyError("KEY_STATE_CONFLICT", {
                    "key_id": key_id,
                    "status": record["status"],
                })

            record["attempts_left"] -= 1
            self._counters["failures"] += 1
            record["time_spent"] = 0
            if record["attempts_left"] <= 0:
                record["attempts_left"] = 0
                record["status"] = "depleted"
            else:
                record["status"] = "fresh"
            return self._view(record)

    def affixes_for(self, party: str, level: int, *, week: int) -> tuple[str, ...]:
        party = self._require_identifier(party, "party")
        level = self._require_level(level, self.min_level, self.max_level)
        week = self._require_week_value(week)
        with self._lock:
            return self._select_affixes(
                party, level, week, self.affixes_per_key
            )

    def level_of(self, key_id: str) -> int:
        with self._lock:
            return self._get_record(key_id)["level"]

    def key_of(self, key_id: str) -> KeyRecord:
        with self._lock:
            return self._view(self._get_record(key_id))

    def weekly_reset(self, *, week: int) -> dict:
        week = self._require_week_value(week)
        with self._lock:
            if week <= self.week:
                raise DungeonKeyError("KEY_WEEK_INVALID", {
                    "requested_week": week,
                    "current_week": self.week,
                })

            downgraded = 0
            deferred = 0
            to_defer: list[dict] = []
            to_downgrade: list[tuple[dict, int, tuple[str, ...]]] = []
            for record in self._keys.values():
                was_deferred = bool(record.get("deferred", False))
                if record["status"] == "active" and not was_deferred:
                    to_defer.append(record)
                    continue

                is_deferred_active = (
                    record["status"] == "active" and was_deferred
                )
                if record["status"] != "fresh" and not is_deferred_active:
                    continue

                new_level = max(self.weekly_floor, record["level"] - 1)
                affixes = self._select_affixes(
                    record["party"], new_level, week,
                    self.affixes_per_key,
                )
                to_downgrade.append((record, new_level, affixes))

            for record in to_defer:
                record["deferred"] = True
                deferred += 1

            for record, new_level, affixes in to_downgrade:
                record["level"] = new_level
                record["week"] = week
                record["affixes"] = affixes
                record["deferred"] = False
                if record["status"] == "active":
                    record["status"] = "fresh"
                    record["time_spent"] = 0
                downgraded += 1

            self.week = week
            self._counters["resets"] += 1
            return {
                "downgraded": downgraded,
                "deferred": deferred,
                "week": week,
            }

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": self.SNAPSHOT_VERSION,
                "week": self.week,
                "keys": [
                    {
                        "key_id": record["key_id"],
                        "party": record["party"],
                        "level": record["level"],
                        "week": record["week"],
                        "affixes": tuple(record["affixes"]),
                        "time_limit": record["time_limit"],
                        "time_spent": record["time_spent"],
                        "attempts_left": record["attempts_left"],
                        "completions": record["completions"],
                        "status": record["status"],
                        "deferred": bool(record.get("deferred", False)),
                    }
                    for record in self._keys.values()
                ],
                "counters": dict(self._counters),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            parsed = self._parse_snapshot(state)
            self.week = parsed["week"]
            self._keys = parsed["keys"]
            self._counters = parsed["counters"]

    def _parse_snapshot(self, state: object) -> dict:
        if not isinstance(state, dict):
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "state")
        if set(state.keys()) != {"version", "week", "keys", "counters"}:
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "top-level")
        if (
            not self._is_int(state["version"])
            or state["version"] != self.SNAPSHOT_VERSION
        ):
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "version")
        if not self._is_int(state["week"]):
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "week")

        raw_keys = state["keys"]
        if isinstance(raw_keys, dict):
            raw_records = list(raw_keys.values())
        elif isinstance(raw_keys, list):
            raw_records = raw_keys
        else:
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "keys")

        raw_counters = state["counters"]
        if not isinstance(raw_counters, dict):
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "counters")
        counter_fields = ("entered", "clears", "failures", "resets")
        if set(raw_counters.keys()) != set(counter_fields):
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "counters")

        counters = {}
        for field in counter_fields:
            value = raw_counters.get(field)
            if not self._is_int(value) or value < 0:
                raise DungeonKeyError("KEY_SNAPSHOT_INVALID", field)
            counters[field] = value

        choices = set(self._affix_choices())
        keys: dict[str, dict] = {}
        for raw_record in raw_records:
            record = self._parse_snapshot_record(raw_record, choices)
            if record["key_id"] in keys:
                raise DungeonKeyError(
                    "KEY_SNAPSHOT_INVALID",
                    {"field": "key_id", "value": record["key_id"]},
                )
            keys[record["key_id"]] = record

        return {
            "week": state["week"],
            "keys": keys,
            "counters": counters,
        }

    def _parse_snapshot_record(self, raw_record: object,
                               affix_choices: set[str]) -> dict:
        if not isinstance(raw_record, dict):
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "key")

        fields = (
            "key_id", "party", "level", "week", "affixes", "time_limit",
            "time_spent", "attempts_left", "completions", "status",
        )
        optional_fields = ("deferred",)
        allowed_fields = set(fields) | set(optional_fields)
        raw_fields = set(raw_record.keys())
        if not set(fields).issubset(raw_fields):
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "key-fields")
        if not raw_fields.issubset(allowed_fields):
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "key-fields")

        key_id = raw_record["key_id"]
        party = raw_record["party"]
        if not isinstance(key_id, str) or key_id == "":
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "key_id")
        if not isinstance(party, str) or party == "":
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "party")

        level = raw_record["level"]
        if (
            not self._is_int(level)
            or level < self.min_level
            or level > self.max_level
        ):
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "level")

        week = raw_record["week"]
        if not self._is_int(week):
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "week")

        raw_affixes = raw_record["affixes"]
        if not isinstance(raw_affixes, (list, tuple)):
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "affixes")
        if len(raw_affixes) != self.affixes_per_key:
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "affixes")
        affixes = tuple(raw_affixes)
        if (
            not all(isinstance(affix, str) and affix in affix_choices
                    for affix in affixes)
            or len(set(affixes)) != len(affixes)
        ):
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "affixes")

        nonnegative_fields = (
            "time_limit", "time_spent", "attempts_left", "completions"
        )
        values = {}
        for field in nonnegative_fields:
            value = raw_record[field]
            if not self._is_int(value) or value < 0:
                raise DungeonKeyError("KEY_SNAPSHOT_INVALID", field)
            values[field] = value

        if values["time_spent"] > values["time_limit"]:
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "time_spent")
        if values["attempts_left"] > self.attempts:
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "attempts_left")

        status = raw_record["status"]
        if status not in self._STATUSES:
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "status")

        deferred = raw_record.get("deferred", False)
        if not isinstance(deferred, bool):
            raise DungeonKeyError("KEY_SNAPSHOT_INVALID", "deferred")

        return {
            "key_id": key_id,
            "party": party,
            "level": level,
            "week": week,
            "affixes": affixes,
            "status": status,
            "deferred": deferred,
            **values,
        }

    def stats(self) -> dict:
        with self._lock:
            fresh = active = depleted = 0
            for record in self._keys.values():
                if record["status"] == "fresh":
                    fresh += 1
                elif record["status"] == "active":
                    active += 1
                elif record["status"] == "depleted":
                    depleted += 1

            return {
                "keys": len(self._keys),
                "fresh": fresh,
                "active": active,
                "depleted": depleted,
                "entered": self._counters["entered"],
                "clears": self._counters["clears"],
                "failures": self._counters["failures"],
                "resets": self._counters["resets"],
                "week": self.week,
            }
