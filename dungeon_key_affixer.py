"""Dungeon key affixer: weekly affix rotation, time bonus and downgrade flow.

A key belongs to one party and one weekly cycle.  Its affix triple is derived
deterministically from (week, party, level), so re-entering the same level in
the same week always shows the same affixes.  Completion inside the time
budget extends the key, completion past it downgrades the key, and a weekly
reset downgrades unused keys while re-rolling their affixes.
"""

from __future__ import annotations

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

    def roll_key(self, key_id: str, party: str, level: int, *,
                 week: int | None = None) -> KeyRecord:
        raise NotImplementedError

    def enter(self, key_id: str) -> KeyRecord:
        raise NotImplementedError

    def complete(self, key_id: str, *, elapsed: int) -> CompletionOutcome:
        raise NotImplementedError

    def fail(self, key_id: str) -> KeyRecord:
        raise NotImplementedError

    def affixes_for(self, party: str, level: int, *, week: int) -> tuple[str, ...]:
        raise NotImplementedError

    def level_of(self, key_id: str) -> int:
        raise NotImplementedError

    def key_of(self, key_id: str) -> KeyRecord:
        raise NotImplementedError

    def weekly_reset(self, *, week: int) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
