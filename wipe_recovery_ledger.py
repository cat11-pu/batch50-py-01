"""Wipe recovery ledger for raid boss encounters.

Every pull starts from a checkpoint that advances at phase transitions.  A
wipe parks the encounter in a recovery window, recovery restores hp and phase
from the checkpoint and drops combat effects, and exhausting the attempt
budget ejects the raid back to the instance entrance.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "RecoveryError",
    "BossProgress",
    "RecoveryOutcome",
    "DamageResult",
    "WipeRecoveryLedger",
]


class RecoveryError(ValueError):
    """Raised when a boss recovery operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BossProgress:
    """Immutable view of one encounter."""

    boss_id: str
    hp: int
    hp_max: int
    phase: int
    status: str
    consecutive_wipes: int
    total_wipes: int
    attempts_left: int
    checkpoint_hp: int
    checkpoint_phase: int
    buffs: tuple[str, ...]
    summons: tuple[str, ...]


@dataclass(frozen=True)
class RecoveryOutcome:
    """Result of restoring a checkpoint after a wipe."""

    boss_id: str
    restored_hp: int
    restored_phase: int
    cleared_buffs: tuple[str, ...]
    cleared_summons: tuple[str, ...]
    attempts_left: int
    ejected: bool


@dataclass(frozen=True)
class DamageResult:
    """Result of one incoming damage report."""

    boss_id: str
    accepted: bool
    code: str
    remaining_hp: int
    threat_total: int


class WipeRecoveryLedger:
    """Track boss checkpoints, wipe counters and recovery windows."""

    def __init__(self, *, attempts_per_lockout: int = 3) -> None:
        self.attempts_per_lockout = attempts_per_lockout
        self._lock = threading.RLock()

    def enter_combat(self, boss_id: str, *, hp_max: int = 1000,
                     phase: int = 1) -> BossProgress:
        raise NotImplementedError

    def advance_phase(self, boss_id: str, *, phase: int,
                      hp: int) -> BossProgress:
        raise NotImplementedError

    def add_effect(self, boss_id: str, kind: str, name: str) -> BossProgress:
        raise NotImplementedError

    def damage(self, boss_id: str, amount: int,
               source: str) -> DamageResult:
        raise NotImplementedError

    def wipe(self, boss_id: str) -> BossProgress:
        raise NotImplementedError

    def recover(self, boss_id: str) -> RecoveryOutcome:
        raise NotImplementedError

    def mark_clear(self, boss_id: str) -> BossProgress:
        raise NotImplementedError

    def progress_of(self, boss_id: str) -> BossProgress:
        raise NotImplementedError

    def attempts_left(self, boss_id: str) -> int:
        raise NotImplementedError

    def threat_of(self, boss_id: str) -> tuple[tuple[str, int], ...]:
        raise NotImplementedError

    def reset_instance(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
