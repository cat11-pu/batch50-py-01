"""Wipe recovery ledger for raid boss encounters.

Every pull starts from a checkpoint that advances at phase transitions.  A
wipe parks the encounter in a recovery window, recovery restores hp and phase
from the checkpoint and drops combat effects, and exhausting the attempt
budget ejects the raid back to the instance entrance.
"""

from __future__ import annotations

import threading
from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any

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


_STATUS_ENGAGED = "engaged"
_STATUS_RECOVERING = "recovering"
_STATUS_CLEARED = "cleared"
_STATUS_EJECTED = "ejected"
_STATUSES = frozenset(
    {_STATUS_ENGAGED, _STATUS_RECOVERING, _STATUS_CLEARED, _STATUS_EJECTED}
)
_SNAPSHOT_VERSION = 1
_COUNTER_KEYS = ("wipes", "recovers", "clears", "resets")


class _SnapshotInvalid(ValueError):
    """Internal marker for malformed snapshot payloads."""


@dataclass
class _BossState:
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
    buffs: list[str] = field(default_factory=list)
    summons: list[str] = field(default_factory=list)
    threat: dict[str, int] = field(default_factory=dict)


class WipeRecoveryLedger:
    """Track boss checkpoints, wipe counters and recovery windows."""

    def __init__(self, *, attempts_per_lockout: int = 3) -> None:
        self.attempts_per_lockout = attempts_per_lockout
        self._lock = threading.RLock()
        self._bosses: dict[str, _BossState] = {}
        self._counters = {key: 0 for key in _COUNTER_KEYS}

    def enter_combat(self, boss_id: str, *, hp_max: int = 1000,
                     phase: int = 1) -> BossProgress:
        self._require_positive_int(hp_max, "hp_max")
        self._require_positive_int(phase, "phase")

        with self._lock:
            existing = self._bosses.get(boss_id)
            if existing is not None:
                if existing.status == _STATUS_EJECTED:
                    raise RecoveryError(
                        "RECOVERY_EJECTED",
                        {"boss_id": boss_id, "attempts_left": 0},
                    )
                if existing.status == _STATUS_CLEARED:
                    return self._progress_view(existing)
                raise RecoveryError(
                    "RECOVERY_ALREADY_ENGAGED",
                    {"boss_id": boss_id, "status": existing.status},
                )

            attempts_left = self.attempts_per_lockout
            if not self._is_integer(attempts_left) or attempts_left < 0:
                attempts_left = 0

            boss = _BossState(
                boss_id=boss_id,
                hp=hp_max,
                hp_max=hp_max,
                phase=phase,
                status=_STATUS_ENGAGED,
                consecutive_wipes=0,
                total_wipes=0,
                attempts_left=attempts_left,
                checkpoint_hp=hp_max,
                checkpoint_phase=phase,
            )
            self._bosses[boss_id] = boss
            return self._progress_view(boss)

    def advance_phase(self, boss_id: str, *, phase: int,
                      hp: int) -> BossProgress:
        self._require_integer(phase, "phase")
        self._require_integer(hp, "hp")

        with self._lock:
            boss = self._boss(boss_id)
            self._reject_ejected(boss)

            if phase <= boss.phase:
                raise RecoveryError(
                    "RECOVERY_PHASE_REGRESSION",
                    {
                        "boss_id": boss_id,
                        "current_phase": boss.phase,
                        "requested_phase": phase,
                    },
                )

            boss.phase = phase
            boss.hp = hp
            boss.checkpoint_phase = phase
            boss.checkpoint_hp = hp
            return self._progress_view(boss)

    def add_effect(self, boss_id: str, kind: str, name: str) -> BossProgress:
        with self._lock:
            boss = self._boss(boss_id)
            self._reject_ejected(boss)

            if kind not in ("buff", "summon"):
                raise RecoveryError(
                    "RECOVERY_INVALID_EFFECT",
                    {"boss_id": boss_id, "kind": kind, "name": name},
                )
            if not isinstance(name, str) or not name:
                raise RecoveryError(
                    "RECOVERY_INVALID_EFFECT",
                    {"boss_id": boss_id, "kind": kind, "name": name},
                )

            if kind == "buff":
                boss.buffs.append(name)
            else:
                boss.summons.append(name)
            return self._progress_view(boss)

    def damage(self, boss_id: str, amount: int,
               source: str) -> DamageResult:
        with self._lock:
            boss = self._boss(boss_id)
            self._reject_ejected(boss)
            if boss.status != _STATUS_ENGAGED:
                raise RecoveryError(
                    "RECOVERY_NOT_ENGAGED",
                    {"boss_id": boss_id, "status": boss.status},
                )

            if not self._is_integer(amount) or amount < 0:
                raise RecoveryError(
                    "RECOVERY_INVALID_DAMAGE",
                    {"boss_id": boss_id, "amount": amount},
                )
            if not isinstance(source, str) or not source:
                raise RecoveryError(
                    "RECOVERY_INVALID_DAMAGE",
                    {"boss_id": boss_id, "source": source},
                )

            boss.hp = max(0, boss.hp - amount)
            boss.threat[source] = boss.threat.get(source, 0) + amount
            threat_total = boss.threat[source]
            return DamageResult(
                boss_id=boss_id,
                accepted=True,
                code="OK",
                remaining_hp=boss.hp,
                threat_total=threat_total,
            )

    def wipe(self, boss_id: str) -> BossProgress:
        with self._lock:
            boss = self._boss(boss_id)
            self._reject_ejected(boss)

            if boss.status == _STATUS_RECOVERING:
                return self._progress_view(boss)
            if boss.status == _STATUS_CLEARED:
                raise RecoveryError(
                    "RECOVERY_BOSS_CLEARED",
                    {"boss_id": boss_id, "status": boss.status},
                )
            if boss.status != _STATUS_ENGAGED:
                raise RecoveryError(
                    "RECOVERY_NOT_ENGAGED",
                    {"boss_id": boss_id, "status": boss.status},
                )

            boss.consecutive_wipes += 1
            boss.total_wipes += 1
            boss.attempts_left = max(0, boss.attempts_left - 1)
            self._counters["wipes"] += 1

            if boss.attempts_left == 0:
                boss.status = _STATUS_EJECTED
            else:
                boss.status = _STATUS_RECOVERING
            return self._progress_view(boss)

    def recover(self, boss_id: str) -> RecoveryOutcome:
        with self._lock:
            boss = self._boss(boss_id)
            self._reject_ejected(boss)
            if boss.status != _STATUS_RECOVERING:
                raise RecoveryError(
                    "RECOVERY_NOT_RECOVERING",
                    {"boss_id": boss_id, "status": boss.status},
                )

            restored_hp = boss.checkpoint_hp
            restored_phase = boss.checkpoint_phase
            cleared_buffs = tuple(boss.buffs)
            cleared_summons = tuple(boss.summons)

            boss.hp = restored_hp
            boss.phase = restored_phase
            boss.buffs.clear()
            boss.summons.clear()
            boss.status = _STATUS_ENGAGED
            self._counters["recovers"] += 1

            return RecoveryOutcome(
                boss_id=boss_id,
                restored_hp=restored_hp,
                restored_phase=restored_phase,
                cleared_buffs=cleared_buffs,
                cleared_summons=cleared_summons,
                attempts_left=boss.attempts_left,
                ejected=False,
            )

    def mark_clear(self, boss_id: str) -> BossProgress:
        with self._lock:
            boss = self._boss(boss_id)
            self._reject_ejected(boss)
            if boss.status == _STATUS_CLEARED:
                return self._progress_view(boss)
            if boss.status not in (_STATUS_ENGAGED, _STATUS_RECOVERING):
                raise RecoveryError(
                    "RECOVERY_NOT_ENGAGED",
                    {"boss_id": boss_id, "status": boss.status},
                )

            boss.status = _STATUS_CLEARED
            boss.attempts_left = 0
            self._counters["clears"] += 1
            return self._progress_view(boss)

    def progress_of(self, boss_id: str) -> BossProgress:
        with self._lock:
            return self._progress_view(self._boss(boss_id))

    def attempts_left(self, boss_id: str) -> int:
        with self._lock:
            return self._boss(boss_id).attempts_left

    def threat_of(self, boss_id: str) -> tuple[tuple[str, int], ...]:
        with self._lock:
            boss = self._boss(boss_id)
            return tuple(boss.threat.items())

    def reset_instance(self) -> dict:
        with self._lock:
            bosses = len(self._bosses)
            wipes_cleared = sum(
                boss.total_wipes for boss in self._bosses.values()
            )
            self._bosses.clear()
            self._counters["resets"] += 1
            return {"bosses": bosses, "wipes_cleared": wipes_cleared}

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": _SNAPSHOT_VERSION,
                "bosses": {
                    boss_id: self._boss_snapshot(boss)
                    for boss_id, boss in self._bosses.items()
                },
                "counters": dict(self._counters),
            }
            return deepcopy(state)

    def restore(self, state: dict) -> None:
        try:
            frozen = deepcopy(state)
            bosses, counters = self._parse_snapshot(frozen)
        except RecoveryError:
            raise
        except _SnapshotInvalid as exc:
            raise RecoveryError(
                "RECOVERY_SNAPSHOT_INVALID", {"reason": str(exc)}
            ) from exc
        except Exception as exc:
            raise RecoveryError(
                "RECOVERY_SNAPSHOT_INVALID", {"reason": str(exc)}
            ) from exc

        with self._lock:
            self._bosses = bosses
            self._counters = counters

    def stats(self) -> dict:
        with self._lock:
            status_counts = {status: 0 for status in _STATUSES}
            for boss in self._bosses.values():
                status_counts[boss.status] += 1

            return {
                "bosses": len(self._bosses),
                "engaged": status_counts[_STATUS_ENGAGED],
                "recovering": status_counts[_STATUS_RECOVERING],
                "cleared": status_counts[_STATUS_CLEARED],
                "ejected": status_counts[_STATUS_EJECTED],
                "wipes": self._counters["wipes"],
                "recovers": self._counters["recovers"],
                "clears": self._counters["clears"],
                "resets": self._counters["resets"],
            }

    @staticmethod
    def _is_integer(value: Any) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _require_integer(cls, value: Any, field_name: str) -> None:
        if not cls._is_integer(value):
            raise RecoveryError(
                "RECOVERY_INVALID_REQUEST",
                {"field": field_name, "value": value},
            )

    @classmethod
    def _require_positive_int(cls, value: Any, field_name: str) -> None:
        cls._require_integer(value, field_name)
        if value <= 0:
            raise RecoveryError(
                "RECOVERY_INVALID_REQUEST",
                {"field": field_name, "value": value},
            )

    def _boss(self, boss_id: str) -> _BossState:
        boss = self._bosses.get(boss_id)
        if boss is None:
            raise RecoveryError(
                "RECOVERY_BOSS_UNKNOWN", {"boss_id": boss_id}
            )
        return boss

    @staticmethod
    def _reject_ejected(boss: _BossState) -> None:
        if boss.status == _STATUS_EJECTED:
            raise RecoveryError(
                "RECOVERY_EJECTED",
                {"boss_id": boss.boss_id, "attempts_left": 0},
            )

    @staticmethod
    def _require_engaged(boss: _BossState) -> None:
        if boss.status != _STATUS_ENGAGED:
            raise RecoveryError(
                "RECOVERY_NOT_ENGAGED",
                {"boss_id": boss.boss_id, "status": boss.status},
            )

    @staticmethod
    def _progress_view(boss: _BossState) -> BossProgress:
        return BossProgress(
            boss_id=boss.boss_id,
            hp=boss.hp,
            hp_max=boss.hp_max,
            phase=boss.phase,
            status=boss.status,
            consecutive_wipes=boss.consecutive_wipes,
            total_wipes=boss.total_wipes,
            attempts_left=boss.attempts_left,
            checkpoint_hp=boss.checkpoint_hp,
            checkpoint_phase=boss.checkpoint_phase,
            buffs=tuple(boss.buffs),
            summons=tuple(boss.summons),
        )

    @staticmethod
    def _boss_snapshot(boss: _BossState) -> dict:
        return {
            "boss_id": boss.boss_id,
            "hp": boss.hp,
            "hp_max": boss.hp_max,
            "phase": boss.phase,
            "status": boss.status,
            "consecutive_wipes": boss.consecutive_wipes,
            "total_wipes": boss.total_wipes,
            "attempts_left": boss.attempts_left,
            "checkpoint_hp": boss.checkpoint_hp,
            "checkpoint_phase": boss.checkpoint_phase,
            "buffs": list(boss.buffs),
            "summons": list(boss.summons),
            "threat": dict(boss.threat),
        }

    @classmethod
    def _parse_snapshot(
        cls, state: Any
    ) -> tuple[dict[str, _BossState], dict[str, int]]:
        if not isinstance(state, dict):
            raise _SnapshotInvalid("state must be a mapping")
        if set(state) != {"version", "bosses", "counters"}:
            raise _SnapshotInvalid("top-level keys are invalid")
        if state.get("version") != _SNAPSHOT_VERSION:
            raise _SnapshotInvalid("unsupported snapshot version")

        raw_bosses = state["bosses"]
        raw_counters = state["counters"]
        if not isinstance(raw_bosses, dict):
            raise _SnapshotInvalid("bosses must be a mapping")
        if not isinstance(raw_counters, dict):
            raise _SnapshotInvalid("counters must be a mapping")
        if set(raw_counters) != set(_COUNTER_KEYS):
            raise _SnapshotInvalid("counters are invalid")

        counters = {
            key: cls._non_negative_int(raw_counters.get(key), key)
            for key in _COUNTER_KEYS
        }

        boss_fields = {
            "boss_id",
            "hp",
            "hp_max",
            "phase",
            "status",
            "consecutive_wipes",
            "total_wipes",
            "attempts_left",
            "checkpoint_hp",
            "checkpoint_phase",
            "buffs",
            "summons",
            "threat",
        }
        bosses: dict[str, _BossState] = {}
        for boss_id, raw_boss in raw_bosses.items():
            if not isinstance(boss_id, str):
                raise _SnapshotInvalid("boss id must be a string")
            if not isinstance(raw_boss, dict):
                raise _SnapshotInvalid(f"boss {boss_id!r} must be a mapping")
            if set(raw_boss) != boss_fields:
                raise _SnapshotInvalid(f"boss {boss_id!r} fields are invalid")
            if raw_boss["boss_id"] != boss_id:
                raise _SnapshotInvalid(f"boss {boss_id!r} id mismatch")

            status = raw_boss["status"]
            if status not in _STATUSES:
                raise _SnapshotInvalid(f"boss {boss_id!r} status is invalid")

            hp = cls._non_negative_int(raw_boss["hp"], "hp")
            hp_max = cls._positive_int(raw_boss["hp_max"], "hp_max")
            phase = cls._positive_int(raw_boss["phase"], "phase")
            checkpoint_phase = cls._positive_int(
                raw_boss["checkpoint_phase"], "checkpoint_phase"
            )
            checkpoint_hp = cls._non_negative_int(
                raw_boss["checkpoint_hp"], "checkpoint_hp"
            )
            consecutive_wipes = cls._non_negative_int(
                raw_boss["consecutive_wipes"], "consecutive_wipes"
            )
            total_wipes = cls._non_negative_int(
                raw_boss["total_wipes"], "total_wipes"
            )
            attempts_left = cls._non_negative_int(
                raw_boss["attempts_left"], "attempts_left"
            )
            if consecutive_wipes > total_wipes:
                raise _SnapshotInvalid(
                    f"boss {boss_id!r} wipe counters are inconsistent"
                )

            buffs = cls._string_list(raw_boss["buffs"], "buffs")
            summons = cls._string_list(raw_boss["summons"], "summons")
            raw_threat = raw_boss["threat"]
            if not isinstance(raw_threat, dict):
                raise _SnapshotInvalid("threat must be a mapping")
            threat = {}
            for source, value in raw_threat.items():
                if not isinstance(source, str):
                    raise _SnapshotInvalid("threat source must be a string")
                threat[source] = cls._non_negative_int(value, "threat")

            bosses[boss_id] = _BossState(
                boss_id=boss_id,
                hp=hp,
                hp_max=hp_max,
                phase=phase,
                status=status,
                consecutive_wipes=consecutive_wipes,
                total_wipes=total_wipes,
                attempts_left=attempts_left,
                checkpoint_hp=checkpoint_hp,
                checkpoint_phase=checkpoint_phase,
                buffs=buffs,
                summons=summons,
                threat=threat,
            )

        return bosses, counters

    @classmethod
    def _non_negative_int(cls, value: Any, field_name: str) -> int:
        if not cls._is_integer(value) or value < 0:
            raise _SnapshotInvalid(f"{field_name} must be a non-negative int")
        return value

    @classmethod
    def _positive_int(cls, value: Any, field_name: str) -> int:
        if not cls._is_integer(value) or value <= 0:
            raise _SnapshotInvalid(f"{field_name} must be a positive int")
        return value

    @classmethod
    def _string_list(cls, value: Any, field_name: str) -> list[str]:
        if not isinstance(value, list) or not all(
            isinstance(item, str) for item in value
        ):
            raise _SnapshotInvalid(f"{field_name} must be a list of strings")
        return list(value)
