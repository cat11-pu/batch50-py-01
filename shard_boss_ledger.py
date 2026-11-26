"""Sharded world boss ledger: segment dedupe, shared hp, freeze and shard merge."""

from __future__ import annotations

import copy
import math
import threading


_SNAPSHOT_VERSION = 1
_BOSS_FIELDS = ("hp", "max_hp", "phase", "status", "killer", "segments",
                "damage")
_STAT_FIELDS = ("registered", "segments", "duplicates", "damage", "overkill",
                "freezes", "merged")
_UNSET = object()


class ShardError(ValueError):
    """Raised when a boss ledger operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _is_int(value: object) -> bool:
    return type(value) is int


def _is_positive_int(value: object) -> bool:
    return _is_int(value) and value > 0


def _is_nonnegative_int(value: object) -> bool:
    return _is_int(value) and value >= 0


class ShardBossLedger:
    """Aggregate per-shard damage segments into one boss hp ledger."""

    def __init__(self, *, max_hp: int = 100000, phase2_at: float = 0.5) -> None:
        if not _is_positive_int(max_hp):
            raise ShardError("SHARD_INVALID_REQUEST",
                             {"field": "max_hp", "value": max_hp})
        if (isinstance(phase2_at, bool)
                or not isinstance(phase2_at, (int, float))
                or not math.isfinite(phase2_at)):
            raise ShardError("SHARD_INVALID_REQUEST",
                             {"field": "phase2_at", "value": phase2_at})

        self.max_hp = max_hp
        self.phase2_at = phase2_at
        self._lock = threading.RLock()
        self._shards: dict[str, dict[int, int]] = {}
        self._hp = max_hp
        self._frozen = False
        self._killer = None
        self._stats = {
            "registered": 0,
            "segments": 0,
            "duplicates": 0,
            "damage": 0,
            "overkill": 0,
            "freezes": 0,
            "merged": 0,
        }

    @staticmethod
    def _normalize_shard_id(shard_id: object) -> str:
        if not isinstance(shard_id, str):
            raise ShardError("SHARD_INVALID_REQUEST",
                             {"field": "shard_id", "value": shard_id})
        normalized = shard_id.strip()
        if not normalized:
            raise ShardError("SHARD_INVALID_REQUEST",
                             {"field": "shard_id", "value": shard_id})
        return normalized

    def _phase_locked(self) -> str:
        if self._frozen:
            return "settlement"
        if self._hp > self.max_hp * self.phase2_at:
            return "phase-1"
        return "phase-2"

    def _status_locked(self) -> str:
        return "settlement" if self._frozen else "active"

    def _settle_locked(self, killer=_UNSET) -> None:
        if self._frozen:
            return
        self._frozen = True
        if killer is not _UNSET:
            self._killer = killer
        self._stats["freezes"] += 1

    @staticmethod
    def _snapshot_invalid(detail: object = None) -> ShardError:
        return ShardError("SHARD_SNAPSHOT_INVALID", detail)

    def register_shard(self, shard_id: str) -> dict:
        shard_id = self._normalize_shard_id(shard_id)
        with self._lock:
            if shard_id in self._shards:
                raise ShardError("SHARD_INVALID_REQUEST",
                                 {"shard_id": shard_id,
                                  "reason": "already registered"})
            self._shards[shard_id] = {}
            self._stats["registered"] = len(self._shards)
            return {"shard_id": shard_id, "segments": 0, "damage": 0,
                    "max_seq": 0}

    def shard_report(self, shard_id: str) -> dict:
        shard_id = self._normalize_shard_id(shard_id)
        with self._lock:
            segments = self._shards.get(shard_id)
            if segments is None:
                raise ShardError("SHARD_UNKNOWN_SHARD",
                                 {"shard_id": shard_id})
            return {
                "shard_id": shard_id,
                "segments": len(segments),
                "damage": sum(segments.values()),
                "max_seq": max(segments, default=0),
            }

    def apply_damage(self, shard_id: str, segment_seq: int, damage: int, *,
                     actor=None) -> dict:
        if not _is_positive_int(segment_seq):
            raise ShardError("SHARD_INVALID_REQUEST",
                             {"field": "segment_seq", "value": segment_seq})
        if not _is_positive_int(damage):
            raise ShardError("SHARD_INVALID_REQUEST",
                             {"field": "damage", "value": damage})

        shard_id = self._normalize_shard_id(shard_id)
        with self._lock:
            segments = self._shards.get(shard_id)
            if segments is None:
                raise ShardError("SHARD_UNKNOWN_SHARD",
                                 {"shard_id": shard_id})
            if segment_seq in segments:
                self._stats["duplicates"] += 1
                raise ShardError(
                    "SHARD_DUPLICATE_SEGMENT",
                    {"shard_id": shard_id, "segment_seq": segment_seq},
                )

            segments[segment_seq] = damage
            self._stats["segments"] += 1
            self._stats["damage"] += damage

            if self._frozen:
                self._stats["overkill"] += damage
            else:
                applied = min(damage, self._hp)
                self._hp -= applied
                self._stats["overkill"] += damage - applied
                if self._hp == 0:
                    self._settle_locked(killer=actor)

            return {
                "shard_id": shard_id,
                "segment_seq": segment_seq,
                "accepted": True,
                "damage": damage,
                "hp": self._hp,
                "phase": self._phase_locked(),
                "status": self._status_locked(),
            }

    def freeze(self, reason: str = "manual") -> dict:
        with self._lock:
            self._settle_locked()
            return {
                "status": self._status_locked(),
                "phase": self._phase_locked(),
                "frozen_shards": self.frozen_shards(),
            }

    def merge_shards(self, source: str, target: str) -> dict:
        source = self._normalize_shard_id(source)
        target = self._normalize_shard_id(target)
        with self._lock:
            if self._frozen:
                raise ShardError("SHARD_BOSS_FROZEN")
            if source == target:
                raise ShardError("SHARD_INVALID_REQUEST",
                                 {"source": source, "target": target})
            if source not in self._shards or target not in self._shards:
                raise ShardError("SHARD_UNKNOWN_SHARD",
                                 {"source": source, "target": target})

            source_segments = self._shards[source]
            target_segments = self._shards[target]
            moved = 0
            skipped = 0
            for segment_seq, damage in source_segments.items():
                if segment_seq in target_segments:
                    skipped += 1
                else:
                    target_segments[segment_seq] = damage
                    moved += 1

            del self._shards[source]
            self._stats["registered"] = len(self._shards)
            self._stats["merged"] += 1
            return {
                "source": source,
                "target": target,
                "moved": moved,
                "skipped": skipped,
            }

    def boss_state(self) -> dict:
        with self._lock:
            return {
                "hp": self._hp,
                "max_hp": self.max_hp,
                "phase": self._phase_locked(),
                "status": self._status_locked(),
                "killer": self._killer,
                "segments": self._stats["segments"],
                "damage": self._stats["damage"],
            }

    def frozen_shards(self) -> list:
        with self._lock:
            if not self._frozen:
                return []
            return sorted(self._shards)

    def snapshot(self) -> dict:
        with self._lock:
            shards = {
                shard_id: {
                    "segments": dict(segments),
                    "max_seq": max(segments, default=0),
                }
                for shard_id, segments in self._shards.items()
            }
            boss = self.boss_state()
            if self.phase2_at != 0.5:
                boss["phase2_at"] = self.phase2_at
            return copy.deepcopy({
                "version": _SNAPSHOT_VERSION,
                "boss": boss,
                "shards": shards,
                "frozen": self.frozen_shards(),
                "stats": self.stats(),
            })

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._parse_snapshot(state)
            except ShardError:
                raise
            except Exception as exc:
                raise self._snapshot_invalid(str(exc)) from exc

            self.max_hp = restored["max_hp"]
            self.phase2_at = restored["phase2_at"]
            self._hp = restored["hp"]
            self._frozen = restored["frozen"]
            self._killer = restored["killer"]
            self._shards = restored["shards"]
            self._stats = restored["stats"]

    def _parse_snapshot(self, state: object) -> dict:
        if not isinstance(state, dict):
            raise self._snapshot_invalid("snapshot must be a dict")
        required = {"version", "boss", "shards", "frozen", "stats"}
        if set(state) != required:
            raise self._snapshot_invalid("invalid snapshot keys")
        if not _is_int(state["version"]) or state["version"] != _SNAPSHOT_VERSION:
            raise self._snapshot_invalid("unsupported snapshot version")

        boss = state["boss"]
        if not isinstance(boss, dict):
            raise self._snapshot_invalid("boss must be a dict")
        if any(field not in boss for field in _BOSS_FIELDS):
            raise self._snapshot_invalid("boss is missing fields")

        max_hp = boss["max_hp"]
        phase2_at = boss.get("phase2_at", self.phase2_at)
        hp = boss["hp"]
        boss_segments = boss["segments"]
        boss_damage = boss["damage"]
        status = boss["status"]
        phase = boss["phase"]
        if not _is_positive_int(max_hp):
            raise self._snapshot_invalid("invalid max_hp")
        if (isinstance(phase2_at, bool)
                or not isinstance(phase2_at, (int, float))
                or not math.isfinite(phase2_at)):
            raise self._snapshot_invalid("invalid phase2_at")
        if not _is_nonnegative_int(hp) or hp > max_hp:
            raise self._snapshot_invalid("invalid hp")
        if not _is_nonnegative_int(boss_segments):
            raise self._snapshot_invalid("invalid boss segments")
        if not _is_nonnegative_int(boss_damage):
            raise self._snapshot_invalid("invalid boss damage")
        if status not in ("active", "settlement"):
            raise self._snapshot_invalid("invalid boss status")
        if phase not in ("phase-1", "phase-2", "settlement"):
            raise self._snapshot_invalid("invalid boss phase")

        frozen = status == "settlement"
        if frozen:
            if phase != "settlement":
                raise self._snapshot_invalid("frozen boss must be settled")
        else:
            if hp == 0:
                raise self._snapshot_invalid("active boss cannot have zero hp")
            expected_phase = ("phase-1"
                              if hp > max_hp * phase2_at
                              else "phase-2")
            if phase != expected_phase:
                raise self._snapshot_invalid("boss phase mismatch")

        raw_shards = state["shards"]
        if not isinstance(raw_shards, dict):
            raise self._snapshot_invalid("shards must be a dict")
        shards: dict[str, dict[int, int]] = {}
        for raw_id, raw_record in raw_shards.items():
            if not isinstance(raw_id, str) or not raw_id.strip():
                raise self._snapshot_invalid("invalid shard id")
            shard_id = raw_id.strip()
            if shard_id != raw_id or shard_id in shards:
                raise self._snapshot_invalid("invalid shard id")
            if not isinstance(raw_record, dict):
                raise self._snapshot_invalid("invalid shard record")
            if "segments" not in raw_record or "max_seq" not in raw_record:
                raise self._snapshot_invalid("shard record is missing fields")
            raw_segments = raw_record["segments"]
            max_seq = raw_record["max_seq"]
            if not isinstance(raw_segments, dict):
                raise self._snapshot_invalid("segments must be a dict")
            if not _is_nonnegative_int(max_seq):
                raise self._snapshot_invalid("invalid max_seq")

            segments: dict[int, int] = {}
            for raw_seq, damage in raw_segments.items():
                if _is_int(raw_seq):
                    segment_seq = raw_seq
                elif (isinstance(raw_seq, str) and raw_seq.isascii()
                      and raw_seq.isdigit()):
                    segment_seq = int(raw_seq)
                else:
                    raise self._snapshot_invalid("invalid segment sequence")
                if (not _is_positive_int(segment_seq)
                        or not _is_positive_int(damage)
                        or segment_seq in segments):
                    raise self._snapshot_invalid("invalid segment")
                segments[segment_seq] = damage

            actual_max = max(segments, default=0)
            if max_seq != actual_max:
                raise self._snapshot_invalid("max_seq mismatch")
            shards[shard_id] = segments

        raw_frozen = state["frozen"]
        if not isinstance(raw_frozen, list):
            raise self._snapshot_invalid("frozen must be a list")
        if any(not isinstance(shard_id, str) for shard_id in raw_frozen):
            raise self._snapshot_invalid("invalid frozen shard id")
        if frozen:
            valid_frozen = raw_frozen == sorted(shards)
        else:
            valid_frozen = raw_frozen == []
        if not valid_frozen:
            raise self._snapshot_invalid("frozen shards mismatch")

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict):
            raise self._snapshot_invalid("stats must be a dict")
        if any(field not in raw_stats for field in _STAT_FIELDS):
            raise self._snapshot_invalid("stats is missing fields")
        stats = {}
        for field in _STAT_FIELDS:
            value = raw_stats[field]
            if not _is_nonnegative_int(value):
                raise self._snapshot_invalid(f"invalid stat {field}")
            stats[field] = value

        if stats["registered"] != len(shards):
            raise self._snapshot_invalid("registered count mismatch")
        if stats["segments"] != boss_segments:
            raise self._snapshot_invalid("segment count mismatch")
        if stats["damage"] != boss_damage:
            raise self._snapshot_invalid("damage mismatch")
        if frozen:
            if stats["freezes"] < 1:
                raise self._snapshot_invalid("settled boss has no freeze")
        else:
            if stats["freezes"] != 0 or boss["killer"] is not None:
                raise self._snapshot_invalid("active boss has settlement data")

        return {
            "max_hp": max_hp,
            "phase2_at": phase2_at,
            "hp": hp,
            "frozen": frozen,
            "killer": copy.deepcopy(boss["killer"]),
            "shards": shards,
            "stats": stats,
        }

    def stats(self) -> dict:
        with self._lock:
            return {
                "registered": len(self._shards),
                "segments": self._stats["segments"],
                "duplicates": self._stats["duplicates"],
                "damage": self._stats["damage"],
                "overkill": self._stats["overkill"],
                "freezes": self._stats["freezes"],
                "merged": self._stats["merged"],
            }
