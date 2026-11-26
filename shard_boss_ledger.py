"""Sharded world boss ledger: segment dedupe, shared hp, freeze and shard merge."""

from __future__ import annotations

import threading


class ShardError(ValueError):
    """Raised when a boss ledger operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class ShardBossLedger:
    """Aggregate per-shard damage segments into one boss hp ledger."""

    def __init__(self, *, max_hp: int = 100000, phase2_at: float = 0.5) -> None:
        self.max_hp = max_hp
        self.phase2_at = phase2_at
        self._lock = threading.RLock()

    def register_shard(self, shard_id: str) -> dict:
        raise NotImplementedError

    def shard_report(self, shard_id: str) -> dict:
        raise NotImplementedError

    def apply_damage(self, shard_id: str, segment_seq: int, damage: int, *,
                     actor=None) -> dict:
        raise NotImplementedError

    def freeze(self, reason: str = "manual") -> dict:
        raise NotImplementedError

    def merge_shards(self, source: str, target: str) -> dict:
        raise NotImplementedError

    def boss_state(self) -> dict:
        raise NotImplementedError

    def frozen_shards(self) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
