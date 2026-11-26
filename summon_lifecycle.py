"""Battle summon lifecycle ledger: owner caps, remaining time, cooldowns, offline reaping."""

from __future__ import annotations

import threading


class SummonError(ValueError):
    """Raised when a summon operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class SummonLifecycle:
    """Register combat summons, advance their clocks, and reap offline owners."""

    def __init__(self, *, per_owner_cap: int = 3, offline_grace: int = 30,
                 default_ttl: int = 60, default_cooldown: int = 10,
                 cooldowns=None) -> None:
        self.per_owner_cap = per_owner_cap
        self.offline_grace = offline_grace
        self.default_ttl = default_ttl
        self.default_cooldown = default_cooldown
        self.cooldowns = dict(cooldowns or {})
        self._lock = threading.RLock()

    def summon(self, owner: str, kind: str, *, ttl=None, inherit: float = 1.0,
               now=None) -> dict:
        raise NotImplementedError

    def dismiss(self, owner: str, summon_id: str) -> bool:
        raise NotImplementedError

    def tick(self, seconds: int) -> list:
        raise NotImplementedError

    def transfer_owner(self, summon_id: str, new_owner: str, now=None) -> dict:
        raise NotImplementedError

    def list_of(self, owner: str) -> list:
        raise NotImplementedError

    def remaining_of(self, summon_id: str) -> int:
        raise NotImplementedError

    def cooldown_of(self, owner: str, kind: str) -> int:
        raise NotImplementedError

    def owner_offline(self, owner: str, now=None) -> dict:
        raise NotImplementedError

    def owner_online(self, owner: str, now=None) -> dict:
        raise NotImplementedError

    def reap_owner(self, owner: str, now=None) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
