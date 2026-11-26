"""Death and resurrection ledger: costs, cooldowns, soul penalty stacks and requests."""

from __future__ import annotations

import threading


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

    def register_character(self, character: str, *, gold: int = 0, now=None) -> dict:
        raise NotImplementedError

    def state_of(self, character: str) -> dict:
        raise NotImplementedError

    def die(self, character: str, now=None) -> dict:
        raise NotImplementedError

    def resurrect(self, character: str, mode: str, now=None) -> dict:
        raise NotImplementedError

    def request_help(self, target: str, helper: str, now=None) -> dict:
        raise NotImplementedError

    def pending_request(self, target: str):
        raise NotImplementedError

    def cancel_request(self, target: str) -> bool:
        raise NotImplementedError

    def penalty_of(self, character: str, now=None) -> dict:
        raise NotImplementedError

    def cooldown_of(self, character: str, mode: str, now=None) -> int:
        raise NotImplementedError

    def expire_penalty(self, now=None) -> int:
        raise NotImplementedError

    def mark_offline(self, character: str, now=None) -> dict:
        raise NotImplementedError

    def mark_online(self, character: str, now=None) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
