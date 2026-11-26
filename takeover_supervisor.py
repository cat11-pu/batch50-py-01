"""Disconnect takeover supervision: grace window, per-frame action budget, handback."""

from __future__ import annotations

import threading


class TakeoverError(ValueError):
    """Raised when a supervision operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class TakeoverSupervisor:
    """Hand characters to a temporary supervisor while their player is offline."""

    def __init__(self, *, grace_ticks: int = 5, frame_budget: int = 3,
                 max_pending: int = 8,
                 default_actions=("move", "dodge", "guard")) -> None:
        self.grace_ticks = grace_ticks
        self.frame_budget = frame_budget
        self.max_pending = max_pending
        self.default_actions = tuple(default_actions)
        self._lock = threading.RLock()

    def register_character(self, character: str, *, actions=None) -> dict:
        raise NotImplementedError

    def mark_offline(self, character: str, now=None) -> dict:
        raise NotImplementedError

    def heartbeat(self, character: str, now=None) -> dict:
        raise NotImplementedError

    def takeover(self, character: str, now=None) -> dict:
        raise NotImplementedError

    def execute(self, character: str, action: str, now=None) -> dict:
        raise NotImplementedError

    def handback(self, character: str, now=None) -> dict:
        raise NotImplementedError

    def state_of(self, character: str) -> dict:
        raise NotImplementedError

    def pending_actions(self, character: str) -> list:
        raise NotImplementedError

    def submit_input(self, character: str, action: str) -> dict:
        raise NotImplementedError

    def advance_frame(self, frames: int = 1) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
