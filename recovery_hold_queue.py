"""Delayed account recovery: hold queue, multi-channel confirmation, veto and release."""

from __future__ import annotations

import threading


class RecoveryError(ValueError):
    """Refused recovery operation carrying a stable machine-readable code."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class RecoveryHoldQueue:
    """Hold self-service account recovery requests until the waiting period elapses."""

    def __init__(self, *, hold_seconds: int = 172800, confirmations_required: int = 2,
                 max_channels: int = 3, clock=None) -> None:
        self.hold_seconds = hold_seconds
        self.confirmations_required = confirmations_required
        self.max_channels = max_channels
        self._clock = clock
        self._lock = threading.RLock()

    def request(self, account_id: str, channels, *,
                now: int | None = None) -> dict:
        raise NotImplementedError

    def confirm_contact(self, hold_id: str, channel: str, token: str, *,
                        now: int | None = None) -> dict:
        raise NotImplementedError

    def veto(self, hold_id: str, actor: str, reason: str, *,
             now: int | None = None) -> dict:
        raise NotImplementedError

    def release(self, hold_id: str, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def status(self, hold_id: str, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def due_holds(self, *, now: int | None = None) -> list[str]:
        raise NotImplementedError

    def sweep(self, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def hold_view(self, hold_id: str) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
