"""Disclosure embargo clock: acknowledgement, fix deadline, extensions, lift gate."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class EmbargoError(ValueError):
    """Raised when an embargo operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATE_REPORTED = "reported"
STATE_ACKNOWLEDGED = "acknowledged"
STATE_LIFTED = "embargo_lifted"


@dataclass(frozen=True)
class AdvisoryState:
    advisory_id: str
    product: str
    state: str
    reported_at: str
    acknowledged_at: str | None
    fix_due: str | None
    lifted_at: str | None
    extensions_used: int
    extension_days: int
    public_approved: bool
    public_actor: str | None


class DisclosureEmbargoClock:
    """Track coordinated disclosure deadlines, extension budgets and lift gates."""

    def __init__(self, *, max_extensions: int = 2,
                 max_total_days: int = 90) -> None:
        self.max_extensions = max_extensions
        self.max_total_days = max_total_days
        self._lock = threading.RLock()
        self._advisories: dict[str, dict] = {}
        self._holidays: set[str] = set()
        self._stats = {
            "opened": 0,
            "acknowledged": 0,
            "extended": 0,
            "lifted": 0,
            "extension_days": 0,
        }

    def set_holidays(self, days) -> int:
        raise NotImplementedError

    def is_business_day(self, day: str) -> bool:
        raise NotImplementedError

    def open(self, advisory_id: str, *, product: str, fix_window_days: int,
             reported_at: str) -> AdvisoryState:
        raise NotImplementedError

    def ack(self, advisory_id: str, *, now: str) -> AdvisoryState:
        raise NotImplementedError

    def extend(self, advisory_id: str, *, days: int, now: str) -> dict:
        raise NotImplementedError

    def request_public(self, advisory_id: str, *, actor: str, now: str) -> dict:
        raise NotImplementedError

    def lift(self, advisory_id: str, *, now: str) -> AdvisoryState:
        raise NotImplementedError

    def state_of(self, advisory_id: str) -> AdvisoryState:
        raise NotImplementedError

    def history(self, advisory_id: str) -> tuple:
        raise NotImplementedError

    def days_remaining(self, advisory_id: str, *, now: str) -> int:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
