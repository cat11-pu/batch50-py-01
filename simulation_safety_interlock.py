"""Safety interlock for attack simulation runs: scope check, rate budget, trip and cooldown."""

from __future__ import annotations


class InterlockError(ValueError):
    """Raised when an interlock operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATE_IDLE = "idle"
STATE_ARMED = "armed"
STATE_TRIPPED = "tripped"
STATE_COOLING = "cooling"

RUN_ARMED = "armed"
RUN_DISARMED = "disarmed"
RUN_TRIPPED = "tripped"

PERMIT_IN_FLIGHT = "in_flight"
PERMIT_COMPLETED = "completed"
PERMIT_FAILED = "failed"
PERMIT_VOIDED = "voided"

SETTLE_OUTCOMES = ("ok", "failed")


class SimulationSafetyInterlock:
    """Gate simulated actions by authorized scope, token budget and a global trip switch."""

    def __init__(self, *, global_rate: int = 20, per_target_rate: int = 5,
                 window_seconds: int = 10, cooldown_seconds: int = 60) -> None:
        self.global_rate = global_rate
        self.per_target_rate = per_target_rate
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

    def register_scope(self, scope_id: str, *, cidrs) -> dict:
        raise NotImplementedError

    def arm(self, run_id: str, *, scope_id: str, now: int) -> dict:
        raise NotImplementedError

    def disarm(self, run_id: str, *, now: int) -> dict:
        raise NotImplementedError

    def check_action(self, run_id: str, *, action_id: str, target: str,
                     now: int) -> dict:
        raise NotImplementedError

    def finish_action(self, permit_id: str, *, outcome: str, now: int) -> dict:
        raise NotImplementedError

    def trip(self, *, reason: str, now: int) -> dict:
        raise NotImplementedError

    def reset(self, *, now: int) -> dict:
        raise NotImplementedError

    def status(self, *, now: int | None = None) -> dict:
        raise NotImplementedError

    def permits(self, *, run_id: str | None = None) -> tuple:
        raise NotImplementedError

    def report(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
