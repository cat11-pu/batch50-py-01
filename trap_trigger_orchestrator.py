"""Trap trigger orchestrator for dungeon instances.

Keeps the deployment state of dungeon traps: charge counts, trigger radius,
per-player cooldowns and the instance-level one-shot flag.  A single
:meth:`TrapTriggerOrchestrator.trigger` call is one game frame; players are
resolved in arrival order, charges are consumed per successful trigger and a
wipe reset only rearms traps that are marked resettable.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "TrapError",
    "TrapState",
    "TriggerOutcome",
    "TrapTriggerOrchestrator",
]


class TrapError(ValueError):
    """Raised when a trap operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TrapState:
    """Immutable view of one deployed trap."""

    trap_id: str
    charges: int
    initial_charges: int
    radius: int
    cooldown_frames: int
    one_shot: bool
    reset_on_wipe: bool
    armed: bool
    spent: bool


@dataclass(frozen=True)
class TriggerOutcome:
    """Per-player result of one frame resolution."""

    trap_id: str
    player: str
    status: str
    frame: int


class TrapTriggerOrchestrator:
    """Resolve trap triggers frame by frame under charges and cooldowns."""

    def __init__(self, *, max_traps: int = 16) -> None:
        self.max_traps = max_traps
        self._lock = threading.RLock()

    def register_trap(self, trap_id: str, *, charges: int, radius: int,
                      cooldown_frames: int = 0, one_shot: bool = False,
                      reset_on_wipe: bool = True) -> TrapState:
        """Deploy a trap with a charge budget, trigger radius and cooldown."""
        raise NotImplementedError

    def register_player(self, player_id: str) -> None:
        """Register a player that may step on traps."""
        raise NotImplementedError

    def arm(self, trap_id: str) -> TrapState:
        """Arm a deployed trap so it can trigger."""
        raise NotImplementedError

    def disarm(self, trap_id: str) -> TrapState:
        """Disarm a trap so further triggers are refused."""
        raise NotImplementedError

    def trigger(self, trap_id: str,
                arrivals: list[str]) -> tuple[TriggerOutcome, ...]:
        """Resolve one frame with *arrivals* stepping on the trap in order."""
        raise NotImplementedError

    def reset_instance(self) -> dict:
        """Run a wipe reset and rearm the traps marked as resettable."""
        raise NotImplementedError

    def charges_of(self, trap_id: str) -> int:
        """Return the charge count left on a trap."""
        raise NotImplementedError

    def cooldown_of(self, trap_id: str, player_id: str) -> int:
        """Return the frames a player still has to wait for that trap."""
        raise NotImplementedError

    def rearmable(self, trap_id: str) -> bool:
        """Return whether the trap is restored by a wipe reset."""
        raise NotImplementedError

    def trap_state(self, trap_id: str) -> TrapState:
        """Return an immutable view of the trap deployment state."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a deep copy of traps, players, frames and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace orchestrator state with a snapshot, validating it."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative counters for triggers, rejects and resets."""
        raise NotImplementedError
