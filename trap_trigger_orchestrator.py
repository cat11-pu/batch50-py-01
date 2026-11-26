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


@dataclass
class _TrapRecord:
    """Mutable internal representation of a deployed trap."""

    trap_id: str
    charges: int
    initial_charges: int
    radius: int
    cooldown_frames: int
    one_shot: bool
    reset_on_wipe: bool
    armed: bool = False
    spent: bool = False

    def public_state(self) -> TrapState:
        return TrapState(
            trap_id=self.trap_id,
            charges=self.charges,
            initial_charges=self.initial_charges,
            radius=self.radius,
            cooldown_frames=self.cooldown_frames,
            one_shot=self.one_shot,
            reset_on_wipe=self.reset_on_wipe,
            armed=self.armed,
            spent=self.spent,
        )


_COUNTER_NAMES = (
    "triggered",
    "cooldown_rejected",
    "depleted",
    "overflow",
    "resets",
    "arms",
    "disarms",
)


class TrapTriggerOrchestrator:
    """Resolve trap triggers frame by frame under charges and cooldowns."""

    def __init__(self, *, max_traps: int = 16) -> None:
        if not self._is_int(max_traps) or max_traps <= 0:
            raise TrapError("TRAP_INVALID_REQUEST", "max_traps")
        self.max_traps = max_traps
        self._lock = threading.RLock()
        self._traps: dict[str, _TrapRecord] = {}
        self._players: dict[str, None] = {}
        self._cooldowns: dict[str, dict[str, int]] = {}
        self._frame = 0
        self._counters = {name: 0 for name in _COUNTER_NAMES}

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _is_id(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    @staticmethod
    def _is_bool(value: object) -> bool:
        return isinstance(value, bool)

    def _require_trap(self, trap_id: str) -> _TrapRecord:
        if not self._is_id(trap_id) or trap_id not in self._traps:
            raise TrapError("TRAP_UNKNOWN_TRAP", trap_id)
        return self._traps[trap_id]

    def _require_player(self, player_id: str) -> None:
        if not self._is_id(player_id) or player_id not in self._players:
            raise TrapError("TRAP_UNKNOWN_PLAYER", player_id)

    def register_trap(self, trap_id: str, *, charges: int, radius: int,
                      cooldown_frames: int = 0, one_shot: bool = False,
                      reset_on_wipe: bool = True) -> TrapState:
        """Deploy a trap with a charge budget, trigger radius and cooldown."""
        if (
            not self._is_id(trap_id)
            or not self._is_int(charges)
            or charges <= 0
            or not self._is_int(radius)
            or radius <= 0
            or not self._is_int(cooldown_frames)
            or cooldown_frames < 0
            or not self._is_bool(one_shot)
            or not self._is_bool(reset_on_wipe)
        ):
            raise TrapError("TRAP_INVALID_REQUEST", trap_id)

        with self._lock:
            if trap_id in self._traps:
                raise TrapError("TRAP_DUPLICATE_TRAP", trap_id)
            if len(self._traps) >= self.max_traps:
                raise TrapError("TRAP_CAPACITY_EXCEEDED", self.max_traps)
            trap = _TrapRecord(
                trap_id=trap_id,
                charges=charges,
                initial_charges=charges,
                radius=radius,
                cooldown_frames=cooldown_frames,
                one_shot=one_shot,
                reset_on_wipe=reset_on_wipe,
            )
            self._traps[trap_id] = trap
            return trap.public_state()

    def register_player(self, player_id: str) -> None:
        """Register a player that may step on traps."""
        if not self._is_id(player_id):
            raise TrapError("TRAP_INVALID_REQUEST", player_id)
        with self._lock:
            if player_id in self._players:
                raise TrapError("TRAP_DUPLICATE_PLAYER", player_id)
            if len(self._players) >= self.max_traps:
                raise TrapError("TRAP_CAPACITY_EXCEEDED", self.max_traps)
            self._players[player_id] = None

    def arm(self, trap_id: str) -> TrapState:
        """Arm a deployed trap so it can trigger."""
        with self._lock:
            trap = self._require_trap(trap_id)
            if trap.one_shot and trap.spent:
                raise TrapError("TRAP_PERMANENTLY_SPENT", trap_id)
            if trap.armed:
                raise TrapError("TRAP_ALREADY_ARMED", trap_id)
            trap.armed = True
            self._counters["arms"] += 1
            return trap.public_state()

    def disarm(self, trap_id: str) -> TrapState:
        """Disarm a trap so further triggers are refused."""
        with self._lock:
            trap = self._require_trap(trap_id)
            if trap.armed:
                trap.armed = False
                self._counters["disarms"] += 1
            return trap.public_state()

    def trigger(self, trap_id: str,
                arrivals: list[str]) -> tuple[TriggerOutcome, ...]:
        """Resolve one frame with *arrivals* stepping on the trap in order."""
        if not isinstance(arrivals, (list, tuple)) or not arrivals:
            raise TrapError("TRAP_INVALID_REQUEST", "arrivals")
        if any(not self._is_id(player_id) for player_id in arrivals):
            raise TrapError("TRAP_INVALID_REQUEST", "arrivals")

        with self._lock:
            trap = self._require_trap(trap_id)
            if not trap.armed:
                raise TrapError("TRAP_NOT_ARMED", trap_id)
            for player_id in arrivals:
                self._require_player(player_id)

            self._frame += 1
            frame = self._frame

            # Cooldowns existing at frame start age once after the frame is
            # resolved.  A cooldown started by this frame retains its full
            # duration for the next frame.
            aging_cooldowns = tuple(
                (cooldown_trap, player_id, remaining)
                for cooldown_trap, players in self._cooldowns.items()
                for player_id, remaining in players.items()
                if remaining > 0
            )

            outcomes: list[TriggerOutcome] = []
            for index, player_id in enumerate(arrivals):
                if index >= trap.radius:
                    status = "overflow"
                    self._counters["overflow"] += 1
                elif trap.spent or trap.charges <= 0:
                    status = "depleted"
                    self._counters["depleted"] += 1
                else:
                    remaining = self._cooldowns.get(trap_id, {}).get(
                        player_id, 0)
                    if remaining > 0:
                        status = "cooldown"
                        self._counters["cooldown_rejected"] += 1
                    else:
                        status = "triggered"
                        if trap.one_shot:
                            trap.charges = 0
                            trap.spent = True
                            trap.armed = False
                        else:
                            trap.charges -= 1
                            if trap.charges == 0:
                                trap.armed = False
                        if trap.cooldown_frames > 0:
                            self._cooldowns.setdefault(
                                trap_id, {})[player_id] = (
                                    trap.cooldown_frames)
                        self._counters["triggered"] += 1

                outcomes.append(TriggerOutcome(
                    trap_id=trap_id,
                    player=player_id,
                    status=status,
                    frame=frame,
                ))

            for cooldown_trap, player_id, remaining in aging_cooldowns:
                players = self._cooldowns.get(cooldown_trap)
                if players is None or player_id not in players:
                    continue
                players[player_id] = remaining - 1
                if players[player_id] <= 0:
                    del players[player_id]
            for cooldown_trap in tuple(self._cooldowns):
                if not self._cooldowns[cooldown_trap]:
                    del self._cooldowns[cooldown_trap]

            return tuple(outcomes)

    def reset_instance(self) -> dict:
        """Run a wipe reset and rearm the traps marked as resettable."""
        with self._lock:
            restored = 0
            left_alone = 0
            for trap_id, trap in self._traps.items():
                if trap.reset_on_wipe and not trap.one_shot:
                    trap.charges = trap.initial_charges
                    trap.armed = True
                    trap.spent = False
                    self._cooldowns.pop(trap_id, None)
                    restored += 1
                else:
                    left_alone += 1
            self._counters["resets"] += 1
            return {
                "restored": restored,
                "left_alone": left_alone,
            }

    def charges_of(self, trap_id: str) -> int:
        """Return the charge count left on a trap."""
        with self._lock:
            return self._require_trap(trap_id).charges

    def cooldown_of(self, trap_id: str, player_id: str) -> int:
        """Return the frames a player still has to wait for that trap."""
        with self._lock:
            self._require_trap(trap_id)
            self._require_player(player_id)
            return self._cooldowns.get(trap_id, {}).get(player_id, 0)

    def rearmable(self, trap_id: str) -> bool:
        """Return whether the trap is restored by a wipe reset."""
        with self._lock:
            trap = self._require_trap(trap_id)
            return trap.reset_on_wipe and not trap.one_shot

    def trap_state(self, trap_id: str) -> TrapState:
        """Return an immutable view of the trap deployment state."""
        with self._lock:
            return self._require_trap(trap_id).public_state()

    def snapshot(self) -> dict:
        """Return a deep copy of traps, players, frames and counters."""
        with self._lock:
            return {
                "frame": self._frame,
                "traps": {
                    trap_id: {
                        "trap_id": trap.trap_id,
                        "charges": trap.charges,
                        "initial_charges": trap.initial_charges,
                        "radius": trap.radius,
                        "cooldown_frames": trap.cooldown_frames,
                        "one_shot": trap.one_shot,
                        "reset_on_wipe": trap.reset_on_wipe,
                        "armed": trap.armed,
                        "spent": trap.spent,
                    }
                    for trap_id, trap in self._traps.items()
                },
                "players": list(self._players),
                "cooldowns": {
                    trap_id: dict(players)
                    for trap_id, players in self._cooldowns.items()
                    if players
                },
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        """Replace orchestrator state with a snapshot, validating it."""
        if not isinstance(state, dict):
            raise TrapError("TRAP_SNAPSHOT_INVALID", "state")

        with self._lock:
            try:
                (
                    traps,
                    players,
                    cooldowns,
                    frame,
                    counters,
                ) = self._parse_snapshot(state)
            except TrapError:
                raise
            except (TypeError, ValueError, KeyError, OverflowError) as exc:
                raise TrapError("TRAP_SNAPSHOT_INVALID", exc) from exc

            self._traps = traps
            self._players = players
            self._cooldowns = cooldowns
            self._frame = frame
            self._counters = counters

    def _parse_snapshot(
        self,
        state: dict,
    ) -> tuple[
        dict[str, _TrapRecord],
        dict[str, None],
        dict[str, dict[str, int]],
        int,
        dict[str, int],
    ]:
        if (
            "traps" not in state
            or "players" not in state
            or "frame" not in state
        ):
            raise TrapError("TRAP_SNAPSHOT_INVALID", "missing field")

        frame = state["frame"]
        if not self._is_int(frame) or frame < 0:
            raise TrapError("TRAP_SNAPSHOT_INVALID", "frame")

        raw_traps = state["traps"]
        if not isinstance(raw_traps, dict):
            raise TrapError("TRAP_SNAPSHOT_INVALID", "traps")
        if len(raw_traps) > self.max_traps:
            raise TrapError("TRAP_SNAPSHOT_INVALID", "traps capacity")

        traps: dict[str, _TrapRecord] = {}
        for trap_id, raw_trap in raw_traps.items():
            if not self._is_id(trap_id) or not isinstance(raw_trap, dict):
                raise TrapError("TRAP_SNAPSHOT_INVALID", "trap")
            required = (
                "trap_id",
                "charges",
                "initial_charges",
                "radius",
                "cooldown_frames",
                "one_shot",
                "reset_on_wipe",
                "armed",
                "spent",
            )
            if any(field not in raw_trap for field in required):
                raise TrapError("TRAP_SNAPSHOT_INVALID", trap_id)
            if raw_trap["trap_id"] != trap_id:
                raise TrapError("TRAP_SNAPSHOT_INVALID", trap_id)

            charges = raw_trap["charges"]
            initial_charges = raw_trap["initial_charges"]
            radius = raw_trap["radius"]
            cooldown_frames = raw_trap["cooldown_frames"]
            if (
                not self._is_int(charges)
                or charges < 0
                or not self._is_int(initial_charges)
                or initial_charges <= 0
                or charges > initial_charges
                or not self._is_int(radius)
                or radius <= 0
                or not self._is_int(cooldown_frames)
                or cooldown_frames < 0
            ):
                raise TrapError("TRAP_SNAPSHOT_INVALID", trap_id)

            one_shot = raw_trap["one_shot"]
            reset_on_wipe = raw_trap["reset_on_wipe"]
            armed = raw_trap["armed"]
            spent = raw_trap["spent"]
            if (
                not self._is_bool(one_shot)
                or not self._is_bool(reset_on_wipe)
                or not self._is_bool(armed)
                or not self._is_bool(spent)
                or (spent and (not one_shot or charges != 0 or armed))
            ):
                raise TrapError("TRAP_SNAPSHOT_INVALID", trap_id)

            traps[trap_id] = _TrapRecord(
                trap_id=trap_id,
                charges=charges,
                initial_charges=initial_charges,
                radius=radius,
                cooldown_frames=cooldown_frames,
                one_shot=one_shot,
                reset_on_wipe=reset_on_wipe,
                armed=armed,
                spent=spent,
            )

        raw_players = state["players"]
        if not isinstance(raw_players, (list, tuple)):
            raise TrapError("TRAP_SNAPSHOT_INVALID", "players")
        if len(raw_players) > self.max_traps:
            raise TrapError("TRAP_SNAPSHOT_INVALID", "players capacity")
        players: dict[str, None] = {}
        for player_id in raw_players:
            if not self._is_id(player_id) or player_id in players:
                raise TrapError("TRAP_SNAPSHOT_INVALID", "players")
            players[player_id] = None

        raw_cooldowns = state.get("cooldowns", {})
        if not isinstance(raw_cooldowns, dict):
            raise TrapError("TRAP_SNAPSHOT_INVALID", "cooldowns")
        cooldowns: dict[str, dict[str, int]] = {}
        for trap_id, raw_players_cooldowns in raw_cooldowns.items():
            if trap_id not in traps or not isinstance(
                    raw_players_cooldowns, dict):
                raise TrapError("TRAP_SNAPSHOT_INVALID", "cooldowns")
            players_cooldowns: dict[str, int] = {}
            for player_id, remaining in raw_players_cooldowns.items():
                if player_id not in players:
                    raise TrapError("TRAP_SNAPSHOT_INVALID", "cooldowns")
                if (
                    not self._is_int(remaining)
                    or remaining < 0
                    or remaining > traps[trap_id].cooldown_frames
                ):
                    raise TrapError("TRAP_SNAPSHOT_INVALID", "cooldowns")
                if remaining > 0:
                    players_cooldowns[player_id] = remaining
            if players_cooldowns:
                cooldowns[trap_id] = players_cooldowns

        raw_counters = state.get("counters", state.get("stats", {}))
        if not isinstance(raw_counters, dict):
            raise TrapError("TRAP_SNAPSHOT_INVALID", "counters")
        counters = {name: 0 for name in _COUNTER_NAMES}
        for name in _COUNTER_NAMES:
            if name not in raw_counters:
                continue
            value = raw_counters[name]
            if not self._is_int(value) or value < 0:
                raise TrapError("TRAP_SNAPSHOT_INVALID", "counters")
            counters[name] = value

        return traps, players, cooldowns, frame, counters

    def stats(self) -> dict:
        """Return cumulative counters for triggers, rejects and resets."""
        with self._lock:
            result = {
                "traps": len(self._traps),
                "players": len(self._players),
                "frames": self._frame,
            }
            result.update(self._counters)
            return result
