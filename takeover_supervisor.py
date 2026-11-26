"""Disconnect takeover supervision: grace window, action budget, and handback."""

from __future__ import annotations

import copy
import threading


_SNAPSHOT_VERSION = 1
_ONLINE = "online"
_GRACE = "grace"
_SUPERVISED = "supervised"
_RETURNING = "returning"

_PLAYER = "player"
_SUPERVISOR = "supervisor"
_FROZEN = "frozen"

_VALID_STATUSES = {_ONLINE, _GRACE, _SUPERVISED, _RETURNING}
_VALID_CONTROLLERS = {_PLAYER, _SUPERVISOR, _FROZEN}
_CONTROLLER_BY_STATUS = {
    _ONLINE: _PLAYER,
    _GRACE: _PLAYER,
    _SUPERVISED: _SUPERVISOR,
    _RETURNING: _FROZEN,
}
_STATS_KEYS = (
    "registered",
    "offline",
    "takeovers",
    "handbacks",
    "executed",
    "queued",
    "denied",
    "refused",
)


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
        self._frame = 0
        self._characters: dict[str, dict] = {}
        self._stats = {key: 0 for key in _STATS_KEYS}

    def register_character(self, character: str, *, actions=None) -> dict:
        name = self._character_name(character)
        normalized_actions = self._normalize_actions(actions)
        with self._lock:
            if name in self._characters:
                self._refuse("TAKEOVER_INVALID_REQUEST",
                             f"character already registered: {name}")
            record = {
                "character": name,
                "status": _ONLINE,
                "controller": _PLAYER,
                "grace_left": 0,
                "frozen_ticks": 0,
                "budget_left": self.frame_budget,
                "actions": normalized_actions,
                "pending": [],
            }
            self._characters[name] = record
            self._stats["registered"] += 1
            return self._state_view(record)

    def mark_offline(self, character: str, now=None) -> dict:
        with self._lock:
            record = self._record(character)
            if record["status"] in (_ONLINE, _GRACE):
                record["status"] = _GRACE
                record["controller"] = _PLAYER
                record["grace_left"] = self.grace_ticks
            self._stats["offline"] += 1
            return self._state_view(record)

    def heartbeat(self, character: str, now=None) -> dict:
        with self._lock:
            record = self._record(character)
            if record["status"] == _GRACE:
                record["status"] = _ONLINE
                record["controller"] = _PLAYER
                record["grace_left"] = 0
            return self._state_view(record)

    def takeover(self, character: str, now=None) -> dict:
        with self._lock:
            record = self._record(character)
            status = record["status"]

            if status in (_SUPERVISED, _RETURNING):
                self._refuse("TAKEOVER_ALREADY_SUPERVISED", character)
            if status == _ONLINE:
                self._refuse("TAKEOVER_NOT_OFFLINE", character)
            if status == _GRACE and record["grace_left"] > 0:
                self._refuse("TAKEOVER_GRACE_ACTIVE",
                            {"character": character,
                             "grace_left": record["grace_left"]})

            record["status"] = _SUPERVISED
            record["controller"] = _SUPERVISOR
            record["grace_left"] = 0
            record["frozen_ticks"] = 0
            record["budget_left"] = self.frame_budget
            record["pending"] = []
            self._stats["takeovers"] += 1
            return self._state_view(record)

    def execute(self, character: str, action: str, now=None) -> dict:
        with self._lock:
            record = self._record(character)
            status = record["status"]

            if status == _RETURNING:
                self._refuse("TAKEOVER_CONTROL_FROZEN", character)
            if status != _SUPERVISED:
                self._refuse("TAKEOVER_NOT_SUPERVISED",
                             {"character": character, "status": status})
            if action not in record["actions"]:
                self._stats["denied"] += 1
                raise TakeoverError(
                    "TAKEOVER_ACTION_DENIED",
                    {"character": record["character"], "action": action},
                )

            if record["budget_left"] > 0:
                record["budget_left"] -= 1
                self._stats["executed"] += 1
                result_status = "executed"
            else:
                if len(record["pending"]) >= self.max_pending:
                    self._refuse(
                        "TAKEOVER_QUEUE_FULL",
                        {"character": record["character"],
                         "max_pending": self.max_pending},
                    )
                record["pending"].append(action)
                self._stats["queued"] += 1
                result_status = "queued"

            return {
                "character": record["character"],
                "action": action,
                "status": result_status,
                "frame": self._frame,
                "budget_left": record["budget_left"],
                "pending": len(record["pending"]),
            }

    def handback(self, character: str, now=None) -> dict:
        with self._lock:
            record = self._record(character)
            if record["status"] != _SUPERVISED:
                self._refuse("TAKEOVER_NOT_SUPERVISED",
                             {"character": record["character"],
                              "status": record["status"]})

            record["status"] = _RETURNING
            record["controller"] = _FROZEN
            record["frozen_ticks"] = 1
            record["pending"].clear()
            self._stats["handbacks"] += 1
            return self._state_view(record)

    def state_of(self, character: str) -> dict:
        with self._lock:
            return self._state_view(self._record(character))

    def pending_actions(self, character: str) -> list:
        with self._lock:
            record = self._record(character)
            if record["status"] != _SUPERVISED:
                return []
            return list(record["pending"])

    def submit_input(self, character: str, action: str) -> dict:
        with self._lock:
            record = self._record(character)
            if record["status"] == _RETURNING:
                self._refuse("TAKEOVER_CONTROL_FROZEN", character)
            if record["status"] != _ONLINE:
                self._refuse("TAKEOVER_NOT_ONLINE",
                             {"character": character,
                              "status": record["status"]})
            return {
                "character": record["character"],
                "action": action,
                "accepted": True,
            }

    def advance_frame(self, frames: int = 1) -> dict:
        if isinstance(frames, bool) or not isinstance(frames, int) or frames <= 0:
            with self._lock:
                self._refuse("TAKEOVER_INVALID_REQUEST",
                             {"frames": frames})

        with self._lock:
            self._frame += frames
            grace_expired = []
            returned = []

            for name in sorted(self._characters):
                record = self._characters[name]

                if record["grace_left"] > 0:
                    previous = record["grace_left"]
                    record["grace_left"] = max(0, previous - frames)
                    if (record["status"] == _GRACE
                            and record["grace_left"] == 0):
                        grace_expired.append(name)

                if record["status"] in (_SUPERVISED, _RETURNING):
                    record["budget_left"] = self.frame_budget

                if record["frozen_ticks"] > 0:
                    record["frozen_ticks"] = max(
                        0, record["frozen_ticks"] - frames
                    )
                    if (record["status"] == _RETURNING
                            and record["frozen_ticks"] == 0):
                        record["status"] = _ONLINE
                        record["controller"] = _PLAYER
                        returned.append(name)

            return {
                "frame": self._frame,
                "grace_expired": grace_expired,
                "returned": returned,
            }

    def snapshot(self) -> dict:
        with self._lock:
            payload = {
                "version": _SNAPSHOT_VERSION,
                "frame": self._frame,
                "characters": {
                    name: self._record_snapshot(record)
                    for name, record in self._characters.items()
                },
                "stats": dict(self._stats),
            }
            return copy.deepcopy(payload)

    def restore(self, state: dict) -> None:
        new_frame, new_characters, new_stats = self._parse_snapshot(state)
        with self._lock:
            self._frame = new_frame
            self._characters = new_characters
            self._stats = new_stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _record(self, character: str) -> dict:
        name = self._character_name(character)
        record = self._characters.get(name)
        if record is None:
            self._refuse("TAKEOVER_UNKNOWN_CHARACTER", name)
        return record

    @staticmethod
    def _character_name(character: object) -> str:
        if not isinstance(character, str):
            raise TakeoverError("TAKEOVER_INVALID_REQUEST",
                                "character must be a string")
        name = character.strip()
        if not name:
            raise TakeoverError("TAKEOVER_INVALID_REQUEST",
                                "character must not be blank")
        return name

    def _normalize_actions(self, actions) -> tuple:
        source = self.default_actions if actions is None else actions
        try:
            candidates = tuple(source)
        except TypeError as exc:
            raise TakeoverError(
                "TAKEOVER_INVALID_REQUEST",
                "actions must be an iterable",
            ) from exc

        normalized = []
        for action in candidates:
            if action not in normalized:
                normalized.append(action)
        return tuple(normalized)

    def _refuse(self, code: str, detail: object = None):
        self._stats["refused"] += 1
        raise TakeoverError(code, detail)

    @staticmethod
    def _state_view(record: dict) -> dict:
        return {
            "character": record["character"],
            "status": record["status"],
            "controller": record["controller"],
            "grace_left": record["grace_left"],
            "frozen_ticks": record["frozen_ticks"],
            "budget_left": record["budget_left"],
        }

    @staticmethod
    def _record_snapshot(record: dict) -> dict:
        return {
            "character": record["character"],
            "status": record["status"],
            "controller": record["controller"],
            "grace_left": record["grace_left"],
            "frozen_ticks": record["frozen_ticks"],
            "budget_left": record["budget_left"],
            "actions": list(record["actions"]),
            "pending": list(record["pending"]),
        }

    def _parse_snapshot(self, state: object):
        try:
            state = copy.deepcopy(state)
            if not isinstance(state, dict):
                raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                    "snapshot must be an object")
            if set(state.keys()) != {"version", "frame", "characters", "stats"}:
                raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                    "snapshot keys are invalid")
            if self._invalid_int(state["version"]) or state["version"] != _SNAPSHOT_VERSION:
                raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                    "unsupported snapshot version")
            if self._invalid_int(state["frame"], minimum=0):
                raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                    "frame must be a non-negative integer")
            if not isinstance(state["characters"], dict):
                raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                    "characters must be an object")
            if not isinstance(state["stats"], dict):
                raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                    "stats must be an object")

            new_characters = {}
            for key, raw_record in state["characters"].items():
                record = self._parse_character_snapshot(key, raw_record)
                new_characters[record["character"]] = record

            new_stats = self._parse_stats_snapshot(state["stats"])
            return state["frame"], new_characters, new_stats
        except TakeoverError as exc:
            if exc.code == "TAKEOVER_SNAPSHOT_INVALID":
                raise
            raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                 "snapshot structure is invalid") from exc
        except Exception as exc:
            raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                "snapshot structure is invalid") from exc

    def _parse_character_snapshot(self, key: object, raw: object) -> dict:
        if not isinstance(key, str) or not isinstance(raw, dict):
            raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                "character snapshot is invalid")

        required = {
            "character", "status", "controller", "grace_left",
            "frozen_ticks", "budget_left", "actions", "pending",
        }
        if not required.issubset(raw.keys()):
            raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                "character fields are missing")

        character = self._character_name(raw["character"])
        if key != character:
            raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                "character key mismatch")
        status = raw["status"]
        controller = raw["controller"]
        if status not in _VALID_STATUSES:
            raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                "invalid character status")
        if controller not in _VALID_CONTROLLERS:
            raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                "invalid controller")
        if controller != _CONTROLLER_BY_STATUS[status]:
            raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                "status and controller do not match")

        for field in ("grace_left", "frozen_ticks", "budget_left"):
            if self._invalid_int(raw[field], minimum=0):
                raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                    f"{field} must be non-negative integer")

        if not isinstance(raw["actions"], list):
            raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                "actions must be a list")
        actions = self._normalize_actions(raw["actions"])

        if not isinstance(raw["pending"], list):
            raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                "pending actions must be a list")
        pending = list(raw["pending"])
        if any(action not in actions for action in pending):
            raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                "pending action is not allowed")

        return {
            "character": character,
            "status": status,
            "controller": controller,
            "grace_left": raw["grace_left"],
            "frozen_ticks": raw["frozen_ticks"],
            "budget_left": raw["budget_left"],
            "actions": actions,
            "pending": pending,
        }

    def _parse_stats_snapshot(self, raw: dict) -> dict:
        if set(raw.keys()) != set(_STATS_KEYS):
            raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                "stats fields are invalid")
        stats = {}
        for key in _STATS_KEYS:
            value = raw[key]
            if self._invalid_int(value, minimum=0):
                raise TakeoverError("TAKEOVER_SNAPSHOT_INVALID",
                                    f"stat {key} must be non-negative integer")
            stats[key] = value
        return stats

    @staticmethod
    def _invalid_int(value: object, *, minimum: int | None = None) -> bool:
        if isinstance(value, bool) or not isinstance(value, int):
            return True
        return minimum is not None and value < minimum
