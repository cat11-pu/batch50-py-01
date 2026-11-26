"""Safety interlock for simulation runs: scope, rate budget, trip and cooldown."""

from __future__ import annotations

import copy
import ipaddress
import math
import threading
import time


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

SNAPSHOT_FORMAT = "simulation-safety-interlock-v1"
_SNAPSHOT_KEYS = frozenset(
    {"format", "scopes", "runs", "permits", "switch", "counters"}
)
_COUNTER_KEYS = ("scopes", "runs", "permits", "trips", "resets")
_RUN_STATES = frozenset({RUN_ARMED, RUN_DISARMED, RUN_TRIPPED})
_PERMIT_STATES = frozenset(
    {PERMIT_IN_FLIGHT, PERMIT_COMPLETED, PERMIT_FAILED, PERMIT_VOIDED}
)


def _is_number(value: object) -> bool:
    if isinstance(value, bool):
        return False
    if not isinstance(value, (int, float)):
        return False
    return not isinstance(value, float) or math.isfinite(value)


def _parse_network(cidr: object):
    if not isinstance(cidr, str):
        raise ValueError("CIDR must be a string")
    return ipaddress.ip_network(cidr, strict=False)


def _parse_ip(target: object):
    if not isinstance(target, str):
        raise ValueError("target must be a string")
    return ipaddress.ip_address(target)


class SimulationSafetyInterlock:
    """Gate actions by scope, fixed-window budgets, a global trip and cooldown."""

    def __init__(
        self,
        *,
        global_rate: int = 20,
        per_target_rate: int = 5,
        window_seconds: int = 10,
        cooldown_seconds: int = 60,
    ) -> None:
        self.global_rate = global_rate
        self.per_target_rate = per_target_rate
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds

        self._lock = threading.RLock()
        self._scopes: dict[str, dict] = {}
        self._runs: dict[str, dict] = {}
        self._permits: dict[str, dict] = {}
        self._global_windows: dict[object, int] = {}
        self._target_windows: dict[object, dict[str, int]] = {}
        self._permit_seq = 0

        self._trips = 0
        self._resets = 0
        self._switch_state = STATE_IDLE
        self._tripped_at: object = None
        self._trip_reason: str | None = None
        self._reset_at: object = None
        self._cooling_until: object = None
        self._last_now: object = None

    def register_scope(self, scope_id: str, *, cidrs) -> dict:
        if not isinstance(scope_id, str) or not scope_id.strip():
            raise InterlockError(
                "INTERLOCK_INVALID_REQUEST", {"field": "scope_id"}
            )

        try:
            raw_cidrs = list(cidrs)
        except TypeError as exc:
            raise InterlockError(
                "INTERLOCK_BAD_SCOPE", {"cidrs": cidrs}
            ) from exc

        if not raw_cidrs:
            raise InterlockError("INTERLOCK_BAD_SCOPE", {"cidrs": raw_cidrs})

        networks = []
        for cidr in raw_cidrs:
            try:
                networks.append(_parse_network(cidr))
            except (ValueError, TypeError) as exc:
                raise InterlockError(
                    "INTERLOCK_BAD_SCOPE", {"cidr": cidr}
                ) from exc

        with self._lock:
            if scope_id in self._scopes:
                raise InterlockError(
                    "INTERLOCK_SCOPE_EXISTS", {"scope_id": scope_id}
                )
            self._scopes[scope_id] = {
                "scope_id": scope_id,
                "cidrs": tuple(raw_cidrs),
                "networks": tuple(networks),
            }
            return {"scope_id": scope_id, "cidrs": tuple(raw_cidrs)}

    def arm(self, run_id: str, *, scope_id: str, now: int) -> dict:
        current_now = self._require_now(now)

        with self._lock:
            self._last_now = current_now
            self._raise_if_switch_blocks(current_now, operation="arm")

            scope = (
                self._scopes.get(scope_id)
                if isinstance(scope_id, str)
                else None
            )
            if scope is None:
                raise InterlockError(
                    "INTERLOCK_SCOPE_UNKNOWN", {"scope_id": scope_id}
                )

            if not isinstance(run_id, str) or not run_id.strip():
                raise InterlockError(
                    "INTERLOCK_INVALID_REQUEST", {"field": "run_id"}
                )
            if run_id in self._runs:
                raise InterlockError(
                    "INTERLOCK_RUN_EXISTS", {"run_id": run_id}
                )

            self._runs[run_id] = {
                "run_id": run_id,
                "scope_id": scope_id,
                "state": RUN_ARMED,
                "armed_at": current_now,
                "disarmed_at": None,
                "tripped_at": None,
                "action_ids": set(),
            }
            return {
                "run_id": run_id,
                "scope_id": scope_id,
                "state": RUN_ARMED,
                "armed_at": current_now,
            }

    def disarm(self, run_id: str, *, now: int) -> dict:
        current_now = self._require_now(now)

        with self._lock:
            self._last_now = current_now
            run = self._get_run(run_id)
            if run is None:
                raise InterlockError(
                    "INTERLOCK_RUN_UNKNOWN", {"run_id": run_id}
                )
            if run["state"] != RUN_ARMED:
                raise InterlockError(
                    "INTERLOCK_RUN_STATE",
                    {"run_id": run_id, "state": run["state"]},
                )

            run["state"] = RUN_DISARMED
            run["disarmed_at"] = current_now
            return {
                "run_id": run_id,
                "state": RUN_DISARMED,
                "disarmed_at": current_now,
            }

    def check_action(
        self,
        run_id: str,
        *,
        action_id: str,
        target: str,
        now: int,
    ) -> dict:
        current_now = self._require_now(now)

        with self._lock:
            self._last_now = current_now
            self._raise_if_switch_blocks(current_now, operation="check_action")

            run = self._get_run(run_id)
            if run is None:
                raise InterlockError(
                    "INTERLOCK_RUN_UNKNOWN", {"run_id": run_id}
                )
            if run["state"] != RUN_ARMED:
                raise InterlockError(
                    "INTERLOCK_RUN_STATE",
                    {"run_id": run_id, "state": run["state"]},
                )

            if not isinstance(action_id, str) or not action_id.strip():
                raise InterlockError(
                    "INTERLOCK_INVALID_REQUEST", {"field": "action_id"}
                )
            if action_id in run["action_ids"]:
                raise InterlockError(
                    "INTERLOCK_DUPLICATE_ACTION",
                    {"run_id": run_id, "action_id": action_id},
                )

            try:
                target_ip = _parse_ip(target)
            except (ValueError, TypeError) as exc:
                raise InterlockError(
                    "INTERLOCK_BAD_TARGET", {"target": target}
                ) from exc

            scope = self._scopes.get(run["scope_id"])
            if scope is None or not self._target_in_scope(target_ip, scope):
                raise InterlockError(
                    "SCOPE_TARGET_DENIED",
                    {
                        "run_id": run_id,
                        "scope_id": run["scope_id"],
                        "target": target,
                    },
                )

            window = current_now // self.window_seconds
            global_used = self._global_windows.get(window, 0)
            if global_used >= self.global_rate:
                raise InterlockError(
                    "RATE_GLOBAL_EXCEEDED",
                    {
                        "window": window,
                        "used": global_used,
                        "limit": self.global_rate,
                    },
                )

            target_key = str(target_ip)
            target_bucket = self._target_windows.setdefault(window, {})
            target_used = target_bucket.get(target_key, 0)
            if target_used >= self.per_target_rate:
                raise InterlockError(
                    "RATE_TARGET_EXCEEDED",
                    {
                        "window": window,
                        "target": target_key,
                        "used": target_used,
                        "limit": self.per_target_rate,
                    },
                )

            self._permit_seq += 1
            permit_id = f"P-{self._permit_seq:04d}"
            permit = {
                "permit_id": permit_id,
                "run_id": run_id,
                "action_id": action_id,
                "target": target,
                "state": PERMIT_IN_FLIGHT,
                "granted_at": current_now,
                "settled_at": None,
            }

            self._global_windows[window] = global_used + 1
            target_bucket[target_key] = target_used + 1
            self._permits[permit_id] = permit
            run["action_ids"].add(action_id)

            return self._granted_view(permit)

    def finish_action(
        self, permit_id: str, *, outcome: str, now: int
    ) -> dict:
        with self._lock:
            permit = (
                self._permits.get(permit_id)
                if isinstance(permit_id, str)
                else None
            )
            if permit is None:
                raise InterlockError(
                    "INTERLOCK_PERMIT_UNKNOWN", {"permit_id": permit_id}
                )
            if permit["state"] != PERMIT_IN_FLIGHT:
                raise InterlockError(
                    "INTERLOCK_PERMIT_SETTLED",
                    {
                        "permit_id": permit_id,
                        "state": permit["state"],
                        "settled_at": permit.get("settled_at"),
                    },
                )
            if outcome not in SETTLE_OUTCOMES:
                raise InterlockError(
                    "INTERLOCK_INVALID_REQUEST", {"outcome": outcome}
                )

            settled_at = self._require_now(now)
            self._last_now = settled_at
            permit["state"] = (
                PERMIT_COMPLETED if outcome == "ok" else PERMIT_FAILED
            )
            permit["settled_at"] = settled_at
            return dict(permit)

    def trip(self, *, reason: str, now: int) -> dict:
        if not isinstance(reason, str) or not reason.strip():
            raise InterlockError(
                "INTERLOCK_INVALID_REQUEST", {"field": "reason"}
            )
        tripped_at = self._require_now(now)

        with self._lock:
            self._last_now = tripped_at
            tripped_runs = len(self._runs)
            for run in self._runs.values():
                run["state"] = RUN_TRIPPED
                run["tripped_at"] = tripped_at

            frozen_permits = 0
            for permit in self._permits.values():
                if permit["state"] == PERMIT_IN_FLIGHT:
                    permit["state"] = PERMIT_VOIDED
                    permit["settled_at"] = tripped_at
                    frozen_permits += 1

            self._switch_state = STATE_TRIPPED
            self._tripped_at = tripped_at
            self._trip_reason = reason
            self._reset_at = None
            self._cooling_until = None
            self._trips += 1

            return {
                "tripped_runs": tripped_runs,
                "frozen_permits": frozen_permits,
                "reason": reason,
                "tripped_at": tripped_at,
            }

    def reset(self, *, now: int) -> dict:
        reset_at = self._require_now(now)

        with self._lock:
            if self._switch_state != STATE_TRIPPED:
                raise InterlockError(
                    "INTERLOCK_NOT_TRIPPED",
                    {"state": self._switch_state},
                )

            cooling_until = self._tripped_at + self.cooldown_seconds
            self._switch_state = STATE_COOLING
            self._reset_at = reset_at
            self._cooling_until = cooling_until
            self._resets += 1
            self._last_now = reset_at

            return {
                "state": STATE_COOLING,
                "reset_at": reset_at,
                "cooling_until": cooling_until,
            }

    def status(self, *, now: int | None = None) -> dict:
        with self._lock:
            if now is None:
                current_now = (
                    self._last_now
                    if self._last_now is not None
                    else time.time()
                )
            else:
                current_now = self._require_now(now)
                self._last_now = current_now

            cooling_remaining = self._cooling_remaining_locked(current_now)
            if self._switch_state == STATE_TRIPPED:
                state = STATE_TRIPPED
            elif (
                self._switch_state == STATE_COOLING
                and cooling_remaining > 0
            ):
                state = STATE_COOLING
            elif any(run["state"] == RUN_ARMED for run in self._runs.values()):
                state = STATE_ARMED
            else:
                state = STATE_IDLE

            in_flight = sum(
                permit["state"] == PERMIT_IN_FLIGHT
                for permit in self._permits.values()
            )
            armed_runs = sum(
                run["state"] == RUN_ARMED for run in self._runs.values()
            )

            return {
                "state": state,
                "armed_runs": armed_runs,
                "in_flight": in_flight,
                "trips": self._trips,
                "cooling_remaining": cooling_remaining,
            }

    def permits(self, *, run_id: str | None = None) -> tuple:
        with self._lock:
            rows = [
                dict(permit)
                for permit in self._permits.values()
                if run_id is None or permit["run_id"] == run_id
            ]
            rows.sort(key=lambda permit: int(permit["permit_id"][2:]))
            return tuple(rows)

    def report(self) -> dict:
        with self._lock:
            return {
                "actions": len(self._permits),
                "in_flight": sum(
                    p["state"] == PERMIT_IN_FLIGHT
                    for p in self._permits.values()
                ),
                "completed": sum(
                    p["state"] == PERMIT_COMPLETED
                    for p in self._permits.values()
                ),
                "failed": sum(
                    p["state"] == PERMIT_FAILED
                    for p in self._permits.values()
                ),
                "voided": sum(
                    p["state"] == PERMIT_VOIDED
                    for p in self._permits.values()
                ),
            }

    def stats(self) -> dict:
        with self._lock:
            return {
                "scopes": len(self._scopes),
                "runs": len(self._runs),
                "permits": len(self._permits),
                "trips": self._trips,
                "resets": self._resets,
            }

    def snapshot(self) -> dict:
        with self._lock:
            scopes = [
                {
                    "scope_id": scope["scope_id"],
                    "cidrs": list(scope["cidrs"]),
                }
                for scope in self._scopes.values()
            ]
            runs = []
            for run in self._runs.values():
                row = {
                    key: value
                    for key, value in run.items()
                    if key != "action_ids"
                }
                row["action_ids"] = sorted(run["action_ids"])
                runs.append(row)

            state = {
                "format": SNAPSHOT_FORMAT,
                "scopes": scopes,
                "runs": runs,
                "permits": [
                    dict(permit) for permit in self._permits.values()
                ],
                "switch": {
                    "state": self._switch_state,
                    "tripped_at": self._tripped_at,
                    "reason": self._trip_reason,
                    "reset_at": self._reset_at,
                    "cooling_until": self._cooling_until,
                    "last_now": self._last_now,
                    "config": {
                        "global_rate": self.global_rate,
                        "per_target_rate": self.per_target_rate,
                        "window_seconds": self.window_seconds,
                        "cooldown_seconds": self.cooldown_seconds,
                    },
                },
                "counters": self.stats(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            candidate = self._build_restore_candidate(state)
            config = candidate["config"]

            self.global_rate = config["global_rate"]
            self.per_target_rate = config["per_target_rate"]
            self.window_seconds = config["window_seconds"]
            self.cooldown_seconds = config["cooldown_seconds"]

            self._scopes = candidate["scopes"]
            self._runs = candidate["runs"]
            self._permits = candidate["permits"]
            self._global_windows = candidate["global_windows"]
            self._target_windows = candidate["target_windows"]
            self._permit_seq = candidate["permit_seq"]
            self._trips = candidate["trips"]
            self._resets = candidate["resets"]
            self._switch_state = candidate["switch_state"]
            self._tripped_at = candidate["tripped_at"]
            self._trip_reason = candidate["trip_reason"]
            self._reset_at = candidate["reset_at"]
            self._cooling_until = candidate["cooling_until"]
            self._last_now = candidate["last_now"]

    @staticmethod
    def _snapshot_invalid(detail: object = None) -> InterlockError:
        return InterlockError("INTERLOCK_SNAPSHOT_INVALID", detail)

    def _build_restore_candidate(self, state: object) -> dict:
        if not isinstance(state, dict):
            raise self._snapshot_invalid({"reason": "snapshot_not_object"})
        if set(state.keys()) != _SNAPSHOT_KEYS:
            raise self._snapshot_invalid(
                {"reason": "unexpected_snapshot_keys"}
            )
        if state.get("format") != SNAPSHOT_FORMAT:
            raise self._snapshot_invalid({"field": "format"})

        counters = self._parse_snapshot_counters(state.get("counters"))
        switch_parts = self._parse_snapshot_switch(state.get("switch"))
        config = switch_parts["config"]
        scopes = self._parse_snapshot_scopes(state.get("scopes"))
        runs = self._parse_snapshot_runs(state.get("runs"), scopes)
        permits, permit_seq = self._parse_snapshot_permits(
            state.get("permits"), runs, scopes
        )
        self._validate_snapshot_switch_consistency(
            switch_parts["switch_state"],
            runs,
            permits,
            switch_parts,
        )

        if counters["scopes"] != len(scopes):
            raise self._snapshot_invalid({"field": "counters.scopes"})
        if counters["runs"] != len(runs):
            raise self._snapshot_invalid({"field": "counters.runs"})
        if counters["permits"] != len(permits):
            raise self._snapshot_invalid({"field": "counters.permits"})

        global_windows, target_windows = self._rebuild_rate_windows(
            permits, config["window_seconds"]
        )

        return {
            "config": config,
            "scopes": scopes,
            "runs": runs,
            "permits": permits,
            "permit_seq": permit_seq,
            "global_windows": global_windows,
            "target_windows": target_windows,
            "trips": counters["trips"],
            "resets": counters["resets"],
            **switch_parts,
        }

    def _parse_snapshot_counters(self, raw: object) -> dict:
        if not isinstance(raw, dict) or set(raw.keys()) != set(_COUNTER_KEYS):
            raise self._snapshot_invalid({"field": "counters"})

        counters = {}
        for key in _COUNTER_KEYS:
            value = raw[key]
            if (
                not isinstance(value, int)
                or isinstance(value, bool)
                or value < 0
            ):
                raise self._snapshot_invalid({"field": f"counters.{key}"})
            counters[key] = value
        return counters

    def _parse_snapshot_switch(self, raw: object) -> dict:
        if not isinstance(raw, dict):
            raise self._snapshot_invalid({"field": "switch"})

        config = {
            "global_rate": self.global_rate,
            "per_target_rate": self.per_target_rate,
            "window_seconds": self.window_seconds,
            "cooldown_seconds": self.cooldown_seconds,
        }
        raw_config = raw.get("config", {})
        if "config" in raw:
            if not isinstance(raw_config, dict):
                raise self._snapshot_invalid({"field": "switch.config"})
            for key in config:
                if key in raw_config:
                    value = raw_config[key]
                    if not _is_number(value):
                        raise self._snapshot_invalid(
                            {"field": f"switch.config.{key}"}
                        )
                    config[key] = value

        if config["window_seconds"] <= 0:
            raise self._snapshot_invalid(
                {"field": "switch.config.window_seconds"}
            )

        switch_state = raw.get("state", STATE_IDLE)
        if switch_state == STATE_ARMED:
            switch_state = STATE_IDLE
        if switch_state not in (STATE_IDLE, STATE_TRIPPED, STATE_COOLING):
            raise self._snapshot_invalid({"field": "switch.state"})

        tripped_at = self._snapshot_timestamp(raw.get("tripped_at"))
        reset_at = self._snapshot_timestamp(raw.get("reset_at"))
        cooling_until = self._snapshot_timestamp(raw.get("cooling_until"))
        last_now = self._snapshot_timestamp(raw.get("last_now"))
        if last_now is None:
            last_now = reset_at if reset_at is not None else tripped_at

        trip_reason = raw.get("reason")
        if trip_reason is not None and (
            not isinstance(trip_reason, str) or not trip_reason.strip()
        ):
            raise self._snapshot_invalid({"field": "switch.reason"})

        if switch_state == STATE_TRIPPED and (
            tripped_at is None or trip_reason is None
        ):
            raise self._snapshot_invalid({"field": "switch.trip"})
        if switch_state == STATE_COOLING and (
            tripped_at is None or reset_at is None or cooling_until is None
        ):
            raise self._snapshot_invalid({"field": "switch.reset"})

        return {
            "config": config,
            "switch_state": switch_state,
            "tripped_at": tripped_at,
            "trip_reason": trip_reason,
            "reset_at": reset_at,
            "cooling_until": cooling_until,
            "last_now": last_now,
        }

    def _parse_snapshot_scopes(self, raw: object) -> dict:
        if not isinstance(raw, (list, tuple)):
            raise self._snapshot_invalid({"field": "scopes"})

        scopes = {}
        for raw_scope in raw:
            if not isinstance(raw_scope, dict):
                raise self._snapshot_invalid({"field": "scopes[]"})

            scope_id = raw_scope.get("scope_id")
            raw_cidrs = raw_scope.get("cidrs")
            if not isinstance(scope_id, str) or not scope_id.strip():
                raise self._snapshot_invalid({"field": "scopes.scope_id"})
            if scope_id in scopes:
                raise self._snapshot_invalid({"field": "scopes.duplicate"})
            if not isinstance(raw_cidrs, (list, tuple)) or not raw_cidrs:
                raise self._snapshot_invalid({"field": "scopes.cidrs"})

            cidrs = []
            networks = []
            for cidr in raw_cidrs:
                try:
                    network = _parse_network(cidr)
                except (ValueError, TypeError) as exc:
                    raise self._snapshot_invalid(
                        {"field": "scopes.cidrs", "cidr": cidr}
                    ) from exc
                cidrs.append(cidr)
                networks.append(network)

            scopes[scope_id] = {
                "scope_id": scope_id,
                "cidrs": tuple(cidrs),
                "networks": tuple(networks),
            }
        return scopes

    def _parse_snapshot_runs(self, raw: object, scopes: dict) -> dict:
        if not isinstance(raw, (list, tuple)):
            raise self._snapshot_invalid({"field": "runs"})

        runs = {}
        for raw_run in raw:
            if not isinstance(raw_run, dict):
                raise self._snapshot_invalid({"field": "runs[]"})

            run_id = raw_run.get("run_id")
            scope_id = raw_run.get("scope_id")
            state = raw_run.get("state")
            if not isinstance(run_id, str) or not run_id.strip():
                raise self._snapshot_invalid({"field": "runs.run_id"})
            if run_id in runs:
                raise self._snapshot_invalid({"field": "runs.duplicate"})
            if not isinstance(scope_id, str) or scope_id not in scopes:
                raise self._snapshot_invalid({"field": "runs.scope_id"})
            if state not in _RUN_STATES:
                raise self._snapshot_invalid({"field": "runs.state"})

            armed_at = self._snapshot_timestamp(
                raw_run.get("armed_at"), True
            )
            disarmed_at = self._snapshot_timestamp(raw_run.get("disarmed_at"))
            tripped_at = self._snapshot_timestamp(raw_run.get("tripped_at"))

            raw_actions = raw_run.get("action_ids", [])
            if not isinstance(
                raw_actions, (list, tuple, set, frozenset)
            ):
                raise self._snapshot_invalid({"field": "runs.action_ids"})
            action_ids = set()
            for action_id in raw_actions:
                if not isinstance(action_id, str) or not action_id.strip():
                    raise self._snapshot_invalid(
                        {"field": "runs.action_ids[]"}
                    )
                if action_id in action_ids:
                    raise self._snapshot_invalid(
                        {"field": "runs.action_ids.duplicate"}
                    )
                action_ids.add(action_id)

            runs[run_id] = {
                "run_id": run_id,
                "scope_id": scope_id,
                "state": state,
                "armed_at": armed_at,
                "disarmed_at": disarmed_at,
                "tripped_at": tripped_at,
                "action_ids": action_ids,
            }
        return runs

    def _parse_snapshot_permits(
        self, raw: object, runs: dict, scopes: dict
    ) -> tuple[dict, int]:
        if not isinstance(raw, (list, tuple)):
            raise self._snapshot_invalid({"field": "permits"})

        parsed = []
        permit_ids = set()
        run_actions_seen = {run_id: set() for run_id in runs}
        permit_seq = 0

        for raw_permit in raw:
            if not isinstance(raw_permit, dict):
                raise self._snapshot_invalid({"field": "permits[]"})

            permit_id = raw_permit.get("permit_id")
            run_id = raw_permit.get("run_id")
            action_id = raw_permit.get("action_id")
            target = raw_permit.get("target")
            state = raw_permit.get("state")

            if not isinstance(permit_id, str) or not permit_id.startswith("P-"):
                raise self._snapshot_invalid(
                    {"field": "permits.permit_id"}
                )
            try:
                seq = int(permit_id[2:])
            except ValueError as exc:
                raise self._snapshot_invalid(
                    {"field": "permits.permit_id"}
                ) from exc
            if seq <= 0 or permit_id != f"P-{seq:04d}":
                raise self._snapshot_invalid(
                    {"field": "permits.permit_id"}
                )
            if permit_id in permit_ids:
                raise self._snapshot_invalid({"field": "permits.duplicate"})

            run = runs.get(run_id) if isinstance(run_id, str) else None
            if run is None:
                raise self._snapshot_invalid({"field": "permits.run_id"})
            if not isinstance(action_id, str) or not action_id.strip():
                raise self._snapshot_invalid({"field": "permits.action_id"})
            if action_id not in run["action_ids"]:
                raise self._snapshot_invalid(
                    {"field": "permits.action_id_not_registered"}
                )
            if action_id in run_actions_seen[run_id]:
                raise self._snapshot_invalid(
                    {"field": "permits.duplicate_action"}
                )
            if state not in _PERMIT_STATES:
                raise self._snapshot_invalid({"field": "permits.state"})

            try:
                target_ip = _parse_ip(target)
            except (ValueError, TypeError) as exc:
                raise self._snapshot_invalid(
                    {"field": "permits.target", "target": target}
                ) from exc
            if not self._target_in_scope(
                target_ip, scopes[run["scope_id"]]
            ):
                raise self._snapshot_invalid(
                    {"field": "permits.target_scope"}
                )

            granted_at = self._snapshot_timestamp(
                raw_permit.get("granted_at"), True
            )
            settled_at = self._snapshot_timestamp(
                raw_permit.get("settled_at")
            )
            if state == PERMIT_IN_FLIGHT:
                if settled_at is not None:
                    raise self._snapshot_invalid(
                        {"field": "permits.settled_at"}
                    )
            elif settled_at is None:
                raise self._snapshot_invalid(
                    {"field": "permits.settled_at"}
                )

            permit_ids.add(permit_id)
            permit_seq = max(permit_seq, seq)
            run_actions_seen[run_id].add(action_id)
            parsed.append(
                (
                    seq,
                    {
                        "permit_id": permit_id,
                        "run_id": run_id,
                        "action_id": action_id,
                        "target": target,
                        "state": state,
                        "granted_at": granted_at,
                        "settled_at": settled_at,
                    },
                )
            )

        for run_id, run in runs.items():
            if run_actions_seen[run_id] != run["action_ids"]:
                raise self._snapshot_invalid(
                    {"field": "runs.action_ids_permits_mismatch"}
                )

        parsed.sort(key=lambda item: item[0])
        permits = {
            permit["permit_id"]: permit for _, permit in parsed
        }
        return permits, permit_seq

    def _validate_snapshot_switch_consistency(
        self,
        switch_state: str,
        runs: dict,
        permits: dict,
        switch_parts: dict,
    ) -> None:
        if switch_state in (STATE_TRIPPED, STATE_COOLING):
            if any(run["state"] != RUN_TRIPPED for run in runs.values()):
                raise self._snapshot_invalid(
                    {"field": "switch.run_state_mismatch"}
                )
            if any(
                permit["state"] == PERMIT_IN_FLIGHT
                for permit in permits.values()
            ):
                raise self._snapshot_invalid(
                    {"field": "switch.in_flight_permit_mismatch"}
                )

        if switch_state == STATE_COOLING:
            tripped_at = switch_parts["tripped_at"]
            cooling_until = switch_parts["cooling_until"]
            cooldown = switch_parts["config"]["cooldown_seconds"]
            if (
                tripped_at is None
                or cooling_until is None
                or not _is_number(cooldown)
                or cooling_until != tripped_at + cooldown
            ):
                raise self._snapshot_invalid(
                    {"field": "switch.cooling_until"}
                )

    def _rebuild_rate_windows(
        self, permits: dict, window_seconds: object
    ) -> tuple[dict, dict]:
        global_windows: dict[object, int] = {}
        target_windows: dict[object, dict[str, int]] = {}

        for permit in permits.values():
            window = permit["granted_at"] // window_seconds
            target_ip = _parse_ip(permit["target"])
            target_key = str(target_ip)

            global_windows[window] = global_windows.get(window, 0) + 1
            bucket = target_windows.setdefault(window, {})
            bucket[target_key] = bucket.get(target_key, 0) + 1

        return global_windows, target_windows

    def _require_now(self, now: object) -> object:
        if not _is_number(now):
            raise InterlockError(
                "INTERLOCK_INVALID_REQUEST",
                {"field": "now", "value": now},
            )
        return now

    def _snapshot_timestamp(
        self, value: object, required: bool = False
    ) -> object:
        if value is None and not required:
            return None
        if not _is_number(value):
            raise self._snapshot_invalid(
                {"field": "timestamp", "value": value}
            )
        return value

    def _get_run(self, run_id: object) -> dict | None:
        if not isinstance(run_id, str):
            return None
        return self._runs.get(run_id)

    @staticmethod
    def _target_in_scope(target_ip, scope: dict) -> bool:
        for network in scope["networks"]:
            if target_ip.version == network.version and target_ip in network:
                return True
        return False

    def _raise_if_switch_blocks(
        self, now: object, *, operation: str
    ) -> None:
        if self._switch_state == STATE_TRIPPED:
            raise InterlockError(
                "INTERLOCK_TRIPPED",
                {"operation": operation, "tripped_at": self._tripped_at},
            )
        if (
            self._switch_state == STATE_COOLING
            and self._cooling_until is not None
            and now < self._cooling_until
        ):
            raise InterlockError(
                "INTERLOCK_COOLING_DOWN",
                {
                    "operation": operation,
                    "cooling_until": self._cooling_until,
                    "remaining": max(0, self._cooling_until - now),
                },
            )

    def _cooling_remaining_locked(self, now: object) -> object:
        if (
            self._switch_state != STATE_COOLING
            or self._cooling_until is None
        ):
            return 0
        try:
            return max(0, self._cooling_until - now)
        except TypeError:
            return 0

    @staticmethod
    def _granted_view(permit: dict) -> dict:
        return {
            "permit_id": permit["permit_id"],
            "run_id": permit["run_id"],
            "action_id": permit["action_id"],
            "target": permit["target"],
            "state": permit["state"],
            "granted_at": permit["granted_at"],
        }
