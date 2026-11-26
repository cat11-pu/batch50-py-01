"""Fuzz budget allocator: yield feedback, per round decay, starvation floor."""

from __future__ import annotations

import copy
import math
import threading
from fractions import Fraction
from typing import Any


class AllocError(ValueError):
    """Raised when the allocator refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATE_ACTIVE = "active"
STATE_OBSERVING = "observing"

OBSERVE_AFTER_ROUNDS = 3
DECAY_FLOOR_EXPONENT = 3
SNAPSHOT_VERSION = 1


def _is_strict_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_non_negative_int(value: Any) -> bool:
    return _is_strict_int(value) and value >= 0


def _valid_weight(weight: Any) -> bool:
    return (
        isinstance(weight, (int, float))
        and not isinstance(weight, bool)
        and math.isfinite(weight)
        and 0 < weight < 100
    )


def _decay_for_streak(zero_streak: int) -> Fraction:
    exponent = min(max(zero_streak, 0), DECAY_FLOOR_EXPONENT)
    return Fraction(1, 2**exponent)


def _largest_remainder(seats: int,
                       weights: dict[str, Fraction]) -> dict[str, int]:
    """Apportion exactly ``seats`` integer units, with deterministic ties."""
    names = sorted(weights)
    result = {name: 0 for name in names}
    if seats <= 0 or not names:
        return result

    total_weight = sum((weights[name] for name in names), Fraction(0, 1))
    if total_weight <= 0:
        base = seats // len(names)
        extra = seats % len(names)
        for index, name in enumerate(names):
            result[name] = base + (1 if index < extra else 0)
        return result

    exact = {
        name: Fraction(seats, 1) * weights[name] / total_weight
        for name in names
    }
    floors = {
        name: exact[name].numerator // exact[name].denominator
        for name in names
    }
    for name in names:
        result[name] = floors[name]

    remaining = seats - sum(floors.values())
    if remaining:
        order = sorted(
            names,
            key=lambda name: (-(exact[name] - floors[name]), name),
        )
        for index in range(remaining):
            result[order[index % len(names)]] += 1

    return result


class FuzzBudgetAllocator:
    """Split a per-round compute budget across fuzz targets."""

    def __init__(self, *, floor_quota: int = 64,
                 yield_threshold: int = 1) -> None:
        self.floor_quota = floor_quota
        self.yield_threshold = yield_threshold
        self._lock = threading.RLock()
        self._targets: dict[str, dict[str, Any]] = {}
        self._round = 0
        self._allocated: dict[str, int] = {}
        self._consumed: dict[str, int] = {}
        self._productive: set[str] = set()
        self._counters: dict[str, int] = {
            "yield_reports": 0,
            "allocated_total": 0,
            "consumed_total": 0,
        }

    def register(self, target: str, *, weight: float = 1.0,
                 note: str = "") -> dict:
        with self._lock:
            if not isinstance(target, str) or not target.strip():
                raise AllocError("ALLOC_BAD_TARGET", {"target": target})
            if target in self._targets:
                raise AllocError("ALLOC_DUPLICATE_TARGET",
                                 {"target": target})
            if not _valid_weight(weight):
                raise AllocError("ALLOC_BAD_WEIGHT", {"weight": weight})

            record = {
                "target": target,
                "weight": float(weight),
                "note": note,
                "state": STATE_ACTIVE,
                "zero_streak": 0,
                "yield_points": 0,
                "reports": 0,
            }
            self._targets[target] = record
            self._allocated[target] = 0
            self._consumed[target] = 0
            return self._public_target(record)

    def allocate(self, total_budget: int) -> dict[str, int]:
        with self._lock:
            self._validate_budget(total_budget)
            if not self._targets:
                raise AllocError("ALLOC_NO_TARGETS")

            allocation = self._plan_allocation(total_budget)
            self._round += 1
            self._allocated = dict(allocation)
            self._consumed = {name: 0 for name in allocation}
            self._counters["allocated_total"] += total_budget
            self._advance_feedback_state()
            return dict(allocation)

    def report_yield(self, target: str, *, new_coverage: int = 0,
                     crashes: int = 0) -> dict:
        if not _is_non_negative_int(new_coverage):
            raise AllocError("ALLOC_BAD_YIELD",
                             {"new_coverage": new_coverage})
        if not _is_non_negative_int(crashes):
            raise AllocError("ALLOC_BAD_YIELD", {"crashes": crashes})

        with self._lock:
            record = self._targets.get(target)
            if record is None:
                raise AllocError("ALLOC_UNKNOWN_TARGET",
                                 {"target": target})

            score = new_coverage * 3 + crashes * 5
            record["yield_points"] += score
            record["reports"] += 1
            self._counters["yield_reports"] += 1

            if score > 0:
                record["zero_streak"] = 0
                record["state"] = STATE_ACTIVE
                self._productive.add(target)

            return {
                "target": target,
                "score": score,
                "yield_points": record["yield_points"],
                "zero_streak": record["zero_streak"],
                "state": record["state"],
            }

    def rebalance(self, *, total_budget: int) -> dict[str, int]:
        with self._lock:
            self._validate_budget(total_budget)
            if not self._targets:
                raise AllocError("ALLOC_NO_TARGETS")
            return self._plan_allocation(total_budget)

    def consume(self, target: str, units: int) -> int:
        if not _is_strict_int(units) or units <= 0:
            raise AllocError("ALLOC_BAD_UNITS", {"units": units})

        with self._lock:
            if target not in self._targets:
                raise AllocError("ALLOC_UNKNOWN_TARGET",
                                 {"target": target})

            consumed = self._consumed.get(target, 0)
            allocated = self._allocated.get(target, 0)
            if consumed + units > allocated:
                raise AllocError(
                    "ALLOC_BUDGET_EXHAUSTED",
                    {
                        "target": target,
                        "requested": units,
                        "allocated": allocated,
                        "consumed": consumed,
                    },
                )

            consumed += units
            self._consumed[target] = consumed
            self._counters["consumed_total"] += units
            return allocated - consumed

    def usage(self) -> dict:
        with self._lock:
            names = sorted(self._targets)
            allocated = {
                name: int(self._allocated.get(name, 0))
                for name in names
            }
            consumed = {
                name: int(self._consumed.get(name, 0))
                for name in names
            }
            remaining = {
                name: allocated[name] - consumed[name]
                for name in names
            }
            return {
                "round": self._round,
                "allocated": allocated,
                "consumed": consumed,
                "remaining": remaining,
            }

    def targets(self) -> list[dict]:
        with self._lock:
            return [
                self._public_target(record)
                for record in self._targets.values()
            ]

    def states(self) -> dict[str, str]:
        with self._lock:
            return {
                name: self._targets[name]["state"]
                for name in sorted(self._targets)
            }

    def round_no(self) -> int:
        with self._lock:
            return self._round

    def stats(self) -> dict:
        with self._lock:
            observing = sum(
                record["state"] == STATE_OBSERVING
                for record in self._targets.values()
            )
            return {
                "rounds": self._round,
                "targets": len(self._targets),
                "observing": observing,
                "yield_reports": self._counters["yield_reports"],
                "allocated_total": self._counters["allocated_total"],
                "consumed_total": self._counters["consumed_total"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": SNAPSHOT_VERSION,
                "round": self._round,
                "floor_quota": self.floor_quota,
                "yield_threshold": self.yield_threshold,
                "targets": copy.deepcopy(self._targets),
                "productive": sorted(self._productive),
                "allocated": copy.deepcopy(self._allocated),
                "consumed": copy.deepcopy(self._consumed),
                "counters": copy.deepcopy(self._counters),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                candidate = copy.deepcopy(state)
                restored = self._validated_snapshot(candidate)
            except AllocError:
                raise
            except Exception as exc:
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"reason": str(exc)},
                ) from exc

            self.floor_quota = restored["floor_quota"]
            self.yield_threshold = restored["yield_threshold"]
            self._round = restored["round"]
            self._targets = restored["targets"]
            self._productive = restored["productive"]
            self._allocated = restored["allocated"]
            self._consumed = restored["consumed"]
            self._counters = restored["counters"]

    @staticmethod
    def _validate_budget(total_budget: Any) -> None:
        if not _is_strict_int(total_budget) or total_budget <= 0:
            raise AllocError(
                "ALLOC_BAD_BUDGET",
                {"total_budget": total_budget},
            )

    def _yield_coefficient(self, yield_points: int) -> Fraction:
        threshold = self.yield_threshold
        if not _is_strict_int(threshold) or threshold <= 0:
            threshold = 1
        return Fraction(1 + yield_points // threshold, 1)

    def _effective_weights(self) -> dict[str, Fraction]:
        weights = {}
        for name, record in self._targets.items():
            registered_weight = Fraction(record["weight"])
            yield_factor = self._yield_coefficient(
                record["yield_points"]
            )
            decay = _decay_for_streak(record["zero_streak"])
            weights[name] = (
                registered_weight * yield_factor * decay
            )
        return weights

    def _plan_allocation(self, total_budget: int) -> dict[str, int]:
        names = sorted(self._targets)
        weights = self._effective_weights()
        floor_total = len(names) * self.floor_quota

        if total_budget < floor_total:
            return _largest_remainder(total_budget, weights)

        allocation = {name: self.floor_quota for name in names}
        remainder = total_budget - floor_total
        extra = _largest_remainder(remainder, weights)
        for name in names:
            allocation[name] += extra[name]
        return allocation

    def _advance_feedback_state(self) -> None:
        for name, record in self._targets.items():
            if name in self._productive:
                record["zero_streak"] = 0
            else:
                record["zero_streak"] += 1

            if record["zero_streak"] >= OBSERVE_AFTER_ROUNDS:
                record["state"] = STATE_OBSERVING
            else:
                record["state"] = STATE_ACTIVE
        self._productive.clear()

    @staticmethod
    def _public_target(record: dict[str, Any]) -> dict[str, Any]:
        return {
            "target": record["target"],
            "weight": record["weight"],
            "note": record["note"],
            "state": record["state"],
            "zero_streak": record["zero_streak"],
            "yield_points": record["yield_points"],
        }

    def _validated_snapshot(self, state: Any) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise AllocError(
                "ALLOC_SNAPSHOT_INVALID",
                "snapshot is not an object",
            )

        version = state.get("version")
        if (
            not _is_strict_int(version)
            or version != SNAPSHOT_VERSION
        ):
            raise AllocError(
                "ALLOC_SNAPSHOT_INVALID",
                {"version": version},
            )

        required = (
            "round",
            "floor_quota",
            "yield_threshold",
            "targets",
            "productive",
            "allocated",
            "consumed",
            "counters",
        )
        for key in required:
            if key not in state:
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"missing": key},
                )

        round_no = state["round"]
        floor_quota = state["floor_quota"]
        yield_threshold = state["yield_threshold"]
        if not _is_non_negative_int(round_no):
            raise AllocError(
                "ALLOC_SNAPSHOT_INVALID",
                {"round": round_no},
            )
        if not _is_non_negative_int(floor_quota):
            raise AllocError(
                "ALLOC_SNAPSHOT_INVALID",
                {"floor_quota": floor_quota},
            )
        if (
            not _is_strict_int(yield_threshold)
            or yield_threshold <= 0
        ):
            raise AllocError(
                "ALLOC_SNAPSHOT_INVALID",
                {"yield_threshold": yield_threshold},
            )

        raw_targets = state["targets"]
        if not isinstance(raw_targets, dict):
            raise AllocError(
                "ALLOC_SNAPSHOT_INVALID",
                {"targets": type(raw_targets).__name__},
            )

        targets: dict[str, dict[str, Any]] = {}
        for name, record in raw_targets.items():
            if not isinstance(name, str) or not name.strip():
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"target": name},
                )
            if not isinstance(record, dict):
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"target": name},
                )
            if record.get("target", name) != name:
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"target": name},
                )

            weight = record.get("weight")
            if not _valid_weight(weight):
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"weight": weight},
                )

            note = record.get("note", "")
            if not isinstance(note, str):
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"target": name},
                )

            target_state = record.get("state")
            zero_streak = record.get("zero_streak")
            yield_points = record.get("yield_points")
            reports = record.get("reports", 0)
            if target_state not in (STATE_ACTIVE, STATE_OBSERVING):
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"state": target_state},
                )
            if not _is_non_negative_int(zero_streak):
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"zero_streak": zero_streak},
                )
            if not _is_non_negative_int(yield_points):
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"yield_points": yield_points},
                )
            if not _is_non_negative_int(reports):
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"reports": reports},
                )

            expected_state = (
                STATE_OBSERVING
                if zero_streak >= OBSERVE_AFTER_ROUNDS
                else STATE_ACTIVE
            )
            if target_state != expected_state:
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"state": target_state},
                )

            targets[name] = {
                "target": name,
                "weight": float(weight),
                "note": note,
                "state": target_state,
                "zero_streak": zero_streak,
                "yield_points": yield_points,
                "reports": reports,
            }

        target_names = set(targets)
        allocated = self._validated_amount_map(
            state["allocated"], target_names, "allocated"
        )
        consumed = self._validated_amount_map(
            state["consumed"], target_names, "consumed"
        )
        for name in target_names:
            if consumed[name] > allocated[name]:
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"consumed": name},
                )

        raw_productive = state["productive"]
        if not isinstance(raw_productive, list):
            raise AllocError(
                "ALLOC_SNAPSHOT_INVALID",
                {"productive": type(raw_productive).__name__},
            )
        productive = set()
        for name in raw_productive:
            if not isinstance(name, str) or name not in target_names:
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"productive": name},
                )
            if name in productive:
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"productive": name},
                )
            if targets[name]["zero_streak"] != 0:
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {"productive": name},
                )
            productive.add(name)

        raw_counters = state["counters"]
        if not isinstance(raw_counters, dict):
            raise AllocError(
                "ALLOC_SNAPSHOT_INVALID",
                {"counters": type(raw_counters).__name__},
            )
        counters = {}
        for key in (
            "yield_reports",
            "allocated_total",
            "consumed_total",
        ):
            value = raw_counters.get(key)
            if not _is_non_negative_int(value):
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {key: value},
                )
            counters[key] = value

        if counters["yield_reports"] != sum(
            record["reports"] for record in targets.values()
        ):
            raise AllocError(
                "ALLOC_SNAPSHOT_INVALID",
                {"counters": "yield_reports"},
            )
        if counters["allocated_total"] < sum(allocated.values()):
            raise AllocError(
                "ALLOC_SNAPSHOT_INVALID",
                {"counters": "allocated_total"},
            )
        if counters["consumed_total"] < sum(consumed.values()):
            raise AllocError(
                "ALLOC_SNAPSHOT_INVALID",
                {"counters": "consumed_total"},
            )

        return {
            "round": round_no,
            "floor_quota": floor_quota,
            "yield_threshold": yield_threshold,
            "targets": targets,
            "productive": productive,
            "allocated": allocated,
            "consumed": consumed,
            "counters": counters,
        }

    @staticmethod
    def _validated_amount_map(
        raw: Any,
        target_names: set[str],
        label: str,
    ) -> dict[str, int]:
        if not isinstance(raw, dict):
            raise AllocError(
                "ALLOC_SNAPSHOT_INVALID",
                {label: type(raw).__name__},
            )
        if set(raw) != target_names:
            raise AllocError(
                "ALLOC_SNAPSHOT_INVALID",
                {label: "targets"},
            )

        result = {}
        for name, value in raw.items():
            if not isinstance(name, str) or name not in target_names:
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {label: name},
                )
            if not _is_non_negative_int(value):
                raise AllocError(
                    "ALLOC_SNAPSHOT_INVALID",
                    {label: value},
                )
            result[name] = value
        return result
