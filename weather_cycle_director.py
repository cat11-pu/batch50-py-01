"""Weather cycle director: per-region states, forecast windows, override stack."""

from __future__ import annotations

import copy
import random
import threading


MAX_OVERRIDES_PER_REGION = 32
_SNAPSHOT_VERSION = 1
_STATS_KEYS = frozenset({
    "ticks", "regions", "switches", "overrides", "cleared", "expired",
    "forecasts",
})
_REGION_KEYS = frozenset({
    "seed", "state", "remaining", "transition_from", "transition_elapsed",
    "overrides", "next_order", "rng_state",
})
_OVERRIDE_KEYS = frozenset({
    "state", "priority", "source", "remaining", "order",
})


class WeatherError(ValueError):
    """Raised when a weather operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _is_int(value: object) -> bool:
    return type(value) is int


def _coerce_rng_state(value: object) -> tuple:
    if isinstance(value, tuple):
        return tuple(_coerce_rng_state(item) for item in value)
    if isinstance(value, list):
        return tuple(_coerce_rng_state(item) for item in value)
    return value


class WeatherCycleDirector:
    """Drive day/night weather states per region with forecasts and overrides."""

    def __init__(self, *, max_regions: int = 24, max_forecast: int = 6,
                 transition_ticks: int = 4, seed: int = 7,
                 states=None, durations=None) -> None:
        if not _is_int(max_regions) or max_regions < 0:
            raise WeatherError("WEATHER_INVALID_REQUEST", "invalid max_regions")
        if not _is_int(max_forecast) or max_forecast < 1:
            raise WeatherError("WEATHER_INVALID_REQUEST", "invalid max_forecast")
        if not _is_int(transition_ticks) or transition_ticks < 0:
            raise WeatherError(
                "WEATHER_INVALID_REQUEST", "invalid transition_ticks")
        if not _is_int(seed):
            raise WeatherError("WEATHER_INVALID_REQUEST", "invalid seed")

        if states is None:
            normalized_states = ("clear", "cloudy", "rain", "storm")
        else:
            if isinstance(states, (str, bytes)):
                raise WeatherError("WEATHER_INVALID_REQUEST", "invalid states")
            try:
                normalized_states = tuple(states)
            except TypeError as exc:
                raise WeatherError(
                    "WEATHER_INVALID_REQUEST", "invalid states") from exc
            if not normalized_states or any(
                    type(item) is not str or not item.strip()
                    for item in normalized_states):
                raise WeatherError("WEATHER_INVALID_REQUEST", "invalid states")
            if len(set(normalized_states)) != len(normalized_states):
                raise WeatherError("WEATHER_INVALID_REQUEST", "duplicate states")

        if durations is None:
            if normalized_states != ("clear", "cloudy", "rain", "storm"):
                raise WeatherError(
                    "WEATHER_INVALID_REQUEST", "missing durations")
            normalized_durations = {
                "clear": 20, "cloudy": 15, "rain": 12, "storm": 8,
            }
        else:
            try:
                normalized_durations = dict(durations)
            except (TypeError, ValueError) as exc:
                raise WeatherError(
                    "WEATHER_INVALID_REQUEST", "invalid durations") from exc
            for state in normalized_states:
                value = normalized_durations.get(state)
                if not _is_int(value) or value <= 0:
                    raise WeatherError(
                        "WEATHER_INVALID_REQUEST",
                        {"state": state, "duration": value},
                    )

        self.max_regions = max_regions
        self.max_forecast = max_forecast
        self.transition_ticks = transition_ticks
        self.seed = seed
        self.states = normalized_states
        self.durations = normalized_durations
        self._lock = threading.RLock()
        self._regions: dict[str, dict] = {}
        self._tick = 0
        self._stats = {
            "ticks": 0,
            "regions": 0,
            "switches": 0,
            "overrides": 0,
            "cleared": 0,
            "expired": 0,
            "forecasts": 0,
        }

    def _region_id(self, region_id: object) -> str:
        if type(region_id) is not str:
            raise WeatherError(
                "WEATHER_INVALID_REQUEST", "region_id must be a string")
        normalized = region_id.strip()
        if not normalized:
            raise WeatherError(
                "WEATHER_INVALID_REQUEST", "region_id must not be empty")
        return normalized

    def _known_region(self, region_id: object) -> tuple[str, dict]:
        normalized = self._region_id(region_id)
        try:
            return normalized, self._regions[normalized]
        except KeyError as exc:
            raise WeatherError(
                "WEATHER_UNKNOWN_REGION", normalized) from exc

    def _validate_state(self, state: object) -> str:
        if type(state) is not str or state not in self.durations:
            raise WeatherError("WEATHER_INVALID_REQUEST", {"state": state})
        return state

    def _pick_next(self, current: str, rng: random.Random) -> str:
        candidates = [state for state in self.states if state != current]
        if not candidates:
            candidates = list(self.states)
        return rng.choice(candidates)

    def _blend(self, elapsed: int) -> float:
        if self.transition_ticks == 0:
            return 1.0
        return min(elapsed, self.transition_ticks) / self.transition_ticks

    def _active_layer(self, region: dict):
        layer = None
        for candidate in region["overrides"]:
            if layer is None:
                layer = candidate
                continue
            key = (candidate["priority"], candidate["order"])
            current_key = (layer["priority"], layer["order"])
            if key > current_key:
                layer = candidate
        return layer

    @staticmethod
    def _public_layer(layer: dict) -> dict:
        return {
            "state": layer["state"],
            "priority": layer["priority"],
            "source": layer["source"],
            "remaining": layer["remaining"],
        }

    def _advance_natural(self, region: dict, ticks: int,
                         start_tick: int) -> list:
        events = []
        consumed = 0

        while consumed < ticks:
            step = min(region["remaining"], ticks - consumed)
            if region["transition_from"] is not None:
                region["transition_elapsed"] = min(
                    self.transition_ticks,
                    region["transition_elapsed"] + step,
                )

            region["remaining"] -= step
            consumed += step
            if region["remaining"] > 0:
                break

            previous = region["state"]
            elapsed = region["transition_elapsed"]
            carried = (
                elapsed if elapsed < self.transition_ticks else 0
            )
            following = self._pick_next(previous, region["rng"])

            region["state"] = following
            region["remaining"] = self.durations[following]
            region["transition_from"] = previous
            region["transition_elapsed"] = carried
            events.append({
                "tick": start_tick + consumed,
                "region": region["region"],
                "from": previous,
                "to": following,
            })

        return events

    def _advance_overrides(self, region: dict, ticks: int) -> int:
        expired = 0
        kept = []
        for layer in region["overrides"]:
            remaining = layer["remaining"]
            if remaining is None:
                kept.append(layer)
            elif remaining <= ticks:
                expired += 1
            else:
                layer["remaining"] = remaining - ticks
                kept.append(layer)
        region["overrides"] = kept
        return expired

    def register_region(self, region_id: str, *, seed=None, state=None,
                        remaining=None) -> dict:
        with self._lock:
            normalized = self._region_id(region_id)
            if normalized in self._regions:
                raise WeatherError("WEATHER_REGION_EXISTS", normalized)

            selected_state = (
                self.states[0] if state is None else self._validate_state(state)
            )
            if remaining is None:
                selected_remaining = self.durations[selected_state]
            else:
                if not _is_int(remaining) or remaining <= 0:
                    raise WeatherError(
                        "WEATHER_INVALID_REQUEST", {"remaining": remaining})
                selected_remaining = remaining

            selected_seed = self.seed if seed is None else seed
            if not _is_int(selected_seed):
                raise WeatherError(
                    "WEATHER_INVALID_REQUEST", {"seed": seed})

            if len(self._regions) >= self.max_regions:
                raise WeatherError(
                    "WEATHER_CAPACITY_EXCEEDED", len(self._regions))

            rng = random.Random(selected_seed)
            region = {
                "region": normalized,
                "seed": selected_seed,
                "state": selected_state,
                "remaining": selected_remaining,
                "transition_from": None,
                "transition_elapsed": self.transition_ticks,
                "overrides": [],
                "next_order": 0,
                "rng": rng,
            }
            self._regions[normalized] = region
            self._stats["regions"] = len(self._regions)
            return {
                "region": normalized,
                "state": selected_state,
                "remaining": selected_remaining,
                "seed": selected_seed,
                "overridden": False,
            }

    def advance(self, ticks: int = 1) -> list:
        if not _is_int(ticks) or ticks <= 0:
            raise WeatherError("WEATHER_INVALID_REQUEST", {"ticks": ticks})

        with self._lock:
            start_tick = self._tick
            events = []
            expired = 0
            for region in self._regions.values():
                events.extend(
                    self._advance_natural(region, ticks, start_tick))
                expired += self._advance_overrides(region, ticks)

            self._tick += ticks
            self._stats["ticks"] += ticks
            self._stats["switches"] += len(events)
            self._stats["expired"] += expired
            events.sort(key=lambda event: (event["tick"], event["region"]))
            return events

    def current(self, region_id: str) -> dict:
        with self._lock:
            normalized, region = self._known_region(region_id)
            layer = self._active_layer(region)
            return {
                "region": normalized,
                "state": layer["state"] if layer is not None else region["state"],
                "remaining": region["remaining"],
                "blend": self._blend(region["transition_elapsed"]),
                "overridden": layer is not None,
                "source": layer["source"] if layer is not None else "natural",
            }

    def transition_state(self, region_id: str) -> dict:
        with self._lock:
            normalized, region = self._known_region(region_id)
            elapsed = min(
                region["transition_elapsed"], self.transition_ticks)
            return {
                "region": normalized,
                "from": region["transition_from"],
                "to": region["state"],
                "elapsed": elapsed,
                "total": self.transition_ticks,
                "blend": self._blend(elapsed),
            }

    def forecast(self, region_id: str, *, slots=None) -> list:
        if slots is None:
            selected_slots = 3
        else:
            selected_slots = slots
        if (not _is_int(selected_slots) or selected_slots < 1
                or selected_slots > self.max_forecast):
            raise WeatherError(
                "WEATHER_INVALID_REQUEST", {"slots": slots})

        with self._lock:
            _, region = self._known_region(region_id)
            rng = random.Random()
            rng.setstate(region["rng"].getstate())
            state = region["state"]
            duration = region["remaining"]
            rows = []
            for slot in range(1, selected_slots + 1):
                rows.append({
                    "slot": slot,
                    "state": state,
                    "ticks": duration,
                })
                state = self._pick_next(state, rng)
                duration = self.durations[state]

            self._stats["forecasts"] += 1
            return rows

    def override(self, region_id: str, state: str, *, priority: int = 0,
                 source: str = "event", duration=None) -> dict:
        with self._lock:
            _, region = self._known_region(region_id)
            selected_state = self._validate_state(state)
            if not _is_int(priority):
                raise WeatherError(
                    "WEATHER_INVALID_REQUEST", {"priority": priority})
            if type(source) is not str or not source.strip():
                raise WeatherError(
                    "WEATHER_INVALID_REQUEST", {"source": source})
            normalized_source = source.strip()
            if duration is not None and (
                    not _is_int(duration) or duration <= 0):
                raise WeatherError(
                    "WEATHER_INVALID_REQUEST", {"duration": duration})
            if len(region["overrides"]) >= MAX_OVERRIDES_PER_REGION:
                raise WeatherError(
                    "WEATHER_CAPACITY_EXCEEDED",
                    {"overrides": len(region["overrides"])},
                )

            region["next_order"] += 1
            layer = {
                "state": selected_state,
                "priority": priority,
                "source": normalized_source,
                "remaining": duration,
                "order": region["next_order"],
            }
            region["overrides"].append(layer)
            self._stats["overrides"] += 1
            return self._public_layer(layer)

    def clear_override(self, region_id: str, *, priority=None,
                       source=None) -> int:
        with self._lock:
            _, region = self._known_region(region_id)
            if priority is not None and not _is_int(priority):
                raise WeatherError(
                    "WEATHER_INVALID_REQUEST", {"priority": priority})
            if source is not None and type(source) is not str:
                raise WeatherError(
                    "WEATHER_INVALID_REQUEST", {"source": source})
            normalized_source = source.strip() if source is not None else None
            if source is not None and not normalized_source:
                raise WeatherError(
                    "WEATHER_INVALID_REQUEST", {"source": source})

            kept = []
            removed = 0
            for layer in region["overrides"]:
                priority_match = (
                    priority is None or layer["priority"] == priority)
                source_match = (
                    normalized_source is None
                    or layer["source"] == normalized_source)
                if priority_match and source_match:
                    removed += 1
                else:
                    kept.append(layer)

            if removed == 0:
                raise WeatherError("WEATHER_OVERRIDE_EMPTY")

            region["overrides"] = kept
            self._stats["cleared"] += removed
            return removed

    def active_overrides(self, region_id: str) -> list:
        with self._lock:
            _, region = self._known_region(region_id)
            layers = sorted(
                region["overrides"],
                key=lambda layer: (layer["priority"], layer["order"]),
                reverse=True,
            )
            return [self._public_layer(layer) for layer in layers]

    def list_regions(self) -> list:
        with self._lock:
            return sorted(self._regions)

    def snapshot(self) -> dict:
        with self._lock:
            regions = {}
            for region_id, region in self._regions.items():
                regions[region_id] = {
                    "seed": region["seed"],
                    "state": region["state"],
                    "remaining": region["remaining"],
                    "transition_from": region["transition_from"],
                    "transition_elapsed": region["transition_elapsed"],
                    "overrides": copy.deepcopy(region["overrides"]),
                    "next_order": region["next_order"],
                    "rng_state": copy.deepcopy(region["rng"].getstate()),
                }
            return {
                "version": _SNAPSHOT_VERSION,
                "tick": self._tick,
                "regions": regions,
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        try:
            if not isinstance(state, dict):
                raise ValueError
            if set(state) != {"version", "tick", "regions", "stats"}:
                raise ValueError
            if not _is_int(state["version"]) or state["version"] != 1:
                raise ValueError
            if not _is_int(state["tick"]) or state["tick"] < 0:
                raise ValueError
            if not isinstance(state["regions"], dict):
                raise ValueError
            if len(state["regions"]) > self.max_regions:
                raise ValueError
            if not isinstance(state["stats"], dict):
                raise ValueError
            if set(state["stats"]) != _STATS_KEYS:
                raise ValueError
            for value in state["stats"].values():
                if not _is_int(value) or value < 0:
                    raise ValueError

            restored_regions = {}
            for region_id, raw_region in state["regions"].items():
                if type(region_id) is not str:
                    raise ValueError
                if region_id != region_id.strip() or not region_id:
                    raise ValueError
                if region_id in restored_regions:
                    raise ValueError
                if not isinstance(raw_region, dict):
                    raise ValueError
                if set(raw_region) != _REGION_KEYS:
                    raise ValueError

                seed = raw_region["seed"]
                selected_state = raw_region["state"]
                remaining = raw_region["remaining"]
                transition_from = raw_region["transition_from"]
                transition_elapsed = raw_region["transition_elapsed"]
                overrides = raw_region["overrides"]
                next_order = raw_region["next_order"]
                rng_state = raw_region["rng_state"]

                if not _is_int(seed):
                    raise ValueError
                if selected_state not in self.durations:
                    raise ValueError
                if not _is_int(remaining) or remaining <= 0:
                    raise ValueError
                if (transition_from is not None
                        and transition_from not in self.durations):
                    raise ValueError
                if (not _is_int(transition_elapsed)
                        or transition_elapsed < 0
                        or transition_elapsed > self.transition_ticks):
                    raise ValueError
                if not isinstance(overrides, list):
                    raise ValueError
                if len(overrides) > MAX_OVERRIDES_PER_REGION:
                    raise ValueError
                if not _is_int(next_order) or next_order < 0:
                    raise ValueError

                restored_overrides = []
                largest_order = 0
                for raw_layer in overrides:
                    if not isinstance(raw_layer, dict):
                        raise ValueError
                    if set(raw_layer) != _OVERRIDE_KEYS:
                        raise ValueError
                    layer_state = raw_layer["state"]
                    layer_priority = raw_layer["priority"]
                    layer_source = raw_layer["source"]
                    layer_remaining = raw_layer["remaining"]
                    layer_order = raw_layer["order"]
                    if layer_state not in self.durations:
                        raise ValueError
                    if not _is_int(layer_priority):
                        raise ValueError
                    if (type(layer_source) is not str
                            or not layer_source
                            or layer_source != layer_source.strip()):
                        raise ValueError
                    if layer_remaining is not None and (
                            not _is_int(layer_remaining)
                            or layer_remaining <= 0):
                        raise ValueError
                    if not _is_int(layer_order) or layer_order < 1:
                        raise ValueError
                    largest_order = max(largest_order, layer_order)
                    restored_overrides.append(copy.deepcopy(raw_layer))

                if next_order < largest_order:
                    raise ValueError

                rng = random.Random(seed)
                try:
                    rng.setstate(_coerce_rng_state(copy.deepcopy(rng_state)))
                except (TypeError, ValueError):
                    raise ValueError from None

                restored_regions[region_id] = {
                    "region": region_id,
                    "seed": seed,
                    "state": selected_state,
                    "remaining": remaining,
                    "transition_from": transition_from,
                    "transition_elapsed": transition_elapsed,
                    "overrides": restored_overrides,
                    "next_order": next_order,
                    "rng": rng,
                }

            restored_tick = state["tick"]
            restored_stats = copy.deepcopy(state["stats"])
            restored_stats["regions"] = len(restored_regions)
        except (KeyError, TypeError, ValueError):
            raise WeatherError(
                "WEATHER_SNAPSHOT_INVALID", "invalid snapshot") from None

        with self._lock:
            self._regions = restored_regions
            self._tick = restored_tick
            self._stats = restored_stats

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)
