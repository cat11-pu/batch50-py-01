"""Weather cycle director: per-region states, forecast windows, override stack."""

from __future__ import annotations

import threading


class WeatherError(ValueError):
    """Raised when a weather operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class WeatherCycleDirector:
    """Drive day/night weather states per region with forecasts and overrides."""

    def __init__(self, *, max_regions: int = 24, max_forecast: int = 6,
                 transition_ticks: int = 4, seed: int = 7,
                 states=None, durations=None) -> None:
        self.max_regions = max_regions
        self.max_forecast = max_forecast
        self.transition_ticks = transition_ticks
        self.seed = seed
        self.states = tuple(states) if states is not None else (
            "clear", "cloudy", "rain", "storm")
        self.durations = dict(durations) if durations is not None else {
            "clear": 20, "cloudy": 15, "rain": 12, "storm": 8}
        self._lock = threading.RLock()

    def register_region(self, region_id: str, *, seed=None, state=None,
                        remaining=None) -> dict:
        raise NotImplementedError

    def advance(self, ticks: int = 1) -> list:
        raise NotImplementedError

    def current(self, region_id: str) -> dict:
        raise NotImplementedError

    def transition_state(self, region_id: str) -> dict:
        raise NotImplementedError

    def forecast(self, region_id: str, *, slots=None) -> list:
        raise NotImplementedError

    def override(self, region_id: str, state: str, *, priority: int = 0,
                 source: str = "event", duration=None) -> dict:
        raise NotImplementedError

    def clear_override(self, region_id: str, *, priority=None,
                       source=None) -> int:
        raise NotImplementedError

    def active_overrides(self, region_id: str) -> list:
        raise NotImplementedError

    def list_regions(self) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
