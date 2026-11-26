"""Atmospheric scattering lookup-table cache.

Splits the scattering table into buckets addressed by sun altitude and
azimuth, rebuilds only the buckets affected by a weather preset change and
evicts the least used bucket when the cache grows past its capacity.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "AtmosphereCacheError",
    "BucketStats",
    "AtmosphereScatterCache",
    "ALT_MIN",
    "ALT_STEP",
    "ALT_BUCKETS",
    "AZ_STEP",
    "AZ_BUCKETS",
    "WEATHER_PRESETS",
    "LOW_ALTITUDE_LIMIT",
]

ALT_MIN = -90.0
ALT_STEP = 5.0
ALT_BUCKETS = 36
AZ_STEP = 15.0
AZ_BUCKETS = 24
DEFAULT_SAMPLES = 8
WEATHER_PRESETS = {"clear": 1000, "hazy": 1400, "overcast": 1800}
LOW_ALTITUDE_LIMIT = 10.0


class AtmosphereCacheError(ValueError):
    """Raised when a scatter-cache request is rejected."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class BucketStats:
    bucket: tuple[int, int]
    cached: bool
    builds: int
    lookups: int
    boundary_fallbacks: int
    density: int
    values: tuple[int, ...] | None


class AtmosphereScatterCache:
    """Bucket the scattering tables of one scene by sun angle."""

    def __init__(self, *, capacity: int = 8, samples: int = DEFAULT_SAMPLES,
                 boundary_tolerance: float = 5.0) -> None:
        self.capacity = capacity
        self.samples = samples
        self.boundary_tolerance = boundary_tolerance
        self._lock = threading.RLock()

    def set_sun(self, altitude: float, azimuth: float) -> tuple[int, int]:
        raise NotImplementedError

    def bucket_for(self, altitude: float, azimuth: float) -> tuple[int, int]:
        raise NotImplementedError

    def build(self, altitude: float, azimuth: float) -> tuple[int, ...]:
        raise NotImplementedError

    def lookup(self, altitude: float, azimuth: float, index: int) -> float:
        raise NotImplementedError

    def invalidate(self, altitude: float, azimuth: float) -> bool:
        raise NotImplementedError

    def set_weather(self, preset: str) -> int:
        raise NotImplementedError

    def resize(self, capacity: int) -> int:
        raise NotImplementedError

    def stats_of(self, altitude: float, azimuth: float) -> BucketStats:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
