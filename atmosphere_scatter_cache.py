"""Atmospheric scattering lookup-table cache.

Splits the scattering table into buckets addressed by sun altitude and
azimuth, rebuilds only the buckets affected by a weather preset change and
evicts the least used bucket when the cache grows past its capacity.
"""

from __future__ import annotations

import copy
import math
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
SNAPSHOT_VERSION = 1

_SNAPSHOT_KEYS = {
    "version",
    "weather",
    "sun",
    "settings",
    "buckets",
    "registry",
    "counters",
}
_SETTING_KEYS = {"capacity", "samples", "boundary_tolerance"}
_COUNTER_KEYS = {
    "builds",
    "evictions",
    "lookups",
    "invalidations",
    "weather_changes",
    "build_seq",
}
_REGISTRY_KEYS = {
    "builds",
    "lookups",
    "boundary_fallbacks",
    "build_seq",
    "density",
}


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
        if not self._valid_capacity(capacity):
            raise AtmosphereCacheError(
                "ATMOSPHERE_INVALID_CAPACITY", capacity)
        if not self._valid_nonnegative_int(samples) or samples == 0:
            raise AtmosphereCacheError("ATMOSPHERE_INVALID_SAMPLES", samples)
        if not self._valid_tolerance(boundary_tolerance):
            raise AtmosphereCacheError(
                "ATMOSPHERE_INVALID_SETTINGS", boundary_tolerance)

        self._capacity = capacity
        self._samples = samples
        self._boundary_tolerance = float(boundary_tolerance)
        self._lock = threading.RLock()
        self._weather = "clear"
        self._sun: tuple[float, float] | None = None
        self._buckets: dict[tuple[int, int], tuple[int, ...]] = {}
        self._registry: dict[tuple[int, int], dict[str, int]] = {}
        self._counters = {key: 0 for key in _COUNTER_KEYS}

    @property
    def capacity(self) -> int:
        return self._capacity

    @property
    def samples(self) -> int:
        return self._samples

    @property
    def boundary_tolerance(self) -> float:
        return self._boundary_tolerance

    @staticmethod
    def _valid_nonnegative_int(value: object) -> bool:
        return (isinstance(value, int) and not isinstance(value, bool)
                and value >= 0)

    @classmethod
    def _valid_capacity(cls, value: object) -> bool:
        return cls._valid_nonnegative_int(value) and value > 0

    @staticmethod
    def _valid_tolerance(value: object) -> bool:
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return False
        return math.isfinite(value) and value >= 0.0

    @staticmethod
    def _validate_angle(altitude: float, azimuth: float) -> tuple[float, float]:
        if (isinstance(altitude, bool) or isinstance(azimuth, bool)
                or not isinstance(altitude, (int, float))
                or not isinstance(azimuth, (int, float))):
            raise AtmosphereCacheError(
                "ATMOSPHERE_INVALID_ANGLE", (altitude, azimuth))
        try:
            alt = float(altitude)
            az = float(azimuth)
        except (OverflowError, TypeError, ValueError):
            raise AtmosphereCacheError(
                "ATMOSPHERE_INVALID_ANGLE", (altitude, azimuth)) from None
        if (not math.isfinite(alt) or not math.isfinite(az)
                or alt < -90.0 or alt > 90.0
                or az < 0.0 or az >= 360.0):
            raise AtmosphereCacheError(
                "ATMOSPHERE_INVALID_ANGLE", (altitude, azimuth))
        return alt, az

    @staticmethod
    def _bucket_for_validated(
            altitude: float, azimuth: float) -> tuple[int, int]:
        altitude_bucket = int(math.floor((altitude - ALT_MIN) / ALT_STEP))
        altitude_bucket = min(max(altitude_bucket, 0), ALT_BUCKETS - 1)
        azimuth_bucket = int(math.floor(azimuth / AZ_STEP))
        azimuth_bucket = min(max(azimuth_bucket, 0), AZ_BUCKETS - 1)
        return altitude_bucket, azimuth_bucket

    @staticmethod
    def _altitude_centre(bucket: int) -> float:
        return ALT_MIN + (bucket + 0.5) * ALT_STEP

    @staticmethod
    def _azimuth_centre(bucket: int) -> float:
        return (bucket + 0.5) * AZ_STEP

    @staticmethod
    def _density(preset: str) -> int:
        return WEATHER_PRESETS[preset]

    def _table_values(
            self, bucket: tuple[int, int], density: int) -> tuple[int, ...]:
        altitude_bucket, azimuth_bucket = bucket
        return tuple(
            ((altitude_bucket * 1000 + azimuth_bucket * 37 + index * 3)
             * density) // 1000
            for index in range(self._samples)
        )

    def _registry_entry(
            self, bucket: tuple[int, int], *, create: bool = False
    ) -> dict[str, int] | None:
        entry = self._registry.get(bucket)
        if entry is None and create:
            entry = {
                "builds": 0,
                "lookups": 0,
                "boundary_fallbacks": 0,
                "build_seq": 0,
                "density": self._density(self._weather),
            }
            self._registry[bucket] = entry
        return entry

    def _evict_until(self, target: int) -> int:
        evicted = 0
        while len(self._buckets) > target:
            victim = min(
                self._buckets,
                key=lambda bucket: (
                    self._registry[bucket]["lookups"],
                    self._registry[bucket]["build_seq"],
                    bucket,
                ),
            )
            del self._buckets[victim]
            self._counters["evictions"] += 1
            evicted += 1
        return evicted

    def _ensure_bucket(self, bucket: tuple[int, int]) -> tuple[int, ...]:
        cached = self._buckets.get(bucket)
        if cached is not None:
            return cached

        values = self._table_values(bucket, self._density(self._weather))
        if len(self._buckets) >= self._capacity:
            self._evict_until(self._capacity - 1)

        entry = self._registry_entry(bucket, create=True)
        assert entry is not None
        self._counters["builds"] += 1
        self._counters["build_seq"] += 1
        entry["builds"] += 1
        entry["build_seq"] = self._counters["build_seq"]
        entry["density"] = self._density(self._weather)
        self._buckets[bucket] = values
        return values

    def _altitude_weights(self, altitude: float) -> list[tuple[int, float]]:
        first = 0
        last = ALT_BUCKETS - 1
        if altitude <= self._altitude_centre(first):
            return [(first, 1.0)]
        if altitude >= self._altitude_centre(last):
            return [(last, 1.0)]

        lower = int(math.floor(
            (altitude - self._altitude_centre(first)) / ALT_STEP))
        lower = min(max(lower, first), last - 1)
        centre = self._altitude_centre(lower)
        if altitude == centre:
            return [(lower, 1.0)]
        fraction = (altitude - centre) / ALT_STEP
        return [(lower, 1.0 - fraction), (lower + 1, fraction)]

    def _azimuth_weights(self, azimuth: float) -> list[tuple[int, float]]:
        first = 0
        last = AZ_BUCKETS - 1
        first_centre = self._azimuth_centre(first)
        last_centre = self._azimuth_centre(last)

        if azimuth == first_centre:
            return [(first, 1.0)]
        if azimuth == last_centre:
            return [(last, 1.0)]
        if azimuth < first_centre:
            lower = last
            fraction = (azimuth - (last_centre - 360.0)) / AZ_STEP
        elif azimuth > last_centre:
            lower = last
            fraction = (azimuth - last_centre) / AZ_STEP
        else:
            lower = int(math.floor(
                (azimuth - first_centre) / AZ_STEP))
            lower = min(max(lower, first), last - 1)
            fraction = (azimuth - self._azimuth_centre(lower)) / AZ_STEP

        if fraction == 0.0:
            return [(lower, 1.0)]
        return [(lower, 1.0 - fraction), ((lower + 1) % AZ_BUCKETS, fraction)]

    @staticmethod
    def _values_differ_beyond_tolerance(
            values: dict[tuple[int, int], int],
            altitude_weights: list[tuple[int, float]],
            azimuth_weights: list[tuple[int, float]],
            tolerance: float,
    ) -> bool:
        altitude_buckets = [bucket for bucket, _ in altitude_weights]
        azimuth_buckets = [bucket for bucket, _ in azimuth_weights]

        if len(altitude_buckets) == 2:
            for azimuth_bucket in azimuth_buckets:
                left = values[(altitude_buckets[0], azimuth_bucket)]
                right = values[(altitude_buckets[1], azimuth_bucket)]
                if abs(right - left) > tolerance:
                    return True

        if len(azimuth_buckets) == 2:
            for altitude_bucket in altitude_buckets:
                left = values[(altitude_bucket, azimuth_buckets[0])]
                right = values[(altitude_bucket, azimuth_buckets[1])]
                if abs(right - left) > tolerance:
                    return True

        return False

    def set_sun(self, altitude: float, azimuth: float) -> tuple[int, int]:
        alt, az = self._validate_angle(altitude, azimuth)
        bucket = self._bucket_for_validated(alt, az)
        with self._lock:
            self._sun = (alt, az)
        return bucket

    def bucket_for(self, altitude: float, azimuth: float) -> tuple[int, int]:
        alt, az = self._validate_angle(altitude, azimuth)
        return self._bucket_for_validated(alt, az)

    def build(self, altitude: float, azimuth: float) -> tuple[int, ...]:
        alt, az = self._validate_angle(altitude, azimuth)
        bucket = self._bucket_for_validated(alt, az)
        with self._lock:
            return self._ensure_bucket(bucket)

    def lookup(self, altitude: float, azimuth: float, index: int) -> float:
        alt, az = self._validate_angle(altitude, azimuth)
        if (isinstance(index, bool) or not isinstance(index, int)
                or index < 0 or index >= self._samples):
            raise AtmosphereCacheError("ATMOSPHERE_INVALID_INDEX", index)

        request_bucket = self._bucket_for_validated(alt, az)
        with self._lock:
            altitude_weights = self._altitude_weights(alt)
            azimuth_weights = self._azimuth_weights(az)
            tables = {
                bucket: self._ensure_bucket(bucket)
                for bucket in sorted({
                    (altitude_bucket, azimuth_bucket)
                    for altitude_bucket, _ in altitude_weights
                    for azimuth_bucket, _ in azimuth_weights
                })
            }

            sampled_values = {
                bucket: table[index] for bucket, table in tables.items()
            }
            result = 0.0
            for altitude_bucket, altitude_weight in altitude_weights:
                for azimuth_bucket, azimuth_weight in azimuth_weights:
                    result += (
                        altitude_weight
                        * azimuth_weight
                        * sampled_values[(altitude_bucket, azimuth_bucket)]
                    )

            entry = self._registry_entry(request_bucket, create=True)
            assert entry is not None
            self._counters["lookups"] += 1
            entry["lookups"] += 1
            if self._values_differ_beyond_tolerance(
                    sampled_values,
                    altitude_weights,
                    azimuth_weights,
                    self._boundary_tolerance):
                entry["boundary_fallbacks"] += 1

            return round(result, 4)

    def invalidate(self, altitude: float, azimuth: float) -> bool:
        alt, az = self._validate_angle(altitude, azimuth)
        bucket = self._bucket_for_validated(alt, az)
        with self._lock:
            if bucket not in self._buckets:
                return False
            del self._buckets[bucket]
            self._counters["invalidations"] += 1
            return True

    def set_weather(self, preset: str) -> int:
        if not isinstance(preset, str) or preset not in WEATHER_PRESETS:
            raise AtmosphereCacheError("ATMOSPHERE_UNKNOWN_PRESET", preset)
        with self._lock:
            if preset == self._weather:
                return 0

            self._weather = preset
            removed = 0
            for bucket in list(self._buckets):
                altitude_centre = self._altitude_centre(bucket[0])
                if altitude_centre < LOW_ALTITUDE_LIMIT:
                    del self._buckets[bucket]
                    removed += 1
            self._counters["weather_changes"] += 1
            return removed

    def resize(self, capacity: int) -> int:
        if not self._valid_capacity(capacity):
            raise AtmosphereCacheError(
                "ATMOSPHERE_INVALID_CAPACITY", capacity)
        with self._lock:
            if capacity > self._capacity:
                self._capacity = capacity
                return 0
            if capacity == self._capacity:
                return 0
            evicted = self._evict_until(capacity)
            self._capacity = capacity
            return evicted

    def stats_of(self, altitude: float, azimuth: float) -> BucketStats:
        alt, az = self._validate_angle(altitude, azimuth)
        bucket = self._bucket_for_validated(alt, az)
        with self._lock:
            entry = self._registry.get(bucket)
            cached_values = self._buckets.get(bucket)
            if entry is None:
                return BucketStats(
                    bucket=bucket,
                    cached=False,
                    builds=0,
                    lookups=0,
                    boundary_fallbacks=0,
                    density=self._density(self._weather),
                    values=None,
                )
            return BucketStats(
                bucket=bucket,
                cached=cached_values is not None,
                builds=entry["builds"],
                lookups=entry["lookups"],
                boundary_fallbacks=entry["boundary_fallbacks"],
                density=entry["density"],
                values=cached_values,
            )

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy({
                "version": SNAPSHOT_VERSION,
                "weather": self._weather,
                "sun": self._sun,
                "settings": {
                    "capacity": self._capacity,
                    "samples": self._samples,
                    "boundary_tolerance": self._boundary_tolerance,
                },
                "buckets": self._buckets,
                "registry": self._registry,
                "counters": self._counters,
            })

    @classmethod
    def _snapshot_invalid(cls, detail: object) -> AtmosphereCacheError:
        return AtmosphereCacheError("ATMOSPHERE_SNAPSHOT_INVALID", detail)

    @classmethod
    def _validate_bucket_key(cls, bucket: object) -> tuple[int, int]:
        if (not isinstance(bucket, tuple) or len(bucket) != 2
                or not cls._valid_nonnegative_int(bucket[0])
                or not cls._valid_nonnegative_int(bucket[1])
                or bucket[0] >= ALT_BUCKETS or bucket[1] >= AZ_BUCKETS):
            raise cls._snapshot_invalid(bucket)
        return bucket

    def _validated_snapshot_state(self, state: object) -> dict:
        try:
            data = copy.deepcopy(state)
        except Exception as exc:
            raise self._snapshot_invalid(type(exc).__name__) from None

        if not isinstance(data, dict) or set(data) != _SNAPSHOT_KEYS:
            raise self._snapshot_invalid(data)
        if (not self._valid_nonnegative_int(data["version"])
                or data["version"] != SNAPSHOT_VERSION):
            raise self._snapshot_invalid(data["version"])

        weather = data["weather"]
        if not isinstance(weather, str) or weather not in WEATHER_PRESETS:
            raise self._snapshot_invalid(weather)

        sun = data["sun"]
        if sun is not None:
            if (not isinstance(sun, tuple) or len(sun) != 2
                    or isinstance(sun[0], bool) or isinstance(sun[1], bool)
                    or not isinstance(sun[0], (int, float))
                    or not isinstance(sun[1], (int, float))):
                raise self._snapshot_invalid(sun)
            try:
                self._validate_angle(sun[0], sun[1])
            except AtmosphereCacheError:
                raise self._snapshot_invalid(sun) from None

        settings = data["settings"]
        if not isinstance(settings, dict) or set(settings) != _SETTING_KEYS:
            raise self._snapshot_invalid(settings)
        capacity = settings["capacity"]
        samples = settings["samples"]
        tolerance = settings["boundary_tolerance"]
        if not self._valid_capacity(capacity):
            raise self._snapshot_invalid(settings)
        if not self._valid_nonnegative_int(samples) or samples == 0:
            raise self._snapshot_invalid(settings)
        if not self._valid_tolerance(tolerance):
            raise self._snapshot_invalid(settings)

        counters = data["counters"]
        if not isinstance(counters, dict) or set(counters) != _COUNTER_KEYS:
            raise self._snapshot_invalid(counters)
        if any(not self._valid_nonnegative_int(value)
               for value in counters.values()):
            raise self._snapshot_invalid(counters)

        buckets = data["buckets"]
        if not isinstance(buckets, dict):
            raise self._snapshot_invalid(buckets)
        if len(buckets) > capacity:
            raise self._snapshot_invalid(buckets)
        for bucket, values in buckets.items():
            self._validate_bucket_key(bucket)
            if not isinstance(values, tuple) or len(values) != samples:
                raise self._snapshot_invalid(values)
            if any(not isinstance(value, int) or isinstance(value, bool)
                   for value in values):
                raise self._snapshot_invalid(values)

        registry = data["registry"]
        if not isinstance(registry, dict):
            raise self._snapshot_invalid(registry)
        for bucket, entry in registry.items():
            self._validate_bucket_key(bucket)
            if not isinstance(entry, dict) or set(entry) != _REGISTRY_KEYS:
                raise self._snapshot_invalid(entry)
            if any(not self._valid_nonnegative_int(entry[key])
                   for key in (
                       "builds", "lookups", "boundary_fallbacks",
                       "build_seq")):
                raise self._snapshot_invalid(entry)
            if entry["builds"] == 0 or entry["build_seq"] == 0:
                raise self._snapshot_invalid(entry)
            if (not isinstance(entry["density"], int)
                    or isinstance(entry["density"], bool)
                    or entry["density"] not in WEATHER_PRESETS.values()):
                raise self._snapshot_invalid(entry)

        for bucket in buckets:
            if bucket not in registry:
                raise self._snapshot_invalid(bucket)
        if sum(entry["builds"] for entry in registry.values()) != counters[
                "builds"]:
            raise self._snapshot_invalid(counters)
        if sum(entry["lookups"] for entry in registry.values()) != counters[
                "lookups"]:
            raise self._snapshot_invalid(counters)
        sequences = [entry["build_seq"] for entry in registry.values()]
        if (max(sequences, default=0) != counters["build_seq"]
                or len(set(sequences)) != len(sequences)):
            raise self._snapshot_invalid(counters)

        return data

    def restore(self, state: dict) -> None:
        with self._lock:
            data = self._validated_snapshot_state(state)
            settings = data["settings"]
            self._capacity = settings["capacity"]
            self._samples = settings["samples"]
            self._boundary_tolerance = float(settings["boundary_tolerance"])
            self._weather = data["weather"]
            self._sun = data["sun"]
            self._buckets = dict(data["buckets"])
            self._registry = copy.deepcopy(data["registry"])
            self._counters = dict(data["counters"])

    def stats(self) -> dict:
        with self._lock:
            return {
                "capacity": self._capacity,
                "samples": self._samples,
                "boundary_tolerance": self._boundary_tolerance,
                "weather": self._weather,
                "sun": self._sun,
                "cached": len(self._buckets),
                "builds": self._counters["builds"],
                "evictions": self._counters["evictions"],
                "lookups": self._counters["lookups"],
                "invalidations": self._counters["invalidations"],
                "weather_changes": self._counters["weather_changes"],
                "build_seq": self._counters["build_seq"],
            }
