"""Animation curve keyframe reducer."""

from __future__ import annotations

import copy
import math
import re
import threading
from dataclasses import dataclass
from urllib.parse import quote, unquote_to_bytes

__all__ = [
    "CurveReducerError",
    "CurveInfo",
    "CurveKeyframeReducer",
    "DEFAULT_TOLERANCE",
    "SERIAL_VERSION",
    "SNAPSHOT_VERSION",
]

DEFAULT_TOLERANCE = 0.01
SERIAL_VERSION = "CURVE1"
SNAPSHOT_VERSION = 1

_SERIAL_FIELDS = (
    "curve_id",
    "sample_rate",
    "tolerance",
    "events",
    "keys",
    "samples",
)
_SNAPSHOT_FIELDS = (
    "version",
    "curve_id",
    "sample_rate",
    "tolerance",
    "samples",
    "events",
    "keys",
    "counters",
)
_INTEGER_TOKEN = re.compile(r"[+-]?\d+\Z")
_PERCENT_ESCAPE = re.compile(r"%(?![0-9A-Fa-f]{2})")


class CurveReducerError(ValueError):
    """Raised when a curve reduction request is rejected."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CurveInfo:
    curve_id: str
    sample_rate: int
    sample_count: int
    events: tuple[int, ...]


def _strict_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _valid_tolerance(value: object) -> bool:
    return _number(value) and math.isfinite(value) and value > 0


def _coerce_samples(samples: object) -> list[float]:
    try:
        raw_samples = list(samples)  # type: ignore[arg-type]
    except TypeError as exc:
        raise CurveReducerError(
            "CURVE_INVALID_INPUT", "samples must contain at least four numbers"
        ) from exc

    if len(raw_samples) < 4:
        raise CurveReducerError(
            "CURVE_INVALID_INPUT", "samples must contain at least four numbers"
        )

    values: list[float] = []
    for index, value in enumerate(raw_samples):
        if not _number(value):
            raise CurveReducerError(
                "CURVE_INVALID_INPUT", f"sample {index} is not numeric"
            )
        try:
            values.append(float(value))  # type: ignore[arg-type]
        except (OverflowError, TypeError, ValueError) as exc:
            raise CurveReducerError(
                "CURVE_INVALID_INPUT", f"sample {index} is not a float"
            ) from exc
    return values


def _coerce_events(events: object, sample_count: int) -> tuple[int, ...]:
    if events is None:
        return ()
    if isinstance(events, (str, bytes, bytearray)):
        raise CurveReducerError("CURVE_INVALID_INPUT", "events must be indices")

    try:
        raw_events = list(events)  # type: ignore[arg-type]
    except TypeError as exc:
        raise CurveReducerError(
            "CURVE_INVALID_INPUT", "events must be an iterable of indices"
        ) from exc

    unique_events: set[int] = set()
    for event in raw_events:
        if not _strict_int(event) or not 0 <= event < sample_count:
            raise CurveReducerError(
                "CURVE_INVALID_INPUT", f"event index {event!r} is out of range"
            )
        unique_events.add(event)
    return tuple(sorted(unique_events))


def _int_token(token: str) -> int:
    if not _INTEGER_TOKEN.fullmatch(token):
        raise ValueError(f"invalid integer: {token!r}")
    return int(token)


def _parse_index_field(
    raw: object, sample_count: int, *, field_name: str, allow_empty: bool
) -> tuple[int, ...]:
    if isinstance(raw, str):
        tokens = [] if raw == "" else raw.split(",")
        values: list[int] = []
        try:
            values = [_int_token(token.strip()) for token in tokens]
        except ValueError as exc:
            raise CurveReducerError(
                "CURVE_SERIALIZE_INVALID", f"invalid {field_name}"
            ) from exc
    elif isinstance(raw, (list, tuple)):
        values = []
        for value in raw:
            if not _strict_int(value):
                raise CurveReducerError(
                    "CURVE_SNAPSHOT_INVALID", f"invalid {field_name}"
                )
            values.append(value)
    else:
        raise CurveReducerError(
            "CURVE_SNAPSHOT_INVALID", f"invalid {field_name}"
        )

    if not allow_empty and not values:
        raise CurveReducerError(
            "CURVE_SNAPSHOT_INVALID", f"{field_name} must not be empty"
        )
    if any(not 0 <= value < sample_count for value in values):
        raise CurveReducerError(
            "CURVE_SNAPSHOT_INVALID", f"{field_name} index is out of range"
        )
    if values != sorted(values) or len(set(values)) != len(values):
        raise CurveReducerError(
            "CURVE_SNAPSHOT_INVALID", f"{field_name} must be sorted and unique"
        )
    return tuple(values)


class CurveKeyframeReducer:
    """Thin a dense animation curve down to a sparse keyframe track."""

    def __init__(self, *, tolerance: float = DEFAULT_TOLERANCE) -> None:
        self._lock = threading.RLock()
        self._compressions = 0
        self._reset_curve_state_locked()
        self.tolerance = tolerance

    def _reset_curve_state_locked(self) -> None:
        self._loaded = False
        self._curve_id = ""
        self._sample_rate = 60
        self._tolerance = DEFAULT_TOLERANCE
        self._samples: list[float] = []
        self._events: tuple[int, ...] = ()
        self._keys: tuple[int, ...] | None = None

    @property
    def tolerance(self) -> float:
        return self._tolerance

    @tolerance.setter
    def tolerance(self, value: float) -> None:
        if not _valid_tolerance(value):
            raise CurveReducerError(
                "CURVE_INVALID_TOLERANCE",
                "tolerance must be a finite positive number",
            )
        with self._lock:
            self._tolerance = float(value)
            self._keys = None

    def load(self, curve_id: str, samples, *, events=None,
             sample_rate: int = 60) -> CurveInfo:
        if not isinstance(curve_id, str) or not curve_id.strip():
            raise CurveReducerError(
                "CURVE_INVALID_INPUT", "curve_id must be non-empty after stripping"
            )
        if not _strict_int(sample_rate) or sample_rate <= 0:
            raise CurveReducerError(
                "CURVE_INVALID_INPUT", "sample_rate must be a positive integer"
            )

        new_samples = _coerce_samples(samples)
        new_events = _coerce_events(events, len(new_samples))

        with self._lock:
            self._loaded = True
            self._curve_id = curve_id
            self._samples = new_samples
            self._sample_rate = sample_rate
            self._events = new_events
            self._keys = None

        return CurveInfo(
            curve_id=curve_id,
            sample_rate=sample_rate,
            sample_count=len(new_samples),
            events=new_events,
        )

    def set_tolerance(self, tolerance: float) -> float:
        with self._lock:
            self.tolerance = tolerance
            return self._tolerance

    def compress(self) -> list[int]:
        with self._lock:
            self._require_loaded_locked()
            sample_count = len(self._samples)
            tolerance = self._tolerance

            anchors = set(self._forced_keys_locked())
            for index, value in enumerate(self._samples):
                if not math.isfinite(value):
                    anchors.add(index)
                    if index > 0:
                        anchors.add(index - 1)
                    if index + 1 < sample_count:
                        anchors.add(index + 1)

            ordered_anchors = sorted(anchors)
            selected = set(ordered_anchors)
            stack = [
                (ordered_anchors[index], ordered_anchors[index + 1])
                for index in range(len(ordered_anchors) - 1)
            ]

            while stack:
                left, right = stack.pop()
                if right - left <= 1:
                    continue
                worst_error, worst_index = self._max_deviation(
                    self._samples, left, right
                )
                if worst_error > tolerance:
                    selected.add(worst_index)
                    stack.append((left, worst_index))
                    stack.append((worst_index, right))

            keys = sorted(selected)

            for _ in range(sample_count):
                rebuilt = self._reconstruct_values(self._samples, keys)
                violating: list[int] = []
                for index, original in enumerate(self._samples):
                    if not math.isfinite(original):
                        continue
                    predicted = rebuilt[index]
                    if not math.isfinite(predicted):
                        violating.append(index)
                        continue
                    error = abs(original - predicted)
                    if not math.isfinite(error) or error > tolerance:
                        violating.append(index)

                if not violating:
                    break
                keys = sorted(set(keys).union(violating))
            else:
                keys = list(range(sample_count))

            self._keys = tuple(keys)
            self._compressions += 1
            return list(keys)

    def reconstruct(self) -> tuple[float, ...]:
        with self._lock:
            self._require_compressed_locked()
            return self._reconstruct_values(self._samples, self._keys)

    def forced_keys(self) -> tuple[int, ...]:
        with self._lock:
            self._require_loaded_locked()
            return self._forced_keys_locked()

    def error_stats(self) -> dict:
        with self._lock:
            self._require_compressed_locked()
            rebuilt = self._reconstruct_values(self._samples, self._keys)
            tolerance = self._tolerance

            evaluated = 0
            running_mean = 0.0
            max_error = 0.0
            violations = 0
            has_infinite_error = False

            for original, predicted in zip(self._samples, rebuilt):
                if math.isnan(original):
                    continue

                if original == predicted:
                    error = 0.0
                else:
                    error = abs(original - predicted)
                if math.isnan(error):
                    error = math.inf

                evaluated += 1
                if math.isinf(error):
                    has_infinite_error = True
                    max_error = math.inf
                    violations += 1
                    continue

                if not has_infinite_error:
                    running_mean += (error - running_mean) / evaluated
                max_error = max(max_error, error)
                if error > tolerance:
                    violations += 1

            mean_error = math.inf if has_infinite_error else (
                running_mean if evaluated else 0.0
            )
            return {
                "samples": len(self._samples),
                "keys": len(self._keys),
                "tolerance": tolerance,
                "max_error": max_error,
                "mean_error": mean_error,
                "violations": violations,
            }

    def serialize_curve(self) -> str:
        with self._lock:
            self._require_compressed_locked()
            fields = [
                f"curve_id={quote(self._curve_id, safe='')}",
                f"sample_rate={self._sample_rate}",
                f"tolerance={self._tolerance!r}",
                "events=" + ",".join(str(index) for index in self._events),
                "keys=" + ",".join(str(index) for index in self._keys),
                "samples=" + ",".join(repr(value) for value in self._samples),
            ]
            return SERIAL_VERSION + "|" + "|".join(fields)

    def deserialize(self, blob: str) -> CurveInfo:
        candidate = self._parse_serialized_curve(blob)

        with self._lock:
            self._loaded = True
            self._curve_id = candidate["curve_id"]
            self._sample_rate = candidate["sample_rate"]
            self._tolerance = candidate["tolerance"]
            self._samples = candidate["samples"]
            self._events = candidate["events"]
            self._keys = candidate["keys"]

        return CurveInfo(
            curve_id=candidate["curve_id"],
            sample_rate=candidate["sample_rate"],
            sample_count=len(candidate["samples"]),
            events=candidate["events"],
        )

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": SNAPSHOT_VERSION,
                "curve_id": self._curve_id,
                "sample_rate": self._sample_rate,
                "tolerance": self._tolerance,
                "samples": list(self._samples),
                "events": list(self._events),
                "keys": list(self._keys) if self._keys is not None else [],
                "counters": {"compressions": self._compressions},
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        candidate = self._parse_snapshot(state)
        with self._lock:
            self._loaded = candidate["loaded"]
            self._curve_id = candidate["curve_id"]
            self._sample_rate = candidate["sample_rate"]
            self._tolerance = candidate["tolerance"]
            self._samples = candidate["samples"]
            self._events = candidate["events"]
            self._keys = candidate["keys"]
            self._compressions = candidate["compressions"]

    def stats(self) -> dict:
        with self._lock:
            key_count = 0 if self._keys is None else len(self._keys)
            return {
                "loaded": self._loaded,
                "curve_id": self._curve_id,
                "sample_rate": self._sample_rate,
                "samples": len(self._samples),
                "sample_count": len(self._samples),
                "tolerance": self._tolerance,
                "events": self._events,
                "keys": key_count,
                "compressed": self._keys is not None,
                "compressions": self._compressions,
            }

    def _require_loaded_locked(self) -> None:
        if not self._loaded:
            raise CurveReducerError("CURVE_NOT_LOADED", "no curve is loaded")

    def _require_compressed_locked(self) -> None:
        self._require_loaded_locked()
        if self._keys is None:
            raise CurveReducerError(
                "CURVE_NOT_COMPRESSED", "compress the curve before using its keys"
            )

    def _forced_keys_locked(self) -> tuple[int, ...]:
        sample_count = len(self._samples)
        forced = {0, sample_count - 1}

        max_index: int | None = None
        min_index: int | None = None
        max_value = -math.inf
        min_value = math.inf

        for index, value in enumerate(self._samples):
            if math.isnan(value):
                continue
            if max_index is None or value > max_value:
                max_index = index
                max_value = value
            if min_index is None or value < min_value:
                min_index = index
                min_value = value

        if max_index is not None:
            forced.add(max_index)
        if min_index is not None:
            forced.add(min_index)

        for event in self._events:
            forced.add(event)
            if event > 0:
                forced.add(event - 1)
            if event + 1 < sample_count:
                forced.add(event + 1)

        for index, value in enumerate(self._samples):
            if math.isnan(value):
                forced.add(index)

        return tuple(sorted(forced))

    @staticmethod
    def _interpolated_value(
        samples: list[float], left: int, right: int, index: int
    ) -> float:
        if index == left:
            return samples[left]
        if index == right:
            return samples[right]
        ratio = (index - left) / (right - left)
        return samples[left] + (samples[right] - samples[left]) * ratio

    @classmethod
    def _max_deviation(
        cls, samples: list[float], left: int, right: int
    ) -> tuple[float, int]:
        if not math.isfinite(samples[left]) or not math.isfinite(samples[right]):
            return math.inf, (left + right) // 2

        worst_error = -1.0
        worst_index = left + 1
        for index in range(left + 1, right):
            original = samples[index]
            if not math.isfinite(original):
                return math.inf, index
            predicted = cls._interpolated_value(samples, left, right, index)
            error = abs(original - predicted)
            if not math.isfinite(error) or error > worst_error:
                if not math.isfinite(error):
                    return math.inf, index
                worst_error = error
                worst_index = index
        return worst_error, worst_index

    @classmethod
    def _reconstruct_values(
        cls, samples: list[float], keys: tuple[int, ...] | list[int] | None
    ) -> tuple[float, ...]:
        if not keys:
            raise CurveReducerError("CURVE_NOT_COMPRESSED", "no keyframes available")

        reconstructed = [math.nan] * len(samples)
        for position in range(len(keys) - 1):
            left = keys[position]
            right = keys[position + 1]
            for index in range(left, right + 1):
                reconstructed[index] = cls._interpolated_value(
                    samples, left, right, index
                )

        if keys[0] != 0:
            for index in range(0, keys[0]):
                reconstructed[index] = samples[index]
        if keys[-1] != len(samples) - 1:
            for index in range(keys[-1] + 1, len(samples)):
                reconstructed[index] = samples[index]

        return tuple(reconstructed)

    @staticmethod
    def _parse_serialized_curve(blob: object) -> dict:
        invalid = CurveReducerError(
            "CURVE_SERIALIZE_INVALID", "invalid CURVE1 payload"
        )
        if not isinstance(blob, str) or not blob.startswith(SERIAL_VERSION + "|"):
            raise invalid

        fields: dict[str, str] = {}
        for segment in blob[len(SERIAL_VERSION) + 1:].split("|"):
            key, separator, value = segment.partition("=")
            if not separator or not key:
                raise invalid
            if key in fields:
                raise CurveReducerError(
                    "CURVE_SERIALIZE_INVALID", f"duplicate field {key!r}"
                )
            fields[key] = value

        if set(fields) != set(_SERIAL_FIELDS):
            raise invalid

        curve_token = fields["curve_id"]
        if _PERCENT_ESCAPE.search(curve_token):
            raise invalid
        try:
            curve_id = unquote_to_bytes(curve_token).decode("utf-8")
        except UnicodeDecodeError:
            raise invalid
        if not curve_id.strip():
            raise invalid

        try:
            sample_rate = _int_token(fields["sample_rate"])
        except ValueError:
            raise invalid
        if not _strict_int(sample_rate) or sample_rate <= 0:
            raise invalid

        try:
            tolerance = float(fields["tolerance"])
        except ValueError:
            raise invalid
        if not _valid_tolerance(tolerance):
            raise invalid

        sample_text = fields["samples"]
        if sample_text == "":
            raise invalid
        samples: list[float] = []
        for token in sample_text.split(","):
            try:
                samples.append(float(token))
            except ValueError:
                raise invalid
        if len(samples) < 4:
            raise invalid

        try:
            events = _parse_index_field(
                fields["events"],
                len(samples),
                field_name="events",
                allow_empty=True,
            )
            keys = _parse_index_field(
                fields["keys"],
                len(samples),
                field_name="keys",
                allow_empty=False,
            )
        except CurveReducerError as exc:
            if exc.code == "CURVE_SNAPSHOT_INVALID":
                raise invalid from exc
            raise
        if keys[0] != 0 or keys[-1] != len(samples) - 1:
            raise invalid

        return {
            "curve_id": curve_id,
            "sample_rate": sample_rate,
            "tolerance": float(tolerance),
            "samples": samples,
            "events": events,
            "keys": keys,
        }

    @staticmethod
    def _parse_snapshot(state: object) -> dict:
        invalid = CurveReducerError(
            "CURVE_SNAPSHOT_INVALID", "invalid reducer snapshot"
        )
        if not isinstance(state, dict):
            raise invalid
        if set(state.keys()) != set(_SNAPSHOT_FIELDS):
            raise invalid

        version = state["version"]
        if not _strict_int(version) or version != SNAPSHOT_VERSION:
            raise invalid

        curve_id = state["curve_id"]
        if not isinstance(curve_id, str):
            raise invalid

        sample_rate = state["sample_rate"]
        if not _strict_int(sample_rate) or sample_rate <= 0:
            raise invalid

        tolerance = state["tolerance"]
        if not _valid_tolerance(tolerance):
            raise invalid

        raw_samples = state["samples"]
        if not isinstance(raw_samples, list):
            raise invalid
        if len(raw_samples) != 0 and len(raw_samples) < 4:
            raise invalid

        samples: list[float] = []
        for value in raw_samples:
            if not _number(value):
                raise invalid
            try:
                samples.append(float(value))
            except (OverflowError, TypeError, ValueError):
                raise invalid

        sample_count = len(samples)
        if sample_count == 0:
            if curve_id != "":
                raise invalid
        elif not curve_id.strip():
            raise invalid

        try:
            events = _parse_index_field(
                state["events"],
                sample_count,
                field_name="events",
                allow_empty=True,
            )
            keys = _parse_index_field(
                state["keys"],
                sample_count,
                field_name="keys",
                allow_empty=True,
            )
        except CurveReducerError as exc:
            if exc.code == "CURVE_SERIALIZE_INVALID":
                raise invalid from exc
            raise
        if keys and (keys[0] != 0 or keys[-1] != sample_count - 1):
            raise invalid

        counters = state["counters"]
        if not isinstance(counters, dict) or set(counters.keys()) != {
            "compressions"
        }:
            raise invalid
        compressions = counters["compressions"]
        if not _strict_int(compressions) or compressions < 0:
            raise invalid

        return {
            "loaded": sample_count > 0,
            "curve_id": curve_id,
            "sample_rate": sample_rate,
            "tolerance": float(tolerance),
            "samples": samples,
            "events": events,
            "keys": keys if keys else None,
            "compressions": compressions,
        }
