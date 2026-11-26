"""Animation curve keyframe reducer."""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "CurveReducerError",
    "CurveInfo",
    "CurveKeyframeReducer",
    "DEFAULT_TOLERANCE",
    "SERIAL_VERSION",
]

DEFAULT_TOLERANCE = 0.01
SERIAL_VERSION = "CURVE1"


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


class CurveKeyframeReducer:
    """Thin a dense animation curve down to a sparse keyframe track."""

    def __init__(self, *, tolerance: float = DEFAULT_TOLERANCE) -> None:
        self.tolerance = tolerance
        self._lock = threading.RLock()

    def load(self, curve_id: str, samples, *, events=None,
             sample_rate: int = 60) -> CurveInfo:
        raise NotImplementedError

    def set_tolerance(self, tolerance: float) -> float:
        raise NotImplementedError

    def compress(self) -> list[int]:
        raise NotImplementedError

    def reconstruct(self) -> tuple[float, ...]:
        raise NotImplementedError

    def forced_keys(self) -> tuple[int, ...]:
        raise NotImplementedError

    def error_stats(self) -> dict:
        raise NotImplementedError

    def serialize_curve(self) -> str:
        raise NotImplementedError

    def deserialize(self, blob: str) -> CurveInfo:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
