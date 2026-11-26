"""Vegetation wind sway driver with distance-based update budgets."""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "WindDriverError",
    "FieldRecord",
    "InstanceRecord",
    "Pose",
    "VegetationWindDriver",
    "DEFAULT_FREQUENCY",
]

DEFAULT_FREQUENCY = 0.35


class WindDriverError(ValueError):
    """Raised when a wind-driver request is rejected."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FieldRecord:
    field_id: str
    wavelength: float
    phase: float


@dataclass(frozen=True)
class InstanceRecord:
    instance_id: str
    position: tuple[float, float]
    stiffness: float
    field: str
    tier: str
    phase: float


@dataclass(frozen=True)
class Pose:
    instance_id: str
    time: float
    phase: float
    amplitude: float
    sway: float
    tier: str
    interpolated: bool


class VegetationWindDriver:
    """Drive the sway state of many vegetation instances per frame."""

    def __init__(self, *, frequency: float = DEFAULT_FREQUENCY) -> None:
        self.frequency = frequency
        self._lock = threading.RLock()

    def register_field(self, field_id: str, *, wavelength: float,
                       phase: float = 0.0) -> FieldRecord:
        raise NotImplementedError

    def register_instance(self, instance_id: str, *, position,
                          stiffness: float = 1.0,
                          field: str) -> InstanceRecord:
        raise NotImplementedError

    def set_wind(self, strength: float, direction: float, *,
                 transition: float = 0.0) -> dict:
        raise NotImplementedError

    def set_lod_budget(self, per_update: int, *, near_radius: float = 30.0,
                       far_stride: int = 3) -> dict:
        raise NotImplementedError

    def update(self, time: float) -> dict:
        raise NotImplementedError

    def sample_instance(self, instance_id: str, time: float) -> Pose:
        raise NotImplementedError

    def batch_of(self, time: float) -> list[Pose]:
        raise NotImplementedError

    def phase_of(self, instance_id: str) -> float:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
