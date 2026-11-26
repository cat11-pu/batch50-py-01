"""Particle trail builder: sample history ring, ribbon geometry, budgeted rebuild."""

from __future__ import annotations

import threading

__all__ = [
    "ParticleError",
    "ParticleTrailBuilder",
    "DEFAULT_COLOR",
]

DEFAULT_COLOR = (1.0, 1.0, 1.0, 1.0)


class ParticleError(ValueError):
    """Raised when a trail request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class ParticleTrailBuilder:
    """Keep per-emitter sample rings and turn them into camera-facing ribbons."""

    def __init__(self, *, teleport_distance: float = 1000.0,
                 vertex_budget: int = 4096, max_emitters: int = 16) -> None:
        self.teleport_distance = teleport_distance
        self.vertex_budget = vertex_budget
        self.max_emitters = max_emitters
        self._lock = threading.RLock()

    def register_emitter(self, emitter_id: str, *, capacity: int = 64,
                         max_age: float = 2.0, min_distance: float = 0.1,
                         priority: int = 0) -> None:
        raise NotImplementedError

    def remove_emitter(self, emitter_id: str) -> None:
        raise NotImplementedError

    def push_sample(self, emitter_id: str, *, position, time,
                    width: float = 1.0, color=DEFAULT_COLOR) -> None:
        raise NotImplementedError

    def build_ribbon(self, emitter_id: str, *, budget: int | None = None) -> dict:
        raise NotImplementedError

    def break_trail(self, emitter_id: str, *, reason: str = "manual") -> int:
        raise NotImplementedError

    def set_budget(self, vertex_budget: int) -> None:
        raise NotImplementedError

    def segments(self, emitter_id: str) -> tuple[dict, ...]:
        raise NotImplementedError

    def emitter_state(self, emitter_id: str) -> dict:
        raise NotImplementedError

    def emitters(self) -> tuple[str, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
