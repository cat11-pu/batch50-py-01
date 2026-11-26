"""Static shadow map cache with per-frame slot reuse."""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "ShadowCacheError",
    "ObjectRecord",
    "SlotRender",
    "SlotInfo",
    "StaticShadowCache",
    "INVALIDATION_REASONS",
]

INVALIDATION_REASONS = ("transform", "material", "lod")


class ShadowCacheError(ValueError):
    """Raised when a shadow-cache request is rejected."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ObjectRecord:
    object_id: str
    transform: tuple[float, float, float]
    material: str
    lod: int


@dataclass(frozen=True)
class SlotRender:
    object_id: str
    slot: int
    frame: int
    generation: int
    payload: dict
    rendered: bool


@dataclass(frozen=True)
class SlotInfo:
    object_id: str
    slot: int | None
    dirty: bool
    generation: int
    last_frame: int
    uses: int
    rendered: bool


class StaticShadowCache:
    """Reuse the shadow maps of static objects across frames."""

    def __init__(self, *, capacity: int = 4) -> None:
        self.capacity = capacity
        self._lock = threading.RLock()

    def register(self, object_id: str, *, transform=(0.0, 0.0, 0.0),
                 material: str = "default", lod: int = 0) -> ObjectRecord:
        raise NotImplementedError

    def tick(self) -> int:
        raise NotImplementedError

    def acquire_slot(self, object_id: str) -> int:
        raise NotImplementedError

    def release_slot(self, object_id: str) -> bool:
        raise NotImplementedError

    def refresh(self, object_id: str) -> SlotRender:
        raise NotImplementedError

    def invalidate(self, object_id: str, reason: str = "transform") -> bool:
        raise NotImplementedError

    def lookup(self, object_id: str) -> SlotInfo:
        raise NotImplementedError

    def resize(self, capacity: int) -> int:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
