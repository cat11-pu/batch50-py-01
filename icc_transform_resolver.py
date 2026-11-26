"""ICC profile registry and colour transform cache.

Profiles are registered per device with a version, device class, white point and
gamut label.  Transforms are compiled per (source version, target version,
rendering intent, black point compensation), cached under a stable key and
handed out as handles that can be retained by in-flight render frames.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "IccError",
    "ProfileView",
    "TransformHandle",
    "CacheStats",
    "IccTransformResolver",
]

INTENTS = ("perceptual", "relative", "saturation", "absolute")
DEVICE_CLASSES = ("input", "display", "output", "colorspace")
SUPPORTED_GAMUTS = ("srgb", "display-p3", "rec2020", "adobe-rgb", "prophoto")


class IccError(ValueError):
    """Raised when a profile or transform operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ProfileView:
    """Immutable snapshot of one registered profile."""

    profile_id: str
    device_class: str
    version: int
    white_point: tuple[float, float]
    gamut: str
    media_white: tuple[float, float] | None
    valid: bool
    diagnostics: tuple[str, ...]


@dataclass(frozen=True)
class TransformHandle:
    """One compiled colour transform handed to a caller."""

    cache_key: str
    source_id: str
    source_version: int
    target_id: str
    target_version: int
    intent: str
    bpc: bool
    fallback: bool
    diagnostic: str | None
    refs: int


@dataclass(frozen=True)
class CacheStats:
    """Counters for the transform cache."""

    entries: int
    limit: int
    hits: int
    misses: int
    compiles: int
    evictions: int
    invalidations: int
    refusals: int


class IccTransformResolver:
    """Register device profiles and resolve cached colour transforms."""

    def __init__(self, *, max_cache_entries: int = 64,
                 black_point_compensation: bool = True,
                 fallback_profile: str = "srgb") -> None:
        self.max_cache_entries = max_cache_entries
        self.black_point_compensation = black_point_compensation
        self.fallback_profile = fallback_profile
        self._lock = threading.RLock()

    def register_profile(self, profile_id: str, *, device_class: str,
                         white_point: tuple[float, float], gamut: str,
                         version: int = 1,
                         media_white: tuple[float, float] | None = None) -> ProfileView:
        """Register or replace a profile under its device identity."""
        raise NotImplementedError

    def profile_view(self, profile_id: str) -> ProfileView:
        """Return the current registration of a profile."""
        raise NotImplementedError

    def validate_profile(self, profile_id: str) -> dict:
        """Check a profile and report diagnostics plus the fallback target."""
        raise NotImplementedError

    def link_cache_key(self, source_id: str, target_id: str, *,
                       intent: str = "perceptual", bpc: bool | None = None) -> str:
        """Return the stable cache key for a transform request."""
        raise NotImplementedError

    def resolve_transform(self, source_id: str, target_id: str, *,
                          intent: str = "perceptual",
                          bpc: bool | None = None) -> TransformHandle:
        """Compile or reuse the transform for a profile pair and intent."""
        raise NotImplementedError

    def retain_handle(self, handle: TransformHandle) -> TransformHandle:
        """Mark a transform as referenced by an in-flight render frame."""
        raise NotImplementedError

    def release_handle(self, handle: TransformHandle) -> TransformHandle:
        """Drop one in-flight reference from a transform handle."""
        raise NotImplementedError

    def invalidate_device(self, device_id: str) -> tuple[str, ...]:
        """Drop every cached transform that involves one device."""
        raise NotImplementedError

    def cache_stats(self) -> CacheStats:
        """Return cache entry counts and hit/miss/eviction counters."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a deep copy of profiles, cache and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace resolver state with a snapshot, validating its structure."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative counters for registrations, resolves and fallbacks."""
        raise NotImplementedError
