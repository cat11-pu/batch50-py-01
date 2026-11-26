"""Media asset orientation normalization driven by rotation and pixel aspect.

Each asset carries a rotation, optional horizontal or vertical flip and a
pixel aspect ratio.  Normalizing folds those into a transcode filter chain,
rewrites the stored metadata into a single upright orientation and keeps the
previous metadata so the operation can be rolled back.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "MediaError",
    "AssetState",
    "NormalizePlan",
    "MediaRotationNormalizer",
]


class MediaError(ValueError):
    """Raised when an orientation normalization step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AssetState:
    """Stored orientation metadata of one media asset."""

    asset_id: str
    width: int
    height: int
    rotation: int
    flip_h: bool
    flip_v: bool
    sar: tuple[int, int]
    revision: int
    normalized: bool


@dataclass(frozen=True)
class NormalizePlan:
    """Planned transcode for one asset."""

    plan_id: str
    asset_id: str
    status: str
    rotation: int
    filters: tuple[str, ...]
    output_width: int
    output_height: int


class MediaRotationNormalizer:
    """Turn stored rotation metadata into an upright, square-pixel asset."""

    def __init__(self, *, profile: str = "mp4-h264",
                 allow_downscale: bool = False) -> None:
        self.profile = profile
        self.allow_downscale = allow_downscale
        self._lock = threading.RLock()

    def register(self, asset_id: str, *, width: int, height: int,
                 rotation: int = 0, flip_h: bool = False,
                 flip_v: bool = False, sar: str = "1:1") -> AssetState:
        """Register an asset with its display matrix and aspect metadata."""
        raise NotImplementedError

    def inspect(self, asset_id: str) -> dict:
        """Return the stored and normalized geometry of *asset_id*."""
        raise NotImplementedError

    def plan_filters(self, asset_id: str) -> tuple[str, ...]:
        """Return the ordered filter chain needed for *asset_id*."""
        raise NotImplementedError

    def normalize(self, asset_id: str) -> NormalizePlan:
        """Create (or reuse) the normalization plan for *asset_id*."""
        raise NotImplementedError

    def apply(self, plan_id: str) -> NormalizePlan:
        """Apply a pending plan and mark the asset as normalized."""
        raise NotImplementedError

    def rollback(self, asset_id: str) -> AssetState:
        """Restore the metadata captured before normalization."""
        raise NotImplementedError

    def metadata_of(self, asset_id: str) -> dict:
        """Return before/after metadata of *asset_id* as a detached copy."""
        raise NotImplementedError

    def is_normalized(self, asset_id: str) -> bool:
        """Tell whether *asset_id* already carries upright metadata."""
        raise NotImplementedError

    def pending_plans(self) -> tuple[str, ...]:
        """Return the ids of the plans that were not applied yet."""
        raise NotImplementedError

    def discard_plan(self, plan_id: str) -> bool:
        """Drop a pending plan without touching the asset metadata."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of the normalizer state."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the normalizer state with a previously taken snapshot."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the registration, planning and apply counters."""
        raise NotImplementedError
