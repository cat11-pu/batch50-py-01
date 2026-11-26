"""Audio fingerprint index with approximate duplicate detection and review.

Clips are stored as deduplicated fingerprint sets.  A query counts shared
fingerprints per clip, compares the count against a hit threshold and either
declares the clip a duplicate, sends it to the review queue or reports it as a
plain partial match.  The index has a hard capacity and evicts the entry that
went unmatched for the longest time.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "FingerprintError",
    "FingerprintEntry",
    "MatchResult",
    "ReviewRecord",
    "AudioFingerprintIndex",
]


class FingerprintError(ValueError):
    """Raised when a fingerprint index operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class FingerprintEntry:
    """One indexed clip."""

    clip_id: str
    hashes: tuple[int, ...]
    indexed_seq: int
    last_hit_seq: int
    meta: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class MatchResult:
    """One query hit against an indexed clip."""

    clip_id: str
    hits: int
    similarity: float
    verdict: str


@dataclass(frozen=True)
class ReviewRecord:
    """One clip waiting for a human duplicate decision."""

    review_id: str
    clip_id: str
    hits: int
    similarity: float
    fingerprint_digest: str
    status: str


class AudioFingerprintIndex:
    """Index clip fingerprints and answer approximate duplicate queries."""

    def __init__(self, *, capacity: int = 64, hit_threshold: int = 4) -> None:
        self._max_entries = capacity
        self.hit_threshold = hit_threshold
        self._lock = threading.RLock()

    def index(self, clip_id: str, *, hashes, meta=None) -> FingerprintEntry:
        """Store (or replace) the fingerprints of *clip_id*."""
        raise NotImplementedError

    def query(self, hashes) -> tuple[MatchResult, ...]:
        """Compare *hashes* against every indexed clip."""
        raise NotImplementedError

    def remove(self, clip_id: str) -> bool:
        """Drop *clip_id* from the index; return whether it existed."""
        raise NotImplementedError

    def capacity(self) -> int:
        """Return the current entry capacity."""
        raise NotImplementedError

    def set_capacity(self, capacity: int) -> int:
        """Resize the index, evicting least recently hit entries on shrink."""
        raise NotImplementedError

    def evict(self) -> str | None:
        """Evict the least recently hit entry when the index is full."""
        raise NotImplementedError

    def review_queue(self) -> tuple[ReviewRecord, ...]:
        """Return the still open review records in arrival order."""
        raise NotImplementedError

    def resolve_review(self, review_id: str, *, decision: str) -> ReviewRecord:
        """Close one review record as duplicate or distinct."""
        raise NotImplementedError

    def entry_of(self, clip_id: str) -> FingerprintEntry | None:
        """Return the stored entry of *clip_id*, if any."""
        raise NotImplementedError

    def entries(self) -> tuple[FingerprintEntry, ...]:
        """Return every entry ordered by clip id."""
        raise NotImplementedError

    def size(self) -> int:
        """Return how many clips are indexed."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached snapshot of the index state."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace the index state with a previously taken snapshot."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the index, query and eviction counters."""
        raise NotImplementedError
