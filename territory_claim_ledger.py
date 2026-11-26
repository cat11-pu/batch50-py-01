"""Territory claim ledger for guild stronghold contests.

Accumulates contest progress per stronghold, arbitrates ownership transfers
and runs the transfer cooldown.  Every :meth:`TerritoryClaimLedger.tick` adds
the member count of each contending guild to its progress, capped at the claim
threshold; a guild sitting at the cap is eligible to settle, and a successful
settle changes the owner and starts the cooldown window.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "TerritoryError",
    "SiteState",
    "ClaimEvent",
    "TerritoryClaimLedger",
]


class TerritoryError(ValueError):
    """Raised when a territory claim operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SiteState:
    """Immutable view of one stronghold ledger entry."""

    site_id: str
    owner: str | None
    claim_threshold: int
    cooldown_ticks: int
    cooldown_left: int
    contenders: tuple[str, ...]
    progress: tuple[tuple[str, int], ...]
    members: tuple[tuple[str, int], ...]
    suspended: bool
    window_seq: int


@dataclass(frozen=True)
class ClaimEvent:
    """Result of one settled ownership transfer."""

    site_id: str
    guild: str
    previous_owner: str | None
    transferred: bool
    window_seq: int


class TerritoryClaimLedger:
    """Accumulate contest progress per site and arbitrate ownership changes."""

    def __init__(self, *, claim_threshold: int = 100, cooldown_ticks: int = 5,
                 max_contenders_per_site: int = 8) -> None:
        self.claim_threshold = claim_threshold
        self.cooldown_ticks = cooldown_ticks
        self.max_contenders_per_site = max_contenders_per_site
        self._lock = threading.RLock()

    def add_site(self, site_id: str, *, owner: str | None = None) -> SiteState:
        """Register a stronghold, optionally already held by *owner*."""
        raise NotImplementedError

    def join_contest(self, site_id: str, guild: str, *, members: int,
                     now: int | None = None) -> SiteState:
        """Enter *guild* into the contest with *members* fighters per round."""
        raise NotImplementedError

    def leave_contest(self, site_id: str, guild: str,
                      now: int | None = None) -> SiteState:
        """Drop *guild* from the contest, forfeiting its accumulated progress."""
        raise NotImplementedError

    def tick(self, site_id: str, *, now: int | None = None) -> dict:
        """Run one contest round: add member progress and age the cooldown."""
        raise NotImplementedError

    def settle(self, site_id: str, guild: str,
               now: int | None = None) -> ClaimEvent:
        """Finalize the ownership transfer for a guild sitting at the cap."""
        raise NotImplementedError

    def owner_of(self, site_id: str) -> str | None:
        """Return the owner guild, or ``None`` while the site is neutral."""
        raise NotImplementedError

    def progress_of(self, site_id: str, guild: str) -> int:
        """Return the control points *guild* accumulated at *site_id*."""
        raise NotImplementedError

    def cooldown_left(self, site_id: str) -> int:
        """Return how many contest rounds the transfer cooldown still blocks."""
        raise NotImplementedError

    def contenders(self, site_id: str) -> tuple[str, ...]:
        """Return contending guilds in registration order."""
        raise NotImplementedError

    def state_of(self, site_id: str) -> SiteState:
        """Return an immutable view of the site ledger entry."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a deep copy of sites and counters suitable for ``restore``."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace ledger state with a snapshot, validating its structure."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative counters for joins, ticks, claims and refusals."""
        raise NotImplementedError
