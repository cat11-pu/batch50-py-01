"""Territory claim ledger for guild stronghold contests.

Accumulates contest progress per stronghold, arbitrates ownership transfers
and runs the transfer cooldown.  Every :meth:`TerritoryClaimLedger.tick` adds
the member count of each contending guild to its progress, capped at the claim
threshold; a guild sitting at the cap is eligible to settle, and a successful
settle changes the owner and starts the cooldown window.
"""

from __future__ import annotations

import threading
from collections.abc import Mapping
from dataclasses import dataclass, field

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


@dataclass
class _Contender:
    """Mutable per-guild contest entry."""

    members: int
    progress: int = 0


@dataclass
class _SiteLedger:
    """Mutable per-site ledger state."""

    site_id: str
    owner: str | None
    claim_threshold: int
    cooldown_ticks: int
    cooldown_left: int = 0
    window_seq: int = 0
    contenders: dict[str, _Contender] = field(default_factory=dict)


class TerritoryClaimLedger:
    """Accumulate contest progress per site and arbitrate ownership changes."""

    def __init__(self, *, claim_threshold: int = 100, cooldown_ticks: int = 5,
                 max_contenders_per_site: int = 8) -> None:
        self._validate_positive_int(claim_threshold, "claim_threshold")
        self._validate_nonnegative_int(cooldown_ticks, "cooldown_ticks")
        self._validate_positive_int(
            max_contenders_per_site, "max_contenders_per_site"
        )
        self.claim_threshold = claim_threshold
        self.cooldown_ticks = cooldown_ticks
        self.max_contenders_per_site = max_contenders_per_site
        self._sites: dict[str, _SiteLedger] = {}
        self._stats = {
            "joins": 0,
            "leaves": 0,
            "ticks": 0,
            "claims": 0,
            "transfers": 0,
            "refused_settles": 0,
            "capacity_refusals": 0,
        }
        self._lock = threading.RLock()

    @staticmethod
    def _validate_positive_int(value: object, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            raise TerritoryError("TERRITORY_INVALID_REQUEST", name)
        return value

    @staticmethod
    def _validate_nonnegative_int(value: object, name: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise TerritoryError("TERRITORY_INVALID_REQUEST", name)
        return value

    @staticmethod
    def _identifier(value: object, name: str) -> str:
        if not isinstance(value, str):
            raise TerritoryError("TERRITORY_INVALID_REQUEST", name)
        normalized = value.strip()
        if not normalized:
            raise TerritoryError("TERRITORY_INVALID_REQUEST", name)
        return normalized

    @classmethod
    def _owner_identifier(cls, value: object) -> str | None:
        if value is None:
            return None
        return cls._identifier(value, "owner")

    def _site(self, site_id: object) -> _SiteLedger:
        normalized = self._identifier(site_id, "site_id")
        try:
            return self._sites[normalized]
        except KeyError:
            raise TerritoryError("TERRITORY_UNKNOWN_SITE", normalized) from None

    @staticmethod
    def _is_suspended(site: _SiteLedger) -> bool:
        if site.cooldown_left <= 0:
            return False
        return any(
            contender.progress >= site.claim_threshold
            for contender in site.contenders.values()
        )

    @staticmethod
    def _state(site: _SiteLedger) -> SiteState:
        return SiteState(
            site_id=site.site_id,
            owner=site.owner,
            claim_threshold=site.claim_threshold,
            cooldown_ticks=site.cooldown_ticks,
            cooldown_left=site.cooldown_left,
            contenders=tuple(site.contenders),
            progress=tuple(
                (guild, contender.progress)
                for guild, contender in site.contenders.items()
            ),
            members=tuple(
                (guild, contender.members)
                for guild, contender in site.contenders.items()
            ),
            suspended=TerritoryClaimLedger._is_suspended(site),
            window_seq=site.window_seq,
        )

    def add_site(self, site_id: str, *, owner: str | None = None) -> SiteState:
        """Register a stronghold, optionally already held by *owner*."""
        with self._lock:
            normalized = self._identifier(site_id, "site_id")
            normalized_owner = self._owner_identifier(owner)
            if normalized in self._sites:
                raise TerritoryError("TERRITORY_SITE_EXISTS", normalized)
            site = _SiteLedger(
                site_id=normalized,
                owner=normalized_owner,
                claim_threshold=self.claim_threshold,
                cooldown_ticks=self.cooldown_ticks,
            )
            self._sites[normalized] = site
            return self._state(site)

    def join_contest(self, site_id: str, guild: str, *, members: int,
                     now: int | None = None) -> SiteState:
        """Enter *guild* into the contest with *members* fighters per round."""
        with self._lock:
            normalized_site = self._identifier(site_id, "site_id")
            normalized_guild = self._identifier(guild, "guild")
            self._validate_positive_int(members, "members")
            site = self._site(normalized_site)

            contender = site.contenders.get(normalized_guild)
            if contender is None:
                if len(site.contenders) >= self.max_contenders_per_site:
                    self._stats["capacity_refusals"] += 1
                    raise TerritoryError(
                        "TERRITORY_CAPACITY_EXCEEDED", normalized_site
                    )
                site.contenders[normalized_guild] = _Contender(members=members)
            else:
                contender.members = members
            self._stats["joins"] += 1
            return self._state(site)

    def leave_contest(self, site_id: str, guild: str,
                      now: int | None = None) -> SiteState:
        """Drop *guild* from the contest, forfeiting its accumulated progress."""
        with self._lock:
            normalized_site = self._identifier(site_id, "site_id")
            normalized_guild = self._identifier(guild, "guild")
            site = self._site(normalized_site)
            if normalized_guild not in site.contenders:
                raise TerritoryError(
                    "TERRITORY_NOT_CONTENDING", normalized_guild
                )
            del site.contenders[normalized_guild]
            self._stats["leaves"] += 1
            return self._state(site)

    def tick(self, site_id: str, *, now: int | None = None) -> dict:
        """Run one contest round: add member progress and age the cooldown."""
        with self._lock:
            site = self._site(site_id)
            for contender in site.contenders.values():
                contender.progress = min(
                    site.claim_threshold,
                    contender.progress + contender.members,
                )
            if site.cooldown_left > 0:
                site.cooldown_left -= 1
            site.window_seq += 1
            self._stats["ticks"] += 1

            progress = {
                guild: contender.progress
                for guild, contender in site.contenders.items()
            }
            ready = tuple(sorted(
                guild
                for guild, points in progress.items()
                if points >= site.claim_threshold
            ))
            return {
                "site_id": site.site_id,
                "owner": site.owner,
                "window_seq": site.window_seq,
                "cooldown_left": site.cooldown_left,
                "progress": progress,
                "ready": ready,
                "suspended": bool(ready) and site.cooldown_left > 0,
            }

    def settle(self, site_id: str, guild: str,
               now: int | None = None) -> ClaimEvent:
        """Finalize the ownership transfer for a guild sitting at the cap."""
        with self._lock:
            normalized_site = self._identifier(site_id, "site_id")
            normalized_guild = self._identifier(guild, "guild")
            site = self._site(normalized_site)
            contender = site.contenders.get(normalized_guild)
            if contender is None:
                self._stats["refused_settles"] += 1
                raise TerritoryError(
                    "TERRITORY_NOT_CONTENDING", normalized_guild
                )
            if site.owner == normalized_guild:
                self._stats["refused_settles"] += 1
                raise TerritoryError("TERRITORY_ALREADY_OWNER", normalized_guild)
            if site.cooldown_left > 0:
                self._stats["refused_settles"] += 1
                raise TerritoryError("TERRITORY_IN_COOLDOWN", normalized_site)
            if contender.progress < site.claim_threshold:
                self._stats["refused_settles"] += 1
                raise TerritoryError("TERRITORY_NOT_READY", normalized_guild)

            previous_owner = site.owner
            site.owner = normalized_guild
            for entry in site.contenders.values():
                entry.progress = 0
            site.cooldown_left = site.cooldown_ticks
            self._stats["claims"] += 1
            if previous_owner is not None:
                self._stats["transfers"] += 1
            return ClaimEvent(
                site_id=site.site_id,
                guild=normalized_guild,
                previous_owner=previous_owner,
                transferred=previous_owner is not None,
                window_seq=site.window_seq,
            )

    def owner_of(self, site_id: str) -> str | None:
        """Return the owner guild, or ``None`` while the site is neutral."""
        with self._lock:
            return self._site(site_id).owner

    def progress_of(self, site_id: str, guild: str) -> int:
        """Return the control points *guild* accumulated at *site_id*."""
        with self._lock:
            site = self._site(site_id)
            normalized_guild = self._identifier(guild, "guild")
            contender = site.contenders.get(normalized_guild)
            return 0 if contender is None else contender.progress

    def cooldown_left(self, site_id: str) -> int:
        """Return how many contest rounds the transfer cooldown still blocks."""
        with self._lock:
            return self._site(site_id).cooldown_left

    def contenders(self, site_id: str) -> tuple[str, ...]:
        """Return contending guilds in registration order."""
        with self._lock:
            return tuple(self._site(site_id).contenders)

    def state_of(self, site_id: str) -> SiteState:
        """Return an immutable view of the site ledger entry."""
        with self._lock:
            return self._state(self._site(site_id))

    def snapshot(self) -> dict:
        """Return a deep copy of sites and counters suitable for ``restore``."""
        with self._lock:
            sites = {}
            for site_id in sorted(self._sites):
                site = self._sites[site_id]
                sites[site_id] = {
                    "site_id": site.site_id,
                    "owner": site.owner,
                    "claim_threshold": site.claim_threshold,
                    "cooldown_ticks": site.cooldown_ticks,
                    "cooldown_left": site.cooldown_left,
                    "window_seq": site.window_seq,
                    "contenders": list(site.contenders),
                    "members": {
                        guild: contender.members
                        for guild, contender in site.contenders.items()
                    },
                    "progress": {
                        guild: contender.progress
                        for guild, contender in site.contenders.items()
                    },
                    "suspended": self._is_suspended(site),
                }
            return {"sites": sites, "stats": self.stats()}

    def restore(self, state: dict) -> None:
        """Replace ledger state with a snapshot, validating its structure."""
        with self._lock:
            if not isinstance(state, Mapping):
                raise TerritoryError(
                    "TERRITORY_SNAPSHOT_INVALID", "snapshot must be a mapping"
                )

            raw_sites = state.get("sites")
            raw_stats = state.get("stats")
            if not isinstance(raw_sites, Mapping) or not isinstance(
                raw_stats, Mapping
            ):
                raise TerritoryError(
                    "TERRITORY_SNAPSHOT_INVALID", "sites and stats are required"
                )

            restored_sites: dict[str, _SiteLedger] = {}
            for raw_site_id, raw_site in raw_sites.items():
                if (
                    not isinstance(raw_site_id, str)
                    or not raw_site_id
                    or raw_site_id != raw_site_id.strip()
                    or not isinstance(raw_site, Mapping)
                ):
                    raise TerritoryError(
                        "TERRITORY_SNAPSHOT_INVALID", "invalid site entry"
                    )

                site_id = raw_site.get("site_id")
                owner = raw_site.get("owner")
                threshold = raw_site.get("claim_threshold")
                site_cooldown = raw_site.get("cooldown_ticks")
                cooldown_left = raw_site.get("cooldown_left")
                window_seq = raw_site.get("window_seq")
                contenders = raw_site.get("contenders")
                members = raw_site.get("members")
                progress = raw_site.get("progress")

                if site_id != raw_site_id:
                    raise TerritoryError(
                        "TERRITORY_SNAPSHOT_INVALID", "site id mismatch"
                    )
                if owner is not None and (
                    not isinstance(owner, str)
                    or not owner
                    or owner != owner.strip()
                ):
                    raise TerritoryError(
                        "TERRITORY_SNAPSHOT_INVALID", "invalid owner"
                    )
                if not self._snapshot_int(threshold, minimum=1):
                    raise TerritoryError(
                        "TERRITORY_SNAPSHOT_INVALID", "invalid claim threshold"
                    )
                if not self._snapshot_int(site_cooldown, minimum=0):
                    raise TerritoryError(
                        "TERRITORY_SNAPSHOT_INVALID", "invalid cooldown ticks"
                    )
                if (
                    not self._snapshot_int(cooldown_left, minimum=0)
                    or cooldown_left > site_cooldown
                ):
                    raise TerritoryError(
                        "TERRITORY_SNAPSHOT_INVALID", "invalid cooldown left"
                    )
                if not self._snapshot_int(window_seq, minimum=0):
                    raise TerritoryError(
                        "TERRITORY_SNAPSHOT_INVALID", "invalid window sequence"
                    )
                if (
                    not isinstance(contenders, (list, tuple))
                    or isinstance(contenders, (str, bytes))
                    or not isinstance(members, Mapping)
                    or not isinstance(progress, Mapping)
                ):
                    raise TerritoryError(
                        "TERRITORY_SNAPSHOT_INVALID", "invalid contender data"
                    )

                restored = _SiteLedger(
                    site_id=raw_site_id,
                    owner=owner,
                    claim_threshold=threshold,
                    cooldown_ticks=site_cooldown,
                    cooldown_left=cooldown_left,
                    window_seq=window_seq,
                )
                for guild in contenders:
                    if (
                        not isinstance(guild, str)
                        or not guild
                        or guild != guild.strip()
                        or guild in restored.contenders
                    ):
                        raise TerritoryError(
                            "TERRITORY_SNAPSHOT_INVALID",
                            "invalid contender name",
                        )
                    member_count = members.get(guild)
                    points = progress.get(guild)
                    if (
                        not self._snapshot_int(member_count, minimum=1)
                        or not self._snapshot_int(points, minimum=0)
                        or points > threshold
                    ):
                        raise TerritoryError(
                            "TERRITORY_SNAPSHOT_INVALID",
                            "invalid contender values",
                        )
                    restored.contenders[guild] = _Contender(
                        members=member_count, progress=points
                    )

                if (
                    len(restored.contenders) != len(members)
                    or len(restored.contenders) != len(progress)
                    or set(restored.contenders) != set(members)
                    or set(restored.contenders) != set(progress)
                ):
                    raise TerritoryError(
                        "TERRITORY_SNAPSHOT_INVALID", "contender data mismatch"
                    )
                restored_sites[raw_site_id] = restored

            required_stats = (
                "sites",
                "joins",
                "leaves",
                "ticks",
                "claims",
                "transfers",
                "refused_settles",
                "capacity_refusals",
            )
            restored_stats = {}
            for name in required_stats:
                value = raw_stats.get(name)
                if not self._snapshot_int(value, minimum=0):
                    raise TerritoryError(
                        "TERRITORY_SNAPSHOT_INVALID", f"invalid stat: {name}"
                    )
                restored_stats[name] = value
            if restored_stats["sites"] != len(restored_sites):
                raise TerritoryError(
                    "TERRITORY_SNAPSHOT_INVALID", "site count mismatch"
                )

            self._sites = restored_sites
            self._stats = {
                name: value
                for name, value in restored_stats.items()
                if name != "sites"
            }

    @staticmethod
    def _snapshot_int(value: object, *, minimum: int) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and value >= minimum
        )

    def stats(self) -> dict:
        """Return cumulative counters for joins, ticks, claims and refusals."""
        with self._lock:
            return {
                "sites": len(self._sites),
                "joins": self._stats["joins"],
                "leaves": self._stats["leaves"],
                "ticks": self._stats["ticks"],
                "claims": self._stats["claims"],
                "transfers": self._stats["transfers"],
                "refused_settles": self._stats["refused_settles"],
                "capacity_refusals": self._stats["capacity_refusals"],
            }
