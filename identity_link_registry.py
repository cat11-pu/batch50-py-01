"""External identity links: uniqueness, unlink protection and tombstones."""

from __future__ import annotations

import copy
import threading
from collections import Counter
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
from typing import Any


_SNAPSHOT_VERSION = 1
_SNAPSHOT_KEYS = {
    "version",
    "accounts",
    "links",
    "tombstones",
    "cooldowns",
    "stats",
}
_STAT_FIELDS = (
    "accounts_created",
    "links_created",
    "links_removed",
    "merges",
    "cooldown_hits",
)
_STAT_KEYS = set(_STAT_FIELDS)


class IdentityLinkError(ValueError):
    """Raised when an identity-link operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Account:
    account_id: str
    state: str
    created_at: str
    link_count: int


@dataclass(frozen=True)
class LinkRecord:
    account_id: str
    provider: str
    external_id: str
    sequence: int
    linked_at: str


@dataclass(frozen=True)
class MergeResult:
    source: str
    target: str
    state: str
    moved: int
    dropped: int
    merged_at: str


def _require_text(value: Any, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise IdentityLinkError(
            "IDENTITY_INVALID_REQUEST", {"field": field}
        )
    return value


def _parse_time(value: str) -> datetime:
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_now(now: str | None) -> str:
    if now is None:
        return datetime.now(timezone.utc).isoformat()
    if not isinstance(now, str) or not now:
        raise IdentityLinkError("IDENTITY_INVALID_REQUEST", {"field": "now"})
    try:
        _parse_time(now)
    except ValueError as exc:
        raise IdentityLinkError(
            "IDENTITY_INVALID_REQUEST", {"field": "now"}
        ) from exc
    return now


def _cooldown_active(unlinked_at: str, now: str, cooldown_seconds: int) -> bool:
    if cooldown_seconds <= 0:
        return False
    elapsed = _parse_time(now) - _parse_time(unlinked_at)
    return elapsed.total_seconds() < cooldown_seconds


class IdentityLinkRegistry:
    """Own the mapping between accounts and external identities."""

    def __init__(
        self,
        *,
        max_links_per_provider: int = 8,
        cooldown_seconds: int = 86400,
    ) -> None:
        self.max_links_per_provider = max_links_per_provider
        self.cooldown_seconds = cooldown_seconds
        self._lock = threading.RLock()
        self._accounts: dict[str, dict[str, Any]] = {}
        self._links: dict[tuple[str, str, str], LinkRecord] = {}
        self._identity_index: dict[tuple[str, str], tuple[str, str, str]] = {}
        self._tombstones: dict[str, dict[str, str]] = {}
        self._cooldowns: dict[tuple[str, str, str], str] = {}
        self._stats = {
            "accounts_created": 0,
            "links_created": 0,
            "links_removed": 0,
            "merges": 0,
            "cooldown_hits": 0,
        }

    def create_account(
        self, account_id: str, *, now: str | None = None
    ) -> Account:
        account_id = _require_text(account_id, "account_id")
        created_at = _normalize_now(now)
        with self._lock:
            account = self._accounts.get(account_id)
            if account is not None:
                if account["state"] == "tombstoned":
                    raise IdentityLinkError(
                        "IDENTITY_ACCOUNT_TOMBSTONED",
                        {"account_id": account_id},
                    )
                return self._account_view_locked(account_id)

            self._accounts[account_id] = {
                "account_id": account_id,
                "state": "active",
                "created_at": created_at,
                "sequence": 0,
            }
            self._stats["accounts_created"] += 1
            return self._account_view_locked(account_id)

    def link(
        self,
        account_id: str,
        *,
        provider: str,
        external_id: str,
        now: str | None = None,
    ) -> LinkRecord:
        account_id = _require_text(account_id, "account_id")
        provider = _require_text(provider, "provider")
        external_id = _require_text(external_id, "external_id")
        linked_at = _normalize_now(now)

        with self._lock:
            account = self._require_active_account_locked(account_id)
            link_key = (account_id, provider, external_id)
            identity_key = (provider, external_id)
            owner_key = self._identity_index.get(identity_key)

            if owner_key == link_key and link_key in self._links:
                return self._links[link_key]

            unlinked_at = self._cooldowns.get(link_key)
            if unlinked_at is not None and _cooldown_active(
                unlinked_at, linked_at, self.cooldown_seconds
            ):
                self._stats["cooldown_hits"] += 1
                raise IdentityLinkError(
                    "IDENTITY_COOLDOWN",
                    {
                        "account_id": account_id,
                        "provider": provider,
                        "external_id": external_id,
                        "unlinked_at": unlinked_at,
                    },
                )

            if owner_key is not None:
                raise IdentityLinkError(
                    "IDENTITY_LINK_TAKEN",
                    {
                        "account_id": account_id,
                        "provider": provider,
                        "external_id": external_id,
                        "owner_account_id": owner_key[0],
                    },
                )

            provider_count = self._provider_count_locked(
                account_id, provider
            )
            if provider_count >= self.max_links_per_provider:
                raise IdentityLinkError(
                    "IDENTITY_LINK_LIMIT",
                    {
                        "account_id": account_id,
                        "provider": provider,
                        "limit": self.max_links_per_provider,
                    },
                )

            sequence = int(account["sequence"]) + 1
            record = LinkRecord(
                account_id=account_id,
                provider=provider,
                external_id=external_id,
                sequence=sequence,
                linked_at=linked_at,
            )
            account["sequence"] = sequence
            self._links[link_key] = record
            self._identity_index[identity_key] = link_key
            self._stats["links_created"] += 1
            return record

    def unlink(
        self,
        account_id: str,
        *,
        provider: str,
        external_id: str,
        now: str | None = None,
    ) -> bool:
        account_id = _require_text(account_id, "account_id")
        unlinked_at = _normalize_now(now)

        with self._lock:
            if account_id not in self._accounts:
                raise IdentityLinkError(
                    "IDENTITY_ACCOUNT_UNKNOWN",
                    {"account_id": account_id},
                )

            link_key = (account_id, provider, external_id)
            record = self._links.get(link_key)
            if record is None:
                return False

            if self._link_count_locked(account_id) <= 1:
                raise IdentityLinkError(
                    "IDENTITY_LAST_LOGIN",
                    {
                        "account_id": account_id,
                        "provider": provider,
                        "external_id": external_id,
                    },
                )

            del self._links[link_key]
            self._identity_index.pop((provider, external_id), None)
            self._cooldowns[link_key] = unlinked_at
            self._stats["links_removed"] += 1
            return True

    def resolve(self, provider: str, external_id: str) -> dict | None:
        with self._lock:
            owner_key = self._identity_index.get((provider, external_id))
            if owner_key is None:
                return None
            record = self._links.get(owner_key)
            if record is None:
                return None
            return {
                "account_id": record.account_id,
                "provider": record.provider,
                "external_id": record.external_id,
            }

    def merge_accounts(
        self,
        source: str,
        target: str,
        *,
        now: str | None = None,
    ) -> MergeResult:
        source = _require_text(source, "source")
        target = _require_text(target, "target")
        merged_at = _normalize_now(now)

        with self._lock:
            if source == target:
                raise IdentityLinkError(
                    "IDENTITY_MERGE_INVALID",
                    {"source": source, "target": target},
                )

            source_account = self._accounts.get(source)
            target_account = self._accounts.get(target)
            if source_account is None or target_account is None:
                missing = source if source_account is None else target
                raise IdentityLinkError(
                    "IDENTITY_ACCOUNT_UNKNOWN",
                    {"account_id": missing},
                )
            if (
                source_account["state"] == "tombstoned"
                or target_account["state"] == "tombstoned"
            ):
                tombstoned = (
                    source
                    if source_account["state"] == "tombstoned"
                    else target
                )
                raise IdentityLinkError(
                    "IDENTITY_ACCOUNT_TOMBSTONED",
                    {"account_id": tombstoned},
                )

            source_records = sorted(
                (
                    record
                    for record in self._links.values()
                    if record.account_id == source
                ),
                key=lambda record: (
                    record.provider,
                    record.external_id,
                    record.sequence,
                ),
            )
            target_counts = Counter(
                record.provider
                for record in self._links.values()
                if record.account_id == target
            )
            for provider, count in target_counts.items():
                if count > self.max_links_per_provider:
                    raise IdentityLinkError(
                        "IDENTITY_LINK_LIMIT",
                        {
                            "account_id": target,
                            "provider": provider,
                            "limit": self.max_links_per_provider,
                        },
                    )

            final_counts = dict(target_counts)
            moves: list[LinkRecord] = []
            drops: list[LinkRecord] = []

            for record in source_records:
                target_key = (target, record.provider, record.external_id)
                if target_key in self._links:
                    drops.append(record)
                    continue

                next_count = final_counts.get(record.provider, 0) + 1
                if next_count > self.max_links_per_provider:
                    raise IdentityLinkError(
                        "IDENTITY_LINK_LIMIT",
                        {
                            "account_id": target,
                            "provider": record.provider,
                            "limit": self.max_links_per_provider,
                        },
                    )
                final_counts[record.provider] = next_count
                moves.append(record)

            new_accounts = copy.deepcopy(self._accounts)
            new_links = dict(self._links)
            new_identity_index = dict(self._identity_index)
            new_tombstones = copy.deepcopy(self._tombstones)
            new_stats = dict(self._stats)
            new_cooldowns = dict(self._cooldowns)

            target_state = new_accounts[target]
            target_sequence = int(target_state["sequence"])

            for record in moves:
                source_key = (source, record.provider, record.external_id)
                target_key = (target, record.provider, record.external_id)
                new_record = replace(record, account_id=target)
                new_links.pop(source_key, None)
                new_links[target_key] = new_record
                new_identity_index[(record.provider, record.external_id)] = (
                    target_key
                )
                target_sequence = max(target_sequence, record.sequence)

            for record in drops:
                source_key = (source, record.provider, record.external_id)
                target_key = (target, record.provider, record.external_id)
                new_links.pop(source_key, None)
                new_identity_index[(record.provider, record.external_id)] = (
                    target_key
                )

            target_state["sequence"] = target_sequence
            new_accounts[source]["state"] = "tombstoned"
            new_tombstones[source] = {
                "merged_into": target,
                "merged_at": merged_at,
            }
            new_stats["merges"] += 1

            self._accounts = new_accounts
            self._links = new_links
            self._identity_index = new_identity_index
            self._tombstones = new_tombstones
            self._cooldowns = new_cooldowns
            self._stats = new_stats

            return MergeResult(
                source=source,
                target=target,
                state="merged",
                moved=len(moves),
                dropped=len(drops),
                merged_at=merged_at,
            )

    def list_links(self, account_id: str) -> list[LinkRecord]:
        with self._lock:
            if account_id not in self._accounts:
                raise IdentityLinkError(
                    "IDENTITY_ACCOUNT_UNKNOWN",
                    {"account_id": account_id},
                )
            if self._accounts[account_id]["state"] == "tombstoned":
                return []
            return sorted(
                (
                    record
                    for record in self._links.values()
                    if record.account_id == account_id
                ),
                key=lambda record: (record.provider, record.external_id),
            )

    def status(self, account_id: str) -> dict:
        with self._lock:
            account = self._accounts.get(account_id)
            if account is None:
                raise IdentityLinkError(
                    "IDENTITY_ACCOUNT_UNKNOWN",
                    {"account_id": account_id},
                )

            providers = sorted(
                {
                    record.provider
                    for record in self._links.values()
                    if record.account_id == account_id
                }
            )
            tombstone = self._tombstones.get(account_id)
            return {
                "account_id": account_id,
                "state": account["state"],
                "merged_into": (
                    tombstone["merged_into"] if tombstone is not None else None
                ),
                "link_count": self._link_count_locked(account_id),
                "providers": providers,
            }

    def tombstone_of(self, account_id: str) -> dict | None:
        with self._lock:
            tombstone = self._tombstones.get(account_id)
            return copy.deepcopy(tombstone) if tombstone is not None else None

    def accounts(self) -> list[str]:
        with self._lock:
            return list(self._accounts)

    def snapshot(self) -> dict:
        with self._lock:
            cooldowns: dict[str, dict[str, dict[str, str]]] = {}
            for account_id in sorted(
                {key[0] for key in self._cooldowns}
            ):
                for provider in sorted(
                    {
                        key[1]
                        for key in self._cooldowns
                        if key[0] == account_id
                    }
                ):
                    provider_bucket: dict[str, str] = {}
                    for external_id in sorted(
                        key[2]
                        for key in self._cooldowns
                        if key[0] == account_id and key[1] == provider
                    ):
                        provider_bucket[external_id] = self._cooldowns[
                            (account_id, provider, external_id)
                        ]
                    cooldowns.setdefault(account_id, {})[provider] = (
                        provider_bucket
                    )

            return {
                "version": _SNAPSHOT_VERSION,
                "accounts": copy.deepcopy(self._accounts),
                "links": [
                    asdict(record)
                    for record in sorted(
                        self._links.values(),
                        key=lambda record: (
                            record.account_id,
                            record.provider,
                            record.external_id,
                        ),
                    )
                ],
                "tombstones": copy.deepcopy(self._tombstones),
                "cooldowns": cooldowns,
                "stats": dict(self._stats),
            }

    def restore(self, state: dict) -> None:
        try:
            candidate = self._parse_snapshot(copy.deepcopy(state))
        except IdentityLinkError:
            raise
        except Exception as exc:
            raise IdentityLinkError(
                "IDENTITY_SNAPSHOT_INVALID", None
            ) from exc

        with self._lock:
            (
                accounts,
                links,
                identity_index,
                tombstones,
                cooldowns,
                stats,
            ) = candidate
            self._accounts = accounts
            self._links = links
            self._identity_index = identity_index
            self._tombstones = tombstones
            self._cooldowns = cooldowns
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _account_view_locked(self, account_id: str) -> Account:
        account = self._accounts[account_id]
        return Account(
            account_id=account["account_id"],
            state=account["state"],
            created_at=account["created_at"],
            link_count=self._link_count_locked(account_id),
        )

    def _require_active_account_locked(self, account_id: str) -> dict:
        account = self._accounts.get(account_id)
        if account is None:
            raise IdentityLinkError(
                "IDENTITY_ACCOUNT_UNKNOWN",
                {"account_id": account_id},
            )
        if account["state"] == "tombstoned":
            raise IdentityLinkError(
                "IDENTITY_ACCOUNT_TOMBSTONED",
                {"account_id": account_id},
            )
        return account

    def _link_count_locked(self, account_id: str) -> int:
        return sum(
            1
            for record in self._links.values()
            if record.account_id == account_id
        )

    def _provider_count_locked(self, account_id: str, provider: str) -> int:
        return sum(
            1
            for record in self._links.values()
            if record.account_id == account_id
            and record.provider == provider
        )

    def _parse_snapshot(self, state: Any) -> tuple[
        dict[str, dict[str, Any]],
        dict[tuple[str, str, str], LinkRecord],
        dict[tuple[str, str], tuple[str, str, str]],
        dict[str, dict[str, str]],
        dict[tuple[str, str, str], str],
        dict[str, int],
    ]:
        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
        if (
            not isinstance(state["version"], int)
            or isinstance(state["version"], bool)
            or state["version"] != _SNAPSHOT_VERSION
        ):
            raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")

        raw_accounts = state["accounts"]
        if not isinstance(raw_accounts, dict):
            raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")

        accounts: dict[str, dict[str, Any]] = {}
        for account_id, raw_account in raw_accounts.items():
            if not isinstance(account_id, str) or not account_id.strip():
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if not isinstance(raw_account, dict):
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if set(raw_account) != {
                "account_id",
                "state",
                "created_at",
                "sequence",
            }:
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if raw_account["account_id"] != account_id:
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if raw_account["state"] not in {"active", "tombstoned"}:
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if (
                not isinstance(raw_account["created_at"], str)
                or not raw_account["created_at"]
            ):
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if (
                not isinstance(raw_account["sequence"], int)
                or isinstance(raw_account["sequence"], bool)
                or raw_account["sequence"] < 0
            ):
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            accounts[account_id] = copy.deepcopy(raw_account)

        raw_links = state["links"]
        if not isinstance(raw_links, list):
            raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")

        links: dict[tuple[str, str, str], LinkRecord] = {}
        identity_index: dict[
            tuple[str, str], tuple[str, str, str]
        ] = {}
        for raw_link in raw_links:
            if not isinstance(raw_link, dict):
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if set(raw_link) != {
                "account_id",
                "provider",
                "external_id",
                "sequence",
                "linked_at",
            }:
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")

            account_id = raw_link["account_id"]
            provider = raw_link["provider"]
            external_id = raw_link["external_id"]
            sequence = raw_link["sequence"]
            linked_at = raw_link["linked_at"]
            if (
                not isinstance(account_id, str)
                or not account_id.strip()
                or account_id not in accounts
            ):
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if not isinstance(provider, str) or not provider.strip():
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if not isinstance(external_id, str) or not external_id.strip():
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if (
                not isinstance(sequence, int)
                or isinstance(sequence, bool)
                or sequence <= 0
            ):
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if not isinstance(linked_at, str) or not linked_at:
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")

            link_key = (account_id, provider, external_id)
            identity_key = (provider, external_id)
            if link_key in links or identity_key in identity_index:
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if accounts[account_id]["state"] == "tombstoned":
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")

            links[link_key] = LinkRecord(
                account_id=account_id,
                provider=provider,
                external_id=external_id,
                sequence=sequence,
                linked_at=linked_at,
            )
            identity_index[identity_key] = link_key

        for link_key, record in links.items():
            if record.sequence > accounts[link_key[0]]["sequence"]:
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")

        raw_tombstones = state["tombstones"]
        if not isinstance(raw_tombstones, dict):
            raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")

        tombstones: dict[str, dict[str, str]] = {}
        for account_id, raw_tombstone in raw_tombstones.items():
            if account_id not in accounts:
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if not isinstance(raw_tombstone, dict):
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if set(raw_tombstone) != {"merged_into", "merged_at"}:
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            merged_into = raw_tombstone["merged_into"]
            merged_at = raw_tombstone["merged_at"]
            if (
                not isinstance(merged_into, str)
                or merged_into not in accounts
            ):
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            if not isinstance(merged_at, str) or not merged_at:
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            try:
                _parse_time(merged_at)
            except ValueError as exc:
                raise IdentityLinkError(
                    "IDENTITY_SNAPSHOT_INVALID"
                ) from exc
            if accounts[account_id]["state"] != "tombstoned":
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            tombstones[account_id] = {
                "merged_into": merged_into,
                "merged_at": merged_at,
            }

        for account_id, account in accounts.items():
            if account["state"] == "tombstoned" and account_id not in tombstones:
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")

        raw_cooldowns = state["cooldowns"]
        if not isinstance(raw_cooldowns, dict):
            raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")

        cooldowns: dict[tuple[str, str, str], str] = {}
        for account_id, providers in raw_cooldowns.items():
            if account_id not in accounts or not isinstance(providers, dict):
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            for provider, externals in providers.items():
                if (
                    not isinstance(provider, str)
                    or not provider.strip()
                    or not isinstance(externals, dict)
                ):
                    raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
                for external_id, unlinked_at in externals.items():
                    if (
                        not isinstance(external_id, str)
                        or not external_id.strip()
                        or not isinstance(unlinked_at, str)
                        or not unlinked_at
                    ):
                        raise IdentityLinkError(
                            "IDENTITY_SNAPSHOT_INVALID"
                        )
                    try:
                        _parse_time(unlinked_at)
                    except ValueError as exc:
                        raise IdentityLinkError(
                            "IDENTITY_SNAPSHOT_INVALID"
                        ) from exc
                    cooldown_key = (account_id, provider, external_id)
                    if cooldown_key in cooldowns:
                        raise IdentityLinkError(
                            "IDENTITY_SNAPSHOT_INVALID"
                        )
                    cooldowns[cooldown_key] = unlinked_at

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict) or set(raw_stats) != _STAT_KEYS:
            raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
        stats: dict[str, int] = {}
        for key in _STAT_FIELDS:
            value = raw_stats[key]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise IdentityLinkError("IDENTITY_SNAPSHOT_INVALID")
            stats[key] = value

        return (
            accounts,
            links,
            identity_index,
            tombstones,
            cooldowns,
            stats,
        )
