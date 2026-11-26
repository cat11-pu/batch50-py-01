"""External identity links: uniqueness, unlink protection and account tombstones."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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


class IdentityLinkRegistry:
    """Own the mapping between accounts and external identities."""

    def __init__(self, *, max_links_per_provider: int = 8,
                 cooldown_seconds: int = 86400) -> None:
        self.max_links_per_provider = max_links_per_provider
        self.cooldown_seconds = cooldown_seconds
        self._lock = threading.RLock()

    def create_account(self, account_id: str, *,
                       now: str | None = None) -> Account:
        raise NotImplementedError

    def link(self, account_id: str, *, provider: str, external_id: str,
             now: str | None = None) -> LinkRecord:
        raise NotImplementedError

    def unlink(self, account_id: str, *, provider: str, external_id: str,
               now: str | None = None) -> bool:
        raise NotImplementedError

    def resolve(self, provider: str, external_id: str) -> dict | None:
        raise NotImplementedError

    def merge_accounts(self, source: str, target: str, *,
                       now: str | None = None) -> MergeResult:
        raise NotImplementedError

    def list_links(self, account_id: str) -> list[LinkRecord]:
        raise NotImplementedError

    def status(self, account_id: str) -> dict:
        raise NotImplementedError

    def tombstone_of(self, account_id: str) -> dict | None:
        raise NotImplementedError

    def accounts(self) -> list[str]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
