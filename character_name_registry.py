"""Character name registry: normalized uniqueness, reservations, rename cooldowns."""

from __future__ import annotations

import threading


class NameRegistryError(ValueError):
    """Raised when a naming operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class CharacterNameRegistry:
    """Reserve and confirm character/guild names in a normalized namespace."""

    def __init__(self, *, token_ttl: int = 300, rename_cooldown: int = 86400,
                 max_tokens_per_owner: int = 3, max_name_length: int = 16,
                 min_name_length: int = 2, banned_words=None,
                 reserved_words=None) -> None:
        self.token_ttl = token_ttl
        self.rename_cooldown = rename_cooldown
        self.max_tokens_per_owner = max_tokens_per_owner
        self.max_name_length = max_name_length
        self.min_name_length = min_name_length
        self.banned_words = tuple(banned_words or ())
        self.reserved_words = tuple(reserved_words or ())
        self._lock = threading.RLock()

    def normalize(self, name: str) -> str:
        raise NotImplementedError

    def reserve(self, name: str, owner: str, *, now=None) -> dict:
        raise NotImplementedError

    def confirm(self, token: str, *, display_name=None, now=None) -> dict:
        raise NotImplementedError

    def release(self, token: str, owner: str) -> bool:
        raise NotImplementedError

    def rename(self, owner: str, new_name: str, *, now=None) -> dict:
        raise NotImplementedError

    def lookup(self, name: str) -> dict:
        raise NotImplementedError

    def expire(self, now=None) -> int:
        raise NotImplementedError

    def owner_names(self, owner: str) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
