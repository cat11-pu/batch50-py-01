"""Rich text HTML sanitizing gate: allow-list rewriting, mXSS normalization, idempotent output."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class SanitizeError(ValueError):
    """Raised when sanitizing or a policy operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SanitizePolicy:
    version: int
    allowed_tags: tuple
    allowed_attributes: dict
    allowed_protocols: tuple


@dataclass(frozen=True)
class SanitizeResult:
    policy_version: int
    html: str
    dropped_tags: tuple
    dropped_attributes: tuple
    duplicate_attributes: int


class HtmlSanitizeGate:
    """Rewrite untrusted rich text against a versioned allow-list policy."""

    def __init__(self, *, max_length: int = 4096, max_depth: int = 12) -> None:
        self.max_length = max_length
        self.max_depth = max_depth
        self._lock = threading.RLock()

    def sanitize(self, html: str, *, tenant: str = "default") -> SanitizeResult:
        raise NotImplementedError

    def validate_policy(self, *, allowed_tags, allowed_attributes,
                        allowed_protocols) -> SanitizePolicy:
        raise NotImplementedError

    def reload_policy(self, *, allowed_tags, allowed_attributes,
                      allowed_protocols) -> SanitizePolicy:
        raise NotImplementedError

    def explain(self, html: str, *, tenant: str = "default") -> list:
        raise NotImplementedError

    def status(self) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def reset_stats(self) -> None:
        raise NotImplementedError

    def set_limits(self, *, max_length=None, max_depth=None) -> None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
