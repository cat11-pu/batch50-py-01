"""authorized_keys governance: option parsing, fingerprint dedup, atomic file replacement."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class KeysError(ValueError):
    """Raised when a registry operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


KEY_TYPES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256")

VALUE_OPTIONS = ("from", "command", "expiry-time", "principals", "environment")
FLAG_OPTIONS = ("no-pty", "no-port-forwarding", "no-agent-forwarding",
                "no-X11-forwarding", "restrict")

DEDUP_POLICIES = ("reject", "isolate")


@dataclass(frozen=True)
class KeyEntry:
    account: str
    fingerprint: str
    key_type: str
    comment: str
    options: dict
    line: str
    revision: int
    added_at: str


class AuthorizedKeysRegistry:
    """Maintain per-account authorized keys with fingerprint dedup and atomic writes."""

    def __init__(self, *, dedup_policy: str = "reject") -> None:
        self.dedup_policy = dedup_policy
        self._lock = threading.RLock()
        self._entries: dict[tuple[str, str], KeyEntry] = {}
        self._revoked: dict[str, str] = {}
        self._quarantined: list[str] = []
        self._comments: list[str] = []
        self._audit: list[dict] = []
        self._counters: dict[str, int] = {}

    def parse_line(self, line: str, *, account: str = "") -> KeyEntry:
        raise NotImplementedError

    def upsert(self, account: str, line: str, *, now=None) -> KeyEntry:
        raise NotImplementedError

    def revoke(self, fingerprint: str, *, now=None) -> bool:
        raise NotImplementedError

    def render(self) -> str:
        raise NotImplementedError

    def apply(self, path) -> dict:
        raise NotImplementedError

    def diff(self, path) -> dict:
        raise NotImplementedError

    def load(self, path, *, account: str, now=None) -> int:
        raise NotImplementedError

    def entries(self, account=None) -> list[KeyEntry]:
        raise NotImplementedError

    def quarantined(self) -> list[str]:
        raise NotImplementedError

    def audit_log(self) -> list[dict]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
