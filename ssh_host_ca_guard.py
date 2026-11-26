"""SSH host certificate trust guard: CA anchors, revocation versions, known_hosts migration."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass

__all__ = [
    "HostTrustError",
    "CaRecord",
    "HostCertificate",
    "HostVerdict",
    "MigrationEntry",
    "SshHostCaGuard",
]


class HostTrustError(ValueError):
    """Raised when a trust-anchor, revocation or migration operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CaRecord:
    name: str
    public_key: str
    valid_from: str
    valid_to: str
    retired_at: str | None


@dataclass(frozen=True)
class HostCertificate:
    ca_name: str
    serial: str
    principals: tuple[str, ...]
    valid_from: str
    valid_to: str


@dataclass(frozen=True)
class HostVerdict:
    host: str
    port: int
    accepted: bool
    reason: str
    ca_name: str | None
    serial: str | None


@dataclass(frozen=True)
class MigrationEntry:
    host: str
    port: int
    fingerprint: str
    key_type: str
    migrated_at: str


class SshHostCaGuard:
    """Validate SSH host certificates against trusted CAs and revocation state."""

    def __init__(self, *, max_cas: int = 8, max_revocations: int = 256,
                 max_migration_entries: int = 64, cache_ttl: float = 300.0,
                 clock=None) -> None:
        self.max_cas = max_cas
        self.max_revocations = max_revocations
        self.max_migration_entries = max_migration_entries
        self.cache_ttl = cache_ttl
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()

    def trust_ca(self, name: str, public_key: str, valid_from: str, valid_to: str,
                 now: str | None = None) -> CaRecord:
        raise NotImplementedError

    def untrust_ca(self, name: str, now: str | None = None) -> bool:
        raise NotImplementedError

    def verify_host(self, host: str, port: int, certificate: HostCertificate,
                    now: str | None = None) -> HostVerdict:
        raise NotImplementedError

    def revoke(self, serial: str, ca_name: str, version: int,
               now: str | None = None) -> int:
        raise NotImplementedError

    def revocation_version(self) -> int:
        raise NotImplementedError

    def migrate_known_hosts(self, entries, now: str | None = None) -> tuple[MigrationEntry, ...]:
        raise NotImplementedError

    def known_hosts_entries(self) -> tuple[MigrationEntry, ...]:
        raise NotImplementedError

    def status(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
