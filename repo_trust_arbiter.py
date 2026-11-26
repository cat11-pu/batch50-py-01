"""Repository trust arbitration: per-source keyrings, pins and downgrade control."""

from __future__ import annotations

import threading
from dataclasses import dataclass


ERR_INVALID_REQUEST = "REPO_INVALID_REQUEST"
ERR_KEY_CONFLICT = "REPO_KEY_CONFLICT"
ERR_KEY_UNKNOWN = "REPO_KEY_UNKNOWN"
ERR_KEY_ALREADY_BOUND = "REPO_KEY_ALREADY_BOUND"
ERR_KEY_NOT_BOUND = "REPO_KEY_NOT_BOUND"
ERR_SOURCE_DUPLICATE = "REPO_SOURCE_DUPLICATE"
ERR_SOURCE_UNKNOWN = "REPO_SOURCE_UNKNOWN"
ERR_COMPONENT_UNKNOWN = "REPO_COMPONENT_UNKNOWN"
ERR_RELEASE_SCOPE_MISMATCH = "REPO_RELEASE_SCOPE_MISMATCH"
ERR_RELEASE_SIGNATURE_INVALID = "REPO_RELEASE_SIGNATURE_INVALID"
ERR_RELEASE_EXPIRED = "REPO_RELEASE_EXPIRED"
ERR_NO_CANDIDATE = "REPO_NO_CANDIDATE"
ERR_DOWNGRADE_REFUSED = "REPO_DOWNGRADE_REFUSED"
ERR_PACKAGE_DUPLICATE = "REPO_PACKAGE_DUPLICATE"
ERR_SNAPSHOT_INVALID = "REPO_SNAPSHOT_INVALID"


class RepoError(ValueError):
    """Raised when a repository operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SourceInfo:
    source_id: str
    origin: str
    suite: str
    components: tuple
    priority: int
    keys: tuple
    state: str
    valid_until: object


@dataclass(frozen=True)
class Candidate:
    name: str
    version: str
    source_id: str
    priority: int
    suite: str


@dataclass(frozen=True)
class ResolveResult:
    name: str
    version: str
    source_id: str
    priority: int
    action: str


class RepoTrustArbiter:
    """Decide whether a package version from some source may be installed."""

    def __init__(self, *, installed_versions=None, arch: str = "amd64") -> None:
        self.installed_versions = dict(installed_versions or {})
        self.arch = arch
        self._lock = threading.RLock()

    def add_key(self, key_id: str, material: str) -> None:
        raise NotImplementedError

    def revoke_key(self, key_id: str) -> bool:
        raise NotImplementedError

    def add_source(self, source_id: str, *, origin: str, suite: str,
                   components=(), priority: int = 100, keys=()) -> SourceInfo:
        raise NotImplementedError

    def remove_source(self, source_id: str) -> bool:
        raise NotImplementedError

    def publish_package(self, source_id: str, *, name: str, version: str,
                        component: str, origin=None, suite=None,
                        arch: str = "amd64", digest: str = "") -> None:
        raise NotImplementedError

    def verify_release(self, source_id: str, *, suite: str, origin: str,
                       valid_until: str, now: str, key_id: str,
                       signature: str) -> dict:
        raise NotImplementedError

    def pin(self, package: str, *, source_id: str, priority: int,
            reason: str = "") -> None:
        raise NotImplementedError

    def unpin(self, package: str, *, source_id: str) -> bool:
        raise NotImplementedError

    def mark_installed(self, name: str, version: str) -> None:
        raise NotImplementedError

    def candidates(self, name: str, *, now=None) -> list:
        raise NotImplementedError

    def resolve(self, name: str, *, now=None, allow_downgrade: bool = False) -> ResolveResult:
        raise NotImplementedError

    def status(self, source_id=None) -> object:
        raise NotImplementedError

    def audit(self, *, now=None) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
