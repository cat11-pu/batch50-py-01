"""Bucket exposure scanner: ACL evaluation, anonymous probes, rescan ledger."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class ExposureError(ValueError):
    """Raised when a bucket registration or probe transition is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AclVerdict:
    bucket: str
    region: str
    read_allowed: bool
    write_allowed: bool
    public_read: bool
    public_write: bool
    explicit_denies: tuple[str, ...]
    reasons: tuple[str, ...]


@dataclass(frozen=True)
class ProbeResult:
    bucket: str
    region: str
    action: str
    status: int | None
    state: str
    evidence: tuple[str, ...]
    reproducible: bool


@dataclass(frozen=True)
class Conclusion:
    bucket: str
    region: str
    account: str
    policy_version: int
    state: str
    evidence: tuple[str, ...]
    read_public: bool
    write_public: bool
    confirmed_at: int | None
    rescanned_at: int | None
    cached: bool = False


class BucketExposureScanner:
    """Detect publicly exposed object storage buckets and keep a rescan ledger."""

    def __init__(self, *, max_buckets: int = 100, probe_per_minute: int = 30,
                 cooldown_seconds: int = 60, rescan_interval: int = 600,
                 prober=None) -> None:
        self.max_buckets = max_buckets
        self.probe_per_minute = probe_per_minute
        self.cooldown_seconds = cooldown_seconds
        self.rescan_interval = rescan_interval
        self._prober = prober
        self._lock = threading.RLock()

    def register(self, bucket: str, *, region: str, account: str,
                 acl=None, policy=None) -> int:
        raise NotImplementedError

    def evaluate_acl(self, bucket: str, *, region: str, acl=None,
                     policy=None) -> AclVerdict:
        raise NotImplementedError

    def probe_anonymous(self, bucket: str, *, region: str,
                        now: int | None = None) -> ProbeResult:
        raise NotImplementedError

    def confirm(self, bucket: str, *, region: str, verdict: str = "exposed",
                now: int | None = None) -> str:
        raise NotImplementedError

    def rescan(self, bucket: str, *, region: str,
               now: int | None = None) -> Conclusion:
        raise NotImplementedError

    def conclusions(self, *, state: str | None = None) -> list[Conclusion]:
        raise NotImplementedError

    def set_probe_rate(self, limit: int) -> None:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
