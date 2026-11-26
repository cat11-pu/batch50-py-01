"""Upload scanning gate with digest verdict cache, timeout quarantine and manual release."""

from __future__ import annotations


class ScanGateError(ValueError):
    """Raised when a gate operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


DECISION_ALLOW = "allow"
DECISION_DENY = "deny"
DECISION_PENDING = "pending"

STATE_QUEUED = "queued"
STATE_SCANNING = "scanning"
STATE_DECIDED = "decided"
STATE_QUARANTINED = "quarantined"

SCAN_OUTCOMES = ("benign", "malicious")


class UploadScanGate:
    """Serialize uploads by content digest, scan each digest once and cache clean verdicts."""

    def __init__(self, *, cache_ttl: int = 300, scan_timeout: int = 60,
                 max_queue: int = 8, max_bytes: int = 1048576) -> None:
        self.cache_ttl = cache_ttl
        self.scan_timeout = scan_timeout
        self.max_queue = max_queue
        self.max_bytes = max_bytes

    def submit(self, upload_id: str, data, *, now: int) -> dict:
        raise NotImplementedError

    def claim(self, *, now: int) -> dict | None:
        raise NotImplementedError

    def complete_scan(self, digest: str, *, outcome: str, now: int) -> dict:
        raise NotImplementedError

    def verdict(self, upload_id: str) -> dict:
        raise NotImplementedError

    def queue(self) -> tuple:
        raise NotImplementedError

    def cache_lookup(self, digest: str, *, now: int) -> dict | None:
        raise NotImplementedError

    def quarantine(self, digest: str, *, reason: str, now: int) -> dict:
        raise NotImplementedError

    def release(self, digest: str, *, actor: str, now: int) -> dict:
        raise NotImplementedError

    def sweep(self, *, now: int) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
