"""URL reputation queue: redirect expansion, loop and hop limits, per-domain verdict cache."""

from __future__ import annotations


class UrlQueueError(ValueError):
    """Raised when a queue operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


VERDICT_MALICIOUS = "malicious"
VERDICT_BENIGN = "benign"
VERDICT_UNDETERMINED = "undetermined"

OUTCOME_RESOLVED = "resolved"
OUTCOME_LOOP = "loop"
OUTCOME_HOP_LIMIT = "hop_limit"
OUTCOME_OUT_OF_SCOPE = "out_of_scope"

JOB_QUEUED = "queued"
JOB_EXPANDED = "expanded"

VERDICTS = (VERDICT_MALICIOUS, VERDICT_BENIGN)


class UrlReputationQueue:
    """Expand submitted URLs along observed redirects and cache the verdict per URL."""

    def __init__(self, *, hop_limit: int = 5, allowed_domains=(),
                 default_ttl: int = 600, max_pending: int = 32) -> None:
        self.hop_limit = hop_limit
        self.allowed_domains = tuple(allowed_domains)
        self.default_ttl = default_ttl
        self.max_pending = max_pending

    def register_domain_policy(self, domain: str, *, ttl: int | None = None,
                               verdict: str = VERDICT_BENIGN) -> dict:
        raise NotImplementedError

    def submit(self, url: str, *, chain=(), now: int) -> dict:
        raise NotImplementedError

    def pending(self) -> tuple:
        raise NotImplementedError

    def expand(self, job_id: str, *, now: int) -> dict:
        raise NotImplementedError

    def expand_result(self, job_id: str) -> dict:
        raise NotImplementedError

    def verdict(self, job_id: str) -> dict:
        raise NotImplementedError

    def cache_lookup(self, url: str, *, now: int) -> dict | None:
        raise NotImplementedError

    def expire(self, *, now: int) -> int:
        raise NotImplementedError

    def jobs(self) -> tuple:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
