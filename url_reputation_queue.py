"""URL reputation queue: redirect expansion, loop and hop limits, per-domain verdict cache."""

from __future__ import annotations

import copy
import threading
from urllib.parse import urlsplit, urlunsplit


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

SNAPSHOT_FORMAT = "url-reputation-queue-v1"
_SNAPSHOT_KEYS = frozenset({"format", "policies", "jobs", "cache", "counters"})
_COUNTER_KEYS = (
    "submitted",
    "expansions",
    "cache_hits",
    "expired",
    "undetermined",
)
_RESULT_KEYS = frozenset(
    {"outcome", "hops", "chain", "final_url", "verdict", "reason"}
)
_OUTCOMES = frozenset(
    {
        OUTCOME_RESOLVED,
        OUTCOME_LOOP,
        OUTCOME_HOP_LIMIT,
        OUTCOME_OUT_OF_SCOPE,
    }
)
_HEX_DIGITS = frozenset("0123456789abcdefABCDEF")


def _has_valid_percent_encoding(value: str) -> bool:
    index = 0
    length = len(value)
    while index < length:
        if value[index] != "%":
            index += 1
            continue
        if (index + 2 >= length
                or value[index + 1] not in _HEX_DIGITS
                or value[index + 2] not in _HEX_DIGITS):
            return False
        index += 3
    return True


def _remove_dot_segments(path: str) -> str:
    output = ""

    while path:
        if path.startswith("../"):
            path = path[3:]
        elif path.startswith("./"):
            path = path[2:]
        elif path.startswith("/./"):
            path = "/" + path[3:]
        elif path == "/.":
            path = "/"
        elif path.startswith("/../"):
            path = "/" + path[4:]
            last_slash = output.rfind("/")
            output = output[:last_slash] if last_slash >= 0 else ""
        elif path == "/..":
            path = "/"
            last_slash = output.rfind("/")
            output = output[:last_slash] if last_slash >= 0 else ""
        elif path in (".", ".."):
            path = ""
        else:
            search_from = 1 if path.startswith("/") else 0
            next_slash = path.find("/", search_from)
            if next_slash == -1:
                segment = path
                path = ""
            else:
                segment = path[:next_slash]
                path = path[next_slash:]
            output += segment

    return output


def normalize_url(value: object) -> str:
    if not isinstance(value, str) or not value:
        raise UrlQueueError("URL_BAD_URL", "url must be a non-empty string")
    if any(character.isspace() or ord(character) < 32 for character in value):
        raise UrlQueueError("URL_BAD_URL", "url contains invalid whitespace")
    if not _has_valid_percent_encoding(value):
        raise UrlQueueError("URL_BAD_URL", "url contains invalid percent encoding")

    try:
        parts = urlsplit(value)
        scheme = (parts.scheme or "").lower()
        if scheme not in ("http", "https"):
            raise UrlQueueError("URL_BAD_URL", "scheme must be http or https")

        host = parts.hostname
        if not host:
            raise UrlQueueError("URL_BAD_URL", "url must include a host")
        if parts.password is not None:
            raise UrlQueueError("URL_BAD_URL", "urls with passwords are not allowed")

        port = parts.port
    except UrlQueueError:
        raise
    except (TypeError, ValueError) as exc:
        raise UrlQueueError("URL_BAD_URL", "url is malformed") from exc

    host = host.lower()
    if ":" in host:
        host_port = f"[{host}]"
    else:
        host_port = host

    default_port = (scheme == "http" and port == 80) or (
        scheme == "https" and port == 443
    )
    if port is not None and not default_port:
        host_port = f"{host_port}:{port}"

    if "@" in parts.netloc:
        userinfo = parts.netloc.rsplit("@", 1)[0]
        netloc = f"{userinfo}@{host_port}"
    else:
        netloc = host_port

    path = _remove_dot_segments(parts.path or "")
    if not path:
        path = "/"

    return urlunsplit((scheme, netloc, path, parts.query, ""))


def _normalize_domain(value: object) -> str:
    if not isinstance(value, str):
        raise ValueError("domain must be a string")
    domain = value.strip().lower()
    domain = domain.strip(".")
    if not domain or any(character.isspace() for character in domain):
        raise ValueError("domain is invalid")
    return domain


class UrlReputationQueue:
    """Expand submitted URLs along observed redirects and cache the verdict per URL."""

    def __init__(self, *, hop_limit: int = 5, allowed_domains=(),
                 default_ttl: int = 600, max_pending: int = 32) -> None:
        self.hop_limit = hop_limit
        raw_allowed_domains = (
            (allowed_domains,) if isinstance(allowed_domains, str)
            else allowed_domains
        )
        self.allowed_domains = tuple(
            _normalize_domain(domain) for domain in raw_allowed_domains
        )
        self.default_ttl = default_ttl
        self.max_pending = max_pending
        self._lock = threading.RLock()
        self._policies: dict[str, dict] = {}
        self._jobs: dict[str, dict] = {}
        self._pending: dict[str, str] = {}
        self._pending_by_url: dict[str, str] = {}
        self._cache: dict[str, dict] = {}
        self._next_job_number = 1
        self._counters = {key: 0 for key in _COUNTER_KEYS}

    def register_domain_policy(self, domain: str, *, ttl: int | None = None,
                               verdict: str = VERDICT_BENIGN) -> dict:
        try:
            normalized_domain = _normalize_domain(domain)
        except ValueError as exc:
            raise UrlQueueError("URL_BAD_POLICY", "domain is invalid") from exc
        if verdict not in VERDICTS:
            raise UrlQueueError("URL_BAD_POLICY", "verdict must be benign or malicious")
        if ttl is not None and (
                not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0):
            raise UrlQueueError("URL_BAD_POLICY", "ttl must be a non-negative integer")

        policy = {
            "domain": normalized_domain,
            "ttl": ttl,
            "verdict": verdict,
        }
        with self._lock:
            self._policies[normalized_domain] = policy
        return dict(policy)

    def submit(self, url: str, *, chain=(), now: int) -> dict:
        normalized_url = normalize_url(url)
        try:
            raw_chain = tuple(chain)
        except TypeError as exc:
            raise UrlQueueError("URL_BAD_CHAIN", "chain must be iterable") from exc

        normalized_chain = []
        for entry in raw_chain:
            try:
                normalized_chain.append(normalize_url(entry))
            except UrlQueueError as exc:
                raise UrlQueueError("URL_BAD_CHAIN", entry) from exc
        chain_urls = tuple(normalized_chain)

        with self._lock:
            cached = self._cache_lookup(normalized_url, now)
            if cached is not None:
                self._counters["submitted"] += 1
                self._counters["cache_hits"] += 1
                return {
                    "job_id": None,
                    "url": normalized_url,
                    "state": "cached",
                    "verdict": cached,
                }

            existing_job_id = self._pending_by_url.get(normalized_url)
            if existing_job_id is not None:
                self._counters["submitted"] += 1
                return {
                    "job_id": existing_job_id,
                    "url": normalized_url,
                    "state": JOB_QUEUED,
                }

            if len(self._pending) >= self.max_pending:
                raise UrlQueueError("URL_QUEUE_FULL", self.max_pending)

            job_id = f"JOB-{self._next_job_number:04d}"
            self._next_job_number += 1
            job = {
                "job_id": job_id,
                "url": normalized_url,
                "state": JOB_QUEUED,
                "chain": chain_urls,
                "result": None,
            }
            self._jobs[job_id] = job
            self._pending[job_id] = normalized_url
            self._pending_by_url[normalized_url] = job_id
            self._counters["submitted"] += 1
            return {
                "job_id": job_id,
                "url": normalized_url,
                "state": JOB_QUEUED,
            }

    def pending(self) -> tuple:
        with self._lock:
            return tuple(self._pending)

    def expand(self, job_id: str, *, now: int) -> dict:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise UrlQueueError("URL_JOB_UNKNOWN", job_id)
            if job["state"] == JOB_EXPANDED:
                return copy.deepcopy(job["result"])

            result = self._build_result(job, now)
            job["state"] = JOB_EXPANDED
            job["result"] = result
            self._pending.pop(job_id, None)
            self._pending_by_url.pop(job["url"], None)

            self._counters["expansions"] += 1
            if result["verdict"] == VERDICT_UNDETERMINED:
                self._counters["undetermined"] += 1

            if result["outcome"] == OUTCOME_RESOLVED:
                policy = self._policy_for_url(result["final_url"])
                ttl = self.default_ttl if policy is None else policy["ttl"]
                if ttl is None:
                    ttl = self.default_ttl
                self._cache[result["final_url"]] = {
                    "verdict": result["verdict"],
                    "expires_at": now + ttl,
                }

            return copy.deepcopy(result)

    def expand_result(self, job_id: str) -> dict:
        with self._lock:
            job = self._jobs.get(job_id)
            if job is None:
                raise UrlQueueError("URL_JOB_UNKNOWN", job_id)
            if job["state"] != JOB_EXPANDED or job["result"] is None:
                raise UrlQueueError("URL_JOB_PENDING", job_id)
            return copy.deepcopy(job["result"])

    def verdict(self, job_id: str) -> dict:
        result = self.expand_result(job_id)
        return {
            "verdict": result["verdict"],
            "reason": result["reason"],
        }

    def cache_lookup(self, url: str, *, now: int) -> dict | None:
        normalized_url = normalize_url(url)
        with self._lock:
            return self._cache_lookup(normalized_url, now)

    def expire(self, *, now: int) -> int:
        with self._lock:
            expired = [
                url for url, entry in self._cache.items()
                if entry["expires_at"] <= now
            ]
            for url in expired:
                del self._cache[url]
            self._counters["expired"] += len(expired)
            return len(expired)

    def jobs(self) -> tuple:
        with self._lock:
            return tuple(
                {
                    "job_id": job["job_id"],
                    "url": job["url"],
                    "state": job["state"],
                }
                for job in self._jobs.values()
            )

    def stats(self) -> dict:
        with self._lock:
            return {
                "policies": len(self._policies),
                "submitted": self._counters["submitted"],
                "expansions": self._counters["expansions"],
                "cache_hits": self._counters["cache_hits"],
                "expired": self._counters["expired"],
                "undetermined": self._counters["undetermined"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "format": SNAPSHOT_FORMAT,
                "policies": copy.deepcopy(self._policies),
                "jobs": copy.deepcopy(self._jobs),
                "cache": copy.deepcopy(self._cache),
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        try:
            restored = self._validate_snapshot(state)
        except (TypeError, ValueError, KeyError):
            raise UrlQueueError("URL_SNAPSHOT_INVALID", "malformed snapshot") from None

        with self._lock:
            self._policies = restored["policies"]
            self._jobs = restored["jobs"]
            self._cache = restored["cache"]
            self._counters = restored["counters"]
            self._next_job_number = restored["next_job_number"]
            self._pending = {
                job_id: job["url"]
                for job_id, job in self._jobs.items()
                if job["state"] == JOB_QUEUED
            }
            self._pending_by_url = {
                url: job_id for job_id, url in self._pending.items()
            }

    def _cache_lookup(self, normalized_url: str, now: int) -> dict | None:
        entry = self._cache.get(normalized_url)
        if entry is None or entry["expires_at"] <= now:
            return None
        return {
            "verdict": entry["verdict"],
            "expires_at": entry["expires_at"],
        }

    def _domain_in_scope(self, host: str) -> bool:
        if not self.allowed_domains:
            return True
        normalized_host = host.lower().rstrip(".")
        return any(
            normalized_host == domain
            or normalized_host.endswith(f".{domain}")
            for domain in self.allowed_domains
        )

    def _policy_for_url(self, url: str) -> dict | None:
        host = (urlsplit(url).hostname or "").lower().rstrip(".")
        policy = self._policies.get(host)
        if policy is not None:
            return policy

        parts = host.split(".")
        for index in range(1, len(parts)):
            candidate = ".".join(parts[index:])
            policy = self._policies.get(candidate)
            if policy is not None:
                return policy
        return None

    @staticmethod
    def _loop_identity(url: str) -> str:
        parts = urlsplit(url)
        return urlunsplit(("", parts.netloc, parts.path, parts.query, ""))

    def _build_result(self, job: dict, now: int) -> dict:
        start_url = job["url"]
        visited = [start_url]
        seen = {self._loop_identity(start_url)}
        hops = 0

        for target_url in job["chain"]:
            if hops >= self.hop_limit:
                return {
                    "outcome": OUTCOME_HOP_LIMIT,
                    "hops": hops,
                    "chain": tuple(visited),
                    "final_url": None,
                    "verdict": VERDICT_UNDETERMINED,
                    "reason": OUTCOME_HOP_LIMIT,
                }

            visited.append(target_url)
            hops += 1

            target_identity = self._loop_identity(target_url)
            if target_identity in seen:
                return {
                    "outcome": OUTCOME_LOOP,
                    "hops": hops,
                    "chain": tuple(visited),
                    "final_url": None,
                    "verdict": VERDICT_UNDETERMINED,
                    "reason": "redirect_loop",
                }
            seen.add(target_identity)

            host = urlsplit(target_url).hostname or ""
            if not self._domain_in_scope(host):
                return {
                    "outcome": OUTCOME_OUT_OF_SCOPE,
                    "hops": hops,
                    "chain": tuple(visited),
                    "final_url": target_url,
                    "verdict": VERDICT_UNDETERMINED,
                    "reason": OUTCOME_OUT_OF_SCOPE,
                }

        final_url = visited[-1]
        policy = self._policy_for_url(final_url)
        if policy is None:
            verdict = VERDICT_BENIGN
            reason = "default_policy"
        else:
            verdict = policy["verdict"]
            reason = "domain_policy"

        return {
            "outcome": OUTCOME_RESOLVED,
            "hops": hops,
            "chain": tuple(visited),
            "final_url": final_url,
            "verdict": verdict,
            "reason": reason,
        }

    @classmethod
    def _validate_snapshot(cls, state: object) -> dict:
        if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
            raise ValueError("snapshot must contain exactly the supported keys")
        if state["format"] != SNAPSHOT_FORMAT:
            raise ValueError("unsupported snapshot format")

        policies = cls._validate_policies(state["policies"])
        jobs, next_job_number = cls._validate_jobs(state["jobs"])
        cache = cls._validate_cache(state["cache"])
        counters = cls._validate_counters(state["counters"])
        return {
            "policies": policies,
            "jobs": jobs,
            "cache": cache,
            "counters": counters,
            "next_job_number": next_job_number,
        }

    @staticmethod
    def _validate_policies(raw_policies: object) -> dict:
        if not isinstance(raw_policies, dict):
            raise ValueError("policies must be a dict")

        policies = {}
        for raw_domain, raw_policy in raw_policies.items():
            domain = _normalize_domain(raw_domain)
            if not isinstance(raw_policy, dict):
                raise ValueError("policy must be a dict")
            if set(raw_policy) != {"domain", "ttl", "verdict"}:
                raise ValueError("policy has invalid keys")
            if not isinstance(raw_policy["domain"], str):
                raise ValueError("policy domain is invalid")
            ttl = raw_policy["ttl"]
            if ttl is not None and (
                    not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 0):
                raise ValueError("policy ttl is invalid")
            if raw_policy["verdict"] not in VERDICTS:
                raise ValueError("policy verdict is invalid")

            policies[domain] = {
                "domain": domain,
                "ttl": ttl,
                "verdict": raw_policy["verdict"],
            }
        return policies

    @classmethod
    def _validate_jobs(cls, raw_jobs: object) -> tuple[dict, int]:
        if not isinstance(raw_jobs, dict):
            raise ValueError("jobs must be a dict")

        jobs = {}
        pending_urls = set()
        next_job_number = 1

        for job_id, raw_job in raw_jobs.items():
            if (not isinstance(job_id, str) or not job_id.startswith("JOB-")
                    or not job_id[4:].isdigit()):
                raise ValueError("job id is invalid")
            job_number = int(job_id[4:])
            if job_number <= 0:
                raise ValueError("job id is invalid")
            next_job_number = max(next_job_number, job_number + 1)

            if not isinstance(raw_job, dict):
                raise ValueError("job must be a dict")
            if set(raw_job) != {"job_id", "url", "state", "chain", "result"}:
                raise ValueError("job has invalid keys")
            if raw_job["job_id"] != job_id:
                raise ValueError("job id does not match its key")

            url = normalize_url(raw_job["url"])
            raw_chain = raw_job["chain"]
            if not isinstance(raw_chain, (list, tuple)):
                raise ValueError("job chain must be a sequence")
            chain = tuple(normalize_url(entry) for entry in raw_chain)

            state = raw_job["state"]
            result = raw_job["result"]
            if state == JOB_QUEUED:
                if result is not None:
                    raise ValueError("queued job cannot have a result")
                if url in pending_urls:
                    raise ValueError("duplicate pending url")
                pending_urls.add(url)
            elif state == JOB_EXPANDED:
                result = cls._validate_result(result, url)
            else:
                raise ValueError("job state is invalid")

            jobs[job_id] = {
                "job_id": job_id,
                "url": url,
                "state": state,
                "chain": chain,
                "result": result,
            }

        return jobs, next_job_number

    @staticmethod
    def _validate_result(raw_result: object, expected_url: str) -> dict:
        if not isinstance(raw_result, dict):
            raise ValueError("result must be a dict")
        if set(raw_result) != _RESULT_KEYS:
            raise ValueError("result has invalid keys")

        outcome = raw_result["outcome"]
        verdict = raw_result["verdict"]
        reason = raw_result["reason"]
        hops = raw_result["hops"]
        raw_chain = raw_result["chain"]
        final_url = raw_result["final_url"]

        if outcome not in _OUTCOMES:
            raise ValueError("result outcome is invalid")
        if verdict not in (
                VERDICT_BENIGN, VERDICT_MALICIOUS, VERDICT_UNDETERMINED):
            raise ValueError("result verdict is invalid")
        if not isinstance(reason, str):
            raise ValueError("result reason is invalid")
        if not isinstance(hops, int) or isinstance(hops, bool) or hops < 0:
            raise ValueError("result hops are invalid")
        if not isinstance(raw_chain, (list, tuple)):
            raise ValueError("result chain must be a sequence")

        chain = tuple(normalize_url(entry) for entry in raw_chain)
        if not chain or chain[0] != expected_url:
            raise ValueError("result chain does not start with the job url")
        if len(chain) != hops + 1:
            raise ValueError("result chain length does not match hops")

        if final_url is not None:
            final_url = normalize_url(final_url)

        if outcome == OUTCOME_RESOLVED:
            if final_url != chain[-1]:
                raise ValueError("resolved result has an invalid final url")
            if verdict not in VERDICTS:
                raise ValueError("resolved verdict is invalid")
            if reason not in ("default_policy", "domain_policy"):
                raise ValueError("resolved reason is invalid")
        elif outcome == OUTCOME_LOOP:
            if final_url is not None or verdict != VERDICT_UNDETERMINED:
                raise ValueError("loop result is invalid")
            if reason != "redirect_loop":
                raise ValueError("loop reason is invalid")
        elif outcome == OUTCOME_HOP_LIMIT:
            if final_url is not None or verdict != VERDICT_UNDETERMINED:
                raise ValueError("hop limit result is invalid")
            if reason != OUTCOME_HOP_LIMIT:
                raise ValueError("hop limit reason is invalid")
        else:
            if verdict != VERDICT_UNDETERMINED:
                raise ValueError("out-of-scope verdict is invalid")
            if reason != OUTCOME_OUT_OF_SCOPE:
                raise ValueError("out-of-scope reason is invalid")
            if final_url != chain[-1]:
                raise ValueError("out-of-scope final url is invalid")

        return {
            "outcome": outcome,
            "hops": hops,
            "chain": chain,
            "final_url": final_url,
            "verdict": verdict,
            "reason": reason,
        }

    @staticmethod
    def _validate_cache(raw_cache: object) -> dict:
        if not isinstance(raw_cache, dict):
            raise ValueError("cache must be a dict")

        cache = {}
        for raw_url, raw_entry in raw_cache.items():
            url = normalize_url(raw_url)
            if not isinstance(raw_entry, dict):
                raise ValueError("cache entry must be a dict")
            if set(raw_entry) != {"verdict", "expires_at"}:
                raise ValueError("cache entry has invalid keys")
            if raw_entry["verdict"] not in VERDICTS:
                raise ValueError("cache verdict is invalid")
            expires_at = raw_entry["expires_at"]
            if (not isinstance(expires_at, (int, float))
                    or isinstance(expires_at, bool)):
                raise ValueError("cache expiry is invalid")

            cache[url] = {
                "verdict": raw_entry["verdict"],
                "expires_at": expires_at,
            }
        return cache

    @staticmethod
    def _validate_counters(raw_counters: object) -> dict:
        if not isinstance(raw_counters, dict):
            raise ValueError("counters must be a dict")
        if set(raw_counters) != set(_COUNTER_KEYS):
            raise ValueError("counters have invalid keys")

        counters = {}
        for key in _COUNTER_KEYS:
            value = raw_counters[key]
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"counter {key} is invalid")
            counters[key] = value
        return counters
