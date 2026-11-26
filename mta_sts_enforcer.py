"""MTA-STS outbound policy cache: freshness, MX matching, reports and snapshots."""

from __future__ import annotations

import copy
import re
import threading
import time
from dataclasses import dataclass
from ipaddress import ip_address


class StsError(ValueError):
    """Raised when a policy cannot be fetched or parsed."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PolicyRecord:
    domain: str
    policy_id: str | None
    mode: str
    max_age: int
    mx: tuple
    fetched_at: int | float
    expires_at: int | float


@dataclass(frozen=True)
class DeliveryDecision:
    domain: str
    mx_host: str
    action: str
    reason: str
    policy_id: object


_POLICY_MODES = frozenset({"enforce", "testing", "none"})
_STAT_KEYS = (
    "fetched",
    "cache_hits",
    "failures",
    "evicted",
    "delivered",
    "deferred",
    "opportunistic",
    "report_dropped",
)
_REPORT_KEYS = ("deliver", "defer", "opportunistic")
_SNAPSHOT_VERSION = 1
_SNAPSHOT_KEYS = frozenset({"version", "policies", "reports", "failures", "stats"})
_HOST_LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$")


class _InflightFetch:
    __slots__ = ("event", "result", "error")

    def __init__(self) -> None:
        self.event = threading.Event()
        self.result: PolicyRecord | None = None
        self.error: BaseException | None = None


def _current_time(now: int | float | None) -> int | float:
    return int(time.time()) if now is None else now


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_timestamp(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _valid_hostname(value: object, *, allow_wildcard: bool = False) -> bool:
    if not isinstance(value, str) or not value:
        return False

    host = value
    if allow_wildcard and host.startswith("*."):
        host = host[2:]
        if not host or "*" in host:
            return False
    elif "*" in host:
        return False

    if host.endswith("."):
        host = host[:-1]
    if not host or len(host) > 253:
        return False

    try:
        ascii_host = host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return False

    if len(ascii_host) > 253:
        return False

    try:
        ip_address(ascii_host)
    except ValueError:
        pass
    else:
        return False

    labels = ascii_host.split(".")
    for label in labels:
        if not 1 <= len(label) <= 63:
            return False
        if _HOST_LABEL_RE.fullmatch(label) is None:
            return False

    return True


def _canonical_host(value: object) -> str:
    if not isinstance(value, str):
        return ""
    host = value[:-1] if value.endswith(".") else value
    try:
        return host.encode("idna").decode("ascii").lower()
    except UnicodeError:
        return host.lower()


def _mx_pattern_matches(pattern: str, host: object) -> bool:
    if not _valid_hostname(host):
        return False

    canonical_host = _canonical_host(host)
    if pattern.startswith("*."):
        suffix = _canonical_host(pattern[2:])
        if not suffix:
            return False
        return canonical_host.endswith("." + suffix)

    return _canonical_host(pattern) == canonical_host


def _parse_policy(domain: str, raw: object, fetched_at: int | float) -> PolicyRecord:
    if not isinstance(raw, dict):
        raise StsError("STS_POLICY_INVALID", "policy must be a mapping")

    if "version" in raw and raw["version"] != "STSv1":
        raise StsError("STS_POLICY_INVALID", "unsupported STS version")

    mode = raw.get("mode")
    if not isinstance(mode, str) or mode not in _POLICY_MODES:
        raise StsError("STS_POLICY_INVALID", "invalid policy mode")

    max_age = raw.get("max_age")
    if not _is_integer(max_age) or max_age < 0:
        raise StsError("STS_POLICY_INVALID", "invalid max_age")

    mx_values = raw.get("mx")
    if not isinstance(mx_values, (list, tuple)) or not mx_values:
        raise StsError("STS_POLICY_INVALID", "mx list must not be empty")

    mx_hosts: list[str] = []
    for mx_value in mx_values:
        if not _valid_hostname(mx_value, allow_wildcard=True):
            raise StsError("STS_POLICY_INVALID", "invalid MX hostname")
        mx_hosts.append(mx_value)

    policy_id = raw.get("policy_id")
    if policy_id is None:
        policy_id = raw.get("id")
    if policy_id is not None and not isinstance(policy_id, str):
        raise StsError("STS_POLICY_INVALID", "invalid policy id")

    return PolicyRecord(
        domain=domain,
        policy_id=policy_id,
        mode=mode,
        max_age=max_age,
        mx=tuple(mx_hosts),
        fetched_at=fetched_at,
        expires_at=fetched_at + max_age,
    )


class MtaStsEnforcer:
    """Cache sender-domain MTA-STS policies and decide outbound delivery mode."""

    def __init__(self, *, fetcher, cache_capacity: int = 64,
                 report_capacity: int = 128) -> None:
        self._fetcher = fetcher
        self.cache_capacity = cache_capacity
        self.report_capacity = report_capacity
        self._lock = threading.RLock()
        self._inflight: dict[str, _InflightFetch] = {}
        self._policies: dict[str, PolicyRecord] = {}
        self._reports: dict[str, dict[str, int]] = {}
        self._failures: dict[str, int] = {}
        self._counters: dict[str, int] = {key: 0 for key in _STAT_KEYS}

    def fetch(self, domain: str, *, now=None, force: bool = False) -> PolicyRecord:
        fetched_at = _current_time(now)
        leader = False
        inflight: _InflightFetch | None = None

        with self._lock:
            if not force:
                cached = self._fresh_policy_locked(domain, fetched_at)
                if cached is not None:
                    self._counters["cache_hits"] += 1
                    return cached

            inflight = self._inflight.get(domain)
            if inflight is None:
                inflight = _InflightFetch()
                self._inflight[domain] = inflight
                leader = True

        if not leader:
            assert inflight is not None
            inflight.event.wait()
            if inflight.error is not None:
                raise inflight.error
            assert inflight.result is not None
            return inflight.result

        result: PolicyRecord | None = None
        error: StsError | BaseException | None = None

        try:
            raw_policy = self._fetcher(domain)
            try:
                result = _parse_policy(domain, raw_policy, fetched_at)
            except StsError as exc:
                error = exc
            except Exception as exc:  # Defensive: parsers should report StsError.
                error = StsError("STS_POLICY_INVALID", exc)
        except Exception as exc:
            error = StsError("STS_FETCH_FAILED", exc)
        except BaseException as exc:
            with self._lock:
                if self._inflight.get(domain) is inflight:
                    del self._inflight[domain]
                inflight.error = exc
                inflight.event.set()
            raise

        with self._lock:
            if error is None:
                assert result is not None
                self._store_policy_locked(result)
                self._counters["fetched"] += 1
                inflight.result = result
            else:
                self._record_fetch_failure_locked(domain)
                inflight.error = error

            if self._inflight.get(domain) is inflight:
                del self._inflight[domain]
            inflight.event.set()

        if error is not None:
            raise error
        assert result is not None
        return result

    def decide(self, domain: str, mx_host: str, *, now=None) -> DeliveryDecision:
        decision_time = _current_time(now)

        with self._lock:
            policy = self._fresh_policy_locked(domain, decision_time)
            if policy is None:
                decision = DeliveryDecision(
                    domain=domain,
                    mx_host=mx_host,
                    action="opportunistic",
                    reason="NO_POLICY",
                    policy_id=None,
                )
                self._count_decision_locked(domain, "opportunistic")
                return decision

            if policy.mode == "none":
                decision = DeliveryDecision(
                    domain=domain,
                    mx_host=mx_host,
                    action="deliver",
                    reason="POLICY_NONE",
                    policy_id=policy.policy_id,
                )
                self._count_decision_locked(domain, "deliver")
                return decision

            matched = any(
                _mx_pattern_matches(pattern, mx_host)
                for pattern in policy.mx
            )

            if policy.mode == "enforce":
                if matched:
                    action = "deliver"
                    reason = "POLICY_MATCH"
                else:
                    action = "defer"
                    reason = "MX_NOT_ALLOWED"
            else:  # testing
                action = "deliver"
                reason = "POLICY_MATCH" if matched else "TESTING_MISMATCH"

            decision = DeliveryDecision(
                domain=domain,
                mx_host=mx_host,
                action=action,
                reason=reason,
                policy_id=policy.policy_id,
            )
            self._count_decision_locked(
                domain,
                "defer" if action == "defer" else "deliver",
            )
            if policy.mode == "testing" and not matched:
                self._record_failure_locked(domain)
            return decision

    def refresh(self, domain: str, *, now=None) -> bool:
        try:
            self.fetch(domain, now=now, force=True)
        except StsError:
            return False
        return True

    def policy_for(self, domain: str, *, now=None):
        policy_time = _current_time(now)
        with self._lock:
            return self._fresh_policy_locked(domain, policy_time)

    def mx_matches(self, domain: str, host: str, *, now=None) -> bool:
        match_time = _current_time(now)
        with self._lock:
            policy = self._fresh_policy_locked(domain, match_time)
            if policy is None:
                return False
            return any(
                _mx_pattern_matches(pattern, host)
                for pattern in policy.mx
            )

    def report(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._reports)

    def purge_expired(self, now) -> int:
        purge_time = _current_time(now)
        with self._lock:
            expired = [
                domain
                for domain, record in self._policies.items()
                if record.expires_at <= purge_time
            ]
            for domain in expired:
                del self._policies[domain]
            return len(expired)

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": _SNAPSHOT_VERSION,
                "policies": {
                    domain: {
                        "domain": record.domain,
                        "policy_id": record.policy_id,
                        "mode": record.mode,
                        "max_age": record.max_age,
                        "mx": list(record.mx),
                        "fetched_at": record.fetched_at,
                        "expires_at": record.expires_at,
                    }
                    for domain, record in self._policies.items()
                },
                "reports": copy.deepcopy(self._reports),
                "failures": copy.deepcopy(self._failures),
                "stats": dict(self._counters),
            }
        return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        try:
            policies, reports, failures, counters = _validate_snapshot(
                state,
                cache_capacity=self.cache_capacity,
                report_capacity=self.report_capacity,
            )
        except StsError:
            raise
        except Exception as exc:
            raise StsError("STS_SNAPSHOT_INVALID", exc) from exc
        with self._lock:
            self._inflight.clear()
            self._policies = policies
            self._reports = reports
            self._failures = failures
            self._counters = counters

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def _fresh_policy_locked(
        self, domain: str, now: int | float
    ) -> PolicyRecord | None:
        record = self._policies.get(domain)
        if record is not None and record.expires_at > now:
            return record
        return None

    def _store_policy_locked(self, record: PolicyRecord) -> None:
        domain = record.domain
        capacity = self.cache_capacity

        if not _is_integer(capacity) or capacity <= 0:
            self._policies.pop(domain, None)
            return

        if domain not in self._policies:
            while len(self._policies) >= capacity:
                oldest_domain = min(
                    self._policies,
                    key=lambda candidate: (
                        self._policies[candidate].fetched_at,
                    ),
                )
                del self._policies[oldest_domain]
                self._counters["evicted"] += 1

        self._policies.pop(domain, None)
        self._policies[domain] = record

    def _count_decision_locked(self, domain: str, action: str) -> None:
        if action == "deliver":
            self._counters["delivered"] += 1
            report_key = "deliver"
        elif action == "defer":
            self._counters["deferred"] += 1
            report_key = "defer"
        else:
            self._counters["opportunistic"] += 1
            report_key = "opportunistic"

        bucket = self._reports.get(domain)
        if bucket is None:
            if len(self._reports) >= self.report_capacity:
                self._counters["report_dropped"] += 1
                return
            bucket = {key: 0 for key in _REPORT_KEYS}
            self._reports[domain] = bucket

        bucket[report_key] += 1

    def _record_failure_locked(self, domain: str) -> None:
        self._failures[domain] = self._failures.get(domain, 0) + 1
        self._counters["failures"] += 1

    def _record_fetch_failure_locked(self, domain: str) -> None:
        self._record_failure_locked(domain)


def _invalid_snapshot(detail: object = None) -> StsError:
    return StsError("STS_SNAPSHOT_INVALID", detail)


def _validate_snapshot(
    state: object,
    *,
    cache_capacity: object,
    report_capacity: object,
) -> tuple[
    dict[str, PolicyRecord],
    dict[str, dict[str, int]],
    dict[str, int],
    dict[str, int],
]:
    if not isinstance(state, dict) or set(state) != _SNAPSHOT_KEYS:
        raise _invalid_snapshot("snapshot must contain exactly the supported keys")

    version = state["version"]
    if not _is_integer(version) or version != _SNAPSHOT_VERSION:
        raise _invalid_snapshot("unsupported snapshot version")

    policies_raw = state["policies"]
    reports_raw = state["reports"]
    failures_raw = state["failures"]
    stats_raw = state["stats"]

    if not isinstance(policies_raw, dict):
        raise _invalid_snapshot("policies must be a mapping")
    if not isinstance(reports_raw, dict):
        raise _invalid_snapshot("reports must be a mapping")
    if not isinstance(failures_raw, dict):
        raise _invalid_snapshot("failures must be a mapping")
    if not isinstance(stats_raw, dict):
        raise _invalid_snapshot("stats must be a mapping")

    if _is_integer(cache_capacity) and cache_capacity >= 0:
        if len(policies_raw) > cache_capacity:
            raise _invalid_snapshot("too many policy domains")
    if _is_integer(report_capacity) and report_capacity >= 0:
        if len(reports_raw) > report_capacity:
            raise _invalid_snapshot("too many report domains")

    policies: dict[str, PolicyRecord] = {}
    for domain, item in policies_raw.items():
        if not isinstance(domain, str) or not isinstance(item, dict):
            raise _invalid_snapshot("invalid policy entry")

        required_keys = {
            "domain",
            "policy_id",
            "mode",
            "max_age",
            "mx",
            "fetched_at",
            "expires_at",
        }
        if set(item) != required_keys:
            raise _invalid_snapshot("invalid policy fields")
        if item["domain"] != domain:
            raise _invalid_snapshot("policy domain mismatch")

        policy_id = item["policy_id"]
        if policy_id is not None and not isinstance(policy_id, str):
            raise _invalid_snapshot("invalid policy id")

        mode = item["mode"]
        if not isinstance(mode, str) or mode not in _POLICY_MODES:
            raise _invalid_snapshot("invalid policy mode")

        max_age = item["max_age"]
        if not _is_integer(max_age) or max_age < 0:
            raise _invalid_snapshot("invalid max_age")

        mx_raw = item["mx"]
        if not isinstance(mx_raw, (list, tuple)):
            raise _invalid_snapshot("invalid mx list")
        mx_hosts: list[str] = []
        for mx_value in mx_raw:
            if not _valid_hostname(mx_value, allow_wildcard=True):
                raise _invalid_snapshot("invalid MX hostname")
            mx_hosts.append(mx_value)

        fetched_at = item["fetched_at"]
        expires_at = item["expires_at"]
        if not _is_timestamp(fetched_at) or not _is_timestamp(expires_at):
            raise _invalid_snapshot("invalid policy timestamp")
        if expires_at != fetched_at + max_age:
            raise _invalid_snapshot("invalid policy expiry")

        policies[domain] = PolicyRecord(
            domain=domain,
            policy_id=policy_id,
            mode=mode,
            max_age=max_age,
            mx=tuple(mx_hosts),
            fetched_at=fetched_at,
            expires_at=expires_at,
        )

    reports: dict[str, dict[str, int]] = {}
    for domain, bucket in reports_raw.items():
        if not isinstance(domain, str) or not isinstance(bucket, dict):
            raise _invalid_snapshot("invalid report entry")
        if set(bucket) != set(_REPORT_KEYS):
            raise _invalid_snapshot("invalid report fields")

        clean_bucket: dict[str, int] = {}
        for key in _REPORT_KEYS:
            count = bucket[key]
            if not _is_integer(count) or count < 0:
                raise _invalid_snapshot("invalid report count")
            clean_bucket[key] = count
        reports[domain] = clean_bucket

    failures: dict[str, int] = {}
    for domain, count in failures_raw.items():
        if not isinstance(domain, str):
            raise _invalid_snapshot("invalid failure domain")
        if not _is_integer(count) or count < 0:
            raise _invalid_snapshot("invalid failure count")
        failures[domain] = count

    if set(stats_raw) != set(_STAT_KEYS):
        raise _invalid_snapshot("invalid stats fields")
    counters: dict[str, int] = {}
    for key in _STAT_KEYS:
        count = stats_raw[key]
        if not _is_integer(count) or count < 0:
            raise _invalid_snapshot("invalid stat count")
        counters[key] = count

    return policies, reports, failures, counters
