"""Inbound DMARC record parsing, policy caching and message evaluation."""

from __future__ import annotations

import copy
import hashlib
import threading
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


_POLICY_VALUES = frozenset({"none", "quarantine", "reject"})
_ALIGNMENT_VALUES = frozenset({"r", "s"})
_DISPOSITIONS = ("none", "quarantine", "reject")
_RESULT_KEYS = ("pass", "fail", "none")
_STAT_KEYS = (
    "evaluations",
    "policy_hits",
    "policy_misses",
    "resolver_calls",
    "invalidated",
    "purged",
)
_DEFAULT_ORG_SUFFIXES = ("co.uk", "com.cn", "com.au", "co.jp")


class DmarcError(ValueError):
    """Raised when a record, request or snapshot is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class DmarcPolicy:
    domain: str
    p: str
    sp: str
    pct: int
    adkim: str
    aspf: str
    rua: tuple[str, ...]


@dataclass(frozen=True)
class DmarcResult:
    from_domain: str
    dkim_domain: str | None
    spf_domain: str | None
    dkim_aligned: bool
    spf_aligned: bool
    result: str
    disposition: str
    policy_source: str
    sampled: bool


@dataclass(frozen=True)
class _CacheEntry:
    policy: DmarcPolicy | None
    expires_at: datetime


def _normalize_domain(domain: object) -> str:
    if not isinstance(domain, str):
        return ""
    return domain.strip().lower().rstrip(".")


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str):
        raise DmarcError("DMARC_INVALID_TIME", value)
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise DmarcError("DMARC_INVALID_TIME", value) from exc
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise DmarcError("DMARC_INVALID_TIME", value)
    return parsed


def _empty_counts() -> dict:
    return {
        "total": 0,
        "pass": 0,
        "fail": 0,
        "none": 0,
        "by_disposition": {name: 0 for name in _DISPOSITIONS},
    }


def _valid_count(value: object) -> bool:
    return type(value) is int and value >= 0


class DmarcPolicyEvaluator:
    """Evaluate DMARC alignment and disposition for inbound messages."""

    def __init__(self, *, resolver=None, cache_ttl: int = 300,
                 negative_ttl: int = 60, sample_salt: str = "dmarc-v1",
                 max_cache: int = 256, org_suffixes=None) -> None:
        self.resolver = resolver
        self.cache_ttl = cache_ttl
        self.negative_ttl = negative_ttl
        self.sample_salt = sample_salt
        self.max_cache = max_cache
        suffixes = org_suffixes or _DEFAULT_ORG_SUFFIXES
        self.org_suffixes = tuple(
            suffix for suffix in (_normalize_domain(item) for item in suffixes)
            if suffix
        )
        self._lock = threading.RLock()
        self._cache: OrderedDict[str, _CacheEntry] = OrderedDict()
        self._aggregates: dict[str, dict] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

    def parse_record(self, domain: str, record_text: str) -> DmarcPolicy:
        normalized_domain = _normalize_domain(domain)
        if not normalized_domain:
            raise DmarcError("DMARC_INVALID_RECORD", "missing domain")
        if not isinstance(record_text, str):
            raise DmarcError("DMARC_INVALID_RECORD", record_text)

        tags: dict[str, str] = {}
        rua_values: set[str] = set()
        for part in record_text.split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" not in part:
                raise DmarcError("DMARC_INVALID_RECORD", part)
            name, value = part.split("=", 1)
            name = name.strip().lower()
            value = value.strip()
            if not name:
                raise DmarcError("DMARC_INVALID_RECORD", part)
            if name == "rua":
                rua_values.update(
                    item.strip() for item in value.split(",") if item.strip()
                )
            elif name in {"v", "p", "sp", "pct", "adkim", "aspf"}:
                tags[name] = value

        if tags.get("v") != "DMARC1":
            raise DmarcError("DMARC_INVALID_RECORD", "invalid or missing v")

        policy_value = tags.get("p", "none").strip()
        sp_value = tags.get("sp", "inherit").strip()
        if policy_value not in _POLICY_VALUES:
            raise DmarcError("DMARC_INVALID_RECORD", "invalid p")
        if sp_value != "inherit" and sp_value not in _POLICY_VALUES:
            raise DmarcError("DMARC_INVALID_RECORD", "invalid sp")

        pct_text = tags.get("pct", "100").strip()
        if not pct_text.isdigit():
            raise DmarcError("DMARC_INVALID_RECORD", "invalid pct")
        try:
            pct = int(pct_text)
        except ValueError as exc:
            raise DmarcError("DMARC_INVALID_RECORD", "invalid pct") from exc
        if not 0 <= pct <= 100:
            raise DmarcError("DMARC_INVALID_RECORD", "pct out of range")

        adkim = tags.get("adkim", "r").strip()
        aspf = tags.get("aspf", "r").strip()
        if adkim not in _ALIGNMENT_VALUES:
            raise DmarcError("DMARC_INVALID_RECORD", "invalid adkim")
        if aspf not in _ALIGNMENT_VALUES:
            raise DmarcError("DMARC_INVALID_RECORD", "invalid aspf")

        return DmarcPolicy(
            domain=normalized_domain,
            p=policy_value,
            sp=sp_value,
            pct=pct,
            adkim=adkim,
            aspf=aspf,
            rua=tuple(sorted(rua_values)),
        )

    def organizational_domain(self, domain: str) -> str:
        normalized = _normalize_domain(domain)
        labels = [label for label in normalized.split(".") if label]
        if not labels:
            return ""
        for suffix in self.org_suffixes:
            suffix_labels = suffix.split(".")
            if len(labels) >= len(suffix_labels):
                if labels[-len(suffix_labels):] == suffix_labels:
                    return ".".join(labels[-3:])
        return ".".join(labels[-2:])

    def cache_policy(self, domain: str, record_text: str, *, now: str) -> DmarcPolicy:
        policy = self.parse_record(domain, record_text)
        current = _parse_time(now)
        entry = _CacheEntry(
            policy=policy,
            expires_at=current + timedelta(seconds=self.cache_ttl),
        )
        with self._lock:
            self._store_entry_locked(policy.domain, entry)
        return policy

    def policy_for(self, domain: str, *, now: str) -> DmarcPolicy | None:
        normalized_domain = _normalize_domain(domain)
        current = _parse_time(now)
        with self._lock:
            return self._policy_for_locked(normalized_domain, current)

    def _policy_for_locked(
        self, domain: str, current: datetime
    ) -> DmarcPolicy | None:
        entry = self._cache.get(domain)
        if entry is not None:
            if current < entry.expires_at:
                self._cache.move_to_end(domain)
                if entry.policy is not None:
                    self._stats["policy_hits"] += 1
                else:
                    self._stats["policy_misses"] += 1
                return entry.policy
            del self._cache[domain]

        record = None
        if self.resolver is not None:
            self._stats["resolver_calls"] += 1
            record = self.resolver(domain)

        if record is None:
            policy = None
            expires_at = current + timedelta(seconds=self.negative_ttl)
            self._stats["policy_misses"] += 1
        else:
            policy = self.parse_record(domain, record)
            expires_at = current + timedelta(seconds=self.cache_ttl)
            self._stats["policy_hits"] += 1

        self._store_entry_locked(
            domain,
            _CacheEntry(policy=policy, expires_at=expires_at),
        )
        return policy

    def _store_entry_locked(self, domain: str, entry: _CacheEntry) -> None:
        self._cache.pop(domain, None)
        if self.max_cache > 0:
            self._cache[domain] = entry
            while len(self._cache) > self.max_cache:
                self._cache.popitem(last=False)

    def invalidate(self, domain: str) -> bool:
        normalized_domain = _normalize_domain(domain)
        with self._lock:
            if normalized_domain not in self._cache:
                return False
            del self._cache[normalized_domain]
            self._stats["invalidated"] += 1
            return True

    def purge_expired(self, *, now: str) -> int:
        current = _parse_time(now)
        with self._lock:
            expired = [
                domain
                for domain, entry in self._cache.items()
                if entry.expires_at <= current
            ]
            for domain in expired:
                del self._cache[domain]
            self._stats["purged"] += len(expired)
            return len(expired)

    def evaluate(self, message: dict, *, now: str | None = None) -> DmarcResult:
        current = _parse_time(
            now if now is not None else datetime.now(timezone.utc).isoformat()
        )
        if not isinstance(message, Mapping):
            raise DmarcError("DMARC_INVALID_MESSAGE", message)

        from_domain = _normalize_domain(message.get("from_domain"))
        dkim_value = message.get("dkim_domain")
        spf_value = message.get("spf_domain")
        dkim_domain = None if dkim_value is None else _normalize_domain(dkim_value)
        spf_domain = None if spf_value is None else _normalize_domain(spf_value)
        message_id = message.get("message_id", "")

        with self._lock:
            self._stats["evaluations"] += 1
            policy = self._policy_for_locked(from_domain, current)
            policy_source = "own" if policy is not None else "none"

            if policy is None:
                org_domain = self.organizational_domain(from_domain)
                if org_domain and org_domain != from_domain:
                    policy = self._policy_for_locked(org_domain, current)
                    if policy is not None:
                        policy_source = "org"

            dkim_aligned = self._aligned(
                from_domain, dkim_domain, policy.adkim if policy else "r"
            )
            spf_aligned = self._aligned(
                from_domain, spf_domain, policy.aspf if policy else "r"
            )

            sampled = False
            if policy is None:
                result = "none"
                disposition = "none"
                report_domain = from_domain
            else:
                sampled = self._sampled(
                    from_domain, message_id, policy.domain, policy.pct
                )
                if dkim_aligned or spf_aligned:
                    result = "pass"
                    disposition = "none"
                else:
                    result = "fail"
                    if not sampled:
                        disposition = "none"
                    elif policy_source == "org" and from_domain != policy.domain:
                        disposition = (
                            policy.p if policy.sp == "inherit" else policy.sp
                        )
                    else:
                        disposition = policy.p
                report_domain = policy.domain

            self._record_aggregate_locked(report_domain, result, disposition)
            return DmarcResult(
                from_domain=from_domain,
                dkim_domain=dkim_domain,
                spf_domain=spf_domain,
                dkim_aligned=dkim_aligned,
                spf_aligned=spf_aligned,
                result=result,
                disposition=disposition,
                policy_source=policy_source,
                sampled=sampled,
            )

    def _aligned(
        self, from_domain: str, auth_domain: str | None, mode: str
    ) -> bool:
        if not from_domain or auth_domain is None or not auth_domain:
            return False
        if mode == "s":
            return auth_domain == from_domain
        return (
            self.organizational_domain(auth_domain)
            == self.organizational_domain(from_domain)
        )

    def _sampled(
        self, from_domain: str, message_id: object, policy_domain: str, pct: int
    ) -> bool:
        if pct <= 0:
            return False
        if pct >= 100:
            return True
        key = "|".join(
            (str(self.sample_salt), from_domain, str(message_id), policy_domain)
        )
        digest = hashlib.sha256(key.encode("utf-8")).digest()
        bucket = int.from_bytes(digest, "big") % 100
        return bucket < pct

    def _record_aggregate_locked(
        self, domain: str, result: str, disposition: str
    ) -> None:
        counts = self._aggregates.setdefault(domain, _empty_counts())
        counts["total"] += 1
        counts[result] += 1
        counts["by_disposition"][disposition] += 1

    def report_aggregate(self, *, domain: str | None = None) -> dict:
        with self._lock:
            return self._report_locked(domain)

    def _report_locked(self, domain: str | None = None) -> dict:
        normalized_domain = _normalize_domain(domain) if domain is not None else ""
        if normalized_domain:
            counts = self._aggregates.get(normalized_domain)
            return copy.deepcopy(counts) if counts is not None else _empty_counts()

        total = _empty_counts()
        domains: dict[str, dict] = {}
        for name, counts in self._aggregates.items():
            subtotal = copy.deepcopy(counts)
            domains[name] = subtotal
            total["total"] += counts["total"]
            for key in _RESULT_KEYS:
                total[key] += counts[key]
            for key in _DISPOSITIONS:
                total["by_disposition"][key] += counts["by_disposition"][key]
        total["domains"] = domains
        return total

    def snapshot(self) -> dict:
        with self._lock:
            policies = {
                domain: {
                    "policy": (
                        None if entry.policy is None
                        else self._policy_to_dict(entry.policy)
                    ),
                    "expires_at": entry.expires_at.isoformat(),
                }
                for domain, entry in self._cache.items()
            }
            state = {
                "version": 1,
                "policies": policies,
                "aggregates": self._report_locked(),
                "stats": dict(self._stats),
            }
            return copy.deepcopy(state)

    @staticmethod
    def _policy_to_dict(policy: DmarcPolicy) -> dict:
        return {
            "domain": policy.domain,
            "p": policy.p,
            "sp": policy.sp,
            "pct": policy.pct,
            "adkim": policy.adkim,
            "aspf": policy.aspf,
            "rua": list(policy.rua),
        }

    def restore(self, state: dict) -> None:
        try:
            copied = copy.deepcopy(state)
            validated = self._validate_snapshot(copied)
        except DmarcError as exc:
            if exc.code == "DMARC_SNAPSHOT_INVALID":
                raise
            raise DmarcError("DMARC_SNAPSHOT_INVALID", exc.detail) from exc
        except Exception as exc:
            raise DmarcError("DMARC_SNAPSHOT_INVALID", repr(exc)) from exc

        with self._lock:
            self._cache = validated["cache"]
            self._aggregates = validated["aggregates"]
            self._stats = validated["stats"]

    def _validate_snapshot(self, state: object) -> dict:
        expected_keys = {"version", "policies", "aggregates", "stats"}
        if not isinstance(state, dict) or set(state) != expected_keys:
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid top-level structure")
        if type(state["version"]) is not int or state["version"] != 1:
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid version")

        policies_value = state["policies"]
        if not isinstance(policies_value, dict):
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid policies")
        cache: OrderedDict[str, _CacheEntry] = OrderedDict()
        for domain, raw_entry in policies_value.items():
            normalized_domain = _normalize_domain(domain)
            if (
                not isinstance(domain, str)
                or not normalized_domain
                or normalized_domain != domain
            ):
                raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid policy domain")
            if not isinstance(raw_entry, dict) or set(raw_entry) != {
                "policy", "expires_at"
            }:
                raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid policy entry")
            try:
                expires_at = _parse_time(raw_entry["expires_at"])
            except DmarcError as exc:
                raise DmarcError(
                    "DMARC_SNAPSHOT_INVALID", "invalid policy expiry"
                ) from exc

            raw_policy = raw_entry["policy"]
            if raw_policy is None:
                policy = None
            else:
                policy = self._policy_from_dict(raw_policy)
                if policy.domain != domain:
                    raise DmarcError(
                        "DMARC_SNAPSHOT_INVALID", "policy domain mismatch"
                    )
            cache[domain] = _CacheEntry(policy=policy, expires_at=expires_at)

        aggregates = self._aggregates_from_snapshot(state["aggregates"])
        stats = self._stats_from_snapshot(state["stats"])
        return {"cache": cache, "aggregates": aggregates, "stats": stats}

    def _policy_from_dict(self, value: object) -> DmarcPolicy:
        expected = {"domain", "p", "sp", "pct", "adkim", "aspf", "rua"}
        if not isinstance(value, dict) or set(value) != expected:
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid policy")

        domain = value["domain"]
        if (
            not isinstance(domain, str)
            or not domain
            or _normalize_domain(domain) != domain
        ):
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid policy domain")
        if value["p"] not in _POLICY_VALUES:
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid policy p")
        if value["sp"] != "inherit" and value["sp"] not in _POLICY_VALUES:
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid policy sp")
        if not _valid_count(value["pct"]) or value["pct"] > 100:
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid policy pct")
        if value["adkim"] not in _ALIGNMENT_VALUES:
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid policy adkim")
        if value["aspf"] not in _ALIGNMENT_VALUES:
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid policy aspf")
        if not isinstance(value["rua"], (list, tuple)) or any(
            not isinstance(item, str) for item in value["rua"]
        ):
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid policy rua")

        return DmarcPolicy(
            domain=domain,
            p=value["p"],
            sp=value["sp"],
            pct=value["pct"],
            adkim=value["adkim"],
            aspf=value["aspf"],
            rua=tuple(value["rua"]),
        )

    def _aggregates_from_snapshot(self, value: object) -> dict[str, dict]:
        expected = {
            "total", "pass", "fail", "none", "by_disposition", "domains"
        }
        if not isinstance(value, dict) or set(value) != expected:
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid aggregates")

        domains_value = value["domains"]
        if not isinstance(domains_value, dict):
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid aggregate domains")

        for key in ("total", *_RESULT_KEYS):
            if not _valid_count(value[key]):
                raise DmarcError(
                    "DMARC_SNAPSHOT_INVALID", "invalid aggregate total"
                )
        top_by_disposition = value["by_disposition"]
        if not isinstance(top_by_disposition, dict) or set(
            top_by_disposition
        ) != set(_DISPOSITIONS):
            raise DmarcError(
                "DMARC_SNAPSHOT_INVALID", "invalid aggregate dispositions"
            )
        for key in _DISPOSITIONS:
            if not _valid_count(top_by_disposition[key]):
                raise DmarcError(
                    "DMARC_SNAPSHOT_INVALID", "invalid disposition count"
                )

        aggregates: dict[str, dict] = {}
        aggregate_total = _empty_counts()
        for domain, raw_counts in domains_value.items():
            normalized_domain = _normalize_domain(domain)
            if (
                not isinstance(domain, str)
                or not normalized_domain
                or normalized_domain != domain
            ):
                raise DmarcError(
                    "DMARC_SNAPSHOT_INVALID", "invalid aggregate domain"
                )
            counts = self._counts_from_snapshot(raw_counts)
            aggregates[domain] = counts
            aggregate_total["total"] += counts["total"]
            for key in _RESULT_KEYS:
                aggregate_total[key] += counts[key]
            for key in _DISPOSITIONS:
                aggregate_total["by_disposition"][key] += (
                    counts["by_disposition"][key]
                )

        for key in ("total", *_RESULT_KEYS):
            if value[key] != aggregate_total[key]:
                raise DmarcError(
                    "DMARC_SNAPSHOT_INVALID", "aggregate total mismatch"
                )
        if top_by_disposition != aggregate_total["by_disposition"]:
            raise DmarcError(
                "DMARC_SNAPSHOT_INVALID", "aggregate disposition mismatch"
            )
        return aggregates

    def _counts_from_snapshot(self, value: object) -> dict:
        expected = {"total", "pass", "fail", "none", "by_disposition"}
        if not isinstance(value, dict) or set(value) != expected:
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid aggregate counts")
        for key in ("total", *_RESULT_KEYS):
            if not _valid_count(value[key]):
                raise DmarcError(
                    "DMARC_SNAPSHOT_INVALID", "invalid aggregate count"
                )
        by_disposition = value["by_disposition"]
        if not isinstance(by_disposition, dict) or set(by_disposition) != set(
            _DISPOSITIONS
        ):
            raise DmarcError(
                "DMARC_SNAPSHOT_INVALID", "invalid aggregate dispositions"
            )
        for key in _DISPOSITIONS:
            if not _valid_count(by_disposition[key]):
                raise DmarcError(
                    "DMARC_SNAPSHOT_INVALID", "invalid disposition count"
                )
        if value["total"] != sum(value[key] for key in _RESULT_KEYS):
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "aggregate result mismatch")
        if value["total"] != sum(by_disposition.values()):
            raise DmarcError(
                "DMARC_SNAPSHOT_INVALID", "aggregate disposition mismatch"
            )
        return copy.deepcopy(value)

    def _stats_from_snapshot(self, value: object) -> dict[str, int]:
        if not isinstance(value, dict) or set(value) != set(_STAT_KEYS):
            raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid stats")
        for key in _STAT_KEYS:
            if not _valid_count(value[key]):
                raise DmarcError("DMARC_SNAPSHOT_INVALID", "invalid stat")
        return {key: value[key] for key in _STAT_KEYS}

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
