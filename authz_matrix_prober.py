"""Authorization matrix probing: role/endpoint cartesian product, sharded progress, rate budget."""

from __future__ import annotations

import copy
import hashlib
import threading
import time
from collections.abc import Mapping
from dataclasses import asdict, dataclass
from datetime import date, datetime


_VERDICTS = ("denied", "granted", "exceeded", "review", "invalid")
_SNAPSHOT_VERSION = 1
_SUMMARY_LIMIT = 120
_BLOCK_STATUS_CODES = {423, 429}
_BLOCK_MARKERS = (
    "blocked",
    "banned",
    "suspended",
    "account disabled",
    "account locked",
    "too many",
    "too many requests",
    "rate limit",
    "throttl",
    "concurr",
    "risk control",
    "封禁",
    "风控",
    "拦截",
    "限流",
)


class MatrixError(ValueError):
    """Raised when a matrix operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Endpoint:
    method: str
    path: str
    domain: str
    resource_kind: str
    write: bool


@dataclass(frozen=True)
class Role:
    name: str
    account_id: str
    write_allowed: bool


@dataclass(frozen=True)
class MatrixEntry:
    index: int
    fingerprint: str
    method: str
    path: str
    domain: str
    role: str
    account_id: str
    expectation: str
    marker: str
    write: bool

    @property
    def headers(self) -> dict:
        """Request headers carrying the marker used by the target audit log."""

        return {"X-Probe-Marker": self.marker}


@dataclass(frozen=True)
class ProbeResult:
    index: int
    fingerprint: str
    verdict: str
    status_code: int
    evidence: dict


class AuthzMatrixProber:
    """Compose an authorization probe matrix and run it in resumable shards."""

    def __init__(self, *, executor=None, max_entries: int = 500,
                 rate_per_minute: int = 60, clock=None) -> None:
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 0:
            raise MatrixError("MATRIX_INVALID_REQUEST",
                              "max_entries must be a non-negative integer")
        if isinstance(rate_per_minute, bool) or not isinstance(rate_per_minute, int) \
                or rate_per_minute < 0:
            raise MatrixError("MATRIX_INVALID_REQUEST",
                              "rate_per_minute must be a non-negative integer")

        self.executor = executor
        self.max_entries = max_entries
        self.rate_per_minute = rate_per_minute
        self._clock = clock

        self._lock = threading.Lock()
        self._domain_locks: dict[str, threading.Lock] = {}

        self._endpoints: list[Endpoint] = []
        self._endpoint_keys: set[tuple[str, str, str]] = set()
        self._roles: list[Role] = []
        self._role_index: dict[str, int] = {}
        self._deduped = 0
        self._catalog_dirty = True
        self._built = False

        self._entries: list[MatrixEntry] = []
        self._results: dict[int, ProbeResult] = {}
        self._claimed: set[int] = set()
        self._shards: dict[int, int] = {}
        self._status = "pending"
        self._paused_reason: str | None = None

        self._blocked_roles: set[str] = set()
        self._block_evidence: dict[str, tuple[int, str]] = {}
        self._marker_fingerprints: dict[str, str] = {}

        self._rate_budgets: dict[str, int] = {}
        self._domain_usage: dict[str, tuple[int, int]] = {}
        self._rate_paused_domains: set[str] = set()
        self._rate_resume_domains: set[str] = set()

    @staticmethod
    def _fingerprint(method: str, path: str, role: str) -> str:
        raw = "{} {} {}".format(method.upper(), path, role).encode("utf-8")
        return hashlib.sha256(raw).hexdigest()[:16]

    @staticmethod
    def _truncate_summary(value: object) -> str:
        if value is None:
            return ""
        return str(value)[:_SUMMARY_LIMIT]

    @staticmethod
    def _timestamp(value: object) -> float:
        if isinstance(value, datetime):
            return value.timestamp()
        if isinstance(value, date):
            return datetime(value.year, value.month, value.day).timestamp()
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            text = value.strip()
            try:
                return float(text)
            except ValueError:
                pass
            try:
                return datetime.fromisoformat(text.replace("Z", "+00:00")).timestamp()
            except ValueError:
                pass
        timestamp = getattr(value, "timestamp", None)
        if callable(timestamp):
            result = timestamp()
            if isinstance(result, (int, float)):
                return float(result)
        return time.monotonic()

    def _now(self, now: object = None) -> float:
        if now is not None:
            return self._timestamp(now)
        if self._clock is not None:
            value = self._clock() if callable(self._clock) else self._clock
            return self._timestamp(value)
        return time.time()

    def _domain_lock(self, domain: str) -> threading.Lock:
        with self._lock:
            lock = self._domain_locks.get(domain)
            if lock is None:
                lock = threading.Lock()
                self._domain_locks[domain] = lock
            return lock

    def _domain_locks_snapshot(self) -> list[tuple[str, threading.Lock]]:
        with self._lock:
            return sorted(self._domain_locks.items())

    @staticmethod
    def _raise_invalid(detail: object) -> None:
        raise MatrixError("MATRIX_INVALID_REQUEST", detail)

    def register_endpoint(self, method: str, path: str, *, domain: str,
                          resource_kind: str = "own", write: bool = False) -> Endpoint:
        if not isinstance(method, str) or not method.strip():
            self._raise_invalid("method is required")
        if not isinstance(path, str) or not path.strip():
            self._raise_invalid("path is required")
        if not isinstance(domain, str) or not domain.strip():
            self._raise_invalid("domain is required")
        if not isinstance(resource_kind, str) or not resource_kind.strip():
            self._raise_invalid("resource_kind is required")

        normalized_method = method.strip().upper()
        endpoint = Endpoint(
            method=normalized_method,
            path=path,
            domain=domain,
            resource_kind=resource_kind,
            write=bool(write),
        )
        key = (normalized_method, path, domain)
        with self._lock:
            if key in self._endpoint_keys:
                self._deduped += 1
                for existing in self._endpoints:
                    if (existing.method, existing.path, existing.domain) == key:
                        return existing

            self._endpoints.append(endpoint)
            self._endpoint_keys.add(key)
            self._catalog_dirty = True
            if domain not in self._domain_locks:
                self._domain_locks[domain] = threading.Lock()
            return endpoint

    def register_role(self, name: str, account_id: str, *,
                      write_allowed: bool = False) -> Role:
        if not isinstance(name, str) or not name.strip():
            self._raise_invalid("role name is required")
        if not isinstance(account_id, str) or not account_id.strip():
            self._raise_invalid("account_id is required")

        role = Role(name=name, account_id=account_id, write_allowed=bool(write_allowed))
        with self._lock:
            index = self._role_index.get(name)
            if index is None:
                self._role_index[name] = len(self._roles)
                self._roles.append(role)
            else:
                self._roles[index] = role
            self._catalog_dirty = True
            return role

    def build_matrix(self) -> list:
        with self._lock:
            if self._built and not self._catalog_dirty:
                return list(self._entries)

            if not self._endpoints or not self._roles:
                self._raise_invalid("at least one endpoint and one role are required")

            total = len(self._endpoints) * len(self._roles)
            if total > self.max_entries:
                raise MatrixError(
                    "MATRIX_CAPACITY_EXCEEDED",
                    "matrix requires {} entries but max_entries is {}".format(
                        total, self.max_entries
                    ),
                )

            entries: list[MatrixEntry] = []
            marker_fingerprints: dict[str, str] = {}
            index = 0
            for endpoint in self._endpoints:
                for role in self._roles:
                    fingerprint = self._fingerprint(endpoint.method, endpoint.path, role.name)
                    marker = "MK-{}-{:04d}".format(fingerprint[:8], index)
                    expectation = "deny" if endpoint.write and not role.write_allowed else "allow"
                    entry = MatrixEntry(
                        index=index,
                        fingerprint=fingerprint,
                        method=endpoint.method,
                        path=endpoint.path,
                        domain=endpoint.domain,
                        role=role.name,
                        account_id=role.account_id,
                        expectation=expectation,
                        marker=marker,
                        write=endpoint.write,
                    )
                    entries.append(entry)
                    marker_fingerprints[marker] = fingerprint
                    index += 1

            if entries != self._entries:
                self._entries = entries
                self._results = {}
                self._claimed.clear()
                self._shards = {}
                self._status = "pending"
                self._paused_reason = None
                self._blocked_roles.clear()
                self._block_evidence.clear()
                self._domain_usage.clear()
                self._rate_paused_domains.clear()
                self._rate_resume_domains.clear()
            self._marker_fingerprints = marker_fingerprints
            self._built = True
            self._catalog_dirty = False
            return list(self._entries)

    @staticmethod
    def _normalize_status(raw_status: object) -> int:
        try:
            return int(raw_status)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _is_block_response(status_code: int, summary: str) -> bool:
        if status_code in _BLOCK_STATUS_CODES:
            return True
        if 200 <= status_code < 300:
            return False
        folded = summary.casefold()
        return any(marker in folded for marker in _BLOCK_MARKERS)

    def _record_blocked_roles_locked(self, entry: MatrixEntry,
                                     status_code: int, summary: str) -> None:
        for candidate in self._entries:
            if candidate.account_id == entry.account_id:
                self._blocked_roles.add(candidate.role)
                self._block_evidence.setdefault(
                    candidate.role, (status_code, summary)
                )

    def _block_evidence_for_locked(self, role: str) -> tuple[int, str]:
        return self._block_evidence.get(role, (0, "role blocked by target risk control"))

    def _add_result_locked(self, entry: MatrixEntry, verdict: str, status_code: int,
                           evidence: dict, shard_index: int) -> ProbeResult:
        result = ProbeResult(
            index=entry.index,
            fingerprint=entry.fingerprint,
            verdict=verdict,
            status_code=status_code,
            evidence=copy.deepcopy(evidence),
        )
        self._results[entry.index] = result
        self._shards[shard_index] = self._shards.get(shard_index, 0) + 1
        if len(self._results) == len(self._entries):
            self._status = "completed"
            self._paused_reason = None
        return result

    def _resolve_404_controls_locked(self) -> None:
        existing_keys: set[tuple[str, str, str]] = set()
        for index, result in self._results.items():
            if 200 <= result.status_code < 300:
                entry = self._entries[index]
                existing_keys.add((entry.method, entry.path, entry.domain))

        if not existing_keys:
            return
        for index, result in list(self._results.items()):
            entry = self._entries[index]
            key = (entry.method, entry.path, entry.domain)
            if result.status_code == 404 and result.verdict == "review" and key in existing_keys:
                self._results[index] = ProbeResult(
                    index=result.index,
                    fingerprint=result.fingerprint,
                    verdict="denied",
                    status_code=result.status_code,
                    evidence=copy.deepcopy(result.evidence),
                )

    def _rate_allows_locked(self, domain: str, now: object) -> bool:
        limit = self._rate_budgets.get(domain, self.rate_per_minute)
        if limit <= 0:
            return False
        moment = self._now(now)
        window = int(moment // 60)
        previous = self._domain_usage.get(domain)
        used = 0 if previous is None or previous[0] != window else previous[1]
        if used >= limit:
            return False
        self._domain_usage[domain] = (window, used + 1)
        return True

    def run_shard(self, shard_index: int, shard_count: int, *, now=None) -> dict:
        if isinstance(shard_count, bool) or not isinstance(shard_count, int) or shard_count < 1:
            raise MatrixError("MATRIX_SHARD_INVALID", "shard_count must be at least 1")
        if isinstance(shard_index, bool) or not isinstance(shard_index, int) \
                or shard_index < 0 or shard_index >= shard_count:
            raise MatrixError("MATRIX_SHARD_INVALID", "shard_index is outside the shard range")
        if self.executor is None:
            self._raise_invalid("an executor is required")

        with self._lock:
            built = self._built
        if not built:
            self.build_matrix()

        with self._lock:
            if self._status == "paused":
                raise MatrixError("MATRIX_PAUSED", self._paused_reason)
            entries = list(self._entries)
            if self._status == "pending":
                self._status = "running"
            bypass_domains = set(self._rate_resume_domains)
            self._rate_resume_domains.clear()

        target = [entry for entry in entries if entry.index % shard_count == shard_index]
        produced: list[ProbeResult] = []

        for entry in target:
            domain_lock = self._domain_lock(entry.domain)
            execute = False
            with domain_lock:
                with self._lock:
                    if self._status == "paused":
                        break
                    if entry.index in self._results or entry.index in self._claimed:
                        continue
                    if entry.role in self._blocked_roles:
                        status_code, summary = self._block_evidence_for_locked(entry.role)
                        produced.append(
                            self._add_result_locked(
                                entry,
                                "invalid",
                                status_code,
                                {"status_code": status_code, "summary": summary},
                                shard_index,
                            )
                        )
                        continue
                    if entry.domain not in bypass_domains \
                            and not self._rate_allows_locked(entry.domain, now):
                        self._status = "paused"
                        self._paused_reason = "rate_budget"
                        self._rate_paused_domains.add(entry.domain)
                        break
                    self._claimed.add(entry.index)
                    execute = True

            if not execute:
                continue

            try:
                response = self.executor(entry)
                if not isinstance(response, (tuple, list)) or len(response) != 2:
                    raise ValueError("executor must return (status_code, body)")
                raw_status, body = response
            except Exception as exc:
                raw_status = 0
                body = {"summary": "executor error: {}".format(type(exc).__name__)}

            status_code = self._normalize_status(raw_status)
            if isinstance(body, Mapping):
                owner = body.get("resource_owner")
                summary = self._truncate_summary(body.get("summary"))
            else:
                owner = None
                summary = ""

            verdict = self._is_block_response(status_code, summary)
            if verdict:
                final_verdict = "invalid"
            elif status_code in (401, 403):
                final_verdict = "denied"
            elif 200 <= status_code < 300:
                final_verdict = "granted" if owner == entry.account_id else "exceeded"
            else:
                final_verdict = "review"
            evidence = {"status_code": status_code, "summary": summary}

            with domain_lock:
                with self._lock:
                    self._claimed.discard(entry.index)
                    if entry.index in self._results:
                        continue

                    if entry.role in self._blocked_roles and final_verdict != "invalid":
                        final_verdict = "invalid"
                        status_code, summary = self._block_evidence_for_locked(entry.role)
                        evidence = {"status_code": status_code, "summary": summary}

                    if final_verdict == "invalid":
                        self._record_blocked_roles_locked(
                            entry, status_code, evidence["summary"]
                        )

                    produced.append(
                        self._add_result_locked(
                            entry, final_verdict, status_code, evidence, shard_index
                        )
                    )
                    if self._status not in ("completed", "paused"):
                        self._status = "running"

        with self._lock:
            self._resolve_404_controls_locked()
            if len(self._results) == len(self._entries):
                self._status = "completed"
                self._paused_reason = None
            elif self._status != "paused":
                self._status = "running"
            status = self._status
            produced = sorted(
                (self._results[result.index] for result in produced),
                key=lambda result: result.index,
            )
        return {
            "executed": len(produced),
            "status": status,
            "results": produced,
        }

    def pause(self, reason: str) -> None:
        with self._lock:
            self._status = "paused"
            self._paused_reason = reason
            self._rate_paused_domains.clear()

    def resume(self, now=None) -> dict:
        domain_locks = self._domain_locks_snapshot()
        for _, lock in domain_locks:
            lock.acquire()
        try:
            with self._lock:
                if self._status == "paused":
                    was_rate_pause = self._paused_reason == "rate_budget"
                    self._paused_reason = None
                    if was_rate_pause:
                        for domain in self._rate_paused_domains:
                            self._domain_usage.pop(domain, None)
                        self._rate_resume_domains.update(self._rate_paused_domains)
                        self._rate_paused_domains.clear()
                    if self._entries and len(self._results) == len(self._entries):
                        self._status = "completed"
                    else:
                        self._status = "running"
                status = self._status
                completed = len(self._results)
        finally:
            for _, lock in reversed(domain_locks):
                lock.release()
        return {"status": status, "completed": completed}

    def progress(self) -> dict:
        with self._lock:
            return {
                "status": self._status,
                "completed": len(self._results),
                "paused_reason": self._paused_reason,
                "shards": dict(sorted(self._shards.items())),
            }

    def report(self) -> dict:
        with self._lock:
            counts = {verdict: 0 for verdict in _VERDICTS}
            for result in self._results.values():
                if result.verdict in counts:
                    counts[result.verdict] += 1
            return {
                "total": len(self._entries),
                "executed": len(self._results),
                "deduped": self._deduped,
                "verdicts": counts,
                "blocked_roles": sorted(self._blocked_roles),
            }

    def blocked_roles(self) -> tuple:
        with self._lock:
            return tuple(sorted(self._blocked_roles))

    def set_rate_budget(self, domain: str, per_minute: int) -> None:
        if not isinstance(domain, str) or not domain.strip():
            self._raise_invalid("domain is required")
        if isinstance(per_minute, bool) or not isinstance(per_minute, int) or per_minute < 0:
            self._raise_invalid("per_minute must be a non-negative integer")
        domain_lock = self._domain_lock(domain)
        with domain_lock:
            with self._lock:
                self._rate_budgets[domain] = per_minute

    @staticmethod
    def _snapshot_invalid(detail: object) -> None:
        raise MatrixError("MATRIX_SNAPSHOT_INVALID", detail)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "endpoints": [copy.deepcopy(asdict(endpoint)) for endpoint in self._endpoints],
                "roles": [copy.deepcopy(asdict(role)) for role in self._roles],
                "entries": [copy.deepcopy(asdict(entry)) for entry in self._entries],
                "results": [
                    copy.deepcopy(asdict(self._results[index]))
                    for index in sorted(self._results)
                ],
                "deduped": self._deduped,
                "shards": dict(sorted(self._shards.items())),
            }

    @staticmethod
    def _require_mapping(value: object) -> dict:
        if not isinstance(value, dict):
            AuthzMatrixProber._snapshot_invalid("expected an object")
        return value

    @staticmethod
    def _require_string(mapping: dict, key: str) -> str:
        value = mapping.get(key)
        if not isinstance(value, str) or not value:
            AuthzMatrixProber._snapshot_invalid("invalid {!r}".format(key))
        return value

    @staticmethod
    def _require_int(mapping: dict, key: str) -> int:
        value = mapping.get(key)
        if isinstance(value, bool) or not isinstance(value, int):
            AuthzMatrixProber._snapshot_invalid("invalid {!r}".format(key))
        return value

    @staticmethod
    def _require_bool(mapping: dict, key: str) -> bool:
        value = mapping.get(key)
        if not isinstance(value, bool):
            AuthzMatrixProber._snapshot_invalid("invalid {!r}".format(key))
        return value

    def restore(self, state: dict) -> None:
        if not isinstance(state, dict):
            self._snapshot_invalid("snapshot must be an object")
        required = {"version", "endpoints", "roles", "entries",
                    "results", "deduped", "shards"}
        if not required.issubset(state):
            self._snapshot_invalid("snapshot is missing required keys")
        version = state.get("version")
        if isinstance(version, bool) or not isinstance(version, int) \
                or version != _SNAPSHOT_VERSION:
            self._snapshot_invalid("unsupported snapshot version")
        if not isinstance(state.get("endpoints"), list):
            self._snapshot_invalid("endpoints must be a list")
        if not isinstance(state.get("roles"), list):
            self._snapshot_invalid("roles must be a list")
        if not isinstance(state.get("entries"), list):
            self._snapshot_invalid("entries must be a list")
        if not isinstance(state.get("results"), list):
            self._snapshot_invalid("results must be a list")
        deduped = state.get("deduped")
        if isinstance(deduped, bool) or not isinstance(deduped, int) or deduped < 0:
            self._snapshot_invalid("deduped must be a non-negative integer")
        raw_shards = state.get("shards")
        if not isinstance(raw_shards, dict):
            self._snapshot_invalid("shards must be an object")

        endpoints: list[Endpoint] = []
        for item in state["endpoints"]:
            data = self._require_mapping(item)
            endpoints.append(
                Endpoint(
                    method=self._require_string(data, "method"),
                    path=self._require_string(data, "path"),
                    domain=self._require_string(data, "domain"),
                    resource_kind=self._require_string(data, "resource_kind"),
                    write=self._require_bool(data, "write"),
                )
            )

        roles: list[Role] = []
        role_index: dict[str, int] = {}
        for item in state["roles"]:
            data = self._require_mapping(item)
            role = Role(
                name=self._require_string(data, "name"),
                account_id=self._require_string(data, "account_id"),
                write_allowed=self._require_bool(data, "write_allowed"),
            )
            if role.name in role_index:
                self._snapshot_invalid("duplicate role name")
            role_index[role.name] = len(roles)
            roles.append(role)

        entries: list[MatrixEntry] = []
        marker_fingerprints: dict[str, str] = {}
        seen_markers: set[str] = set()
        for expected_index, item in enumerate(state["entries"]):
            data = self._require_mapping(item)
            entry = MatrixEntry(
                index=self._require_int(data, "index"),
                fingerprint=self._require_string(data, "fingerprint"),
                method=self._require_string(data, "method"),
                path=self._require_string(data, "path"),
                domain=self._require_string(data, "domain"),
                role=self._require_string(data, "role"),
                account_id=self._require_string(data, "account_id"),
                expectation=self._require_string(data, "expectation"),
                marker=self._require_string(data, "marker"),
                write=self._require_bool(data, "write"),
            )
            if entry.index != expected_index:
                self._snapshot_invalid("entry indexes must be contiguous")
            if entry.expectation not in ("allow", "deny"):
                self._snapshot_invalid("invalid entry expectation")
            if len(entry.fingerprint) != 16:
                self._snapshot_invalid("invalid entry fingerprint")
            if entry.marker in seen_markers:
                self._snapshot_invalid("duplicate entry marker")
            seen_markers.add(entry.marker)
            marker_fingerprints[entry.marker] = entry.fingerprint
            entries.append(entry)

        results: dict[int, ProbeResult] = {}
        for item in state["results"]:
            data = self._require_mapping(item)
            index = self._require_int(data, "index")
            fingerprint = self._require_string(data, "fingerprint")
            verdict = self._require_string(data, "verdict")
            status_code = self._require_int(data, "status_code")
            evidence_data = self._require_mapping(data.get("evidence"))
            evidence_status = self._require_int(evidence_data, "status_code")
            summary = evidence_data.get("summary")
            if not isinstance(summary, str):
                self._snapshot_invalid("evidence summary must be a string")
            if len(summary) > _SUMMARY_LIMIT:
                self._snapshot_invalid("evidence summary is too long")
            if evidence_status != status_code:
                self._snapshot_invalid("evidence status does not match result status")
            if verdict not in _VERDICTS:
                self._snapshot_invalid("invalid verdict")
            if index < 0 or index >= len(entries):
                self._snapshot_invalid("result index is outside the matrix")
            if index in results:
                self._snapshot_invalid("duplicate result index")
            if entries[index].fingerprint != fingerprint:
                self._snapshot_invalid("result fingerprint does not match entry")
            results[index] = ProbeResult(
                index=index,
                fingerprint=fingerprint,
                verdict=verdict,
                status_code=status_code,
                evidence={"status_code": evidence_status, "summary": summary},
            )

        shards: dict[int, int] = {}
        for raw_key, raw_value in raw_shards.items():
            if isinstance(raw_key, bool):
                self._snapshot_invalid("invalid shard index")
            if isinstance(raw_key, int):
                key = raw_key
            elif isinstance(raw_key, str):
                try:
                    key = int(raw_key)
                except ValueError:
                    self._snapshot_invalid("invalid shard index")
            else:
                self._snapshot_invalid("invalid shard index")
            if key < 0 or isinstance(raw_value, bool) or not isinstance(raw_value, int) \
                    or raw_value < 0:
                self._snapshot_invalid("invalid shard count")
            shards[key] = raw_value

        blocked_roles: set[str] = set()
        block_evidence: dict[str, tuple[int, str]] = {}
        for result in results.values():
            if result.verdict != "invalid":
                continue
            entry = entries[result.index]
            blocked_roles.add(entry.role)
            block_evidence.setdefault(
                entry.role, (result.status_code, result.evidence.get("summary", ""))
            )
            for candidate in entries:
                if candidate.account_id == entry.account_id:
                    blocked_roles.add(candidate.role)
                    block_evidence.setdefault(
                        candidate.role,
                        (result.status_code, result.evidence.get("summary", "")),
                    )

        endpoint_keys = {(entry.method, entry.path, entry.domain) for entry in endpoints}
        new_status = "pending"
        if entries and len(results) == len(entries):
            new_status = "completed"
        elif results:
            new_status = "running"

        domain_locks = self._domain_locks_snapshot()
        for _, lock in domain_locks:
            lock.acquire()
        try:
            with self._lock:
                for domain in endpoint_keys:
                    self._domain_locks.setdefault(domain, threading.Lock())
                self._endpoints = endpoints
                self._endpoint_keys = endpoint_keys
                self._roles = roles
                self._role_index = role_index
                self._deduped = deduped
                self._entries = entries
                self._results = results
                self._claimed.clear()
                self._shards = shards
                self._status = new_status
                self._paused_reason = None
                self._blocked_roles = blocked_roles
                self._block_evidence = block_evidence
                self._marker_fingerprints = marker_fingerprints
                self._domain_usage.clear()
                self._rate_paused_domains.clear()
                self._rate_resume_domains.clear()
                self._catalog_dirty = False
                self._built = bool(entries)
        finally:
            for _, lock in reversed(domain_locks):
                lock.release()
