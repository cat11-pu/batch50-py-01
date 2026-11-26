"""Bucket exposure scanner: ACL evaluation, anonymous probes, rescan ledger."""

from __future__ import annotations

import copy
import re
import threading
import time
from dataclasses import asdict, dataclass
from fnmatch import fnmatchcase
from typing import Any


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
    confirmed_at: int | float | None
    rescanned_at: int | float | None
    cached: bool = False


_BUCKET_NAME_RE = re.compile(r"[a-z0-9-]{3,63}\Z")
_READ_ACTION_NAMES = (
    "GetObject",
    "GetObjectAcl",
    "GetObjectAttributes",
    "GetObjectTagging",
    "ListBucket",
    "ListBucketVersions",
    "ListObjects",
    "ListObjectsV2",
)
_WRITE_ACTION_NAMES = (
    "PutObject",
    "PutObjectAcl",
    "PutObjectTagging",
    "DeleteObject",
    "DeleteObjects",
    "InitiateMultipartUpload",
    "UploadPart",
    "CompleteMultipartUpload",
    "AbortMultipartUpload",
)
_PUBLIC_GRANT_MARKERS = ("allusers", "anonymous")
_CONCLUSION_STATES = {
    "unknown",
    "candidate",
    "confirmed",
    "clean",
    "missing",
    "cooldown",
    "fixed",
    "failed",
}


def _valid_bucket_name(bucket: object) -> bool:
    return isinstance(bucket, str) and _BUCKET_NAME_RE.fullmatch(bucket) is not None


def _timestamp(now: int | float | None) -> int | float:
    if now is not None:
        return now
    return time.time()


def _optional_number(value: object) -> int | float | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return value
    return None


def _non_negative_int(value: object) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return value


def _is_public_principal(value: object) -> bool:
    if isinstance(value, str):
        return value == "*"
    if isinstance(value, (list, tuple, set)):
        return any(_is_public_principal(item) for item in value)
    if isinstance(value, dict):
        return any(_is_public_principal(item) for item in value.values())
    return False


def _action_capabilities(action: object) -> set[str]:
    text = str(action).strip()
    if not text:
        return set()
    normalized = text.lower()
    if normalized in {"*", "s3:*"}:
        return {"read", "write"}
    if normalized.startswith("s3:"):
        normalized = normalized[3:]

    capabilities: set[str] = set()
    for name in _READ_ACTION_NAMES:
        if fnmatchcase(name.lower(), normalized):
            capabilities.add("read")
            break
    for name in _WRITE_ACTION_NAMES:
        if fnmatchcase(name.lower(), normalized):
            capabilities.add("write")
            break

    if not capabilities:
        if normalized.startswith(("get", "list", "head", "describe")):
            capabilities.add("read")
        elif normalized.startswith(("put", "delete", "create", "update")):
            capabilities.add("write")
    return capabilities


def _new_capability_status() -> dict[str, str]:
    return {"read": "neutral", "write": "neutral"}


def _evaluate_policy(policy: object) -> tuple[dict[str, str], list[str], list[str]]:
    status = _new_capability_status()
    denies: list[str] = []
    reasons: list[str] = []
    if not isinstance(policy, dict):
        return status, denies, reasons

    statements = policy.get("statements", policy.get("Statement", []))
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list):
        return status, denies, reasons

    for index, statement in enumerate(statements):
        if not isinstance(statement, dict):
            continue
        effect = str(statement.get("effect", statement.get("Effect", ""))).lower()
        if effect not in {"allow", "deny"}:
            continue
        principal = statement.get("principal", statement.get("Principal"))
        public = _is_public_principal(principal)
        actions = statement.get("action", statement.get("Action", []))
        if isinstance(actions, str):
            actions = [actions]
        if not isinstance(actions, list):
            continue

        capabilities: set[str] = set()
        for action in actions:
            capabilities.update(_action_capabilities(action))

        statement_id = statement.get("id", statement.get("sid", statement.get("Id")))
        label = str(statement_id) if statement_id not in (None, "") else f"policy-statement-{index}"
        for capability in capabilities:
            if effect == "deny":
                status[capability] = "deny"
                denies.append(label)
            elif effect == "allow" and public and status[capability] != "deny":
                status[capability] = "allow"
                reasons.append(f"policy:{capability}:{label}")

    return status, list(dict.fromkeys(denies)), reasons


def _acl_flag(acl: dict[str, Any], capability: str) -> str:
    deny_names = (f"deny_{capability}", f"{capability}_denied", f"deny_public_{capability}")
    for name in deny_names:
        if acl.get(name) is True:
            return "deny"

    names = (
        f"public_{capability}",
        f"{capability}_public",
        f"allows_public_{capability}",
        f"allow_public_{capability}",
        capability,
    )
    for name in names:
        if name not in acl:
            continue
        value = acl[name]
        if value is True:
            return "allow"
        if isinstance(value, str):
            lowered = value.strip().lower()
            if lowered in {"allow", "allowed", "public", "yes", "true"}:
                return "allow"
            if lowered == "deny":
                return "deny"
        if value == "deny":
            return "deny"
    return "neutral"


def _public_acl_grantee(grantee: object) -> bool:
    if isinstance(grantee, str):
        lowered = grantee.lower()
        return grantee == "*" or any(marker in lowered for marker in _PUBLIC_GRANT_MARKERS)
    if isinstance(grantee, dict):
        uri = grantee.get("uri", grantee.get("URI", grantee.get("Uri")))
        if isinstance(uri, str):
            lowered = uri.lower()
            if any(marker in lowered for marker in _PUBLIC_GRANT_MARKERS):
                return True
        return _is_public_principal(grantee)
    return False


def _evaluate_acl_permissions(acl: object) -> tuple[dict[str, str], list[str], list[str]]:
    status = _new_capability_status()
    denies: list[str] = []
    reasons: list[str] = []
    if not isinstance(acl, dict):
        return status, denies, reasons

    for capability in ("read", "write"):
        result = _acl_flag(acl, capability)
        if result == "allow":
            status[capability] = "allow"
            reasons.append(f"acl:{capability}:public")
        elif result == "deny":
            status[capability] = "deny"
            denies.append(f"acl:{capability}:deny")

    grants = acl.get("grants", acl.get("Grants", acl.get("grant", [])))
    if isinstance(grants, dict):
        grants = [grants]
    if not isinstance(grants, list):
        grants = []

    for index, grant in enumerate(grants):
        if isinstance(grant, str):
            permission = grant
            effect = "allow"
            grantee = "*"
        elif isinstance(grant, dict):
            permission = str(grant.get("permission", grant.get("Permission", "")))
            effect = str(grant.get("effect", grant.get("Effect", "allow"))).lower()
            grantee = grant.get("grantee", grant.get("Grantee", grant.get("principal", "*")))
        else:
            continue

        if not _public_acl_grantee(grantee):
            continue
        upper_permission = permission.upper()
        capabilities: set[str] = set()
        if upper_permission in {"READ", "GET", "LIST"}:
            capabilities.add("read")
        elif upper_permission in {"WRITE", "PUT"}:
            capabilities.add("write")
        elif upper_permission == "FULL_CONTROL":
            capabilities.update({"read", "write"})

        label = f"acl-grant-{index}:{upper_permission.lower()}"
        for capability in capabilities:
            if effect == "deny":
                status[capability] = "deny"
                denies.append(label)
            elif effect == "allow" and status[capability] != "deny":
                status[capability] = "allow"
                reasons.append(label)

    return status, list(dict.fromkeys(denies)), reasons


def _build_verdict(bucket: str, region: str, acl: object, policy: object) -> AclVerdict:
    acl_status, acl_denies, acl_reasons = _evaluate_acl_permissions(acl)
    policy_status, policy_denies, policy_reasons = _evaluate_policy(policy)
    explicit_denies = tuple(dict.fromkeys(acl_denies + policy_denies))

    merged: dict[str, bool] = {}
    for capability in ("read", "write"):
        if acl_status[capability] == "deny" or policy_status[capability] == "deny":
            merged[capability] = False
        else:
            merged[capability] = (
                acl_status[capability] == "allow"
                and policy_status[capability] == "allow"
            )

    reasons = tuple(acl_reasons + policy_reasons)
    return AclVerdict(
        bucket=bucket,
        region=region,
        read_allowed=merged["read"],
        write_allowed=merged["write"],
        public_read=merged["read"],
        public_write=merged["write"],
        explicit_denies=explicit_denies,
        reasons=reasons,
    )


def _response_status(response: object) -> int | None:
    if isinstance(response, (int, float)) and not isinstance(response, bool):
        return int(response)
    if isinstance(response, dict):
        for key in ("status", "status_code", "statusCode", "http_status"):
            value = response.get(key)
            if isinstance(value, int) and not isinstance(value, bool):
                return value
        return None
    for attr in ("status", "status_code", "statusCode"):
        value = getattr(response, attr, None)
        if isinstance(value, int) and not isinstance(value, bool):
            return value
    return None


def _first_response_key(response: object) -> str | None:
    if not isinstance(response, dict):
        for attr in ("keys", "objects", "Contents"):
            value = getattr(response, attr, None)
            if value is not None:
                response = {attr: value}
                break
        else:
            return None

    keys = response.get("keys", response.get("Keys", response.get("objects", response.get("Contents", ()))))
    if isinstance(keys, str):
        keys = [keys]
    if not isinstance(keys, (list, tuple)):
        return None
    for item in keys:
        if isinstance(item, str) and item:
            return item
        if isinstance(item, dict):
            key = item.get("key", item.get("Key"))
            if isinstance(key, str) and key:
                return key
    return None


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
        self._buckets: dict[tuple[str, str], dict[str, Any]] = {}
        self._watermarks: dict[tuple[str, str], dict[str, Any]] = {}
        self._conclusions: dict[tuple[str, str], dict[str, Any]] = {}
        self._stats = {
            "buckets": 0,
            "probes": 0,
            "not_found": 0,
            "failures": 0,
            "cooldowns": 0,
        }
        self._rate_window: int | float | None = None
        self._rate_used = 0

    def _validate_key(self, bucket: object, region: object) -> tuple[str, str]:
        if not _valid_bucket_name(bucket):
            raise ExposureError("INVALID_BUCKET", {"bucket": bucket})
        if not isinstance(region, str) or not region:
            raise ExposureError("INVALID_REGION", {"region": region})
        return bucket, region

    def _record(self, key: tuple[str, str]) -> dict[str, Any]:
        record = self._buckets.get(key)
        if record is None:
            raise ExposureError("BUCKET_UNKNOWN", {"bucket": key[0], "region": key[1]})
        return record

    def _watermark(self, key: tuple[str, str]) -> dict[str, Any]:
        watermark = self._watermarks.get(key)
        if watermark is None:
            watermark = {
                "last_probe_at": None,
                "scanned_at": None,
                "cache_anchor_at": None,
                "last_5xx_at": None,
                "last_failure_at": None,
                "read_hits": 0,
                "hit_timestamps": [],
                "hit_policy_version": None,
                "last_evidence": (),
            }
            self._watermarks[key] = watermark
        return watermark

    def register(self, bucket: str, *, region: str, account: str,
                 acl=None, policy=None) -> int:
        key = self._validate_key(bucket, region)
        with self._lock:
            existing = self._buckets.get(key)
            if existing is None and len(self._buckets) >= self.max_buckets:
                raise ExposureError(
                    "CAPACITY_EXCEEDED",
                    {"max_buckets": self.max_buckets, "bucket": bucket, "region": region},
                )

            policy_version = 1 if existing is None else int(existing["policy_version"]) + 1
            acl_copy = copy.deepcopy(acl)
            policy_copy = copy.deepcopy(policy)
            verdict = _build_verdict(bucket, region, acl_copy, policy_copy)
            self._buckets[key] = {
                "bucket": bucket,
                "region": region,
                "account": account,
                "acl": acl_copy,
                "policy": policy_copy,
                "policy_version": policy_version,
                "verdict": verdict,
                "registered_at": time.time() if existing is None else existing.get("registered_at"),
            }

            watermark = self._watermarks.get(key)
            if watermark is not None:
                watermark["read_hits"] = 0
                watermark["hit_timestamps"] = []
                watermark["hit_policy_version"] = None
                watermark["last_evidence"] = ()
                watermark["scanned_at"] = None
                watermark["cache_anchor_at"] = None

            self._stats["buckets"] = len(self._buckets)
            return policy_version

    def evaluate_acl(self, bucket: str, *, region: str, acl=None,
                     policy=None) -> AclVerdict:
        key = self._validate_key(bucket, region)
        with self._lock:
            record = self._buckets.get(key)
            if acl is None and policy is None:
                record = self._record(key)
                acl = record["acl"]
                policy = record["policy"]
            else:
                if acl is None:
                    acl = record["acl"] if record is not None else {}
                if policy is None:
                    policy = record["policy"] if record is not None else {}
            return _build_verdict(bucket, region, acl, policy)

    def _cooldown_remaining_locked(self, key: tuple[str, str], now: int | float) -> int | float:
        watermark = self._watermarks.get(key)
        if watermark is None:
            return 0
        last_error = watermark.get("last_5xx_at")
        if last_error is None:
            return 0
        elapsed = now - last_error
        if elapsed < self.cooldown_seconds:
            return self.cooldown_seconds - elapsed
        return 0

    def _consume_rate_budget_locked(self, now: int | float) -> None:
        window = int(now // 60)
        if self._rate_window != window:
            self._rate_window = window
            self._rate_used = 0
        if self._rate_used >= self.probe_per_minute:
            raise ExposureError(
                "PROBE_RATE_LIMITED",
                {"probe_per_minute": self.probe_per_minute, "window": window},
            )
        self._rate_used += 1

    def _call_prober_locked(self, bucket: str, region: str, action: str) -> object:
        prober = self._prober
        if not callable(prober):
            raise ExposureError("PROBE_FAILED", {"reason": "prober_not_configured"})
        try:
            return prober(bucket, region, action)
        except ExposureError:
            raise
        except Exception as exc:
            raise ExposureError(
                "PROBE_FAILED",
                {"action": action, "error_type": type(exc).__name__, "error": str(exc)},
            ) from exc

    def _probe_actions_locked(self, bucket: str, region: str) -> dict[str, object]:
        head_response = self._call_prober_locked(bucket, region, "HEAD")
        head_status = _response_status(head_response)
        if head_status is None:
            raise ExposureError("PROBE_FAILED", {"action": "HEAD", "reason": "invalid_response"})

        if 500 <= head_status < 600:
            return {"state": "cooldown", "action": "HEAD", "status": head_status,
                    "evidence": (f"HEAD:{head_status}",)}
        if head_status == 404:
            return {"state": "missing", "action": "HEAD", "status": head_status,
                    "evidence": (f"HEAD:{head_status}",)}
        if not (200 <= head_status < 300) and not (400 <= head_status < 500):
            raise ExposureError("PROBE_FAILED", {"action": "HEAD", "status": head_status})
        return self._get_read_outcome_locked(bucket, region)

    def _get_read_outcome_locked(self, bucket: str, region: str) -> dict[str, object]:
        get_response = self._call_prober_locked(bucket, region, "GET")
        get_status = _response_status(get_response)
        if get_status is None:
            raise ExposureError("PROBE_FAILED", {"action": "GET", "reason": "invalid_response"})
        if 500 <= get_status < 600:
            return {"state": "cooldown", "action": "GET", "status": get_status,
                    "evidence": (f"GET:{get_status}",)}
        if get_status == 404:
            return {"state": "missing", "action": "GET", "status": get_status,
                    "evidence": (f"GET:{get_status}",)}
        if get_status in {401, 403} or 400 <= get_status < 500:
            return {"state": "clean", "action": "GET", "status": get_status,
                    "evidence": (f"GET:{get_status}",)}
        if not (200 <= get_status < 300):
            raise ExposureError("PROBE_FAILED", {"action": "GET", "status": get_status})

        first_key = _first_response_key(get_response)
        evidence = (first_key,) if first_key else (f"GET:{get_status}",)
        return {"state": "candidate", "action": "GET", "status": get_status,
                "evidence": evidence}

    def _apply_probe_outcome_locked(
        self,
        key: tuple[str, str],
        record: dict[str, Any],
        now: int | float,
        outcome: dict[str, object],
    ) -> bool:
        watermark = self._watermark(key)
        state = str(outcome["state"])
        evidence = tuple(outcome["evidence"])  # type: ignore[arg-type]
        watermark["last_probe_at"] = now

        existing = self._conclusions.get(key)
        conclusion = existing if existing is not None else {
            "bucket": key[0],
            "region": key[1],
            "account": record.get("account", ""),
            "confirmed_at": None,
            "rescanned_at": None,
            "fixed_at": None,
        }
        conclusion["account"] = record.get("account", "")
        conclusion["policy_version"] = record["policy_version"]
        conclusion["last_action"] = outcome.get("action")
        conclusion["last_status"] = outcome.get("status")
        conclusion["rescanned_at"] = now
        conclusion["cached"] = False
        conclusion["write_public"] = bool(record["verdict"].public_write)

        reproducible = False
        if state == "candidate":
            watermark["scanned_at"] = now
            anchor = watermark.get("cache_anchor_at")
            if anchor is None or now - anchor >= self.rescan_interval:
                watermark["cache_anchor_at"] = now
            watermark["read_hits"] = int(watermark["read_hits"]) + 1
            watermark["hit_timestamps"].append(now)
            watermark["hit_policy_version"] = record["policy_version"]
            watermark["last_evidence"] = evidence
            reproducible = (
                int(watermark["read_hits"]) >= 2
                and watermark["hit_policy_version"] == record["policy_version"]
            )
            conclusion["evidence"] = evidence
            conclusion["read_public"] = True
            if existing is not None and existing.get("state") == "confirmed" and reproducible:
                conclusion["state"] = "confirmed"
            else:
                conclusion["state"] = "candidate"
        elif state in {"clean", "missing"}:
            watermark["scanned_at"] = now
            if (
                watermark.get("cache_anchor_at") is None
                or now - watermark["cache_anchor_at"] >= self.rescan_interval
            ):
                watermark["cache_anchor_at"] = now
            watermark["read_hits"] = 0
            watermark["hit_timestamps"] = []
            watermark["hit_policy_version"] = None
            watermark["last_evidence"] = ()
            conclusion["state"] = state
            conclusion["evidence"] = evidence
            conclusion["read_public"] = False
        elif state == "cooldown":
            watermark["last_5xx_at"] = now
            if existing is not None and existing.get("state") in {"candidate", "confirmed"}:
                conclusion.setdefault("state", existing["state"])
                conclusion.setdefault("evidence", existing.get("evidence", ()))
                conclusion.setdefault("read_public", existing.get("read_public", False))
            else:
                conclusion["state"] = "cooldown"
                conclusion["evidence"] = evidence
                conclusion["read_public"] = False

        self._conclusions[key] = conclusion
        return reproducible

    def probe_anonymous(self, bucket: str, region: str,
                        now: int | float | None = None) -> ProbeResult:
        key = self._validate_key(bucket, region)
        at = _timestamp(now)
        with self._lock:
            record = self._record(key)
            remaining = self._cooldown_remaining_locked(key, at)
            if remaining > 0:
                raise ExposureError(
                    "COOLDOWN_ACTIVE",
                    {"bucket": bucket, "region": region, "retry_after": remaining},
                )

            self._consume_rate_budget_locked(at)
            self._stats["probes"] += 1
            try:
                outcome = self._probe_actions_locked(bucket, region)
            except ExposureError as exc:
                if exc.code == "PROBE_FAILED":
                    self._stats["failures"] += 1
                    watermark = self._watermark(key)
                    watermark["last_failure_at"] = at
                raise

            state = str(outcome["state"])
            if state == "missing":
                self._stats["not_found"] += 1
            elif state == "cooldown":
                self._stats["cooldowns"] += 1

            reproducible = self._apply_probe_outcome_locked(key, record, at, outcome)
            return ProbeResult(
                bucket=bucket,
                region=region,
                action=str(outcome["action"]),
                status=int(outcome["status"]),  # type: ignore[arg-type]
                state=state,
                evidence=tuple(outcome["evidence"]),  # type: ignore[arg-type]
                reproducible=reproducible,
            )

    def confirm(self, bucket: str, region: str | None = None,
                now: int | float | None = None, verdict: str = "exposed") -> str:
        key = self._validate_key(bucket, region)
        at = _timestamp(now)
        with self._lock:
            record = self._record(key)
            watermark = self._watermarks.get(key)
            reproducible = (
                watermark is not None
                and int(watermark.get("read_hits", 0)) >= 2
                and watermark.get("hit_policy_version") == record["policy_version"]
                and bool(watermark.get("last_evidence"))
            )
            if not reproducible:
                raise ExposureError(
                    "NOT_REPRODUCIBLE",
                    {
                        "bucket": bucket,
                        "region": region,
                        "read_hits": 0 if watermark is None else watermark.get("read_hits", 0),
                    },
                )

            conclusion = self._conclusions.get(key)
            if conclusion is None:
                raise ExposureError("NOT_REPRODUCIBLE", {"bucket": bucket, "region": region})
            conclusion["state"] = "confirmed"
            conclusion["policy_version"] = record["policy_version"]
            conclusion["confirmed_at"] = at
            conclusion["read_public"] = True
            conclusion["write_public"] = bool(record["verdict"].public_write)
            conclusion["evidence"] = tuple(watermark["last_evidence"])
            conclusion["cached"] = False
            return "confirmed"

    def _cache_valid_locked(self, key: tuple[str, str], record: dict[str, Any],
                            now: int | float) -> bool:
        conclusion = self._conclusions.get(key)
        watermark = self._watermarks.get(key)
        if conclusion is None or watermark is None:
            return False
        if conclusion.get("policy_version") != record["policy_version"]:
            return False
        cache_anchor = watermark.get("cache_anchor_at", watermark.get("scanned_at"))
        if cache_anchor is None:
            return False
        return now - cache_anchor < self.rescan_interval

    def rescan(self, bucket: str, region: str | None = None,
               now: int | float | None = None) -> Conclusion:
        key = self._validate_key(bucket, region)
        at = _timestamp(now)
        with self._lock:
            record = self._record(key)
            if self._cache_valid_locked(key, record, at):
                cached = self._conclusions[key]
                cached["rescanned_at"] = at
                return self._to_conclusion(key, cached=True)

            previous = self._conclusions.get(key)
            previous_state = None if previous is None else previous.get("state")
            result = self.probe_anonymous(bucket, region, at)
            conclusion = self._conclusions[key]

            if previous_state in {"confirmed", "fixed"}:
                if result.state in {"clean", "missing"}:
                    conclusion["state"] = "fixed"
                    conclusion["fixed_at"] = at
                    conclusion["read_public"] = False
                elif result.state == "candidate" and not result.reproducible:
                    conclusion["state"] = "candidate"

            conclusion["rescanned_at"] = at
            conclusion["cached"] = False
            return self._to_conclusion(key, cached=False)

    def _to_conclusion(self, key: tuple[str, str], *, cached: bool) -> Conclusion:
        data = self._conclusions[key]
        return Conclusion(
            bucket=key[0],
            region=key[1],
            account=str(data.get("account", "")),
            policy_version=int(data.get("policy_version", 1)),
            state=str(data.get("state", "unknown")),
            evidence=tuple(data.get("evidence", ())),
            read_public=bool(data.get("read_public", False)),
            write_public=bool(data.get("write_public", False)),
            confirmed_at=_optional_number(data.get("confirmed_at")),
            rescanned_at=_optional_number(data.get("rescanned_at")),
            cached=cached,
        )

    def conclusions(self, *, state: str | None = None) -> list[Conclusion]:
        with self._lock:
            items = [
                self._to_conclusion(key, cached=False)
                for key in self._conclusions
            ]
        if state is None:
            return items
        return [item for item in items if item.state == state]

    def set_probe_rate(self, limit: int) -> None:
        if not isinstance(limit, int) or isinstance(limit, bool) or limit < 0:
            raise ExposureError("INVALID_RATE_LIMIT", {"probe_per_minute": limit})
        with self._lock:
            self.probe_per_minute = limit

    def snapshot(self) -> dict:
        with self._lock:
            ledger: list[dict[str, Any]] = []
            for key, record in self._buckets.items():
                entry = {
                    "bucket": record["bucket"],
                    "region": record["region"],
                    "account": record.get("account", ""),
                    "acl": copy.deepcopy(record.get("acl")),
                    "policy": copy.deepcopy(record.get("policy")),
                    "policy_version": int(record["policy_version"]),
                    "verdict": asdict(record["verdict"]),
                    "registered_at": _optional_number(record.get("registered_at")),
                    "watermark": copy.deepcopy(self._watermarks.get(key)),
                    "conclusion": copy.deepcopy(self._conclusions.get(key)),
                }
                ledger.append(entry)

            watermark_entries = []
            for key, watermark in self._watermarks.items():
                watermark_entries.append({
                    "bucket": key[0],
                    "region": key[1],
                    **copy.deepcopy(watermark),
                })

            snapshot = {
                "schema": "bucket-exposure-scanner-snapshot/v1",
                "config": {
                    "max_buckets": self.max_buckets,
                    "probe_per_minute": self.probe_per_minute,
                    "cooldown_seconds": self.cooldown_seconds,
                    "rescan_interval": self.rescan_interval,
                },
                "stats": copy.deepcopy(self._stats),
                "probe_watermarks": {
                    "rate_window": self._rate_window,
                    "rate_used": self._rate_used,
                    "entries": watermark_entries,
                    "buckets": watermark_entries,
                },
                "ledger": ledger,
                "conclusions": copy.deepcopy(list(self._conclusions.values())),
            }
            snapshot["buckets"] = copy.deepcopy(ledger)
            return copy.deepcopy(snapshot)

    def restore(self, state: dict) -> None:
        try:
            parsed = _parse_snapshot(state)
        except ExposureError:
            raise
        except Exception as exc:
            raise ExposureError("SNAPSHOT_INVALID", {"error": str(exc)}) from exc
        with self._lock:
            old_state = (
                self._buckets,
                self._watermarks,
                self._conclusions,
                self._stats,
                self._rate_window,
                self._rate_used,
            )
            try:
                self._buckets = parsed["buckets"]
                self._watermarks = parsed["watermarks"]
                self._conclusions = parsed["conclusions"]
                self._stats = parsed["stats"]
                self._rate_window = parsed["rate_window"]
                self._rate_used = parsed["rate_used"]
            except Exception as exc:
                (
                    self._buckets,
                    self._watermarks,
                    self._conclusions,
                    self._stats,
                    self._rate_window,
                    self._rate_used,
                ) = old_state
                raise ExposureError("SNAPSHOT_INVALID", {"error": str(exc)}) from exc

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)


def _invalid_snapshot(detail: object = None) -> ExposureError:
    return ExposureError("SNAPSHOT_INVALID", detail)


def _parse_snapshot(state: object) -> dict[str, Any]:
    if not isinstance(state, dict):
        raise _invalid_snapshot({"reason": "snapshot_not_object"})

    def snapshot_time(data: dict[str, Any], field: str) -> int | float | None:
        value = data.get(field)
        if value is None:
            return None
        parsed = _optional_number(value)
        if parsed is None:
            raise _invalid_snapshot({"field": field})
        return parsed

    stats_input = state.get("stats")
    if not isinstance(stats_input, dict):
        raise _invalid_snapshot({"field": "stats"})
    stats: dict[str, int] = {}
    for name in ("buckets", "probes", "not_found", "failures", "cooldowns"):
        value = _non_negative_int(stats_input.get(name))
        if value is None:
            raise _invalid_snapshot({"field": f"stats.{name}"})
        stats[name] = value

    watermarks_input = state.get("probe_watermarks", state.get("watermarks"))
    if not isinstance(watermarks_input, dict):
        raise _invalid_snapshot({"field": "probe_watermarks"})
    rate_window = watermarks_input.get("rate_window", watermarks_input.get("window"))
    if rate_window is not None:
        if isinstance(rate_window, bool) or not isinstance(rate_window, (int, float)):
            raise _invalid_snapshot({"field": "probe_watermarks.rate_window"})
    rate_used = _non_negative_int(watermarks_input.get("rate_used", watermarks_input.get("used", 0)))
    if rate_used is None:
        raise _invalid_snapshot({"field": "probe_watermarks.rate_used"})

    top_watermarks: dict[tuple[str, str], dict[str, Any]] = {}
    raw_watermark_entries = watermarks_input.get(
        "entries", watermarks_input.get("buckets", watermarks_input.get("items", []))
    )
    if isinstance(raw_watermark_entries, dict):
        raw_watermark_entries = list(raw_watermark_entries.values())
    if not isinstance(raw_watermark_entries, list):
        raise _invalid_snapshot({"field": "probe_watermarks.entries"})
    for watermark_entry in raw_watermark_entries:
        if not isinstance(watermark_entry, dict):
            raise _invalid_snapshot({"field": "probe_watermarks.entries[]"})
        wm_bucket = watermark_entry.get("bucket")
        wm_region = watermark_entry.get("region")
        if not _valid_bucket_name(wm_bucket) or not isinstance(wm_region, str) or not wm_region:
            raise _invalid_snapshot({"field": "probe_watermarks.entries[].key"})
        top_watermarks[(wm_bucket, wm_region)] = watermark_entry

    entries_input = state.get("ledger", state.get("buckets", state.get("records")))
    if isinstance(entries_input, dict):
        entries = list(entries_input.values())
    elif isinstance(entries_input, list):
        entries = entries_input
    else:
        raise _invalid_snapshot({"field": "ledger"})

    conclusions_input = state.get("conclusions", [])
    conclusion_items: list[object]
    if isinstance(conclusions_input, dict):
        conclusion_items = list(conclusions_input.values())
    elif isinstance(conclusions_input, list):
        conclusion_items = conclusions_input
    else:
        raise _invalid_snapshot({"field": "conclusions"})

    conclusion_map: dict[tuple[str, str], dict[str, Any]] = {}
    for item in conclusion_items:
        if not isinstance(item, dict):
            raise _invalid_snapshot({"field": "conclusions[]"})
        bucket = item.get("bucket")
        region = item.get("region")
        if not _valid_bucket_name(bucket) or not isinstance(region, str) or not region:
            raise _invalid_snapshot({"field": "conclusions[].key"})
        conclusion_map[(bucket, region)] = item

    buckets: dict[tuple[str, str], dict[str, Any]] = {}
    watermarks: dict[tuple[str, str], dict[str, Any]] = {}
    conclusions: dict[tuple[str, str], dict[str, Any]] = {}

    for entry in entries:
        if not isinstance(entry, dict):
            raise _invalid_snapshot({"field": "ledger[]"})
        bucket = entry.get("bucket")
        region = entry.get("region")
        if not _valid_bucket_name(bucket) or not isinstance(region, str) or not region:
            raise _invalid_snapshot({"field": "ledger[].key"})
        key = (bucket, region)
        if key in buckets:
            raise _invalid_snapshot({"field": "ledger[].duplicate_key", "key": list(key)})

        policy_version = _non_negative_int(entry.get("policy_version", 1))
        if policy_version is None or policy_version < 1:
            raise _invalid_snapshot({"field": "ledger[].policy_version"})

        acl = copy.deepcopy(entry.get("acl"))
        policy = copy.deepcopy(entry.get("policy"))
        if acl is not None and not isinstance(acl, dict):
            raise _invalid_snapshot({"field": "ledger[].acl"})
        if policy is not None and not isinstance(policy, dict):
            raise _invalid_snapshot({"field": "ledger[].policy"})

        account = entry.get("account", "")
        if account is None:
            account = ""
        if not isinstance(account, str):
            account = str(account)

        buckets[key] = {
            "bucket": bucket,
            "region": region,
            "account": account,
            "acl": acl,
            "policy": policy,
            "policy_version": policy_version,
            "verdict": _build_verdict(bucket, region, acl, policy),
            "registered_at": snapshot_time(entry, "registered_at"),
        }

        watermark_input = entry.get("watermark", entry.get("probe_watermark"))
        if watermark_input is None:
            watermark_input = top_watermarks.get(key)
        if watermark_input is None:
            watermark_input = watermarks_input.get(f"{bucket}\x1f{region}")
        if watermark_input is None:
            watermark_input = watermarks_input.get(f"{bucket}:{region}")
        if watermark_input is not None and not isinstance(watermark_input, dict):
            raise _invalid_snapshot({"field": "ledger[].watermark"})
        watermark_input = watermark_input if isinstance(watermark_input, dict) else {}

        hit_timestamps = watermark_input.get("hit_timestamps", [])
        if not isinstance(hit_timestamps, list):
            raise _invalid_snapshot({"field": "watermark.hit_timestamps"})
        normalized_timestamps: list[int | float] = []
        for timestamp_value in hit_timestamps:
            number = _optional_number(timestamp_value)
            if number is None:
                raise _invalid_snapshot({"field": "watermark.hit_timestamps[]"})
            normalized_timestamps.append(number)

        read_hits = _non_negative_int(watermark_input.get("read_hits", len(normalized_timestamps)))
        if read_hits is None:
            raise _invalid_snapshot({"field": "watermark.read_hits"})
        hit_version = watermark_input.get("hit_policy_version")
        if hit_version is not None:
            hit_version = _non_negative_int(hit_version)
            if hit_version is None or hit_version < 1:
                raise _invalid_snapshot({"field": "watermark.hit_policy_version"})

        last_evidence = watermark_input.get("last_evidence", ())
        if isinstance(last_evidence, str):
            last_evidence = [last_evidence]
        if not isinstance(last_evidence, (list, tuple)) or not all(isinstance(item, str) for item in last_evidence):
            raise _invalid_snapshot({"field": "watermark.last_evidence"})

        scanned_at = snapshot_time(watermark_input, "scanned_at")
        cache_anchor_at = snapshot_time(watermark_input, "cache_anchor_at")
        if cache_anchor_at is None:
            cache_anchor_at = scanned_at

        watermarks[key] = {
            "last_probe_at": snapshot_time(watermark_input, "last_probe_at"),
            "scanned_at": scanned_at,
            "cache_anchor_at": cache_anchor_at,
            "last_5xx_at": snapshot_time(watermark_input, "last_5xx_at"),
            "last_failure_at": snapshot_time(watermark_input, "last_failure_at"),
            "read_hits": read_hits,
            "hit_timestamps": normalized_timestamps,
            "hit_policy_version": hit_version,
            "last_evidence": tuple(last_evidence),
        }

        conclusion_input = entry.get("conclusion")
        if conclusion_input is None:
            conclusion_input = conclusion_map.get(key)
        if conclusion_input is None:
            continue
        if not isinstance(conclusion_input, dict):
            raise _invalid_snapshot({"field": "ledger[].conclusion"})

        state_name = conclusion_input.get("state")
        if not isinstance(state_name, str) or state_name not in _CONCLUSION_STATES:
            raise _invalid_snapshot({"field": "conclusion.state"})

        evidence = conclusion_input.get("evidence", ())
        if isinstance(evidence, str):
            evidence = [evidence]
        if not isinstance(evidence, (list, tuple)) or not all(isinstance(item, str) for item in evidence):
            raise _invalid_snapshot({"field": "conclusion.evidence"})

        conclusion_version = _non_negative_int(conclusion_input.get("policy_version", policy_version))
        if conclusion_version is None or conclusion_version < 1:
            raise _invalid_snapshot({"field": "conclusion.policy_version"})

        for boolean_field in ("read_public", "write_public"):
            if not isinstance(conclusion_input.get(boolean_field, False), bool):
                raise _invalid_snapshot({"field": f"conclusion.{boolean_field}"})

        conclusions[key] = {
            "bucket": bucket,
            "region": region,
            "account": account,
            "policy_version": conclusion_version,
            "state": state_name,
            "evidence": tuple(evidence),
            "read_public": conclusion_input.get("read_public", False),
            "write_public": conclusion_input.get("write_public", False),
            "confirmed_at": snapshot_time(conclusion_input, "confirmed_at"),
            "rescanned_at": snapshot_time(conclusion_input, "rescanned_at"),
            "fixed_at": snapshot_time(conclusion_input, "fixed_at"),
            "last_action": conclusion_input.get("last_action"),
            "last_status": conclusion_input.get("last_status"),
            "cached": False,
        }

    stats["buckets"] = len(buckets)
    return {
        "buckets": buckets,
        "watermarks": watermarks,
        "conclusions": conclusions,
        "stats": stats,
        "rate_window": rate_window,
        "rate_used": rate_used,
    }
