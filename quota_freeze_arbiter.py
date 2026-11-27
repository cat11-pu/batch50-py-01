"""Tenant disk quota arbiter: soft/hard limits, grace freeze and audit trail."""

from __future__ import annotations

import copy
import threading
from dataclasses import asdict, dataclass
from datetime import datetime, timedelta, timezone

SCHEMA_VERSION = 1

OUTCOMES = ("allowed", "grace", "denied")

STATES = ("ok", "grace", "frozen")

ERR_POLICY_EXISTS = "QUOTA_POLICY_EXISTS"
ERR_POLICY_INVALID = "QUOTA_POLICY_INVALID"
ERR_UNKNOWN_VOLUME = "QUOTA_UNKNOWN_VOLUME"
ERR_INVALID_REQUEST = "QUOTA_INVALID_REQUEST"
ERR_WRITE_TOO_LARGE = "QUOTA_WRITE_TOO_LARGE"
ERR_HARD_LIMIT = "QUOTA_HARD_LIMIT"
ERR_GRACE_EXPIRED = "QUOTA_GRACE_EXPIRED"
ERR_TENANT_LIMIT = "QUOTA_TENANT_LIMIT"
ERR_TENANT_FROZEN = "QUOTA_TENANT_FROZEN"
ERR_NOT_FROZEN = "QUOTA_NOT_FROZEN"
ERR_RELEASE_REFUSED = "QUOTA_RELEASE_REFUSED"
ERR_SNAPSHOT_INVALID = "QUOTA_SNAPSHOT_INVALID"

_SNAPSHOT_KEYS = (
    "version",
    "volumes",
    "policies",
    "tenant_limits",
    "objects",
    "states",
    "audit",
    "stats",
)

_STATS_KEYS = (
    "admitted",
    "grace_admitted",
    "denied",
    "written_bytes",
    "reclaimed_bytes",
    "grace_entered",
    "frozen",
    "released",
    "audit_writes",
)


class QuotaError(ValueError):
    """Raised when a quota request or a state transition is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class QuotaPolicy:
    """Per tenant and volume limit pair."""

    tenant: str
    volume: str
    soft_limit: int
    hard_limit: int


@dataclass(frozen=True)
class WriteDecision:
    """Admission decision for one write request."""

    tenant: str
    volume: str
    path: str
    size: int
    outcome: str
    state: str
    code: str | None
    usage: int
    remaining: int
    grace_deadline: str | None


@dataclass(frozen=True)
class ReclaimResult:
    """Result of deleting or shrinking one object."""

    tenant: str
    volume: str
    path: str
    reclaimed: int
    usage: int
    state: str


@dataclass(frozen=True)
class TruncateResult:
    """Result of a truncation, either a reclaim or an admission."""

    tenant: str
    volume: str
    path: str
    action: str
    reclaimed: int
    decision: WriteDecision | None
    usage: int
    state: str


@dataclass(frozen=True)
class AuditEntry:
    """One sealed quota decision record."""

    seq: int
    action: str
    tenant: str
    volume: str
    path: str
    outcome: str
    code: str | None
    usage_after: int


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _non_negative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _parse_datetime(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = datetime.fromtimestamp(value, tz=timezone.utc)
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        parsed = datetime.fromisoformat(text)
    else:
        raise ValueError(f"unsupported time: {value!r}")

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


class QuotaFreezeArbiter:
    """Track tenant usage per volume and freeze writes at the agreed limits."""

    def __init__(self, *, soft_limit: int = 1024, hard_limit: int = 4096,
                 grace_seconds: int = 3600, max_write_bytes: int = 1024,
                 aggregate_hard_limit: int | None = None, clock=None) -> None:
        if not _positive_int(soft_limit) or not _positive_int(hard_limit):
            raise QuotaError(ERR_POLICY_INVALID, {
                "soft_limit": soft_limit,
                "hard_limit": hard_limit,
            })
        if not _non_negative_int(grace_seconds):
            raise QuotaError(ERR_POLICY_INVALID, {
                "grace_seconds": grace_seconds,
            })
        if not _positive_int(max_write_bytes):
            raise QuotaError(ERR_POLICY_INVALID, {
                "max_write_bytes": max_write_bytes,
            })
        if aggregate_hard_limit is not None and not _positive_int(
                aggregate_hard_limit):
            raise QuotaError(ERR_POLICY_INVALID, {
                "aggregate_hard_limit": aggregate_hard_limit,
            })

        self.soft_limit = soft_limit
        self.hard_limit = hard_limit
        self.grace_seconds = grace_seconds
        self.max_write_bytes = max_write_bytes
        self.aggregate_hard_limit = aggregate_hard_limit
        self._clock = clock
        self._lock = threading.RLock()
        self._volumes: list[str] = []
        self._policies: dict[tuple[str, str], QuotaPolicy] = {}
        self._tenant_limits: dict[str, int] = {}
        self._objects: dict[tuple[str, str, str], dict] = {}
        self._states: dict[str, dict] = {}
        self._audit: list[AuditEntry] = []
        self._counters = {"object_seq": 0, "audit_seq": 0}
        self._stats = {key: 0 for key in _STATS_KEYS}

    def register_volume(self, volume: str) -> str:
        """Register a storage volume that tenants may be limited on."""
        if not isinstance(volume, str) or not volume:
            raise QuotaError(ERR_INVALID_REQUEST, {"volume": volume})
        with self._lock:
            if volume not in self._volumes:
                self._volumes.append(volume)
            return volume

    def volumes(self) -> tuple:
        """Return the registered volume names in order."""
        with self._lock:
            return tuple(self._volumes)

    def set_quota(self, tenant: str, volume: str, *, soft_limit: int,
                  hard_limit: int) -> QuotaPolicy:
        """Install a limit pair for one tenant on one volume."""
        self._require_tenant(tenant)
        if not _positive_int(soft_limit) or not _positive_int(hard_limit):
            raise QuotaError(ERR_POLICY_INVALID, {
                "soft_limit": soft_limit,
                "hard_limit": hard_limit,
            })
        if soft_limit >= hard_limit:
            raise QuotaError(ERR_POLICY_INVALID, {
                "soft_limit": soft_limit,
                "hard_limit": hard_limit,
            })

        with self._lock:
            self._require_volume_locked(volume)
            key = (tenant, volume)
            if key in self._policies:
                raise QuotaError(ERR_POLICY_EXISTS, {
                    "tenant": tenant,
                    "volume": volume,
                })
            policy = QuotaPolicy(tenant, volume, soft_limit, hard_limit)
            self._policies[key] = policy
            return policy

    def quota_policy(self, tenant: str, volume: str) -> QuotaPolicy | None:
        """Return the explicit policy for a tenant and volume, if any."""
        self._require_tenant(tenant)
        with self._lock:
            self._require_volume_locked(volume)
            return self._policies.get((tenant, volume))

    def set_tenant_limit(self, tenant: str, hard_limit: int) -> int:
        """Cap the aggregate usage of a tenant across all volumes."""
        self._require_tenant(tenant)
        if not _positive_int(hard_limit):
            raise QuotaError(ERR_POLICY_INVALID, {"hard_limit": hard_limit})

        now_dt = self._moment(None)
        with self._lock:
            current = self._tenant_limits.get(
                tenant, self.aggregate_hard_limit)
            if current is not None and hard_limit > current:
                raise QuotaError(ERR_POLICY_INVALID, {
                    "reason": "tenant_limit_may_only_be_reduced",
                    "current": current,
                    "requested": hard_limit,
                })

            self._tenant_limits[tenant] = hard_limit
            total_usage, _ = self._usage_locked(tenant)
            if total_usage >= hard_limit:
                self._freeze_locked(
                    tenant,
                    "tenant aggregate limit reached",
                    now_dt,
                    "tenant_limit",
                    ERR_TENANT_LIMIT,
                )
            return hard_limit

    def admit_write(self, tenant: str, volume: str, path: str, size: int,
                    *, inode: int | None = None,
                    now=None) -> WriteDecision:
        """Decide whether a write may proceed and account for it when it does."""
        self._require_tenant(tenant)
        now_dt = self._moment(now)
        inode_value = self._validated_inode(inode)
        with self._lock:
            self._require_volume_locked(volume)
            self._validate_path_and_size(path, size)
            return self._admit_delta_locked(
                tenant,
                volume,
                path,
                size,
                inode_value,
                now_dt,
                "admit",
            )

    def delete_object(self, tenant: str, volume: str, path: str,
                      *, now=None) -> ReclaimResult:
        """Remove a tracked object and reclaim its bytes."""
        self._require_tenant(tenant)
        now_dt = self._moment(now)
        with self._lock:
            self._require_volume_locked(volume)
            self._validate_path(path)

            removed = self._objects.pop((tenant, volume, path), None)
            reclaimed = 0
            if removed is not None:
                reclaimed = max(0, int(removed.get("size", 0)))
                self._stats["reclaimed_bytes"] += reclaimed

            _, by_volume = self._usage_locked(tenant)
            usage = by_volume.get(volume, 0)
            state = self._state_record_locked(tenant)
            grace = state.get("grace")
            soft_limit = self._soft_limit_for_locked(tenant, volume)
            if isinstance(grace, dict) and usage < soft_limit:
                grace.pop(volume, None)

            tenant_state = self._derive_state_locked(tenant, now_dt)
            self._append_audit_locked(
                "delete", tenant, volume, path, "reclaimed", None, usage)
            return ReclaimResult(
                tenant=tenant,
                volume=volume,
                path=path,
                reclaimed=reclaimed,
                usage=usage,
                state=tenant_state,
            )

    def truncate_object(self, tenant: str, volume: str, path: str,
                        new_size: int, *, now=None) -> TruncateResult:
        """Shrink or grow a tracked object under the same rules as writes."""
        self._require_tenant(tenant)
        now_dt = self._moment(now)
        if not _non_negative_int(new_size):
            raise QuotaError(ERR_INVALID_REQUEST, {"new_size": new_size})

        with self._lock:
            self._require_volume_locked(volume)
            self._validate_path(path)
            key = (tenant, volume, path)
            old = self._objects.get(key)
            old_size = int(old.get("size", 0)) if old is not None else 0

            if new_size <= old_size:
                reclaimed = old_size - new_size
                if old is not None:
                    updated = copy.deepcopy(old)
                    updated["size"] = new_size
                    self._objects[key] = updated
                self._stats["reclaimed_bytes"] += reclaimed

                _, by_volume = self._usage_locked(tenant)
                usage = by_volume.get(volume, 0)
                state = self._state_record_locked(tenant)
                grace = state.get("grace")
                soft_limit = self._soft_limit_for_locked(tenant, volume)
                if isinstance(grace, dict) and usage < soft_limit:
                    grace.pop(volume, None)

                tenant_state = self._derive_state_locked(tenant, now_dt)
                self._append_audit_locked(
                    "truncate", tenant, volume, path, "reclaimed", None, usage)
                return TruncateResult(
                    tenant=tenant,
                    volume=volume,
                    path=path,
                    action="reclaim",
                    reclaimed=reclaimed,
                    decision=None,
                    usage=usage,
                    state=tenant_state,
                )

            delta = new_size - old_size
            if delta > self.max_write_bytes:
                raise QuotaError(ERR_WRITE_TOO_LARGE, {
                    "delta": delta,
                    "max_write_bytes": self.max_write_bytes,
                })

            decision = self._admit_delta_locked(
                tenant,
                volume,
                path,
                delta,
                None,
                now_dt,
                "truncate",
            )
            return TruncateResult(
                tenant=tenant,
                volume=volume,
                path=path,
                action="admit",
                reclaimed=0,
                decision=decision,
                usage=decision.usage,
                state=decision.state,
            )

    def usage(self, tenant: str) -> int:
        """Return aggregate tenant usage across all volumes."""
        self._require_tenant(tenant)
        with self._lock:
            total, _ = self._usage_locked(tenant)
            return total

    def usage_by_volume(self, tenant: str) -> dict:
        """Return tenant usage per registered volume."""
        self._require_tenant(tenant)
        with self._lock:
            _, by_volume = self._usage_locked(tenant)
            return dict(by_volume)

    def tenant_state(self, tenant: str, now=None) -> str:
        """Return ok, grace or frozen for the tenant."""
        self._require_tenant(tenant)
        now_dt = self._moment(now)
        with self._lock:
            return self._derive_state_locked(tenant, now_dt)

    def freeze_tenant(self, tenant: str, reason: str, *, now=None) -> str:
        """Freeze a tenant by operator decision."""
        self._require_tenant(tenant)
        now_dt = self._moment(now)
        with self._lock:
            state = self._state_record_locked(tenant)
            if not state.get("frozen"):
                self._freeze_locked(
                    tenant, reason, now_dt, "admin", None)
            return "frozen"

    def lift_freeze(self, tenant: str, *, now=None) -> bool:
        """Release an operator freeze when usage has fallen below the soft limit."""
        self._require_tenant(tenant)
        now_dt = self._moment(now)
        with self._lock:
            state = self._state_record_locked(tenant)
            if not state.get("frozen"):
                derived_state = self._derive_state_locked(tenant, now_dt)
                if derived_state != "frozen":
                    raise QuotaError(ERR_NOT_FROZEN, {"tenant": tenant})
                self._freeze_locked(
                    tenant,
                    "grace period expired",
                    now_dt,
                    "grace_expired",
                    ERR_GRACE_EXPIRED,
                )

            total_usage, by_volume = self._usage_locked(tenant)
            for volume in self._volumes:
                soft_limit = self._soft_limit_for_locked(tenant, volume)
                if by_volume.get(volume, 0) >= soft_limit:
                    raise QuotaError(ERR_RELEASE_REFUSED, {
                        "tenant": tenant,
                        "volume": volume,
                        "usage": by_volume.get(volume, 0),
                        "soft_limit": soft_limit,
                        "usage_total": total_usage,
                    })

            state["frozen"] = False
            state["state"] = "ok"
            state["frozen_at"] = None
            state["frozen_reason"] = None
            state["freeze_source"] = None
            state["grace"] = {}
            state["released_at"] = _iso(now_dt)
            self._stats["released"] += 1
            self._append_audit_locked(
                "release", tenant, "", "", "released", None, total_usage)
            return True

    def audit_entries(self) -> tuple:
        """Return the sealed decision records in sequence order."""
        with self._lock:
            return tuple(self._audit)

    def snapshot(self) -> dict:
        """Return a detached copy of volumes, policies, objects and audit."""
        with self._lock:
            policies: dict[str, dict[str, dict]] = {}
            for (tenant, volume), policy in self._policies.items():
                policies.setdefault(tenant, {})[volume] = asdict(policy)

            objects: dict[str, dict[str, dict[str, dict]]] = {}
            for (tenant, volume, path), obj in self._objects.items():
                objects.setdefault(tenant, {}).setdefault(volume, {})[path] = {
                    "size": int(obj["size"]),
                    "inode": obj.get("inode"),
                }

            snapshot = {
                "version": SCHEMA_VERSION,
                "volumes": list(self._volumes),
                "policies": policies,
                "tenant_limits": dict(self._tenant_limits),
                "objects": objects,
                "states": copy.deepcopy(self._states),
                "audit": [asdict(entry) for entry in self._audit],
                "stats": dict(self._stats),
            }
            return copy.deepcopy(snapshot)

    def restore(self, state: dict) -> None:
        """Replace live state with a validated snapshot."""
        restored = self._build_restored_state(state)
        with self._lock:
            self._volumes = restored["volumes"]
            self._policies = restored["policies"]
            self._tenant_limits = restored["tenant_limits"]
            self._objects = restored["objects"]
            self._states = restored["states"]
            self._audit = restored["audit"]
            self._stats = restored["stats"]
            self._counters = {
                "object_seq": 0,
                "audit_seq": restored["audit"][-1].seq
                if restored["audit"] else 0,
            }

    def stats(self) -> dict:
        """Return the admission, reclaim and freeze counters."""
        with self._lock:
            return dict(self._stats)

    def _moment(self, now: object) -> datetime:
        value = now
        if value is None and self._clock is not None:
            value = self._clock()
        if value is None:
            value = datetime.now(timezone.utc)
        try:
            return _parse_datetime(value)
        except Exception as exc:
            raise QuotaError(ERR_INVALID_REQUEST, {"now": now}) from exc

    @staticmethod
    def _require_tenant(tenant: object) -> None:
        if not isinstance(tenant, str) or not tenant:
            raise QuotaError(ERR_INVALID_REQUEST, {"tenant": tenant})

    @staticmethod
    def _validate_path(path: object) -> None:
        if not isinstance(path, str) or not path:
            raise QuotaError(ERR_INVALID_REQUEST, {"path": path})

    def _validate_path_and_size(self, path: object, size: object) -> None:
        self._validate_path(path)
        if not _positive_int(size):
            raise QuotaError(ERR_INVALID_REQUEST, {"size": size})
        if size > self.max_write_bytes:
            raise QuotaError(ERR_WRITE_TOO_LARGE, {
                "size": size,
                "max_write_bytes": self.max_write_bytes,
            })

    def _require_volume_locked(self, volume: object) -> None:
        if not isinstance(volume, str) or volume not in self._volumes:
            raise QuotaError(ERR_UNKNOWN_VOLUME, {"volume": volume})

    @staticmethod
    def _validated_inode(inode: object) -> object:
        if inode is None:
            return None
        try:
            hash(inode)
        except TypeError as exc:
            raise QuotaError(ERR_INVALID_REQUEST, {"inode": inode}) from exc
        return inode

    @staticmethod
    def _synthetic_inode(tenant: str, volume: str, path: str) -> str:
        return "\x1f".join(("__quota_path_inode__", tenant, volume, path))

    def _limits_for_locked(self, tenant: str,
                           volume: str) -> tuple[int, int]:
        policy = self._policies.get((tenant, volume))
        if policy is not None:
            return policy.soft_limit, policy.hard_limit
        return self.soft_limit, self.hard_limit

    def _soft_limit_for_locked(self, tenant: str, volume: str) -> int:
        return self._limits_for_locked(tenant, volume)[0]

    def _tenant_limit_for_locked(self, tenant: str) -> int | None:
        return self._tenant_limits.get(tenant, self.aggregate_hard_limit)

    @staticmethod
    def _fresh_state() -> dict:
        return {
            "state": "ok",
            "frozen": False,
            "frozen_at": None,
            "frozen_reason": None,
            "freeze_source": None,
            "grace": {},
        }

    def _state_record_locked(self, tenant: str) -> dict:
        state = self._states.get(tenant)
        if not isinstance(state, dict):
            state = self._fresh_state()
            self._states[tenant] = state
        if not isinstance(state.get("grace"), dict):
            state["grace"] = {}
        state.setdefault("state", "ok")
        state.setdefault("frozen", False)
        return state

    def _usage_locked(
            self, tenant: str,
            objects: dict | None = None) -> tuple[int, dict[str, int]]:
        source = self._objects if objects is None else objects
        by_volume = {volume: 0 for volume in self._volumes}
        first_volume: dict[object, str] = {}
        inode_size: dict[object, int] = {}

        for volume in self._volumes:
            for (object_tenant, object_volume, path), obj in source.items():
                if object_tenant != tenant or object_volume != volume:
                    continue
                if not isinstance(obj, dict):
                    continue
                inode = obj.get("inode")
                if inode is None:
                    inode = self._synthetic_inode(
                        object_tenant, object_volume, path)
                else:
                    try:
                        hash(inode)
                    except TypeError:
                        continue

                size = max(0, int(obj.get("size", 0)))
                if inode not in inode_size:
                    first_volume[inode] = volume
                    inode_size[inode] = size
                else:
                    inode_size[inode] = max(inode_size[inode], size)

        for inode, size in inode_size.items():
            volume = first_volume[inode]
            by_volume[volume] = by_volume.get(volume, 0) + size

        total = sum(by_volume.values())
        return total, by_volume

    def _derive_state_locked(self, tenant: str, now_dt: datetime) -> str:
        state = self._states.get(tenant)
        if not isinstance(state, dict):
            return "ok"
        if state.get("frozen"):
            return "frozen"

        _, by_volume = self._usage_locked(tenant)
        grace = state.get("grace")
        if not isinstance(grace, dict):
            return str(state.get("state", "ok"))

        active = False
        expired = False
        for volume in list(grace.keys()):
            marker = grace.get(volume)
            if not isinstance(marker, dict):
                continue
            soft_limit = self._soft_limit_for_locked(tenant, volume)
            if by_volume.get(volume, 0) <= soft_limit:
                grace.pop(volume, None)
                continue

            try:
                deadline = _parse_datetime(marker.get("deadline"))
            except Exception:
                continue
            if now_dt >= deadline:
                expired = True
            else:
                active = True

        if expired:
            return "frozen"
        if active:
            return "grace"
        return "ok"

    def _append_audit_locked(self, action: str, tenant: str, volume: str,
                             path: str, outcome: str, code: str | None,
                             usage_after: int) -> AuditEntry:
        seq = self._counters["audit_seq"] + 1
        self._counters["audit_seq"] = seq
        entry = AuditEntry(
            seq=seq,
            action=action,
            tenant=tenant,
            volume=volume,
            path=path,
            outcome=outcome,
            code=code,
            usage_after=usage_after,
        )
        self._audit.append(entry)
        self._stats["audit_writes"] += 1
        return entry

    def _freeze_locked(self, tenant: str, reason: object, now_dt: datetime,
                       source: str, code: str | None) -> bool:
        state = self._state_record_locked(tenant)
        if state.get("frozen"):
            return False

        usage_after, _ = self._usage_locked(tenant)
        state["frozen"] = True
        state["state"] = "frozen"
        state["frozen_at"] = _iso(now_dt)
        state["frozen_reason"] = copy.deepcopy(reason)
        state["freeze_source"] = source
        self._stats["frozen"] += 1
        self._append_audit_locked(
            "freeze", tenant, "", "", "frozen", code, usage_after)
        return True

    def _deny_admission_locked(
            self, *, tenant: str, volume: str, path: str, size: int,
            action: str, code: str, usage: int, remaining: int,
            grace_deadline: str | None, now_dt: datetime,
            freeze_source: str | None = None,
            freeze_reason: object = None) -> WriteDecision:
        self._stats["denied"] += 1
        decision = WriteDecision(
            tenant=tenant,
            volume=volume,
            path=path,
            size=size,
            outcome="denied",
            state="frozen",
            code=code,
            usage=usage,
            remaining=remaining,
            grace_deadline=grace_deadline,
        )
        self._append_audit_locked(
            action, tenant, volume, path, "denied", code, usage)
        if freeze_source is not None:
            self._freeze_locked(
                tenant,
                freeze_reason or code,
                now_dt,
                freeze_source,
                code,
            )
        return decision

    def _admit_delta_locked(
            self, tenant: str, volume: str, path: str, delta: int,
            inode: object, now_dt: datetime,
            audit_action: str) -> WriteDecision:
        key = (tenant, volume, path)
        current_total, current_by_volume = self._usage_locked(tenant)
        current_usage = current_by_volume.get(volume, 0)
        soft_limit, hard_limit = self._limits_for_locked(tenant, volume)
        tenant_limit = self._tenant_limit_for_locked(tenant)
        state = self._state_record_locked(tenant)

        old = self._objects.get(key)
        old_size = int(old.get("size", 0)) if old is not None else 0
        target_size = old_size + delta
        if inode is None and old is not None:
            inode = old.get("inode")
        if inode is None:
            inode = self._synthetic_inode(tenant, volume, path)

        candidate_objects = dict(self._objects)
        candidate_objects[key] = {"size": target_size, "inode": inode}
        candidate_total, candidate_by_volume = self._usage_locked(
            tenant, candidate_objects)
        candidate_usage = candidate_by_volume.get(volume, 0)
        current_remaining = hard_limit - current_usage

        if state.get("frozen") and state.get("freeze_source") == "admin":
            return self._deny_admission_locked(
                tenant=tenant,
                volume=volume,
                path=path,
                size=delta,
                action=audit_action,
                code=ERR_TENANT_FROZEN,
                usage=current_usage,
                remaining=current_remaining,
                grace_deadline=None,
                now_dt=now_dt,
            )

        if candidate_usage > hard_limit:
            grace = state.get("grace", {})
            marker = grace.get(volume) if isinstance(grace, dict) else None
            deadline = marker.get("deadline") if isinstance(marker, dict) else None
            return self._deny_admission_locked(
                tenant=tenant,
                volume=volume,
                path=path,
                size=delta,
                action=audit_action,
                code=ERR_HARD_LIMIT,
                usage=current_usage,
                remaining=current_remaining,
                grace_deadline=deadline,
                now_dt=now_dt,
                freeze_source="hard_limit",
                freeze_reason="hard limit exceeded",
            )

        if tenant_limit is not None and candidate_total > tenant_limit:
            return self._deny_admission_locked(
                tenant=tenant,
                volume=volume,
                path=path,
                size=delta,
                action=audit_action,
                code=ERR_TENANT_LIMIT,
                usage=current_usage,
                remaining=current_remaining,
                grace_deadline=None,
                now_dt=now_dt,
                freeze_source="tenant_limit",
                freeze_reason="tenant aggregate limit exceeded",
            )

        grace = state["grace"]
        marker = grace.get(volume)
        grace_deadline = None
        if candidate_usage > soft_limit:
            if isinstance(marker, dict):
                grace_deadline = marker.get("deadline")
                try:
                    deadline = _parse_datetime(grace_deadline)
                except Exception:
                    deadline = None
                if deadline is not None and now_dt >= deadline:
                    return self._deny_admission_locked(
                        tenant=tenant,
                        volume=volume,
                        path=path,
                        size=delta,
                        action=audit_action,
                        code=ERR_GRACE_EXPIRED,
                        usage=current_usage,
                        remaining=current_remaining,
                        grace_deadline=grace_deadline,
                        now_dt=now_dt,
                        freeze_source="grace_expired",
                        freeze_reason="grace period expired",
                    )
            else:
                deadline = now_dt + timedelta(seconds=self.grace_seconds)
                marker = {
                    "started_at": _iso(now_dt),
                    "deadline": _iso(deadline),
                }
                grace[volume] = marker
                grace_deadline = marker["deadline"]
                self._stats["grace_entered"] += 1

        if state.get("frozen"):
            return self._deny_admission_locked(
                tenant=tenant,
                volume=volume,
                path=path,
                size=delta,
                action=audit_action,
                code=ERR_TENANT_FROZEN,
                usage=current_usage,
                remaining=current_remaining,
                grace_deadline=grace_deadline,
                now_dt=now_dt,
            )

        if candidate_usage <= soft_limit:
            outcome = "allowed"
            grace.pop(volume, None)
            grace_deadline = None
        else:
            outcome = "grace"

        self._objects[key] = candidate_objects[key]
        if outcome == "allowed":
            self._stats["admitted"] += 1
        else:
            self._stats["grace_admitted"] += 1
        self._stats["written_bytes"] += delta

        self._append_audit_locked(
            audit_action,
            tenant,
            volume,
            path,
            outcome,
            None,
            candidate_usage,
        )

        if candidate_usage >= hard_limit:
            self._freeze_locked(
                tenant,
                "hard limit reached",
                now_dt,
                "hard_limit",
                ERR_HARD_LIMIT,
            )
        elif tenant_limit is not None and candidate_total >= tenant_limit:
            self._freeze_locked(
                tenant,
                "tenant aggregate limit reached",
                now_dt,
                "tenant_limit",
                ERR_TENANT_LIMIT,
            )

        tenant_state = self._derive_state_locked(tenant, now_dt)
        return WriteDecision(
            tenant=tenant,
            volume=volume,
            path=path,
            size=delta,
            outcome=outcome,
            state=tenant_state,
            code=None,
            usage=candidate_usage,
            remaining=hard_limit - candidate_usage,
            grace_deadline=grace_deadline,
        )

    def _build_restored_state(self, state: object) -> dict:
        if not isinstance(state, dict):
            raise QuotaError(ERR_SNAPSHOT_INVALID, {"state_type": type(state)})
        if set(state.keys()) != set(_SNAPSHOT_KEYS):
            raise QuotaError(ERR_SNAPSHOT_INVALID, {
                "keys": sorted(str(key) for key in state.keys()),
            })
        version = state["version"]
        if not _positive_int(version) or version != SCHEMA_VERSION:
            raise QuotaError(ERR_SNAPSHOT_INVALID, {"version": version})

        raw_volumes = state["volumes"]
        if not isinstance(raw_volumes, list):
            raise QuotaError(ERR_SNAPSHOT_INVALID, {
                "volumes": type(raw_volumes),
            })
        volumes: list[str] = []
        for volume in raw_volumes:
            if not isinstance(volume, str) or not volume or volume in volumes:
                raise QuotaError(ERR_SNAPSHOT_INVALID, {"volume": volume})
            volumes.append(volume)

        raw_policies = state["policies"]
        if not isinstance(raw_policies, dict):
            raise QuotaError(ERR_SNAPSHOT_INVALID, {
                "policies": type(raw_policies),
            })
        policies: dict[tuple[str, str], QuotaPolicy] = {}
        for tenant, volume_map in raw_policies.items():
            if not isinstance(tenant, str) or not isinstance(volume_map, dict):
                raise QuotaError(ERR_SNAPSHOT_INVALID, {"policies": tenant})
            for volume, raw_policy in volume_map.items():
                if not isinstance(volume, str) or volume not in volumes:
                    raise QuotaError(ERR_SNAPSHOT_INVALID, {"volume": volume})
                if not isinstance(raw_policy, dict):
                    raise QuotaError(ERR_SNAPSHOT_INVALID, {
                        "policy": raw_policy,
                    })
                soft_limit = raw_policy.get("soft_limit")
                hard_limit = raw_policy.get("hard_limit")
                if (not _positive_int(soft_limit)
                        or not _positive_int(hard_limit)
                        or soft_limit >= hard_limit):
                    raise QuotaError(ERR_SNAPSHOT_INVALID, {
                        "policy": raw_policy,
                    })
                policy_tenant = raw_policy.get("tenant", tenant)
                policy_volume = raw_policy.get("volume", volume)
                if policy_tenant != tenant or policy_volume != volume:
                    raise QuotaError(ERR_SNAPSHOT_INVALID, {
                        "policy": raw_policy,
                    })
                policies[(tenant, volume)] = QuotaPolicy(
                    tenant, volume, soft_limit, hard_limit)

        raw_limits = state["tenant_limits"]
        if not isinstance(raw_limits, dict):
            raise QuotaError(ERR_SNAPSHOT_INVALID, {
                "tenant_limits": type(raw_limits),
            })
        tenant_limits: dict[str, int] = {}
        for tenant, limit in raw_limits.items():
            if not isinstance(tenant, str) or not _positive_int(limit):
                raise QuotaError(ERR_SNAPSHOT_INVALID, {
                    "tenant_limit": limit,
                })
            tenant_limits[tenant] = limit

        raw_objects = state["objects"]
        if not isinstance(raw_objects, dict):
            raise QuotaError(ERR_SNAPSHOT_INVALID, {
                "objects": type(raw_objects),
            })
        objects: dict[tuple[str, str, str], dict] = {}
        for tenant, volume_map in raw_objects.items():
            if not isinstance(tenant, str) or not isinstance(volume_map, dict):
                raise QuotaError(ERR_SNAPSHOT_INVALID, {"objects": tenant})
            for volume, path_map in volume_map.items():
                if (not isinstance(volume, str) or volume not in volumes
                        or not isinstance(path_map, dict)):
                    raise QuotaError(ERR_SNAPSHOT_INVALID, {"volume": volume})
                for path, obj in path_map.items():
                    if not isinstance(path, str) or not path:
                        raise QuotaError(ERR_SNAPSHOT_INVALID, {"path": path})
                    if not isinstance(obj, dict):
                        raise QuotaError(ERR_SNAPSHOT_INVALID, {"object": obj})
                    size = obj.get("size")
                    if not _non_negative_int(size):
                        raise QuotaError(ERR_SNAPSHOT_INVALID, {"object": obj})
                    inode = obj.get("inode")
                    try:
                        hash(inode)
                    except TypeError as exc:
                        raise QuotaError(ERR_SNAPSHOT_INVALID, {
                            "inode": inode,
                        }) from exc
                    objects[(tenant, volume, path)] = {
                        "size": size,
                        "inode": inode,
                    }

        raw_states = state["states"]
        if not isinstance(raw_states, dict):
            raise QuotaError(ERR_SNAPSHOT_INVALID, {
                "states": type(raw_states),
            })
        states = copy.deepcopy(raw_states)
        for tenant, tenant_state in states.items():
            if not isinstance(tenant, str) or not isinstance(
                    tenant_state, dict):
                raise QuotaError(ERR_SNAPSHOT_INVALID, {"state": tenant_state})
            if not isinstance(tenant_state.get("frozen", False), bool):
                raise QuotaError(ERR_SNAPSHOT_INVALID, {"state": tenant_state})
            if tenant_state.get("state", "ok") not in STATES:
                raise QuotaError(ERR_SNAPSHOT_INVALID, {"state": tenant_state})
            grace = tenant_state.get("grace", {})
            if not isinstance(grace, dict):
                raise QuotaError(ERR_SNAPSHOT_INVALID, {"state": tenant_state})
            for volume, marker in grace.items():
                if not isinstance(volume, str) or volume not in volumes:
                    raise QuotaError(ERR_SNAPSHOT_INVALID, {"grace": grace})
                if not isinstance(marker, dict):
                    raise QuotaError(ERR_SNAPSHOT_INVALID, {"marker": marker})
                for time_key in ("started_at", "deadline"):
                    value = marker.get(time_key)
                    if not isinstance(value, str):
                        raise QuotaError(ERR_SNAPSHOT_INVALID, {
                            "marker": marker,
                        })
                    try:
                        _parse_datetime(value)
                    except Exception as exc:
                        raise QuotaError(ERR_SNAPSHOT_INVALID, {
                            "marker": marker,
                        }) from exc

        raw_audit = state["audit"]
        if not isinstance(raw_audit, list):
            raise QuotaError(ERR_SNAPSHOT_INVALID, {
                "audit": type(raw_audit),
            })
        audit: list[AuditEntry] = []
        expected_seq = 1
        for raw_entry in raw_audit:
            if isinstance(raw_entry, AuditEntry):
                entry = raw_entry
            elif isinstance(raw_entry, dict):
                try:
                    entry = AuditEntry(
                        seq=raw_entry["seq"],
                        action=raw_entry["action"],
                        tenant=raw_entry["tenant"],
                        volume=raw_entry["volume"],
                        path=raw_entry["path"],
                        outcome=raw_entry["outcome"],
                        code=raw_entry.get("code"),
                        usage_after=raw_entry["usage_after"],
                    )
                except (KeyError, TypeError) as exc:
                    raise QuotaError(ERR_SNAPSHOT_INVALID, {
                        "audit": raw_entry,
                    }) from exc
            else:
                raise QuotaError(ERR_SNAPSHOT_INVALID, {"audit": raw_entry})

            if (not isinstance(entry.seq, int)
                    or isinstance(entry.seq, bool)
                    or entry.seq != expected_seq
                    or not isinstance(entry.action, str)
                    or not isinstance(entry.tenant, str)
                    or not isinstance(entry.volume, str)
                    or not isinstance(entry.path, str)
                    or not isinstance(entry.outcome, str)
                    or (entry.code is not None
                        and not isinstance(entry.code, str))
                    or not _non_negative_int(entry.usage_after)):
                raise QuotaError(ERR_SNAPSHOT_INVALID, {"audit": raw_entry})
            audit.append(entry)
            expected_seq += 1

        raw_stats = state["stats"]
        if (not isinstance(raw_stats, dict)
                or set(raw_stats.keys()) != set(_STATS_KEYS)):
            raise QuotaError(ERR_SNAPSHOT_INVALID, {
                "stats": type(raw_stats),
            })
        stats = {}
        for key in _STATS_KEYS:
            value = raw_stats.get(key)
            if not _non_negative_int(value):
                raise QuotaError(ERR_SNAPSHOT_INVALID, {"stat": key})
            stats[key] = value

        return {
            "volumes": copy.deepcopy(volumes),
            "policies": copy.deepcopy(policies),
            "tenant_limits": copy.deepcopy(tenant_limits),
            "objects": copy.deepcopy(objects),
            "states": states,
            "audit": list(audit),
            "stats": copy.deepcopy(stats),
        }
