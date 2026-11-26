"""perf_event exposure governance: paranoid tiers, per-cgroup quota, revocation."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any


class PerfAccessError(ValueError):
    """Raised when a performance-event request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class RequestRecord:
    request_id: str
    requester: str
    event_type: str
    cgroup: str
    target_pid: int | None = None
    target_cpu: int | None = None
    kernel: bool = False
    privileged: bool = False
    level: int = 2
    created_at: str = ""
    expires_at: str | None = None


@dataclass
class _RequestState:
    record: RequestRecord
    status: str = "approved"
    fd: int | None = None
    open_refs: int = 0
    quota_charged: bool = False
    pool_charged: bool = False
    inherited_from: str | None = None


@dataclass
class _Descriptor:
    fd: int
    cgroup: str
    target_pid: int | None
    target_cpu: int | None
    refs: list[str] = field(default_factory=list)

    @property
    def key(self) -> tuple[str, int | None, int | None]:
        return (self.cgroup, self.target_pid, self.target_cpu)


class PerfAccessGovernor:
    """Decide who may open which perf events and keep the active set bounded."""

    _STAT_KEYS = (
        "granted",
        "denied",
        "opened",
        "closed",
        "revoked",
        "quota_denied",
        "privilege_denied",
        "review_closed",
        "blacklisted",
    )
    _LIVE_STATES = ("approved", "open")
    _TERMINAL_STATES = ("closed", "revoked", "expired")

    def __init__(self, *, paranoid: int = 2, max_events_per_cgroup: int = 4,
                 privilege_pool: int = 2, privilege_ttl: int = 60,
                 clock=None) -> None:
        if not self._valid_int(paranoid) or not 0 <= paranoid <= 4:
            raise PerfAccessError("PERF_BAD_PARANOID", paranoid)
        if not self._valid_int(max_events_per_cgroup) or max_events_per_cgroup < 0:
            raise PerfAccessError("PERF_BAD_REQUEST", "max_events_per_cgroup")
        if not self._valid_int(privilege_pool) or privilege_pool < 0:
            raise PerfAccessError("PERF_BAD_REQUEST", "privilege_pool")
        if not self._valid_int(privilege_ttl) or privilege_ttl < 0:
            raise PerfAccessError("PERF_BAD_REQUEST", "privilege_ttl")

        self.paranoid = paranoid
        self.max_events_per_cgroup = max_events_per_cgroup
        self.privilege_pool = privilege_pool
        self.privilege_ttl = privilege_ttl
        self._clock = clock
        self._lock = threading.RLock()

        self._blacklist: set[str] = set()
        self._whitelist: set[str] = set()
        self._requests: dict[str, _RequestState] = {}
        self._descriptors: dict[int, _Descriptor] = {}
        self._fd_by_key: dict[tuple[str, int | None, int | None], int] = {}
        self._quota: dict[str, int] = {}
        self._privilege_used = 0
        self._next_request_seq = 0
        self._next_fd = 3
        self._audit: list[dict[str, Any]] = []
        self._stats = {key: 0 for key in self._STAT_KEYS}

    # ------------------------------------------------------------------
    # small helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _valid_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _nonempty_str(value: object) -> bool:
        return isinstance(value, str) and bool(value)

    def _now_value(self, now: str | datetime | None) -> str | datetime:
        if now is not None:
            return now
        if self._clock is not None:
            return self._clock()
        return datetime.now(timezone.utc)

    @staticmethod
    def _parse_ts(value: object) -> datetime | None:
        if isinstance(value, datetime):
            parsed = value
        elif isinstance(value, str):
            try:
                parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                return None
        else:
            return None
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed

    def _now_string(self, now: str | datetime | None) -> str:
        value = self._now_value(now)
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, str):
            return value
        return str(value)

    def _expires_string(self, created_at: object) -> str | None:
        created = self._parse_ts(created_at)
        if created is None:
            return None
        return (created + timedelta(seconds=self.privilege_ttl)).isoformat()

    def _audit_event(self, action: str, *, requester: str = "",
                     event_type: str = "", cgroup: str = "",
                     request_id: str | None = None,
                     at: str | None = None,
                     **extra: object) -> None:
        entry: dict[str, Any] = {
            "action": action,
            "requester": requester,
            "event_type": event_type,
            "cgroup": cgroup,
        }
        if request_id is not None:
            entry["request_id"] = request_id
        if at is not None:
            entry["at"] = at
        for key, value in extra.items():
            if value is not None:
                entry[key] = value
        self._audit.append(entry)

    def _deny(self, code: str, detail: object, *, requester: str = "",
              event_type: str = "", cgroup: str = "",
              at: str | None = None, **extra: object) -> None:
        self._stats["denied"] += 1
        self._audit_event("denied", requester=requester,
                          event_type=event_type, cgroup=cgroup, at=at,
                          code=code, **extra)
        raise PerfAccessError(code, detail)

    def _tier_denied(self, event_type: str, target_cpu: int | None,
                     kernel: bool, privileged: bool) -> bool:
        """Return whether the current policy denies this authorization."""
        if self.paranoid == 4:
            return True
        level = max(0, self.paranoid - 1) if privileged else self.paranoid
        if kernel and level >= 2:
            return True
        if target_cpu is not None and level >= 3:
            if event_type in self._whitelist and level == 3:
                return False
            return True
        return False

    def _policy_denied(self, event_type: str, target_cpu: int | None,
                       kernel: bool, privileged: bool) -> bool:
        return (event_type in self._blacklist
                or self._tier_denied(event_type, target_cpu, kernel, privileged))

    def _quota_add(self, cgroup: str) -> None:
        self._quota[cgroup] = self._quota.get(cgroup, 0) + 1

    def _quota_drop(self, cgroup: str) -> None:
        current = self._quota.get(cgroup, 0)
        if current <= 1:
            self._quota.pop(cgroup, None)
        else:
            self._quota[cgroup] = current - 1

    def _remove_refs_locked(self, state: _RequestState) -> None:
        if state.fd is None:
            state.open_refs = 0
            return
        descriptor = self._descriptors.get(state.fd)
        if descriptor is not None:
            request_id = state.record.request_id
            descriptor.refs = [ref for ref in descriptor.refs if ref != request_id]
            if not descriptor.refs:
                self._descriptors.pop(descriptor.fd, None)
                self._fd_by_key.pop(descriptor.key, None)
        state.fd = None
        state.open_refs = 0

    def _retire_locked(self, state: _RequestState, action: str,
                       *, at: str | None = None, review: bool = False,
                       audit_action: str | None = None,
                       emit_audit: bool = True) -> bool:
        if state.status in self._TERMINAL_STATES:
            return False

        self._remove_refs_locked(state)
        if state.quota_charged:
            self._quota_drop(state.record.cgroup)
            state.quota_charged = False
        if state.pool_charged:
            self._privilege_used = max(0, self._privilege_used - 1)
            state.pool_charged = False

        if action == "revoked":
            state.status = "revoked"
            self._stats["revoked"] += 1
        elif action == "expired":
            state.status = "expired"
        else:
            state.status = "closed"
        if review:
            self._stats["review_closed"] += 1

        if emit_audit:
            self._audit_event(audit_action or action,
                              requester=state.record.requester,
                              event_type=state.record.event_type,
                              cgroup=state.record.cgroup,
                              request_id=state.record.request_id,
                              at=at)
        return True

    def _live_records_locked(self) -> list[_RequestState]:
        return [state for state in self._requests.values()
                if state.status in self._LIVE_STATES]

    def _is_expired(self, state: _RequestState, now: object) -> bool:
        if not state.record.privileged or state.record.expires_at is None:
            return False
        expires = self._parse_ts(state.record.expires_at)
        current = self._parse_ts(now)
        if expires is None or current is None:
            return False
        return expires <= current

    # ------------------------------------------------------------------
    # policy and request admission
    # ------------------------------------------------------------------
    def set_paranoid(self, level: int) -> None:
        with self._lock:
            at = self._now_string(None)
            if not self._valid_int(level) or not 0 <= level <= 4:
                self._deny("PERF_BAD_PARANOID", level, at=at)
            self.paranoid = level
            self._audit_event("paranoid_changed", at=at, level=level)

    def add_blacklist(self, event_type: str) -> int:
        with self._lock:
            self._blacklist.add(event_type)
            return len(self._blacklist)

    def add_whitelist(self, event_type: str) -> int:
        with self._lock:
            self._whitelist.add(event_type)
            return len(self._whitelist)

    def request(self, *, requester: str, event_type: str, cgroup: str,
                target_pid: int | None = None, target_cpu: int | None = None,
                kernel: bool = False, privileged: bool = False,
                now: str | None = None) -> RequestRecord:
        with self._lock:
            at = self._now_string(now)
            if (not self._nonempty_str(requester)
                    or not self._nonempty_str(event_type)
                    or not self._nonempty_str(cgroup)):
                self._deny("PERF_BAD_REQUEST", "requester/event_type/cgroup",
                           requester=requester if isinstance(requester, str) else "",
                           event_type=event_type if isinstance(event_type, str) else "",
                           cgroup=cgroup if isinstance(cgroup, str) else "",
                           at=at)

            if (target_pid is None) == (target_cpu is None):
                self._deny("PERF_BAD_TARGET", "exactly one target is required",
                           requester=requester, event_type=event_type,
                           cgroup=cgroup, at=at)
            if target_pid is not None:
                if not self._valid_int(target_pid) or target_pid <= 0:
                    self._deny("PERF_BAD_TARGET", "target_pid",
                               requester=requester, event_type=event_type,
                               cgroup=cgroup, at=at)
            if target_cpu is not None:
                if not self._valid_int(target_cpu) or target_cpu < 0:
                    self._deny("PERF_BAD_TARGET", "target_cpu",
                               requester=requester, event_type=event_type,
                               cgroup=cgroup, at=at)

            if event_type in self._blacklist:
                self._stats["blacklisted"] += 1
                self._deny("PERF_BLACKLISTED", event_type,
                           requester=requester, event_type=event_type,
                           cgroup=cgroup, at=at)

            if self._tier_denied(event_type, target_cpu, bool(kernel),
                                 bool(privileged)):
                self._deny("PERF_PARANOID_DENIED", self.paranoid,
                           requester=requester, event_type=event_type,
                           cgroup=cgroup, at=at, level=self.paranoid)

            if privileged and self._privilege_used >= self.privilege_pool:
                self._stats["privilege_denied"] += 1
                self._deny("PERF_PRIVILEGE_EXHAUSTED", self.privilege_pool,
                           requester=requester, event_type=event_type,
                           cgroup=cgroup, at=at)

            if self._quota.get(cgroup, 0) >= self.max_events_per_cgroup:
                self._stats["quota_denied"] += 1
                self._deny("PERF_QUOTA_EXCEEDED", self.max_events_per_cgroup,
                           requester=requester, event_type=event_type,
                           cgroup=cgroup, at=at)

            self._next_request_seq += 1
            request_id = f"req-{self._next_request_seq}"
            level = max(0, self.paranoid - 1) if privileged else self.paranoid
            expires_at = self._expires_string(at) if privileged else None
            record = RequestRecord(
                request_id=request_id,
                requester=requester,
                event_type=event_type,
                cgroup=cgroup,
                target_pid=target_pid,
                target_cpu=target_cpu,
                kernel=bool(kernel),
                privileged=bool(privileged),
                level=level,
                created_at=at,
                expires_at=expires_at,
            )
            state = _RequestState(
                record=record,
                status="approved",
                quota_charged=True,
            )
            self._requests[request_id] = state
            self._quota_add(cgroup)
            if privileged:
                self._privilege_used += 1
                state.pool_charged = True
            self._stats["granted"] += 1
            self._audit_event("granted", requester=requester,
                              event_type=event_type, cgroup=cgroup,
                              request_id=request_id, at=at,
                              level=level, kernel=bool(kernel),
                              privileged=bool(privileged))
            return record

    # ------------------------------------------------------------------
    # descriptor lifecycle
    # ------------------------------------------------------------------
    def open(self, request_id: str, *, now: str | None = None) -> int:
        with self._lock:
            at = self._now_string(now)
            state = self._requests.get(request_id)
            if state is None:
                raise PerfAccessError("PERF_NOT_FOUND", request_id)
            if state.status in self._TERMINAL_STATES:
                raise PerfAccessError("PERF_REQUEST_CLOSED", request_id)
            if self._is_expired(state, at):
                self._retire_locked(state, "expired", at=at,
                                    audit_action="privilege_expired")
                raise PerfAccessError("PERF_REQUEST_CLOSED", request_id)

            descriptor = self._descriptors.get(state.fd) if state.fd is not None else None
            if descriptor is None:
                key = (state.record.cgroup, state.record.target_pid,
                       state.record.target_cpu)
                fd = self._fd_by_key.get(key)
                descriptor = self._descriptors.get(fd) if fd is not None else None
                if descriptor is None:
                    fd = self._next_fd
                    self._next_fd += 1
                    descriptor = _Descriptor(
                        fd=fd,
                        cgroup=state.record.cgroup,
                        target_pid=state.record.target_pid,
                        target_cpu=state.record.target_cpu,
                    )
                    self._descriptors[fd] = descriptor
                    self._fd_by_key[key] = fd

            descriptor.refs.append(request_id)
            state.fd = descriptor.fd
            state.open_refs += 1
            state.status = "open"
            self._stats["opened"] += 1
            self._audit_event("opened",
                              requester=state.record.requester,
                              event_type=state.record.event_type,
                              cgroup=state.record.cgroup,
                              request_id=request_id, at=at,
                              fd=descriptor.fd)
            return descriptor.fd

    def close(self, fd: int, *, now: str | None = None) -> dict:
        with self._lock:
            at = self._now_string(now)
            descriptor = self._descriptors.get(fd)
            if descriptor is None:
                raise PerfAccessError("PERF_BAD_FD", fd)

            request_id = descriptor.refs.pop(0)
            state = self._requests.get(request_id)
            if state is not None:
                state.open_refs = max(0, state.open_refs - 1)
                requester = state.record.requester
                event_type = state.record.event_type
                cgroup = state.record.cgroup
                if state.open_refs == 0:
                    state.fd = None
                    self._retire_locked(state, "closed", at=at, emit_audit=False)
            else:
                requester = event_type = cgroup = ""

            self._stats["closed"] += 1
            if descriptor.refs:
                refcount = len(descriptor.refs)
                closed = False
            else:
                self._descriptors.pop(fd, None)
                self._fd_by_key.pop(descriptor.key, None)
                refcount = 0
                closed = True

            self._audit_event("closed", requester=requester,
                              event_type=event_type, cgroup=cgroup,
                              request_id=request_id, at=at,
                              fd=fd, refcount=refcount, fully_closed=closed)
            return {"fd": fd, "refcount": refcount, "closed": closed}

    def revoke(self, *, requester: str | None = None, cgroup: str | None = None,
               event_type: str | None = None, now: str | None = None) -> int:
        with self._lock:
            at = self._now_string(now)
            matches = []
            for state in self._requests.values():
                if state.status not in self._LIVE_STATES:
                    continue
                record = state.record
                if requester is not None and record.requester != requester:
                    continue
                if cgroup is not None and record.cgroup != cgroup:
                    continue
                if event_type is not None and record.event_type != event_type:
                    continue
                matches.append(state)

            for state in matches:
                self._retire_locked(state, "revoked", at=at)
            return len(matches)

    def review(self, *, now: str | None = None) -> dict:
        with self._lock:
            at = self._now_string(now)
            privilege_expired = 0
            degraded = 0

            for state in list(self._live_records_locked()):
                if self._is_expired(state, at):
                    if self._retire_locked(state, "expired", at=at,
                                           review=True,
                                           audit_action="privilege_expired"):
                        privilege_expired += 1

            for state in list(self._live_records_locked()):
                record = state.record
                if self._policy_denied(record.event_type, record.target_cpu,
                                       record.kernel, record.privileged):
                    if self._retire_locked(state, "closed", at=at, review=True,
                                           audit_action="review_closed"):
                        degraded += 1

            return {
                "privilege_expired": privilege_expired,
                "closed": privilege_expired + degraded,
                "degraded": degraded,
            }

    # ------------------------------------------------------------------
    # fork / inheritance
    # ------------------------------------------------------------------
    def inherit(self, parent_pid: int, child_pid: int, *,
                now: str | None = None) -> int:
        with self._lock:
            at = self._now_string(now)
            if (not self._valid_int(parent_pid) or parent_pid <= 0
                    or not self._valid_int(child_pid) or child_pid <= 0):
                self._deny("PERF_BAD_TARGET", "parent_pid/child_pid", at=at)
            if parent_pid == child_pid:
                return 0

            parents = [
                state for state in self._requests.values()
                if state.record.target_pid == parent_pid
                and state.status in self._LIVE_STATES
            ]
            inherited = 0
            for parent in parents:
                child_id = None
                for state in self._requests.values():
                    if (state.inherited_from == parent.record.request_id
                            and state.record.target_pid == child_pid
                            and state.status in self._LIVE_STATES):
                        child_id = state.record.request_id
                        break
                if child_id is not None:
                    continue

                self._next_request_seq += 1
                request_id = f"req-{self._next_request_seq}"
                parent_record = parent.record
                expires_at = (self._expires_string(at)
                              if parent_record.privileged else None)
                record = RequestRecord(
                    request_id=request_id,
                    requester=parent_record.requester,
                    event_type=parent_record.event_type,
                    cgroup=parent_record.cgroup,
                    target_pid=child_pid,
                    target_cpu=None,
                    kernel=parent_record.kernel,
                    privileged=parent_record.privileged,
                    level=parent_record.level,
                    created_at=at,
                    expires_at=expires_at,
                )
                # Forked events are part of the same monitored workload, so
                # they neither consume another cgroup quota slot nor another
                # privilege-pool slot.
                child = _RequestState(
                    record=record,
                    status="approved",
                    quota_charged=False,
                    pool_charged=False,
                    inherited_from=parent_record.request_id,
                )
                self._requests[request_id] = child

                if parent.status == "open":
                    key = (record.cgroup, record.target_pid, record.target_cpu)
                    fd = self._fd_by_key.get(key)
                    descriptor = self._descriptors.get(fd) if fd is not None else None
                    if descriptor is None:
                        fd = self._next_fd
                        self._next_fd += 1
                        descriptor = _Descriptor(
                            fd=fd,
                            cgroup=record.cgroup,
                            target_pid=record.target_pid,
                            target_cpu=record.target_cpu,
                        )
                        self._descriptors[fd] = descriptor
                        self._fd_by_key[key] = fd
                    descriptor.refs.append(request_id)
                    child.fd = descriptor.fd
                    child.open_refs = 1
                    child.status = "open"

                inherited += 1
                self._audit_event("inherited",
                                  requester=record.requester,
                                  event_type=record.event_type,
                                  cgroup=record.cgroup,
                                  request_id=request_id, at=at,
                                  parent_pid=parent_pid, child_pid=child_pid)
            return inherited

    # ------------------------------------------------------------------
    # views / audit / stats
    # ------------------------------------------------------------------
    def audit(self, *, now: str | None = None) -> list:
        with self._lock:
            return copy.deepcopy(self._audit)

    def active(self) -> list:
        with self._lock:
            result = []
            for fd in sorted(self._descriptors):
                descriptor = self._descriptors[fd]
                if not descriptor.refs:
                    continue
                result.append({
                    "fd": descriptor.fd,
                    "cgroup": descriptor.cgroup,
                    "target_pid": descriptor.target_pid,
                    "target_cpu": descriptor.target_cpu,
                    "refcount": len(descriptor.refs),
                })
            return result

    def status(self) -> dict:
        with self._lock:
            active = self.active()
            degraded = 0
            expired = 0
            at = self._now_string(None)
            for state in self._live_records_locked():
                record = state.record
                if self._is_expired(state, at):
                    expired += 1
                if self._policy_denied(record.event_type, record.target_cpu,
                                       record.kernel, record.privileged):
                    degraded += 1
            return {
                "paranoid": self.paranoid,
                "active": active,
                "active_count": len(active),
                "degraded": degraded,
                "expired": expired,
                "privileged_active": self._privilege_used,
            }

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    # ------------------------------------------------------------------
    # snapshot / restore
    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        with self._lock:
            requests: dict[str, dict[str, Any]] = {}
            for request_id, state in self._requests.items():
                record = state.record
                requests[request_id] = {
                    "request_id": record.request_id,
                    "requester": record.requester,
                    "event_type": record.event_type,
                    "cgroup": record.cgroup,
                    "target_pid": record.target_pid,
                    "target_cpu": record.target_cpu,
                    "kernel": record.kernel,
                    "privileged": record.privileged,
                    "level": record.level,
                    "created_at": record.created_at,
                    "expires_at": record.expires_at,
                    "status": state.status,
                    "fd": state.fd,
                    "open_refs": state.open_refs,
                    "quota_charged": state.quota_charged,
                    "pool_charged": state.pool_charged,
                    "inherited_from": state.inherited_from,
                }

            descriptors: dict[str, dict[str, Any]] = {}
            for fd, descriptor in self._descriptors.items():
                descriptors[str(fd)] = {
                    "fd": descriptor.fd,
                    "cgroup": descriptor.cgroup,
                    "target_pid": descriptor.target_pid,
                    "target_cpu": descriptor.target_cpu,
                    "refs": list(descriptor.refs),
                }

            active = self.active()
            state = {
                "format": "perf-access-governor",
                "version": 1,
                "paranoid": self.paranoid,
                "max_events_per_cgroup": self.max_events_per_cgroup,
                "privilege_pool": self.privilege_pool,
                "privilege_ttl": self.privilege_ttl,
                "blacklist": sorted(self._blacklist),
                "whitelist": sorted(self._whitelist),
                "quota": dict(self._quota),
                "privilege_used": self._privilege_used,
                "next_request_seq": self._next_request_seq,
                "next_fd": self._next_fd,
                "requests": requests,
                "descriptors": descriptors,
                "active": active,
                "collections": active,
                "audit": copy.deepcopy(self._audit),
                "stats": dict(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                candidate = self._parse_snapshot(state)
                self._revalidate_candidate(candidate)
            except PerfAccessError:
                raise
            except Exception as exc:
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", str(exc)) from exc

            self.paranoid = candidate["paranoid"]
            self.max_events_per_cgroup = candidate["max_events_per_cgroup"]
            self.privilege_pool = candidate["privilege_pool"]
            self.privilege_ttl = candidate["privilege_ttl"]
            self._blacklist = candidate["blacklist"]
            self._whitelist = candidate["whitelist"]
            self._quota = candidate["quota"]
            self._privilege_used = candidate["privilege_used"]
            self._next_request_seq = candidate["next_request_seq"]
            self._next_fd = candidate["next_fd"]
            self._requests = candidate["requests"]
            self._descriptors = candidate["descriptors"]
            self._fd_by_key = candidate["fd_by_key"]
            self._audit = candidate["audit"]
            self._stats = candidate["stats"]

    def _parse_snapshot(self, state: object) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "state")
        if "collections" in state and not isinstance(state["collections"], list):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "collections")
        if "active" in state and not isinstance(state["active"], list):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "active")
        if "paranoid" not in state:
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "paranoid")

        paranoid = state["paranoid"]
        if not self._valid_int(paranoid) or not 0 <= paranoid <= 4:
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "paranoid")
        max_events = state.get("max_events_per_cgroup", 4)
        pool = state.get("privilege_pool", 2)
        ttl = state.get("privilege_ttl", 60)
        for value in (max_events, pool, ttl):
            if not self._valid_int(value) or value < 0:
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "config")

        blacklist_raw = state.get("blacklist", [])
        whitelist_raw = state.get("whitelist", [])
        if not isinstance(blacklist_raw, (list, tuple, set)):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "blacklist")
        if not isinstance(whitelist_raw, (list, tuple, set)):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "whitelist")
        blacklist = set(blacklist_raw)
        whitelist = set(whitelist_raw)
        if (any(not isinstance(item, str) for item in blacklist)
                or any(not isinstance(item, str) for item in whitelist)):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "policy")

        quota_raw = state.get("quota", {})
        if not isinstance(quota_raw, dict):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "quota")
        quota: dict[str, int] = {}
        for cgroup, count in quota_raw.items():
            if (not isinstance(cgroup, str) or not self._valid_int(count)
                    or count < 0):
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "quota")
            if count:
                quota[cgroup] = count

        requests_raw = state.get("requests", {})
        descriptors_raw = state.get("descriptors", {})
        if not isinstance(requests_raw, dict) or not isinstance(descriptors_raw, dict):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "collections")

        requests: dict[str, _RequestState] = {}
        for key, item in requests_raw.items():
            if not isinstance(key, str) or not isinstance(item, dict):
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "request")
            record = self._record_from_snapshot(item)
            if record.request_id != key:
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "request_id")
            status = item.get("status", "approved")
            if status not in self._LIVE_STATES + self._TERMINAL_STATES:
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "status")
            fd = item.get("fd")
            if fd is not None and not self._valid_int(fd):
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "fd")
            open_refs = item.get("open_refs", 0)
            if not self._valid_int(open_refs) or open_refs < 0:
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "open_refs")
            quota_charged = item.get("quota_charged", False)
            pool_charged = item.get("pool_charged", False)
            inherited_from = item.get("inherited_from")
            if not isinstance(quota_charged, bool) or not isinstance(pool_charged, bool):
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "charge")
            if inherited_from is not None and not isinstance(inherited_from, str):
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "inherited_from")
            requests[key] = _RequestState(
                record=record,
                status=status,
                fd=fd,
                open_refs=open_refs,
                quota_charged=quota_charged,
                pool_charged=pool_charged,
                inherited_from=inherited_from,
            )

        descriptors: dict[int, _Descriptor] = {}
        fd_by_key: dict[tuple[str, int | None, int | None], int] = {}
        for key, item in descriptors_raw.items():
            if not isinstance(key, str) or not isinstance(item, dict):
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "descriptor")
            fd = item.get("fd")
            if not self._valid_int(fd) or fd < 3:
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "fd")
            try:
                if int(key) != fd:
                    raise ValueError
            except ValueError as exc:
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "fd") from exc
            cgroup = item.get("cgroup")
            if not self._nonempty_str(cgroup):
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "cgroup")
            target_pid = item.get("target_pid")
            target_cpu = item.get("target_cpu")
            if (target_pid is None) == (target_cpu is None):
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "target")
            if target_pid is not None and (
                    not self._valid_int(target_pid) or target_pid <= 0):
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "target_pid")
            if target_cpu is not None and (
                    not self._valid_int(target_cpu) or target_cpu < 0):
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "target_cpu")
            refs = item.get("refs", [])
            if not isinstance(refs, list) or any(
                    not isinstance(ref, str) for ref in refs):
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "refs")
            descriptor = _Descriptor(
                fd=fd,
                cgroup=cgroup,
                target_pid=target_pid,
                target_cpu=target_cpu,
                refs=list(refs),
            )
            if descriptor.key in fd_by_key:
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "duplicate target")
            descriptors[fd] = descriptor
            fd_by_key[descriptor.key] = fd

        for request_id, request in requests.items():
            if request.status == "open":
                descriptor = descriptors.get(request.fd)
                if descriptor is None:
                    raise PerfAccessError("PERF_SNAPSHOT_INVALID", "open request")
                actual_refs = descriptor.refs.count(request_id)
                if actual_refs != request.open_refs or actual_refs <= 0:
                    raise PerfAccessError("PERF_SNAPSHOT_INVALID", "refcount")
                record = request.record
                if (descriptor.cgroup != record.cgroup
                        or descriptor.target_pid != record.target_pid
                        or descriptor.target_cpu != record.target_cpu):
                    raise PerfAccessError("PERF_SNAPSHOT_INVALID", "target")
            else:
                if request.fd is not None or request.open_refs != 0:
                    raise PerfAccessError("PERF_SNAPSHOT_INVALID", "closed request")

        for descriptor in descriptors.values():
            for request_id in descriptor.refs:
                request = requests.get(request_id)
                if request is None or request.status != "open":
                    raise PerfAccessError("PERF_SNAPSHOT_INVALID", "refs")

        expected_quota: dict[str, int] = {}
        for request in requests.values():
            if request.quota_charged:
                cgroup = request.record.cgroup
                expected_quota[cgroup] = expected_quota.get(cgroup, 0) + 1
        if expected_quota != quota:
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "quota")

        privilege_used = state.get("privilege_used",
                                   sum(1 for item in requests.values()
                                       if item.pool_charged))
        if not self._valid_int(privilege_used) or privilege_used < 0:
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "privilege_used")
        if privilege_used != sum(1 for item in requests.values()
                                 if item.pool_charged):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "privilege_used")

        max_request_seq = 0
        for request_id in requests:
            if request_id.startswith("req-"):
                try:
                    max_request_seq = max(max_request_seq, int(request_id[4:]))
                except ValueError:
                    pass
        next_request_seq = state.get("next_request_seq", max_request_seq)
        if (not self._valid_int(next_request_seq)
                or next_request_seq < max_request_seq):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "next_request_seq")

        max_fd = max(descriptors, default=2)
        next_fd = state.get("next_fd", max(3, max_fd + 1))
        if not self._valid_int(next_fd) or next_fd <= max_fd or next_fd < 3:
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "next_fd")

        stats_raw = state.get("stats", {})
        if not isinstance(stats_raw, dict):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "stats")
        stats = {}
        for key in self._STAT_KEYS:
            value = stats_raw.get(key, 0)
            if not self._valid_int(value) or value < 0:
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "stats")
            stats[key] = value

        audit_raw = state.get("audit", [])
        if not isinstance(audit_raw, list):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "audit")
        for item in audit_raw:
            if not isinstance(item, dict):
                raise PerfAccessError("PERF_SNAPSHOT_INVALID", "audit")
            for key in ("action", "requester", "event_type", "cgroup"):
                if key not in item:
                    raise PerfAccessError("PERF_SNAPSHOT_INVALID", "audit")

        return {
            "paranoid": paranoid,
            "max_events_per_cgroup": max_events,
            "privilege_pool": pool,
            "privilege_ttl": ttl,
            "blacklist": blacklist,
            "whitelist": whitelist,
            "quota": quota,
            "privilege_used": privilege_used,
            "next_request_seq": next_request_seq,
            "next_fd": next_fd,
            "requests": requests,
            "descriptors": descriptors,
            "fd_by_key": fd_by_key,
            "audit": copy.deepcopy(audit_raw),
            "stats": stats,
        }

    def _record_from_snapshot(self, item: dict[str, Any]) -> RequestRecord:
        request_id = item.get("request_id")
        requester = item.get("requester")
        event_type = item.get("event_type")
        cgroup = item.get("cgroup")
        if not isinstance(request_id, str) or not request_id:
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "request_id")
        if not self._nonempty_str(requester) or not self._nonempty_str(event_type):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "request")
        if not self._nonempty_str(cgroup):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "cgroup")
        target_pid = item.get("target_pid")
        target_cpu = item.get("target_cpu")
        if (target_pid is None) == (target_cpu is None):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "target")
        if target_pid is not None and (
                not self._valid_int(target_pid) or target_pid <= 0):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "target_pid")
        if target_cpu is not None and (
                not self._valid_int(target_cpu) or target_cpu < 0):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "target_cpu")
        kernel = item.get("kernel", False)
        privileged = item.get("privileged", False)
        level = item.get("level", 2)
        created_at = item.get("created_at", "")
        expires_at = item.get("expires_at")
        if not isinstance(kernel, bool) or not isinstance(privileged, bool):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "record")
        if not self._valid_int(level) or not 0 <= level <= 4:
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "level")
        if not isinstance(created_at, str):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "created_at")
        if expires_at is not None and not isinstance(expires_at, str):
            raise PerfAccessError("PERF_SNAPSHOT_INVALID", "expires_at")
        return RequestRecord(
            request_id=request_id,
            requester=requester,
            event_type=event_type,
            cgroup=cgroup,
            target_pid=target_pid,
            target_cpu=target_cpu,
            kernel=kernel,
            privileged=privileged,
            level=level,
            created_at=created_at,
            expires_at=expires_at,
        )

    def _revalidate_candidate(self, candidate: dict[str, Any]) -> None:
        """Drop restored collections that the snapshot policy no longer allows."""
        self.paranoid, saved_paranoid = candidate["paranoid"], self.paranoid
        self._blacklist, saved_blacklist = candidate["blacklist"], self._blacklist
        self._whitelist, saved_whitelist = candidate["whitelist"], self._whitelist
        try:
            requests = candidate["requests"]
            descriptors = candidate["descriptors"]
            quota = candidate["quota"]
            privilege_used = candidate["privilege_used"]

            def drop(state: _RequestState) -> None:
                nonlocal privilege_used
                request_id = state.record.request_id
                if state.fd is not None:
                    descriptor = descriptors.get(state.fd)
                    if descriptor is not None:
                        descriptor.refs = [ref for ref in descriptor.refs
                                           if ref != request_id]
                        if not descriptor.refs:
                            descriptors.pop(descriptor.fd, None)
                            candidate["fd_by_key"].pop(descriptor.key, None)
                if state.quota_charged:
                    count = quota.get(state.record.cgroup, 0)
                    if count <= 1:
                        quota.pop(state.record.cgroup, None)
                    else:
                        quota[state.record.cgroup] = count - 1
                    state.quota_charged = False
                if state.pool_charged:
                    privilege_used = max(0, privilege_used - 1)
                    state.pool_charged = False
                state.status = "closed"
                state.fd = None
                state.open_refs = 0

            for state in list(requests.values()):
                if state.status not in self._LIVE_STATES:
                    continue
                record = state.record
                if self._policy_denied(record.event_type, record.target_cpu,
                                       record.kernel, record.privileged):
                    drop(state)
            candidate["privilege_used"] = privilege_used
        finally:
            self.paranoid = saved_paranoid
            self._blacklist = saved_blacklist
            self._whitelist = saved_whitelist
