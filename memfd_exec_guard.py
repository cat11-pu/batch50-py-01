"""Exec guard for anonymous memory files: seal tracking, source resolution, quarantine."""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import asdict, dataclass, replace
from datetime import datetime, timedelta, timezone
from numbers import Real
from typing import Any


class MemfdError(ValueError):
    """Raised when a guard operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


SEAL_SEAL = "F_SEAL_SEAL"
SEAL_SHRINK = "F_SEAL_SHRINK"
SEAL_GROW = "F_SEAL_GROW"
SEAL_WRITE = "F_SEAL_WRITE"
SEAL_FUTURE_WRITE = "F_SEAL_FUTURE_WRITE"

ALL_SEALS = frozenset(
    {SEAL_SEAL, SEAL_SHRINK, SEAL_GROW, SEAL_WRITE, SEAL_FUTURE_WRITE}
)
WRITE_SEALS = frozenset({SEAL_WRITE, SEAL_FUTURE_WRITE})

MEMFD_BAD_SEAL = "MEMFD_BAD_SEAL"
MEMFD_UNSEALED = "MEMFD_UNSEALED"
MEMFD_WRITABLE = "MEMFD_WRITABLE"
MEMFD_NOT_ALLOWED = "MEMFD_NOT_ALLOWED"
MEMFD_ALLOWED = "MEMFD_ALLOWED"
MEMFD_UNKNOWN = "MEMFD_UNKNOWN"
MEMFD_QUARANTINED = "MEMFD_QUARANTINED"
MEMFD_INHERITED_BLOCK = "MEMFD_INHERITED_BLOCK"
MEMFD_PROC_QUARANTINED = "MEMFD_PROC_QUARANTINED"
MEMFD_SNAPSHOT_INVALID = "MEMFD_SNAPSHOT_INVALID"
MEMFD_WRITE_REVOKED = "MEMFD_WRITE_REVOKED"
EXEC_FILE = "EXEC_FILE"

SNAPSHOT_VERSION = 1
EXEC_DENIED_KIND = "exec_denied"
ALLOW_REVOKED_KIND = "allow_revoked"

_PROC_FD_RE = re.compile(
    r"^/proc/(?P<pid>\d+|self|thread-self)/fd/(?P<fd>\d+)(?:/.*)?$"
)


@dataclass(frozen=True)
class MemfdRecord:
    inode: int
    name: str
    pid: int
    fd: int
    seals: frozenset
    state: str
    updated_at: str


@dataclass(frozen=True)
class ExecDecision:
    pid: int
    path: str
    source: str
    inode: int | None
    decision: str
    code: str


def _epoch(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool):
        raise MemfdError("MEMFD_BAD_TIME", {"value": value})
    if isinstance(value, Real):
        return float(value)
    if isinstance(value, datetime):
        current = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return current.timestamp()
    if isinstance(value, str):
        text = value.strip()
        try:
            return float(text)
        except ValueError:
            pass
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise MemfdError("MEMFD_BAD_TIME", {"value": value}) from exc
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    raise MemfdError("MEMFD_BAD_TIME", {"value": value})


def _normalize_seals(seals: Any) -> frozenset[str]:
    try:
        normalized = frozenset(seals)
    except TypeError as exc:
        raise MemfdError(
            MEMFD_BAD_SEAL, {"seals": seals, "reason": "seals must be iterable"}
        ) from exc
    bad = sorted(seal for seal in normalized if seal not in ALL_SEALS)
    if bad:
        raise MemfdError(MEMFD_BAD_SEAL, {"bad_seals": bad, "seals": sorted(normalized)})
    return normalized


def _seal_failure(seals: frozenset[str]) -> tuple[str | None, str | None]:
    if SEAL_SEAL not in seals:
        return MEMFD_UNSEALED, "F_SEAL_SEAL is required"
    if not (seals & WRITE_SEALS):
        return MEMFD_WRITABLE, "F_SEAL_WRITE or F_SEAL_FUTURE_WRITE is required"
    return None, None


def _required_int(value: Any, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise MemfdError("MEMFD_BAD_REQUEST", {"field": field, "value": value})
    return value


def _snapshot_int(value: Any, field: str, *, allow_none: bool = False) -> int | None:
    if allow_none and value is None:
        return None
    if isinstance(value, bool):
        raise ValueError(f"{field} must be an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str):
        return int(value.strip())
    raise ValueError(f"{field} must be an integer")


class MemfdExecGuard:
    """Track memfd seals, resolve exec sources, permit or block anonymous-memory execution."""

    def __init__(self, *, allow_ttl: int = 300, default_deny: bool = True) -> None:
        self.allow_ttl = allow_ttl
        self.default_deny = default_deny
        self._lock = threading.RLock()
        self._memfds: dict[int, MemfdRecord] = {}
        self._by_name: dict[str, int] = {}
        self._by_fd: dict[tuple[int, int], int] = {}
        self._allowed: dict[int, dict[str, Any]] = {}
        self._quarantined_inodes: dict[int, dict[str, Any]] = {}
        self._quarantined_pids: dict[int, dict[str, Any]] = {}
        self._parent: dict[int, int] = {}
        self._children: dict[int, set[int]] = {}
        self._writes: dict[int, dict[str, Any]] = {}
        self._events: list[dict[str, Any]] = []
        self._event_index: dict[tuple[Any, ...], int] = {}
        self._counters: dict[str, int] = {"allowed": 0, "denied": 0}

    def on_memfd_create(
        self,
        *,
        pid: int,
        fd: int,
        inode: int,
        name: str,
        seals: Any,
        now: str,
    ) -> MemfdRecord:
        normalized_seals = _normalize_seals(seals)
        now_epoch = _epoch(now)
        pid = _required_int(pid, "pid")
        fd = _required_int(fd, "fd")
        inode = _required_int(inode, "inode")
        if not isinstance(name, str):
            raise MemfdError("MEMFD_BAD_REQUEST", {"field": "name", "value": name})

        with self._lock:
            previous = self._memfds.get(inode)
            if previous is not None:
                old_fd_key = (previous.pid, previous.fd)
                if self._by_fd.get(old_fd_key) == inode:
                    self._by_fd.pop(old_fd_key, None)
                if previous.name != name and self._by_name.get(previous.name) == inode:
                    self._by_name.pop(previous.name, None)

            self._by_fd[(pid, fd)] = inode
            self._by_name[name] = inode

            if inode in self._quarantined_inodes:
                state = "quarantined"
            else:
                seal_code, _ = _seal_failure(normalized_seals)
                state = (
                    "allowed"
                    if seal_code is None and self._active_allowance(inode, now_epoch)
                    else "tracked"
                )

            record = MemfdRecord(
                inode=inode,
                name=name,
                pid=pid,
                fd=fd,
                seals=normalized_seals,
                state=state,
                updated_at=now,
            )
            self._memfds[inode] = record
            return record

    def on_exec(self, *, pid: int, path: str, now: str) -> ExecDecision:
        now_epoch = _epoch(now)
        pid = _required_int(pid, "pid")

        with self._lock:
            inode, source, resolution = self._resolve_path(pid=pid, path=path)

            if source == "file":
                self._counters["allowed"] += 1
                return ExecDecision(
                    pid=pid,
                    path=path,
                    source="file",
                    inode=None,
                    decision="allow",
                    code=EXEC_FILE,
                )

            if inode is None:
                detail = {"resolution": resolution, "default_deny": self.default_deny}
                return self._deny(
                    pid=pid,
                    path=path,
                    inode=None,
                    source=source,
                    code=MEMFD_UNKNOWN,
                    now=now,
                    reason="execution source is not a registered memfd",
                    detail=detail,
                )

            record = self._memfds[inode]
            base_detail: dict[str, Any] = {
                "inode": inode,
                "name": record.name,
                "seals": sorted(record.seals),
                "resolution": resolution,
            }

            process_quarantine = self._process_quarantine(pid)
            if process_quarantine is not None:
                detail = dict(base_detail)
                detail.update(
                    {
                        "quarantined_pid": process_quarantine["quarantined_pid"],
                        "relation": process_quarantine["kind"],
                        "reason": process_quarantine.get("reason"),
                    }
                )
                code = process_quarantine["code"]
                return self._deny(
                    pid=pid,
                    path=path,
                    inode=inode,
                    code=code,
                    now=now,
                    reason=str(process_quarantine.get("reason") or code),
                    detail=detail,
                )

            quarantine = self._quarantined_inodes.get(inode)
            if quarantine is not None:
                detail = dict(base_detail)
                detail.update(
                    {
                        "reason": quarantine.get("reason"),
                        "quarantined_at": quarantine.get("quarantined_at"),
                    }
                )
                return self._deny(
                    pid=pid,
                    path=path,
                    inode=inode,
                    code=MEMFD_QUARANTINED,
                    now=now,
                    reason=str(quarantine.get("reason") or MEMFD_QUARANTINED),
                    detail=detail,
                )

            seal_code, seal_reason = _seal_failure(record.seals)
            if seal_code is not None:
                detail = dict(base_detail)
                detail["reason"] = seal_reason
                return self._deny(
                    pid=pid,
                    path=path,
                    inode=inode,
                    code=seal_code,
                    now=now,
                    reason=seal_reason or seal_code,
                    detail=detail,
                )

            allowance = self._active_allowance(inode, now_epoch)
            if allowance is None and self.default_deny:
                allowance_state = self._allowance_state(inode, now_epoch)
                if record.state == "allowed":
                    self._memfds[inode] = replace(
                        record, state="tracked", updated_at=now
                    )
                detail = dict(base_detail)
                detail["allowance"] = allowance_state
                reason = allowance_state.get("reason") or MEMFD_NOT_ALLOWED
                return self._deny(
                    pid=pid,
                    path=path,
                    inode=inode,
                    code=MEMFD_NOT_ALLOWED,
                    now=now,
                    reason=str(reason),
                    detail=detail,
                )

            self._counters["allowed"] += 1
            return ExecDecision(
                pid=pid,
                path=path,
                source="memfd",
                inode=inode,
                decision="allow",
                code=MEMFD_ALLOWED,
            )

    def allow(
        self, inode: int, *, ttl: float | int | None = None, now: str
    ) -> MemfdRecord:
        inode = _required_int(inode, "inode")
        now_epoch = _epoch(now)

        with self._lock:
            record = self._memfds.get(inode)
            if record is None:
                raise MemfdError(MEMFD_UNKNOWN, {"inode": inode})

            quarantine = self._quarantined_inodes.get(inode)
            if quarantine is not None:
                raise MemfdError(
                    MEMFD_QUARANTINED,
                    {"inode": inode, "reason": quarantine.get("reason")},
                )

            seal_code, seal_reason = _seal_failure(record.seals)
            if seal_code is not None:
                raise MemfdError(
                    seal_code,
                    {
                        "inode": inode,
                        "reason": seal_reason,
                        "seals": sorted(record.seals),
                    },
                )

            ttl_seconds = self._ttl_seconds(self.allow_ttl if ttl is None else ttl)
            candidate_expiry = (
                None if ttl_seconds is None else now_epoch + float(ttl_seconds)
            )
            current = self._allowed.get(inode)
            active = self._active_allowance(inode, now_epoch)

            if active is not None:
                expiry = active.get("expires_epoch")
                if expiry is None:
                    new_expiry = None
                elif candidate_expiry is None:
                    new_expiry = float(expiry)
                else:
                    new_expiry = max(float(expiry), candidate_expiry)
                entry = dict(active)
                entry.update(
                    {
                        "granted_at": now,
                        "granted_epoch": now_epoch,
                        "requested_ttl_seconds": ttl_seconds,
                        "expires_epoch": new_expiry,
                        "last_renewed_at": now,
                    }
                )
            else:
                generation = 1
                if isinstance(current, dict):
                    generation = int(current.get("generation", 0)) + 1
                entry = {
                    "granted_at": now,
                    "granted_epoch": now_epoch,
                    "ttl_seconds": ttl_seconds,
                    "requested_ttl_seconds": ttl_seconds,
                    "expires_epoch": candidate_expiry,
                    "generation": generation,
                    "revoked": False,
                }

            self._allowed[inode] = entry
            updated = replace(record, state="allowed", updated_at=now)
            self._memfds[inode] = updated
            return updated

    def quarantine(self, inode: int, *, reason: str, now: str) -> MemfdRecord:
        inode = _required_int(inode, "inode")
        if not isinstance(reason, str):
            raise MemfdError("MEMFD_BAD_REQUEST", {"field": "reason", "value": reason})

        with self._lock:
            record = self._memfds.get(inode)
            if record is None:
                raise MemfdError(MEMFD_UNKNOWN, {"inode": inode})

            entry = self._quarantined_inodes.get(inode)
            if entry is None:
                self._quarantined_inodes[inode] = {
                    "reason": reason,
                    "quarantined_at": now,
                }
            else:
                entry["reason"] = reason
                entry["quarantined_at"] = now

            allowance = self._allowed.get(inode)
            if isinstance(allowance, dict):
                allowance["revoked"] = True
                allowance["revoked_at"] = now
                allowance["revoke_reason"] = f"inode quarantined: {reason}"

            updated = replace(record, state="quarantined", updated_at=now)
            self._memfds[inode] = updated
            return updated

    def quarantine_process(self, pid: int, *, reason: str, now: str) -> dict:
        pid = _required_int(pid, "pid")
        if not isinstance(reason, str):
            raise MemfdError("MEMFD_BAD_REQUEST", {"field": "reason", "value": reason})

        with self._lock:
            entry = self._quarantined_pids.get(pid)
            if entry is None:
                self._quarantined_pids[pid] = {
                    "reason": reason,
                    "quarantined_at": now,
                }
            else:
                entry["reason"] = reason
                entry["quarantined_at"] = now

            descendants = self._descendants_locked(pid)
            return {
                "pid": pid,
                "decision": "deny",
                "code": MEMFD_PROC_QUARANTINED,
                "reason": reason,
                "quarantined_at": now,
                "children": sorted(self._children.get(pid, set())),
                "descendants": sorted(descendants),
            }

    def on_write(
        self, *, inode: int, offset: int, length: int, now: str
    ) -> MemfdRecord:
        inode = _required_int(inode, "inode")
        offset = _required_int(offset, "offset")
        length = _required_int(length, "length")
        if offset < 0 or length < 0:
            raise MemfdError(
                "MEMFD_BAD_RANGE",
                {"inode": inode, "offset": offset, "length": length},
            )

        now_epoch = _epoch(now)

        with self._lock:
            record = self._memfds.get(inode)
            if record is None:
                raise MemfdError(MEMFD_UNKNOWN, {"inode": inode})

            write_info = {
                "at": now,
                "offset": offset,
                "length": length,
            }
            self._writes[inode] = write_info

            allowance = self._allowed.get(inode)
            active = self._active_allowance(inode, now_epoch)
            record_revocation = active is not None
            revoke_reason = None
            if active is not None:
                revoke_reason = (
                    "observed write through a writable mapping at "
                    f"offset={offset}, length={length}"
                )
                active["revoked"] = True
                active["revoked_at"] = now
                active["revoke_reason"] = revoke_reason
                active["revoke_code"] = MEMFD_WRITE_REVOKED
                active_generation = active.get("generation")
            elif (
                isinstance(allowance, dict)
                and allowance.get("revoked")
                and allowance.get("revoke_code") == MEMFD_WRITE_REVOKED
            ):
                record_revocation = True
                revoke_reason = str(
                    allowance.get("revoke_reason") or MEMFD_WRITE_REVOKED
                )
                active_generation = allowance.get("generation")

            if record_revocation:
                updated = replace(record, state="tracked", updated_at=now)
                self._memfds[inode] = updated
                self._record_event(
                    kind=ALLOW_REVOKED_KIND,
                    code=MEMFD_WRITE_REVOKED,
                    inode=inode,
                    pid=None,
                    path=None,
                    now=now,
                    reason=revoke_reason or MEMFD_WRITE_REVOKED,
                    detail={
                        "write": dict(write_info),
                        "seals": sorted(record.seals),
                        "allowance_generation": active_generation,
                    },
                    extra={
                        "offset": offset,
                        "length": length,
                        "seals": sorted(record.seals),
                    },
                )
                return updated

            return record

    def on_clone(self, *, parent_pid: int, child_pid: int) -> dict:
        parent_pid = _required_int(parent_pid, "parent_pid")
        child_pid = _required_int(child_pid, "child_pid")

        with self._lock:
            previous_parent = self._parent.get(child_pid)
            if previous_parent is not None and previous_parent != parent_pid:
                siblings = self._children.get(previous_parent)
                if siblings is not None:
                    siblings.discard(child_pid)

            self._parent[child_pid] = parent_pid
            self._children.setdefault(parent_pid, set()).add(child_pid)

            status = self._process_quarantine(child_pid)
            return {
                "parent_pid": parent_pid,
                "child_pid": child_pid,
                "blocked": status is not None,
                "code": status["code"] if status is not None else None,
                "inherited_from": (
                    status.get("quarantined_pid") if status is not None else None
                ),
            }

    def report(self, *, kind: str | None = None) -> list[dict]:
        with self._lock:
            return [
                copy.deepcopy(event)
                for event in self._events
                if kind is None or event.get("kind") == kind
            ]

    def records(self) -> list[MemfdRecord]:
        with self._lock:
            return list(self._memfds.values())

    def seals_for(self, inode: int) -> frozenset:
        inode = _required_int(inode, "inode")
        with self._lock:
            record = self._memfds.get(inode)
            if record is None:
                raise MemfdError(MEMFD_UNKNOWN, {"inode": inode})
            return record.seals

    def snapshot(self) -> dict:
        with self._lock:
            memfds = {}
            for key, record in self._memfds.items():
                data = asdict(record)
                data["seals"] = sorted(record.seals)
                memfds[str(key)] = data

            state = {
                "version": SNAPSHOT_VERSION,
                "memfds": memfds,
                "allowed": {
                    str(inode): copy.deepcopy(entry)
                    for inode, entry in self._allowed.items()
                },
                "quarantined_inodes": {
                    str(inode): copy.deepcopy(entry)
                    for inode, entry in self._quarantined_inodes.items()
                },
                "quarantined_pids": {
                    str(pid): copy.deepcopy(entry)
                    for pid, entry in self._quarantined_pids.items()
                },
                "parent": {
                    str(child): parent for child, parent in self._parent.items()
                },
                "children": {
                    str(parent): sorted(children)
                    for parent, children in self._children.items()
                },
                "writes": {
                    str(inode): copy.deepcopy(entry)
                    for inode, entry in self._writes.items()
                },
                "events": copy.deepcopy(self._events),
                "counters": copy.deepcopy(self._counters),
                "stats": self._stats_locked(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        restored = self._build_snapshot(state)
        with self._lock:
            self._memfds = restored["memfds"]
            self._by_name = restored["by_name"]
            self._by_fd = restored["by_fd"]
            self._allowed = restored["allowed"]
            self._quarantined_inodes = restored["quarantined_inodes"]
            self._quarantined_pids = restored["quarantined_pids"]
            self._parent = restored["parent"]
            self._children = restored["children"]
            self._writes = restored["writes"]
            self._events = restored["events"]
            self._event_index = restored["event_index"]
            self._counters = restored["counters"]

    def stats(self) -> dict:
        with self._lock:
            return self._stats_locked()

    def _stats_locked(self) -> dict:
        return {
            "tracked": len(self._memfds),
            "allowed": int(self._counters.get("allowed", 0)),
            "denied": int(self._counters.get("denied", 0)),
            "quarantined": len(self._quarantined_inodes)
            + len(self._quarantined_pids),
            "events": len(self._events),
        }

    @staticmethod
    def _ttl_seconds(ttl: Any) -> float | None:
        if ttl is None:
            return None
        if isinstance(ttl, timedelta):
            return ttl.total_seconds()
        if isinstance(ttl, bool) or not isinstance(ttl, Real):
            raise MemfdError("MEMFD_BAD_TTL", {"ttl": ttl})
        return float(ttl)

    def _active_allowance(
        self, inode: int, now_epoch: float | None
    ) -> dict[str, Any] | None:
        entry = self._allowed.get(inode)
        if not isinstance(entry, dict) or entry.get("revoked"):
            return None
        expiry = entry.get("expires_epoch")
        if expiry is not None and now_epoch is not None:
            if now_epoch > float(expiry):
                entry["expired"] = True
                return None
        return entry

    def _allowance_state(
        self, inode: int, now_epoch: float | None
    ) -> dict[str, Any]:
        entry = self._allowed.get(inode)
        if not isinstance(entry, dict):
            return {"active": False, "reason": MEMFD_NOT_ALLOWED}
        if entry.get("revoked"):
            return {
                "active": False,
                "reason": entry.get("revoke_reason") or "allowance revoked",
                "revoked_at": entry.get("revoked_at"),
                "revoke_code": entry.get("revoke_code"),
                "generation": entry.get("generation"),
            }
        expiry = entry.get("expires_epoch")
        if expiry is not None and now_epoch is not None and now_epoch > float(expiry):
            return {
                "active": False,
                "reason": "allowance expired",
                "expires_epoch": expiry,
                "generation": entry.get("generation"),
            }
        return {"active": False, "reason": MEMFD_NOT_ALLOWED}

    def _process_quarantine(self, pid: int) -> dict[str, Any] | None:
        direct = self._quarantined_pids.get(pid)
        if direct is not None:
            return {
                "kind": "direct",
                "code": MEMFD_PROC_QUARANTINED,
                "quarantined_pid": pid,
                "reason": direct.get("reason"),
            }

        seen: set[int] = set()
        current = pid
        while current in self._parent:
            parent = self._parent[current]
            quarantined = self._quarantined_pids.get(parent)
            if quarantined is not None:
                return {
                    "kind": "inherited",
                    "code": MEMFD_INHERITED_BLOCK,
                    "quarantined_pid": parent,
                    "reason": quarantined.get("reason"),
                }
            if parent in seen or parent == current:
                break
            seen.add(parent)
            current = parent
        return None

    def _descendants_locked(self, pid: int) -> set[int]:
        result: set[int] = set()
        pending = list(self._children.get(pid, set()))
        while pending:
            child = pending.pop()
            if child in result:
                continue
            result.add(child)
            pending.extend(self._children.get(child, set()))
        return result

    def _resolve_path(self, *, pid: int, path: Any) -> tuple[int | None, str, dict]:
        if not isinstance(path, str) or not path:
            return None, "file", {"reason": "invalid path"}

        match = _PROC_FD_RE.match(path)
        if match is not None:
            token = match.group("pid")
            fd = int(match.group("fd"))
            path_pid = pid if token in {"self", "thread-self"} else int(token)
            resolution: dict[str, Any] = {
                "matched": "proc_fd",
                "path_pid": path_pid,
                "fd": fd,
            }
            inode = self._by_fd.get((path_pid, fd))
            if inode is None and path_pid != pid:
                inode = self._by_fd.get((pid, fd))
                if inode is not None:
                    resolution["resolved_via"] = "exec_pid_fd"
            if inode is not None:
                resolution["inode"] = inode
                return inode, "memfd", resolution
            return None, "proc_fd", resolution

        if path.startswith("memfd:"):
            name = path[len("memfd:") :]
        elif path.startswith("/memfd:"):
            name = path[len("/memfd:") :]
        else:
            name = None

        if name is not None:
            if name.endswith(" (deleted)"):
                name = name[: -len(" (deleted)")]
            inode = self._by_name.get(name)
            resolution = {"matched": "memfd_name", "name": name}
            if inode is not None:
                resolution["inode"] = inode
                return inode, "memfd", resolution
            return None, "memfd", resolution

        return None, "file", {"matched": "ordinary_path"}

    def _deny(
        self,
        *,
        pid: int,
        path: str,
        inode: int | None,
        code: str,
        now: str,
        reason: str,
        detail: dict[str, Any],
        source: str = "memfd",
        kind: str = EXEC_DENIED_KIND,
    ) -> ExecDecision:
        self._counters["denied"] += 1
        self._record_event(
            kind=kind,
            code=code,
            inode=inode,
            pid=pid,
            path=path,
            now=now,
            reason=reason,
            detail=detail,
        )
        return ExecDecision(
            pid=pid,
            path=path,
            source=source,
            inode=inode,
            decision="deny",
            code=code,
        )

    def _record_event(
        self,
        *,
        kind: str,
        code: str,
        inode: int | None,
        pid: int | None,
        path: str | None,
        now: Any,
        reason: str,
        detail: dict[str, Any],
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        key = (kind, code, inode, pid, path)
        index = self._event_index.get(key)
        if index is not None:
            event = self._events[index]
            event["count"] = int(event.get("count", 1)) + 1
            event["last_at"] = now
            return event

        event = {
            "kind": kind,
            "code": code,
            "inode": inode,
            "pid": pid,
            "path": path,
            "count": 1,
            "first_at": now,
            "last_at": now,
            "reason": reason,
            "detail": copy.deepcopy(detail),
        }
        if extra:
            event.update(copy.deepcopy(extra))
        self._event_index[key] = len(self._events)
        self._events.append(event)
        return event

    def _build_snapshot(self, state: Any) -> dict[str, Any]:
        try:
            if not isinstance(state, dict):
                raise ValueError("snapshot must be a dict")
            version = state.get("version")
            if isinstance(version, bool) or version != SNAPSHOT_VERSION:
                raise ValueError("unsupported snapshot version")

            required = {
                "version",
                "memfds",
                "allowed",
                "quarantined_inodes",
                "quarantined_pids",
                "children",
                "events",
                "counters",
                "stats",
            }
            missing = required.difference(state)
            if missing:
                raise ValueError(f"missing snapshot keys: {sorted(missing)}")

            memfds_raw = state["memfds"]
            allowed_raw = state["allowed"]
            quarantined_inodes_raw = state["quarantined_inodes"]
            quarantined_pids_raw = state["quarantined_pids"]
            children_raw = state["children"]
            events_raw = state["events"]
            counters_raw = state["counters"]
            stats_raw = state["stats"]

            if not isinstance(memfds_raw, dict):
                raise ValueError("memfds must be a dict")
            if not isinstance(allowed_raw, dict):
                raise ValueError("allowed must be a dict")
            if not isinstance(quarantined_inodes_raw, dict):
                raise ValueError("quarantined_inodes must be a dict")
            if not isinstance(quarantined_pids_raw, dict):
                raise ValueError("quarantined_pids must be a dict")
            if not isinstance(children_raw, dict):
                raise ValueError("children must be a dict")
            if not isinstance(events_raw, list):
                raise ValueError("events must be a list")
            if not isinstance(counters_raw, dict):
                raise ValueError("counters must be a dict")
            if not isinstance(stats_raw, dict):
                raise ValueError("stats must be a dict")

            memfds: dict[int, MemfdRecord] = {}
            by_name: dict[str, int] = {}
            by_fd: dict[tuple[int, int], int] = {}

            for raw_inode, raw_record in memfds_raw.items():
                inode = _snapshot_int(raw_inode, "memfds key")
                if inode is None or not isinstance(raw_record, dict):
                    raise ValueError("memfds record must be a dict")
                record_inode = _snapshot_int(
                    raw_record.get("inode", inode), "memfds.inode"
                )
                if record_inode != inode:
                    raise ValueError("memfds inode mismatch")
                pid = _snapshot_int(raw_record.get("pid"), "memfds.pid")
                fd = _snapshot_int(raw_record.get("fd"), "memfds.fd")
                if pid is None or fd is None:
                    raise ValueError("memfds pid and fd are required")
                name = raw_record.get("name")
                if not isinstance(name, str):
                    raise ValueError("memfds name must be a string")
                updated_at = raw_record.get("updated_at")
                if not isinstance(updated_at, (str, int, float)) or isinstance(
                    updated_at, bool
                ):
                    raise ValueError("memfds updated_at is invalid")
                record_state = raw_record.get("state")
                if record_state not in {"tracked", "allowed", "quarantined"}:
                    raise ValueError("memfds state is invalid")
                seals = _normalize_seals(raw_record.get("seals"))

                memfds[inode] = MemfdRecord(
                    inode=inode,
                    name=name,
                    pid=pid,
                    fd=fd,
                    seals=seals,
                    state=record_state,
                    updated_at=updated_at,
                )
                by_name[name] = inode
                by_fd[(pid, fd)] = inode

            allowed: dict[int, dict[str, Any]] = {}
            for raw_inode, raw_allowance in allowed_raw.items():
                inode = _snapshot_int(raw_inode, "allowed key")
                if inode is None or inode not in memfds:
                    raise ValueError("allowed inode is not tracked")

                if isinstance(raw_allowance, (str, int, float)) and not isinstance(
                    raw_allowance, bool
                ):
                    granted_epoch = _epoch(raw_allowance)
                    ttl_seconds = self._ttl_seconds(self.allow_ttl)
                    allowance = {
                        "granted_at": raw_allowance,
                        "granted_epoch": granted_epoch,
                        "ttl_seconds": ttl_seconds,
                        "expires_epoch": (
                            None
                            if ttl_seconds is None or granted_epoch is None
                            else granted_epoch + ttl_seconds
                        ),
                        "generation": 1,
                        "revoked": False,
                    }
                elif isinstance(raw_allowance, dict):
                    allowance = copy.deepcopy(raw_allowance)
                    granted_epoch = allowance.get("granted_epoch")
                    if granted_epoch is None and allowance.get("granted_at") is not None:
                        granted_epoch = _epoch(allowance["granted_at"])
                        allowance["granted_epoch"] = granted_epoch
                    elif granted_epoch is not None:
                        granted_epoch = float(granted_epoch)
                        allowance["granted_epoch"] = granted_epoch

                    ttl_seconds = allowance.get(
                        "ttl_seconds", allowance.get("ttl")
                    )
                    if ttl_seconds is not None:
                        ttl_seconds = self._ttl_seconds(ttl_seconds)
                        allowance["ttl_seconds"] = ttl_seconds

                    expiry = allowance.get("expires_epoch")
                    if expiry is not None:
                        allowance["expires_epoch"] = float(expiry)
                    elif granted_epoch is not None and ttl_seconds is not None:
                        allowance["expires_epoch"] = granted_epoch + float(ttl_seconds)
                    else:
                        allowance["expires_epoch"] = None

                    if "revoked" in allowance and not isinstance(
                        allowance["revoked"], bool
                    ):
                        raise ValueError("allowed revoked must be boolean")
                    if "generation" in allowance:
                        allowance["generation"] = int(allowance["generation"])
                else:
                    raise ValueError("allowed entry is invalid")

                allowed[inode] = allowance

            quarantined_inodes: dict[int, dict[str, Any]] = {}
            for raw_inode, raw_entry in quarantined_inodes_raw.items():
                inode = _snapshot_int(raw_inode, "quarantined_inodes key")
                if inode is None or inode not in memfds:
                    raise ValueError("quarantined inode is not tracked")
                quarantined_inodes[inode] = self._restore_reason_entry(raw_entry)

            quarantined_pids: dict[int, dict[str, Any]] = {}
            for raw_pid, raw_entry in quarantined_pids_raw.items():
                pid = _snapshot_int(raw_pid, "quarantined_pids key")
                if pid is None:
                    raise ValueError("quarantined pid is invalid")
                quarantined_pids[pid] = self._restore_reason_entry(raw_entry)

            children: dict[int, set[int]] = {}
            parent: dict[int, int] = {}
            for raw_parent, raw_children in children_raw.items():
                parent_pid = _snapshot_int(raw_parent, "children key")
                if parent_pid is None:
                    raise ValueError("parent pid is invalid")
                if not isinstance(raw_children, (list, tuple, set, frozenset)):
                    raise ValueError("children must be a sequence")
                child_set: set[int] = set()
                for raw_child in raw_children:
                    child_pid = _snapshot_int(raw_child, "child pid")
                    if child_pid is None:
                        raise ValueError("child pid is invalid")
                    existing_parent = parent.get(child_pid)
                    if existing_parent is not None and existing_parent != parent_pid:
                        raise ValueError("child has multiple parents")
                    parent[child_pid] = parent_pid
                    child_set.add(child_pid)
                children[parent_pid] = child_set

            writes: dict[int, dict[str, Any]] = {}
            writes_raw = state.get("writes", {})
            if not isinstance(writes_raw, dict):
                raise ValueError("writes must be a dict")
            for raw_inode, raw_write in writes_raw.items():
                inode = _snapshot_int(raw_inode, "writes key")
                if inode is None or not isinstance(raw_write, dict):
                    raise ValueError("write entry is invalid")
                writes[inode] = copy.deepcopy(raw_write)

            events: list[dict[str, Any]] = []
            event_index: dict[tuple[Any, ...], int] = {}
            for raw_event in events_raw:
                if not isinstance(raw_event, dict):
                    raise ValueError("event must be a dict")
                for field in (
                    "kind",
                    "code",
                    "inode",
                    "pid",
                    "path",
                    "count",
                    "first_at",
                    "last_at",
                ):
                    if field not in raw_event:
                        raise ValueError(f"event missing {field}")
                if not isinstance(raw_event["kind"], str):
                    raise ValueError("event kind must be a string")
                if not isinstance(raw_event["code"], str):
                    raise ValueError("event code must be a string")
                count = raw_event["count"]
                if isinstance(count, bool) or not isinstance(count, int) or count < 1:
                    raise ValueError("event count must be a positive integer")
                inode = _snapshot_int(
                    raw_event["inode"], "event inode", allow_none=True
                )
                pid = _snapshot_int(raw_event["pid"], "event pid", allow_none=True)
                path = raw_event["path"]
                if path is not None and not isinstance(path, str):
                    raise ValueError("event path must be a string or None")

                event = copy.deepcopy(raw_event)
                event["inode"] = inode
                event["pid"] = pid
                key = (event["kind"], event["code"], inode, pid, path)
                if key in event_index:
                    raise ValueError("duplicate event identity in snapshot")
                event_index[key] = len(events)
                events.append(event)

            counters: dict[str, int] = {}
            for key, value in counters_raw.items():
                if not isinstance(key, str):
                    raise ValueError("counter key must be a string")
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise ValueError("counter must be a non-negative integer")
                counters[key] = value
            counters.setdefault("allowed", 0)
            counters.setdefault("denied", 0)

            return {
                "memfds": memfds,
                "by_name": by_name,
                "by_fd": by_fd,
                "allowed": allowed,
                "quarantined_inodes": quarantined_inodes,
                "quarantined_pids": quarantined_pids,
                "parent": parent,
                "children": children,
                "writes": writes,
                "events": events,
                "event_index": event_index,
                "counters": counters,
            }
        except MemfdError as exc:
            if exc.code == MEMFD_SNAPSHOT_INVALID:
                raise
            raise MemfdError(
                MEMFD_SNAPSHOT_INVALID,
                {"reason": exc.code, "detail": exc.detail},
            ) from exc
        except Exception as exc:
            raise MemfdError(
                MEMFD_SNAPSHOT_INVALID, {"reason": str(exc)}
            ) from exc

    @staticmethod
    def _restore_reason_entry(raw_entry: Any) -> dict[str, Any]:
        if isinstance(raw_entry, str):
            return {"reason": raw_entry}
        if not isinstance(raw_entry, dict):
            raise ValueError("quarantine entry must be a string or dict")
        reason = raw_entry.get("reason")
        if not isinstance(reason, str):
            raise ValueError("quarantine reason must be a string")
        return copy.deepcopy(raw_entry)
