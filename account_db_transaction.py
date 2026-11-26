"""Local account database transactions: fixed lock order, atomic replacement, NSS cache."""

from __future__ import annotations

import copy
import threading
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterable, Iterator, Mapping, MutableMapping, Sequence

FILES = ("passwd", "shadow", "group", "gshadow")
LOCK_ORDER = ("passwd", "shadow", "group", "gshadow")
RESERVED_IDS = (0, 1, 2, 65534)
KINDS = ("add_user", "delete_user", "add_group", "join_group", "set_shell")


class AccountDbError(ValueError):
    """Raised when an account database transaction is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AccountChange:
    kind: str
    name: str
    fields: dict


@dataclass(frozen=True)
class ChangePlan:
    plan_id: str
    changes: tuple[AccountChange, ...]
    files: tuple[str, ...]
    lock_order: tuple[str, ...]
    version: int


@dataclass(frozen=True)
class CommitResult:
    plan_id: str
    files_written: tuple[str, ...]
    cache_invalidated: int
    version: int
    committed_at: str


@dataclass(frozen=True)
class VerifyReport:
    ok: bool
    duplicate_uids: tuple[str, ...]
    dangling_gids: tuple[str, ...]
    duplicate_names: tuple[str, ...]


_LOCK_REGISTRY_LOCK = threading.RLock()
_FILE_LOCKS = {name: threading.RLock() for name in FILES}
_NAME_LOCKS: dict[str, threading.RLock] = {}


def _name_lock(name: str) -> threading.RLock:
    with _LOCK_REGISTRY_LOCK:
        return _NAME_LOCKS.setdefault(name, threading.RLock())


@contextmanager
def _locked_names(names: Iterable[str]) -> Iterator[None]:
    locks = [_name_lock(name) for name in sorted(set(names), key=str)]
    for lock in locks:
        lock.acquire()
    try:
        yield
    finally:
        for lock in reversed(locks):
            lock.release()


@contextmanager
def _locked_files(names: Iterable[str]) -> Iterator[None]:
    wanted = set(names)
    locks = [_FILE_LOCKS[name] for name in LOCK_ORDER if name in wanted]
    for lock in locks:
        lock.acquire()
    try:
        yield
    finally:
        for lock in reversed(locks):
            lock.release()


def _as_text(value: object) -> str:
    if isinstance(value, str):
        return value
    if isinstance(value, bytes):
        try:
            return value.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise AccountDbError("ACCOUNTDB_SNAPSHOT_INVALID", str(exc)) from exc
    raise AccountDbError("ACCOUNTDB_SNAPSHOT_INVALID", "file content must be text")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _clone_entries(entries: Mapping[str, Sequence[dict]]) -> dict[str, list[dict]]:
    return copy.deepcopy(dict(entries))


def _records(entries: Mapping[str, Sequence[dict]], filename: str) -> list[dict]:
    return [entry for entry in entries[filename] if entry.get("type") != "raw"]


def _find(entries: Mapping[str, Sequence[dict]], filename: str, name: str) -> dict | None:
    for entry in _records(entries, filename):
        if entry["parts"][0] == name:
            return entry
    return None


def _find_all(entries: Mapping[str, Sequence[dict]], filename: str, name: str) -> list[dict]:
    return [
        entry for entry in _records(entries, filename)
        if entry["parts"][0] == name
    ]


def _members(record: dict) -> list[str]:
    return [item for item in record["parts"][3].split(",") if item]


def _set_members(record: dict, members: Iterable[str]) -> None:
    record["parts"][3] = ",".join(members)
    record["dirty"] = True


def _render(entries: Sequence[dict]) -> str:
    lines = [
        ":".join(entry["parts"]) if entry.get("dirty") else entry["raw"]
        for entry in entries
    ]
    if not lines:
        return ""
    return "\n".join(lines) + "\n"


def _parse_file(filename: str, content: str) -> list[dict]:
    entries: list[dict] = []
    for line in content.splitlines():
        if not line or line.lstrip().startswith("#"):
            entries.append({"type": "raw", "raw": line})
            continue
        parts = line.split(":")
        minimum = 7 if filename == "passwd" else 2 if filename == "shadow" else 4
        if len(parts) < minimum or not parts[0]:
            entries.append({"type": "raw", "raw": line})
            continue
        try:
            if filename == "passwd":
                int(parts[2])
                int(parts[3])
            elif filename == "group":
                int(parts[2])
        except ValueError:
            entries.append({"type": "raw", "raw": line})
            continue
        entries.append({
            "type": filename,
            "raw": line,
            "parts": parts,
            "dirty": False,
        })
    return entries


def _new_record(filename: str, parts: list[str]) -> dict:
    return {
        "type": filename,
        "raw": ":".join(parts),
        "parts": parts,
        "dirty": True,
    }


def _change_from(value: object) -> AccountChange:
    if isinstance(value, AccountChange):
        change = value
    elif isinstance(value, Mapping):
        change = AccountChange(
            kind=value.get("kind"),  # type: ignore[arg-type]
            name=value.get("name"),  # type: ignore[arg-type]
            fields=value.get("fields"),  # type: ignore[arg-type]
        )
    else:
        raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", "change must be AccountChange")
    if not isinstance(change.kind, str) or change.kind not in KINDS:
        raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", getattr(change, "kind", None))
    if not isinstance(change.name, str) or not change.name:
        raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", "name is required")
    if ":" in change.name or "\n" in change.name or "\r" in change.name:
        raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", "invalid name")
    fields = change.fields
    if fields is None:
        fields = {}
    if not isinstance(fields, Mapping):
        raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", "fields must be a mapping")
    return AccountChange(change.kind, change.name, copy.deepcopy(dict(fields)))


def _join_target(change: AccountChange) -> tuple[str, str]:
    group = change.fields.get("group")
    user = change.fields.get(
        "user", change.fields.get("username", change.fields.get("member"))
    )
    if isinstance(group, str) and group:
        if isinstance(user, str) and user:
            if change.name == group:
                return user, group
            if user != change.name:
                raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", "ambiguous join target")
        return change.name, group
    if isinstance(user, str) and user:
        return user, change.name
    members = change.fields.get("members")
    if isinstance(members, str):
        members = [item for item in members.split(",") if item]
    if isinstance(members, (list, tuple)) and len(members) == 1:
        member = members[0]
        if isinstance(member, str) and member:
            return member, change.name
    raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", "join_group requires group or user")


def _validate_change_shape(change: AccountChange) -> None:
    fields = change.fields
    if change.kind == "set_shell":
        shell = fields.get("shell")
        if not isinstance(shell, str) or not shell:
            raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", "set_shell requires shell")
    elif change.kind == "join_group":
        _join_target(change)
    elif change.kind == "add_group":
        gid = fields.get("gid")
        if gid is not None and not _is_int(gid):
            raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", "gid must be an integer")
    elif change.kind == "add_user":
        for key in ("shell", "home"):
            value = fields.get(key)
            if value is not None and not isinstance(value, str):
                raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", f"{key} must be text")
        gid = fields.get("gid")
        if gid is not None and not _is_int(gid):
            raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", "gid must be an integer")


def _kind_files(kind: str) -> tuple[str, ...]:
    if kind in ("add_user", "delete_user"):
        return FILES
    if kind in ("add_group", "join_group"):
        return ("group", "gshadow")
    return ("passwd",)


def _plan_files(changes: Sequence[AccountChange]) -> tuple[str, ...]:
    touched = set()
    for change in changes:
        touched.update(_kind_files(change.kind))
    return tuple(name for name in FILES if name in touched)


def _affected_names(changes: Sequence[AccountChange]) -> set[str]:
    names: set[str] = set()
    for change in changes:
        names.add(change.name)
        if change.kind == "join_group":
            user, group = _join_target(change)
            names.add(user)
            names.add(group)
    return names


def _next_id(used: set[int], floor: int, ceiling: int, error_code: str) -> int:
    for candidate in range(floor, ceiling):
        if candidate in RESERVED_IDS or candidate in used:
            continue
        return candidate
    raise AccountDbError(error_code, {"floor": floor, "ceiling": ceiling})


def _serialize_change(change: AccountChange) -> dict:
    return {"kind": change.kind, "name": change.name, "fields": copy.deepcopy(change.fields)}


def _serialize_plan(plan: MutableMapping[str, object]) -> dict:
    return {
        "plan_id": plan["plan_id"],
        "changes": [_serialize_change(change) for change in plan["changes"]],
        "files": list(plan["files"]),
        "lock_order": list(plan["lock_order"]),
        "version": plan["version"],
        "status": plan["status"],
        "before_files": copy.deepcopy(plan.get("before_files")),
        "after_files": copy.deepcopy(plan.get("after_files")),
        "before_versions": copy.deepcopy(plan.get("before_versions")),
        "after_versions": copy.deepcopy(plan.get("after_versions")),
        "version_before": plan.get("version_before"),
        "committed_at": plan.get("committed_at"),
        "cache_invalidated": plan.get("cache_invalidated", 0),
    }


class AccountDbTransaction:
    """Apply batched changes to the four local account database files."""

    def __init__(self, *, uid_floor: int = 1000, uid_ceiling: int = 60000,
                 gid_floor: int = 1000, gid_ceiling: int = 60000) -> None:
        self.uid_floor = uid_floor
        self.uid_ceiling = uid_ceiling
        self.gid_floor = gid_floor
        self.gid_ceiling = gid_ceiling
        self._lock = threading.RLock()
        self._files = {name: "" for name in FILES}
        self._entries: dict[str, list[dict]] = {name: [] for name in FILES}
        self._versions = {name: 1 for name in FILES}
        self._plans: dict[str, dict] = {}
        self._version = 0
        self._journal: list[dict] = []
        self._cache_failures: list[dict] = []
        self._counters = {
            "plans": 0, "commits": 0, "rollbacks": 0,
            "cache_invalidations": 0, "recovered": 0,
        }

    def load(self, files: dict) -> dict:
        if not isinstance(files, Mapping):
            raise AccountDbError("ACCOUNTDB_SNAPSHOT_INVALID", "files must be a mapping")
        missing = [name for name in FILES if name not in files]
        if missing:
            raise AccountDbError("ACCOUNTDB_SNAPSHOT_INVALID", missing)
        parsed: dict[str, list[dict]] = {}
        contents: dict[str, str] = {}
        for name in FILES:
            text = _as_text(files[name])
            contents[name] = text
            parsed[name] = _parse_file(name, text)
        with _locked_files(FILES), self._lock:
            self._files = contents
            self._entries = parsed
            self._versions = {name: 1 for name in FILES}
            self._plans = {}
            self._version = 0
            self._journal = []
            self._cache_failures = []
            self._counters = {
                "plans": 0, "commits": 0, "rollbacks": 0,
                "cache_invalidations": 0, "recovered": 0,
            }
        return {name: len(_records(parsed, name)) for name in FILES}

    def files(self) -> dict:
        with _locked_files(FILES), self._lock:
            return dict(self._files)

    def users(self) -> list[dict]:
        with _locked_files(FILES), self._lock:
            result = []
            for record in _records(self._entries, "passwd"):
                parts = record["parts"]
                result.append({
                    "name": parts[0],
                    "uid": int(parts[2]),
                    "gid": int(parts[3]),
                    "home": parts[5],
                    "shell": parts[6],
                })
            return sorted(result, key=lambda item: item["name"])

    def groups(self) -> list[dict]:
        with _locked_files(FILES), self._lock:
            result = []
            for record in _records(self._entries, "group"):
                parts = record["parts"]
                result.append({
                    "name": parts[0],
                    "gid": int(parts[2]),
                    "members": tuple(_members(record)),
                })
            return sorted(result, key=lambda item: item["name"])

    def allocate_uid(self, name: str) -> int:
        del name
        with self._lock:
            used = {int(record["parts"][2]) for record in _records(self._entries, "passwd")}
            return _next_id(
                used, self.uid_floor, self.uid_ceiling, "ACCOUNTDB_UID_EXHAUSTED"
            )

    def allocate_gid(self, name: str) -> int:
        del name
        with self._lock:
            used = {int(record["parts"][2]) for record in _records(self._entries, "group")}
            return _next_id(
                used, self.gid_floor, self.gid_ceiling, "ACCOUNTDB_GID_EXHAUSTED"
            )

    def plan(self, changes) -> ChangePlan:
        if isinstance(changes, (str, bytes)) or not isinstance(changes, Iterable):
            raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", "changes must be iterable")
        normalized = tuple(_change_from(change) for change in changes)
        if not normalized:
            raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", "at least one change is required")
        for change in normalized:
            _validate_change_shape(change)
        files = _plan_files(normalized)
        with self._lock:
            pending_versions = [
                int(record["version"]) for record in self._plans.values()
                if record.get("status") == "pending"
            ]
            version = max([self._version, *pending_versions]) + 1
            plan_id = uuid.uuid4().hex
            self._plans[plan_id] = {
                "plan_id": plan_id,
                "changes": copy.deepcopy(normalized),
                "files": files,
                "lock_order": LOCK_ORDER,
                "version": version,
                "status": "pending",
                "before_files": None,
                "after_files": None,
                "before_versions": None,
                "after_versions": None,
                "version_before": None,
                "committed_at": None,
                "cache_invalidated": 0,
            }
            self._counters["plans"] += 1
        return ChangePlan(plan_id, normalized, files, LOCK_ORDER, version)

    def apply(self, plan_id: str, *, now: str) -> CommitResult:
        plan = self._known_plan(plan_id)
        with _locked_names(_affected_names(plan["changes"])), _locked_files(plan["files"]), self._lock:
            record = self._plans.get(plan_id)
            if record is None:
                raise AccountDbError("ACCOUNTDB_PLAN_UNKNOWN", plan_id)
            if record["status"] != "pending":
                raise AccountDbError("ACCOUNTDB_PLAN_APPLIED", plan_id)

            self._check_consistency(self._entries)
            work = _clone_entries(self._entries)
            self._simulate_changes(work, record["changes"])
            self._check_consistency(work)

            before_files = {name: self._files[name] for name in record["files"]}
            before_versions = {name: self._versions[name] for name in record["files"]}
            after_files = {name: _render(work[name]) for name in record["files"]}
            after_versions = {
                name: before_versions[name] + 1 for name in record["files"]
            }
            version_before = self._version
            entry = {
                "txn_id": uuid.uuid4().hex,
                "kind": "commit",
                "plan_id": plan_id,
                "phase": "prepared",
                "files": list(record["files"]),
                "before_files": before_files,
                "after_files": after_files,
                "before_versions": before_versions,
                "after_versions": after_versions,
                "version_before": version_before,
                "version_after": record["version"],
                "plan_status_before": record["status"],
                "now": now,
            }
            self._journal.append(entry)
            try:
                for name in record["files"]:
                    self._files[name] = after_files[name]
                    self._entries[name] = work[name]
                    self._versions[name] = after_versions[name]
                self._version = max(self._version, record["version"])
                record["before_files"] = before_files
                record["before_versions"] = before_versions
                record["after_files"] = after_files
                record["after_versions"] = after_versions
                record["version_before"] = version_before
                record["committed_at"] = now
                record["status"] = "applied"
                self._counters["commits"] += 1
            except Exception:
                for name in record["files"]:
                    self._files[name] = before_files[name]
                    self._entries[name] = _parse_file(name, before_files[name])
                    self._versions[name] = before_versions[name]
                self._version = version_before
                entry["phase"] = "aborted"
                raise

            files_written = record["files"]
            committed_version = record["version"]
            entry["phase"] = "committed"

        try:
            cache_invalidated = self._invalidate_nss(files_written)
        except Exception as exc:
            with self._lock:
                self._cache_failures.append({
                    "file": "*",
                    "error": type(exc).__name__,
                    "detail": str(exc),
                })
            cache_invalidated = 0
        with self._lock:
            current = self._plans.get(plan_id)
            if current is not None:
                current["cache_invalidated"] = cache_invalidated
            entry["cache_invalidated"] = cache_invalidated
        return CommitResult(
            plan_id=plan_id,
            files_written=files_written,
            cache_invalidated=cache_invalidated,
            version=committed_version,
            committed_at=now,
        )

    def rollback(self, plan_id: str, *, now: str) -> int:
        plan = self._known_plan(plan_id)
        with _locked_names(_affected_names(plan["changes"])), _locked_files(plan["files"]), self._lock:
            record = self._plans.get(plan_id)
            if record is None:
                raise AccountDbError("ACCOUNTDB_PLAN_UNKNOWN", plan_id)
            if record["status"] != "applied":
                raise AccountDbError("ACCOUNTDB_PLAN_APPLIED", plan_id)

            for name in record["files"]:
                if self._files[name] != record["after_files"][name]:
                    raise AccountDbError(
                        "ACCOUNTDB_ROLLBACK_CONFLICT",
                        {"file": name, "plan_id": plan_id},
                    )

            current_files = {name: self._files[name] for name in record["files"]}
            current_versions = {name: self._versions[name] for name in record["files"]}
            version_now = self._version
            version_after = (
                record["version_before"]
                if self._version == record["version"]
                else self._version
            )
            entry = {
                "txn_id": uuid.uuid4().hex,
                "kind": "rollback",
                "plan_id": plan_id,
                "phase": "prepared",
                "files": list(record["files"]),
                "before_files": current_files,
                "after_files": copy.deepcopy(record["before_files"]),
                "before_versions": current_versions,
                "after_versions": copy.deepcopy(record["before_versions"]),
                "version_before": version_now,
                "version_after": version_after,
                "plan_status_before": record["status"],
                "now": now,
            }
            self._journal.append(entry)
            try:
                for name in record["files"]:
                    self._files[name] = record["before_files"][name]
                    self._entries[name] = _parse_file(name, record["before_files"][name])
                    self._versions[name] = record["before_versions"][name]
                self._version = version_after
                record["status"] = "rolled_back"
                self._counters["rollbacks"] += 1
                entry["phase"] = "committed"
                entry["rolled_back_at"] = now
            except Exception:
                for name in record["files"]:
                    self._files[name] = current_files[name]
                    self._entries[name] = _parse_file(name, current_files[name])
                    self._versions[name] = current_versions[name]
                self._version = version_now
                entry["phase"] = "aborted"
                raise
        return len(record["files"])

    def recover(self, *, now: str) -> dict:
        with _locked_files(FILES), self._lock:
            recovered = 0
            for entry in self._journal:
                if entry.get("phase") != "prepared":
                    continue
                recovered += self._recover_entry(entry, now)
            self._counters["recovered"] += recovered
        return {"recovered": recovered}

    def verify(self) -> VerifyReport:
        with _locked_files(FILES), self._lock:
            report = self._verify_entries(self._entries)
        return VerifyReport(
            ok=not (
                report["duplicate_uids"]
                or report["duplicate_names"]
                or report["dangling_gids"]
            ),
            duplicate_uids=tuple(report["duplicate_uids"]),
            dangling_gids=tuple(report["dangling_gids"]),
            duplicate_names=tuple(report["duplicate_names"]),
        )

    def stats(self) -> dict:
        with self._lock:
            return {
                "users": len(_records(self._entries, "passwd")),
                "groups": len(_records(self._entries, "group")),
                "plans": self._counters["plans"],
                "commits": self._counters["commits"],
                "rollbacks": self._counters["rollbacks"],
                "cache_invalidations": self._counters["cache_invalidations"],
                "recovered": self._counters["recovered"],
            }

    def snapshot(self) -> dict:
        with _locked_files(FILES), self._lock:
            return {
                "schema": "account-db-transaction.v1",
                "files": dict(self._files),
                "versions": dict(self._versions),
                "version": self._version,
                "plans": {
                    plan_id: _serialize_plan(plan)
                    for plan_id, plan in self._plans.items()
                },
                "counters": dict(self._counters),
                "journal": copy.deepcopy(self._journal),
                "cache_failures": copy.deepcopy(self._cache_failures),
            }

    def restore(self, state: dict) -> None:
        validated = self._validate_snapshot(state)
        with _locked_files(FILES), self._lock:
            self._files = validated["files"]
            self._entries = validated["entries"]
            self._versions = validated["versions"]
            self._version = validated["version"]
            self._plans = validated["plans"]
            self._counters = validated["counters"]
            self._journal = validated["journal"]
            self._cache_failures = validated["cache_failures"]

    def _known_plan(self, plan_id: str) -> dict:
        with self._lock:
            plan = self._plans.get(plan_id)
            if plan is None:
                raise AccountDbError("ACCOUNTDB_PLAN_UNKNOWN", plan_id)
            return plan

    def _nss_cache_invalidate(self, filename: str) -> None:
        """Hook used by local deployments/tests to report NSS invalidation failures."""
        del filename

    def _invalidate_nss(self, files: Sequence[str]) -> int:
        invalidated = 0
        for name in files:
            try:
                self._nss_cache_invalidate(name)
            except Exception as exc:
                with self._lock:
                    self._cache_failures.append({
                        "file": name,
                        "error": type(exc).__name__,
                        "detail": str(exc),
                    })
            else:
                invalidated += 1
                with self._lock:
                    self._counters["cache_invalidations"] += 1
        return invalidated

    def _verify_entries(self, entries: Mapping[str, Sequence[dict]]) -> dict:
        uid_names: dict[int, list[str]] = {}
        name_counts: dict[str, int] = {}
        passwd_gids: list[tuple[str, int]] = []
        for record in _records(entries, "passwd"):
            parts = record["parts"]
            name = parts[0]
            uid = int(parts[2])
            gid = int(parts[3])
            uid_names.setdefault(uid, []).append(name)
            name_counts[name] = name_counts.get(name, 0) + 1
            passwd_gids.append((name, gid))
        group_gids = {int(record["parts"][2]) for record in _records(entries, "group")}
        duplicate_uids = sorted(
            {name for names in uid_names.values() if len(names) > 1 for name in names}
        )
        duplicate_names = sorted(
            {name for name, count in name_counts.items() if count > 1}
        )
        dangling_gids = sorted(
            {name for name, gid in passwd_gids if gid not in group_gids}
        )
        return {
            "duplicate_uids": duplicate_uids,
            "duplicate_names": duplicate_names,
            "dangling_gids": dangling_gids,
        }

    def _check_consistency(self, entries: Mapping[str, Sequence[dict]]) -> None:
        report = self._verify_entries(entries)
        if report["duplicate_uids"]:
            raise AccountDbError(
                "ACCOUNTDB_DUPLICATE_UID",
                tuple(report["duplicate_uids"]),
            )
        if report["duplicate_names"]:
            raise AccountDbError(
                "ACCOUNTDB_DUPLICATE_NAME",
                tuple(report["duplicate_names"]),
            )
        if report["dangling_gids"]:
            raise AccountDbError(
                "ACCOUNTDB_DANGLING_GID",
                tuple(report["dangling_gids"]),
            )
        group_names = [record["parts"][0] for record in _records(entries, "group")]
        duplicate_groups = sorted({
            name for name in group_names if group_names.count(name) > 1
        })
        if duplicate_groups:
            raise AccountDbError("ACCOUNTDB_DUPLICATE_NAME", tuple(duplicate_groups))

    def _simulate_changes(
        self, entries: MutableMapping[str, list[dict]], changes: Sequence[AccountChange]
    ) -> None:
        passwd_names = {record["parts"][0] for record in _records(entries, "passwd")}
        group_names = {record["parts"][0] for record in _records(entries, "group")}
        shadow_names = {record["parts"][0] for record in _records(entries, "shadow")}
        used_uids = {int(record["parts"][2]) for record in _records(entries, "passwd")}
        used_gids = {int(record["parts"][2]) for record in _records(entries, "group")}

        for change in changes:
            if change.kind == "add_user":
                if change.name in passwd_names or change.name in shadow_names:
                    raise AccountDbError("ACCOUNTDB_DUPLICATE_NAME", change.name)
                if change.name in group_names:
                    raise AccountDbError("ACCOUNTDB_DUPLICATE_NAME", change.name)
                uid = _next_id(
                    used_uids, self.uid_floor, self.uid_ceiling,
                    "ACCOUNTDB_UID_EXHAUSTED",
                )
                private_gid = uid
                if private_gid in used_gids or private_gid in RESERVED_IDS:
                    private_gid = _next_id(
                        used_gids, self.gid_floor, self.gid_ceiling,
                        "ACCOUNTDB_GID_EXHAUSTED",
                    )
                home = change.fields.get("home", f"/home/{change.name}")
                shell = change.fields.get("shell", "/bin/bash")
                passwd = _new_record("passwd", [
                    change.name, "x", str(uid), str(private_gid), "",
                    str(home), str(shell),
                ])
                shadow = _new_record("shadow", [
                    change.name, "!", "19000", "0", "99999", "7", "", "", "",
                ])
                group = _new_record("group", [
                    change.name, "x", str(private_gid), "",
                ])
                gshadow = _new_record("gshadow", [change.name, "!", "", ""])
                entries["passwd"].append(passwd)
                entries["shadow"].append(shadow)
                entries["group"].append(group)
                entries["gshadow"].append(gshadow)
                passwd_names.add(change.name)
                shadow_names.add(change.name)
                group_names.add(change.name)
                used_uids.add(uid)
                used_gids.add(private_gid)

            elif change.kind == "delete_user":
                user = _find(entries, "passwd", change.name)
                if user is None:
                    raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", change.name)
                entries["passwd"] = [
                    entry for entry in entries["passwd"]
                    if entry.get("type") == "raw" or entry["parts"][0] != change.name
                ]
                entries["shadow"] = [
                    entry for entry in entries["shadow"]
                    if entry.get("type") == "raw" or entry["parts"][0] != change.name
                ]
                entries["group"] = [
                    entry for entry in entries["group"]
                    if entry.get("type") == "raw" or entry["parts"][0] != change.name
                ]
                entries["gshadow"] = [
                    entry for entry in entries["gshadow"]
                    if entry.get("type") == "raw" or entry["parts"][0] != change.name
                ]
                for record in _records(entries, "group"):
                    members = _members(record)
                    if change.name in members:
                        _set_members(record, [m for m in members if m != change.name])
                for record in _records(entries, "gshadow"):
                    members = _members(record)
                    if change.name in members:
                        _set_members(record, [m for m in members if m != change.name])
                passwd_names.discard(change.name)
                shadow_names.discard(change.name)
                group_names.discard(change.name)
                used_uids = {
                    int(record["parts"][2]) for record in _records(entries, "passwd")
                }
                used_gids = {
                    int(record["parts"][2]) for record in _records(entries, "group")
                }

            elif change.kind == "add_group":
                if change.name in group_names:
                    raise AccountDbError("ACCOUNTDB_DUPLICATE_NAME", change.name)
                gid = change.fields.get("gid")
                if gid is None:
                    gid = _next_id(
                        used_gids, self.gid_floor, self.gid_ceiling,
                        "ACCOUNTDB_GID_EXHAUSTED",
                    )
                elif not _is_int(gid) or gid in RESERVED_IDS or gid in used_gids:
                    raise AccountDbError("ACCOUNTDB_DUPLICATE_GID", gid)
                members = change.fields.get("members", ())
                if isinstance(members, str):
                    members = [item for item in members.split(",") if item]
                elif not isinstance(members, (list, tuple, set)):
                    raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", "members must be a list")
                member_text = ",".join(str(item) for item in members)
                group = _new_record("group", [change.name, "x", str(gid), member_text])
                gshadow = _new_record(
                    "gshadow", [change.name, "!", "", member_text]
                )
                entries["group"].append(group)
                entries["gshadow"].append(gshadow)
                group_names.add(change.name)
                used_gids.add(gid)

            elif change.kind == "join_group":
                user_name, group_name = _join_target(change)
                if _find(entries, "passwd", user_name) is None:
                    raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", user_name)
                group = _find(entries, "group", group_name)
                if group is None:
                    raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", group_name)
                gshadow = _find(entries, "gshadow", group_name)
                if gshadow is None:
                    gshadow = _new_record("gshadow", [group_name, "!", "", ""])
                    entries["gshadow"].append(gshadow)
                group_members = _members(group)
                if user_name not in group_members:
                    group_members.append(user_name)
                    _set_members(group, group_members)
                shadow_members = _members(gshadow)
                if user_name not in shadow_members:
                    shadow_members.append(user_name)
                    _set_members(gshadow, shadow_members)

            elif change.kind == "set_shell":
                user = _find(entries, "passwd", change.name)
                if user is None:
                    raise AccountDbError("ACCOUNTDB_INVALID_CHANGE", change.name)
                user["parts"][6] = change.fields["shell"]
                user["dirty"] = True

    def _recover_entry(self, entry: dict, now: str) -> int:
        files = list(entry.get("files", ()))
        before_files = entry.get("before_files")
        after_files = entry.get("after_files")
        if not files or not isinstance(before_files, dict) or not isinstance(after_files, dict):
            entry["phase"] = "invalid"
            entry["recovered_at"] = now
            return 1

        plan = self._plans.get(entry.get("plan_id"))
        if all(self._files.get(name) == after_files.get(name) for name in files):
            for name in files:
                if name in FILES:
                    self._files[name] = after_files[name]
                    self._entries[name] = _parse_file(name, after_files[name])
                    self._versions[name] = entry["after_versions"][name]
            self._version = max(self._version, int(entry.get("version_after", 0)))
            if plan is not None:
                target = "applied" if entry.get("kind") == "commit" else "rolled_back"
                if plan.get("status") != target:
                    plan["status"] = target
                    if target == "applied":
                        plan["committed_at"] = entry.get("now")
                        plan["before_files"] = copy.deepcopy(before_files)
                        plan["after_files"] = copy.deepcopy(after_files)
                        plan["before_versions"] = copy.deepcopy(entry["before_versions"])
                        plan["after_versions"] = copy.deepcopy(entry["after_versions"])
                        plan["version_before"] = entry["version_before"]
                        self._counters["commits"] += 1
                    else:
                        self._counters["rollbacks"] += 1
            entry["phase"] = "recovered-commit"
        else:
            if isinstance(entry.get("before_versions"), dict):
                for name in files:
                    if name not in FILES:
                        continue
                    self._files[name] = before_files[name]
                    self._entries[name] = _parse_file(name, before_files[name])
                    self._versions[name] = entry["before_versions"][name]
            if self._version == entry.get("version_after"):
                self._version = entry.get("version_before", self._version)
            if plan is not None:
                plan["status"] = entry.get("plan_status_before", "pending")
            entry["phase"] = "recovered-rollback"
        entry["recovered_at"] = now
        return 1

    def _validate_snapshot(self, state: object) -> dict:
        try:
            if not isinstance(state, Mapping):
                raise ValueError("snapshot must be a mapping")
            required = ("files", "versions", "version", "plans", "counters")
            if any(key not in state for key in required):
                raise ValueError("snapshot is missing required fields")
            files = state["files"]
            if not isinstance(files, Mapping):
                raise ValueError("files must be a mapping")
            contents: dict[str, str] = {}
            parsed: dict[str, list[dict]] = {}
            for name in FILES:
                if name not in files or not isinstance(files[name], str):
                    raise ValueError(f"invalid file {name}")
                contents[name] = files[name]
                parsed[name] = _parse_file(name, files[name])

            versions = state["versions"]
            if not isinstance(versions, Mapping):
                raise ValueError("versions must be a mapping")
            clean_versions: dict[str, int] = {}
            for name in FILES:
                value = versions.get(name)
                if not _is_int(value) or value < 1:
                    raise ValueError(f"invalid version for {name}")
                clean_versions[name] = value

            version = state["version"]
            if not _is_int(version) or version < 0:
                raise ValueError("invalid transaction version")

            counters = state["counters"]
            counter_names = (
                "plans", "commits", "rollbacks",
                "cache_invalidations", "recovered",
            )
            if not isinstance(counters, Mapping):
                raise ValueError("counters must be a mapping")
            clean_counters = {}
            for name in counter_names:
                value = counters.get(name)
                if not _is_int(value) or value < 0:
                    raise ValueError(f"invalid counter {name}")
                clean_counters[name] = value

            plans_state = state["plans"]
            if not isinstance(plans_state, Mapping):
                raise ValueError("plans must be a mapping")
            plans = self._restore_plans(plans_state)

            journal = state.get("journal", [])
            if not isinstance(journal, list) or not all(isinstance(e, dict) for e in journal):
                raise ValueError("journal must be a list")
            journal_copy = copy.deepcopy(journal)
            cache_failures = state.get("cache_failures", [])
            if not isinstance(cache_failures, list) or not all(
                isinstance(item, dict) for item in cache_failures
            ):
                raise ValueError("cache_failures must be a list")
            return {
                "files": contents,
                "entries": parsed,
                "versions": clean_versions,
                "version": version,
                "plans": plans,
                "counters": clean_counters,
                "journal": journal_copy,
                "cache_failures": copy.deepcopy(cache_failures),
            }
        except AccountDbError as exc:
            if exc.code == "ACCOUNTDB_SNAPSHOT_INVALID":
                raise
            raise AccountDbError("ACCOUNTDB_SNAPSHOT_INVALID", str(exc)) from exc
        except Exception as exc:
            raise AccountDbError("ACCOUNTDB_SNAPSHOT_INVALID", str(exc)) from exc

    def _restore_plans(self, plans_state: Mapping[str, object]) -> dict[str, dict]:
        plans: dict[str, dict] = {}
        for key, value in plans_state.items():
            if not isinstance(key, str) or not isinstance(value, Mapping):
                raise ValueError("invalid plan")
            if value.get("plan_id") != key:
                raise ValueError("plan id mismatch")
            raw_changes = value.get("changes")
            if not isinstance(raw_changes, list):
                raise ValueError("invalid plan changes")
            changes = tuple(_change_from(item) for item in raw_changes)
            files = value.get("files")
            if not isinstance(files, (list, tuple)) or not all(
                item in FILES for item in files
            ):
                raise ValueError("invalid plan files")
            ordered_files = tuple(name for name in FILES if name in set(files))
            if ordered_files != _plan_files(changes):
                raise ValueError("plan files do not match changes")
            for change in changes:
                _validate_change_shape(change)
            lock_order = value.get("lock_order", LOCK_ORDER)
            if tuple(lock_order) != LOCK_ORDER:
                raise ValueError("invalid lock order")
            plan_version = value.get("version")
            if not _is_int(plan_version) or plan_version < 1:
                raise ValueError("invalid plan version")
            status = value.get("status")
            if status not in ("pending", "applied", "rolled_back"):
                raise ValueError("invalid plan status")
            for field_name in ("before_files", "after_files"):
                image = value.get(field_name)
                if image is not None:
                    if not isinstance(image, Mapping) or any(
                        name not in image or not isinstance(image[name], str)
                        for name in ordered_files
                    ):
                        raise ValueError(f"invalid {field_name}")
            for field_name in ("before_versions", "after_versions"):
                image = value.get(field_name)
                if image is not None:
                    if not isinstance(image, Mapping) or any(
                        name not in image
                        or not _is_int(image[name])
                        or image[name] < 1
                        for name in ordered_files
                    ):
                        raise ValueError(f"invalid {field_name}")
            if status in ("applied", "rolled_back"):
                for field_name in (
                    "before_files", "after_files",
                    "before_versions", "after_versions",
                ):
                    if value.get(field_name) is None:
                        raise ValueError(f"missing {field_name}")
            plans[key] = {
                "plan_id": key,
                "changes": changes,
                "files": ordered_files,
                "lock_order": LOCK_ORDER,
                "version": plan_version,
                "status": status,
                "before_files": copy.deepcopy(value.get("before_files")),
                "after_files": copy.deepcopy(value.get("after_files")),
                "before_versions": copy.deepcopy(value.get("before_versions")),
                "after_versions": copy.deepcopy(value.get("after_versions")),
                "version_before": value.get("version_before"),
                "committed_at": value.get("committed_at"),
                "cache_invalidated": value.get("cache_invalidated", 0),
            }
        return plans
