"""Thread scoped fsuid/gid switching with nesting, fallback and audit trail."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass

SCHEMA_VERSION = 1

FAULT_POINTS = ("uid", "gid")

STATS_KEYS = (
    "pushes",
    "pops",
    "denied",
    "forced_returns",
    "expired_scopes",
    "depth_peak",
    "faults_injected",
)

SNAPSHOT_KEYS = ("schema", "baseline", "workers", "seq", "stats")


class GuardError(ValueError):
    """Raised when an identity switch is refused or rolled back."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ScopeHandle:
    """Token handed out by push_scope and required by pop_scope."""

    worker: int
    depth: int
    target: tuple
    deadline: int | None


@dataclass(frozen=True)
class AuditEntry:
    """One audited identity action."""

    seq: int
    worker: int
    action: str
    identity_from: tuple
    identity_to: tuple
    reason: str
    ok: bool


class FsuidSwitchGuard:
    """Switch the calling thread's fsuid/gid inside nested scopes."""

    def __init__(self, *, baseline=(1000, 1000), privileged: bool = False,
                 max_depth: int = 8) -> None:
        self.baseline = tuple(baseline)
        self.privileged = privileged
        self.max_depth = max_depth
        self._lock = threading.RLock()
        self._workers = {}
        self._seq = 0
        self._audit = []
        self._faults = {}
        self._stats = {key: 0 for key in STATS_KEYS}

    @staticmethod
    def _valid_identity(value) -> bool:
        if not isinstance(value, tuple) or len(value) != 2:
            return False
        for part in value:
            if isinstance(part, bool) or not isinstance(part, int) or part < 0:
                return False
        return True

    @staticmethod
    def _valid_moment(value) -> bool:
        return not isinstance(value, bool) and isinstance(value, int) and value > 0

    def _stack_for(self, worker: int) -> list:
        return self._workers.setdefault(worker, {"stack": []})["stack"]

    def _identity_for(self, worker: int) -> tuple:
        worker_state = self._workers.get(worker)
        if worker_state and worker_state["stack"]:
            return worker_state["stack"][-1]["target"]
        return self.baseline

    def _record(self, worker: int, action: str, identity_from, identity_to,
                reason: str, ok: bool) -> None:
        self._seq += 1
        self._audit.append(AuditEntry(self._seq, worker, action, identity_from,
                                      identity_to, reason, ok))

    def _refused(self, worker: int, code: str, identity_to, reason: str,
                 detail: object = None) -> GuardError:
        self._record(worker, "denied", self._identity_for(worker), identity_to,
                     reason, False)
        self._stats["denied"] += 1
        return GuardError(code, detail if detail is not None else
                          {"target": identity_to})

    def push_scope(self, target, *, reason: str = "", timeout: int | None = None,
                   now: int | None = None) -> ScopeHandle:
        worker = threading.get_ident()
        with self._lock:
            if not self._valid_identity(target):
                raise self._refused(worker, "IDENTITY_INVALID", target, reason)
            if (timeout is None) != (now is None):
                raise self._refused(worker, "SCOPE_INVALID", target, reason,
                                    {"timeout": timeout, "now": now})
            if timeout is not None:
                if not self._valid_moment(timeout) or not self._valid_moment(now):
                    raise self._refused(worker, "SCOPE_INVALID", target, reason,
                                        {"timeout": timeout, "now": now})
                deadline = now + timeout
            else:
                deadline = None
            if not self.privileged and target[0] < self.baseline[0]:
                raise self._refused(worker, "ELEVATION_DENIED", target, reason,
                                    {"baseline": self.baseline})
            stack = self._stack_for(worker)
            if len(stack) >= self.max_depth:
                raise self._refused(worker, "DEPTH_EXCEEDED", target, reason,
                                    {"max_depth": self.max_depth})
            failed_step = None
            for step in FAULT_POINTS:
                if self._faults.get(step, 0) > 0:
                    self._faults[step] -= 1
                    failed_step = step
                    break
            if failed_step is not None:
                # The switch is a two step uid/gid transition. A failure in
                # either step undoes the first one so no half-switched
                # identity is ever left behind.
                current = self._identity_for(worker)
                self._record(worker, "rolled_back", current, current, reason,
                             False)
                raise GuardError("SCOPE_ROLLED_BACK",
                                 {"failed_step": failed_step,
                                  "target": target})
            previous = self._identity_for(worker)
            entry = {"target": tuple(target), "deadline": deadline}
            stack.append(entry)
            depth = len(stack)
            self._stats["pushes"] += 1
            if depth > self._stats["depth_peak"]:
                self._stats["depth_peak"] = depth
            self._record(worker, "push", previous, entry["target"], reason,
                         True)
            return ScopeHandle(worker=worker, depth=depth,
                               target=entry["target"], deadline=deadline)

    def pop_scope(self, handle: ScopeHandle) -> tuple:
        worker = threading.get_ident()
        with self._lock:
            current = self._identity_for(worker)
            if not isinstance(handle, ScopeHandle):
                raise self._refused(worker, "SCOPE_OUT_OF_ORDER", current, "",
                                    {"handle": handle})
            if handle.worker != worker:
                raise self._refused(worker, "SCOPE_FOREIGN", current, "",
                                    {"handle_worker": handle.worker})
            stack = self._workers.get(worker, {"stack": []})["stack"]
            depth = len(stack)
            if (not stack or handle.depth != depth
                    or tuple(handle.target) != stack[-1]["target"]):
                raise self._refused(worker, "SCOPE_OUT_OF_ORDER", current, "",
                                    {"handle_depth": handle.depth,
                                     "handle_target": handle.target})
            stack.pop()
            restored = self._identity_for(worker)
            self._stats["pops"] += 1
            self._record(worker, "pop", current, restored, "", True)
            return restored

    def current_identity(self) -> tuple:
        worker = threading.get_ident()
        with self._lock:
            return self._identity_for(worker)

    def force_baseline(self, *, reason: str = "manual") -> tuple:
        worker = threading.get_ident()
        with self._lock:
            stack = self._workers.get(worker, {"stack": []})["stack"]
            if not stack:
                return self.baseline
            current = self._identity_for(worker)
            stack.clear()
            self._stats["forced_returns"] += 1
            self._record(worker, "force_baseline", current, self.baseline,
                         reason, True)
            return self.baseline

    def tick(self, now: int) -> int:
        worker = threading.get_ident()
        with self._lock:
            stack = self._workers.get(worker, {"stack": []})["stack"]
            if not stack:
                return 0
            expired = any(scope["deadline"] is not None and now >= scope["deadline"]
                          for scope in stack)
            if not expired:
                return 0
            current = self._identity_for(worker)
            count = len(stack)
            stack.clear()
            self._stats["expired_scopes"] += count
            self._stats["forced_returns"] += 1
            self._record(worker, "force_baseline", current, self.baseline,
                         "expired", True)
            return count

    def scope_depth(self) -> int:
        worker = threading.get_ident()
        with self._lock:
            return len(self._workers.get(worker, {"stack": []})["stack"])

    def audit_trail(self, *, limit: int | None = None) -> tuple:
        with self._lock:
            if limit is None:
                return tuple(self._audit)
            if limit <= 0:
                return ()
            return tuple(self._audit[-limit:])

    def set_baseline(self, uid: int, gid: int) -> tuple:
        worker = threading.get_ident()
        with self._lock:
            new_baseline = (uid, gid)
            if not self._valid_identity(new_baseline):
                raise GuardError("IDENTITY_INVALID",
                                 {"baseline": new_baseline})
            if any(state["stack"] for state in self._workers.values()):
                raise self._refused(worker, "GUARD_BUSY", new_baseline, "",
                                    {"baseline": self.baseline})
            old_baseline = self.baseline
            self.baseline = new_baseline
            self._record(worker, "set_baseline", old_baseline, new_baseline,
                         "", True)
            return self.baseline

    def inject_fault(self, point: str, *, times: int = 1) -> None:
        with self._lock:
            if point not in FAULT_POINTS:
                raise GuardError("FAULT_INVALID", {"point": point})
            if isinstance(times, bool) or not isinstance(times, int) or times <= 0:
                raise GuardError("FAULT_INVALID", {"times": times})
            self._faults[point] = self._faults.get(point, 0) + times
            self._stats["faults_injected"] += times

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy({
                "schema": SCHEMA_VERSION,
                "baseline": self.baseline,
                "workers": self._workers,
                "seq": self._seq,
                "stats": self._stats,
            })

    @staticmethod
    def _valid_workers(workers) -> bool:
        if not isinstance(workers, dict):
            return False
        for key, value in workers.items():
            if isinstance(key, bool) or not isinstance(key, int):
                return False
            if not isinstance(value, dict):
                return False
            stack = value.get("stack")
            if not isinstance(stack, list):
                return False
            for scope in stack:
                if not isinstance(scope, dict):
                    return False
                if not FsuidSwitchGuard._valid_identity(scope.get("target")):
                    return False
                deadline = scope.get("deadline")
                if deadline is not None and not FsuidSwitchGuard._valid_moment(
                        deadline):
                    return False
        return True

    @staticmethod
    def _valid_stats(stats) -> bool:
        if not isinstance(stats, dict):
            return False
        for key in STATS_KEYS:
            value = stats.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                return False
        return True

    def restore(self, state: dict) -> None:
        with self._lock:
            valid = isinstance(state, dict)
            if valid:
                for key in SNAPSHOT_KEYS:
                    if key not in state:
                        valid = False
                        break
            if valid:
                schema = state["schema"]
                valid = (not isinstance(schema, bool)
                         and schema == SCHEMA_VERSION)
            if valid:
                valid = self._valid_identity(state["baseline"])
            if valid:
                valid = self._valid_workers(state["workers"])
            if valid:
                seq = state["seq"]
                valid = (not isinstance(seq, bool) and isinstance(seq, int)
                         and seq >= 0)
            if valid:
                valid = self._valid_stats(state["stats"])
            if not valid:
                raise GuardError("SNAPSHOT_INVALID", {"state": state})

            workers = copy.deepcopy(state["workers"])
            for worker_state in workers.values():
                for scope in worker_state["stack"]:
                    scope["target"] = tuple(scope["target"])
            self.baseline = tuple(state["baseline"])
            self._workers = workers
            self._stats = {key: state["stats"][key] for key in STATS_KEYS}
            self._faults = {}

            # Rebuild the trail by replaying the restored scopes so sequence
            # numbers stay dense and start at 1.
            total = sum(len(worker_state["stack"])
                        for worker_state in workers.values())
            seq = max(1, state["seq"] - total + 1)
            self._audit = []
            for worker in sorted(workers):
                previous = self.baseline
                for scope in workers[worker]["stack"]:
                    self._audit.append(AuditEntry(seq, worker, "push", previous,
                                                  scope["target"], "", True))
                    previous = scope["target"]
                    seq += 1
            self._seq = max(state["seq"], seq - 1)

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
