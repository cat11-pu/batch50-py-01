"""Service unit startup privilege gate: capability floor, order and rollback."""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import dataclass

SCHEMA_VERSION = 1

ALLOWED_CAPABILITIES = (
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_KILL",
    "CAP_NET_ADMIN",
    "CAP_NET_BIND_SERVICE",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
)

ROOT_ONLY_CAPABILITIES = (
    "CAP_CHOWN",
    "CAP_DAC_OVERRIDE",
    "CAP_NET_ADMIN",
    "CAP_SETGID",
    "CAP_SETUID",
    "CAP_SYS_ADMIN",
    "CAP_SYS_CHROOT",
    "CAP_SYS_PTRACE",
)

NON_ROOT_CAPABILITIES = ("CAP_KILL", "CAP_NET_BIND_SERVICE")

STATES = ("registered", "running", "stopping", "stopped", "failed")

_NAME_RE = re.compile(r"[a-z0-9._-]+\Z", re.ASCII)
_STAT_KEYS = (
    "registered",
    "started",
    "stopped",
    "rolled_back",
    "refused",
    "plans",
    "audit_writes",
    "already_running",
)
_SNAPSHOT_KEYS = ("version", "units", "audit", "counters", "stats")


class UnitGateError(ValueError):
    """Raised when a unit registration, plan or transition is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class UnitSpec:
    """Declared identity, privilege and dependency set of one unit."""

    name: str
    user: str
    capabilities: tuple
    no_new_privs: bool
    requires: tuple


@dataclass(frozen=True)
class StartupPlan:
    """Topologically ordered start list plus each unit's effective caps."""

    target: str
    ordered: tuple
    effective: dict


@dataclass(frozen=True)
class StartResult:
    """Outcome of starting one unit."""

    unit: str
    state: str
    started: bool
    effective_caps: tuple


@dataclass(frozen=True)
class StopResult:
    """Outcome of stopping one unit, with any cascaded stops."""

    unit: str
    stopped: tuple
    outcome: str


@dataclass(frozen=True)
class BatchResult:
    """Outcome of a batch start, including rollback of what it started."""

    status: str
    started: tuple
    rolled_back: tuple
    failed: str | None
    code: str | None


@dataclass(frozen=True)
class AuditEntry:
    """One sealed unit gate record."""

    seq: int
    action: str
    unit: str
    outcome: str
    code: str | None
    caps: tuple


class UnitPrivilegeGate:
    """Validate declared privileges, order starts and roll back safely."""

    def __init__(self, *, max_units: int = 128, clock=None) -> None:
        self.max_units = max_units
        self._clock = clock
        self._lock = threading.RLock()
        self._specs: dict[str, UnitSpec] = {}
        self._states: dict[str, str] = {}
        self._effective_caps: dict[str, tuple] = {}
        self._audit: list[AuditEntry] = []
        self._counters = {"audit_seq": 0}
        self._stats = {key: 0 for key in _STAT_KEYS}

    @staticmethod
    def _valid_name(name: object) -> bool:
        return (
            isinstance(name, str)
            and 1 <= len(name) <= 64
            and _NAME_RE.fullmatch(name) is not None
        )

    @staticmethod
    def _strict_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _normalize_capabilities(cls, capabilities: object) -> tuple:
        if not isinstance(capabilities, (list, tuple)):
            raise UnitGateError(
                "UNIT_INVALID_REQUEST",
                "capabilities must be a list or tuple",
            )

        normalized = set()
        for capability in capabilities:
            if not isinstance(capability, str) or not capability:
                raise UnitGateError(
                    "UNIT_INVALID_REQUEST",
                    "capability entries must be non-empty strings",
                )
            if capability not in ALLOWED_CAPABILITIES:
                raise UnitGateError(
                    "UNIT_UNKNOWN_CAPABILITY",
                    {"capability": capability},
                )
            normalized.add(capability)
        return tuple(sorted(normalized))

    @classmethod
    def _normalize_requires(cls, requires: object) -> tuple:
        if isinstance(requires, (str, bytes)):
            raise UnitGateError(
                "UNIT_INVALID_REQUEST",
                "requires must be a sequence of unit names",
            )
        try:
            items = tuple(requires)
        except TypeError as exc:
            raise UnitGateError(
                "UNIT_INVALID_REQUEST",
                "requires must be a sequence of unit names",
            ) from exc

        for dependency in items:
            if not cls._valid_name(dependency):
                raise UnitGateError(
                    "UNIT_INVALID_REQUEST",
                    {"dependency": dependency},
                )
        return items

    def _append_audit_locked(
        self,
        action: str,
        unit: object,
        outcome: str,
        code: str | None,
        caps: object,
    ) -> AuditEntry:
        if not isinstance(caps, tuple):
            caps = tuple(caps)
        unit_name = unit if isinstance(unit, str) else ""
        self._counters["audit_seq"] += 1
        entry = AuditEntry(
            seq=self._counters["audit_seq"],
            action=action,
            unit=unit_name,
            outcome=outcome,
            code=code,
            caps=caps,
        )
        self._audit.append(entry)
        self._stats["audit_writes"] += 1
        return entry

    def _refuse_locked(
        self,
        code: str,
        detail: object = None,
        *,
        action: str,
        unit: object,
        caps: object = (),
    ) -> None:
        self._stats["refused"] += 1
        self._append_audit_locked(action, unit, "refused", code, caps)
        raise UnitGateError(code, detail)

    def register_unit(self, name: str, user: str = "root",
                      capabilities=(), no_new_privs: bool = True,
                      requires=()) -> UnitSpec:
        """Validate and record one unit declaration."""
        with self._lock:
            if not self._valid_name(name):
                self._refuse_locked(
                    "UNIT_INVALID_REQUEST",
                    {"name": name},
                    action="register",
                    unit=name,
                )

            if name in self._specs:
                self._refuse_locked(
                    "UNIT_ALREADY_REGISTERED",
                    {"unit": name},
                    action="register",
                    unit=name,
                )

            if len(self._specs) >= self.max_units:
                self._refuse_locked(
                    "UNIT_CAPACITY_EXCEEDED",
                    {"max_units": self.max_units},
                    action="register",
                    unit=name,
                )

            if not isinstance(user, str) or not user:
                self._refuse_locked(
                    "UNIT_INVALID_REQUEST",
                    {"user": user},
                    action="register",
                    unit=name,
                )

            try:
                caps = self._normalize_capabilities(capabilities)
                dependency_names = self._normalize_requires(requires)
            except UnitGateError as exc:
                self._refuse_locked(
                    exc.code,
                    exc.detail,
                    action="register",
                    unit=name,
                )

            if user != "root":
                if any(cap in ROOT_ONLY_CAPABILITIES for cap in caps):
                    self._refuse_locked(
                        "UNIT_PRIVILEGE_ESCALATION",
                        {"user": user, "capabilities": caps},
                        action="register",
                        unit=name,
                        caps=caps,
                    )
                if not no_new_privs:
                    self._refuse_locked(
                        "UNIT_NO_NEW_PRIVS_REQUIRED",
                        {"user": user},
                        action="register",
                        unit=name,
                        caps=caps,
                    )

            spec = UnitSpec(
                name=name,
                user=user,
                capabilities=caps,
                no_new_privs=bool(no_new_privs),
                requires=dependency_names,
            )
            self._specs[name] = spec
            self._states[name] = "registered"
            self._effective_caps[name] = caps
            self._stats["registered"] += 1
            return spec

    def unit_spec(self, name: str) -> UnitSpec:
        """Return the declaration recorded for a unit."""
        with self._lock:
            spec = self._specs.get(name)
            if spec is None:
                raise UnitGateError("UNIT_UNKNOWN_UNIT", {"unit": name})
            return spec

    def units(self) -> tuple:
        """Return all registered unit names in order."""
        with self._lock:
            return tuple(self._specs)

    def effective_capabilities(self, name: str) -> tuple:
        """Return the capabilities the unit itself may hold at runtime."""
        with self._lock:
            if name not in self._specs:
                raise UnitGateError("UNIT_UNKNOWN_UNIT", {"unit": name})
            return tuple(self._effective_caps.get(name, ()))

    def _build_plan_locked(self, name: str) -> StartupPlan:
        if not self._valid_name(name):
            raise UnitGateError("UNIT_INVALID_REQUEST", {"unit": name})
        if name not in self._specs:
            raise UnitGateError("UNIT_UNKNOWN_UNIT", {"unit": name})

        ordered: list[str] = []
        effective: dict[str, tuple] = {}
        completed: set[str] = set()
        visiting: set[str] = set()

        def visit(current: str) -> None:
            if current in visiting:
                raise UnitGateError(
                    "UNIT_DEPENDENCY_CYCLE",
                    {"unit": current},
                )
            if current in completed:
                return

            spec = self._specs.get(current)
            if spec is None:
                raise UnitGateError(
                    "UNIT_UNKNOWN_DEPENDENCY",
                    {"dependency": current},
                )

            visiting.add(current)
            for dependency in sorted(spec.requires):
                visit(dependency)
            visiting.remove(current)
            completed.add(current)
            ordered.append(current)
            effective[current] = tuple(spec.capabilities)

        visit(name)
        return StartupPlan(
            target=name,
            ordered=tuple(ordered),
            effective=effective,
        )

    def plan_start(self, name: str) -> StartupPlan:
        """Expand the dependency chain into a deterministic start order."""
        with self._lock:
            try:
                plan = self._build_plan_locked(name)
            except UnitGateError as exc:
                self._refuse_locked(
                    exc.code,
                    exc.detail,
                    action="plan",
                    unit=name,
                    caps=self._effective_caps.get(name, ()),
                )

            self._stats["plans"] += 1
            return plan

    def start_unit(self, name: str, now=None) -> StartResult:
        """Start one unit after checking that its dependencies are running."""
        with self._lock:
            spec = self._specs.get(name)
            if spec is None:
                self._refuse_locked(
                    "UNIT_UNKNOWN_UNIT",
                    {"unit": name},
                    action="start",
                    unit=name,
                )

            if self._states[name] == "running":
                caps = tuple(self._effective_caps.get(name, spec.capabilities))
                self._stats["already_running"] += 1
                self._append_audit_locked(
                    "start", name, "already_running", None, caps
                )
                return StartResult(name, "running", False, caps)

            for dependency in spec.requires:
                if self._states.get(dependency) != "running":
                    self._refuse_locked(
                        "UNIT_DEPENDENCY_NOT_RUNNING",
                        {"unit": name, "dependency": dependency},
                        action="start",
                        unit=name,
                        caps=spec.capabilities,
                    )

            caps = tuple(spec.capabilities)
            self._states[name] = "running"
            self._effective_caps[name] = caps
            self._stats["started"] += 1
            self._append_audit_locked("start", name, "started", None, caps)
            return StartResult(name, "running", True, caps)

    def _reverse_dependencies_locked(self) -> dict[str, list[str]]:
        reverse: dict[str, list[str]] = {name: [] for name in self._specs}
        for dependent, spec in self._specs.items():
            for dependency in spec.requires:
                if dependency in reverse:
                    reverse[dependency].append(dependent)
        return reverse

    def _dependent_names_locked(self, name: str) -> set[str]:
        reverse = self._reverse_dependencies_locked()
        result: set[str] = set()
        stack = list(reverse.get(name, ()))

        while stack:
            current = stack.pop()
            if current == name or current in result:
                continue
            result.add(current)
            stack.extend(reverse.get(current, ()))
        return result

    def _cascade_stop_order_locked(self, name: str) -> tuple[str, ...]:
        reverse = self._reverse_dependencies_locked()
        ordered: list[str] = []
        completed: set[str] = set()
        active: set[str] = set()

        def visit(current: str) -> None:
            if current in completed or current in active:
                return
            active.add(current)
            for dependent in sorted(set(reverse.get(current, ()))):
                visit(dependent)
            active.discard(current)
            completed.add(current)
            ordered.append(current)

        visit(name)
        return tuple(ordered)

    def _stop_unit_record_locked(self, name: str) -> None:
        self._states[name] = "stopping"
        self._effective_caps[name] = ()
        self._states[name] = "stopped"
        self._stats["stopped"] += 1
        self._append_audit_locked("stop", name, "stopped", None, ())

    def stop_unit(self, name: str, cascade: bool = False,
                  now=None) -> StopResult:
        """Stop one unit, optionally cascading through its dependents."""
        with self._lock:
            if name not in self._specs:
                self._refuse_locked(
                    "UNIT_UNKNOWN_UNIT",
                    {"unit": name},
                    action="stop",
                    unit=name,
                )

            if not cascade:
                running_dependents = sorted(
                    dependent
                    for dependent in self._dependent_names_locked(name)
                    if self._states.get(dependent) == "running"
                )
                if running_dependents:
                    self._refuse_locked(
                        "UNIT_DEPENDENTS_RUNNING",
                        {"unit": name, "dependents": running_dependents},
                        action="stop",
                        unit=name,
                        caps=self._effective_caps.get(name, ()),
                    )
                order = (name,)
            else:
                order = self._cascade_stop_order_locked(name)

            stopped: list[str] = []
            for unit_name in order:
                if unit_name not in self._specs:
                    continue
                self._stop_unit_record_locked(unit_name)
                stopped.append(unit_name)

            return StopResult(
                unit=name,
                stopped=tuple(stopped),
                outcome="stopped",
            )

    def _rollback_unit_locked(self, name: str) -> str:
        self._stop_unit_record_locked(name)
        self._stats["rolled_back"] += 1
        self._append_audit_locked(
            "rollback", name, "rolled_back", None, ()
        )
        return name

    def start_batch(self, names, now=None) -> BatchResult:
        """Start a list of units, rolling back the batch on any failure."""
        if isinstance(names, (str, bytes)):
            with self._lock:
                self._refuse_locked(
                    "UNIT_INVALID_REQUEST",
                    {"names": names},
                    action="batch",
                    unit="",
                )

        try:
            requested_names = tuple(names)
        except TypeError as exc:
            with self._lock:
                self._refuse_locked(
                    "UNIT_INVALID_REQUEST",
                    {"names": names},
                    action="batch",
                    unit="",
                )
            raise  # pragma: no cover - _refuse_locked always raises

        with self._lock:
            started_here: list[str] = []
            failed_name: str | None = None

            try:
                for requested_name in requested_names:
                    failed_name = (
                        requested_name
                        if isinstance(requested_name, str)
                        else None
                    )
                    plan = self.plan_start(requested_name)
                    for unit_name in plan.ordered:
                        failed_name = unit_name
                        result = self.start_unit(unit_name, now=now)
                        if result.started:
                            started_here.append(unit_name)
                    failed_name = None
            except UnitGateError as exc:
                rolled_back = [
                    self._rollback_unit_locked(unit_name)
                    for unit_name in reversed(started_here)
                ]
                return BatchResult(
                    status="rolled_back",
                    started=tuple(started_here),
                    rolled_back=tuple(rolled_back),
                    failed=failed_name,
                    code=exc.code,
                )

            return BatchResult(
                status="ok",
                started=tuple(started_here),
                rolled_back=(),
                failed=None,
                code=None,
            )

    def unit_state(self, name: str) -> str:
        """Return the current state of one unit."""
        with self._lock:
            if name not in self._states:
                raise UnitGateError("UNIT_UNKNOWN_UNIT", {"unit": name})
            return self._states[name]

    def running_units(self) -> tuple:
        """Return the units currently in the running state."""
        with self._lock:
            return tuple(sorted(
                name
                for name, state in self._states.items()
                if state == "running"
            ))

    def audit_entries(self) -> tuple:
        """Return the sealed gate records in sequence order."""
        with self._lock:
            return tuple(self._audit)

    def snapshot(self) -> dict:
        """Return a detached copy of units, audit, counters and stats."""
        with self._lock:
            units = {}
            for name, spec in self._specs.items():
                units[name] = {
                    "name": spec.name,
                    "user": spec.user,
                    "capabilities": list(spec.capabilities),
                    "no_new_privs": spec.no_new_privs,
                    "requires": list(spec.requires),
                    "state": self._states[name],
                    "effective_caps": list(self._effective_caps[name]),
                }

            audit = [
                {
                    "seq": entry.seq,
                    "action": entry.action,
                    "unit": entry.unit,
                    "outcome": entry.outcome,
                    "code": entry.code,
                    "caps": list(entry.caps),
                }
                for entry in self._audit
            ]

            data = {
                "version": SCHEMA_VERSION,
                "units": units,
                "audit": audit,
                "counters": dict(self._counters),
                "stats": dict(self._stats),
            }
        return copy.deepcopy(data)

    def _snapshot_invalid(self, detail: object = None) -> None:
        raise UnitGateError("UNIT_SNAPSHOT_INVALID", detail)

    def _load_snapshot_locked(self, state: dict) -> dict:
        if not isinstance(state, dict):
            self._snapshot_invalid("snapshot must be a dict")
        if tuple(state.keys()) != _SNAPSHOT_KEYS and set(state.keys()) != set(
            _SNAPSHOT_KEYS
        ):
            self._snapshot_invalid("snapshot has unsupported keys")
        if not self._strict_int(state.get("version")):
            self._snapshot_invalid("version must be an integer")
        if state.get("version") != SCHEMA_VERSION:
            self._snapshot_invalid("unsupported snapshot version")

        units_raw = state.get("units")
        if not isinstance(units_raw, dict):
            self._snapshot_invalid("units must be a dict")

        specs: dict[str, UnitSpec] = {}
        states: dict[str, str] = {}
        effective_caps: dict[str, tuple] = {}

        for name, record in units_raw.items():
            if not self._valid_name(name) or not isinstance(record, dict):
                self._snapshot_invalid("invalid unit record")
            if "name" in record and record["name"] != name:
                self._snapshot_invalid("unit name mismatch")

            user = record.get("user")
            if not isinstance(user, str) or not user:
                self._snapshot_invalid("invalid unit user")

            try:
                caps = self._normalize_capabilities(
                    record.get("capabilities", ())
                )
                requires = self._normalize_requires(
                    record.get("requires", ())
                )
                snapshot_effective = self._normalize_capabilities(
                    record.get("effective_caps", ())
                )
            except UnitGateError:
                self._snapshot_invalid("invalid unit capability or dependency")

            no_new_privs = record.get("no_new_privs")
            if not isinstance(no_new_privs, bool):
                self._snapshot_invalid("no_new_privs must be a bool")

            unit_state = record.get("state")
            if unit_state not in STATES:
                self._snapshot_invalid("invalid unit state")

            if user != "root":
                if any(cap in ROOT_ONLY_CAPABILITIES for cap in caps):
                    self._snapshot_invalid("privilege escalation in snapshot")
                if not no_new_privs:
                    self._snapshot_invalid("no_new_privs required in snapshot")

            if unit_state == "stopped":
                if snapshot_effective:
                    self._snapshot_invalid("stopped unit retains capabilities")
            elif unit_state in ("registered", "running"):
                if snapshot_effective != caps:
                    self._snapshot_invalid("effective capabilities mismatch")

            specs[name] = UnitSpec(
                name=name,
                user=user,
                capabilities=caps,
                no_new_privs=no_new_privs,
                requires=requires,
            )
            states[name] = unit_state
            effective_caps[name] = snapshot_effective

        audit_raw = state.get("audit")
        if not isinstance(audit_raw, (list, tuple)):
            self._snapshot_invalid("audit must be a list")

        audit: list[AuditEntry] = []
        for sequence, raw_entry in enumerate(audit_raw, start=1):
            if not isinstance(raw_entry, dict):
                self._snapshot_invalid("audit entry must be a dict")
            if not self._strict_int(raw_entry.get("seq")):
                self._snapshot_invalid("audit seq must be an integer")
            if raw_entry["seq"] != sequence:
                self._snapshot_invalid("audit sequence is not continuous")
            for key in ("action", "unit", "outcome"):
                if not isinstance(raw_entry.get(key), str):
                    self._snapshot_invalid(f"audit {key} must be a string")
            code = raw_entry.get("code")
            if code is not None and not isinstance(code, str):
                self._snapshot_invalid("audit code must be a string or None")
            try:
                caps = self._normalize_capabilities(raw_entry.get("caps", ()))
            except UnitGateError:
                self._snapshot_invalid("invalid audit capabilities")

            audit.append(AuditEntry(
                seq=sequence,
                action=raw_entry["action"],
                unit=raw_entry["unit"],
                outcome=raw_entry["outcome"],
                code=code,
                caps=caps,
            ))

        counters = state.get("counters")
        if not isinstance(counters, dict):
            self._snapshot_invalid("counters must be a dict")
        if set(counters) != {"audit_seq"}:
            self._snapshot_invalid("unsupported counters")
        audit_seq = counters.get("audit_seq")
        if not self._strict_int(audit_seq) or audit_seq != len(audit):
            self._snapshot_invalid("invalid audit sequence counter")

        stats = state.get("stats")
        if not isinstance(stats, dict) or set(stats) != set(_STAT_KEYS):
            self._snapshot_invalid("invalid stats")
        for key in _STAT_KEYS:
            value = stats.get(key)
            if not self._strict_int(value) or value < 0:
                self._snapshot_invalid(f"stat {key} must be non-negative int")
        if stats["audit_writes"] != len(audit):
            self._snapshot_invalid("audit write counter mismatch")

        return {
            "specs": specs,
            "states": states,
            "effective_caps": effective_caps,
            "audit": audit,
            "counters": {"audit_seq": len(audit)},
            "stats": {key: stats[key] for key in _STAT_KEYS},
        }

    def restore(self, state: dict) -> None:
        """Replace live state with a validated snapshot."""
        with self._lock:
            loaded = self._load_snapshot_locked(state)
            self._specs = loaded["specs"]
            self._states = loaded["states"]
            self._effective_caps = loaded["effective_caps"]
            self._audit = loaded["audit"]
            self._counters = loaded["counters"]
            self._stats = loaded["stats"]

    def stats(self) -> dict:
        """Return the registration, start, stop and rollback counters."""
        with self._lock:
            return dict(self._stats)
