"""Service unit startup privilege gate: capability floor, order and rollback."""

from __future__ import annotations

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
        self._units: dict = {}
        self._states: dict = {}
        self._audit: list = []
        self._counters = {"audit_seq": 0}
        self._stats = {
            "registered": 0,
            "started": 0,
            "stopped": 0,
            "rolled_back": 0,
            "refused": 0,
            "plans": 0,
            "audit_writes": 0,
            "already_running": 0,
        }

    def register_unit(self, name: str, *, user: str, capabilities,
                      no_new_privs: bool = True, requires=()) -> UnitSpec:
        """Validate and record one unit declaration."""
        raise NotImplementedError

    def unit_spec(self, name: str) -> UnitSpec:
        """Return the declaration recorded for a unit."""
        raise NotImplementedError

    def units(self) -> tuple:
        """Return all registered unit names in order."""
        raise NotImplementedError

    def effective_capabilities(self, name: str) -> tuple:
        """Return the capabilities the unit itself may hold at runtime."""
        raise NotImplementedError

    def plan_start(self, name: str) -> StartupPlan:
        """Expand the dependency chain into a deterministic start order."""
        raise NotImplementedError

    def start_unit(self, name: str, *, now=None) -> StartResult:
        """Start one unit after checking that its dependencies are running."""
        raise NotImplementedError

    def stop_unit(self, name: str, *, cascade: bool = False,
                  now=None) -> StopResult:
        """Stop one unit, optionally cascading through its dependents."""
        raise NotImplementedError

    def start_batch(self, names, *, now=None) -> BatchResult:
        """Start a list of units, rolling back the batch on any failure."""
        raise NotImplementedError

    def unit_state(self, name: str) -> str:
        """Return the current state of one unit."""
        raise NotImplementedError

    def running_units(self) -> tuple:
        """Return the units currently in the running state."""
        raise NotImplementedError

    def audit_entries(self) -> tuple:
        """Return the sealed gate records in sequence order."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached copy of units, audit, counters and stats."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace live state with a validated snapshot."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return the registration, start, stop and rollback counters."""
        raise NotImplementedError
