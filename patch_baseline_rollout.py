"""Patch baseline rollout: missing-patch planning, batch gating, failure rollback."""

from __future__ import annotations

import threading
from dataclasses import dataclass


class RolloutError(ValueError):
    """Raised when a rollout operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


RESULT_INSTALLED = "installed"
RESULT_FAILED = "failed"
RESULT_ROLLED_BACK = "rolled_back"

RESULT_STATUSES = (RESULT_INSTALLED, RESULT_FAILED)


@dataclass(frozen=True)
class HostPlan:
    host_id: str
    missing: tuple
    batch_index: int


@dataclass(frozen=True)
class DispatchRecord:
    batch_index: int
    host_id: str
    patches: tuple
    dispatched_at: str


@dataclass(frozen=True)
class PatchResult:
    host_id: str
    patch_id: str
    status: str
    reboot_required: bool
    reboot_confirmed: bool
    recorded_at: str


class PatchBaselineRollout:
    """Plan missing patches per host, release them batch by batch, gate on success."""

    def __init__(self, *, batch_size: int = 50, success_ratio: float = 0.9) -> None:
        self.batch_size = batch_size
        self.success_ratio = success_ratio
        self._lock = threading.RLock()
        self._baseline_name = ""
        self._baseline: tuple = ()
        self._hosts: dict[str, dict] = {}
        self._batches: dict[int, list[str]] = {}
        self._dispatched: dict[int, list[DispatchRecord]] = {}
        self._results: dict[tuple[str, str], PatchResult] = {}
        self._halted = False
        self._counters: dict[str, int] = {}

    def define_baseline(self, name: str, patches) -> int:
        raise NotImplementedError

    def register_host(self, host_id: str, *, installed=(), exemptions=None,
                      window=None) -> None:
        raise NotImplementedError

    def in_window(self, host_id: str, *, now: str) -> bool:
        raise NotImplementedError

    def missing_for(self, host_id: str, *, now: str) -> tuple:
        raise NotImplementedError

    def plan(self, *, now: str) -> dict:
        raise NotImplementedError

    def dispatch(self, batch_index: int, *, now: str) -> list:
        raise NotImplementedError

    def on_result(self, host_id: str, patch_id: str, *, status: str,
                  reboot_required: bool = False, now=None) -> bool:
        raise NotImplementedError

    def confirm_reboot(self, host_id: str, *, now: str) -> int:
        raise NotImplementedError

    def gate(self, batch_index: int) -> dict:
        raise NotImplementedError

    def rollback(self, batch_index: int, *, now: str) -> int:
        raise NotImplementedError

    def batches(self) -> dict:
        raise NotImplementedError

    def status(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
