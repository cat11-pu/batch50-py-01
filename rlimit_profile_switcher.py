"""Named rlimit profiles, per-process binding stack and identity-checked restore."""

from __future__ import annotations

import threading
from dataclasses import dataclass

LIMIT_KEYS = ("nofile", "nproc", "stack")

DEFAULT_LIMITS = {
    "nofile": (1024, 4096),
    "nproc": (512, 1024),
    "stack": (8388608, 8388608),
}

SCHEMA_VERSION = 1


class RlimitError(ValueError):
    """Raised when a profile or binding operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ProfileSpec:
    """A named set of (soft, hard) rlimit targets; None means inherit."""

    name: str
    limits: dict


@dataclass(frozen=True)
class Frame:
    """One entry of a process binding stack."""

    profile: str
    tenant: str | None


class RlimitProfileSwitcher:
    """Keep named rlimit profiles and a per-pid stack of applied profiles."""

    def __init__(self, *, max_profiles: int = 32, max_frames_per_pid: int = 8) -> None:
        self.max_profiles = max_profiles
        self.max_frames_per_pid = max_frames_per_pid
        self._lock = threading.RLock()
        self._profiles = {}
        self._processes = {}
        self._bases = {}
        self._frames = {}
        self._stats = {
            "profiles": 0,
            "applied": 0,
            "denied": 0,
            "frames_popped": 0,
            "stale_bindings": 0,
            "saves": 0,
            "loads": 0,
        }

    def define_profile(self, name: str, limits: dict) -> ProfileSpec:
        raise NotImplementedError

    def remove_profile(self, name: str) -> bool:
        raise NotImplementedError

    def apply_profile(self, pid: int, name: str, *, tenant: str | None = None) -> dict:
        raise NotImplementedError

    def bind_pid(self, pid: int, name: str, *, start_time: str,
                 tenant: str | None = None) -> int:
        raise NotImplementedError

    def rollback_last(self, pid: int, *, steps: int = 1) -> tuple:
        raise NotImplementedError

    def effective_limits(self, pid: int) -> dict:
        raise NotImplementedError

    def profile_of(self, pid: int) -> str | None:
        raise NotImplementedError

    def frames(self, pid: int) -> tuple:
        raise NotImplementedError

    def register_process(self, pid: int, start_time: str) -> None:
        raise NotImplementedError

    def inherit(self, parent_pid: int, child_pid: int, *, start_time: str) -> dict:
        raise NotImplementedError

    def save(self, path: str) -> int:
        raise NotImplementedError

    def load(self, path: str) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
