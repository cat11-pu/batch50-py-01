"""Named rlimit profiles, per-process binding stack and identity-checked restore."""

from __future__ import annotations

import copy
import json
import os
import tempfile
import threading
from dataclasses import dataclass
from bisect import bisect_right


LIMIT_KEYS = ("nofile", "nproc", "stack")
SORTED_LIMIT_KEYS = tuple(sorted(LIMIT_KEYS))

DEFAULT_LIMITS = {
    "nofile": (1024, 4096),
    "nproc": (512, 1024),
    "stack": (8388608, 8388608),
}

SCHEMA_VERSION = 1
STATS_KEYS = (
    "profiles",
    "applied",
    "denied",
    "frames_popped",
    "stale_bindings",
    "saves",
    "loads",
)


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


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_limit_number(value: object) -> bool:
    return _is_int(value) and value >= 0


def _clean_component(value: object) -> int | None:
    if value is None:
        return None
    if not _valid_limit_number(value):
        raise RlimitError("PROFILE_INVALID", {"value": value})
    return int(value)


def _normalize_limits(limits: object) -> dict:
    if not isinstance(limits, dict) or not limits:
        raise RlimitError("PROFILE_INVALID", {"reason": "limits must be a non-empty mapping"})

    normalized: dict = {}
    for key, raw_pair in limits.items():
        if key not in LIMIT_KEYS:
            raise RlimitError("PROFILE_INVALID", {"key": key})
        if not isinstance(raw_pair, (tuple, list)) or len(raw_pair) != 2:
            raise RlimitError("PROFILE_INVALID", {"key": key, "value": raw_pair})

        soft = _clean_component(raw_pair[0])
        hard = _clean_component(raw_pair[1])
        if soft is not None and hard is not None and soft > hard:
            raise RlimitError("PROFILE_INVALID", {"key": key, "soft": soft, "hard": hard})
        normalized[key] = (soft, hard)

    return {key: normalized[key] for key in SORTED_LIMIT_KEYS if key in normalized}


def _full_limits(partial: object) -> dict:
    if not isinstance(partial, dict):
        raise RlimitError("STATE_INVALID", {"reason": "limits must be a mapping"})

    unknown = [key for key in partial if key not in LIMIT_KEYS]
    if unknown:
        raise RlimitError("STATE_INVALID", {"key": unknown[0]})

    result = copy.deepcopy(DEFAULT_LIMITS)
    for key in SORTED_LIMIT_KEYS:
        if key not in partial:
            continue
        pair = partial[key]
        if not isinstance(pair, (tuple, list)) or len(pair) != 2:
            raise RlimitError("STATE_INVALID", {"key": key, "value": pair})
        soft = pair[0]
        hard = pair[1]
        if soft is None:
            soft = result[key][0]
        if hard is None:
            hard = result[key][1]
        if not _valid_limit_number(soft) or not _valid_limit_number(hard) or soft > hard:
            raise RlimitError("STATE_INVALID", {"key": key, "soft": soft, "hard": hard})
        result[key] = (int(soft), int(hard))

    return {key: result[key] for key in SORTED_LIMIT_KEYS}


def _coerce_pid(value: object, code: str = "PID_UNKNOWN") -> int:
    if _is_int(value):
        return int(value)
    if isinstance(value, str):
        text = value.strip()
        try:
            return int(text)
        except ValueError as exc:
            raise RlimitError(code, {"pid": value}) from exc
    raise RlimitError(code, {"pid": value})


_INVALID_PID_KEY = object()


def _pid_for_lookup(value: object) -> object:
    try:
        return _coerce_pid(value)
    except RlimitError:
        return _INVALID_PID_KEY


def _json_safe(value: object) -> object:
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_safe(item) for item in value]
    if isinstance(value, ProfileSpec):
        return _json_safe(value.limits)
    if isinstance(value, Frame):
        return [value.profile, value.tenant]
    return value


class RlimitProfileSwitcher:
    """Keep named rlimit profiles and a per-pid stack of applied profiles."""

    def __init__(self, *, max_profiles: int = 32, max_frames_per_pid: int = 8) -> None:
        self.max_profiles = max_profiles
        self.max_frames_per_pid = max_frames_per_pid
        self._lock = threading.RLock()
        self._profiles: dict[str, ProfileSpec] = {}
        self._processes: dict[int, object] = {}
        self._bases: dict[int, dict] = {}
        self._frames: dict[int, list[Frame]] = {}
        self._frame_order: dict[int, list[tuple]] = {}
        self._order_seq = 0
        self._stats = {key: 0 for key in STATS_KEYS}

    def define_profile(self, name: str, limits: dict) -> ProfileSpec:
        if not isinstance(name, str) or not name.strip():
            raise RlimitError("PROFILE_INVALID", {"name": name})
        normalized = _normalize_limits(limits)

        with self._lock:
            if name in self._profiles:
                raise RlimitError("PROFILE_EXISTS", {"name": name})
            if len(self._profiles) >= self.max_profiles:
                raise RlimitError("PROFILE_CAPACITY", {"max_profiles": self.max_profiles})

            spec = ProfileSpec(name, copy.deepcopy(normalized))
            self._profiles[name] = spec
            self._stats["profiles"] = len(self._profiles)
            return ProfileSpec(name, copy.deepcopy(normalized))

    def remove_profile(self, name: str) -> bool:
        with self._lock:
            if name not in self._profiles:
                return False
            if any(frame.profile == name for stack in self._frames.values() for frame in stack):
                raise RlimitError("PROFILE_IN_USE", {"name": name})

            del self._profiles[name]
            self._stats["profiles"] = len(self._profiles)
            return True

    def apply_profile(self, pid: int, name: str, *, tenant: str | None = None) -> dict:
        with self._lock:
            return self._apply_locked(pid, name, tenant=tenant)

    def _apply_locked(self, pid: int, name: str, *, tenant: str | None) -> dict:
        try:
            pid = _coerce_pid(pid)
            spec = self._profiles.get(name) if isinstance(name, str) else None
            if spec is None:
                raise RlimitError("PROFILE_UNKNOWN", {"name": name})
            if len(self._frames.get(pid, ())) >= self.max_frames_per_pid:
                raise RlimitError(
                    "FRAME_CAPACITY",
                    {"pid": pid, "max_frames_per_pid": self.max_frames_per_pid},
                )

            effective = self._effective_locked(pid)
            candidate = copy.deepcopy(effective)
            for key, target in spec.limits.items():
                soft_target, hard_target = target
                current_soft, current_hard = candidate[key]
                next_hard = current_hard if hard_target is None else hard_target
                if next_hard > current_hard:
                    raise RlimitError(
                        "HARD_RAISE_REFUSED",
                        {"key": key, "current_hard": current_hard, "target_hard": next_hard},
                    )

                next_soft = current_soft if soft_target is None else soft_target
                if next_soft > next_hard:
                    raise RlimitError(
                        "SOFT_ABOVE_HARD",
                        {"key": key, "soft": next_soft, "hard": next_hard},
                    )
                candidate[key] = (next_soft, next_hard)

            sequence = int(self._order_seq)
            self._order_seq += 1
            frame = Frame(name, tenant)
            stack = self._frames.setdefault(pid, [])
            order = self._frame_order.setdefault(pid, [])
            native_id = threading.get_native_id()
            if native_id is None:
                native_id = threading.get_ident()
            ordered_key = (1, int(native_id), sequence)
            position = bisect_right(order, ordered_key)
            stack.insert(position, frame)
            order.insert(position, ordered_key)
            if not self._stack_transitions_safe_locked(pid):
                stack.pop(position)
                order.pop(position)
                actual_key = (2, sequence)
                stack.append(frame)
                order.append(actual_key)
            self._stats["applied"] += 1
            return self._effective_locked(pid)
        except RlimitError:
            self._stats["denied"] += 1
            raise

    def _stack_transitions_safe_locked(self, pid: object) -> bool:
        limits = copy.deepcopy(self._bases.get(pid, DEFAULT_LIMITS))
        for frame in self._frames.get(pid, ()):
            spec = self._profiles[frame.profile]
            for key, target in spec.limits.items():
                soft_target, hard_target = target
                current_soft, current_hard = limits[key]
                next_hard = current_hard if hard_target is None else hard_target
                next_soft = current_soft if soft_target is None else soft_target
                if next_hard > current_hard or next_soft > next_hard:
                    return False
                limits[key] = (next_soft, next_hard)
        return True

    def bind_pid(self, pid: int, name: str, *, start_time: str,
                 tenant: str | None = None) -> int:
        with self._lock:
            try:
                bound_pid = _coerce_pid(pid)
            except RlimitError:
                self._stats["denied"] += 1
                raise
            self._apply_locked(bound_pid, name, tenant=tenant)
            self._processes[bound_pid] = start_time
            return len(self._frames[bound_pid])

    def rollback_last(self, pid: int, *, steps: int = 1) -> tuple:
        with self._lock:
            target_pid = _pid_for_lookup(pid)
            stack = self._frames.get(target_pid)
            if not stack:
                return ()
            if not _is_int(steps):
                raise RlimitError("PROFILE_INVALID", {"steps": steps})
            if steps <= 0:
                return ()

            count = min(int(steps), len(stack))
            removed = stack[-count:]
            names = tuple(frame.profile for frame in reversed(removed))
            del stack[-count:]
            order = self._frame_order.get(target_pid, [])
            if order:
                del order[-count:]
            self._stats["frames_popped"] += count
            if not stack:
                self._frames.pop(target_pid, None)
                self._frame_order.pop(target_pid, None)
            return names

    def effective_limits(self, pid: int) -> dict:
        with self._lock:
            return self._effective_locked(_pid_for_lookup(pid))

    def _effective_locked(self, pid: object) -> dict:
        limits = copy.deepcopy(self._bases.get(pid, DEFAULT_LIMITS))
        for key in SORTED_LIMIT_KEYS:
            if key not in limits:
                limits[key] = copy.deepcopy(DEFAULT_LIMITS[key])

        for frame in self._frames.get(pid, ()):
            spec = self._profiles[frame.profile]
            for key, target in spec.limits.items():
                soft_target, hard_target = target
                current_soft, current_hard = limits[key]
                next_soft = current_soft if soft_target is None else soft_target
                next_hard = current_hard if hard_target is None else hard_target
                limits[key] = (next_soft, next_hard)

        return {key: tuple(limits[key]) for key in SORTED_LIMIT_KEYS}

    def profile_of(self, pid: int) -> str | None:
        with self._lock:
            target_pid = _pid_for_lookup(pid)
            stack = self._frames.get(target_pid)
            return stack[-1].profile if stack else None

    def frames(self, pid: int) -> tuple:
        with self._lock:
            target_pid = _pid_for_lookup(pid)
            return tuple(frame for frame in self._frames.get(target_pid, ()))

    def register_process(self, pid: int, start_time: str) -> None:
        with self._lock:
            self._processes[_coerce_pid(pid)] = start_time

    def inherit(self, parent_pid: int, child_pid: int, *, start_time: str) -> dict:
        with self._lock:
            parent = _coerce_pid(parent_pid, "PID_UNKNOWN")
            if not self._pid_known_locked(parent):
                raise RlimitError("PID_UNKNOWN", {"parent_pid": parent})

            inherited = self._effective_locked(parent)
            child = _coerce_pid(child_pid, "PID_UNKNOWN")
            self._processes[child] = start_time
            self._bases[child] = copy.deepcopy(inherited)
            return copy.deepcopy(inherited)

    def _pid_known_locked(self, pid: int) -> bool:
        return pid in self._processes or pid in self._frames or pid in self._bases

    def save(self, path: str) -> int:
        with self._lock:
            state = self._snapshot_locked()
            try:
                state["stats"]["saves"] = int(self._stats["saves"]) + 1
                payload = json.dumps(
                    _json_safe(state), ensure_ascii=False, indent=2, sort_keys=False
                )

                destination = os.path.abspath(os.fspath(path))
                directory = os.path.dirname(destination) or "."
                descriptor, temporary_path = tempfile.mkstemp(
                    prefix=".rlimit-state-", suffix=".tmp", dir=directory
                )
                try:
                    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                        handle.write(payload)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.replace(temporary_path, destination)
                    temporary_path = None
                finally:
                    if temporary_path is not None:
                        try:
                            os.unlink(temporary_path)
                        except FileNotFoundError:
                            pass
            except (OSError, TypeError, ValueError) as exc:
                raise RlimitError("STATE_WRITE_FAILED", {"path": str(path)}) from exc

            self._stats["saves"] += 1
            return int(self._stats["saves"])

    def load(self, path: str) -> dict:
        try:
            with open(os.fspath(path), "r", encoding="utf-8") as handle:
                raw = json.load(handle)
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            raise RlimitError("STATE_INVALID", {"path": str(path)}) from exc

        state = self._coerce_state(raw, "STATE_INVALID")

        with self._lock:
            live_processes = copy.deepcopy(self._processes)
            reattached = 0
            stale = 0
            restored_frames: dict[int, list[Frame]] = {}
            restored_bases: dict[int, dict] = {}
            restored_order: dict[int, list[tuple[int, int]]] = {}

            for pid, stack in state["frames"].items():
                if not stack:
                    continue
                saved_start = state["processes"].get(pid)
                current_start = live_processes.get(pid)
                if saved_start is not None and current_start == saved_start:
                    restored_frames[pid] = list(stack)
                    restored_order[pid] = [(0, index) for index in range(len(stack))]
                    reattached += 1
                else:
                    stale += len(stack)

            for pid, base in state["bases"].items():
                saved_start = state["processes"].get(pid)
                current_start = live_processes.get(pid)
                if saved_start is not None and current_start == saved_start:
                    restored_bases[pid] = copy.deepcopy(base)

            merged_processes = copy.deepcopy(state["processes"])
            merged_processes.update(live_processes)

            stats = copy.deepcopy(state["stats"])
            stats["stale_bindings"] = int(stats.get("stale_bindings", 0)) + stale
            stats["loads"] = int(self._stats.get("loads", 0)) + 1

            self._profiles = state["profiles"]
            self._processes = merged_processes
            self._bases = restored_bases
            self._frames = restored_frames
            self._frame_order = restored_order
            self._stats = stats
            return {"reattached": reattached, "stale": stale}

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._snapshot_locked())

    def _snapshot_locked(self) -> dict:
        return {
            "schema": SCHEMA_VERSION,
            "profiles": copy.deepcopy(self._profiles),
            "processes": copy.deepcopy(self._processes),
            "bases": copy.deepcopy(self._bases),
            "frames": {
                pid: copy.deepcopy(stack)
                for pid, stack in self._frames.items() if stack
            },
            "stats": self.stats(),
        }

    def restore(self, state: dict) -> None:
        canonical = self._coerce_state(state, "SNAPSHOT_INVALID")
        with self._lock:
            self._profiles = canonical["profiles"]
            self._processes = canonical["processes"]
            self._bases = canonical["bases"]
            self._frames = canonical["frames"]
            self._frame_order = {
                pid: [(0, index) for index in range(len(stack))]
                for pid, stack in canonical["frames"].items()
            }
            self._stats = canonical["stats"]

    @classmethod
    def _coerce_state(cls, raw_state: object, error_code: str) -> dict:
        def invalid(detail: object = None) -> RlimitError:
            return RlimitError(error_code, detail)

        if not isinstance(raw_state, dict):
            raise invalid({"reason": "state must be a mapping"})

        required = {"schema", "profiles", "processes", "bases", "frames", "stats"}
        missing = required.difference(raw_state)
        if missing:
            raise invalid({"missing": sorted(missing)})

        schema = raw_state["schema"]
        if not _is_int(schema) or schema != SCHEMA_VERSION:
            raise invalid({"schema": schema})
        if not isinstance(raw_state["profiles"], dict):
            raise invalid({"key": "profiles"})
        if not isinstance(raw_state["processes"], dict):
            raise invalid({"key": "processes"})
        if not isinstance(raw_state["bases"], dict):
            raise invalid({"key": "bases"})
        if not isinstance(raw_state["frames"], dict):
            raise invalid({"key": "frames"})
        if not isinstance(raw_state["stats"], dict):
            raise invalid({"key": "stats"})

        profiles: dict[str, ProfileSpec] = {}
        for name, raw_limits in raw_state["profiles"].items():
            if not isinstance(name, str) or not name.strip():
                raise invalid({"profile": name})
            limits_source = raw_limits
            if isinstance(limits_source, ProfileSpec):
                limits_source = limits_source.limits
            elif isinstance(limits_source, dict) and "limits" in limits_source:
                limits_source = limits_source["limits"]
            try:
                limits = _normalize_limits(limits_source)
            except RlimitError as exc:
                raise invalid(exc.detail) from exc
            profiles[name] = ProfileSpec(name, limits)

        processes: dict[int, object] = {}
        for raw_pid, start_time in raw_state["processes"].items():
            pid = _coerce_pid(raw_pid, error_code)
            if pid in processes:
                raise invalid({"pid": pid, "reason": "duplicate pid after normalization"})
            if not isinstance(start_time, str) and not _is_int(start_time):
                raise invalid({"pid": pid, "start_time": start_time})
            processes[pid] = start_time

        bases: dict[int, dict] = {}
        for raw_pid, raw_limits in raw_state["bases"].items():
            pid = _coerce_pid(raw_pid, error_code)
            if pid in bases:
                raise invalid({"pid": pid, "reason": "duplicate pid after normalization"})
            try:
                bases[pid] = _full_limits(raw_limits)
            except RlimitError as exc:
                raise invalid(exc.detail) from exc

        frames: dict[int, list[Frame]] = {}
        for raw_pid, raw_frames in raw_state["frames"].items():
            pid = _coerce_pid(raw_pid, error_code)
            if pid in frames:
                raise invalid({"pid": pid, "reason": "duplicate pid after normalization"})
            if not isinstance(raw_frames, (list, tuple)):
                raise invalid({"pid": pid, "reason": "frames must be a list"})

            stack: list[Frame] = []
            for raw_frame in raw_frames:
                profile_name: object
                tenant: object = None
                if isinstance(raw_frame, Frame):
                    profile_name = raw_frame.profile
                    tenant = raw_frame.tenant
                elif isinstance(raw_frame, dict):
                    profile_name = raw_frame.get("profile")
                    tenant = raw_frame.get("tenant")
                elif isinstance(raw_frame, (list, tuple)) and len(raw_frame) == 2:
                    profile_name, tenant = raw_frame
                else:
                    raise invalid({"pid": pid, "frame": raw_frame})

                if not isinstance(profile_name, str) or profile_name not in profiles:
                    raise invalid({"pid": pid, "profile": profile_name})
                if tenant is not None and not isinstance(tenant, str):
                    raise invalid({"pid": pid, "tenant": tenant})
                stack.append(Frame(profile_name, tenant))
            frames[pid] = stack

        stats_raw = raw_state["stats"]
        if set(stats_raw) != set(STATS_KEYS):
            raise invalid({"stats": sorted(stats_raw)})
        stats = {}
        for key in STATS_KEYS:
            value = stats_raw[key]
            if not _is_int(value) or value < 0:
                raise invalid({"stats_key": key, "value": value})
            stats[key] = int(value)

        for pid, stack in frames.items():
            current = copy.deepcopy(bases.get(pid, DEFAULT_LIMITS))
            for frame in stack:
                spec = profiles[frame.profile]
                for key, target in spec.limits.items():
                    soft_target, hard_target = target
                    current_soft, current_hard = current[key]
                    next_hard = current_hard if hard_target is None else hard_target
                    next_soft = current_soft if soft_target is None else soft_target
                    if next_hard > current_hard or next_soft > next_hard:
                        raise invalid({"pid": pid, "profile": frame.profile})
                    current[key] = (next_soft, next_hard)

        return {
            "schema": SCHEMA_VERSION,
            "profiles": profiles,
            "processes": processes,
            "bases": bases,
            "frames": frames,
            "stats": stats,
        }

    def stats(self) -> dict:
        with self._lock:
            result = copy.deepcopy(self._stats)
            bound_profiles = {
                frame.profile
                for stack in self._frames.values()
                for frame in stack
            }
            result["profiles"] = len(self._profiles) - len(bound_profiles)
            return result
