"""Patch baseline rollout: planning, gated dispatch, reboot and rollback state."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass
from datetime import date, datetime, time, timezone


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
SNAPSHOT_VERSION = 1
STAT_KEYS = (
    "planned",
    "dispatched",
    "installed",
    "failed",
    "duplicate_results",
    "rolled_back",
)


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


def _empty_stats() -> dict[str, int]:
    return {key: 0 for key in STAT_KEYS}


def _as_set(value) -> set:
    if value is None:
        return set()
    if isinstance(value, str):
        return {value}
    if isinstance(value, (set, frozenset, tuple, list, dict)):
        return set(value)
    return set(value)


def _as_date(value) -> date:
    if isinstance(value, datetime):
        return value.date()
    if isinstance(value, date):
        return value
    text = str(value).strip().replace("Z", "+00:00")
    if "T" in text:
        return datetime.fromisoformat(text).date()
    return date.fromisoformat(text[:10])


def _as_datetime(value) -> datetime:
    if isinstance(value, datetime):
        current = value
    else:
        text = str(value).strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        current = datetime.fromisoformat(text)
    if current.tzinfo is None:
        return current.replace(tzinfo=timezone.utc)
    return current


def _timestamp(now) -> str:
    if now is None:
        return datetime.now(timezone.utc).isoformat()
    if isinstance(now, datetime):
        return now.isoformat()
    return str(now)


def _window_parts(window):
    if isinstance(window, dict):
        start = None
        end = None
        for key in (
            "start",
            "start_at",
            "start_time",
            "start_hour",
            "begin",
            "from",
        ):
            if key in window:
                start = window[key]
                break
        for key in (
            "end",
            "end_at",
            "end_time",
            "end_hour",
            "finish",
            "until",
            "to",
        ):
            if key in window:
                end = window[key]
                break
        return start, end

    start = None
    end = None
    for start_name in ("start", "start_at", "start_time", "begin", "from_time"):
        if hasattr(window, start_name):
            start = getattr(window, start_name)
            break
    for end_name in (
        "end",
        "end_at",
        "end_time",
        "end_hour",
        "stop",
        "finish",
        "until",
        "to_time",
    ):
        if hasattr(window, end_name):
            end = getattr(window, end_name)
            break
    if start is not None or end is not None:
        return start, end

    if isinstance(window, (tuple, list)) and len(window) == 2:
        return window[0], window[1]

    if isinstance(window, str):
        for separator in ("~", "–", "—", ",", "/", " to "):
            if separator in window:
                left, right = window.split(separator, 1)
                return left.strip(), right.strip()
        parts = window.split("-")
        if len(parts) >= 6:
            return "-".join(parts[:3]), "-".join(parts[3:])
        if len(parts) == 2 and ":" in parts[0]:
            return parts[0], parts[1]

    return None, None


def _window_minutes(value, now_value: datetime) -> tuple[int, int] | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, time):
        boundary = value
        if boundary.tzinfo is not None:
            boundary_dt = datetime.combine(now_value.date(), boundary)
            if now_value.tzinfo is not None:
                boundary_dt = boundary_dt.astimezone(now_value.tzinfo)
            boundary_minutes = boundary_dt.hour * 60 + boundary_dt.minute
        else:
            boundary_minutes = boundary.hour * 60 + boundary.minute
        current_minutes = now_value.hour * 60 + now_value.minute
        return boundary_minutes, current_minutes
    if isinstance(value, datetime):
        boundary = value
        if boundary.tzinfo is None:
            boundary = boundary.replace(tzinfo=timezone.utc)
        return boundary.hour * 60 + boundary.minute, now_value.hour * 60 + now_value.minute
    if isinstance(value, (int, float)):
        hour = float(value)
        if 0 <= hour <= 24:
            boundary_minutes = int(round(hour * 60))
            return boundary_minutes, now_value.hour * 60 + now_value.minute
        return None
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if ":" in text:
            clock = text[:5] if len(text) >= 5 else text
            try:
                hour_text, minute_text = clock.split(":", 1)
                hour = int(hour_text)
                minute = int(minute_text)
                if hour == 24 and minute == 0:
                    boundary_minutes = 24 * 60
                    return boundary_minutes, now_value.hour * 60 + now_value.minute
                if 0 <= hour < 24 and 0 <= minute < 60:
                    boundary_minutes = hour * 60 + minute
                    return boundary_minutes, now_value.hour * 60 + now_value.minute
            except (ValueError, IndexError):
                pass
        try:
            parsed = time.fromisoformat(text)
        except ValueError:
            try:
                parsed_dt = _as_datetime(text)
                parsed = parsed_dt.time()
            except ValueError:
                if text.isdigit() and 0 <= int(text) <= 24:
                    boundary_minutes = int(text) * 60
                    return boundary_minutes, now_value.hour * 60 + now_value.minute
                return None
        return _window_minutes(parsed, now_value)
    return None


def _in_maintenance_window(window, now_value: datetime) -> bool:
    if window is None:
        return True
    if callable(window):
        return bool(window(now_value))

    start_raw, end_raw = _window_parts(window)
    if start_raw is None and end_raw is None:
        try:
            return bool(now_value in window)
        except TypeError:
            return False

    start_pair = _window_minutes(start_raw, now_value)
    end_pair = _window_minutes(end_raw, now_value)
    if start_pair is None or end_pair is None:
        return False

    start_minutes, current_minutes = start_pair
    end_minutes, _ = end_pair
    day_minutes = 24 * 60
    start_minutes %= day_minutes
    current_minutes %= day_minutes
    if end_minutes == day_minutes:
        return current_minutes >= start_minutes
    end_minutes %= day_minutes

    if start_minutes <= end_minutes:
        return start_minutes <= current_minutes <= end_minutes
    return current_minutes >= start_minutes or current_minutes <= end_minutes


class PatchBaselineRollout:
    """Plan missing patches per host, release them batch by batch, gate on success."""

    def __init__(self, *, batch_size: int = 50, success_ratio: float = 0.9) -> None:
        if not isinstance(batch_size, int) or isinstance(batch_size, bool) or batch_size <= 0:
            raise RolloutError("ROLLOUT_INVALID_BATCH_SIZE", batch_size)
        if isinstance(success_ratio, bool) or not isinstance(success_ratio, (int, float)):
            raise RolloutError("ROLLOUT_INVALID_SUCCESS_RATIO", success_ratio)
        if not 0 <= float(success_ratio) <= 1:
            raise RolloutError("ROLLOUT_INVALID_SUCCESS_RATIO", success_ratio)

        self.batch_size = batch_size
        self.success_ratio = float(success_ratio)
        self._lock = threading.RLock()

        self._baseline_defined = False
        self._baseline_name: str | None = None
        self._baseline: tuple = ()
        self._baseline_revision = 1

        self._hosts: dict[str, dict] = {}
        self._batches: dict[int, list[str]] = {}
        self._planned = False
        self._dispatched: dict[int, list[dict]] = {}
        self._results: dict[tuple[str, str], dict] = {}
        self._halted = False
        self._stats = _empty_stats()

        self._assigned: dict[tuple[str, str], dict] = {}
        self._dispatch_order: list[tuple[str, str]] = []

    def define_baseline(self, name: str, patches) -> int:
        with self._lock:
            patch_tuple = tuple(sorted(_as_set(patches), key=lambda item: str(item)))
            if self._baseline_defined:
                if name == self._baseline_name and patch_tuple == self._baseline:
                    return self._baseline_revision
                raise RolloutError(
                    "ROLLOUT_BASELINE_CONFLICT",
                    {"name": name, "baseline_name": self._baseline_name},
                )

            self._baseline_defined = True
            self._baseline_name = name
            self._baseline = patch_tuple
            self._baseline_revision = 1
            return self._baseline_revision

    def register_host(self, host_id: str, *, installed=(), exemptions=None,
                      window=None) -> None:
        with self._lock:
            installed_set = _as_set(installed)
            exemption_map = dict(exemptions or {})
            normalized_exemptions = {}
            for patch_id, expires_on in exemption_map.items():
                if isinstance(expires_on, (date, datetime)):
                    normalized_exemptions[patch_id] = expires_on.isoformat()[:10]
                else:
                    normalized_exemptions[patch_id] = str(expires_on)

            self._hosts[host_id] = {
                "installed": installed_set,
                "exemptions": normalized_exemptions,
                "window": window,
                "pending_reboot": set(),
                "effective": set(installed_set),
            }

    def _require_host(self, host_id: str) -> dict:
        try:
            return self._hosts[host_id]
        except KeyError as exc:
            raise RolloutError("ROLLOUT_HOST_UNKNOWN", {"host_id": host_id}) from exc

    def in_window(self, host_id: str, *, now: str) -> bool:
        with self._lock:
            host = self._require_host(host_id)
            return _in_maintenance_window(host["window"], _as_datetime(now))

    def _active_exemptions(self, host: dict, now_value: datetime) -> set:
        today = now_value.date()
        active = set()
        for patch_id, expires_on in host["exemptions"].items():
            try:
                expiry_date = _as_date(expires_on)
            except (TypeError, ValueError):
                continue
            if today < expiry_date:
                active.add(patch_id)
        return active

    def missing_for(self, host_id: str, *, now: str) -> tuple:
        with self._lock:
            host = self._require_host(host_id)
            now_value = _as_datetime(now)
            exempted = self._active_exemptions(host, now_value)
            missing = set(self._baseline) - set(host["installed"]) - exempted
            return tuple(sorted(missing, key=lambda item: str(item)))

    def _plan_chunk_size(self) -> int:
        """Use one-host replanning while a dispatched result is outstanding."""
        if self._first_pending_result_key() is not None:
            return 1
        return self.batch_size

    def plan(self, *, now: str) -> dict:
        with self._lock:
            self._planned = True
            now_value = _as_datetime(now)
            planned_hosts = []
            planned_pairs = 0
            for host_id in sorted(self._hosts, key=lambda item: str(item)):
                host = self._hosts[host_id]
                exempted = self._active_exemptions(host, now_value)
                missing = tuple(sorted(
                    set(self._baseline) - set(host["installed"]) - exempted,
                    key=lambda item: str(item),
                ))
                if missing:
                    planned_hosts.append((host_id, missing))
                    planned_pairs += len(missing)

            chunk_size = self._plan_chunk_size()
            batches = {}
            for offset in range(0, len(planned_hosts), chunk_size):
                batch_index = offset // chunk_size
                batches[batch_index] = [
                    host_id for host_id, _ in planned_hosts[offset:offset + chunk_size]
                ]

            self._batches = batches
            self._stats["planned"] = planned_pairs
            return copy.deepcopy(batches)

    def _dispatched_hosts(self, batch_index: int) -> set:
        return {
            record["host_id"]
            for record in self._dispatched.get(batch_index, [])
        }

    def _batch_complete(self, batch_index: int) -> bool:
        if batch_index not in self._dispatched:
            return False
        planned_hosts = self._batches.get(batch_index, [])
        done_hosts = self._dispatched_hosts(batch_index)
        return all(host_id in done_hosts for host_id in planned_hosts)

    def _next_batch_index(self) -> int:
        index = 0
        while self._batch_complete(index):
            index += 1
        return index

    def dispatch(self, batch_index: int, *, now: str) -> list:
        with self._lock:
            if not self._planned:
                raise RolloutError("ROLLOUT_NOT_PLANNED", {"batch_index": batch_index})

            if self._batch_complete(batch_index):
                raise RolloutError(
                    "ROLLOUT_BATCH_ALREADY_DISPATCHED",
                    {"batch_index": batch_index},
                )

            next_index = self._next_batch_index()
            if batch_index != next_index:
                raise RolloutError(
                    "ROLLOUT_BATCH_OUT_OF_ORDER",
                    {"batch_index": batch_index, "next_batch": next_index},
                )
            if batch_index not in self._batches:
                raise RolloutError("ROLLOUT_BATCH_UNKNOWN", {"batch_index": batch_index})

            if batch_index > 0:
                gate_info = self.gate(batch_index - 1)
                if not gate_info["passed"]:
                    self._halted = True
                    raise RolloutError(
                        "ROLLOUT_GATE_NOT_MET",
                        {"batch": batch_index - 1, "gate": gate_info},
                    )

            if self._halted:
                raise RolloutError("ROLLOUT_HALTED", {"batch_index": batch_index})

            now_value = _as_datetime(now)
            done_hosts = self._dispatched_hosts(batch_index)
            records = []

            for host_id in self._batches[batch_index]:
                if host_id in done_hosts:
                    continue
                if not _in_maintenance_window(
                    self._hosts[host_id]["window"], now_value
                ):
                    continue

                host = self._hosts[host_id]
                exempted = self._active_exemptions(host, now_value)
                current_missing = sorted(
                    set(self._baseline) - set(host["installed"]) - exempted,
                    key=lambda item: str(item),
                )
                patches = [
                    patch_id
                    for patch_id in current_missing
                    if (host_id, patch_id) not in self._assigned
                ]
                record = {"host_id": host_id, "patches": list(patches)}
                records.append(record)

                for patch_id in patches:
                    key = (host_id, patch_id)
                    if key in self._assigned:
                        continue
                    self._assigned[key] = {
                        "batch": batch_index,
                        "dispatched_at": _timestamp(now),
                    }
                    self._dispatch_order.append(key)
                    self._stats["dispatched"] += 1

            if not records:
                return []

            self._dispatched.setdefault(batch_index, []).extend(
                copy.deepcopy(records)
            )
            return copy.deepcopy(records)

    def _first_pending_result_key(self):
        for key in self._dispatch_order:
            if key not in self._results:
                return key
        return None

    def on_result(self, host_id: str, patch_id: str, *, status: str,
                  reboot_required: bool = False, now=None) -> bool:
        with self._lock:
            key = (host_id, patch_id)

            if key in self._results:
                self._stats["duplicate_results"] += 1
                return False

            expected_key = self._first_pending_result_key()
            if key not in self._assigned or (
                expected_key is not None and key != expected_key
            ):
                raise RolloutError(
                    "ROLLOUT_RESULT_UNKNOWN",
                    {"host_id": host_id, "patch_id": patch_id},
                )

            if status not in RESULT_STATUSES:
                raise RolloutError(
                    "ROLLOUT_RESULT_INVALID",
                    {"status": status, "allowed": list(RESULT_STATUSES)},
                )

            recorded_at = _timestamp(now)
            result = {
                "host_id": host_id,
                "patch_id": patch_id,
                "status": status,
                "reboot_required": bool(reboot_required),
                "reboot_confirmed": False,
                "recorded_at": recorded_at,
                "confirmed_at": None,
                "rolled_back": False,
                "rolled_back_at": None,
            }
            self._results[key] = result

            host = self._hosts[host_id]
            if status == RESULT_INSTALLED:
                self._stats["installed"] += 1
                host["installed"].add(patch_id)
                if reboot_required:
                    host["pending_reboot"].add(patch_id)
                    host["effective"].discard(patch_id)
                else:
                    host["effective"].add(patch_id)
                    host["pending_reboot"].discard(patch_id)
            else:
                self._stats["failed"] += 1

            return True

    def confirm_reboot(self, host_id: str, *, now: str) -> int:
        with self._lock:
            host = self._require_host(host_id)
            confirmed = 0
            confirmed_at = _timestamp(now)
            for patch_id in list(host["pending_reboot"]):
                key = (host_id, patch_id)
                if patch_id not in host["installed"]:
                    host["pending_reboot"].discard(patch_id)
                    continue
                host["pending_reboot"].discard(patch_id)
                host["effective"].add(patch_id)
                result = self._results.get(key)
                if result is not None:
                    result["reboot_confirmed"] = True
                    result["confirmed_at"] = confirmed_at
                confirmed += 1
            return confirmed

    def gate(self, batch_index: int) -> dict:
        with self._lock:
            if batch_index not in self._batches:
                raise RolloutError("ROLLOUT_BATCH_UNKNOWN", {"batch": batch_index})

            installed = 0
            failed = 0
            total = 0
            for key, metadata in self._assigned.items():
                if metadata.get("batch") != batch_index:
                    continue
                total += 1
                result = self._results.get(key)
                if result is None:
                    continue
                host_id, patch_id = key
                if result["status"] == RESULT_FAILED:
                    failed += 1
                elif (
                    result["status"] == RESULT_INSTALLED
                    and patch_id in self._hosts[host_id]["installed"]
                ):
                    installed += 1

            ratio = installed / total if total else 0.0
            passed = ratio >= self.success_ratio
            info = {
                "batch": batch_index,
                "installed": installed,
                "failed": failed,
                "total": total,
                "ratio": ratio,
                "passed": passed,
            }
            return info

    def rollback(self, batch_index: int, *, now: str) -> int:
        with self._lock:
            if batch_index not in self._batches:
                raise RolloutError("ROLLOUT_BATCH_UNKNOWN", {"batch": batch_index})
            if batch_index not in self._dispatched:
                raise RolloutError(
                    "ROLLOUT_BATCH_NOT_DISPATCHED",
                    {"batch": batch_index},
                )

            rolled_back = 0
            rolled_back_at = _timestamp(now)
            for key, metadata in list(self._assigned.items()):
                if metadata.get("batch") != batch_index:
                    continue
                host_id, patch_id = key
                host = self._hosts[host_id]
                if patch_id not in host["installed"]:
                    continue

                host["installed"].discard(patch_id)
                host["effective"].discard(patch_id)
                host["pending_reboot"].discard(patch_id)
                result = self._results.get(key)
                if result is not None:
                    result["rolled_back"] = True
                    result["rolled_back_at"] = rolled_back_at
                self._stats["rolled_back"] += 1
                rolled_back += 1

            self._halted = True
            return rolled_back

    def batches(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._batches)

    def status(self) -> dict:
        with self._lock:
            baseline_set = set(self._baseline)
            fixed = 0
            pending_reboot = 0
            for host in self._hosts.values():
                effective = host["effective"]
                pending = host["pending_reboot"]
                if baseline_set:
                    fixed += len(effective & baseline_set)
                    pending_reboot += len(pending & baseline_set)
                else:
                    fixed += len(effective)
                    pending_reboot += len(pending)

            return {
                "baseline": self._baseline_name,
                "hosts": len(self._hosts),
                "batches": len(self._batches),
                "dispatched_batches": len(self._dispatched),
                "halted": self._halted,
                "fixed": fixed,
                "failed": self._stats["failed"],
                "pending_reboot": pending_reboot,
            }

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

    def snapshot(self) -> dict:
        with self._lock:
            hosts = {}
            for host_id, host in self._hosts.items():
                hosts[host_id] = {
                    "installed": sorted(host["installed"], key=lambda item: str(item)),
                    "exemptions": copy.deepcopy(host["exemptions"]),
                    "window": copy.deepcopy(host["window"]),
                    "pending_reboot": sorted(
                        host["pending_reboot"], key=lambda item: str(item)
                    ),
                    "effective": sorted(
                        host["effective"], key=lambda item: str(item)
                    ),
                }

            return {
                "version": SNAPSHOT_VERSION,
                "batch_size": self.batch_size,
                "success_ratio": self.success_ratio,
                "baseline": list(self._baseline),
                "baseline_name": self._baseline_name,
                "baseline_defined": self._baseline_defined,
                "baseline_revision": self._baseline_revision,
                "hosts": hosts,
                "batches": copy.deepcopy(self._batches),
                "plan_ready": self._planned,
                "dispatched": copy.deepcopy(self._dispatched),
                "results": [copy.deepcopy(result) for result in self._results.values()],
                "halted": self._halted,
                "counters": copy.deepcopy(self._stats),
                "stats": self.stats(),
            }

    def _decode_snapshot(self, state: object) -> dict:
        if not isinstance(state, dict):
            raise ValueError("snapshot must be a dict")

        version = state.get("version")
        if type(version) is not int or version != SNAPSHOT_VERSION:
            raise ValueError("unsupported snapshot version")

        required = (
            "baseline",
            "baseline_name",
            "hosts",
            "batches",
            "dispatched",
            "results",
            "halted",
            "counters",
            "stats",
        )
        missing = [key for key in required if key not in state]
        if missing:
            raise ValueError(f"missing snapshot fields: {missing}")

        batch_size = state.get("batch_size", self.batch_size)
        if (
            not isinstance(batch_size, int)
            or isinstance(batch_size, bool)
            or batch_size <= 0
        ):
            raise ValueError("invalid batch_size")
        success_ratio = state.get("success_ratio", self.success_ratio)
        if isinstance(success_ratio, bool) or not isinstance(
            success_ratio, (int, float)
        ):
            raise ValueError("invalid success_ratio")
        if not 0 <= float(success_ratio) <= 1:
            raise ValueError("invalid success_ratio")

        baseline_raw = state["baseline"]
        if not isinstance(baseline_raw, (list, tuple)):
            raise ValueError("invalid baseline")
        baseline = tuple(baseline_raw)
        try:
            frozenset(baseline)
        except TypeError as exc:
            raise ValueError("invalid baseline patch ids") from exc
        baseline_name = state["baseline_name"]
        if baseline_name is not None and not isinstance(baseline_name, str):
            raise ValueError("invalid baseline_name")
        baseline_defined = state.get("baseline_defined", baseline_name is not None)
        if not isinstance(baseline_defined, bool):
            raise ValueError("invalid baseline_defined")

        hosts_raw = state["hosts"]
        if not isinstance(hosts_raw, dict):
            raise ValueError("invalid hosts")
        hosts = {}
        for host_id, raw_host in hosts_raw.items():
            if not isinstance(host_id, str) or not isinstance(raw_host, dict):
                raise ValueError("invalid host entry")
            installed = _as_set(raw_host.get("installed", ()))
            exemptions = raw_host.get("exemptions") or {}
            if not isinstance(exemptions, dict):
                raise ValueError("invalid exemptions")
            pending_reboot = _as_set(raw_host.get("pending_reboot", ()))
            effective = _as_set(raw_host.get("effective", installed))
            window = raw_host.get("window")
            hosts[host_id] = {
                "installed": installed,
                "exemptions": dict(exemptions),
                "window": copy.deepcopy(window),
                "pending_reboot": pending_reboot,
                "effective": effective,
            }

        batches_raw = state["batches"]
        if not isinstance(batches_raw, dict):
            raise ValueError("invalid batches")
        batches = {}
        for batch_key, host_ids in batches_raw.items():
            if isinstance(batch_key, str) and not batch_key.lstrip("-").isdigit():
                raise ValueError("invalid batch key")
            batch_index = int(batch_key)
            if not isinstance(host_ids, list):
                raise ValueError("invalid batch hosts")
            if not all(isinstance(host_id, str) for host_id in host_ids):
                raise ValueError("invalid batch host id")
            batches[batch_index] = list(host_ids)
        if any(index < 0 for index in batches):
            raise ValueError("negative batch index")

        dispatched_raw = state["dispatched"]
        if not isinstance(dispatched_raw, dict):
            raise ValueError("invalid dispatched")
        dispatched = {}
        for batch_key, records_raw in dispatched_raw.items():
            if isinstance(batch_key, str) and not batch_key.lstrip("-").isdigit():
                raise ValueError("invalid dispatched key")
            batch_index = int(batch_key)
            if not isinstance(records_raw, list):
                raise ValueError("invalid dispatched records")
            records = []
            for record_raw in records_raw:
                if not isinstance(record_raw, dict):
                    raise ValueError("invalid dispatch record")
                host_id = record_raw.get("host_id")
                patches_raw = record_raw.get("patches")
                if not isinstance(host_id, str) or not isinstance(patches_raw, list):
                    raise ValueError("invalid dispatch record fields")
                records.append({"host_id": host_id, "patches": list(patches_raw)})
            dispatched[batch_index] = records

        assigned = {}
        dispatch_order = []
        for batch_index in sorted(dispatched):
            for record in dispatched[batch_index]:
                host_id = record["host_id"]
                for patch_id in record["patches"]:
                    key = (host_id, patch_id)
                    if key in assigned:
                        raise ValueError("duplicate assigned patch")
                    assigned[key] = {"batch": batch_index}
                    dispatch_order.append(key)

        results_raw = state["results"]
        if not isinstance(results_raw, list):
            raise ValueError("invalid results")
        results = {}
        for result_raw in results_raw:
            if not isinstance(result_raw, dict):
                raise ValueError("invalid result")
            host_id = result_raw.get("host_id")
            patch_id = result_raw.get("patch_id")
            status = result_raw.get("status")
            if not isinstance(host_id, str) or patch_id is None:
                raise ValueError("invalid result key")
            if status not in RESULT_STATUSES:
                raise ValueError("invalid result status")
            key = (host_id, patch_id)
            if key in results:
                raise ValueError("duplicate result entry")
            if key not in assigned:
                raise ValueError("result without dispatch assignment")
            result = copy.deepcopy(result_raw)
            result.setdefault("reboot_required", False)
            result.setdefault("reboot_confirmed", False)
            result.setdefault("recorded_at", None)
            result.setdefault("confirmed_at", None)
            result.setdefault("rolled_back", False)
            result.setdefault("rolled_back_at", None)
            results[key] = result

        halted = state["halted"]
        if not isinstance(halted, bool):
            raise ValueError("invalid halted")

        for field_name in ("counters", "stats"):
            if not isinstance(state[field_name], dict):
                raise ValueError(f"invalid {field_name}")

        stats_raw = state["stats"]
        counters_raw = state["counters"]
        stats = _empty_stats()
        for key in STAT_KEYS:
            value = stats_raw.get(key, counters_raw.get(key, 0))
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError(f"invalid stat {key}")
            stats[key] = value

        if all(key in stats_raw for key in STAT_KEYS):
            for key in STAT_KEYS:
                if key in counters_raw and counters_raw[key] != stats[key]:
                    raise ValueError("inconsistent counters")

        return {
            "batch_size": batch_size,
            "success_ratio": float(success_ratio),
            "planned": bool(state.get("plan_ready", True)),
            "baseline_defined": baseline_defined,
            "baseline_name": baseline_name,
            "baseline": baseline,
            "baseline_revision": int(state.get("baseline_revision", 1)),
            "hosts": hosts,
            "batches": batches,
            "dispatched": dispatched,
            "assigned": assigned,
            "dispatch_order": dispatch_order,
            "results": results,
            "halted": halted,
            "stats": stats,
        }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                decoded = self._decode_snapshot(state)
            except RolloutError:
                raise
            except Exception as exc:
                raise RolloutError(
                    "ROLLOUT_SNAPSHOT_INVALID",
                    state if isinstance(state, dict) else None,
                ) from exc

            self.batch_size = decoded["batch_size"]
            self.success_ratio = decoded["success_ratio"]
            self._baseline_defined = decoded["baseline_defined"]
            self._baseline_name = decoded["baseline_name"]
            self._baseline = decoded["baseline"]
            self._baseline_revision = decoded["baseline_revision"]
            self._hosts = decoded["hosts"]
            self._batches = decoded["batches"]
            self._planned = decoded["planned"]
            self._dispatched = decoded["dispatched"]
            self._assigned = decoded["assigned"]
            self._dispatch_order = decoded["dispatch_order"]
            self._results = decoded["results"]
            self._halted = decoded["halted"]
            self._stats = decoded["stats"]
