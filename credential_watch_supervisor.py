"""Credential-leak containment for supervised processes."""

from __future__ import annotations

import copy
import threading
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import asdict, dataclass, field

__all__ = [
    "CredentialWatchError",
    "CredentialWatchSupervisor",
    "Finding",
    "ProcessView",
    "TickAction",
]


class CredentialWatchError(ValueError):
    """Raised when a supervisor operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


SNAPSHOT_VERSION = 1
_PROCESS_STATES = frozenset(
    {"healthy", "waiting_restart", "contained", "circuit_open"}
)
_STATS_KEYS = (
    "processes",
    "healthy",
    "contained",
    "circuit_open",
    "restarts",
    "missed",
    "findings",
    "rotations",
    "releases",
)


def _is_real_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _require_now(now: object) -> int:
    if not _is_real_int(now):
        raise CredentialWatchError(
            "CW_INVALID_REQUEST", {"field": "now", "value": repr(now)}
        )
    return now


def _require_nonempty_string(value: object, field_name: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise CredentialWatchError(
            "CW_INVALID_REQUEST",
            {"field": field_name, "value": repr(value)},
        )
    return value


def _positive_int(value: object) -> bool:
    return _is_real_int(value) and value > 0


def _non_negative_int(value: object) -> bool:
    return _is_real_int(value) and value >= 0


@dataclass
class _CredentialRecord:
    credential_id: str
    fingerprint: str
    registered_at: int
    updated_at: int
    rotation_count: int = 0
    retired_fingerprints: list[str] = field(default_factory=list)


@dataclass
class _ProcessRecord:
    name: str
    pid: int
    credential_ids: tuple[str, ...]
    deadline_at: int
    last_heartbeat_at: int
    registered_at: int
    state: str = "healthy"
    heartbeat_count: int = 0
    consecutive_crashes: int = 0
    restart_count: int = 0
    restart_due_at: int | None = None
    containment_reason: str | None = None
    contained_at: int | None = None
    crash_times: list[int] = field(default_factory=list)
    last_restart_at: int | None = None


@dataclass(frozen=True)
class ProcessView:
    """Immutable snapshot of one supervised process."""

    name: str
    pid: int
    state: str
    deadline_at: int
    last_heartbeat_at: int
    heartbeat_count: int
    consecutive_crashes: int
    restart_count: int
    restart_due_at: int | None
    containment_reason: str | None
    credential_ids: tuple[str, ...]


@dataclass(frozen=True)
class Finding:
    """One credential fingerprint observed inside a supervised process."""

    process: str
    credential_id: str
    fingerprint: str
    source: str
    location: str
    fd: int | None
    detected_at: int
    status: str


@dataclass(frozen=True)
class TickAction:
    """One decision produced by a heartbeat tick."""

    process: str
    action: str
    at: int
    due_at: int | None
    attempt: int


def _snapshot_invalid(detail: object = None) -> CredentialWatchError:
    return CredentialWatchError("CW_SNAPSHOT_INVALID", detail)


def _snapshot_string(value: object) -> bool:
    return isinstance(value, str) and bool(value)


def _build_restored_state(data: dict) -> dict:
    required = {
        "version",
        "processes",
        "credentials",
        "retired",
        "findings",
        "counters",
        "stats",
    }
    if not required.issubset(data):
        raise _snapshot_invalid({"reason": "missing_keys"})
    if not _is_real_int(data["version"]) or data["version"] != SNAPSHOT_VERSION:
        raise _snapshot_invalid({"reason": "version"})

    processes_data = data["processes"]
    credentials_data = data["credentials"]
    retired_data = data["retired"]
    findings_data = data["findings"]
    counters_data = data["counters"]
    stats_data = data["stats"]

    if not isinstance(processes_data, dict):
        raise _snapshot_invalid({"field": "processes"})
    if not isinstance(credentials_data, dict):
        raise _snapshot_invalid({"field": "credentials"})
    if not isinstance(findings_data, (list, tuple)):
        raise _snapshot_invalid({"field": "findings"})
    if not isinstance(counters_data, dict):
        raise _snapshot_invalid({"field": "counters"})
    if not isinstance(stats_data, dict):
        raise _snapshot_invalid({"field": "stats"})

    if isinstance(retired_data, dict):
        retired_fingerprints = list(retired_data.keys())
    elif isinstance(retired_data, (list, tuple)):
        retired_fingerprints = list(retired_data)
    else:
        raise _snapshot_invalid({"field": "retired"})
    for fingerprint in retired_fingerprints:
        if not _snapshot_string(fingerprint):
            raise _snapshot_invalid({"field": "retired"})

    for key in _STATS_KEYS:
        if key in stats_data:
            value = stats_data[key]
            if not _non_negative_int(value):
                raise _snapshot_invalid({"field": f"stats.{key}"})

    findings: OrderedDict[tuple, Finding] = OrderedDict()
    for item in findings_data:
        if not isinstance(item, dict):
            raise _snapshot_invalid({"field": "findings[]"})
        try:
            process_name = item["process"]
            credential_id = item["credential_id"]
            fingerprint = item["fingerprint"]
            source = item["source"]
            location = item["location"]
            fd = item["fd"]
            detected_at = item["detected_at"]
            status = item["status"]
        except KeyError as exc:
            raise _snapshot_invalid({"field": "findings[]"}) from exc

        if not all(
            _snapshot_string(value)
            for value in (
                process_name,
                credential_id,
                fingerprint,
                source,
                location,
                status,
            )
        ):
            raise _snapshot_invalid({"field": "findings[]"})
        if source not in {"env", "fd"}:
            raise _snapshot_invalid({"field": "findings[].source"})
        if not _is_real_int(detected_at):
            raise _snapshot_invalid({"field": "findings[].detected_at"})
        if source == "env":
            if fd is not None:
                raise _snapshot_invalid({"field": "findings[].fd"})
            dedupe_key = (process_name, "env", location, fingerprint)
        else:
            if not _non_negative_int(fd):
                raise _snapshot_invalid({"field": "findings[].fd"})
            dedupe_key = (process_name, "fd", fd, fingerprint)

        if dedupe_key in findings:
            raise _snapshot_invalid({"field": "findings[].duplicate"})
        findings[dedupe_key] = Finding(
            process=process_name,
            credential_id=credential_id,
            fingerprint=fingerprint,
            source=source,
            location=location,
            fd=fd,
            detected_at=detected_at,
            status=status,
        )

    credentials: dict[str, _CredentialRecord] = {}
    for credential_id, record in credentials_data.items():
        if not _snapshot_string(credential_id) or not isinstance(record, dict):
            raise _snapshot_invalid({"field": "credentials[]"})
        if "credential_id" in record and record["credential_id"] != credential_id:
            raise _snapshot_invalid({"field": "credentials[].credential_id"})
        fingerprint = record.get("fingerprint")
        if not _snapshot_string(fingerprint):
            raise _snapshot_invalid({"field": "credentials[].fingerprint"})

        registered_at = record.get("registered_at", record.get("updated_at", 0))
        updated_at = record.get("updated_at", registered_at)
        if not _is_real_int(registered_at) or not _is_real_int(updated_at):
            raise _snapshot_invalid({"field": "credentials[].time"})

        rotation_count = record.get("rotation_count", 0)
        if not _non_negative_int(rotation_count):
            raise _snapshot_invalid({"field": "credentials[].rotation_count"})

        retired_history = record.get("retired_fingerprints", [])
        if not isinstance(retired_history, (list, tuple)) or any(
            not _snapshot_string(value) for value in retired_history
        ):
            raise _snapshot_invalid(
                {"field": "credentials[].retired_fingerprints"}
            )

        credentials[credential_id] = _CredentialRecord(
            credential_id=credential_id,
            fingerprint=fingerprint,
            registered_at=registered_at,
            updated_at=updated_at,
            rotation_count=rotation_count,
            retired_fingerprints=list(retired_history),
        )

    processes: dict[str, _ProcessRecord] = {}
    for name, record in processes_data.items():
        if not _snapshot_string(name) or not isinstance(record, dict):
            raise _snapshot_invalid({"field": "processes[]"})
        if "name" in record and record["name"] != name:
            raise _snapshot_invalid({"field": "processes[].name"})

        pid = record.get("pid")
        state = record.get("state")
        deadline_at = record.get("deadline_at")
        last_heartbeat_at = record.get("last_heartbeat_at")
        heartbeat_count = record.get("heartbeat_count", 0)
        consecutive_crashes = record.get("consecutive_crashes", 0)
        restart_count = record.get("restart_count", 0)
        restart_due_at = record.get("restart_due_at")
        containment_reason = record.get("containment_reason")
        credential_ids = record.get("credential_ids", ())

        if not _positive_int(pid):
            raise _snapshot_invalid({"field": "processes[].pid"})
        if state not in _PROCESS_STATES:
            raise _snapshot_invalid({"field": "processes[].state"})
        if not _is_real_int(deadline_at) or not _is_real_int(last_heartbeat_at):
            raise _snapshot_invalid({"field": "processes[].deadline"})
        for field_name, value in (
            ("heartbeat_count", heartbeat_count),
            ("consecutive_crashes", consecutive_crashes),
            ("restart_count", restart_count),
        ):
            if not _non_negative_int(value):
                raise _snapshot_invalid({"field": f"processes[].{field_name}"})
        if not (restart_due_at is None or _is_real_int(restart_due_at)):
            raise _snapshot_invalid({"field": "processes[].restart_due_at"})
        if containment_reason is not None and not isinstance(
            containment_reason, str
        ):
            raise _snapshot_invalid(
                {"field": "processes[].containment_reason"}
            )
        if not isinstance(credential_ids, (list, tuple)) or any(
            not _snapshot_string(value) for value in credential_ids
        ):
            raise _snapshot_invalid({"field": "processes[].credential_ids"})

        registered_at = record.get("registered_at", last_heartbeat_at)
        contained_at = record.get("contained_at")
        last_restart_at = record.get("last_restart_at")
        crash_times = record.get("crash_times", [])
        if not _is_real_int(registered_at):
            raise _snapshot_invalid({"field": "processes[].registered_at"})
        if not (contained_at is None or _is_real_int(contained_at)):
            raise _snapshot_invalid({"field": "processes[].contained_at"})
        if not (last_restart_at is None or _is_real_int(last_restart_at)):
            raise _snapshot_invalid({"field": "processes[].last_restart_at"})
        if not isinstance(crash_times, (list, tuple)) or any(
            not _is_real_int(value) for value in crash_times
        ):
            raise _snapshot_invalid({"field": "processes[].crash_times"})

        processes[name] = _ProcessRecord(
            name=name,
            pid=pid,
            credential_ids=tuple(credential_ids),
            deadline_at=deadline_at,
            last_heartbeat_at=last_heartbeat_at,
            registered_at=registered_at,
            state=state,
            heartbeat_count=heartbeat_count,
            consecutive_crashes=consecutive_crashes,
            restart_count=restart_count,
            restart_due_at=restart_due_at,
            containment_reason=containment_reason,
            contained_at=contained_at,
            crash_times=list(crash_times),
            last_restart_at=last_restart_at,
        )

    counters = {
        "restarts": 0,
        "missed": 0,
        "findings": 0,
        "rotations": 0,
        "releases": 0,
    }
    for key in counters:
        if key in counters_data:
            value = counters_data[key]
            if not _non_negative_int(value):
                raise _snapshot_invalid({"field": f"counters.{key}"})
            counters[key] = value

    fingerprints: OrderedDict[str, str] = OrderedDict()
    entries = counters_data.get("fingerprint_entries")
    if entries is not None:
        if not isinstance(entries, (list, tuple)):
            raise _snapshot_invalid(
                {"field": "counters.fingerprint_entries"}
            )
        for entry in entries:
            if not isinstance(entry, (list, tuple)) or len(entry) != 2:
                raise _snapshot_invalid(
                    {"field": "counters.fingerprint_entries[]"}
                )
            fingerprint, owner = entry
            if not _snapshot_string(fingerprint) or not isinstance(owner, str):
                raise _snapshot_invalid(
                    {"field": "counters.fingerprint_entries[]"}
                )
            fingerprints[fingerprint] = owner

    for credential_id, credential in credentials.items():
        fingerprints[credential.fingerprint] = credential_id
        for fingerprint in credential.retired_fingerprints:
            fingerprints.setdefault(fingerprint, credential_id)

    retired: OrderedDict[str, None] = OrderedDict()
    for fingerprint in retired_fingerprints:
        retired[fingerprint] = None
        if fingerprint not in fingerprints:
            owner = next(
                (
                    item.credential_id
                    for item in findings.values()
                    if item.fingerprint == fingerprint
                ),
                "",
            )
            fingerprints[fingerprint] = owner

    return {
        "processes": processes,
        "credentials": credentials,
        "fingerprints": fingerprints,
        "retired": retired,
        "findings": findings,
        "counters": counters,
    }


def _finding_sort_key(finding: Finding) -> tuple:
    return (
        finding.process,
        finding.credential_id,
        finding.source,
        finding.location,
        finding.fd if finding.fd is not None else -1,
        finding.detected_at,
        finding.fingerprint,
    )


class CredentialWatchSupervisor:
    """Scan supervised processes for credentials, contain leaks, break loops."""

    def __init__(
        self,
        *,
        heartbeat_timeout_ms: int = 5000,
        backoff_base_ms: int = 1000,
        backoff_cap_ms: int = 30000,
        crash_threshold: int = 3,
        crash_window_ms: int = 60000,
        max_fingerprints: int = 256,
        max_findings: int = 1024,
    ) -> None:
        for field_name, value in (
            ("heartbeat_timeout_ms", heartbeat_timeout_ms),
            ("backoff_base_ms", backoff_base_ms),
            ("backoff_cap_ms", backoff_cap_ms),
            ("crash_window_ms", crash_window_ms),
        ):
            if not _non_negative_int(value):
                raise CredentialWatchError(
                    "CW_INVALID_REQUEST",
                    {"field": field_name, "value": repr(value)},
                )
        if not _positive_int(crash_threshold):
            raise CredentialWatchError(
                "CW_INVALID_REQUEST", {"field": "crash_threshold"}
            )
        for field_name, value in (
            ("max_fingerprints", max_fingerprints),
            ("max_findings", max_findings),
        ):
            if not _non_negative_int(value):
                raise CredentialWatchError(
                    "CW_INVALID_REQUEST",
                    {"field": field_name, "value": repr(value)},
                )

        self.heartbeat_timeout_ms = heartbeat_timeout_ms
        self.backoff_base_ms = backoff_base_ms
        self.backoff_cap_ms = backoff_cap_ms
        self.crash_threshold = crash_threshold
        self.crash_window_ms = crash_window_ms
        self.max_fingerprints = max_fingerprints
        self.max_findings = max_findings
        self._lock = threading.RLock()
        self._processes: dict[str, _ProcessRecord] = {}
        self._credentials: dict[str, _CredentialRecord] = {}
        self._fingerprints: OrderedDict[str, str] = OrderedDict()
        self._retired: OrderedDict[str, None] = OrderedDict()
        self._findings: OrderedDict[tuple, Finding] = OrderedDict()
        self._counters = {
            "restarts": 0,
            "missed": 0,
            "findings": 0,
            "rotations": 0,
            "releases": 0,
        }

    def _process_locked(self, name: str) -> _ProcessRecord:
        try:
            return self._processes[name]
        except KeyError:
            raise CredentialWatchError(
                "CW_UNKNOWN_PROCESS", {"name": name}
            ) from None

    def _view(self, process: _ProcessRecord) -> ProcessView:
        return ProcessView(
            name=process.name,
            pid=process.pid,
            state=process.state,
            deadline_at=process.deadline_at,
            last_heartbeat_at=process.last_heartbeat_at,
            heartbeat_count=process.heartbeat_count,
            consecutive_crashes=process.consecutive_crashes,
            restart_count=process.restart_count,
            restart_due_at=process.restart_due_at,
            containment_reason=process.containment_reason,
            credential_ids=process.credential_ids,
        )

    def _enforce_fingerprint_cap_locked(self) -> None:
        while len(self._fingerprints) > self.max_fingerprints:
            oldest_fingerprint, owner = self._fingerprints.popitem(last=False)
            self._retired.pop(oldest_fingerprint, None)
            credential = self._credentials.get(owner)
            if (
                credential is not None
                and credential.fingerprint == oldest_fingerprint
            ):
                del self._credentials[owner]

    def _enforce_finding_cap_locked(self) -> None:
        while len(self._findings) > self.max_findings:
            self._findings.popitem(last=False)

    def _contain_locked(
        self, process: _ProcessRecord, now: int, reason: str
    ) -> None:
        if process.state != "contained":
            process.state = "contained"
            process.containment_reason = reason
            process.restart_due_at = None
            process.contained_at = now

    def _backoff_ms(self, attempt: int) -> int:
        if self.backoff_base_ms <= 0 or attempt <= 0:
            return 0
        delay = self.backoff_base_ms
        for _ in range(attempt - 1):
            if delay >= self.backoff_cap_ms:
                break
            delay = min(delay * 2, self.backoff_cap_ms)
        return min(delay, self.backoff_cap_ms)

    @staticmethod
    def _credential_ids_tuple(credential_ids: object) -> tuple[str, ...]:
        if credential_ids is None:
            return ()
        if isinstance(credential_ids, (str, bytes)):
            raise CredentialWatchError(
                "CW_INVALID_REQUEST", {"field": "credential_ids"}
            )
        try:
            values = tuple(credential_ids)
        except TypeError as exc:
            raise CredentialWatchError(
                "CW_INVALID_REQUEST", {"field": "credential_ids"}
            ) from exc
        for credential_id in values:
            _require_nonempty_string(credential_id, "credential_ids")
        return values

    @staticmethod
    def _environment_items(environ: object) -> list[tuple[str, str]]:
        if isinstance(environ, Mapping):
            raw_items = list(environ.items())
        else:
            if isinstance(environ, (str, bytes)):
                raise CredentialWatchError(
                    "CW_INVALID_REQUEST", {"field": "environ"}
                )
            try:
                raw_items = list(environ)
            except TypeError as exc:
                raise CredentialWatchError(
                    "CW_INVALID_REQUEST", {"field": "environ"}
                ) from exc

        items: list[tuple[str, str]] = []
        for item in raw_items:
            if not isinstance(item, (tuple, list)) or len(item) != 2:
                raise CredentialWatchError(
                    "CW_INVALID_REQUEST", {"field": "environ[]"}
                )
            key, value = item
            if not isinstance(key, str) or not isinstance(value, str):
                raise CredentialWatchError(
                    "CW_INVALID_REQUEST", {"field": "environ[]"}
                )
            items.append((key, value))
        return items

    @staticmethod
    def _descriptor_items(descriptors: object) -> list[tuple[int, str]]:
        if isinstance(descriptors, Mapping):
            raw_items = list(descriptors.items())
        else:
            if isinstance(descriptors, (str, bytes)):
                raise CredentialWatchError(
                    "CW_INVALID_REQUEST", {"field": "descriptors"}
                )
            try:
                raw_items = list(descriptors)
            except TypeError as exc:
                raise CredentialWatchError(
                    "CW_INVALID_REQUEST", {"field": "descriptors"}
                ) from exc

        items: list[tuple[int, str]] = []
        for item in raw_items:
            if isinstance(item, Mapping):
                fd = item.get("fd")
                path = item.get("path")
            elif hasattr(item, "fd") and hasattr(item, "path"):
                fd = item.fd
                path = item.path
            elif isinstance(item, (tuple, list)) and len(item) == 2:
                fd, path = item
            else:
                raise CredentialWatchError(
                    "CW_INVALID_REQUEST", {"field": "descriptors[]"}
                )
            if not _non_negative_int(fd):
                raise CredentialWatchError(
                    "CW_INVALID_REQUEST", {"field": "descriptor.fd"}
                )
            _require_nonempty_string(path, "descriptor.path")
            items.append((fd, path))
        return items

    def register_credential(
        self, credential_id: str, fingerprint: str, *, now: int = 0
    ) -> None:
        credential_id = _require_nonempty_string(
            credential_id, "credential_id"
        )
        fingerprint = _require_nonempty_string(fingerprint, "fingerprint")
        now = _require_now(now)

        with self._lock:
            if credential_id in self._credentials:
                raise CredentialWatchError(
                    "CW_DUPLICATE_CREDENTIAL",
                    {"credential_id": credential_id},
                )
            if fingerprint in self._fingerprints:
                raise CredentialWatchError(
                    "CW_FINGERPRINT_CONFLICT",
                    {"fingerprint": fingerprint},
                )

            record = _CredentialRecord(
                credential_id=credential_id,
                fingerprint=fingerprint,
                registered_at=now,
                updated_at=now,
            )
            self._credentials[credential_id] = record
            self._fingerprints[fingerprint] = credential_id
            self._enforce_fingerprint_cap_locked()

    def rotate_credential(
        self, credential_id: str, fingerprint: str, *, now: int = 0
    ) -> int:
        credential_id = _require_nonempty_string(
            credential_id, "credential_id"
        )
        fingerprint = _require_nonempty_string(fingerprint, "fingerprint")
        now = _require_now(now)

        with self._lock:
            credential = self._credentials.get(credential_id)
            if credential is None:
                raise CredentialWatchError(
                    "CW_UNKNOWN_CREDENTIAL",
                    {"credential_id": credential_id},
                )

            old_fingerprint = credential.fingerprint
            if fingerprint == old_fingerprint:
                return 0

            owner = self._fingerprints.get(fingerprint)
            if owner is not None and owner != credential_id:
                raise CredentialWatchError(
                    "CW_FINGERPRINT_CONFLICT",
                    {"fingerprint": fingerprint, "credential_id": owner},
                )

            if fingerprint in self._fingerprints:
                self._fingerprints.move_to_end(fingerprint)
            else:
                self._fingerprints[fingerprint] = credential_id

            if old_fingerprint not in credential.retired_fingerprints:
                credential.retired_fingerprints.append(old_fingerprint)
            self._retired[old_fingerprint] = None
            credential.fingerprint = fingerprint
            credential.updated_at = now
            credential.rotation_count += 1

            for key, finding in tuple(self._findings.items()):
                if finding.fingerprint == old_fingerprint:
                    updated = asdict(finding)
                    updated["status"] = "retired"
                    self._findings[key] = Finding(**updated)
                elif (
                    finding.fingerprint == fingerprint
                    and finding.status == "retired"
                ):
                    updated = asdict(finding)
                    updated["status"] = "active"
                    self._findings[key] = Finding(**updated)

            self._retired.pop(fingerprint, None)
            self._counters["rotations"] += 1
            self._enforce_fingerprint_cap_locked()
            return 1

    def register_process(
        self,
        name: str,
        *,
        pid: int,
        credential_ids=(),
        now: int = 0,
    ) -> ProcessView:
        name = _require_nonempty_string(name, "name")
        if not _positive_int(pid):
            raise CredentialWatchError(
                "CW_INVALID_REQUEST", {"field": "pid", "value": repr(pid)}
            )
        now = _require_now(now)
        requested_ids = self._credential_ids_tuple(credential_ids)

        with self._lock:
            if name in self._processes:
                raise CredentialWatchError(
                    "CW_DUPLICATE_PROCESS", {"name": name}
                )
            for credential_id in requested_ids:
                if credential_id not in self._credentials:
                    raise CredentialWatchError(
                        "CW_INVALID_REQUEST",
                        {
                            "field": "credential_ids",
                            "credential_id": credential_id,
                        },
                    )

            process = _ProcessRecord(
                name=name,
                pid=pid,
                credential_ids=requested_ids,
                deadline_at=now + self.heartbeat_timeout_ms,
                last_heartbeat_at=now,
                registered_at=now,
            )
            self._processes[name] = process
            return self._view(process)

    def unregister_process(self, name: str, *, now: int = 0) -> None:
        name = _require_nonempty_string(name, "name")
        now = _require_now(now)
        with self._lock:
            self._process_locked(name)
            del self._processes[name]

    def heartbeat(self, name: str, *, now: int) -> int:
        name = _require_nonempty_string(name, "name")
        now = _require_now(now)

        with self._lock:
            process = self._process_locked(name)
            if now < process.last_heartbeat_at:
                raise CredentialWatchError(
                    "CW_INVALID_REQUEST",
                    {
                        "field": "now",
                        "last_heartbeat_at": process.last_heartbeat_at,
                        "now": now,
                    },
                )

            process.heartbeat_count += 1
            process.last_heartbeat_at = now
            process.deadline_at = now + self.heartbeat_timeout_ms
            if process.state == "waiting_restart":
                process.state = "healthy"
                process.restart_due_at = None
            return process.deadline_at

    def scan_environment(
        self, name: str, environ, *, now: int
    ) -> tuple[Finding, ...]:
        name = _require_nonempty_string(name, "name")
        now = _require_now(now)
        created: list[Finding] = []

        with self._lock:
            process = self._process_locked(name)
            items = self._environment_items(environ)
            for variable_name, value in items:
                for fingerprint, credential_id in self._fingerprints.items():
                    if fingerprint in self._retired:
                        continue
                    if (
                        fingerprint not in variable_name
                        and fingerprint not in value
                    ):
                        continue

                    dedupe_key = (
                        process.name,
                        "env",
                        variable_name,
                        fingerprint,
                    )
                    finding = self._findings.get(dedupe_key)
                    if finding is None:
                        finding = Finding(
                            process=process.name,
                            credential_id=credential_id,
                            fingerprint=fingerprint,
                            source="env",
                            location=variable_name,
                            fd=None,
                            detected_at=now,
                            status="active",
                        )
                        self._findings[dedupe_key] = finding
                        self._counters["findings"] += 1
                        created.append(finding)
                        self._enforce_finding_cap_locked()

                    self._contain_locked(process, now, "credential_leak")

            return tuple(sorted(created, key=_finding_sort_key))

    def scan_descriptors(
        self, name: str, descriptors, *, now: int
    ) -> tuple[Finding, ...]:
        name = _require_nonempty_string(name, "name")
        now = _require_now(now)
        created: list[Finding] = []

        with self._lock:
            process = self._process_locked(name)
            items = self._descriptor_items(descriptors)
            for fd, path in items:
                for fingerprint, credential_id in self._fingerprints.items():
                    if fingerprint in self._retired:
                        continue
                    if fingerprint not in path:
                        continue

                    dedupe_key = (process.name, "fd", fd, fingerprint)
                    finding = self._findings.get(dedupe_key)
                    if finding is None:
                        finding = Finding(
                            process=process.name,
                            credential_id=credential_id,
                            fingerprint=fingerprint,
                            source="fd",
                            location=path,
                            fd=fd,
                            detected_at=now,
                            status="active",
                        )
                        self._findings[dedupe_key] = finding
                        self._counters["findings"] += 1
                        created.append(finding)
                        self._enforce_finding_cap_locked()

                    self._contain_locked(process, now, "credential_leak")

            return tuple(sorted(created, key=_finding_sort_key))

    def tick(self, now: int) -> tuple[TickAction, ...]:
        now = _require_now(now)
        actions: list[TickAction] = []

        with self._lock:
            for name in sorted(self._processes):
                process = self._processes[name]

                if process.state == "contained":
                    if now > process.deadline_at:
                        actions.append(
                            TickAction(
                                name,
                                "skipped",
                                now,
                                None,
                                process.consecutive_crashes,
                            )
                        )
                    continue

                if process.state == "circuit_open":
                    if now > process.deadline_at:
                        actions.append(
                            TickAction(
                                name,
                                "skipped",
                                now,
                                None,
                                process.consecutive_crashes,
                            )
                        )
                    continue

                if process.state == "waiting_restart":
                    due_at = process.restart_due_at
                    if due_at is not None and now >= due_at:
                        if process.last_restart_at == now:
                            continue
                        process.restart_count += 1
                        self._counters["restarts"] += 1
                        process.state = "healthy"
                        process.restart_due_at = None
                        process.deadline_at = (
                            now + self.heartbeat_timeout_ms
                        )
                        process.last_heartbeat_at = now
                        process.last_restart_at = now
                        actions.append(
                            TickAction(
                                name,
                                "restart",
                                now,
                                None,
                                process.restart_count,
                            )
                        )
                    continue

                if now <= process.deadline_at:
                    continue

                self._counters["missed"] += 1
                process.consecutive_crashes += 1
                process.crash_times.append(now)
                process.crash_times = [
                    timestamp
                    for timestamp in process.crash_times
                    if now - timestamp <= self.crash_window_ms
                ]

                if (
                    process.consecutive_crashes >= self.crash_threshold
                    and len(process.crash_times) >= self.crash_threshold
                ):
                    process.state = "circuit_open"
                    process.restart_due_at = None
                    process.containment_reason = "crash_loop"
                    actions.append(
                        TickAction(
                            name,
                            "circuit_open",
                            now,
                            None,
                            process.consecutive_crashes,
                        )
                    )
                    continue

                attempt = process.consecutive_crashes
                due_at = now + self._backoff_ms(attempt)
                process.state = "waiting_restart"
                process.restart_due_at = due_at
                actions.append(
                    TickAction(name, "missed", now, due_at, attempt)
                )

        return tuple(actions)

    def process_view(self, name: str) -> ProcessView:
        name = _require_nonempty_string(name, "name")
        with self._lock:
            return self._view(self._process_locked(name))

    def process_views(self) -> tuple[ProcessView, ...]:
        with self._lock:
            return tuple(
                self._view(self._processes[name])
                for name in sorted(self._processes)
            )

    def findings(self, name: str | None = None) -> tuple[Finding, ...]:
        if name is not None:
            name = _require_nonempty_string(name, "name")
        with self._lock:
            if name is not None:
                self._process_locked(name)
            values = list(self._findings.values())
            if name is not None:
                values = [
                    finding for finding in values if finding.process == name
                ]
            return tuple(sorted(values, key=_finding_sort_key))

    def release(
        self, name: str, *, operator: str, now: int = 0
    ) -> None:
        name = _require_nonempty_string(name, "name")
        now = _require_now(now)

        with self._lock:
            process = self._process_locked(name)
            if not isinstance(operator, str) or not operator.strip():
                raise CredentialWatchError(
                    "CW_INVALID_REQUEST", {"field": "operator"}
                )
            if process.state not in {"contained", "circuit_open"}:
                raise CredentialWatchError(
                    "CW_NOT_QUARANTINED",
                    {"name": name, "state": process.state},
                )

            process.state = "healthy"
            process.containment_reason = None
            process.consecutive_crashes = 0
            process.crash_times = []
            process.restart_due_at = None
            process.contained_at = None
            process.deadline_at = now + self.heartbeat_timeout_ms
            process.last_heartbeat_at = now
            self._counters["releases"] += 1

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": SNAPSHOT_VERSION,
                "processes": {
                    name: asdict(process)
                    for name, process in self._processes.items()
                },
                "credentials": {
                    credential_id: asdict(credential)
                    for credential_id, credential in self._credentials.items()
                },
                "retired": list(self._retired.keys()),
                "findings": [
                    asdict(finding) for finding in self._findings.values()
                ],
                "counters": {
                    **self._counters,
                    "fingerprint_entries": [
                        [fingerprint, owner]
                        for fingerprint, owner in self._fingerprints.items()
                    ],
                },
                "stats": self.stats(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        if not isinstance(state, Mapping):
            raise _snapshot_invalid({"reason": "state_type"})

        with self._lock:
            try:
                data = copy.deepcopy(state)
                restored = _build_restored_state(data)
            except CredentialWatchError:
                raise
            except Exception as exc:
                raise _snapshot_invalid({"reason": "parse_error"}) from exc

            self._processes = restored["processes"]
            self._credentials = restored["credentials"]
            self._fingerprints = restored["fingerprints"]
            self._retired = restored["retired"]
            self._findings = restored["findings"]
            self._counters = restored["counters"]

    def stats(self) -> dict:
        with self._lock:
            healthy = sum(
                process.state == "healthy"
                for process in self._processes.values()
            )
            contained = sum(
                process.state == "contained"
                for process in self._processes.values()
            )
            circuit_open = sum(
                process.state == "circuit_open"
                for process in self._processes.values()
            )
            return {
                "processes": len(self._processes),
                "healthy": healthy,
                "contained": contained,
                "circuit_open": circuit_open,
                "restarts": self._counters["restarts"],
                "missed": self._counters["missed"],
                "findings": self._counters["findings"],
                "rotations": self._counters["rotations"],
                "releases": self._counters["releases"],
            }
