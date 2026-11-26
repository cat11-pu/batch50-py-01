"""PTP domain candidate tracking and best master clock selection."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass


class PtpError(ValueError):
    """Raised when a PTP message or snapshot is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class MasterInfo:
    domain: int
    clock_identity: str
    priority1: int
    clock_class: int
    clock_accuracy: int
    variance: int
    priority2: int
    steps_removed: int
    source_port: str
    sequence: int


_SNAPSHOT_VERSION = 1

_ANNOUNCE_FIELDS = (
    "domain",
    "clock_identity",
    "priority1",
    "clock_class",
    "clock_accuracy",
    "variance",
    "priority2",
    "steps_removed",
    "source_port",
)

_COUNTER_KEYS = (
    "announces",
    "duplicates",
    "syncs",
    "sync_rejected",
    "timeouts",
    "elections",
    "evicted",
    "domain_dropped",
)


class PtpDomainWarden:
    """Maintain PTP domain ports and elect the best master clock."""

    def __init__(self, *, domain: int = 0, announce_timeout: float = 3.0,
                 max_foreign: int = 16) -> None:
        self.domain = domain
        self.announce_timeout = announce_timeout
        self.max_foreign = max_foreign
        self._lock = threading.RLock()
        self._candidates = {}
        self._master_key = None
        self._sequence = 0
        self._counters = {key: 0 for key in _COUNTER_KEYS}
        self._closed = False

    @staticmethod
    def _compare_key(record: dict) -> tuple:
        return (
            record["priority1"],
            record["clock_class"],
            record["clock_accuracy"],
            record["variance"],
            record["priority2"],
            record["steps_removed"],
            record["clock_identity"],
            record["source_port"],
        )

    def _master_info_locked(self, key) -> MasterInfo:
        record = self._candidates[key]
        sequence = self._sequence if key == self._master_key else record["seq_seen"]
        return MasterInfo(
            domain=self.domain,
            clock_identity=record["clock_identity"],
            priority1=record["priority1"],
            clock_class=record["clock_class"],
            clock_accuracy=record["clock_accuracy"],
            variance=record["variance"],
            priority2=record["priority2"],
            steps_removed=record["steps_removed"],
            source_port=record["source_port"],
            sequence=sequence,
        )

    def _elect_locked(self) -> bool:
        """Recompute the best candidate. Returns True if master identity changed."""
        best_key = None
        if self._candidates:
            best_key = min(self._candidates, key=lambda k: self._compare_key(self._candidates[k]))
        if best_key == self._master_key:
            return False
        self._master_key = best_key
        if best_key is not None:
            self._sequence += 1
            self._counters["elections"] += 1
        return best_key is not None

    def _ensure_open(self) -> None:
        if self._closed:
            raise PtpError("PTP_CLOSED", "warden is closed")

    def on_announce(self, message: dict, *, now: float) -> bool:
        with self._lock:
            self._ensure_open()
            if not isinstance(message, dict):
                raise PtpError("PTP_MESSAGE_INVALID", "announce must be a mapping")
            missing = [field for field in _ANNOUNCE_FIELDS if field not in message]
            if missing:
                raise PtpError("PTP_MESSAGE_INVALID", {"missing": missing})
            if message["domain"] != self.domain:
                self._counters["domain_dropped"] += 1
                return False

            key = (message["clock_identity"], message["source_port"])
            existing = self._candidates.get(key)
            if existing is not None:
                self._counters["duplicates"] += 1
                if now - existing["last_seen"] <= self.announce_timeout:
                    existing["last_seen"] = max(existing["last_seen"], now)
                return True

            record = {field: message[field] for field in _ANNOUNCE_FIELDS}
            record["last_seen"] = now
            record["seq_seen"] = self._sequence
            self._candidates[key] = record
            self._counters["announces"] += 1

            while len(self._candidates) > self.max_foreign:
                worst = max(self._candidates,
                            key=lambda k: self._compare_key(self._candidates[k]))
                del self._candidates[worst]
                self._counters["evicted"] += 1

            self._elect_locked()
            return key in self._candidates

    def on_sync(self, message: dict, *, now: float) -> bool:
        with self._lock:
            self._ensure_open()
            accepted = False
            if isinstance(message, dict) and self._master_key is not None:
                master = self._candidates.get(self._master_key)
                if (
                    master is not None
                    and message.get("domain") == self.domain
                    and message.get("clock_identity") == master["clock_identity"]
                    and message.get("source_port") == master["source_port"]
                    and now - master["last_seen"] <= self.announce_timeout
                ):
                    accepted = True
            if accepted:
                self._counters["syncs"] += 1
            else:
                self._counters["sync_rejected"] += 1
            return accepted

    def tick(self, now: float) -> list[str]:
        with self._lock:
            events: list[str] = []
            expired = [
                key for key, record in self._candidates.items()
                if now - record["last_seen"] > self.announce_timeout
            ]
            for key in expired:
                del self._candidates[key]
                self._counters["timeouts"] += 1
            if expired:
                events.append("announce_timeout")
                if self._elect_locked():
                    events.append("master_changed")
            return events

    def elected(self) -> MasterInfo | None:
        with self._lock:
            if self._master_key is None:
                return None
            return self._master_info_locked(self._master_key)

    def state(self) -> str:
        with self._lock:
            return "master" if self._master_key is not None else "listening"

    def time_trusted(self, *, now: float | None = None) -> bool:
        with self._lock:
            if self._master_key is None:
                return False
            master = self._candidates.get(self._master_key)
            if master is None:
                return False
            if now is None:
                return True
            return now - master["last_seen"] <= self.announce_timeout

    def foreign_records(self) -> tuple[MasterInfo, ...]:
        with self._lock:
            ordered = sorted(
                self._candidates,
                key=lambda k: self._compare_key(self._candidates[k]),
            )
            return tuple(self._master_info_locked(key) for key in ordered)

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy({
                "version": _SNAPSHOT_VERSION,
                "domain": self.domain,
                "candidates": list(self._candidates.values()),
                "master": (
                    self._candidates[self._master_key]
                    if self._master_key is not None
                    else None
                ),
                "sequence": self._sequence,
                "counters": dict(self._counters),
            })

    def restore(self, state: dict) -> None:
        with self._lock:
            required = {"version", "domain", "candidates", "master", "sequence", "counters"}
            valid = (
                isinstance(state, dict)
                and required.issubset(state.keys())
                and state["version"] == _SNAPSHOT_VERSION
                and state["domain"] == self.domain
                and isinstance(state["candidates"], list)
                and isinstance(state["counters"], dict)
                and isinstance(state["sequence"], int)
                and not isinstance(state["sequence"], bool)
            )
            if not valid:
                raise PtpError("PTP_SNAPSHOT_INVALID", "malformed snapshot")
            counters = {}
            for key in _COUNTER_KEYS:
                value = state["counters"].get(key, 0)
                if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                    raise PtpError("PTP_SNAPSHOT_INVALID",
                                   {"counter": key, "value": value})
                counters[key] = value
            self._candidates = {}
            self._master_key = None
            self._sequence = state["sequence"]
            self._counters = counters

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def close(self) -> None:
        with self._lock:
            self._closed = True
