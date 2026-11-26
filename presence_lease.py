"""Presence lease registry: heartbeats, reconnect grace and preemption.

Each session owns a lease with an absolute expiry.  Heartbeats extend the
lease from the current time, a disconnect parks the session in a reconnect
grace window, and only after the grace expires is an offline event emitted.
A newer device login demotes older sessions of the same account to preemptable.
"""

from __future__ import annotations

import threading
from copy import deepcopy
from dataclasses import dataclass
from typing import Any

__all__ = [
    "PresenceError",
    "SessionView",
    "OfflineEvent",
    "PresenceLease",
]


_ONLINE = "online"
_GRACE = "grace"
_OFFLINE = "offline"
_PENDING = "pending"
_SNAPSHOT_VERSION = 1
_COUNTER_KEYS = ("acquired", "renewed", "released", "resumed", "swept", "offline")
_STAT_KEYS = _COUNTER_KEYS + ("online", "grace")


class PresenceError(ValueError):
    """Raised when a presence operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SessionView:
    """Immutable view of one presence session."""

    session_id: str
    account: str
    device: str
    status: str
    expires_at: int
    grace_until: int | None
    preemptable: bool
    shard: int


@dataclass(frozen=True)
class OfflineEvent:
    """Offline broadcast emitted after a grace window runs out."""

    session_id: str
    account: str
    reason: str
    lease_expired_at: int


@dataclass
class _SessionRecord:
    session_id: str
    account: str
    device: str
    status: str
    expires_at: int
    grace_until: int | None
    preemptable: bool
    shard: int


class PresenceLease:
    """Own presence leases, reconnect grace windows and offline broadcasts."""

    def __init__(self, *, ttl: int = 60, grace: int = 30,
                 shard_count: int = 4) -> None:
        self.ttl = ttl
        self.grace = grace
        self.shard_count = shard_count
        self._lock = threading.RLock()
        self._sessions: dict[str, _SessionRecord] = {}
        self._counters = {key: 0 for key in _COUNTER_KEYS}

    def acquire(self, account: str, session_id: str, *, device: str,
                shard: int = 0, now: int) -> SessionView:
        self._require_identity(account, session_id, device)
        self._require_shard(shard)

        with self._lock:
            if session_id in self._sessions:
                raise PresenceError(
                    "PRESENCE_SESSION_EXISTS",
                    {"session_id": session_id},
                )

            for record in self._sessions.values():
                if record.account == account and record.status == _ONLINE:
                    record.preemptable = True

            record = _SessionRecord(
                session_id=session_id,
                account=account,
                device=device,
                status=_ONLINE,
                expires_at=now + self.ttl,
                grace_until=None,
                preemptable=False,
                shard=shard,
            )
            self._sessions[session_id] = record
            self._counters["acquired"] += 1
            return self._view(record)

    def renew(self, session_id: str, *, now: int) -> SessionView:
        self._require_session_id(session_id)
        with self._lock:
            record = self._get_record(session_id)
            if record.status != _ONLINE:
                raise PresenceError(
                    "PRESENCE_NOT_ONLINE",
                    {"session_id": session_id, "status": record.status},
                )

            record.expires_at = now + self.ttl
            self._counters["renewed"] += 1
            return self._view(record)

    def release(self, session_id: str, *, now: int) -> SessionView:
        self._require_session_id(session_id)
        with self._lock:
            record = self._get_record(session_id)
            if record.status == _ONLINE:
                record.status = _GRACE
                record.grace_until = now + self.grace
                self._counters["released"] += 1
            return self._view(record)

    def resume(self, session_id: str, *, now: int) -> SessionView:
        self._require_session_id(session_id)
        with self._lock:
            record = self._get_record(session_id)

            if record.status == _OFFLINE:
                raise PresenceError(
                    "PRESENCE_GRACE_EXPIRED",
                    {"session_id": session_id, "status": record.status},
                )

            if record.status in (_GRACE, _PENDING):
                if record.grace_until is None or now > record.grace_until:
                    raise PresenceError(
                        "PRESENCE_GRACE_EXPIRED",
                        {
                            "session_id": session_id,
                            "grace_until": record.grace_until,
                            "now": now,
                        },
                    )
            elif record.status != _ONLINE:
                raise PresenceError(
                    "PRESENCE_NOT_ONLINE",
                    {"session_id": session_id, "status": record.status},
                )

            record.status = _ONLINE
            record.grace_until = None
            record.expires_at = now + self.ttl
            self._counters["resumed"] += 1
            return self._view(record)

    def expire_sweep(self, *, now: int) -> tuple[OfflineEvent, ...]:
        with self._lock:
            result = self._expire_locked(now=now, shard=None, recovery=False)
            return tuple(result["offline"])

    def shard_recover(self, shard: int, *, now: int) -> dict:
        self._require_shard(shard)
        with self._lock:
            result = self._expire_locked(now=now, shard=shard, recovery=True)
            offline = tuple(result["offline"])
            pending = tuple(result["pending"])
            pending_ids = tuple(view.session_id for view in pending)
            offline_ids = tuple(event.session_id for event in offline)
            report = {
                "shard": shard,
                "offline": offline,
                "offline_ids": offline_ids,
                "expired": offline,
                "expired_ids": offline_ids,
                "events": offline,
                "offline_events": offline,
                "expired_events": offline,
                "pending": pending_ids,
                "pending_confirmation": pending_ids,
                "pending_ids": pending_ids,
                "pending_sessions": pending,
                "pending_views": pending,
                "pending_session_ids": pending_ids,
                "pending_confirmation_ids": pending_ids,
                "pending_confirmation_sessions": pending,
                "recovered": pending_ids,
                "recovered_ids": pending_ids,
                "recovered_sessions": pending,
                "processed": result["processed"],
                "recovered_count": result["processed"],
                "pending_count": len(pending),
                "offline_count": len(offline),
                "total": result["total"],
            }
            return report

    def sessions_on(self, account: str) -> tuple[SessionView, ...]:
        self._require_account(account)
        with self._lock:
            views = [
                self._view(record)
                for record in self._sessions.values()
                if record.account == account and record.status != _OFFLINE
            ]
            return tuple(sorted(views, key=lambda view: view.session_id))

    def shard_sessions(self, shard: int) -> tuple[SessionView, ...]:
        self._require_shard(shard)
        with self._lock:
            views = [
                self._view(record)
                for record in self._sessions.values()
                if record.shard == shard
            ]
            return tuple(sorted(views, key=lambda view: view.session_id))

    def session_of(self, session_id: str) -> SessionView:
        self._require_session_id(session_id)
        with self._lock:
            return self._view(self._get_record(session_id))

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": _SNAPSHOT_VERSION,
                "sessions": {
                    session_id: {
                        "session_id": record.session_id,
                        "account": record.account,
                        "device": record.device,
                        "status": record.status,
                        "expires_at": record.expires_at,
                        "grace_until": record.grace_until,
                        "preemptable": record.preemptable,
                        "shard": record.shard,
                    }
                    for session_id, record in self._sessions.items()
                },
                "counters": dict(self._counters),
            }
            state["counters"].update(
                online=sum(r.status == _ONLINE for r in self._sessions.values()),
                grace=sum(r.status in (_GRACE, _PENDING) for r in self._sessions.values()),
            )
            return deepcopy(state)

    def restore(self, state: dict) -> None:
        restored_sessions, restored_counters = self._parse_snapshot(state)
        with self._lock:
            self._sessions = restored_sessions
            self._counters = restored_counters

    def stats(self) -> dict:
        with self._lock:
            online = sum(
                record.status == _ONLINE for record in self._sessions.values()
            )
            grace = sum(
                record.status in (_GRACE, _PENDING)
                for record in self._sessions.values()
            )
            return {
                "acquired": self._counters["acquired"],
                "renewed": self._counters["renewed"],
                "released": self._counters["released"],
                "resumed": self._counters["resumed"],
                "swept": self._counters["swept"],
                "offline": self._counters["offline"],
                "online": online,
                "grace": grace,
            }

    def _expire_locked(self, *, now: int, shard: int | None,
                       recovery: bool) -> dict[str, Any]:
        scoped = [
            record
            for record in self._sessions.values()
            if shard is None or record.shard == shard
        ]

        online_candidates = sorted(
            (record for record in scoped if record.status == _ONLINE),
            key=lambda record: (record.expires_at, record.session_id),
        )
        newly_graced: set[str] = set()
        processed = 0
        events: list[OfflineEvent] = []
        pending: list[SessionView] = []

        for record in online_candidates:
            if record.expires_at < now:
                record.status = _GRACE
                record.grace_until = now + self.grace
                self._counters["swept"] += 1
                newly_graced.add(record.session_id)
                processed += 1
                if recovery:
                    record.status = _PENDING
                    pending.append(self._view(record))

        grace_candidates = sorted(
            (
                record
                for record in scoped
                if record.status in (_GRACE, _PENDING)
                and record.session_id not in newly_graced
            ),
            key=lambda record: (record.expires_at, record.session_id),
        )

        for record in grace_candidates:
            grace_deadline = record.grace_until
            if grace_deadline is not None and grace_deadline < now:
                event = OfflineEvent(
                    session_id=record.session_id,
                    account=record.account,
                    reason="grace_expired",
                    lease_expired_at=record.expires_at,
                )
                record.status = _OFFLINE
                self._counters["offline"] += 1
                events.append(event)
                processed += 1
            elif recovery:
                record.status = _PENDING
                pending.append(self._view(record))
                processed += 1

        events.sort(key=lambda event: (event.lease_expired_at, event.session_id))
        pending.sort(key=lambda view: (view.expires_at, view.session_id))
        return {
            "offline": events,
            "pending": pending,
            "processed": processed,
            "total": len(scoped),
        }

    def _parse_snapshot(
        self, state: object
    ) -> tuple[dict[str, _SessionRecord], dict[str, int]]:
        if not isinstance(state, dict):
            raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "snapshot is not an object")
        if set(state.keys()) != {"version", "sessions", "counters"}:
            raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "snapshot keys are invalid")
        if state.get("version") != _SNAPSHOT_VERSION:
            raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "unsupported version")

        raw_sessions = state.get("sessions")
        raw_counters = state.get("counters")
        if not isinstance(raw_sessions, dict):
            raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "sessions must be an object")
        if not isinstance(raw_counters, dict):
            raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "counters must be an object")

        counters = self._parse_counters(raw_counters)
        sessions: dict[str, _SessionRecord] = {}

        for key, raw_record in raw_sessions.items():
            if not isinstance(key, str) or not key:
                raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "session key is invalid")
            if not isinstance(raw_record, dict):
                raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "session must be an object")

            allowed = {
                "session_id", "account", "device", "status", "expires_at",
                "grace_until", "preemptable", "shard",
            }
            if set(raw_record.keys()) != allowed:
                raise PresenceError(
                    "PRESENCE_SNAPSHOT_INVALID",
                    {"session_id": key, "reason": "session fields are invalid"},
                )

            session_id = raw_record["session_id"]
            account = raw_record["account"]
            device = raw_record["device"]
            status = raw_record["status"]
            expires_at = raw_record["expires_at"]
            grace_until = raw_record["grace_until"]
            preemptable = raw_record["preemptable"]
            shard = raw_record["shard"]

            if session_id != key:
                raise PresenceError(
                    "PRESENCE_SNAPSHOT_INVALID",
                    {"session_id": key, "reason": "session id mismatch"},
                )
            self._require_text_value(session_id, "session_id", snapshot=True)
            self._require_text_value(account, "account", snapshot=True)
            self._require_text_value(device, "device", snapshot=True)
            known_statuses = {_ONLINE, _GRACE, _OFFLINE, _PENDING}
            if status not in known_statuses:
                raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "invalid session status")
            if not self._is_timestamp(expires_at):
                raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "invalid expiry")
            if grace_until is not None and not self._is_timestamp(grace_until):
                raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "invalid grace deadline")
            if status == _ONLINE and grace_until is not None:
                raise PresenceError(
                    "PRESENCE_SNAPSHOT_INVALID",
                    "online session cannot retain grace deadline",
                )
            if status in (_GRACE, _PENDING) and grace_until is None:
                raise PresenceError(
                    "PRESENCE_SNAPSHOT_INVALID",
                    "grace session requires deadline",
                )
            if not isinstance(preemptable, bool):
                raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "preemptable must be bool")
            if isinstance(shard, bool) or not isinstance(shard, int):
                raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "invalid shard")
            if not 0 <= shard < self.shard_count:
                raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "shard out of range")
            if session_id in sessions:
                raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "duplicate session")

            sessions[session_id] = _SessionRecord(
                session_id=deepcopy(session_id),
                account=deepcopy(account),
                device=deepcopy(device),
                status=status,
                expires_at=deepcopy(expires_at),
                grace_until=deepcopy(grace_until),
                preemptable=preemptable,
                shard=shard,
            )

        return sessions, counters

    def _parse_counters(self, raw_counters: dict) -> dict[str, int]:
        keys = set(raw_counters.keys())
        if keys == set(_COUNTER_KEYS):
            counters: dict[str, int] = {}
            for key in _COUNTER_KEYS:
                value = raw_counters[key]
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    raise PresenceError("PRESENCE_SNAPSHOT_INVALID", f"invalid {key} counter")
                counters[key] = value
            return counters

        required = set(_STAT_KEYS)
        if keys != required:
            raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "counter fields are invalid")

        counters = {}
        for key in _COUNTER_KEYS:
            value = raw_counters[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise PresenceError("PRESENCE_SNAPSHOT_INVALID", f"invalid {key} counter")
            counters[key] = value

        online = raw_counters["online"]
        grace = raw_counters["grace"]
        if isinstance(online, bool) or not isinstance(online, int) or online < 0:
            raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "invalid online counter")
        if isinstance(grace, bool) or not isinstance(grace, int) or grace < 0:
            raise PresenceError("PRESENCE_SNAPSHOT_INVALID", "invalid grace counter")
        return counters

    @staticmethod
    def _is_timestamp(value: object) -> bool:
        return (
            not isinstance(value, bool)
            and isinstance(value, (int, float))
        )

    def _view(self, record: _SessionRecord) -> SessionView:
        return SessionView(
            session_id=record.session_id,
            account=record.account,
            device=record.device,
            status=record.status,
            expires_at=record.expires_at,
            grace_until=record.grace_until,
            preemptable=record.preemptable,
            shard=record.shard,
        )

    def _get_record(self, session_id: str) -> _SessionRecord:
        record = self._sessions.get(session_id)
        if record is None:
            raise PresenceError(
                "PRESENCE_SESSION_UNKNOWN",
                {"session_id": session_id},
            )
        return record

    @classmethod
    def _require_identity(cls, account: object, session_id: object,
                           device: object) -> None:
        cls._require_account(account)
        cls._require_session_id(session_id)
        cls._require_device(device)

    @classmethod
    def _require_account(cls, account: object) -> None:
        cls._require_text_value(account, "account")

    @classmethod
    def _require_session_id(cls, session_id: object) -> None:
        cls._require_text_value(session_id, "session_id")

    @classmethod
    def _require_device(cls, device: object) -> None:
        cls._require_text_value(device, "device")

    @staticmethod
    def _require_text_value(value: object, field: str, *,
                             snapshot: bool = False) -> None:
        if not isinstance(value, str) or not value.strip():
            code = (
                "PRESENCE_SNAPSHOT_INVALID"
                if snapshot
                else "PRESENCE_INVALID"
            )
            raise PresenceError(code, {"field": field})

    def _require_shard(self, shard: object) -> None:
        if isinstance(shard, bool) or not isinstance(shard, int):
            raise PresenceError("PRESENCE_INVALID", {"field": "shard"})
        if not 0 <= shard < self.shard_count:
            raise PresenceError("PRESENCE_INVALID", {"field": "shard", "shard": shard})
