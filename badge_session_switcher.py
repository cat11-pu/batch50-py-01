"""Shared-terminal badge sessions: tap idempotency, suspend and resume, offline grace."""

from __future__ import annotations

import threading
import time
from dataclasses import dataclass


class BadgeError(ValueError):
    """Refused badge operation carrying a stable machine-readable code."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    terminal_id: str
    badge_serial: str
    state: str
    opened_at: int
    last_seen_at: int
    expires_at: int | None


@dataclass(frozen=True)
class TapResult:
    session_id: str
    terminal_id: str
    badge_serial: str
    state: str
    status: str
    replayed: bool


_STAT_KEYS = (
    "taps",
    "replays",
    "opened",
    "suspended",
    "resumed",
    "logouts",
    "purged",
    "refused",
)
_SESSION_FIELDS = (
    "session_id",
    "terminal_id",
    "badge_serial",
    "state",
    "opened_at",
    "last_seen_at",
    "expires_at",
)
_TAP_FIELDS = (
    "session_id",
    "terminal_id",
    "badge_serial",
    "state",
    "status",
    "replayed",
)


class BadgeSessionSwitcher:
    """Keep badge sessions per shared terminal with suspend, resume and idle sweeping."""

    def __init__(self, *, max_active_per_terminal: int = 2,
                 max_terminals_per_badge: int = 3, idle_timeout: int = 300,
                 suspended_ttl: int = 900, offline_grace: int = 120,
                 clock=None) -> None:
        self.max_active_per_terminal = max_active_per_terminal
        self.max_terminals_per_badge = max_terminals_per_badge
        self.idle_timeout = idle_timeout
        self.suspended_ttl = suspended_ttl
        self.offline_grace = offline_grace
        self._clock = clock
        self._lock = threading.RLock()
        self._terminals: dict[str, dict] = {}
        self._sessions: dict[str, dict] = {}
        self._seq: dict[tuple[str, str], int] = {}
        self._events: dict[tuple[str, str, int], TapResult] = {}
        self._counters = {key: 0 for key in _STAT_KEYS}
        self._next_session = 1

    @staticmethod
    def _blank(value: object) -> bool:
        return not isinstance(value, str) or not value.strip()

    @staticmethod
    def _session_number(session_id: str) -> tuple[int, str]:
        try:
            return int(session_id.rsplit("-", 1)[1]), session_id
        except (IndexError, ValueError):
            return 1 << 62, session_id

    def _refuse(self, code: str, detail: object = None) -> None:
        self._counters["refused"] += 1
        raise BadgeError(code, detail)

    def _check_terminal(self, terminal_id: object) -> str:
        if self._blank(terminal_id):
            self._refuse("BADGE_INVALID", {"field": "terminal_id"})
        return terminal_id

    def _check_badge(self, badge_serial: object) -> str:
        if self._blank(badge_serial):
            self._refuse("BADGE_INVALID", {"field": "badge_serial"})
        return badge_serial

    def _now(self, now: int | None) -> int:
        if now is not None:
            try:
                return int(now)
            except (TypeError, ValueError, OverflowError):
                raise BadgeError("BADGE_INVALID", {"field": "now"}) from None
        if self._clock is None:
            return int(time.time())
        clock = self._clock
        try:
            value = clock() if callable(clock) else clock.now()
            if callable(value):
                value = value()
            return int(value)
        except Exception as exc:
            raise BadgeError("BADGE_INVALID", {"field": "now", "error": str(exc)}) from exc

    def _terminal(self, terminal_id: str, *, create: bool = True) -> dict | None:
        terminal = self._terminals.get(terminal_id)
        if terminal is None and create:
            terminal = {
                "offline_since": None,
                "online": True,
                "requires_retap": False,
            }
            self._terminals[terminal_id] = terminal
        return terminal

    def _active_count(self, terminal_id: str) -> int:
        return sum(
            1
            for session in self._sessions.values()
            if session["terminal_id"] == terminal_id and session["state"] == "active"
        )

    def _badge_terminal_set(self, badge_serial: str) -> set[str]:
        return {
            session["terminal_id"]
            for session in self._sessions.values()
            if session["badge_serial"] == badge_serial
        }

    def _record(self, session: dict) -> SessionRecord:
        return SessionRecord(**{key: session[key] for key in _SESSION_FIELDS})

    def _active_sessions(self, terminal_id: str | None = None) -> list[dict]:
        sessions = [
            session
            for session in self._sessions.values()
            if session["state"] == "active"
            and (terminal_id is None or session["terminal_id"] == terminal_id)
        ]
        return sorted(sessions, key=lambda item: self._session_number(item["session_id"]))

    def _clear_retap(self, terminal_id: str) -> None:
        terminal = self._terminal(terminal_id)
        if terminal is not None:
            terminal["requires_retap"] = False

    def _remember_event(self, key: tuple[str, str, int], result: TapResult) -> None:
        self._seq[(key[0], key[1])] = key[2]
        self._events[key] = result

    def _offline_blocks_resume(self, terminal_id: str, now: int) -> bool:
        terminal = self._terminals.get(terminal_id)
        if terminal is None:
            return False
        if terminal["requires_retap"]:
            return True
        offline_since = terminal["offline_since"]
        if offline_since is None:
            return False
        return not terminal["online"] and now - offline_since > self.offline_grace

    def tap(self, terminal_id: str, badge_serial: str, seq: int, *,
            now: int | None = None) -> TapResult:
        with self._lock:
            terminal_id = self._check_terminal(terminal_id)
            badge_serial = self._check_badge(badge_serial)
            if isinstance(seq, bool) or not isinstance(seq, int) or seq <= 0:
                self._refuse("BADGE_INVALID", {"field": "seq"})
            current = self._now(now)

            event_key = (terminal_id, badge_serial, seq)
            seen = self._events.get(event_key)
            if seen is not None:
                self._counters["taps"] += 1
                self._counters["replays"] += 1
                return TapResult(
                    session_id=seen.session_id,
                    terminal_id=seen.terminal_id,
                    badge_serial=seen.badge_serial,
                    state=seen.state,
                    status=seen.status,
                    replayed=True,
                )

            accepted_seq = self._seq.get((terminal_id, badge_serial))
            if accepted_seq is not None and seq < accepted_seq:
                self._refuse("BADGE_STALE", {
                    "terminal_id": terminal_id,
                    "badge_serial": badge_serial,
                    "accepted_seq": accepted_seq,
                    "received_seq": seq,
                })

            same_slot = [
                session
                for session in self._sessions.values()
                if session["terminal_id"] == terminal_id
                and session["badge_serial"] == badge_serial
            ]
            active_here = next(
                (session for session in same_slot if session["state"] == "active"),
                None,
            )
            suspended_here = next(
                (session for session in same_slot if session["state"] == "suspended"),
                None,
            )
            active_elsewhere = sorted(
                (
                    session
                    for session in self._sessions.values()
                    if session["badge_serial"] == badge_serial
                    and session["state"] == "active"
                    and session["terminal_id"] != terminal_id
                ),
                key=lambda item: self._session_number(item["session_id"]),
            )

            if active_here is not None:
                active_here["last_seen_at"] = current
                active_here["expires_at"] = None
                if suspended_here is not None:
                    del self._sessions[suspended_here["session_id"]]
                status = "existing"
                session = active_here
                opened = False
            else:
                badge_terminals = self._badge_terminal_set(badge_serial)
                if (terminal_id not in badge_terminals
                        and len(badge_terminals) >= self.max_terminals_per_badge):
                    self._refuse("BADGE_TERMINAL_LIMIT", {
                        "badge_serial": badge_serial,
                        "terminal_id": terminal_id,
                        "max_terminals_per_badge": self.max_terminals_per_badge,
                    })

                if self._active_count(terminal_id) >= self.max_active_per_terminal:
                    self._refuse("BADGE_TERMINAL_LIMIT", {
                        "terminal_id": terminal_id,
                        "max_active_per_terminal": self.max_active_per_terminal,
                    })

                if active_elsewhere:
                    session = active_elsewhere[0]
                    if suspended_here is not None:
                        del self._sessions[suspended_here["session_id"]]
                    for duplicate in active_elsewhere[1:]:
                        del self._sessions[duplicate["session_id"]]
                    session["terminal_id"] = terminal_id
                    session["last_seen_at"] = current
                    session["expires_at"] = None
                    status = "migrated"
                    opened = False
                elif (suspended_here is not None
                      and suspended_here["expires_at"] is not None
                      and current < suspended_here["expires_at"]):
                    session = suspended_here
                    session["state"] = "active"
                    session["last_seen_at"] = current
                    session["expires_at"] = None
                    status = "existing"
                    opened = False
                else:
                    if suspended_here is not None:
                        del self._sessions[suspended_here["session_id"]]
                    session_id = f"sess-{self._next_session}"
                    self._next_session += 1
                    session = {
                        "session_id": session_id,
                        "terminal_id": terminal_id,
                        "badge_serial": badge_serial,
                        "state": "active",
                        "opened_at": current,
                        "last_seen_at": current,
                        "expires_at": None,
                    }
                    self._sessions[session_id] = session
                    status = "opened"
                    opened = True

            self._terminal(terminal_id)
            self._clear_retap(terminal_id)
            result = TapResult(
                session_id=session["session_id"],
                terminal_id=terminal_id,
                badge_serial=badge_serial,
                state="active",
                status=status,
                replayed=False,
            )
            self._counters["taps"] += 1
            if opened:
                self._counters["opened"] += 1
            self._remember_event(event_key, result)
            return result

    def suspend(self, terminal_id: str, *, now: int | None = None) -> dict:
        with self._lock:
            terminal_id = self._check_terminal(terminal_id)
            current = self._now(now)
            suspended: list[str] = []
            for session in self._active_sessions(terminal_id):
                session["state"] = "suspended"
                session["expires_at"] = current + self.suspended_ttl
                suspended.append(session["session_id"])
            self._counters["suspended"] += len(suspended)
            self._terminal(terminal_id)
            return {
                "terminal_id": terminal_id,
                "suspended": suspended,
                "count": len(suspended),
            }

    def resume(self, terminal_id: str, badge_serial: str, *,
               now: int | None = None) -> SessionRecord:
        with self._lock:
            terminal_id = self._check_terminal(terminal_id)
            badge_serial = self._check_badge(badge_serial)
            current = self._now(now)

            if self._offline_blocks_resume(terminal_id, current):
                self._refuse("BADGE_RESUME", {
                    "terminal_id": terminal_id,
                    "badge_serial": badge_serial,
                    "reason": "offline_grace_expired",
                })

            candidates = sorted(
                (
                    session
                    for session in self._sessions.values()
                    if session["terminal_id"] == terminal_id
                    and session["badge_serial"] == badge_serial
                    and session["state"] == "suspended"
                ),
                key=lambda item: self._session_number(item["session_id"]),
            )
            if not candidates:
                self._refuse("BADGE_RESUME", {
                    "terminal_id": terminal_id,
                    "badge_serial": badge_serial,
                    "reason": "not_suspended",
                })

            session = candidates[0]
            expires_at = session["expires_at"]
            if expires_at is None or current >= expires_at:
                self._refuse("BADGE_RESUME", {
                    "terminal_id": terminal_id,
                    "badge_serial": badge_serial,
                    "reason": "expired",
                    "expires_at": expires_at,
                })

            active_elsewhere = any(
                other["session_id"] != session["session_id"]
                and other["badge_serial"] == badge_serial
                and other["state"] == "active"
                and other["terminal_id"] != terminal_id
                for other in self._sessions.values()
            )
            if active_elsewhere:
                self._refuse("BADGE_RESUME", {
                    "terminal_id": terminal_id,
                    "badge_serial": badge_serial,
                    "reason": "badge_active_elsewhere",
                })
            active_here = any(
                other["session_id"] != session["session_id"]
                and other["badge_serial"] == badge_serial
                and other["state"] == "active"
                and other["terminal_id"] == terminal_id
                for other in self._sessions.values()
            )
            if active_here:
                self._refuse("BADGE_RESUME", {
                    "terminal_id": terminal_id,
                    "badge_serial": badge_serial,
                    "reason": "badge_active_on_terminal",
                })
            if self._active_count(terminal_id) >= self.max_active_per_terminal:
                self._refuse("BADGE_TERMINAL_LIMIT", {
                    "terminal_id": terminal_id,
                    "max_active_per_terminal": self.max_active_per_terminal,
                })

            session["state"] = "active"
            session["expires_at"] = None
            session["last_seen_at"] = current
            self._counters["resumed"] += 1
            self._terminal(terminal_id)
            self._clear_retap(terminal_id)
            return self._record(session)

    def logout(self, terminal_id: str, badge_serial: str | None = None, *,
               now: int | None = None) -> int:
        with self._lock:
            terminal_id = self._check_terminal(terminal_id)
            if badge_serial is not None:
                badge_serial = self._check_badge(badge_serial)
            self._now(now)
            removed = [
                session_id
                for session_id, session in self._sessions.items()
                if session["terminal_id"] == terminal_id
                and (badge_serial is None or session["badge_serial"] == badge_serial)
            ]
            for session_id in removed:
                del self._sessions[session_id]
            self._counters["logouts"] += len(removed)
            return len(removed)

    def list_active(self, terminal_id: str | None = None) -> list[SessionRecord]:
        with self._lock:
            if terminal_id is not None:
                terminal_id = self._check_terminal(terminal_id)
            return [self._record(session) for session in self._active_sessions(terminal_id)]

    def mark_offline(self, terminal_id: str, *, now: int | None = None) -> dict:
        with self._lock:
            terminal_id = self._check_terminal(terminal_id)
            current = self._now(now)
            terminal = self._terminal(terminal_id)
            if terminal["offline_since"] is None:
                terminal["offline_since"] = current
            terminal["online"] = False
            return {
                "terminal_id": terminal_id,
                "offline_since": terminal["offline_since"],
            }

    def mark_online(self, terminal_id: str, *, now: int | None = None) -> dict:
        with self._lock:
            terminal_id = self._check_terminal(terminal_id)
            current = self._now(now)
            terminal = self._terminal(terminal_id)
            offline_since = terminal["offline_since"]
            if offline_since is not None:
                if current - offline_since > self.offline_grace:
                    terminal["requires_retap"] = True
                terminal["offline_since"] = None
            terminal["online"] = True
            return {"terminal_id": terminal_id, "online": True}

    def sweep(self, *, now: int | None = None) -> dict:
        with self._lock:
            current = self._now(now)
            suspended = 0
            for session in self._active_sessions():
                if current - session["last_seen_at"] >= self.idle_timeout:
                    session["state"] = "suspended"
                    session["expires_at"] = current + self.suspended_ttl
                    suspended += 1

            purged = 0
            for session_id, session in list(self._sessions.items()):
                if (session["state"] == "suspended"
                        and session["expires_at"] is not None
                        and current >= session["expires_at"]):
                    del self._sessions[session_id]
                    purged += 1

            self._counters["suspended"] += suspended
            self._counters["purged"] += purged
            return {"suspended": suspended, "purged": purged}

    def session_view(self, session_id: str) -> SessionRecord:
        with self._lock:
            session = self._sessions.get(session_id) if isinstance(session_id, str) else None
            if session is None:
                self._refuse("BADGE_SESSION_UNKNOWN", {"session_id": session_id})
            return self._record(session)

    def snapshot(self) -> dict:
        with self._lock:
            seq: dict[str, dict[str, int]] = {}
            for (terminal_id, badge_serial), value in self._seq.items():
                seq.setdefault(terminal_id, {})[badge_serial] = value

            events: dict[str, dict[str, dict[str, dict]]] = {}
            for (terminal_id, badge_serial, event_seq), result in self._events.items():
                by_badge = events.setdefault(terminal_id, {}).setdefault(badge_serial, {})
                by_badge[str(event_seq)] = {
                    "session_id": result.session_id,
                    "terminal_id": result.terminal_id,
                    "badge_serial": result.badge_serial,
                    "state": result.state,
                    "status": result.status,
                    "replayed": result.replayed,
                }

            return {
                "version": 1,
                "next_session": self._next_session,
                "terminals": {
                    terminal_id: {
                        "offline_since": terminal["offline_since"],
                        "online": terminal["online"],
                        "requires_retap": terminal["requires_retap"],
                    }
                    for terminal_id, terminal in self._terminals.items()
                },
                "sessions": {
                    session_id: {
                        key: self._sessions[session_id][key] for key in _SESSION_FIELDS
                    }
                    for session_id in sorted(self._sessions, key=self._session_number)
                },
                "seq": {"max": seq, "events": events},
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except BadgeError:
                raise
            except Exception as exc:
                raise BadgeError("BADGE_SNAPSHOT", {"error": str(exc)}) from exc
            (
                self._terminals,
                self._sessions,
                self._seq,
                self._events,
                self._counters,
                self._next_session,
            ) = parsed

    @staticmethod
    def _snapshot_error(detail: object = None) -> None:
        raise BadgeError("BADGE_SNAPSHOT", detail)

    def _parse_snapshot(self, state: dict) -> tuple:
        if not isinstance(state, dict):
            self._snapshot_error({"field": "state"})
        version = state.get("version", 1)
        if version != 1:
            self._snapshot_error({"field": "version"})

        raw_terminals = state.get("terminals")
        raw_sessions = state.get("sessions")
        raw_seq = state.get("seq")
        raw_counters = state.get("counters")
        if not isinstance(raw_terminals, dict):
            self._snapshot_error({"field": "terminals"})
        if not isinstance(raw_sessions, (dict, list)):
            self._snapshot_error({"field": "sessions"})
        if not isinstance(raw_seq, dict):
            self._snapshot_error({"field": "seq"})
        if not isinstance(raw_counters, dict):
            self._snapshot_error({"field": "counters"})

        terminals: dict[str, dict] = {}
        for terminal_id, raw in raw_terminals.items():
            if self._blank(terminal_id) or not isinstance(raw, dict):
                self._snapshot_error({"field": "terminals", "terminal_id": terminal_id})
            offline_since = raw.get("offline_since")
            if offline_since is not None and (
                isinstance(offline_since, bool) or not isinstance(offline_since, int)
            ):
                self._snapshot_error({
                    "field": "terminals.offline_since",
                    "terminal_id": terminal_id,
                })
            online = raw.get("online", offline_since is None)
            requires_retap = raw.get("requires_retap", False)
            if not isinstance(online, bool) or not isinstance(requires_retap, bool):
                self._snapshot_error({
                    "field": "terminals.flags",
                    "terminal_id": terminal_id,
                })
            terminals[terminal_id] = {
                "offline_since": offline_since,
                "online": online,
                "requires_retap": requires_retap,
            }

        session_items: list[tuple[str, object]]
        if isinstance(raw_sessions, dict):
            session_items = list(raw_sessions.items())
        else:
            session_items = []
            for raw in raw_sessions:
                if not isinstance(raw, dict):
                    self._snapshot_error({"field": "sessions.item"})
                session_id = raw.get("session_id")
                if not isinstance(session_id, str):
                    self._snapshot_error({"field": "sessions.session_id"})
                session_items.append((session_id, raw))

        sessions: dict[str, dict] = {}
        max_session_number = 0
        for session_id, raw in session_items:
            if not isinstance(session_id, str) or not session_id:
                self._snapshot_error({"field": "sessions.session_id"})
            if not isinstance(raw, dict):
                self._snapshot_error({
                    "field": "sessions",
                    "session_id": session_id,
                })
            stored_id = raw.get("session_id", session_id)
            terminal_id = raw.get("terminal_id")
            badge_serial = raw.get("badge_serial")
            session_state = raw.get("state")
            opened_at = raw.get("opened_at")
            last_seen_at = raw.get("last_seen_at")
            expires_at = raw.get("expires_at")
            if stored_id != session_id or self._blank(terminal_id) or self._blank(badge_serial):
                self._snapshot_error({"field": "sessions.identity", "session_id": session_id})
            if session_state not in ("active", "suspended"):
                self._snapshot_error({"field": "sessions.state", "session_id": session_id})
            for field_name, value in (
                ("opened_at", opened_at),
                ("last_seen_at", last_seen_at),
            ):
                if isinstance(value, bool) or not isinstance(value, int):
                    self._snapshot_error({
                        "field": f"sessions.{field_name}",
                        "session_id": session_id,
                    })
            if expires_at is not None and (
                isinstance(expires_at, bool) or not isinstance(expires_at, int)
            ):
                self._snapshot_error({
                    "field": "sessions.expires_at",
                    "session_id": session_id,
                })
            if session_state == "active" and expires_at is not None:
                self._snapshot_error({
                    "field": "sessions.active_expiry",
                    "session_id": session_id,
                })
            if session_state == "suspended" and expires_at is None:
                self._snapshot_error({
                    "field": "sessions.suspended_expiry",
                    "session_id": session_id,
                })
            sessions[session_id] = {
                "session_id": session_id,
                "terminal_id": terminal_id,
                "badge_serial": badge_serial,
                "state": session_state,
                "opened_at": opened_at,
                "last_seen_at": last_seen_at,
                "expires_at": expires_at,
            }
            try:
                max_session_number = max(
                    max_session_number,
                    int(session_id.rsplit("-", 1)[1]),
                )
            except (IndexError, ValueError):
                pass

        seq: dict[tuple[str, str], int] = {}
        events: dict[tuple[str, str, int], TapResult] = {}
        if "max" in raw_seq or "events" in raw_seq:
            raw_max = raw_seq.get("max") or {}
            raw_events = raw_seq.get("events") or {}
            if not isinstance(raw_max, dict) or not isinstance(raw_events, dict):
                self._snapshot_error({"field": "seq"})
            for terminal_id, by_badge in raw_max.items():
                if self._blank(terminal_id) or not isinstance(by_badge, dict):
                    self._snapshot_error({"field": "seq.max"})
                for badge_serial, value in by_badge.items():
                    if self._blank(badge_serial):
                        self._snapshot_error({"field": "seq.badge"})
                    if (isinstance(value, bool) or not isinstance(value, int)
                            or value <= 0):
                        self._snapshot_error({"field": "seq.value"})
                    seq[(terminal_id, badge_serial)] = value
            for terminal_id, by_badge in raw_events.items():
                if self._blank(terminal_id) or not isinstance(by_badge, dict):
                    self._snapshot_error({"field": "seq.events"})
                for badge_serial, by_seq in by_badge.items():
                    if self._blank(badge_serial) or not isinstance(by_seq, dict):
                        self._snapshot_error({"field": "seq.events.badge"})
                    for raw_event_seq, raw_result in by_seq.items():
                        try:
                            event_seq = int(raw_event_seq)
                        except (TypeError, ValueError):
                            self._snapshot_error({"field": "seq.events.seq"})
                        if event_seq <= 0 or not isinstance(raw_result, dict):
                            self._snapshot_error({"field": "seq.events.result"})
                        if any(field not in raw_result for field in _TAP_FIELDS):
                            self._snapshot_error({"field": "seq.events.result.fields"})
                        if (not isinstance(raw_result["session_id"], str)
                                or not isinstance(raw_result["terminal_id"], str)
                                or not isinstance(raw_result["badge_serial"], str)
                                or not isinstance(raw_result["state"], str)
                                or not isinstance(raw_result["status"], str)
                                or not isinstance(raw_result["replayed"], bool)):
                            self._snapshot_error({"field": "seq.events.result.types"})
                        event_key = (terminal_id, badge_serial, event_seq)
                        events[event_key] = TapResult(
                            session_id=raw_result["session_id"],
                            terminal_id=raw_result["terminal_id"],
                            badge_serial=raw_result["badge_serial"],
                            state=raw_result["state"],
                            status=raw_result["status"],
                            replayed=raw_result["replayed"],
                        )
                        seq[(terminal_id, badge_serial)] = max(
                            seq.get((terminal_id, badge_serial), 0),
                            event_seq,
                        )
        else:
            for key, value in raw_seq.items():
                if isinstance(key, tuple) and len(key) == 2:
                    terminal_id, badge_serial = key
                elif isinstance(key, str) and "\x00" in key:
                    terminal_id, badge_serial = key.split("\x00", 1)
                else:
                    self._snapshot_error({"field": "seq.key"})
                if self._blank(terminal_id) or self._blank(badge_serial):
                    self._snapshot_error({"field": "seq.key"})
                if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
                    self._snapshot_error({"field": "seq.value"})
                seq[(terminal_id, badge_serial)] = value

        counters: dict[str, int] = {}
        for key in _STAT_KEYS:
            value = raw_counters.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                self._snapshot_error({"field": "counters", "key": key})
            counters[key] = value

        next_session = state.get("next_session")
        if next_session is None:
            next_session = max_session_number + 1
        if (isinstance(next_session, bool) or not isinstance(next_session, int)
                or next_session <= max_session_number):
            self._snapshot_error({"field": "next_session"})

        return terminals, sessions, seq, events, counters, next_session

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)
