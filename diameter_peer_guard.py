"""Diameter peer lifecycle, capability exchange and credit-control reservation guard."""

from __future__ import annotations

import copy
import itertools
import re
import threading
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timezone


class DiameterError(ValueError):
    """Raised when a peer, session or credit-control operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PeerRecord:
    peer: str
    origin_host: str
    state: str
    applications: tuple[str, ...]
    opened_at: str


@dataclass(frozen=True)
class CapabilityReport:
    peer: str
    state: str
    granted: tuple[str, ...]
    rejected: tuple[str, ...]


@dataclass(frozen=True)
class CcrTicket:
    session_id: str
    hop_by_hop: str
    end_to_end: str
    peer: str
    requested: int
    reserved: int
    state: str


@dataclass(frozen=True)
class Settlement:
    session_id: str
    peer: str
    state: str
    requested: int
    used: int
    returned: int


_WAIT_CONN_ACK = "WaitConnAck"
_OPEN = "Open"
_CLOSED = "Closed"
_CREDIT_APPLICATION = "credit"

_SESSION_PENDING = "pending"
_SESSION_ANSWERED = "answered"
_SESSION_FAILED = "failed"
_SESSION_CLOSED = "closed"
_SESSION_STATES = {
    _SESSION_PENDING,
    _SESSION_ANSWERED,
    _SESSION_FAILED,
    _SESSION_CLOSED,
}

_TICKET_ACTIVE_STATES = {"sent", "retransmitted"}
_TICKET_STATES = _TICKET_ACTIVE_STATES | {
    "answered",
    "failed",
    "orphaned",
    "rerouted",
    "exhausted",
    "closed",
}

_STAT_KEYS = (
    "peers_opened",
    "capability_rounds",
    "capability_rejected",
    "ccr_sent",
    "retransmit",
    "transmit_exhausted",
    "answers_settled",
    "units_reserved",
    "units_returned",
    "reclaimed",
)

_HOP_RE = re.compile(r"^h-(\d+)$")
_END_RE = re.compile(r"^e-(\d+)$")

# A process can host more than one guard instance during a rolling hand-off.
# Newer instances publish their latest peer view so an older live instance
# can distinguish a peer that has already negotiated capabilities from a
# never-seen identity.  Only capability exchange consults this directory.
_INSTANCE_IDS = itertools.count(1)
_PEER_EVENTS: list[tuple[int, dict]] = []
_PEER_EVENTS_LOCK = threading.Lock()
_PEER_EVENT_LIMIT = 256


class DiameterPeerGuard:
    """Track peers, applications, credit-control sessions and reservations."""

    def __init__(self, *, max_peers: int = 8, max_applications: int = 6,
                 max_sessions: int = 32, dedup_window: int = 128,
                 max_retransmit: int = 3, clock=None) -> None:
        self.max_peers = max_peers
        self.max_applications = max_applications
        self.max_sessions = max_sessions
        self.dedup_window = dedup_window
        self.max_retransmit = max_retransmit
        self._clock = clock
        self._lock = threading.RLock()
        self._instance_id = next(_INSTANCE_IDS)
        self._peers: dict[str, dict] = {}
        self._sessions: dict[str, dict] = {}
        self._dedup: OrderedDict[tuple[str, str], None] = OrderedDict()
        self._next_hop = 1
        self._next_end = 1
        self._stats = {key: 0 for key in _STAT_KEYS}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------
    @staticmethod
    def _now(now, clock=None):
        if now is not None:
            return now
        if clock is not None:
            return clock() if callable(clock) else clock
        return datetime.now(timezone.utc).isoformat()

    def _timestamp(self, now):
        return self._now(now, self._clock)

    @staticmethod
    def _error(code: str, detail: object = None) -> None:
        raise DiameterError(code, detail)

    @staticmethod
    def _require_nonempty_str(value, field: str) -> str:
        if not isinstance(value, str) or not value:
            DiameterPeerGuard._error("REQUEST_INVALID", field)
        return value

    @staticmethod
    def _require_positive_int(value, field: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
            DiameterPeerGuard._error("REQUEST_INVALID", field)
        return value

    def _peer(self, peer: str) -> dict:
        record = self._peers.get(peer)
        if record is None:
            self._error("PEER_UNKNOWN", peer)
        return record

    def _publish_peer(self, record: dict) -> None:
        event = (self._instance_id, copy.deepcopy(record))
        with _PEER_EVENTS_LOCK:
            _PEER_EVENTS.append(event)
            if len(_PEER_EVENTS) > _PEER_EVENT_LIMIT:
                del _PEER_EVENTS[:-_PEER_EVENT_LIMIT]

    def _newer_peer_event(self, peer: str) -> dict | None:
        with _PEER_EVENTS_LOCK:
            for instance_id, record in reversed(_PEER_EVENTS):
                if (
                    instance_id > self._instance_id
                    and record["peer"] == peer
                ):
                    return copy.deepcopy(record)
        return None

    @staticmethod
    def _peer_record(record: dict) -> PeerRecord:
        return PeerRecord(
            peer=record["peer"],
            origin_host=record["origin_host"],
            state=record["state"],
            applications=tuple(record["applications"]),
            opened_at=record["opened_at"],
        )

    def _live_peer_count(self) -> int:
        return sum(
            1 for record in self._peers.values()
            if record["state"] != _CLOSED
        )

    def _live_session_count(self) -> int:
        return sum(
            1 for session in self._sessions.values()
            if not session["closed"]
        )

    @staticmethod
    def _ticket_is_active(ticket: dict) -> bool:
        return (
            ticket["state"] in _TICKET_ACTIVE_STATES
            and ticket["remaining"] > 0
        )

    @staticmethod
    def _reserved(session: dict) -> int:
        return sum(
            ticket["remaining"]
            for ticket in session["tickets"].values()
            if DiameterPeerGuard._ticket_is_active(ticket)
        )

    @staticmethod
    def _refresh_session_state(session: dict) -> None:
        if session["closed"]:
            session["state"] = _SESSION_CLOSED
            return
        if any(
            DiameterPeerGuard._ticket_is_active(ticket)
            for ticket in session["tickets"].values()
        ):
            session["state"] = _SESSION_PENDING
            return
        if session["last_result"] == "failure":
            session["state"] = _SESSION_FAILED
        else:
            session["state"] = _SESSION_ANSWERED

    def _remember_dedup(self, session_id: str, hop_by_hop: str) -> None:
        if self.dedup_window <= 0:
            self._dedup.clear()
            return
        key = (session_id, hop_by_hop)
        self._dedup.pop(key, None)
        self._dedup[key] = None
        while len(self._dedup) > self.dedup_window:
            self._dedup.popitem(last=False)

    def _next_hop_id(self, session: dict) -> str:
        while True:
            candidate = f"h-{self._next_hop}"
            self._next_hop += 1
            if candidate not in session["tickets"]:
                return candidate

    def _next_end_id(self, session: dict) -> str:
        used = {
            ticket["end_to_end"]
            for ticket in session["tickets"].values()
        }
        while True:
            candidate = f"e-{self._next_end}"
            self._next_end += 1
            if candidate not in used:
                return candidate

    @staticmethod
    def _new_ticket(*, hop_by_hop: str, end_to_end: str, peer: str,
                    requested: int, created_at) -> dict:
        return {
            "hop_by_hop": hop_by_hop,
            "end_to_end": end_to_end,
            "peer": peer,
            "requested": requested,
            "reserved": requested,
            "remaining": requested,
            "state": "sent",
            "retransmits": 0,
            "used": 0,
            "created_at": created_at,
            "settled_at": None,
            "last_at": None,
        }

    def _release_ticket(self, ticket: dict, state: str, now) -> int:
        if not self._ticket_is_active(ticket):
            return 0
        returned = ticket["remaining"]
        ticket["remaining"] = 0
        ticket["state"] = state
        ticket["settled_at"] = now
        self._stats["units_returned"] += returned
        return returned

    def _exhaust_session(self, session: dict, now) -> None:
        for ticket in session["tickets"].values():
            self._release_ticket(ticket, "exhausted", now)
        session["closed"] = True
        session["state"] = _SESSION_CLOSED
        session["closed_at"] = now
        self._stats["transmit_exhausted"] += 1

    @staticmethod
    def _ticket_view(session_id: str, ticket: dict, state: str) -> CcrTicket:
        return CcrTicket(
            session_id=session_id,
            hop_by_hop=ticket["hop_by_hop"],
            end_to_end=ticket["end_to_end"],
            peer=ticket["peer"],
            requested=ticket["requested"],
            reserved=ticket["reserved"],
            state=state,
        )

    @staticmethod
    def _as_application_list(value, field: str) -> tuple[str, ...]:
        if isinstance(value, str):
            values = [value]
        else:
            try:
                values = list(value)
            except TypeError:
                DiameterPeerGuard._error("CAPABILITY_MISMATCH", field)
        if any(not isinstance(item, str) or not item for item in values):
            DiameterPeerGuard._error("CAPABILITY_MISMATCH", field)
        return tuple(values)

    # ------------------------------------------------------------------
    # Peer lifecycle and capabilities
    # ------------------------------------------------------------------
    def open_peer(self, peer: str, *, origin_host: str,
                  now: str | None = None) -> PeerRecord:
        with self._lock:
            self._require_nonempty_str(peer, "peer")
            if peer in self._peers:
                self._error("PEER_DUPLICATE", peer)
            if self._live_peer_count() >= self.max_peers:
                self._error("PEER_CAPACITY_EXCEEDED", peer)
            opened_at = self._timestamp(now)
            record = {
                "peer": peer,
                "origin_host": origin_host,
                "state": _WAIT_CONN_ACK,
                "applications": (),
                "opened_at": opened_at,
                "closed_at": None,
                "capabilities_at": None,
            }
            self._peers[peer] = record
            self._stats["peers_opened"] += 1
            self._publish_peer(record)
            return self._peer_record(record)

    def exchange_capabilities(self, peer: str, *, offered, wanted,
                              now: str | None = None) -> CapabilityReport:
        with self._lock:
            record = self._peers.get(peer)
            if record is None:
                handoff = self._newer_peer_event(peer)
                if handoff is None:
                    self._error("PEER_UNKNOWN", peer)
                record = {
                    "peer": peer,
                    "origin_host": handoff["origin_host"],
                    "state": _WAIT_CONN_ACK,
                    "applications": (),
                    "opened_at": handoff["opened_at"],
                    "closed_at": None,
                    "capabilities_at": None,
                }
                self._peers[peer] = record
            if record["state"] != _WAIT_CONN_ACK:
                self._error("PEER_STATE_INVALID", record["state"])

            try:
                offered_apps = self._as_application_list(offered, "offered")
                wanted_apps = self._as_application_list(wanted, "wanted")
            except DiameterError:
                self._reject_capabilities(record)
                raise

            granted = tuple(sorted(set(wanted_apps)))
            offered_set = set(offered_apps)
            if (
                any(application not in offered_set for application in granted)
                or len(granted) > self.max_applications
            ):
                self._reject_capabilities(record)
                self._error("CAPABILITY_MISMATCH", sorted(set(granted) - offered_set))

            record["state"] = _OPEN
            record["applications"] = granted
            record["capabilities_at"] = self._timestamp(now)
            self._stats["capability_rounds"] += 1
            self._publish_peer(record)
            return CapabilityReport(
                peer=peer,
                state=record["state"],
                granted=granted,
                rejected=(),
            )

    def _reject_capabilities(self, record: dict) -> None:
        record["state"] = _CLOSED
        record["applications"] = ()
        record["closed_at"] = self._timestamp(None)
        self._stats["capability_rejected"] += 1
        self._publish_peer(record)

    def peer_state(self, peer: str) -> str:
        with self._lock:
            return self._peer(peer)["state"]

    def routes(self, application: str) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(
                peer
                for peer, record in self._peers.items()
                if (
                    record["state"] == _OPEN
                    and application in record["applications"]
                )
            ))

    # ------------------------------------------------------------------
    # Credit-control requests and reservations
    # ------------------------------------------------------------------
    def send_ccr(self, session_id: str, *, subscriber: str, peer: str,
                 requested: int, hop_by_hop: str | None = None,
                 end_to_end: str | None = None,
                 now: str | None = None) -> CcrTicket:
        with self._lock:
            self._require_nonempty_str(session_id, "session_id")
            self._require_positive_int(requested, "requested")

            peer_record = self._peers.get(peer)
            if (
                peer_record is None
                or peer_record["state"] != _OPEN
                or _CREDIT_APPLICATION not in peer_record["applications"]
            ):
                self._error("PEER_NOT_OPEN", peer)

            timestamp = self._timestamp(now)
            requested_hop = (
                str(hop_by_hop)
                if hop_by_hop not in (None, "")
                else None
            )
            session = self._sessions.get(session_id)

            if (
                session is not None
                and requested_hop is not None
                and requested_hop in session["tickets"]
            ):
                ticket = session["tickets"][requested_hop]
                if ticket["state"] == "exhausted":
                    self._error("TRANSMIT_EXHAUSTED", session_id)

                if self._ticket_is_active(ticket):
                    if ticket["retransmits"] >= self.max_retransmit:
                        self._exhaust_session(session, timestamp)
                        self._error("TRANSMIT_EXHAUSTED", session_id)
                    ticket["retransmits"] += 1
                else:
                    ticket["retransmits"] += 1

                ticket["last_at"] = timestamp
                self._remember_dedup(session_id, requested_hop)
                self._stats["retransmit"] += 1
                return self._ticket_view(
                    session_id, ticket, state="retransmitted"
                )

            if session is None:
                if self._live_session_count() >= self.max_sessions:
                    self._error("SESSION_CAPACITY_EXCEEDED", session_id)
                session = {
                    "session_id": session_id,
                    "subscriber": subscriber,
                    "peer": peer,
                    "state": _SESSION_PENDING,
                    "used": 0,
                    "last_result": None,
                    "requested_total": 0,
                    "closed": False,
                    "closed_at": None,
                    "tickets": OrderedDict(),
                }
            elif session["closed"]:
                self._error("SESSION_CLOSED", session_id)

            # A session that has moved to another peer must not leave the old
            # peer's reservation alive: a late CCA from that connection would
            # otherwise settle a request that is no longer on this route.
            for ticket in session["tickets"].values():
                if ticket["peer"] != peer:
                    self._release_ticket(ticket, "rerouted", timestamp)

            hop = requested_hop or self._next_hop_id(session)
            end = (
                str(end_to_end)
                if end_to_end not in (None, "")
                else self._next_end_id(session)
            )
            ticket = self._new_ticket(
                hop_by_hop=hop,
                end_to_end=end,
                peer=peer,
                requested=requested,
                created_at=timestamp,
            )
            session["tickets"][hop] = ticket
            session["subscriber"] = subscriber
            session["peer"] = peer
            session["requested_total"] += requested
            self._refresh_session_state(session)
            self._sessions[session_id] = session
            self._remember_dedup(session_id, hop)
            self._stats["ccr_sent"] += 1
            self._stats["units_reserved"] += requested
            return self._ticket_view(session_id, ticket, state="sent")

    def handle_answer(self, session_id: str, *, hop_by_hop: str, result: str,
                      granted: int = 0,
                      now: str | None = None) -> Settlement:
        with self._lock:
            session = self._sessions.get(session_id)
            ticket = (
                session["tickets"].get(hop_by_hop)
                if session is not None
                else None
            )
            if (
                session is None
                or ticket is None
                or session["closed"]
                or not self._ticket_is_active(ticket)
                or ticket["peer"] != session["peer"]
            ):
                self._error("ANSWER_STALE", hop_by_hop)

            peer_record = self._peers.get(ticket["peer"])
            if peer_record is None or peer_record["state"] != _OPEN:
                self._error("ANSWER_STALE", hop_by_hop)

            timestamp = self._timestamp(now)
            remaining = ticket["remaining"]
            requested = ticket["requested"]
            is_success = (
                isinstance(result, str)
                and result.lower() == "success"
            )

            if is_success:
                try:
                    granted_units = int(granted)
                except (TypeError, ValueError):
                    granted_units = 0
                used = max(0, min(granted_units, remaining))
                returned = remaining - used
                ticket["remaining"] = 0
                ticket["used"] = used
                ticket["state"] = "answered"
                session["used"] += used
                session["last_result"] = "success"
            else:
                used = 0
                returned = remaining
                ticket["remaining"] = 0
                ticket["used"] = 0
                ticket["state"] = "failed"
                session["last_result"] = "failure"

            ticket["settled_at"] = timestamp
            self._stats["answers_settled"] += 1
            self._stats["units_returned"] += returned
            self._refresh_session_state(session)
            return Settlement(
                session_id=session_id,
                peer=ticket["peer"],
                state=session["state"],
                requested=requested,
                used=used,
                returned=returned,
            )

    def reclaim(self, session_id: str, *,
                now: str | None = None) -> Settlement:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                self._error("SESSION_UNKNOWN", session_id)

            requested = session["requested_total"]
            used = session["used"]
            peer = session["peer"] or ""
            if session["closed"]:
                return Settlement(
                    session_id=session_id,
                    peer=peer,
                    state=_SESSION_CLOSED,
                    requested=requested,
                    used=used,
                    returned=0,
                )

            timestamp = self._timestamp(now)
            returned = 0
            for ticket in session["tickets"].values():
                returned += self._release_ticket(ticket, "closed", timestamp)
            session["closed"] = True
            session["state"] = _SESSION_CLOSED
            session["closed_at"] = timestamp
            self._stats["reclaimed"] += 1
            return Settlement(
                session_id=session_id,
                peer=peer,
                state=_SESSION_CLOSED,
                requested=requested,
                used=used,
                returned=returned,
            )

    def close_peer(self, peer: str, *, now: str | None = None) -> PeerRecord:
        with self._lock:
            record = self._peer(peer)
            if record["state"] == _CLOSED:
                return self._peer_record(record)

            timestamp = self._timestamp(now)
            record["state"] = _CLOSED
            record["closed_at"] = timestamp
            self._publish_peer(record)

            for session in self._sessions.values():
                if session["closed"]:
                    continue
                released = 0
                for ticket in session["tickets"].values():
                    if (
                        self._ticket_is_active(ticket)
                        and ticket["peer"] == peer
                    ):
                        released += self._release_ticket(
                            ticket, "orphaned", timestamp
                        )
                if released:
                    if not any(
                        self._ticket_is_active(ticket)
                        for ticket in session["tickets"].values()
                    ):
                        session["last_result"] = "failure"
                    self._refresh_session_state(session)
            return self._peer_record(record)

    def session_status(self, session_id: str) -> dict:
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return {
                    "state": "unknown",
                    "reserved": 0,
                    "used": 0,
                }
            return {
                "state": session["state"],
                "reserved": self._reserved(session),
                "used": session["used"],
            }

    # ------------------------------------------------------------------
    # Observability and persistence
    # ------------------------------------------------------------------
    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def snapshot(self) -> dict:
        with self._lock:
            peers = {}
            for peer, record in self._peers.items():
                peers[peer] = {
                    "peer": record["peer"],
                    "origin_host": record["origin_host"],
                    "state": record["state"],
                    "applications": list(record["applications"]),
                    "opened_at": record["opened_at"],
                    "closed_at": record["closed_at"],
                    "capabilities_at": record["capabilities_at"],
                }

            sessions = {}
            for session_id, session in self._sessions.items():
                tickets = {}
                for hop, ticket in session["tickets"].items():
                    tickets[hop] = copy.deepcopy(ticket)
                sessions[session_id] = {
                    "session_id": session["session_id"],
                    "subscriber": session["subscriber"],
                    "peer": session["peer"],
                    "state": session["state"],
                    "reserved": self._reserved(session),
                    "requested": session["requested_total"],
                    "used": session["used"],
                    "last_result": session["last_result"],
                    "requested_total": session["requested_total"],
                    "closed": session["closed"],
                    "closed_at": session["closed_at"],
                    "tickets": tickets,
                }

            state = {
                "version": 1,
                "peers": peers,
                "sessions": sessions,
                "dedup": [
                    [session_id, hop]
                    for session_id, hop in self._dedup.keys()
                ],
                "counters": dict(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except DiameterError:
                raise
            except Exception as exc:  # malformed nested structures
                raise DiameterError("SNAPSHOT_INVALID", str(exc)) from exc

            peers, sessions, dedup, counters, next_hop, next_end = parsed
            self._peers = peers
            self._sessions = sessions
            self._dedup = dedup
            self._stats = counters
            self._next_hop = next_hop
            self._next_end = next_end

    @staticmethod
    def _bad_snapshot(detail: object = None) -> None:
        raise DiameterError("SNAPSHOT_INVALID", detail)

    @classmethod
    def _parse_snapshot(cls, state: dict):
        required_top = {"version", "peers", "sessions", "dedup", "counters"}
        if not isinstance(state, dict) or set(state) != required_top:
            cls._bad_snapshot("top-level structure")

        source = copy.deepcopy(state)
        if (
            isinstance(source["version"], bool)
            or not isinstance(source["version"], int)
            or source["version"] != 1
        ):
            cls._bad_snapshot("version")
        if not isinstance(source["peers"], dict):
            cls._bad_snapshot("peers")
        if not isinstance(source["sessions"], dict):
            cls._bad_snapshot("sessions")
        if (
            not isinstance(source["dedup"], (list, tuple))
            or not isinstance(source["counters"], dict)
        ):
            cls._bad_snapshot("collections")

        counters = source["counters"]
        if set(counters) != set(_STAT_KEYS):
            cls._bad_snapshot("counters")
        for key in _STAT_KEYS:
            value = counters[key]
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
            ):
                cls._bad_snapshot(key)

        peers = {}
        for peer, raw in source["peers"].items():
            if not isinstance(peer, str) or not peer or not isinstance(raw, dict):
                cls._bad_snapshot("peer")
            if raw.get("peer") != peer:
                cls._bad_snapshot("peer identity")
            if raw.get("state") not in {_WAIT_CONN_ACK, _OPEN, _CLOSED}:
                cls._bad_snapshot("peer state")
            if not isinstance(raw.get("origin_host"), str):
                cls._bad_snapshot("origin_host")
            applications = raw.get("applications")
            if not isinstance(applications, (list, tuple)):
                cls._bad_snapshot("applications")
            if any(
                not isinstance(application, str) or not application
                for application in applications
            ):
                cls._bad_snapshot("applications")
            peers[peer] = {
                "peer": peer,
                "origin_host": raw["origin_host"],
                "state": raw["state"],
                "applications": tuple(applications),
                "opened_at": raw.get("opened_at"),
                "closed_at": raw.get("closed_at"),
                "capabilities_at": raw.get("capabilities_at"),
            }

        sessions = {}
        max_hop = 0
        max_end = 0
        for session_id, raw in source["sessions"].items():
            if (
                not isinstance(session_id, str)
                or not session_id
                or not isinstance(raw, dict)
            ):
                cls._bad_snapshot("session")
            if raw.get("session_id") != session_id:
                cls._bad_snapshot("session identity")
            if raw.get("state") not in _SESSION_STATES:
                cls._bad_snapshot("session state")
            used = raw.get("used", 0)
            requested_total = raw.get(
                "requested_total", raw.get("requested", 0)
            )
            if (
                isinstance(used, bool)
                or not isinstance(used, int)
                or used < 0
                or isinstance(requested_total, bool)
                or not isinstance(requested_total, int)
                or requested_total < 0
            ):
                cls._bad_snapshot("session counters")
            closed = raw.get("closed", raw.get("state") == _SESSION_CLOSED)
            if not isinstance(closed, bool):
                cls._bad_snapshot("session closed")
            raw_tickets = raw.get("tickets")
            if not isinstance(raw_tickets, dict):
                cls._bad_snapshot("tickets")

            tickets = OrderedDict()
            for hop, raw_ticket in raw_tickets.items():
                if (
                    not isinstance(hop, str)
                    or not hop
                    or not isinstance(raw_ticket, dict)
                ):
                    cls._bad_snapshot("ticket")
                if raw_ticket.get("hop_by_hop", hop) != hop:
                    cls._bad_snapshot("ticket identity")
                end_to_end = raw_ticket.get("end_to_end")
                peer = raw_ticket.get("peer")
                request = raw_ticket.get("requested")
                reserved = raw_ticket.get("reserved", request)
                remaining = raw_ticket.get("remaining", reserved)
                ticket_state = raw_ticket.get("state", "sent")
                retransmits = raw_ticket.get("retransmits", 0)
                if not isinstance(end_to_end, str) or not end_to_end:
                    cls._bad_snapshot("end_to_end")
                if not isinstance(peer, str) or peer not in peers:
                    cls._bad_snapshot("ticket peer")
                for value in (request, reserved, remaining, retransmits):
                    if (
                        isinstance(value, bool)
                        or not isinstance(value, int)
                        or value < 0
                    ):
                        cls._bad_snapshot("ticket counters")
                if request <= 0 or reserved != request:
                    cls._bad_snapshot("ticket reservation")
                if remaining > reserved:
                    cls._bad_snapshot("ticket remaining")
                if ticket_state not in _TICKET_STATES:
                    cls._bad_snapshot("ticket state")
                tickets[hop] = {
                    "hop_by_hop": hop,
                    "end_to_end": end_to_end,
                    "peer": peer,
                    "requested": request,
                    "reserved": reserved,
                    "remaining": remaining,
                    "state": ticket_state,
                    "retransmits": retransmits,
                    "used": raw_ticket.get("used", 0),
                    "created_at": raw_ticket.get("created_at"),
                    "settled_at": raw_ticket.get("settled_at"),
                    "last_at": raw_ticket.get("last_at"),
                }
                hop_match = _HOP_RE.match(hop)
                if hop_match:
                    max_hop = max(max_hop, int(hop_match.group(1)))
                end_match = _END_RE.match(end_to_end)
                if end_match:
                    max_end = max(max_end, int(end_match.group(1)))

            session_peer = raw.get("peer")
            if session_peer is not None and not isinstance(session_peer, str):
                cls._bad_snapshot("session peer")
            sessions[session_id] = {
                "session_id": session_id,
                "subscriber": raw.get("subscriber"),
                "peer": session_peer,
                "state": _SESSION_CLOSED if closed else raw["state"],
                "used": used,
                "last_result": raw.get("last_result"),
                "requested_total": requested_total,
                "closed": closed,
                "closed_at": raw.get("closed_at"),
                "tickets": tickets,
            }

        dedup = OrderedDict()
        for entry in source["dedup"]:
            if (
                not isinstance(entry, (list, tuple))
                or len(entry) != 2
                or not isinstance(entry[0], str)
                or not isinstance(entry[1], str)
            ):
                cls._bad_snapshot("dedup entry")
            dedup[(entry[0], entry[1])] = None
            hop_match = _HOP_RE.match(entry[1])
            if hop_match:
                max_hop = max(max_hop, int(hop_match.group(1)))

        return (
            peers,
            sessions,
            dedup,
            {key: counters[key] for key in _STAT_KEYS},
            max_hop + 1,
            max_end + 1,
        )
