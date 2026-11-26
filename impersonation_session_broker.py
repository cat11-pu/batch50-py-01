"""Customer-service impersonation sessions: dual approval, action scope, one-time tickets."""

from __future__ import annotations

import copy
import re
import threading
import time


_STAT_KEYS = (
    "requests",
    "approvals",
    "sessions",
    "actions",
    "denied_actions",
    "tickets",
    "redeemed",
    "revocations",
    "expired",
)

_REQUEST_STATES = {"pending", "approved", "active"}
_SESSION_STATES = {"active", "expired", "revoked"}
_TICKET_STATES = {"unused", "spent"}

_PASSWORD_FIELDS = {"password", "passwd", "pwd"}
_FACTOR_FIELDS = {"factor", "factors", "mfa", "2fa", "otp", "totp", "authenticator"}
_MUTATION_VERBS = {
    "add",
    "change",
    "disable",
    "enroll",
    "modify",
    "recover",
    "remove",
    "replace",
    "request",
    "reset",
    "revoke",
    "rotate",
    "set",
    "update",
    "verify",
}
_IMPERSONATION_ACTIONS = {
    "act_as",
    "assume_identity",
    "assume_user",
    "create_session",
    "delegate_access",
    "open_session",
    "request_session",
    "start_session",
    "switch_user",
}
_IMPERSONATION_VERBS = {
    "assume",
    "begin",
    "create",
    "delegate",
    "enable",
    "grant",
    "initiate",
    "launch",
    "new",
    "open",
    "request",
    "start",
    "switch",
}


class ImpersonationError(ValueError):
    """Refused impersonation operation carrying a stable machine-readable code."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class ImpersonationBroker:
    """Broker for impersonation requests, approved sessions and scoped action tickets."""

    def __init__(self, *, session_ttl: int = 900, ticket_ttl: int = 120,
                 clock=None) -> None:
        self.session_ttl = int(session_ttl)
        self.ticket_ttl = int(ticket_ttl)
        self._clock = clock
        self._lock = threading.RLock()
        self._requests = {}
        self._sessions = {}
        self._tickets = {}
        self._approvers = set()
        self._counters = {key: 0 for key in _STAT_KEYS}

    def _now(self, now: int | None) -> int:
        if now is None:
            now = self._clock() if self._clock is not None else time.time()
        return int(now)

    @staticmethod
    def _is_text(value: object) -> bool:
        return isinstance(value, str) and bool(value.strip())

    @classmethod
    def _clean_actions(cls, actions) -> tuple[str, ...]:
        if actions is None or isinstance(actions, (str, bytes, bytearray, dict)):
            raise ImpersonationError("IMP_INVALID", "actions")
        try:
            raw_actions = list(actions)
        except TypeError as exc:
            raise ImpersonationError("IMP_INVALID", "actions") from exc
        if not raw_actions:
            raise ImpersonationError("IMP_INVALID", "actions")
        if any(not cls._is_text(action) for action in raw_actions):
            raise ImpersonationError("IMP_INVALID", "actions")
        return tuple(sorted(set(raw_actions)))

    @classmethod
    def _validate_principal(cls, principal: object) -> str:
        if not cls._is_text(principal):
            raise ImpersonationError("IMP_INVALID", "principal")
        return principal

    @staticmethod
    def _request_view(record: dict) -> dict:
        return {
            "request_id": record["request_id"],
            "cs_id": record["cs_id"],
            "target_id": record["target_id"],
            "actions": record["actions"],
            "state": record["state"],
            "approved_by": record["approved_by"],
            "session_id": record["session_id"],
        }

    @staticmethod
    def _session_view(record: dict) -> dict:
        return {
            "session_id": record["session_id"],
            "request_id": record["request_id"],
            "target_id": record["target_id"],
            "actions": record["actions"],
            "state": record["state"],
            "expires_at": record["expires_at"],
        }

    @staticmethod
    def _ticket_view(record: dict) -> dict:
        return {
            "ticket_id": record["ticket_id"],
            "session_id": record["session_id"],
            "action": record["action"],
            "expires_at": record["expires_at"],
            "state": record["state"],
        }

    @staticmethod
    def _is_sensitive_action(action: str) -> bool:
        spaced = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", action.strip())
        normalized = re.sub(r"[^a-z0-9]+", "_", spaced.lower()).strip("_")
        if not normalized:
            return False
        tokens = set(normalized.split("_"))
        if normalized.startswith("act_as") or normalized in _IMPERSONATION_ACTIONS:
            return True
        if (normalized == "impersonation"
                or tokens & {"impersonate", "impersonating"}
                or (tokens & {"impersonation"} and tokens & _IMPERSONATION_VERBS)):
            return True
        mutates = (bool(tokens & _MUTATION_VERBS)
                   or any(normalized.startswith(verb) for verb in _MUTATION_VERBS)
                   or any(normalized.endswith(verb) for verb in _MUTATION_VERBS))
        if mutates and any(field in normalized for field in _PASSWORD_FIELDS):
            return True
        if mutates and any(field in normalized for field in _FACTOR_FIELDS):
            return True
        if tokens & {"session"} and tokens & _IMPERSONATION_VERBS:
            return True
        return False

    def _check_action(self, session: dict, action: object) -> None:
        if (not isinstance(action, str)
                or action not in session["actions"]
                or self._is_sensitive_action(action)):
            self._counters["denied_actions"] += 1
            raise ImpersonationError("IMP_SCOPE", action)

    def _get_request(self, request_id: str) -> dict:
        try:
            return self._requests[request_id]
        except (KeyError, TypeError) as exc:
            raise ImpersonationError("IMP_REQUEST_UNKNOWN", request_id) from exc

    def _get_session(self, session_id: str) -> dict:
        try:
            return self._sessions[session_id]
        except (KeyError, TypeError) as exc:
            raise ImpersonationError("IMP_SESSION_UNKNOWN", session_id) from exc

    def _get_ticket(self, ticket_id: str) -> dict:
        try:
            return self._tickets[ticket_id]
        except (KeyError, TypeError) as exc:
            raise ImpersonationError("IMP_TICKET_UNKNOWN", ticket_id) from exc

    def _active_session(self, session_id: str, now: int) -> dict:
        session = self._get_session(session_id)
        if session["state"] == "revoked":
            raise ImpersonationError("IMP_SESSION_REVOKED", session_id)
        if session["state"] == "expired" or now >= session["expires_at"]:
            raise ImpersonationError("IMP_SESSION_EXPIRED", session_id)
        if session["approved_by"] not in self._approvers:
            raise ImpersonationError("IMP_NOT_APPROVER", session["approved_by"])
        return session

    def _pair_in_flight(self, cs_id: str, target_id: str, now: int) -> bool:
        for request in self._requests.values():
            if (request["cs_id"] == cs_id
                    and request["target_id"] == target_id
                    and request["state"] in {"pending", "approved"}):
                return True
        for session in self._sessions.values():
            if (session["cs_id"] == cs_id
                    and session["target_id"] == target_id
                    and session["state"] == "active"
                    and now < session["expires_at"]):
                return True
        return False

    def grant_approver(self, principal: str) -> dict:
        with self._lock:
            principal = self._validate_principal(principal)
            self._approvers.add(principal)
            return {"principal": principal, "approver": True}

    def revoke_approver(self, principal: str) -> bool:
        with self._lock:
            principal = self._validate_principal(principal)
            if principal not in self._approvers:
                return False
            self._approvers.remove(principal)
            return True

    def request(self, cs_id: str, target_id: str, reason: str, actions, *,
                now: int | None = None) -> dict:
        with self._lock:
            if not self._is_text(cs_id):
                raise ImpersonationError("IMP_INVALID", "cs_id")
            if not self._is_text(target_id):
                raise ImpersonationError("IMP_INVALID", "target_id")
            if not self._is_text(reason):
                raise ImpersonationError("IMP_INVALID", "reason")
            cleaned_actions = self._clean_actions(actions)
            if cs_id == target_id:
                raise ImpersonationError("IMP_SELF", cs_id)
            current = self._now(now)
            if self._pair_in_flight(cs_id, target_id, current):
                raise ImpersonationError("IMP_LIMIT", [cs_id, target_id])
            next_number = self._counters["requests"] + 1
            request_id = f"req-{next_number}"
            record = {
                "request_id": request_id,
                "cs_id": cs_id,
                "target_id": target_id,
                "reason": reason,
                "actions": cleaned_actions,
                "state": "pending",
                "approved_by": None,
                "session_id": None,
            }
            self._requests[request_id] = record
            self._counters["requests"] = next_number
            return self._request_view(record)

    def approve(self, request_id: str, approver: str, *,
                now: int | None = None) -> dict:
        with self._lock:
            self._now(now)
            record = self._get_request(request_id)
            if not self._is_text(approver) or approver not in self._approvers:
                raise ImpersonationError("IMP_NOT_APPROVER", approver)
            if approver == record["cs_id"]:
                raise ImpersonationError("IMP_SELF", approver)
            if record["state"] != "pending":
                raise ImpersonationError("IMP_REQUEST_STATE", record["state"])
            record["state"] = "approved"
            record["approved_by"] = approver
            self._counters["approvals"] += 1
            return self._request_view(record)

    def start(self, request_id: str, *, now: int | None = None) -> dict:
        with self._lock:
            current = self._now(now)
            record = self._get_request(request_id)
            if record["state"] != "approved":
                raise ImpersonationError("IMP_REQUEST_STATE", record["state"])
            if record["approved_by"] not in self._approvers:
                raise ImpersonationError("IMP_NOT_APPROVER", record["approved_by"])
            next_number = self._counters["sessions"] + 1
            session_id = f"imp-{next_number}"
            session = {
                "session_id": session_id,
                "request_id": request_id,
                "cs_id": record["cs_id"],
                "target_id": record["target_id"],
                "actions": record["actions"],
                "state": "active",
                "expires_at": current + self.session_ttl,
                "started_at": current,
                "approved_by": record["approved_by"],
                "action_count": 0,
                "revoked_by": None,
                "revoked_at": None,
                "revoke_reason": None,
            }
            self._sessions[session_id] = session
            record["state"] = "active"
            record["session_id"] = session_id
            self._counters["sessions"] = next_number
            return self._session_view(session)

    def act(self, session_id: str, action: str, *,
            now: int | None = None) -> dict:
        with self._lock:
            current = self._now(now)
            session = self._active_session(session_id, current)
            self._check_action(session, action)
            session["action_count"] += 1
            self._counters["actions"] += 1
            return {
                "session_id": session_id,
                "action": action,
                "allowed": True,
                "count": session["action_count"],
            }

    def issue_ticket(self, session_id: str, action: str, *,
                     now: int | None = None) -> dict:
        with self._lock:
            current = self._now(now)
            session = self._active_session(session_id, current)
            self._check_action(session, action)
            next_number = self._counters["tickets"] + 1
            ticket_id = f"tkt-{next_number}"
            ticket = {
                "ticket_id": ticket_id,
                "session_id": session_id,
                "action": action,
                "expires_at": current + self.ticket_ttl,
                "issued_at": current,
                "state": "unused",
                "redeemed_at": None,
            }
            self._tickets[ticket_id] = ticket
            self._counters["tickets"] = next_number
            return self._ticket_view(ticket)

    def redeem_ticket(self, ticket_id: str, *, now: int | None = None) -> dict:
        with self._lock:
            current = self._now(now)
            ticket = self._get_ticket(ticket_id)
            if ticket["state"] == "spent":
                raise ImpersonationError("IMP_TICKET_SPENT", ticket_id)
            session = self._get_session(ticket["session_id"])
            if session["state"] == "revoked":
                raise ImpersonationError("IMP_SESSION_REVOKED", session["session_id"])
            if session["state"] == "expired" or current >= session["expires_at"]:
                raise ImpersonationError("IMP_SESSION_EXPIRED", session["session_id"])
            if current >= ticket["expires_at"]:
                raise ImpersonationError("IMP_TICKET_EXPIRED", ticket_id)
            if session["approved_by"] not in self._approvers:
                raise ImpersonationError("IMP_NOT_APPROVER", session["approved_by"])
            ticket["state"] = "spent"
            ticket["redeemed_at"] = current
            self._counters["redeemed"] += 1
            return {
                "ticket_id": ticket_id,
                "session_id": ticket["session_id"],
                "action": ticket["action"],
                "redeemed_at": current,
            }

    def revoke(self, session_id: str, actor: str, reason: str, *,
               now: int | None = None) -> dict:
        with self._lock:
            if not self._is_text(actor):
                raise ImpersonationError("IMP_INVALID", "actor")
            if not self._is_text(reason):
                raise ImpersonationError("IMP_INVALID", "reason")
            current = self._now(now)
            session = self._get_session(session_id)
            if session["state"] == "revoked":
                return {
                    "session_id": session_id,
                    "state": "revoked",
                    "revoked_by": session["revoked_by"],
                    "revoked_at": session["revoked_at"],
                }
            session["state"] = "revoked"
            session["revoked_by"] = actor
            session["revoked_at"] = current
            session["revoke_reason"] = reason
            self._counters["revocations"] += 1
            return {
                "session_id": session_id,
                "state": "revoked",
                "revoked_by": actor,
                "revoked_at": current,
            }

    def expire(self, *, now: int | None = None) -> int:
        with self._lock:
            current = self._now(now)
            expired_count = 0
            for session in self._sessions.values():
                if session["state"] == "active" and current >= session["expires_at"]:
                    session["state"] = "expired"
                    expired_count += 1
            self._counters["expired"] += expired_count
            return expired_count

    def session_view(self, session_id: str) -> dict:
        with self._lock:
            return self._session_view(self._get_session(session_id))

    def snapshot(self) -> dict:
        with self._lock:
            requests = {}
            for request_id, record in self._requests.items():
                snapshot_record = copy.deepcopy(record)
                snapshot_record["actions"] = list(record["actions"])
                requests[request_id] = snapshot_record
            sessions = {}
            for session_id, record in self._sessions.items():
                snapshot_record = copy.deepcopy(record)
                snapshot_record["actions"] = list(record["actions"])
                sessions[session_id] = snapshot_record
            return {
                "version": 1,
                "requests": requests,
                "sessions": sessions,
                "tickets": copy.deepcopy(self._tickets),
                "approvers": sorted(self._approvers),
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                requests, sessions, tickets, approvers, counters = (
                    self._parse_snapshot(state)
                )
            except (KeyError, TypeError, ValueError) as exc:
                raise ImpersonationError("IMP_SNAPSHOT", str(exc)) from None
            self._requests = requests
            self._sessions = sessions
            self._tickets = tickets
            self._approvers = approvers
            self._counters = counters

    def stats(self) -> dict:
        with self._lock:
            return {key: self._counters[key] for key in _STAT_KEYS}

    @classmethod
    def _parse_snapshot(cls, state: dict):
        if not isinstance(state, dict):
            raise TypeError("snapshot must be a mapping")
        version = state.get("version")
        if isinstance(version, bool) or version != 1:
            raise ValueError("unsupported snapshot version")
        raw_requests = state["requests"]
        raw_sessions = state["sessions"]
        raw_tickets = state["tickets"]
        raw_approvers = state["approvers"]
        raw_counters = state["counters"]
        if not all(isinstance(item, dict)
                   for item in (raw_requests, raw_sessions, raw_tickets, raw_counters)):
            raise TypeError("snapshot collections must be mappings")
        if not isinstance(raw_approvers, (list, tuple)):
            raise TypeError("approvers must be a sequence")

        approvers = set()
        for principal in raw_approvers:
            if not cls._is_text(principal):
                raise ValueError("invalid approver")
            approvers.add(principal)

        counters = {}
        for key in _STAT_KEYS:
            value = raw_counters[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise ValueError("invalid counter")
            counters[key] = value

        requests = {}
        for request_id, raw in raw_requests.items():
            if not isinstance(request_id, str) or not re.fullmatch(r"req-[1-9]\d*", request_id):
                raise ValueError("invalid request id")
            if not isinstance(raw, dict) or raw.get("request_id") != request_id:
                raise ValueError("invalid request record")
            cs_id = raw["cs_id"]
            target_id = raw["target_id"]
            reason = raw["reason"]
            if not cls._is_text(cs_id) or not cls._is_text(target_id) or not cls._is_text(reason):
                raise ValueError("invalid request identity")
            if cs_id == target_id:
                raise ValueError("invalid self request")
            actions = cls._clean_snapshot_actions(raw["actions"])
            request_state = raw["state"]
            if request_state not in _REQUEST_STATES:
                raise ValueError("invalid request state")
            approved_by = raw["approved_by"]
            session_id = raw["session_id"]
            if approved_by is not None and not cls._is_text(approved_by):
                raise ValueError("invalid approver binding")
            if session_id is not None and not isinstance(session_id, str):
                raise ValueError("invalid request session")
            if request_state == "pending":
                if approved_by is not None or session_id is not None:
                    raise ValueError("invalid pending request")
            elif request_state == "approved":
                if approved_by is None or session_id is not None:
                    raise ValueError("invalid approved request")
            elif approved_by is None or session_id is None:
                raise ValueError("invalid active request")
            requests[request_id] = {
                "request_id": request_id,
                "cs_id": cs_id,
                "target_id": target_id,
                "reason": reason,
                "actions": actions,
                "state": request_state,
                "approved_by": approved_by,
                "session_id": session_id,
            }

        sessions = {}
        for session_id, raw in raw_sessions.items():
            if not isinstance(session_id, str) or not re.fullmatch(r"imp-[1-9]\d*", session_id):
                raise ValueError("invalid session id")
            if not isinstance(raw, dict) or raw.get("session_id") != session_id:
                raise ValueError("invalid session record")
            if raw["state"] not in _SESSION_STATES:
                raise ValueError("invalid session state")
            for key in ("request_id", "cs_id", "target_id", "approved_by"):
                if not cls._is_text(raw[key]):
                    raise ValueError("invalid session identity")
            if raw["cs_id"] == raw["target_id"]:
                raise ValueError("invalid self session")
            expires_at = cls._snapshot_int(raw["expires_at"], "expires_at")
            started_at = cls._snapshot_int(raw["started_at"], "started_at")
            action_count = cls._snapshot_int(raw["action_count"], "action_count")
            revoked_by = raw["revoked_by"]
            revoked_at = raw["revoked_at"]
            revoke_reason = raw["revoke_reason"]
            if raw["state"] == "revoked":
                if not isinstance(revoked_by, str) or not isinstance(revoke_reason, str):
                    raise ValueError("invalid revocation")
                revoked_at = cls._snapshot_int(revoked_at, "revoked_at")
            elif any(item is not None for item in (revoked_by, revoked_at, revoke_reason)):
                raise ValueError("invalid revocation state")
            request = requests.get(raw["request_id"])
            session_actions = cls._clean_snapshot_actions(raw["actions"])
            if (request is None
                    or request["state"] != "active"
                    or request["session_id"] != session_id
                    or request["cs_id"] != raw["cs_id"]
                    or request["target_id"] != raw["target_id"]
                    or request["actions"] != session_actions
                    or request["approved_by"] != raw["approved_by"]):
                raise ValueError("broken request/session link")
            sessions[session_id] = {
                "session_id": session_id,
                "request_id": raw["request_id"],
                "cs_id": raw["cs_id"],
                "target_id": raw["target_id"],
                "actions": session_actions,
                "state": raw["state"],
                "expires_at": expires_at,
                "started_at": started_at,
                "approved_by": raw["approved_by"],
                "action_count": action_count,
                "revoked_by": revoked_by,
                "revoked_at": revoked_at,
                "revoke_reason": revoke_reason,
            }

        tickets = {}
        for ticket_id, raw in raw_tickets.items():
            if not isinstance(ticket_id, str) or not re.fullmatch(r"tkt-[1-9]\d*", ticket_id):
                raise ValueError("invalid ticket id")
            if not isinstance(raw, dict) or raw.get("ticket_id") != ticket_id:
                raise ValueError("invalid ticket record")
            if raw["state"] not in _TICKET_STATES:
                raise ValueError("invalid ticket state")
            if not cls._is_text(raw["action"]):
                raise ValueError("invalid ticket action")
            session = sessions.get(raw["session_id"])
            if session is None or raw["action"] not in session["actions"]:
                raise ValueError("broken ticket/session link")
            expires_at = cls._snapshot_int(raw["expires_at"], "expires_at")
            issued_at = cls._snapshot_int(raw["issued_at"], "issued_at")
            redeemed_at = raw["redeemed_at"]
            if raw["state"] == "spent":
                redeemed_at = cls._snapshot_int(redeemed_at, "redeemed_at")
            elif redeemed_at is not None:
                raise ValueError("invalid unused ticket")
            tickets[ticket_id] = {
                "ticket_id": ticket_id,
                "session_id": raw["session_id"],
                "action": raw["action"],
                "expires_at": expires_at,
                "issued_at": issued_at,
                "state": raw["state"],
                "redeemed_at": redeemed_at,
            }

        cls._validate_id_counter(raw_requests, counters["requests"], "req")
        cls._validate_id_counter(raw_sessions, counters["sessions"], "imp")
        cls._validate_id_counter(raw_tickets, counters["tickets"], "tkt")
        for request in requests.values():
            if request["session_id"] is not None and request["session_id"] not in sessions:
                raise ValueError("unknown request session")
        return requests, sessions, tickets, approvers, counters

    @classmethod
    def _clean_snapshot_actions(cls, actions) -> tuple[str, ...]:
        if not isinstance(actions, (list, tuple)):
            raise ValueError("invalid actions")
        return cls._clean_actions(actions)

    @staticmethod
    def _snapshot_int(value: object, field: str) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError(f"invalid {field}")
        return value

    @staticmethod
    def _validate_id_counter(records: dict, counter: int, prefix: str) -> None:
        highest = 0
        for record_id in records:
            number = int(record_id.rsplit("-", 1)[1])
            highest = max(highest, number)
        if counter < highest:
            raise ValueError(f"{prefix} counter is behind records")
