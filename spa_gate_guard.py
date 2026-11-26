"""Single-packet authorization gate: HMAC window, NAT rebinding and tickets."""

from __future__ import annotations

import copy
import hashlib
import hmac
import threading
import time
from dataclasses import dataclass


class SpaError(ValueError):
    """Raised when an enrollment, packet or ticket operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Enrollment:
    client: str
    generation: int
    ports: tuple[int, ...]
    enrolled_at: int


@dataclass(frozen=True)
class KeyRecord:
    generation: int
    created_at: int
    state: str


@dataclass(frozen=True)
class SpaVerdict:
    status: str
    client: str
    port: int
    nonce: str
    generation: int
    source: str


@dataclass(frozen=True)
class Ticket:
    ticket_id: str
    client: str
    port: int
    source: str
    nonce: str
    generation: int
    issued_at: int
    expires_at: int
    state: str


_STATS_KEYS = (
    "enrollments",
    "keys_rotated",
    "verifications",
    "accepted",
    "rejected",
    "replays",
    "failures",
    "cooldown_hits",
    "tickets_issued",
    "tickets_revoked",
    "tickets_expired",
)

_SNAPSHOT_KEYS = {
    "version",
    "clients",
    "keys",
    "tickets",
    "nonces",
    "failures",
    "counters",
}

_PACKET_FIELDS = (
    "client",
    "port",
    "timestamp",
    "nonce",
    "generation",
    "source",
    "mac",
)


def _is_integer(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _invalid_request(detail: object = None) -> SpaError:
    return SpaError("SPA_INVALID_REQUEST", detail)


def _normalize_ports(ports: object) -> tuple[int, ...]:
    if isinstance(ports, (str, bytes, bytearray)):
        raise _invalid_request({"field": "ports"})
    try:
        values = list(ports)  # type: ignore[arg-type]
    except Exception as exc:
        raise _invalid_request({"field": "ports"}) from exc

    if not values:
        raise _invalid_request({"field": "ports", "reason": "empty"})

    normalized: set[int] = set()
    for port in values:
        if not _is_integer(port):
            raise _invalid_request({"field": "port", "value": port})
        if not 1 <= int(port) <= 65535:
            raise _invalid_request({"field": "port", "value": port})
        normalized.add(int(port))

    return tuple(sorted(normalized))


def _source_prefix(source: object) -> str:
    if not isinstance(source, str) or not source:
        return ""
    if "." in source:
        parts = source.split(".")
        if len(parts) >= 3:
            return ".".join(parts[:3])
        return source
    if ":" in source:
        parts = source.split(":")
        if len(parts) >= 3:
            return ":".join(parts[:3])
    return source


def _generation_key(value: object) -> int | None:
    if _is_integer(value):
        return int(value)
    if isinstance(value, str):
        text = value
        digits = text[1:] if text.startswith("-") else text
        if digits.isdigit():
            return int(text)
    return None


class SpaGateGuard:
    """Authorize single packets and issue short-lived per-port tickets."""

    def __init__(self, *, window: int = 30, skew_steps: int = 1,
                 max_clients: int = 8, max_tickets: int = 32,
                 max_keys: int = 4, cooldown: int = 3,
                 max_failures: int = 5, clock=None) -> None:
        self.window = window
        self.skew_steps = skew_steps
        self.max_clients = max_clients
        self.max_tickets = max_tickets
        self.max_keys = max_keys
        self.cooldown = cooldown
        self.max_failures = max_failures
        self._clock = clock
        self._lock = threading.RLock()
        self._last_now: int | None = None
        self._stats = {key: 0 for key in _STATS_KEYS}
        self._clients: dict[str, dict] = {}
        self._keys: dict[int, dict] = {}
        self._tickets: dict[str, dict] = {}
        self._nonces: dict[str, dict] = {}
        self._failures: dict[str, dict] = {}

    def _resolve_now(self, now: int | None) -> int:
        if now is None:
            if self._last_now is not None:
                return self._last_now
            if self._clock is not None:
                return int(self._clock())
            return int(time.time())
        if not _is_integer(now):
            raise _invalid_request({"field": "now"})
        self._last_now = int(now)
        return int(now)

    def enroll(self, client: str, ports, generation: int, key: bytes,
               now: int | None = None) -> Enrollment:
        with self._lock:
            current_now = self._resolve_now(now)
            if not isinstance(client, str) or not client:
                raise _invalid_request({"field": "client"})
            normalized_ports = _normalize_ports(ports)
            if not _is_integer(generation):
                raise _invalid_request({"field": "generation"})
            if isinstance(key, str):
                key_material = key.encode("utf-8")
            elif isinstance(key, (bytes, bytearray)):
                key_material = bytes(key)
            else:
                raise _invalid_request({"field": "key"})

            if client in self._clients:
                raise SpaError("SPA_CLIENT_EXISTS", {"client": client})
            if len(self._clients) >= self.max_clients:
                raise SpaError(
                    "SPA_CAPACITY_EXCEEDED",
                    {"resource": "clients", "limit": self.max_clients},
                )
            if (generation not in self._keys
                    and len(self._keys) >= self.max_keys):
                raise SpaError(
                    "SPA_KEY_LIMIT",
                    {"limit": self.max_keys, "generation": generation},
                )

            self._clients[client] = {
                "ports": normalized_ports,
                "generation": int(generation),
                "enrolled_at": current_now,
                "failures": 0,
            }
            if generation not in self._keys:
                self._keys[int(generation)] = {
                    "key": key_material,
                    "created_at": current_now,
                    "state": "active",
                }
            self._stats["enrollments"] += 1
            return Enrollment(
                client=client,
                generation=int(generation),
                ports=normalized_ports,
                enrolled_at=current_now,
            )

    def rotate_key(self, generation: int, key: bytes,
                   now: int | None = None) -> KeyRecord:
        with self._lock:
            current_now = self._resolve_now(now)
            if not _is_integer(generation):
                raise _invalid_request({"field": "generation"})
            if isinstance(key, str):
                key_material = key.encode("utf-8")
            elif isinstance(key, (bytes, bytearray)):
                key_material = bytes(key)
            else:
                raise _invalid_request({"field": "key"})

            generation = int(generation)
            if (generation not in self._keys
                    and len(self._keys) >= self.max_keys):
                raise SpaError(
                    "SPA_KEY_LIMIT",
                    {"limit": self.max_keys, "generation": generation},
                )

            for record in self._keys.values():
                record["state"] = "readonly"
            self._keys[generation] = {
                "key": key_material,
                "created_at": current_now,
                "state": "active",
            }
            self._stats["keys_rotated"] += 1
            return KeyRecord(
                generation=generation,
                created_at=current_now,
                state="active",
            )

    def _check_cooldown_locked(self, prefix: str, now: int) -> None:
        if not prefix:
            return
        record = self._failures.get(prefix)
        if record is None:
            return

        blocked_until = record.get("blocked_until", 0)
        if _is_integer(blocked_until) and now < int(blocked_until):
            self._stats["cooldown_hits"] += 1
            record["cooldown_hits"] = int(record.get("cooldown_hits", 0)) + 1
            raise SpaError(
                "SPA_COOLDOWN",
                {
                    "prefix": prefix,
                    "failures": int(record.get("count", 0)),
                    "retry_after": int(blocked_until) - now,
                },
            )

        if blocked_until:
            record["count"] = 0
            record["blocked_until"] = 0

    def _validate_packet_shape(self, packet: object) -> dict:
        if not isinstance(packet, dict):
            raise _invalid_request({"field": "packet"})
        missing = [name for name in _PACKET_FIELDS if name not in packet]
        if missing:
            raise _invalid_request({"missing": missing})

        client = packet["client"]
        port = packet["port"]
        timestamp = packet["timestamp"]
        nonce = packet["nonce"]
        generation = packet["generation"]
        source = packet["source"]
        mac = packet["mac"]

        if not isinstance(client, str) or not client:
            raise _invalid_request({"field": "client"})
        if not _is_integer(port):
            raise _invalid_request({"field": "port"})
        if not _is_integer(timestamp):
            raise _invalid_request({"field": "timestamp"})
        if not isinstance(nonce, str) or not nonce:
            raise _invalid_request({"field": "nonce"})
        if not _is_integer(generation):
            raise _invalid_request({"field": "generation"})
        if not isinstance(source, str) or not source:
            raise _invalid_request({"field": "source"})
        if not isinstance(mac, str) or not mac:
            raise _invalid_request({"field": "mac"})

        return {
            "client": client,
            "port": int(port),
            "timestamp": int(timestamp),
            "nonce": nonce,
            "generation": int(generation),
            "source": source,
            "mac": mac,
        }

    def _register_bad_mac_locked(self, prefix: str, now: int,
                                 client: str | None) -> None:
        self._stats["failures"] += 1
        if client is not None and client in self._clients:
            self._clients[client]["failures"] = int(
                self._clients[client].get("failures", 0)
            ) + 1

        if not prefix:
            return
        record = self._failures.setdefault(prefix, {
            "count": 0,
            "first_failure_at": now,
            "last_failure_at": now,
            "blocked_until": 0,
            "cooldown_hits": 0,
        })
        record["count"] = int(record.get("count", 0)) + 1
        record["last_failure_at"] = now
        record.setdefault("first_failure_at", now)
        if int(record["count"]) >= self.max_failures:
            record["blocked_until"] = now + self.cooldown

    def _ticket_has_nonce_locked(self, nonce: str) -> str | None:
        for ticket_id, ticket in self._tickets.items():
            if ticket.get("nonce") == nonce:
                return ticket_id
        return None

    def _check_nonce_locked(self, fields: dict, now: int,
                            for_grant: bool) -> None:
        nonce = fields["nonce"]
        existing_ticket = self._ticket_has_nonce_locked(nonce)
        if for_grant and existing_ticket is not None:
            self._stats["replays"] += 1
            raise SpaError(
                "SPA_REPLAY",
                {"nonce": nonce, "ticket_id": existing_ticket},
            )

        record = self._nonces.get(nonce)
        if record is not None:
            expires_at = record.get("expires_at")
            expired = (
                _is_integer(expires_at)
                and now >= int(expires_at)
            )
            if not expired:
                self._stats["replays"] += 1
                raise SpaError("SPA_REPLAY", {"nonce": nonce})
            del self._nonces[nonce]

        self._nonces[nonce] = {
            "first_seen": now,
            "last_seen": now,
            "expires_at": now + self.window,
            "ticket_id": existing_ticket,
            "client": fields["client"],
            "port": fields["port"],
            "generation": fields["generation"],
            "source": fields["source"],
        }

    def _authenticate_locked(self, packet: object, now: int,
                             *, for_grant: bool = False) -> dict:
        if isinstance(packet, dict):
            prefix = _source_prefix(packet.get("source"))
        else:
            prefix = ""
        self._check_cooldown_locked(prefix, now)

        fields = self._validate_packet_shape(packet)
        client_record = self._clients.get(fields["client"])
        if client_record is None:
            raise SpaError(
                "SPA_UNKNOWN_CLIENT",
                {"client": fields["client"]},
            )

        key_record = self._keys.get(fields["generation"])
        if key_record is None:
            raise SpaError(
                "SPA_UNKNOWN_GENERATION",
                {"generation": fields["generation"]},
            )

        if abs(fields["timestamp"] - now) > self.skew_steps:
            raise SpaError(
                "SPA_TIME_WINDOW",
                {
                    "timestamp": fields["timestamp"],
                    "now": now,
                    "skew_steps": self.skew_steps,
                },
            )

        if fields["port"] not in client_record["ports"]:
            raise SpaError(
                "SPA_PORT_DENIED",
                {"client": fields["client"], "port": fields["port"]},
            )

        payload = "|".join((
            fields["client"],
            str(fields["port"]),
            str(fields["timestamp"]),
            fields["nonce"],
        )).encode("utf-8")
        expected_mac = hmac.new(
            key_record["key"], payload, hashlib.sha256
        ).hexdigest()
        try:
            mac_matches = hmac.compare_digest(
                expected_mac, fields["mac"].lower()
            )
        except TypeError:
            mac_matches = False
        if not mac_matches:
            self._register_bad_mac_locked(prefix, now, fields["client"])
            raise SpaError("SPA_BAD_MAC", {"client": fields["client"]})

        self._check_nonce_locked(fields, now, for_grant)
        return fields

    def verify(self, packet: dict, now: int | None = None) -> SpaVerdict:
        with self._lock:
            current_now = self._resolve_now(now)
            self._stats["verifications"] += 1
            try:
                fields = self._authenticate_locked(packet, current_now)
            except SpaError:
                self._stats["rejected"] += 1
                raise

            self._stats["accepted"] += 1
            return SpaVerdict(
                status="accepted",
                client=fields["client"],
                port=fields["port"],
                nonce=fields["nonce"],
                generation=fields["generation"],
                source=fields["source"],
            )

    def _ticket_dto(self, record: dict) -> Ticket:
        return Ticket(
            ticket_id=record["ticket_id"],
            client=record["client"],
            port=record["port"],
            source=record["source"],
            nonce=record["nonce"],
            generation=record["generation"],
            issued_at=record["issued_at"],
            expires_at=record["expires_at"],
            state=record["state"],
        )

    def grant(self, packet: dict, ttl: int = 120,
              now: int | None = None) -> Ticket:
        with self._lock:
            current_now = self._resolve_now(now)
            if not _is_integer(ttl):
                raise _invalid_request({"field": "ttl"})

            self._stats["verifications"] += 1
            try:
                fields = self._authenticate_locked(
                    packet, current_now, for_grant=True
                )
                key_record = self._keys[fields["generation"]]
                if key_record.get("state") != "active":
                    raise SpaError(
                        "SPA_KEY_READONLY",
                        {"generation": fields["generation"]},
                    )
                if len(self._tickets) >= self.max_tickets:
                    raise SpaError(
                        "SPA_CAPACITY_EXCEEDED",
                        {"resource": "tickets", "limit": self.max_tickets},
                    )
            except SpaError:
                self._stats["rejected"] += 1
                raise

            self._stats["accepted"] += 1
            ticket_number = int(self._stats["tickets_issued"]) + 1
            ticket_id = f"tk-{ticket_number}"
            ticket = {
                "ticket_id": ticket_id,
                "client": fields["client"],
                "port": fields["port"],
                "source": fields["source"],
                "nonce": fields["nonce"],
                "generation": fields["generation"],
                "issued_at": current_now,
                "expires_at": current_now + int(ttl),
                "ttl": int(ttl),
                "state": "active",
                "revoked_at": None,
                "expired_at": None,
                "rebound_at": None,
                "source_history": [{
                    "source": fields["source"],
                    "at": current_now,
                }],
            }
            self._tickets[ticket_id] = ticket
            nonce_record = self._nonces.get(fields["nonce"])
            if nonce_record is not None:
                nonce_record["ticket_id"] = ticket_id
            self._stats["tickets_issued"] = ticket_number
            return self._ticket_dto(ticket)

    def _expire_ticket_locked(self, record: dict, now: int) -> bool:
        if record.get("state") != "active":
            return False
        expires_at = record.get("expires_at")
        if not _is_integer(expires_at) or now < int(expires_at):
            return False
        record["state"] = "expired"
        record["expired_at"] = now
        self._stats["tickets_expired"] += 1
        return True

    def _expire_tickets_locked(self, now: int,
                               client: str | None = None) -> None:
        for record in self._tickets.values():
            if client is not None and record.get("client") != client:
                continue
            self._expire_ticket_locked(record, now)

    def revoke(self, ticket_id: str, now: int | None = None) -> int:
        with self._lock:
            current_now = self._resolve_now(now)
            if not isinstance(ticket_id, str) or not ticket_id:
                raise SpaError(
                    "SPA_UNKNOWN_TICKET",
                    {"ticket_id": ticket_id},
                )
            record = self._tickets.get(ticket_id)
            if record is None:
                raise SpaError(
                    "SPA_UNKNOWN_TICKET",
                    {"ticket_id": ticket_id},
                )
            if self._expire_ticket_locked(record, current_now):
                return 0
            if record.get("state") != "active":
                return 0

            record["state"] = "revoked"
            record["revoked_at"] = current_now
            self._stats["tickets_revoked"] += 1
            return 1

    def rebind(self, client: str, source: str, ticket_id: str,
               now: int | None = None) -> Ticket:
        with self._lock:
            current_now = self._resolve_now(now)
            if not isinstance(client, str) or not client:
                raise _invalid_request({"field": "client"})
            if not isinstance(source, str) or not source:
                raise _invalid_request({"field": "source"})
            if not isinstance(ticket_id, str) or not ticket_id:
                raise SpaError(
                    "SPA_UNKNOWN_TICKET",
                    {"ticket_id": ticket_id},
                )
            client_record = self._clients.get(client)
            if client_record is None:
                raise SpaError("SPA_UNKNOWN_CLIENT", {"client": client})

            record = self._tickets.get(ticket_id)
            if record is None or record.get("client") != client:
                raise SpaError(
                    "SPA_UNKNOWN_TICKET",
                    {"ticket_id": ticket_id, "client": client},
                )

            self._expire_ticket_locked(record, current_now)
            if record.get("state") == "expired":
                raise SpaError(
                    "SPA_TICKET_EXPIRED",
                    {"ticket_id": ticket_id},
                )
            if record.get("state") == "revoked":
                raise SpaError(
                    "SPA_TICKET_REVOKED",
                    {"ticket_id": ticket_id},
                )
            if record["port"] not in client_record["ports"]:
                raise SpaError(
                    "SPA_PORT_DENIED",
                    {"client": client, "port": record["port"]},
                )
            if current_now < int(record["issued_at"]):
                raise SpaError(
                    "SPA_TIME_WINDOW",
                    {"ticket_id": ticket_id, "now": current_now},
                )
            if current_now >= int(record["expires_at"]):
                self._expire_ticket_locked(record, current_now)
                raise SpaError(
                    "SPA_TICKET_EXPIRED",
                    {"ticket_id": ticket_id},
                )

            if record.get("source") != source:
                record["source"] = source
                record["rebound_at"] = current_now
                history = record.setdefault("source_history", [])
                history.append({"source": source, "at": current_now})
            return self._ticket_dto(record)

    def status(self, client: str, now: int | None = None) -> dict:
        with self._lock:
            current_now = self._resolve_now(now)
            if not isinstance(client, str) or not client:
                raise SpaError("SPA_UNKNOWN_CLIENT", {"client": client})
            client_record = self._clients.get(client)
            if client_record is None:
                raise SpaError("SPA_UNKNOWN_CLIENT", {"client": client})

            self._expire_tickets_locked(current_now, client)
            client_tickets = [
                record for record in self._tickets.values()
                if record.get("client") == client
            ]
            active_ports = tuple(sorted({
                int(record["port"])
                for record in client_tickets
                if record.get("state") == "active"
            }))
            return {
                "active_ports": active_ports,
                "tickets": len(client_tickets),
                "failures": int(client_record.get("failures", 0)),
            }

    def tickets(self, client: str | None = None,
                now: int | None = None) -> tuple[Ticket, ...]:
        with self._lock:
            current_now = self._resolve_now(now)
            self._expire_tickets_locked(current_now, client)
            records = [
                record for record in self._tickets.values()
                if client is None or record.get("client") == client
            ]
            return tuple(self._ticket_dto(record) for record in records)

    def stats(self) -> dict:
        with self._lock:
            return {key: int(self._stats[key]) for key in _STATS_KEYS}

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "clients": copy.deepcopy(self._clients),
                "keys": copy.deepcopy(self._keys),
                "tickets": copy.deepcopy(self._tickets),
                "nonces": copy.deepcopy(self._nonces),
                "failures": copy.deepcopy(self._failures),
                "counters": copy.deepcopy(self._stats),
            }

    def _parse_snapshot_locked(self, state: dict) -> dict:
        if set(state) != _SNAPSHOT_KEYS:
            raise SpaError("SPA_SNAPSHOT_INVALID", {"reason": "top-level"})
        if state.get("version") != 1 or isinstance(state.get("version"), bool):
            raise SpaError("SPA_SNAPSHOT_INVALID", {"reason": "version"})

        for section in (
            "clients", "keys", "tickets", "nonces", "failures", "counters"
        ):
            if not isinstance(state[section], dict):
                raise SpaError(
                    "SPA_SNAPSHOT_INVALID",
                    {"section": section},
                )

        counters = state["counters"]
        parsed_stats: dict[str, int] = {}
        for key in _STATS_KEYS:
            value = counters.get(key)
            if not _is_integer(value) or int(value) < 0:
                raise SpaError(
                    "SPA_SNAPSHOT_INVALID",
                    {"section": "counters", "key": key},
                )
            parsed_stats[key] = int(value)

        keys: dict[int, dict] = {}
        for raw_generation, record in state["keys"].items():
            generation = _generation_key(raw_generation)
            if generation is None or generation in keys:
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "keys"})
            if not isinstance(record, dict):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "keys"})
            key_material = record.get("key")
            if isinstance(key_material, bytearray):
                key_material = bytes(key_material)
            if not isinstance(key_material, bytes):
                raise SpaError(
                    "SPA_SNAPSHOT_INVALID",
                    {"section": "keys", "generation": generation},
                )
            created_at = record.get("created_at")
            key_state = record.get("state")
            if not _is_integer(created_at):
                raise SpaError(
                    "SPA_SNAPSHOT_INVALID",
                    {"section": "keys", "generation": generation},
                )
            if key_state not in {"active", "readonly"}:
                raise SpaError(
                    "SPA_SNAPSHOT_INVALID",
                    {"section": "keys", "generation": generation},
                )
            keys[generation] = {
                "key": key_material,
                "created_at": int(created_at),
                "state": key_state,
            }

        clients: dict[str, dict] = {}
        for client, record in state["clients"].items():
            if not isinstance(client, str) or not client:
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "clients"})
            if not isinstance(record, dict):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "clients"})
            generation = record.get("generation")
            enrolled_at = record.get("enrolled_at")
            failures = record.get("failures", 0)
            if (not _is_integer(generation)
                    or int(generation) not in keys
                    or not _is_integer(enrolled_at)
                    or not _is_integer(failures)
                    or int(failures) < 0):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "clients"})
            ports = _normalize_ports(record.get("ports"))
            clients[client] = {
                "ports": ports,
                "generation": int(generation),
                "enrolled_at": int(enrolled_at),
                "failures": int(failures),
            }

        tickets: dict[str, dict] = {}
        for ticket_id, record in state["tickets"].items():
            if not isinstance(ticket_id, str) or not ticket_id:
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "tickets"})
            if not isinstance(record, dict):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "tickets"})
            required = (
                "ticket_id", "client", "port", "source", "nonce",
                "generation", "issued_at", "expires_at", "state",
            )
            if any(key not in record for key in required):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "tickets"})
            if record["ticket_id"] != ticket_id:
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "tickets"})
            if record["client"] not in clients:
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "tickets"})
            if not _is_integer(record["port"]):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "tickets"})
            if int(record["port"]) not in clients[record["client"]]["ports"]:
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "tickets"})
            if not isinstance(record["source"], str) or not record["source"]:
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "tickets"})
            if not isinstance(record["nonce"], str) or not record["nonce"]:
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "tickets"})
            if (not _is_integer(record["generation"])
                    or int(record["generation"]) not in keys):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "tickets"})
            if (not _is_integer(record["issued_at"])
                    or not _is_integer(record["expires_at"])):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "tickets"})
            if record["state"] not in {"active", "expired", "revoked"}:
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "tickets"})

            ticket = copy.deepcopy(record)
            ticket["port"] = int(ticket["port"])
            ticket["generation"] = int(ticket["generation"])
            ticket["issued_at"] = int(ticket["issued_at"])
            ticket["expires_at"] = int(ticket["expires_at"])
            tickets[ticket_id] = ticket

        nonces: dict[str, dict] = {}
        for nonce, record in state["nonces"].items():
            if not isinstance(nonce, str) or not nonce:
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "nonces"})
            if not isinstance(record, dict):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "nonces"})
            if not _is_integer(record.get("first_seen")):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "nonces"})
            if not _is_integer(record.get("last_seen")):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "nonces"})
            expires_at = record.get("expires_at")
            if expires_at is not None and not _is_integer(expires_at):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "nonces"})
            ticket_id = record.get("ticket_id")
            if ticket_id is not None and ticket_id not in tickets:
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "nonces"})
            nonces[nonce] = copy.deepcopy(record)

        for ticket_id, ticket in tickets.items():
            nonce = ticket["nonce"]
            nonce_record = nonces.get(nonce)
            if nonce_record is None:
                raise SpaError(
                    "SPA_SNAPSHOT_INVALID",
                    {"section": "nonces", "ticket_id": ticket_id},
                )
            if nonce_record.get("ticket_id") != ticket_id:
                raise SpaError(
                    "SPA_SNAPSHOT_INVALID",
                    {"section": "nonces", "ticket_id": ticket_id},
                )

        failures: dict[str, dict] = {}
        for prefix, record in state["failures"].items():
            if not isinstance(prefix, str) or not prefix:
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "failures"})
            if _is_integer(record) and int(record) >= 0:
                failures[prefix] = {
                    "count": int(record),
                    "first_failure_at": None,
                    "last_failure_at": None,
                    "blocked_until": 0,
                    "cooldown_hits": 0,
                }
                continue
            if not isinstance(record, dict):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "failures"})
            count = record.get("count")
            if not _is_integer(count) or int(count) < 0:
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "failures"})
            blocked_until = record.get("blocked_until", 0)
            if not _is_integer(blocked_until):
                raise SpaError("SPA_SNAPSHOT_INVALID", {"section": "failures"})
            failures[prefix] = copy.deepcopy(record)

        return {
            "clients": clients,
            "keys": keys,
            "tickets": tickets,
            "nonces": nonces,
            "failures": failures,
            "counters": parsed_stats,
        }

    def _latest_snapshot_time_locked(self) -> int | None:
        timestamps: list[int] = []
        for client in self._clients.values():
            if _is_integer(client.get("enrolled_at")):
                timestamps.append(int(client["enrolled_at"]))
        for key in self._keys.values():
            if _is_integer(key.get("created_at")):
                timestamps.append(int(key["created_at"]))
        for ticket in self._tickets.values():
            for field in ("issued_at", "revoked_at", "expired_at", "rebound_at"):
                if _is_integer(ticket.get(field)):
                    timestamps.append(int(ticket[field]))
            for event in ticket.get("source_history", []):
                if isinstance(event, dict) and _is_integer(event.get("at")):
                    timestamps.append(int(event["at"]))
        for nonce in self._nonces.values():
            for field in ("first_seen", "last_seen"):
                timestamps.append(int(nonce[field]))
        for failure in self._failures.values():
            for field in ("first_failure_at", "last_failure_at"):
                if _is_integer(failure.get(field)):
                    timestamps.append(int(failure[field]))
        return max(timestamps) if timestamps else None

    def restore(self, state: dict) -> None:
        if not isinstance(state, dict):
            raise SpaError("SPA_SNAPSHOT_INVALID", {"reason": "snapshot"})
        with self._lock:
            try:
                detached = copy.deepcopy(state)
                parsed = self._parse_snapshot_locked(detached)
            except SpaError as exc:
                if exc.code == "SPA_SNAPSHOT_INVALID":
                    raise
                raise SpaError(
                    "SPA_SNAPSHOT_INVALID",
                    {"cause": exc.code, "detail": exc.detail},
                ) from exc
            except Exception as exc:
                raise SpaError(
                    "SPA_SNAPSHOT_INVALID",
                    {"reason": "unparseable"},
                ) from exc

            self._clients = parsed["clients"]
            self._keys = parsed["keys"]
            self._tickets = parsed["tickets"]
            self._nonces = parsed["nonces"]
            self._failures = parsed["failures"]
            self._stats = parsed["counters"]
            self._last_now = self._latest_snapshot_time_locked()

            max_ticket_number = 0
            for ticket_id in self._tickets:
                if ticket_id.startswith("tk-"):
                    suffix = ticket_id[3:]
                    if suffix.isdigit():
                        max_ticket_number = max(
                            max_ticket_number, int(suffix)
                        )
            issued = int(self._stats.get("tickets_issued", 0))
            if issued < max_ticket_number:
                self._stats["tickets_issued"] = max_ticket_number


__all__ = [
    "SpaError",
    "SpaGateGuard",
    "Enrollment",
    "KeyRecord",
    "SpaVerdict",
    "Ticket",
]
