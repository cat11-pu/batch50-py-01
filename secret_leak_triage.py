"""Secret leak triage: fingerprint normalization, verification cache, revocation closure."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


class LeakError(ValueError):
    """Raised when a triage operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATE_PENDING = "pending_verification"
STATE_VALID = "valid"
STATE_INVALID = "invalid"
STATE_DISPOSED = "disposed"

TICKET_OPEN = "open"
TICKET_CLOSED = "closed"

VERDICTS = ("valid", "invalid", "error")
RECORD_STATES = (STATE_PENDING, STATE_VALID, STATE_INVALID, STATE_DISPOSED)
TICKET_STATES = (TICKET_OPEN, TICKET_CLOSED)

SNAPSHOT_VERSION = 1
STATS_KEYS = (
    "ingested",
    "occurrences",
    "verified_valid",
    "verified_invalid",
    "disposed",
    "revocations",
)


@dataclass(frozen=True)
class LeakRecord:
    fingerprint: str
    state: str
    first_seen_at: str
    last_seen_at: str
    occurrences: int
    locations: tuple
    verdict: str | None
    verified_at: str | None
    verify_expires_at: str | None
    disposed_at: str | None


@dataclass(frozen=True)
class RevocationTicket:
    ticket_id: str
    fingerprint: str
    provider: str
    owner: str
    state: str
    opened_at: str
    closed_at: str | None
    resolution: str | None


def _parse_time(value: object, error_code: str = "LEAK_BAD_REQUEST") -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise LeakError(error_code, {"now": value})
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError) as exc:
        raise LeakError(error_code, {"now": value}) from exc
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _require_text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise LeakError("LEAK_BAD_REQUEST", {field: value})
    return value


def _new_record(fingerprint: str, now: str, occurrence: tuple) -> dict:
    return {
        "fingerprint": fingerprint,
        "state": STATE_PENDING,
        "first_seen_at": now,
        "last_seen_at": now,
        "occurrences": 1,
        "locations": [occurrence],
        "verdict": None,
        "verified_at": None,
        "verify_expires_at": None,
        "disposed_at": None,
        "generation": 1,
        "previous": None,
    }


class SecretLeakTriage:
    """Normalize leaked-secret findings by fingerprint and drive revocation."""

    def __init__(self, *, verify_ttl_seconds: int = 3600) -> None:
        self.verify_ttl_seconds = verify_ttl_seconds
        self._lock = threading.RLock()
        self._records: dict[str, dict] = {}
        self._findings: dict[str, dict] = {}
        self._tickets: dict[str, dict] = {}
        self._stats = {key: 0 for key in STATS_KEYS}

    @staticmethod
    def _record_view(record: dict) -> LeakRecord:
        return LeakRecord(
            fingerprint=record["fingerprint"],
            state=record["state"],
            first_seen_at=record["first_seen_at"],
            last_seen_at=record["last_seen_at"],
            occurrences=record["occurrences"],
            locations=tuple(record["locations"]),
            verdict=record["verdict"],
            verified_at=record["verified_at"],
            verify_expires_at=record["verify_expires_at"],
            disposed_at=record["disposed_at"],
        )

    @staticmethod
    def _ticket_view(ticket: dict) -> RevocationTicket:
        return RevocationTicket(
            ticket_id=ticket["ticket_id"],
            fingerprint=ticket["fingerprint"],
            provider=ticket["provider"],
            owner=ticket["owner"],
            state=ticket["state"],
            opened_at=ticket["opened_at"],
            closed_at=ticket["closed_at"],
            resolution=ticket["resolution"],
        )

    def _expire_if_needed(self, record: dict, now: datetime) -> bool:
        """Invalidate an expired cached verdict in-place.

        Returns True when a formerly verified record was expired.
        """
        if record["state"] not in (STATE_VALID, STATE_INVALID):
            return False
        expires_at = record.get("verify_expires_at")
        if expires_at is None:
            return False
        if now < _parse_time(expires_at):
            return False
        record["state"] = STATE_PENDING
        record["verdict"] = None
        record["verified_at"] = None
        record["verify_expires_at"] = None
        return True

    def _require_record(self, fingerprint: str) -> dict:
        record = self._records.get(fingerprint)
        if record is None:
            raise LeakError("LEAK_UNKNOWN", {"fingerprint": fingerprint})
        return record

    def _new_ticket_id(self) -> str:
        highest = len(self._tickets)
        for ticket_id in self._tickets:
            if ticket_id.startswith("REV-"):
                try:
                    highest = max(highest, int(ticket_id[4:]))
                except ValueError:
                    pass
        highest = max(highest, int(self._stats.get("revocations", 0)))
        while True:
            highest += 1
            candidate = f"REV-{highest:08d}"
            if candidate not in self._tickets:
                return candidate

    def ingest(self, finding_id: str, *, repo: str, commit: str, path: str,
               fingerprint: str, now: str) -> dict:
        with self._lock:
            _require_text(finding_id, "finding_id")
            _require_text(repo, "repo")
            _require_text(commit, "commit")
            _require_text(path, "path")
            _require_text(fingerprint, "fingerprint")
            if finding_id in self._findings:
                raise LeakError("LEAK_DUPLICATE_FINDING",
                                {"finding_id": finding_id})

            now_dt = _parse_time(now)
            now_text = _format_time(now_dt)
            location = (repo, commit, path)
            existing = self._records.get(fingerprint)
            duplicate_location = existing is not None

            if existing is None:
                record = _new_record(fingerprint, now_text, location)
                self._records[fingerprint] = record
                generation = 1
            elif existing["state"] == STATE_DISPOSED:
                # A disposed record is historical.  Keep it intact and start a
                # fresh generation for the newly observed exposure.
                prior = copy.deepcopy(existing)
                record = _new_record(fingerprint, now_text, location)
                record["generation"] = int(prior.get("generation", 1)) + 1
                record["previous"] = prior
                self._records[fingerprint] = record
                generation = record["generation"]
            else:
                self._expire_if_needed(existing, now_dt)
                record = existing
                generation = int(record.get("generation", 1))
                record["occurrences"] += 1
                if location not in record["locations"]:
                    record["locations"].append(location)
                    record["locations"].sort()
                if now_text < record["first_seen_at"]:
                    record["first_seen_at"] = now_text
                if now_text > record["last_seen_at"]:
                    record["last_seen_at"] = now_text

            self._findings[finding_id] = {
                "finding_id": finding_id,
                "fingerprint": fingerprint,
                "repo": repo,
                "commit": commit,
                "path": path,
                "seen_at": now_text,
                "generation": generation,
                "duplicate_location": duplicate_location,
                "previous_generation": (
                    int(record["previous"].get("generation", 1))
                    if record.get("previous") else None
                ),
            }
            self._stats["ingested"] += 1
            self._stats["occurrences"] += 1

            return {
                "finding_id": finding_id,
                "fingerprint": fingerprint,
                "master_state": record["state"],
                "duplicate_location": duplicate_location,
                "occurrences": record["occurrences"],
            }

    def verify_result(self, fingerprint: str, *, verdict: str,
                      now: str) -> LeakRecord:
        with self._lock:
            if verdict not in VERDICTS:
                raise LeakError("LEAK_BAD_VERDICT", {"verdict": verdict})
            record = self._require_record(fingerprint)
            now_dt = _parse_time(now)
            if record["state"] == STATE_DISPOSED:
                raise LeakError("LEAK_NOT_REVOCABLE",
                                {"fingerprint": fingerprint,
                                 "state": record["state"]})

            self._expire_if_needed(record, now_dt)
            now_text = _format_time(now_dt)
            expires = now_dt + timedelta(seconds=self.verify_ttl_seconds)
            record["verified_at"] = now_text
            record["verify_expires_at"] = _format_time(expires)
            record["verdict"] = verdict

            if verdict == STATE_VALID:
                record["state"] = STATE_VALID
                self._stats["verified_valid"] += 1
            elif verdict == STATE_INVALID:
                record["state"] = STATE_INVALID
                self._stats["verified_invalid"] += 1
            else:
                record["state"] = STATE_PENDING

            return self._record_view(record)

    def dedupe(self, fingerprint: str) -> tuple:
        with self._lock:
            record = self._records.get(fingerprint)
            if record is None:
                return ()
            return tuple(sorted(set(record["locations"])))

    def open_revocation(self, fingerprint: str, *, provider: str, owner: str,
                        now: str) -> RevocationTicket:
        with self._lock:
            record = self._require_record(fingerprint)
            now_dt = _parse_time(now)
            self._expire_if_needed(record, now_dt)
            if record["state"] != STATE_VALID:
                raise LeakError("LEAK_NOT_REVOCABLE",
                                {"fingerprint": fingerprint,
                                 "state": record["state"]})
            if any(ticket["fingerprint"] == fingerprint
                   and ticket["state"] == TICKET_OPEN
                   for ticket in self._tickets.values()):
                raise LeakError("LEAK_REVOCATION_EXISTS",
                                {"fingerprint": fingerprint})

            ticket_id = self._new_ticket_id()
            ticket = {
                "ticket_id": ticket_id,
                "fingerprint": fingerprint,
                "provider": provider,
                "owner": owner,
                "state": TICKET_OPEN,
                "opened_at": _format_time(now_dt),
                "closed_at": None,
                "resolution": None,
            }
            self._tickets[ticket_id] = ticket
            self._stats["revocations"] += 1
            return self._ticket_view(ticket)

    def close_revocation(self, ticket_id: str, *, resolution: str,
                         now: str) -> dict:
        with self._lock:
            ticket = self._tickets.get(ticket_id)
            if ticket is None:
                raise LeakError("LEAK_UNKNOWN", {"ticket_id": ticket_id})
            if ticket["state"] != TICKET_OPEN:
                raise LeakError("LEAK_NOT_REVOCABLE",
                                {"ticket_id": ticket_id,
                                 "state": ticket["state"]})

            now_dt = _parse_time(now)
            now_text = _format_time(now_dt)
            ticket["state"] = TICKET_CLOSED
            ticket["closed_at"] = now_text
            ticket["resolution"] = resolution

            record = self._records.get(ticket["fingerprint"])
            if record is not None:
                still_open = any(
                    other["fingerprint"] == ticket["fingerprint"]
                    and other["state"] == TICKET_OPEN
                    for other in self._tickets.values()
                )
                if not still_open and record["state"] == STATE_VALID:
                    record["state"] = STATE_DISPOSED
                    record["disposed_at"] = now_text
                    self._stats["disposed"] += 1
                record_state = record["state"]
            else:
                record_state = None

            return {
                "ticket_id": ticket_id,
                "state": ticket["state"],
                "fingerprint": ticket["fingerprint"],
                "record_state": record_state,
            }

    def close_finding(self, fingerprint: str, *, resolution: str,
                      now: str) -> LeakRecord:
        with self._lock:
            record = self._require_record(fingerprint)
            if any(ticket["fingerprint"] == fingerprint
                   and ticket["state"] == TICKET_OPEN
                   for ticket in self._tickets.values()):
                raise LeakError("LEAK_REVOCATION_OPEN",
                                {"fingerprint": fingerprint})
            now_dt = _parse_time(now)
            if record["state"] == STATE_DISPOSED:
                return self._record_view(record)

            self._expire_if_needed(record, now_dt)
            record["state"] = STATE_DISPOSED
            record["disposed_at"] = _format_time(now_dt)
            self._stats["disposed"] += 1
            return self._record_view(record)

    def status(self, fingerprint: str) -> dict:
        with self._lock:
            record = self._require_record(fingerprint)
            view = self._record_view(record)
            return {
                "fingerprint": view.fingerprint,
                "state": view.state,
                "first_seen_at": view.first_seen_at,
                "last_seen_at": view.last_seen_at,
                "occurrences": view.occurrences,
                "locations": view.locations,
                "verdict": view.verdict,
                "verified_at": view.verified_at,
                "verify_expires_at": view.verify_expires_at,
                "disposed_at": view.disposed_at,
            }

    def findings(self, *, state: str | None = None) -> list:
        with self._lock:
            records = [
                self._record_view(record)
                for record in self._records.values()
                if state is None or record["state"] == state
            ]
            return sorted(records, key=lambda record: record.fingerprint)

    def revocations(self, *, state: str | None = None) -> list:
        with self._lock:
            tickets = [
                self._ticket_view(ticket)
                for ticket in self._tickets.values()
                if state is None or ticket["state"] == state
            ]
            return sorted(tickets, key=lambda ticket: ticket.ticket_id)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "records": copy.deepcopy(self._records),
                "findings": copy.deepcopy(self._findings),
                "tickets": copy.deepcopy(self._tickets),
                "stats": copy.deepcopy(self._stats),
            }

    @staticmethod
    def _validate_time(value: object) -> str:
        return _format_time(_parse_time(value, "LEAK_SNAPSHOT_INVALID"))

    @classmethod
    def _validate_record(cls, key: object, raw: object,
                         seen: set[int]) -> dict:
        if not isinstance(key, str) or not key:
            raise LeakError("LEAK_SNAPSHOT_INVALID", {"record_key": key})
        if not isinstance(raw, dict):
            raise LeakError("LEAK_SNAPSHOT_INVALID", {"record": key})
        if id(raw) in seen:
            raise LeakError("LEAK_SNAPSHOT_INVALID", {"record": key})
        seen.add(id(raw))

        fingerprint = raw.get("fingerprint")
        if not isinstance(fingerprint, str) or fingerprint != key:
            raise LeakError("LEAK_SNAPSHOT_INVALID", {"record": key})
        state = raw.get("state")
        if state not in RECORD_STATES:
            raise LeakError("LEAK_SNAPSHOT_INVALID",
                            {"record": key, "state": state})
        occurrences = raw.get("occurrences")
        if (not isinstance(occurrences, int) or isinstance(occurrences, bool)
                or occurrences < 0):
            raise LeakError("LEAK_SNAPSHOT_INVALID",
                            {"record": key, "occurrences": occurrences})

        locations_raw = raw.get("locations")
        if not isinstance(locations_raw, (list, tuple)):
            raise LeakError("LEAK_SNAPSHOT_INVALID",
                            {"record": key, "locations": locations_raw})
        locations = []
        for location in locations_raw:
            if (not isinstance(location, (list, tuple))
                    or len(location) != 3
                    or not all(isinstance(part, str) and part.strip()
                               for part in location)):
                raise LeakError("LEAK_SNAPSHOT_INVALID",
                                {"record": key, "location": location})
            locations.append(tuple(location))
        if len(set(locations)) != len(locations):
            raise LeakError("LEAK_SNAPSHOT_INVALID",
                            {"record": key, "locations": "duplicate"})
        locations.sort()

        first_seen_at = cls._validate_time(raw.get("first_seen_at"))
        last_seen_at = cls._validate_time(raw.get("last_seen_at"))
        if first_seen_at > last_seen_at:
            raise LeakError("LEAK_SNAPSHOT_INVALID",
                            {"record": key, "times": "reversed"})

        verdict = raw.get("verdict")
        if verdict is not None and verdict not in VERDICTS:
            raise LeakError("LEAK_SNAPSHOT_INVALID",
                            {"record": key, "verdict": verdict})

        verified_at = raw.get("verified_at")
        verify_expires_at = raw.get("verify_expires_at")
        disposed_at = raw.get("disposed_at")
        verified_at = (cls._validate_time(verified_at)
                       if verified_at is not None else None)
        verify_expires_at = (cls._validate_time(verify_expires_at)
                             if verify_expires_at is not None else None)
        disposed_at = (cls._validate_time(disposed_at)
                       if disposed_at is not None else None)
        if state == STATE_DISPOSED:
            if disposed_at is None:
                raise LeakError("LEAK_SNAPSHOT_INVALID",
                                {"record": key, "disposed_at": None})
        elif disposed_at is not None:
            raise LeakError("LEAK_SNAPSHOT_INVALID",
                            {"record": key, "disposed_at": disposed_at})

        if state == STATE_VALID and verdict != STATE_VALID:
            raise LeakError("LEAK_SNAPSHOT_INVALID",
                            {"record": key, "verdict": verdict})
        if state == STATE_INVALID and verdict != STATE_INVALID:
            raise LeakError("LEAK_SNAPSHOT_INVALID",
                            {"record": key, "verdict": verdict})
        if state in (STATE_VALID, STATE_INVALID):
            if verified_at is None or verify_expires_at is None:
                raise LeakError("LEAK_SNAPSHOT_INVALID",
                                {"record": key, "verification": "incomplete"})

        generation = raw.get("generation", 1)
        if (not isinstance(generation, int) or isinstance(generation, bool)
                or generation < 1):
            raise LeakError("LEAK_SNAPSHOT_INVALID",
                            {"record": key, "generation": generation})

        previous_raw = raw.get("previous")
        if previous_raw is not None:
            if not isinstance(previous_raw, dict):
                raise LeakError("LEAK_SNAPSHOT_INVALID",
                                {"record": key, "previous": previous_raw})
            previous = cls._validate_record(key, previous_raw, seen)
        else:
            previous = None

        record = {
            "fingerprint": fingerprint,
            "state": state,
            "first_seen_at": first_seen_at,
            "last_seen_at": last_seen_at,
            "occurrences": occurrences,
            "locations": locations,
            "verdict": verdict,
            "verified_at": verified_at,
            "verify_expires_at": verify_expires_at,
            "disposed_at": disposed_at,
            "generation": generation,
            "previous": previous,
        }
        seen.discard(id(raw))
        return record

    @staticmethod
    def _validate_finding(key: object, raw: object) -> dict:
        if not isinstance(key, str) or not key:
            raise LeakError("LEAK_SNAPSHOT_INVALID", {"finding_key": key})
        if isinstance(raw, str):
            if not raw:
                raise LeakError("LEAK_SNAPSHOT_INVALID", {"finding": key})
            return {
                "finding_id": key,
                "fingerprint": raw,
                "repo": None,
                "commit": None,
                "path": None,
                "seen_at": None,
                "generation": None,
                "duplicate_location": None,
                "previous_generation": None,
            }
        if not isinstance(raw, dict):
            raise LeakError("LEAK_SNAPSHOT_INVALID", {"finding": key})
        finding_id = raw.get("finding_id", key)
        fingerprint = raw.get("fingerprint")
        if finding_id != key or not isinstance(fingerprint, str) or not fingerprint:
            raise LeakError("LEAK_SNAPSHOT_INVALID", {"finding": key})
        event = {
            "finding_id": finding_id,
            "fingerprint": fingerprint,
            "repo": raw.get("repo"),
            "commit": raw.get("commit"),
            "path": raw.get("path"),
            "seen_at": raw.get("seen_at"),
            "generation": raw.get("generation"),
            "duplicate_location": raw.get("duplicate_location"),
            "previous_generation": raw.get("previous_generation"),
        }
        if event["seen_at"] is not None:
            event["seen_at"] = SecretLeakTriage._validate_time(event["seen_at"])
        return event

    @classmethod
    def _validate_ticket(cls, key: object, raw: object,
                         records: dict[str, dict]) -> dict:
        if not isinstance(key, str) or not key:
            raise LeakError("LEAK_SNAPSHOT_INVALID", {"ticket_key": key})
        if not isinstance(raw, dict):
            raise LeakError("LEAK_SNAPSHOT_INVALID", {"ticket": key})
        ticket_id = raw.get("ticket_id")
        fingerprint = raw.get("fingerprint")
        provider = raw.get("provider")
        owner = raw.get("owner")
        state = raw.get("state")
        if ticket_id != key or fingerprint not in records:
            raise LeakError("LEAK_SNAPSHOT_INVALID", {"ticket": key})
        if (not isinstance(provider, str) or not isinstance(owner, str)
                or state not in TICKET_STATES):
            raise LeakError("LEAK_SNAPSHOT_INVALID", {"ticket": key})

        opened_at = cls._validate_time(raw.get("opened_at"))
        closed_at = raw.get("closed_at")
        resolution = raw.get("resolution")
        if closed_at is not None:
            closed_at = cls._validate_time(closed_at)
        if state == TICKET_CLOSED and closed_at is None:
            raise LeakError("LEAK_SNAPSHOT_INVALID",
                            {"ticket": key, "closed_at": None})
        if state == TICKET_OPEN and closed_at is not None:
            raise LeakError("LEAK_SNAPSHOT_INVALID",
                            {"ticket": key, "closed_at": closed_at})
        if state == TICKET_CLOSED and not isinstance(resolution, str):
            raise LeakError("LEAK_SNAPSHOT_INVALID",
                            {"ticket": key, "resolution": resolution})
        return {
            "ticket_id": ticket_id,
            "fingerprint": fingerprint,
            "provider": provider,
            "owner": owner,
            "state": state,
            "opened_at": opened_at,
            "closed_at": closed_at,
            "resolution": resolution,
        }

    @staticmethod
    def _validate_stats(raw: object) -> dict:
        if not isinstance(raw, dict) or set(raw) != set(STATS_KEYS):
            raise LeakError("LEAK_SNAPSHOT_INVALID", {"stats": raw})
        stats = {}
        for key in STATS_KEYS:
            value = raw[key]
            if (not isinstance(value, int) or isinstance(value, bool)
                    or value < 0):
                raise LeakError("LEAK_SNAPSHOT_INVALID",
                                {"stats": key, "value": value})
            stats[key] = value
        return stats

    @staticmethod
    def _chain_contains(record: object, target: dict) -> bool:
        while isinstance(record, dict):
            if (record.get("fingerprint") == target.get("fingerprint")
                    and record.get("disposed_at") == target.get("disposed_at")
                    and record.get("state") == target.get("state")):
                return True
            record = record.get("previous")
        return False

    def restore(self, state: dict) -> None:
        try:
            if not isinstance(state, dict):
                raise LeakError("LEAK_SNAPSHOT_INVALID", {"snapshot": state})
            if set(state) != {"version", "records", "findings",
                              "tickets", "stats"}:
                raise LeakError("LEAK_SNAPSHOT_INVALID",
                                {"keys": sorted(state)})
            if (not isinstance(state["version"], int)
                    or isinstance(state["version"], bool)
                    or state["version"] != SNAPSHOT_VERSION):
                raise LeakError("LEAK_SNAPSHOT_INVALID",
                                {"version": state["version"]})

            records_raw = state["records"]
            findings_raw = state["findings"]
            tickets_raw = state["tickets"]
            if not isinstance(records_raw, dict):
                raise LeakError("LEAK_SNAPSHOT_INVALID", {"records": "type"})
            if not isinstance(findings_raw, dict):
                raise LeakError("LEAK_SNAPSHOT_INVALID", {"findings": "type"})
            if not isinstance(tickets_raw, dict):
                raise LeakError("LEAK_SNAPSHOT_INVALID", {"tickets": "type"})

            seen: set[int] = set()
            records = {}
            for key, raw in records_raw.items():
                record = self._validate_record(key, raw, seen)
                records[key] = record

            findings = {}
            for key, raw in findings_raw.items():
                event = self._validate_finding(key, raw)
                if event["fingerprint"] not in records:
                    raise LeakError("LEAK_SNAPSHOT_INVALID",
                                    {"finding": key, "fingerprint": "unknown"})
                findings[key] = event

            tickets = {}
            for key, raw in tickets_raw.items():
                ticket = self._validate_ticket(key, raw, records)
                tickets[key] = ticket

            stats = self._validate_stats(state["stats"])
        except LeakError:
            raise
        except Exception as exc:
            raise LeakError("LEAK_SNAPSHOT_INVALID", str(exc)) from exc

        with self._lock:
            # Restoring must never regress a disposal or reopen a closed
            # ticket.  Those are terminal states in the live instance.
            kept_disposed = False
            for fingerprint, old_record in self._records.items():
                if old_record["state"] != STATE_DISPOSED:
                    continue
                incoming = records.get(fingerprint)
                incoming_new_generation = (
                    incoming is not None
                    and int(incoming.get("generation", 1))
                    > int(old_record.get("generation", 1))
                    and self._chain_contains(incoming.get("previous"),
                                             old_record)
                )
                incoming_is_newer_disposal = (
                    incoming is not None
                    and incoming["state"] == STATE_DISPOSED
                    and int(incoming.get("generation", 1))
                    > int(old_record.get("generation", 1))
                    and self._chain_contains(incoming.get("previous"),
                                             old_record)
                )
                if incoming is None or (
                        not incoming_new_generation
                        and not incoming_is_newer_disposal):
                    records[fingerprint] = copy.deepcopy(old_record)
                    kept_disposed = True

            kept_closed = False
            for ticket_id, old_ticket in self._tickets.items():
                if old_ticket["state"] != TICKET_CLOSED:
                    continue
                fingerprint = old_ticket["fingerprint"]
                if fingerprint not in records and fingerprint in self._records:
                    records[fingerprint] = copy.deepcopy(
                        self._records[fingerprint]
                    )
                tickets[ticket_id] = copy.deepcopy(old_ticket)
                kept_closed = True

            if kept_disposed:
                stats["disposed"] = max(stats["disposed"],
                                        self._stats["disposed"])
            if kept_closed:
                stats["revocations"] = max(stats["revocations"],
                                           self._stats["revocations"])

            # Findings for records that were not restored are not useful.
            findings = {
                key: event for key, event in findings.items()
                if event["fingerprint"] in records
            }
            tickets = {
                key: ticket for key, ticket in tickets.items()
                if ticket["fingerprint"] in records
            }

            self._records = records
            self._findings = findings
            self._tickets = tickets
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)
