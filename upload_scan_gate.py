"""Upload scanning gate with digest verdict cache, timeout quarantine and manual release."""

from __future__ import annotations

import copy
import hashlib
import threading


class ScanGateError(ValueError):
    """Raised when a gate operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


DECISION_ALLOW = "allow"
DECISION_DENY = "deny"
DECISION_PENDING = "pending"

STATE_QUEUED = "queued"
STATE_SCANNING = "scanning"
STATE_DECIDED = "decided"
STATE_QUARANTINED = "quarantined"
STATE_RELEASED = "released"

SCAN_OUTCOMES = ("benign", "malicious")

SOURCE_QUEUE = "queue"
SOURCE_SCAN = "scan"
SOURCE_CACHE = "cache"
SOURCE_QUARANTINE = "quarantine"
SOURCE_MANUAL_RELEASE = "manual_release"

REASON_MALICIOUS = "malicious_content"
REASON_TIMEOUT = "scan_timeout"
REASON_MANUAL_RELEASE = "manual_release"

SNAPSHOT_FORMAT = "upload-scan-gate-v1"

COUNTER_KEYS = (
    "submitted",
    "queued",
    "scanned",
    "cache_hits",
    "timed_out",
    "released",
)

_TICKET_KEYS = {
    "upload_id",
    "digest",
    "state",
    "decision",
    "reason",
    "source",
}

_JOB_KEYS = {
    "digest",
    "upload_ids",
    "state",
    "started_at",
    "outcome",
    "reason",
    "source",
    "decision",
    "actor",
}

_CACHE_KEYS = {"decision", "created_at", "expires_at"}


class UploadScanGate:
    """Serialize uploads by content digest, scan each digest once and cache clean verdicts."""

    def __init__(self, *, cache_ttl: int = 300, scan_timeout: int = 60,
                 max_queue: int = 8, max_bytes: int = 1048576) -> None:
        self.cache_ttl = cache_ttl
        self.scan_timeout = scan_timeout
        self.max_queue = max_queue
        self.max_bytes = max_bytes
        self._lock = threading.RLock()
        self._tickets = {}
        self._jobs = {}
        self._queue = []
        self._cache = {}
        self._counters = {key: 0 for key in COUNTER_KEYS}

    @staticmethod
    def _invalid(detail: object) -> None:
        raise ScanGateError("SCAN_INVALID_REQUEST", detail)

    @staticmethod
    def _unknown_digest(digest: object) -> None:
        raise ScanGateError("SCAN_UNKNOWN_DIGEST", digest)

    @staticmethod
    def _ticket_view(ticket: dict) -> dict:
        return {
            "upload_id": ticket["upload_id"],
            "digest": ticket["digest"],
            "state": ticket["state"],
            "decision": ticket["decision"],
            "reason": ticket["reason"],
            "source": ticket["source"],
        }

    def _validate_submit(self, upload_id: object, data: object) -> None:
        if (not isinstance(upload_id, str) or not upload_id.strip()
                or upload_id in self._tickets):
            self._invalid("invalid or duplicate upload_id")
        if not isinstance(data, (bytes, bytearray)) or not data:
            self._invalid("data must be non-empty bytes or bytearray")
        if len(data) > self.max_bytes:
            self._invalid("data exceeds max_bytes")

    def _new_job(self, digest: str, upload_id: str) -> dict:
        return {
            "digest": digest,
            "upload_ids": [upload_id],
            "state": STATE_QUEUED,
            "started_at": None,
            "outcome": None,
            "reason": None,
            "source": SOURCE_QUEUE,
            "decision": DECISION_PENDING,
            "actor": None,
        }

    def _new_ticket(self, upload_id: str, digest: str) -> dict:
        return {
            "upload_id": upload_id,
            "digest": digest,
            "state": STATE_QUEUED,
            "decision": DECISION_PENDING,
            "reason": None,
            "source": SOURCE_QUEUE,
        }

    def _set_tickets(self, job: dict, *, state: str, decision: str,
                     reason: str | None, source: str) -> None:
        for upload_id in job["upload_ids"]:
            ticket = self._tickets[upload_id]
            ticket["state"] = state
            ticket["decision"] = decision
            ticket["reason"] = reason
            ticket["source"] = source

    def submit(self, upload_id: str, data, *, now: int) -> dict:
        with self._lock:
            self._validate_submit(upload_id, data)
            digest = hashlib.sha256(bytes(data)).hexdigest()
            cache_entry = self._cache.get(digest)
            if cache_entry is not None and cache_entry["expires_at"] > now:
                ticket = {
                    "upload_id": upload_id,
                    "digest": digest,
                    "state": STATE_DECIDED,
                    "decision": DECISION_ALLOW,
                    "reason": None,
                    "source": SOURCE_CACHE,
                }
                self._tickets[upload_id] = ticket
                self._counters["submitted"] += 1
                self._counters["cache_hits"] += 1
                return {
                    "upload_id": upload_id,
                    "digest": digest,
                    "state": STATE_DECIDED,
                }

            job = self._jobs.get(digest)
            if job is not None and job["state"] in (
                    STATE_QUEUED, STATE_SCANNING, STATE_QUARANTINED,
                    STATE_RELEASED):
                job["upload_ids"].append(upload_id)
                ticket = {
                    "upload_id": upload_id,
                    "digest": digest,
                    "state": job["state"],
                    "decision": job["decision"],
                    "reason": job["reason"],
                    "source": job["source"],
                }
                self._tickets[upload_id] = ticket
                self._counters["submitted"] += 1
                return {
                    "upload_id": upload_id,
                    "digest": digest,
                    "state": job["state"],
                }

            if len(self._queue) >= self.max_queue:
                raise ScanGateError("SCAN_QUEUE_FULL", "queue capacity reached")

            job = self._new_job(digest, upload_id)
            self._jobs[digest] = job
            self._tickets[upload_id] = self._new_ticket(upload_id, digest)
            self._queue.append(digest)
            self._counters["submitted"] += 1
            self._counters["queued"] += 1
            return {
                "upload_id": upload_id,
                "digest": digest,
                "state": STATE_QUEUED,
            }

    def claim(self, *, now: int) -> dict | None:
        with self._lock:
            if not self._queue:
                return None
            digest = self._queue.pop(0)
            job = self._jobs[digest]
            job["state"] = STATE_SCANNING
            job["started_at"] = now
            job["source"] = SOURCE_SCAN
            self._set_tickets(
                job,
                state=STATE_SCANNING,
                decision=DECISION_PENDING,
                reason=None,
                source=SOURCE_SCAN,
            )
            return {
                "digest": digest,
                "upload_ids": list(job["upload_ids"]),
                "started_at": now,
            }

    def complete_scan(self, digest: str, *, outcome: str, now: int) -> dict:
        with self._lock:
            if outcome not in SCAN_OUTCOMES:
                self._invalid("outcome must be benign or malicious")
            job = self._jobs.get(digest)
            if job is None:
                self._unknown_digest(digest)
            if job["state"] != STATE_SCANNING:
                raise ScanGateError("SCAN_STATE_INVALID", "job is not scanning")

            if outcome == "benign":
                decision = DECISION_ALLOW
                reason = None
                cache_entry = {
                    "decision": DECISION_ALLOW,
                    "created_at": now,
                    "expires_at": now + self.cache_ttl,
                }
                self._cache[digest] = cache_entry
                cached = True
            else:
                decision = DECISION_DENY
                reason = REASON_MALICIOUS
                self._cache.pop(digest, None)
                cached = False

            job["state"] = STATE_DECIDED
            job["outcome"] = outcome
            job["decision"] = decision
            job["reason"] = reason
            job["source"] = SOURCE_SCAN
            job["actor"] = None
            self._set_tickets(
                job,
                state=STATE_DECIDED,
                decision=decision,
                reason=reason,
                source=SOURCE_SCAN,
            )
            self._counters["scanned"] += 1
            return {"digest": digest, "outcome": outcome, "cached": cached}

    def verdict(self, upload_id: str) -> dict:
        with self._lock:
            ticket = self._tickets.get(upload_id)
            if ticket is None:
                self._invalid("unknown upload_id")
            return self._ticket_view(ticket)

    def queue(self) -> tuple:
        with self._lock:
            return tuple(self._queue)

    def cache_lookup(self, digest: str, *, now: int) -> dict | None:
        with self._lock:
            entry = self._cache.get(digest)
            if entry is None or entry["expires_at"] <= now:
                return None
            return dict(entry)

    def _quarantine_job(self, job: dict, *, reason: str, source: str,
                        timed_out: bool) -> None:
        digest = job["digest"]
        if digest in self._queue:
            self._queue.remove(digest)
        self._cache.pop(digest, None)
        job["state"] = STATE_QUARANTINED
        job["decision"] = DECISION_DENY
        job["reason"] = reason
        job["source"] = source
        job["actor"] = None
        self._set_tickets(
            job,
            state=STATE_QUARANTINED,
            decision=DECISION_DENY,
            reason=reason,
            source=source,
        )
        if timed_out:
            self._counters["timed_out"] += 1

    def quarantine(self, digest: str, *, reason: str, now: int) -> dict:
        with self._lock:
            if not isinstance(reason, str) or not reason.strip():
                self._invalid("reason is required")
            job = self._jobs.get(digest)
            if job is None:
                self._unknown_digest(digest)
            if job["state"] not in (STATE_QUEUED, STATE_SCANNING):
                raise ScanGateError(
                    "SCAN_STATE_INVALID", "job cannot be quarantined")
            clean_reason = reason.strip()
            self._quarantine_job(
                job, reason=clean_reason, source=SOURCE_QUARANTINE,
                timed_out=False)
            return {
                "digest": digest,
                "state": STATE_QUARANTINED,
                "reason": clean_reason,
            }

    def release(self, digest: str, *, actor: str, now: int) -> dict:
        with self._lock:
            if not isinstance(actor, str) or not actor.strip():
                raise ScanGateError("SCAN_ACTOR_REQUIRED", "actor is required")
            clean_actor = actor.strip()
            job = self._jobs.get(digest)
            if job is None:
                self._unknown_digest(digest)
            if job["state"] == STATE_RELEASED:
                raise ScanGateError(
                    "SCAN_ALREADY_RELEASED", "job was already released")
            if job["state"] != STATE_QUARANTINED:
                raise ScanGateError(
                    "SCAN_STATE_INVALID", "job is not quarantined")

            self._cache.pop(digest, None)
            job["state"] = STATE_RELEASED
            job["decision"] = DECISION_ALLOW
            job["reason"] = REASON_MANUAL_RELEASE
            job["source"] = SOURCE_MANUAL_RELEASE
            job["actor"] = clean_actor
            self._set_tickets(
                job,
                state=STATE_RELEASED,
                decision=DECISION_ALLOW,
                reason=REASON_MANUAL_RELEASE,
                source=SOURCE_MANUAL_RELEASE,
            )
            self._counters["released"] += 1
            return {
                "digest": digest,
                "state": STATE_RELEASED,
                "actor": clean_actor,
            }

    def sweep(self, *, now: int) -> dict:
        with self._lock:
            expired = [
                digest for digest, entry in self._cache.items()
                if entry["expires_at"] <= now
            ]
            for digest in expired:
                self._cache.pop(digest, None)

            timed_out = 0
            for job in list(self._jobs.values()):
                if (job["state"] == STATE_SCANNING
                        and job["started_at"] is not None
                        and job["started_at"] + self.scan_timeout <= now):
                    self._quarantine_job(
                        job, reason=REASON_TIMEOUT, source=SOURCE_SCAN,
                        timed_out=True)
                    timed_out += 1
            return {"expired_cache": len(expired), "timed_out": timed_out}

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "format": SNAPSHOT_FORMAT,
                "tickets": copy.deepcopy(self._tickets),
                "jobs": copy.deepcopy(self._jobs),
                "queue": list(self._queue),
                "cache": copy.deepcopy(self._cache),
                "counters": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        try:
            tickets, jobs, queue, cache, counters = self._validate_snapshot(state)
        except Exception:
            raise ScanGateError(
                "SCAN_SNAPSHOT_INVALID", "malformed snapshot") from None
        with self._lock:
            self._tickets = tickets
            self._jobs = jobs
            self._queue = queue
            self._cache = cache
            self._counters = counters

    def _validate_snapshot(self, state: object) -> tuple:
        if not isinstance(state, dict):
            raise ValueError("snapshot must be a dict")
        expected_keys = {"format", "tickets", "jobs", "queue", "cache",
                         "counters"}
        if set(state) != expected_keys:
            raise ValueError("snapshot keys are invalid")
        if state["format"] != SNAPSHOT_FORMAT:
            raise ValueError("snapshot format is invalid")

        raw_tickets = state["tickets"]
        raw_jobs = state["jobs"]
        raw_queue = state["queue"]
        raw_cache = state["cache"]
        raw_counters = state["counters"]
        if not isinstance(raw_tickets, dict) or not isinstance(raw_jobs, dict):
            raise ValueError("tickets and jobs must be dicts")
        if not isinstance(raw_queue, (list, tuple)):
            raise ValueError("queue must be a list or tuple")
        if not isinstance(raw_cache, dict) or not isinstance(raw_counters, dict):
            raise ValueError("cache and counters must be dicts")
        if set(raw_counters) != set(COUNTER_KEYS):
            raise ValueError("counter keys are invalid")

        counters = {}
        for key in COUNTER_KEYS:
            value = raw_counters[key]
            if (not isinstance(value, int) or isinstance(value, bool)
                    or value < 0):
                raise ValueError("counter value is invalid")
            counters[key] = value

        tickets = {}
        for upload_id, raw_ticket in raw_tickets.items():
            if not isinstance(upload_id, str) or not upload_id:
                raise ValueError("ticket upload_id is invalid")
            if not isinstance(raw_ticket, dict):
                raise ValueError("ticket must be a dict")
            if set(raw_ticket) != _TICKET_KEYS:
                raise ValueError("ticket keys are invalid")
            ticket = copy.deepcopy(raw_ticket)
            if (ticket["upload_id"] != upload_id
                    or not self._valid_digest(ticket["digest"])
                    or ticket["state"] not in _ALL_STATES
                    or ticket["decision"] not in _ALL_DECISIONS
                    or not self._optional_string(ticket["reason"])
                    or not isinstance(ticket["source"], str)):
                raise ValueError("ticket fields are invalid")
            tickets[upload_id] = ticket

        jobs = {}
        for digest, raw_job in raw_jobs.items():
            if not self._valid_digest(digest):
                raise ValueError("job digest is invalid")
            if not isinstance(raw_job, dict):
                raise ValueError("job must be a dict")
            if set(raw_job) != _JOB_KEYS:
                raise ValueError("job keys are invalid")
            job = copy.deepcopy(raw_job)
            upload_ids = job["upload_ids"]
            if not isinstance(upload_ids, (list, tuple)) or not upload_ids:
                raise ValueError("job upload_ids are invalid")
            if len(set(upload_ids)) != len(upload_ids):
                raise ValueError("job upload_ids contain duplicates")
            for upload_id in upload_ids:
                if not isinstance(upload_id, str) or upload_id not in tickets:
                    raise ValueError("job references an unknown ticket")
                if tickets[upload_id]["digest"] != digest:
                    raise ValueError("ticket digest does not match job")
            if (job["digest"] != digest
                    or job["state"] not in _ALL_STATES
                    or job["decision"] not in _ALL_DECISIONS
                    or not self._optional_string(job["reason"])
                    or not isinstance(job["source"], str)
                    or not self._optional_string(job["actor"])):
                raise ValueError("job fields are invalid")
            if job["state"] == STATE_QUEUED:
                if (job["started_at"] is not None
                        or job["outcome"] is not None
                        or job["decision"] != DECISION_PENDING
                        or job["reason"] is not None
                        or job["actor"] is not None):
                    raise ValueError("queued job fields are invalid")
            elif job["state"] == STATE_SCANNING:
                if (not self._is_timestamp(job["started_at"])
                        or job["outcome"] is not None
                        or job["decision"] != DECISION_PENDING
                        or job["reason"] is not None
                        or job["actor"] is not None):
                    raise ValueError("scanning job fields are invalid")
            elif job["state"] == STATE_DECIDED:
                expected_decision = (
                    DECISION_ALLOW if job["outcome"] == "benign"
                    else DECISION_DENY if job["outcome"] == "malicious"
                    else None
                )
                if (job["outcome"] not in SCAN_OUTCOMES
                        or job["decision"] != expected_decision
                        or job["actor"] is not None):
                    raise ValueError("decided job fields are invalid")
            elif job["state"] == STATE_QUARANTINED:
                if (job["decision"] != DECISION_DENY
                        or not isinstance(job["reason"], str)
                        or not job["reason"]
                        or job["actor"] is not None
                        or job["outcome"] is not None):
                    raise ValueError("quarantined job fields are invalid")
            elif job["state"] == STATE_RELEASED:
                if (job["decision"] != DECISION_ALLOW
                        or job["reason"] != REASON_MANUAL_RELEASE
                        or job["source"] != SOURCE_MANUAL_RELEASE
                        or not isinstance(job["actor"], str)
                        or not job["actor"]
                        or job["outcome"] is not None):
                    raise ValueError("released job fields are invalid")
            if job["outcome"] is not None and job["outcome"] not in SCAN_OUTCOMES:
                raise ValueError("job outcome is invalid")
            expected_ticket = (
                job["state"], job["decision"], job["reason"], job["source"])
            for upload_id in upload_ids:
                ticket = tickets[upload_id]
                actual_ticket = (
                    ticket["state"],
                    ticket["decision"],
                    ticket["reason"],
                    ticket["source"],
                )
                if actual_ticket != expected_ticket:
                    raise ValueError("ticket does not match its job")
            job["upload_ids"] = list(upload_ids)
            jobs[digest] = job

        for ticket in tickets.values():
            if ticket["digest"] not in jobs:
                raise ValueError("ticket references an unknown job")

        queued_digests = [
            digest for digest, job in jobs.items()
            if job["state"] == STATE_QUEUED
        ]
        if len(raw_queue) != len(set(raw_queue)):
            raise ValueError("queue contains duplicates")
        for digest in raw_queue:
            if not isinstance(digest, str) or digest not in jobs:
                raise ValueError("queue references an unknown job")
            if jobs[digest]["state"] != STATE_QUEUED:
                raise ValueError("queue references a non-queued job")
        if set(raw_queue) != set(queued_digests):
            raise ValueError("queue does not match queued jobs")
        queue = list(raw_queue)

        cache = {}
        for digest, raw_entry in raw_cache.items():
            if not self._valid_digest(digest):
                raise ValueError("cache digest is invalid")
            if digest not in jobs:
                raise ValueError("cache references an unknown job")
            if not isinstance(raw_entry, dict):
                raise ValueError("cache entry must be a dict")
            if set(raw_entry) != _CACHE_KEYS:
                raise ValueError("cache entry keys are invalid")
            entry = copy.deepcopy(raw_entry)
            if (entry["decision"] != DECISION_ALLOW
                    or not self._is_timestamp(entry["created_at"])
                    or not self._is_timestamp(entry["expires_at"])):
                raise ValueError("cache entry fields are invalid")
            cache[digest] = entry

        return tickets, jobs, queue, cache, counters

    @staticmethod
    def _valid_digest(value: object) -> bool:
        if not isinstance(value, str) or len(value) != 64:
            return False
        return all(char in "0123456789abcdef" for char in value)

    @staticmethod
    def _optional_string(value: object) -> bool:
        return value is None or isinstance(value, str)

    @staticmethod
    def _is_timestamp(value: object) -> bool:
        return isinstance(value, (int, float)) and not isinstance(value, bool)


_ALL_STATES = {
    STATE_QUEUED,
    STATE_SCANNING,
    STATE_DECIDED,
    STATE_QUARANTINED,
    STATE_RELEASED,
}

_ALL_DECISIONS = {DECISION_ALLOW, DECISION_DENY, DECISION_PENDING}
