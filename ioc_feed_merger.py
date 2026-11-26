"""Multi source IOC feed merger: weighted confidence, TTL decay, priority verdicts."""

from __future__ import annotations

import copy
import ipaddress
import math
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


class IocError(ValueError):
    """Raised when a feed merger operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


KIND_INTEL = "intel"
KIND_WHITELIST = "whitelist"
KINDS = (KIND_INTEL, KIND_WHITELIST)

VERDICT_BLOCK = "block"
VERDICT_ALLOW = "allow"

IOC_TYPES = ("domain", "ipv4", "sha256", "url")

TTL_MIN = 60
TTL_MAX = 2592000

SNAPSHOT_VERSION = 1
SNAPSHOT_KEYS = frozenset(
    {
        "version",
        "halflife_seconds",
        "batch_limit",
        "sources",
        "observations",
        "audit",
        "counters",
    }
)


@dataclass(frozen=True)
class SourceRecord:
    name: str
    weight: float
    priority: int
    kind: str
    added_at: str


def _parse_time(value: object) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp must be a non-empty string")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1] + "+00:00"
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _format_time(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _require_time(value: object) -> datetime:
    try:
        return _parse_time(value)
    except (TypeError, ValueError, OverflowError) as exc:
        raise IocError("IOC_BAD_VALUE", value) from exc


def _is_finite_number(value: object) -> bool:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return False
    return isinstance(value, int) or math.isfinite(value)


def _validate_source_values(
    *, name: object, weight: object, priority: object, kind: object
) -> None:
    if not isinstance(name, str) or not name.strip():
        raise IocError("IOC_BAD_SOURCE", name)
    if (
        not _is_finite_number(weight)
        or not 0 < weight < 1
    ):
        raise IocError("IOC_BAD_SOURCE", weight)
    if isinstance(priority, bool) or not isinstance(priority, int):
        raise IocError("IOC_BAD_SOURCE", priority)
    if not 0 <= priority <= 100:
        raise IocError("IOC_BAD_SOURCE", priority)
    if kind not in KINDS:
        raise IocError("IOC_BAD_SOURCE", kind)


def _normalize_value(ioc_type: str, value: object) -> str:
    if not isinstance(value, str):
        raise IocError("IOC_BAD_VALUE", value)

    if ioc_type == "domain":
        normalized = value.strip().lower().rstrip(".")
    elif ioc_type == "ipv4":
        try:
            normalized = str(ipaddress.IPv4Address(value.strip()))
        except (ipaddress.AddressValueError, ValueError) as exc:
            raise IocError("IOC_BAD_VALUE", value) from exc
    elif ioc_type == "url":
        normalized = value.strip().lower()
    else:
        normalized = value.strip().lower()

    if not normalized:
        raise IocError("IOC_BAD_VALUE", value)
    return normalized


def _normalize_ioc(ioc_type: object, value: object) -> tuple[str, str]:
    if ioc_type not in IOC_TYPES:
        raise IocError("IOC_BAD_TYPE", ioc_type)
    return ioc_type, _normalize_value(ioc_type, value)


def _validate_ttl(value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise IocError("IOC_BAD_TTL", value)
    if not TTL_MIN <= value <= TTL_MAX:
        raise IocError("IOC_BAD_TTL", value)
    return value


def _validate_confidence(value: object) -> float:
    if (
        not _is_finite_number(value)
        or not 0 <= value <= 1
    ):
        raise IocError("IOC_BAD_CONFIDENCE", value)
    return float(value)


def _indicator_key(ioc_type: str, value: str) -> str:
    return "{0}:{1}".format(ioc_type, value)


def _observation_key(ioc_type: str, value: str, source: str) -> str:
    return "{0}:{1}:{2}".format(ioc_type, value, source)


def _snapshot_indicator_key(ioc_type: str, value: str) -> str:
    return "{0}\x1f{1}".format(ioc_type, value)


class IocFeedMerger:
    """Merge indicators coming from several feeds into one verdict per indicator."""

    def __init__(
        self, *, halflife_seconds: int = 86400, batch_limit: int = 32
    ) -> None:
        self.halflife_seconds = halflife_seconds
        self.batch_limit = batch_limit
        self._lock = threading.RLock()
        self._sources: dict[str, SourceRecord] = {}
        self._observations: dict[tuple[str, str], dict[str, dict]] = {}
        self._audit: list[dict] = []
        self._conflict_signatures: dict[tuple[str, str], tuple] = {}
        self._counters = {
            "accepted": 0,
            "rejected": 0,
            "swept": 0,
            "conflicts": 0,
            "merged_indicators": 0,
        }

    def register_source(
        self, name: str, *, weight: float, priority: int, kind: str, now: str
    ) -> SourceRecord:
        with self._lock:
            _validate_source_values(
                name=name, weight=weight, priority=priority, kind=kind
            )
            if name in self._sources:
                raise IocError("IOC_DUPLICATE_SOURCE", name)
            added_at = _format_time(_require_time(now))
            record = SourceRecord(
                name=name,
                weight=float(weight),
                priority=priority,
                kind=kind,
                added_at=added_at,
            )
            self._sources[name] = record
            return record

    def ingest_feed(self, source: str, items: list[dict], *, now: str) -> dict:
        with self._lock:
            if not isinstance(source, str) or source not in self._sources:
                raise IocError("IOC_UNKNOWN_SOURCE", source)
            if not isinstance(items, list):
                raise IocError("IOC_BAD_VALUE", items)

            ingested_at = _require_time(now)
            source_record = self._sources[source]
            accepted = 0
            rejected = 0
            rejected_indexes: list[int] = []

            for index, raw_item in enumerate(items):
                try:
                    if not isinstance(raw_item, dict):
                        raise IocError("IOC_BAD_VALUE", raw_item)

                    ioc_type, value = _normalize_ioc(
                        raw_item.get("type"), raw_item.get("value")
                    )
                    ttl = _validate_ttl(raw_item.get("ttl"))
                    reported_confidence = _validate_confidence(
                        raw_item.get("confidence", 1.0)
                    )
                except IocError:
                    rejected += 1
                    rejected_indexes.append(index)
                    continue

                base_confidence = source_record.weight * reported_confidence
                expires_at = ingested_at + timedelta(seconds=ttl)
                observation = {
                    "base_confidence": min(1.0, max(0.0, base_confidence)),
                    "reported_confidence": reported_confidence,
                    "ttl": ttl,
                    "observed_at": _format_time(ingested_at),
                    "expires_at": _format_time(expires_at),
                }

                key = (ioc_type, value)
                self._observations.setdefault(key, {})[source] = observation
                accepted += 1

            self._counters["accepted"] += accepted
            self._counters["rejected"] += rejected
            return {
                "accepted": accepted,
                "rejected": rejected,
                "rejected_indexes": rejected_indexes,
            }

    def merge(self, *, now: str) -> list[dict]:
        with self._lock:
            current = _require_time(now)
            rows: list[dict] = []
            for ioc_type, value in sorted(self._observations):
                row = self._resolve_indicator((ioc_type, value), current)
                if row is not None:
                    rows.append(row)
            self._counters["merged_indicators"] += len(rows)
            return rows

    def lookup(self, ioc_type: str, value: str, *, now: str) -> dict:
        with self._lock:
            key = _normalize_ioc(ioc_type, value)
            if key not in self._observations:
                raise IocError("IOC_UNKNOWN", _indicator_key(*key))
            current = _require_time(now)
            row = self._resolve_indicator(key, current)
            if row is None:
                raise IocError("IOC_UNKNOWN", _indicator_key(*key))
            return row

    def effective_confidence(
        self, ioc_type: str, value: str, *, now: str
    ) -> float:
        with self._lock:
            key = _normalize_ioc(ioc_type, value)
            if key not in self._observations:
                raise IocError("IOC_UNKNOWN", _indicator_key(*key))
            current = _require_time(now)
            active = self._active_observations(key, current)
            if not active:
                return 0.0
            return self._noise_or(active)

    def expire_sweep(
        self, *, now: str, batch_size: int | None = None
    ) -> list[str]:
        with self._lock:
            current = _require_time(now)
            limit = self.batch_limit if batch_size is None else batch_size
            if (
                isinstance(limit, bool)
                or not isinstance(limit, int)
                or limit <= 0
            ):
                raise IocError("IOC_BAD_VALUE", batch_size)

            expired: list[tuple[str, str, str]] = []
            for (ioc_type, value), by_source in self._observations.items():
                for source, observation in by_source.items():
                    if _parse_time(observation["expires_at"]) <= current:
                        expired.append((ioc_type, value, source))

            if not expired:
                return []

            expired.sort()
            removed = expired[:limit]
            removed_keys: list[str] = []
            for ioc_type, value, source in removed:
                key = (ioc_type, value)
                by_source = self._observations.get(key)
                if by_source is None or source not in by_source:
                    continue
                del by_source[source]
                removed_keys.append(_observation_key(ioc_type, value, source))
                self._conflict_signatures.pop(key, None)
                if not by_source:
                    del self._observations[key]

            self._counters["swept"] += len(removed_keys)
            return removed_keys

    def sources(self) -> list[SourceRecord]:
        with self._lock:
            return [self._sources[name] for name in sorted(self._sources)]

    def audit(self) -> list[dict]:
        with self._lock:
            return copy.deepcopy(self._audit)

    def stats(self) -> dict:
        with self._lock:
            return {
                "sources": len(self._sources),
                "observations": sum(
                    len(by_source) for by_source in self._observations.values()
                ),
                "indicators": len(self._observations),
                "accepted": self._counters["accepted"],
                "rejected": self._counters["rejected"],
                "swept": self._counters["swept"],
                "conflicts": self._counters["conflicts"],
                "merged_indicators": self._counters["merged_indicators"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            sources = [
                {
                    "name": source.name,
                    "weight": source.weight,
                    "priority": source.priority,
                    "kind": source.kind,
                    "added_at": source.added_at,
                }
                for source in self.sources()
            ]
            observations = {}
            for (ioc_type, value), by_source in sorted(
                self._observations.items()
            ):
                observations[
                    _snapshot_indicator_key(ioc_type, value)
                ] = {
                    "type": ioc_type,
                    "value": value,
                    "sources": {
                        source: copy.deepcopy(observation)
                        for source, observation in sorted(by_source.items())
                    },
                }
            return {
                "version": SNAPSHOT_VERSION,
                "halflife_seconds": self.halflife_seconds,
                "batch_limit": self.batch_limit,
                "sources": sources,
                "observations": observations,
                "audit": copy.deepcopy(self._audit),
                "counters": dict(self._counters),
                "conflict_signatures": [
                    {
                        "type": signature[0][0],
                        "value": signature[0][1],
                        "participants": [
                            list(participant)
                            for participant in signature[1]
                        ],
                        "winner": signature[2],
                    }
                    for _, signature in sorted(
                        self._conflict_signatures.items()
                    )
                ],
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except IocError as exc:
                if exc.code == "IOC_SNAPSHOT_INVALID":
                    raise
                raise IocError("IOC_SNAPSHOT_INVALID", exc.detail) from exc
            except Exception as exc:
                raise IocError("IOC_SNAPSHOT_INVALID", exc) from exc

            (
                halflife_seconds,
                batch_limit,
                sources,
                observations,
                audit_entries,
                counters,
                conflict_signatures,
            ) = parsed
            self.halflife_seconds = halflife_seconds
            self.batch_limit = batch_limit
            self._sources = sources
            self._observations = observations
            self._audit = audit_entries
            self._counters = counters
            self._conflict_signatures = conflict_signatures

    def _parse_snapshot(self, state: object) -> tuple:
        if not isinstance(state, dict) or not SNAPSHOT_KEYS.issubset(state):
            raise IocError("IOC_SNAPSHOT_INVALID", state)
        version = state.get("version")
        if (
            isinstance(version, bool)
            or not isinstance(version, int)
            or version != SNAPSHOT_VERSION
        ):
            raise IocError("IOC_SNAPSHOT_INVALID", version)

        halflife_seconds = state["halflife_seconds"]
        batch_limit = state["batch_limit"]
        if (
            not _is_finite_number(halflife_seconds)
            or halflife_seconds <= 0
        ):
            raise IocError("IOC_SNAPSHOT_INVALID", halflife_seconds)
        if (
            isinstance(batch_limit, bool)
            or not isinstance(batch_limit, int)
            or batch_limit <= 0
        ):
            raise IocError("IOC_SNAPSHOT_INVALID", batch_limit)

        raw_sources = state["sources"]
        if not isinstance(raw_sources, list):
            raise IocError("IOC_SNAPSHOT_INVALID", raw_sources)
        sources: dict[str, SourceRecord] = {}
        for raw_source in raw_sources:
            if not isinstance(raw_source, dict):
                raise IocError("IOC_SNAPSHOT_INVALID", raw_source)
            required = {"name", "weight", "priority", "kind", "added_at"}
            if not required.issubset(raw_source):
                raise IocError("IOC_SNAPSHOT_INVALID", raw_source)
            name = raw_source["name"]
            weight = raw_source["weight"]
            priority = raw_source["priority"]
            kind = raw_source["kind"]
            _validate_source_values(
                name=name, weight=weight, priority=priority, kind=kind
            )
            if name in sources:
                raise IocError("IOC_SNAPSHOT_INVALID", name)
            added_at = raw_source["added_at"]
            if not isinstance(added_at, str):
                raise IocError("IOC_SNAPSHOT_INVALID", added_at)
            _parse_time(added_at)
            sources[name] = SourceRecord(
                name=name,
                weight=float(weight),
                priority=priority,
                kind=kind,
                added_at=added_at,
            )

        raw_observations = state["observations"]
        if not isinstance(raw_observations, dict):
            raise IocError("IOC_SNAPSHOT_INVALID", raw_observations)
        observations: dict[tuple[str, str], dict[str, dict]] = {}
        for snapshot_key, raw_indicator in raw_observations.items():
            if not isinstance(snapshot_key, str) or not isinstance(
                raw_indicator, dict
            ):
                raise IocError("IOC_SNAPSHOT_INVALID", snapshot_key)
            ioc_type = raw_indicator.get("type")
            value = raw_indicator.get("value")
            if ioc_type not in IOC_TYPES or not isinstance(value, str):
                raise IocError("IOC_SNAPSHOT_INVALID", raw_indicator)
            if snapshot_key != _snapshot_indicator_key(ioc_type, value):
                raise IocError("IOC_SNAPSHOT_INVALID", snapshot_key)
            raw_by_source = raw_indicator.get("sources")
            if not isinstance(raw_by_source, dict) or not raw_by_source:
                raise IocError("IOC_SNAPSHOT_INVALID", raw_by_source)

            by_source: dict[str, dict] = {}
            for source, raw_observation in raw_by_source.items():
                if source not in sources or not isinstance(raw_observation, dict):
                    raise IocError("IOC_SNAPSHOT_INVALID", source)
                required = {
                    "base_confidence",
                    "reported_confidence",
                    "ttl",
                    "observed_at",
                    "expires_at",
                }
                if not required.issubset(raw_observation):
                    raise IocError("IOC_SNAPSHOT_INVALID", raw_observation)
                base_confidence = _validate_confidence(
                    raw_observation["base_confidence"]
                )
                reported_confidence = _validate_confidence(
                    raw_observation["reported_confidence"]
                )
                ttl = _validate_ttl(raw_observation["ttl"])
                observed_at = raw_observation["observed_at"]
                expires_at = raw_observation["expires_at"]
                if not isinstance(observed_at, str) or not isinstance(
                    expires_at, str
                ):
                    raise IocError("IOC_SNAPSHOT_INVALID", raw_observation)
                observed_dt = _parse_time(observed_at)
                expires_dt = _parse_time(expires_at)
                if expires_dt != observed_dt + timedelta(seconds=ttl):
                    raise IocError("IOC_SNAPSHOT_INVALID", expires_at)
                by_source[source] = {
                    "base_confidence": base_confidence,
                    "reported_confidence": reported_confidence,
                    "ttl": ttl,
                    "observed_at": observed_at,
                    "expires_at": expires_at,
                }
            observations[(ioc_type, value)] = by_source

        raw_audit = state["audit"]
        if not isinstance(raw_audit, list):
            raise IocError("IOC_SNAPSHOT_INVALID", raw_audit)
        audit_entries: list[dict] = []
        for entry in raw_audit:
            if not isinstance(entry, dict):
                raise IocError("IOC_SNAPSHOT_INVALID", entry)
            audit_entries.append(copy.deepcopy(entry))

        raw_counters = state["counters"]
        if not isinstance(raw_counters, dict):
            raise IocError("IOC_SNAPSHOT_INVALID", raw_counters)
        counters = {}
        for name in (
            "accepted",
            "rejected",
            "swept",
            "conflicts",
            "merged_indicators",
        ):
            value = raw_counters.get(name)
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
            ):
                raise IocError("IOC_SNAPSHOT_INVALID", name)
            counters[name] = value

        raw_signatures = state.get("conflict_signatures", [])
        if not isinstance(raw_signatures, list):
            raise IocError("IOC_SNAPSHOT_INVALID", raw_signatures)
        conflict_signatures = {}
        for raw_signature in raw_signatures:
            if not isinstance(raw_signature, dict):
                raise IocError("IOC_SNAPSHOT_INVALID", raw_signature)
            required = {"type", "value", "participants", "winner"}
            if not required.issubset(raw_signature):
                raise IocError("IOC_SNAPSHOT_INVALID", raw_signature)
            ioc_type = raw_signature["type"]
            value = raw_signature["value"]
            winner = raw_signature["winner"]
            raw_participants = raw_signature["participants"]
            if (
                ioc_type not in IOC_TYPES
                or not isinstance(value, str)
                or winner not in KINDS
                or not isinstance(raw_participants, list)
            ):
                raise IocError("IOC_SNAPSHOT_INVALID", raw_signature)
            participants = []
            for participant in raw_participants:
                if not isinstance(participant, (list, tuple)):
                    raise IocError("IOC_SNAPSHOT_INVALID", participant)
                if len(participant) != 3:
                    raise IocError("IOC_SNAPSHOT_INVALID", participant)
                source, kind, priority = participant
                if (
                    source not in sources
                    or kind not in KINDS
                    or isinstance(priority, bool)
                    or not isinstance(priority, int)
                    or not 0 <= priority <= 100
                ):
                    raise IocError("IOC_SNAPSHOT_INVALID", participant)
                participants.append((source, kind, priority))
            key = (ioc_type, value)
            if key in conflict_signatures:
                raise IocError("IOC_SNAPSHOT_INVALID", ioc_type)
            conflict_signatures[key] = (
                key,
                tuple(sorted(participants)),
                winner,
            )

        return (
            halflife_seconds,
            batch_limit,
            sources,
            observations,
            audit_entries,
            counters,
            conflict_signatures,
        )

    def _active_observations(
        self, key: tuple[str, str], now: datetime
    ) -> list[tuple[SourceRecord, dict, float, datetime]]:
        by_source = self._observations.get(key)
        if not by_source:
            return []

        active: list[tuple[SourceRecord, dict, float, datetime]] = []
        for source, observation in by_source.items():
            source_record = self._sources.get(source)
            if source_record is None:
                continue
            expires_at = _parse_time(observation["expires_at"])
            if expires_at <= now:
                continue
            ttl = observation["ttl"]
            remaining = (expires_at - now).total_seconds()
            ratio = min(1.0, max(0.0, remaining / ttl))
            effective = min(
                1.0, max(0.0, observation["base_confidence"] * ratio)
            )
            active.append((source_record, observation, effective, expires_at))

        if not active:
            return []
        active.sort(key=lambda entry: entry[0].name)
        return active

    @staticmethod
    def _noise_or(
        active: list[tuple[SourceRecord, dict, float, datetime]]
    ) -> float:
        confidence = 1.0
        for _, _, effective, _ in active:
            confidence *= 1.0 - effective
        return min(1.0, max(0.0, 1.0 - confidence))

    def _resolve_indicator(
        self, key: tuple[str, str], now: datetime
    ) -> dict | None:
        active = self._active_observations(key, now)
        if not active:
            self._conflict_signatures.pop(key, None)
            return None

        intel = [entry for entry in active if entry[0].kind == KIND_INTEL]
        whitelist = [
            entry for entry in active if entry[0].kind == KIND_WHITELIST
        ]
        if whitelist and not intel:
            verdict = VERDICT_ALLOW
            self._conflict_signatures.pop(key, None)
        elif intel and not whitelist:
            verdict = VERDICT_BLOCK
            self._conflict_signatures.pop(key, None)
        else:
            intel_priority = max(entry[0].priority for entry in intel)
            whitelist_priority = max(entry[0].priority for entry in whitelist)
            if whitelist_priority > intel_priority:
                verdict = VERDICT_ALLOW
                winner_kind = KIND_WHITELIST
            else:
                verdict = VERDICT_BLOCK
                winner_kind = KIND_INTEL

            signature = (
                key,
                tuple(
                    sorted(
                        (entry[0].name, entry[0].kind, entry[0].priority)
                        for entry in active
                    )
                ),
                winner_kind,
            )
            if self._conflict_signatures.get(key) != signature:
                self._conflict_signatures[key] = signature
                self._audit.append(
                    {
                        "reason": "priority_conflict",
                        "type": key[0],
                        "value": key[1],
                        "sources": [
                            entry[0].name for entry in active
                        ],
                        "winner": winner_kind,
                    }
                )
                self._counters["conflicts"] += 1

        confidence = self._noise_or(active)

        source_entries = []
        for source_record, observation, effective, _ in active:
            source_entries.append(
                {
                    "source": source_record.name,
                    "kind": source_record.kind,
                    "weight": source_record.weight,
                    "priority": source_record.priority,
                    "reported_confidence": observation[
                        "reported_confidence"
                    ],
                    "confidence": effective,
                    "ttl": observation["ttl"],
                    "expires_at": observation["expires_at"],
                }
            )

        return {
            "type": key[0],
            "value": key[1],
            "confidence": confidence,
            "ttl": max(entry[1]["ttl"] for entry in active),
            "expires_at": _format_time(
                max(entry[3] for entry in active)
            ),
            "verdict": verdict,
            "sources": source_entries,
        }
