"""WebAuthn attestation trust policy: AAGUID metadata, trust anchors, quarantine."""

from __future__ import annotations

import copy
import re
import threading
import time
from collections.abc import Iterable


class AttestationError(ValueError):
    """Refused attestation operation carrying a stable machine-readable code."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_FORMATS = ("none", "indirect", "direct", "enterprise")
_FORMAT_STRENGTH = {name: index for index, name in enumerate(_FORMATS)}
_AAGUID_RE = re.compile(r"[0-9a-f]{32}\Z")
_STAT_KEYS = (
    "upserts",
    "reloads",
    "evaluations",
    "cache_hits",
    "quarantined",
    "rotations",
)
_SNAPSHOT_VERSION = 1


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _valid_aaguid(value: object) -> bool:
    return isinstance(value, str) and _AAGUID_RE.fullmatch(value) is not None


def _require_aaguid(value: object) -> str:
    if not _valid_aaguid(value):
        raise AttestationError("ATTEST_INVALID", {"aaguid": value})
    return value  # type: ignore[return-value]


def _invalid_entry(detail: object) -> AttestationError:
    return AttestationError("ATTEST_INVALID", detail)


def _normalize_string_set(value: object, *, field: str,
                          allow_empty: bool) -> tuple[str, ...]:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise _invalid_entry({"field": field, "value": value})
    try:
        values = list(value)
    except TypeError:
        raise _invalid_entry({"field": field, "value": value}) from None

    if not allow_empty and not values:
        raise _invalid_entry({"field": field, "reason": "empty"})

    for item in values:
        if not isinstance(item, str):
            raise _invalid_entry({"field": field, "value": item})
        if field == "formats" and item not in _FORMAT_STRENGTH:
            raise _invalid_entry({"field": field, "value": item})
        if field == "anchors" and not item:
            raise _invalid_entry({"field": field, "value": item})

    return tuple(sorted(set(values)))


def _normalize_entry(entry: object) -> dict:
    if not isinstance(entry, dict):
        raise _invalid_entry({"entry": entry})

    required = ("aaguid", "vendor", "model", "formats", "anchors", "version")
    missing = [key for key in required if key not in entry]
    if missing:
        raise _invalid_entry({"missing": missing})

    aaguid = _require_aaguid(entry["aaguid"])

    vendor = entry["vendor"]
    if not isinstance(vendor, str) or not vendor.strip():
        raise _invalid_entry({"field": "vendor"})

    model = entry["model"]
    if not isinstance(model, str) or not model.strip():
        raise _invalid_entry({"field": "model"})

    formats = _normalize_string_set(
        entry["formats"], field="formats", allow_empty=False
    )
    anchors = _normalize_string_set(
        entry["anchors"], field="anchors", allow_empty=True
    )

    version = entry["version"]
    if not _is_int(version) or version <= 0:
        raise _invalid_entry({"field": "version", "value": version})

    return {
        "aaguid": aaguid,
        "vendor": vendor,
        "model": model,
        "formats": formats,
        "anchors": anchors,
        "version": version,
    }


def _normalize_order(order: object) -> tuple[str, ...]:
    if isinstance(order, (str, bytes)) or not isinstance(order, Iterable):
        raise AttestationError("ATTEST_INVALID", {"field": "order"})
    try:
        values = tuple(order)
    except TypeError:
        raise AttestationError("ATTEST_INVALID", {"field": "order"}) from None
    if any(not isinstance(item, str) or item not in _FORMAT_STRENGTH
           for item in values):
        raise AttestationError("ATTEST_INVALID", {"field": "order"})
    return values


class AttestationTrustPolicy:
    """Decide which attestation formats and authenticator models a relying party accepts."""

    def __init__(self, *, rp_id: str, overlap_seconds: int = 86400,
                 minimum: str = "none", clock=None) -> None:
        self.rp_id = rp_id
        if not _is_int(overlap_seconds) or overlap_seconds < 0:
            raise AttestationError(
                "ATTEST_INVALID", {"overlap_seconds": overlap_seconds}
            )
        self.overlap_seconds = overlap_seconds
        if minimum not in _FORMAT_STRENGTH:
            raise AttestationError("ATTEST_INVALID", {"minimum": minimum})
        self.minimum = minimum
        self._clock = clock
        self._lock = threading.RLock()
        self._metadata: dict[str, dict] = {}
        self._policy_order: tuple[str, ...] = _FORMATS
        self._policy_version = 0
        self._package_version = 0
        self._anchors: dict[str, dict] = {}
        self._quarantine: dict[str, dict] = {}
        self._cache: dict[tuple, dict] = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

    def _now_seconds(self, now: int | None) -> int:
        if now is None:
            if self._clock is None:
                now = time.time()
            elif callable(self._clock):
                now = self._clock()
            else:
                now = self._clock
        try:
            return int(now)
        except (TypeError, ValueError):
            raise AttestationError("ATTEST_INVALID", {"now": now}) from None

    def _evict_aaguid_cache(self, aaguid: str) -> None:
        self._cache = {
            key: value for key, value in self._cache.items()
            if key[0] != aaguid
        }

    def _quarantine_locked(self, aaguid: str, reason: object,
                           now: int) -> None:
        self._quarantine[aaguid] = {
            "reason": copy.deepcopy(reason),
            "quarantined_at": now,
        }
        self._stats["quarantined"] += 1

    def _active_anchors_locked(self, aaguid: str, now: int) -> tuple[str, ...]:
        rotation = self._anchors.get(aaguid)
        if rotation is None:
            record = self._metadata.get(aaguid)
            if record is None:
                return ()
            return tuple(sorted(record["anchors"]))

        roots = {rotation["new_anchor"]}
        if now < rotation["overlap_until"]:
            roots.update(rotation["old_anchors"])
        return tuple(sorted(roots))

    def upsert_metadata(self, entry: dict) -> dict:
        with self._lock:
            record = _normalize_entry(entry)
            aaguid = record["aaguid"]
            existing = self._metadata.get(aaguid)

            if existing is not None:
                if record["version"] < existing["version"]:
                    raise AttestationError("ATTEST_CONFLICT", {
                        "aaguid": aaguid,
                        "reason": "version-rollback",
                        "existing_version": existing["version"],
                        "incoming_version": record["version"],
                    })
                if record["version"] == existing["version"]:
                    if record != existing:
                        raise AttestationError("ATTEST_CONFLICT", {
                            "aaguid": aaguid,
                            "reason": "content-mismatch",
                            "version": record["version"],
                        })
                    return copy.deepcopy(record)

            self._metadata[aaguid] = record
            self._stats["upserts"] += 1
            self._evict_aaguid_cache(aaguid)
            return copy.deepcopy(record)

    def metadata_for(self, aaguid: str) -> dict:
        with self._lock:
            _require_aaguid(aaguid)
            record = self._metadata.get(aaguid)
            if record is None:
                raise AttestationError(
                    "ATTEST_UNKNOWN", {"aaguid": aaguid}
                )
            return copy.deepcopy(record)

    def set_policy(self, order, minimum: str | None = None) -> dict:
        with self._lock:
            normalized_order = _normalize_order(order)
            if minimum is None:
                normalized_minimum = self.minimum
            elif minimum in _FORMAT_STRENGTH:
                normalized_minimum = minimum
            else:
                raise AttestationError(
                    "ATTEST_INVALID", {"minimum": minimum}
                )

            self._policy_order = normalized_order
            self.minimum = normalized_minimum
            self._policy_version += 1
            self._cache.clear()
            return {
                "order": normalized_order,
                "minimum": normalized_minimum,
            }

    def evaluate(self, aaguid: str, fmt: str,
                 trust_path_root: str | None = None,
                 now: int | None = None) -> dict:
        with self._lock:
            self._stats["evaluations"] += 1
            current_now = self._now_seconds(now)
            _require_aaguid(aaguid)

            if aaguid in self._quarantine:
                raise AttestationError(
                    "ATTEST_QUARANTINED", {"aaguid": aaguid}
                )

            metadata = self._metadata.get(aaguid)
            if metadata is None:
                self._quarantine_locked(
                    aaguid, "unknown_aaguid", current_now
                )
                return {
                    "status": "quarantined",
                    "aaguid": aaguid,
                    "fmt": fmt,
                    "code": "ATTEST_UNKNOWN",
                    "metadata_version": None,
                    "cached": False,
                }

            if fmt not in metadata["formats"]:
                raise AttestationError("ATTEST_FORMAT", {
                    "aaguid": aaguid,
                    "fmt": fmt,
                    "supported": metadata["formats"],
                })

            if fmt not in self._policy_order:
                raise AttestationError("ATTEST_FORMAT_NOT_ALLOWED", {
                    "aaguid": aaguid,
                    "fmt": fmt,
                    "order": self._policy_order,
                })

            if (_FORMAT_STRENGTH[fmt]
                    < _FORMAT_STRENGTH[self.minimum]):
                raise AttestationError("ATTEST_WEAKER", {
                    "aaguid": aaguid,
                    "fmt": fmt,
                    "minimum": self.minimum,
                })

            if fmt in ("direct", "enterprise"):
                root_missing = (
                    trust_path_root is None
                    or (isinstance(trust_path_root, str)
                        and not trust_path_root.strip())
                )
                if root_missing:
                    raise AttestationError("ATTEST_ANCHOR_MISSING", {
                        "aaguid": aaguid,
                        "fmt": fmt,
                    })

                active = self._active_anchors_locked(aaguid, current_now)
                if trust_path_root not in active:
                    raise AttestationError("ATTEST_ANCHOR_UNTRUSTED", {
                        "aaguid": aaguid,
                        "fmt": fmt,
                        "trust_path_root": trust_path_root,
                        "active_anchors": active,
                    })

            cache_key = (
                aaguid,
                fmt,
                trust_path_root,
                metadata["version"],
                self._policy_version,
            )
            cached = self._cache.get(cache_key)
            if cached is not None:
                self._stats["cache_hits"] += 1
                result = copy.deepcopy(cached)
                result["cached"] = True
                return result

            result = {
                "status": "accepted",
                "aaguid": aaguid,
                "fmt": fmt,
                "code": "OK",
                "metadata_version": metadata["version"],
                "cached": False,
            }
            self._cache[cache_key] = copy.deepcopy(result)
            return result

    def quarantine(self, aaguid: str, reason: str,
                   now: int | None = None) -> dict:
        with self._lock:
            _require_aaguid(aaguid)
            current_now = self._now_seconds(now)
            self._quarantine_locked(aaguid, reason, current_now)
            return {"aaguid": aaguid, "reason": reason}

    def quarantined(self) -> list[str]:
        with self._lock:
            return sorted(self._quarantine)

    def reload(self, package: dict) -> dict:
        with self._lock:
            if not isinstance(package, dict):
                raise AttestationError("ATTEST_INVALID", {
                    "reason": "package-not-mapping"
                })

            if "version" not in package or "entries" not in package:
                raise AttestationError("ATTEST_INVALID", {
                    "missing": [
                        key for key in ("version", "entries")
                        if key not in package
                    ],
                })

            version = package["version"]
            raw_entries = package["entries"]
            if not _is_int(version) or version <= 0:
                raise AttestationError("ATTEST_INVALID", {
                    "field": "version", "value": version
                })
            if isinstance(raw_entries, (str, bytes, dict)) or not isinstance(
                    raw_entries, Iterable):
                raise AttestationError("ATTEST_INVALID", {
                    "field": "entries"
                })

            entries: dict[str, dict] = {}
            count = 0
            try:
                raw_entry_list = list(raw_entries)
            except TypeError:
                raise AttestationError("ATTEST_INVALID", {
                    "field": "entries"
                }) from None

            for raw_entry in raw_entry_list:
                record = _normalize_entry(raw_entry)
                aaguid = record["aaguid"]
                if aaguid in entries:
                    raise AttestationError("ATTEST_INVALID", {
                        "field": "entries",
                        "reason": "duplicate-aaguid",
                        "aaguid": aaguid,
                    })
                entries[aaguid] = record
                count += 1

            if version < self._package_version:
                raise AttestationError("ATTEST_RELOAD", {
                    "current_version": self._package_version,
                    "attempted_version": version,
                })

            self._metadata = entries
            self._package_version = version
            self._cache.clear()
            self._stats["reloads"] += 1
            return {"version": version, "count": count}

    def rotate_anchor(self, aaguid: str, new_root: str,
                      now: int | None = None) -> dict:
        with self._lock:
            _require_aaguid(aaguid)
            if not isinstance(new_root, str) or not new_root.strip():
                raise AttestationError("ATTEST_INVALID", {
                    "new_root": new_root
                })

            current_now = self._now_seconds(now)
            old_anchors = self._active_anchors_locked(aaguid, current_now)
            overlap_until = current_now + self.overlap_seconds
            self._anchors[aaguid] = {
                "old_anchors": tuple(sorted(set(old_anchors))),
                "new_anchor": new_root,
                "overlap_until": overlap_until,
            }
            self._stats["rotations"] += 1
            self._evict_aaguid_cache(aaguid)
            return {
                "aaguid": aaguid,
                "new_root": new_root,
                "overlap_until": overlap_until,
            }

    def active_anchors(self, aaguid: str,
                       now: int | None = None) -> tuple:
        with self._lock:
            _require_aaguid(aaguid)
            current_now = self._now_seconds(now)
            return self._active_anchors_locked(aaguid, current_now)

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": _SNAPSHOT_VERSION,
                "rp_id": self.rp_id,
                "overlap_seconds": self.overlap_seconds,
                "policy": {
                    "order": list(self._policy_order),
                    "minimum": self.minimum,
                    "policy_version": self._policy_version,
                },
                "package_version": self._package_version,
                "metadata": self._metadata,
                "anchors": self._anchors,
                "quarantine": self._quarantine,
                "stats": self._stats,
            }
            return copy.deepcopy(state)

    @staticmethod
    def _parse_snapshot(state: object) -> dict:
        def invalid(detail: object) -> AttestationError:
            return AttestationError("ATTEST_SNAPSHOT", detail)

        if not isinstance(state, dict):
            raise invalid({"reason": "snapshot-not-mapping"})
        if state.get("version") != _SNAPSHOT_VERSION:
            raise invalid({"field": "version"})

        rp_id = state.get("rp_id")
        if not isinstance(rp_id, str) or not rp_id:
            raise invalid({"field": "rp_id"})

        overlap_seconds = state.get("overlap_seconds")
        if not _is_int(overlap_seconds) or overlap_seconds < 0:
            raise invalid({"field": "overlap_seconds"})

        policy_raw = state.get("policy")
        if not isinstance(policy_raw, dict):
            raise invalid({"field": "policy"})
        order_raw = policy_raw.get("order")
        try:
            policy_order = _normalize_order(order_raw)
        except AttestationError:
            raise invalid({"field": "policy.order"}) from None
        minimum = policy_raw.get("minimum")
        if minimum not in _FORMAT_STRENGTH:
            raise invalid({"field": "policy.minimum"})
        policy_version = policy_raw.get("policy_version")
        if not _is_int(policy_version) or policy_version < 0:
            raise invalid({"field": "policy.policy_version"})

        package_version = state.get("package_version")
        if not _is_int(package_version) or package_version < 0:
            raise invalid({"field": "package_version"})

        metadata_raw = state.get("metadata")
        if not isinstance(metadata_raw, dict):
            raise invalid({"field": "metadata"})
        metadata: dict[str, dict] = {}
        for stored_aaguid, raw_entry in metadata_raw.items():
            if not _valid_aaguid(stored_aaguid):
                raise invalid({"field": "metadata.aaguid"})
            try:
                record = _normalize_entry(raw_entry)
            except AttestationError:
                raise invalid({
                    "field": "metadata.entry",
                    "aaguid": stored_aaguid,
                }) from None
            if record["aaguid"] != stored_aaguid:
                raise invalid({"field": "metadata.aaguid-mismatch"})
            metadata[stored_aaguid] = record

        anchors_raw = state.get("anchors")
        if not isinstance(anchors_raw, dict):
            raise invalid({"field": "anchors"})
        anchors: dict[str, dict] = {}
        for stored_aaguid, raw_anchor in anchors_raw.items():
            if not _valid_aaguid(stored_aaguid):
                raise invalid({"field": "anchors.aaguid"})
            if not isinstance(raw_anchor, dict):
                raise invalid({"field": "anchors.record"})

            if "old_anchors" not in raw_anchor:
                raise invalid({"field": "anchors.old_anchors"})
            old_raw = raw_anchor["old_anchors"]
            if isinstance(old_raw, (str, bytes)) or not isinstance(
                    old_raw, Iterable):
                raise invalid({"field": "anchors.old_anchors"})
            old_anchors: list[str] = []
            try:
                for root in old_raw:
                    if not isinstance(root, str) or not root:
                        raise invalid({"field": "anchors.old_anchors"})
                    old_anchors.append(root)
            except TypeError:
                raise invalid({"field": "anchors.old_anchors"}) from None

            new_anchor = raw_anchor.get("new_anchor")
            if not isinstance(new_anchor, str) or not new_anchor:
                raise invalid({"field": "anchors.new_anchor"})
            overlap_until = raw_anchor.get("overlap_until")
            if not _is_int(overlap_until):
                raise invalid({"field": "anchors.overlap_until"})

            anchors[stored_aaguid] = {
                "old_anchors": tuple(sorted(set(old_anchors))),
                "new_anchor": new_anchor,
                "overlap_until": overlap_until,
            }

        quarantine_raw = state.get("quarantine")
        if not isinstance(quarantine_raw, dict):
            raise invalid({"field": "quarantine"})
        quarantine: dict[str, dict] = {}
        for stored_aaguid, raw_quarantine in quarantine_raw.items():
            if not _valid_aaguid(stored_aaguid):
                raise invalid({"field": "quarantine.aaguid"})
            if (not isinstance(raw_quarantine, dict)
                    or "reason" not in raw_quarantine):
                raise invalid({"field": "quarantine.record"})
            reason = copy.deepcopy(raw_quarantine["reason"])
            quarantined_at = raw_quarantine.get(
                "quarantined_at", raw_quarantine.get("at")
            )
            if quarantined_at is not None and not _is_int(
                    quarantined_at):
                raise invalid({"field": "quarantine.at"})
            quarantine[stored_aaguid] = {
                "reason": reason,
                "quarantined_at": quarantined_at,
            }

        stats_raw = state.get("stats")
        if not isinstance(stats_raw, dict):
            raise invalid({"field": "stats"})
        stats: dict[str, int] = {}
        for key in _STAT_KEYS:
            value = stats_raw.get(key)
            if not _is_int(value) or value < 0:
                raise invalid({"field": f"stats.{key}"})
            stats[key] = value

        return {
            "rp_id": rp_id,
            "overlap_seconds": overlap_seconds,
            "policy_order": policy_order,
            "minimum": minimum,
            "policy_version": policy_version,
            "package_version": package_version,
            "metadata": metadata,
            "anchors": anchors,
            "quarantine": quarantine,
            "stats": stats,
        }

    def restore(self, state: dict) -> None:
        with self._lock:
            restored = self._parse_snapshot(state)
            self.rp_id = restored["rp_id"]
            self.overlap_seconds = restored["overlap_seconds"]
            self.minimum = restored["minimum"]
            self._policy_order = restored["policy_order"]
            self._policy_version = restored["policy_version"]
            self._package_version = restored["package_version"]
            self._metadata = restored["metadata"]
            self._anchors = restored["anchors"]
            self._quarantine = restored["quarantine"]
            self._stats = restored["stats"]
            self._cache = {}

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
