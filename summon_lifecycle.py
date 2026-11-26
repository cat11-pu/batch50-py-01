"""Battle summon lifecycle ledger: owner caps, remaining time, cooldowns, offline reaping."""

from __future__ import annotations

import copy
import threading
from datetime import datetime, timezone


SNAPSHOT_VERSION = 1
SNAPSHOT_KEYS = ("version", "seq", "summons", "owners", "cooldowns", "stats")
RECORD_KEYS = frozenset({
    "summon_id", "seq", "owner", "kind", "remaining", "inherit", "created_at"
})
STATS_KEYS = (
    "summoned", "dismissed", "expired", "transferred",
    "reaped", "evicted", "refused",
)


class SummonError(ValueError):
    """Raised when a summon operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _clean_name(value: object, field: str) -> str:
    if not isinstance(value, str):
        raise SummonError(
            "SUMMON_INVALID_REQUEST",
            {"field": field, "reason": "must be a non-empty string"},
        )
    cleaned = value.strip()
    if not cleaned:
        raise SummonError(
            "SUMMON_INVALID_REQUEST",
            {"field": field, "reason": "must not be blank"},
        )
    return cleaned


def _lookup_name(value: object) -> object:
    return value.strip() if isinstance(value, str) else value


def _parse_iso(value: object) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO8601 string")
    text = value[:-1] + "+00:00" if value.endswith(("Z", "z")) else value
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _current_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _resolve_now(now: object) -> str:
    if now is None:
        return _current_iso()
    try:
        _parse_iso(now)
    except Exception as exc:
        raise SummonError(
            "SUMMON_INVALID_REQUEST",
            {"field": "now", "reason": "must be an ISO8601 UTC timestamp"},
        ) from exc
    return now


class SummonLifecycle:
    """Register combat summons, advance their clocks, and reap offline owners."""

    def __init__(self, *, per_owner_cap: int = 3, offline_grace: int = 30,
                 default_ttl: int = 60, default_cooldown: int = 10,
                 cooldowns=None) -> None:
        self.per_owner_cap = per_owner_cap
        self.offline_grace = offline_grace
        self.default_ttl = default_ttl
        self.default_cooldown = default_cooldown
        self.cooldowns = copy.deepcopy(dict(cooldowns or {}))
        self._lock = threading.RLock()
        self._seq = 0
        self._summons: dict[str, dict] = {}
        self._owners: dict[str, str | None] = {}
        self._cooldowns: dict[str, dict[str, int]] = {}
        self._stats = {key: 0 for key in STATS_KEYS}

    def summon(self, owner: str, kind: str, *, ttl=None, inherit: float = 1.0,
               now=None) -> dict:
        with self._lock:
            try:
                owner_name = _clean_name(owner, "owner")
                kind_name = _clean_name(kind, "kind")

                ttl_value = self.default_ttl if ttl is None else ttl
                if not _plain_int(ttl_value) or ttl_value <= 0:
                    raise SummonError(
                        "SUMMON_INVALID_REQUEST",
                        {"field": "ttl", "reason": "must be a positive integer"},
                    )

                if (isinstance(inherit, bool)
                        or not isinstance(inherit, (int, float))
                        or not 0 < inherit <= 1):
                    raise SummonError(
                        "SUMMON_INVALID_REQUEST",
                        {"field": "inherit", "reason": "must be in (0, 1]"},
                    )

                created_at = _resolve_now(now)
                owner_cooldowns = self._cooldowns.setdefault(owner_name, {})
                active_cooldown = owner_cooldowns.get(kind_name, 0)
                if active_cooldown > 0:
                    raise SummonError(
                        "SUMMON_COOLDOWN_ACTIVE",
                        {
                            "owner": owner_name,
                            "kind": kind_name,
                            "remaining": active_cooldown,
                        },
                    )

                self._make_room(owner_name)

                self._seq += 1
                summon_id = f"s{self._seq:04d}"
                record = {
                    "summon_id": summon_id,
                    "seq": self._seq,
                    "owner": owner_name,
                    "kind": kind_name,
                    "remaining": ttl_value,
                    "inherit": float(inherit),
                    "created_at": created_at,
                }
                self._summons[summon_id] = record
                owner_cooldowns[kind_name] = self._cooldown_duration(
                    owner_name, kind_name
                )
                self._stats["summoned"] += 1
                return dict(record)
            except SummonError:
                self._stats["refused"] += 1
                raise

    def dismiss(self, owner: str, summon_id: str) -> bool:
        with self._lock:
            try:
                record = self._get_record(summon_id)
                if record is None:
                    raise SummonError(
                        "SUMMON_UNKNOWN_SUMMON",
                        {"summon_id": summon_id},
                    )

                owner_name = _lookup_name(owner)
                if record["owner"] != owner_name:
                    raise SummonError(
                        "SUMMON_OWNER_MISMATCH",
                        {
                            "summon_id": summon_id,
                            "owner": owner_name,
                            "actual_owner": record["owner"],
                        },
                    )

                del self._summons[record["summon_id"]]
                self._stats["dismissed"] += 1
                return True
            except SummonError:
                self._stats["refused"] += 1
                raise

    def tick(self, seconds: int) -> list:
        with self._lock:
            try:
                if not _plain_int(seconds) or seconds <= 0:
                    raise SummonError(
                        "SUMMON_INVALID_REQUEST",
                        {"field": "seconds", "reason": "must be a positive integer"},
                    )

                expired = []
                for summon_id, record in list(self._summons.items()):
                    record["remaining"] -= seconds
                    if record["remaining"] <= 0:
                        expired.append(record)
                        del self._summons[summon_id]

                expired.sort(key=lambda record: record["seq"])
                self._stats["expired"] += len(expired)

                for cooldowns in self._cooldowns.values():
                    for kind, remaining in list(cooldowns.items()):
                        cooldowns[kind] = max(0, remaining - seconds)

                return [record["summon_id"] for record in expired]
            except SummonError:
                self._stats["refused"] += 1
                raise

    def transfer_owner(self, summon_id: str, new_owner: str, now=None) -> dict:
        with self._lock:
            try:
                record = self._get_record(summon_id)
                if record is None:
                    raise SummonError(
                        "SUMMON_UNKNOWN_SUMMON",
                        {"summon_id": summon_id},
                    )

                target_owner = _clean_name(new_owner, "new_owner")
                current_owner = record["owner"]
                if target_owner != current_owner:
                    self._make_room(target_owner)
                    moved_record = self._summons.pop(summon_id)
                    record["owner"] = target_owner
                    self._summons[summon_id] = moved_record
                    self._stats["transferred"] += 1

                return dict(record)
            except SummonError:
                self._stats["refused"] += 1
                raise

    def list_of(self, owner: str) -> list:
        owner_name = _lookup_name(owner)
        with self._lock:
            return [
                dict(record)
                for record in self._summons.values()
                if record["owner"] == owner_name
            ]

    def remaining_of(self, summon_id: str) -> int:
        with self._lock:
            try:
                record = self._get_record(summon_id)
                if record is None:
                    raise SummonError(
                        "SUMMON_UNKNOWN_SUMMON",
                        {"summon_id": summon_id},
                    )
                return record["remaining"]
            except SummonError:
                self._stats["refused"] += 1
                raise

    def cooldown_of(self, owner: str, kind: str) -> int:
        owner_name = _lookup_name(owner)
        kind_name = _lookup_name(kind)
        with self._lock:
            return max(0, self._cooldowns.get(owner_name, {}).get(kind_name, 0))

    def owner_offline(self, owner: str, now=None) -> dict:
        with self._lock:
            try:
                owner_name = _clean_name(owner, "owner")
                offline_at = _resolve_now(now)
                offline_marker = self._owners.setdefault(owner_name, offline_at)
                return {
                    "owner": owner_name,
                    "offline_at": offline_marker,
                }
            except SummonError:
                self._stats["refused"] += 1
                raise

    def owner_online(self, owner: str, now=None) -> None:
        owner_name = _lookup_name(owner)
        with self._lock:
            self._owners.pop(owner_name, None)

    def reap_owner(self, owner: str, now=None) -> int:
        with self._lock:
            try:
                owner_name = _clean_name(owner, "owner")
                if now is None:
                    current_time = datetime.now(timezone.utc)
                else:
                    try:
                        current_time = _parse_iso(now)
                    except Exception as exc:
                        raise SummonError(
                            "SUMMON_INVALID_REQUEST",
                            {"field": "now", "reason": "must be an ISO8601 timestamp"},
                        ) from exc

                offline_at = self._owners.get(owner_name)
                if offline_at is None:
                    return 0

                offline_duration = current_time - _parse_iso(offline_at)
                if offline_duration.total_seconds() < self.offline_grace:
                    return 0

                victims = [
                    summon_id
                    for summon_id, record in self._summons.items()
                    if record["owner"] == owner_name
                ]
                for summon_id in victims:
                    del self._summons[summon_id]

                self._stats["reaped"] += len(victims)
                return len(victims)
            except SummonError:
                self._stats["refused"] += 1
                raise

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": SNAPSHOT_VERSION,
                "seq": self._seq,
                "summons": copy.deepcopy(self._summons),
                "owners": copy.deepcopy(self._owners),
                "cooldowns": copy.deepcopy(self._cooldowns),
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        candidate = self._build_restore_candidate(state)
        with self._lock:
            self._seq = candidate["seq"]
            self._summons = candidate["summons"]
            self._owners = candidate["owners"]
            self._cooldowns = candidate["cooldowns"]
            self._stats = candidate["stats"]

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _get_record(self, summon_id: object):
        try:
            return self._summons.get(summon_id)
        except TypeError:
            return None

    def _rows_for(self, owner: str) -> list[dict]:
        return [
            record
            for record in self._summons.values()
            if record["owner"] == owner
        ]

    def _make_room(self, owner: str) -> None:
        cap = self.per_owner_cap
        if not _plain_int(cap) or cap <= 0:
            return

        while True:
            rows = self._rows_for(owner)
            if len(rows) < cap:
                return
            victim = min(rows, key=lambda record: (
                record["remaining"], record["seq"]
            ))
            del self._summons[victim["summon_id"]]
            self._stats["evicted"] += 1

    def _cooldown_duration(self, owner: str, kind: str) -> int:
        config = self.cooldowns
        candidates = [
            config.get((owner, kind)),
            config.get(f"{owner}:{kind}"),
            config.get(kind),
            config.get(owner),
        ]

        kind_config = config.get(kind)
        if isinstance(kind_config, dict):
            candidates.extend((
                kind_config.get(owner),
                kind_config.get("*"),
                kind_config.get("default"),
            ))

        owner_config = config.get(owner)
        if isinstance(owner_config, dict):
            candidates.append(owner_config.get(kind))

        for value in candidates:
            if _plain_int(value) and value >= 0:
                return value

        return self.default_cooldown if _plain_int(self.default_cooldown) else 0

    @classmethod
    def _build_restore_candidate(cls, state: object) -> dict:
        try:
            data = copy.deepcopy(state)
        except Exception as exc:
            raise SummonError(
                "SUMMON_SNAPSHOT_INVALID",
                "snapshot must be a plain dictionary",
            ) from exc

        def invalid(detail: object = None) -> SummonError:
            return SummonError("SUMMON_SNAPSHOT_INVALID", detail)

        if not isinstance(data, dict) or set(data.keys()) != set(SNAPSHOT_KEYS):
            raise invalid("snapshot must contain exactly the supported keys")

        version = data["version"]
        if not _plain_int(version) or version != SNAPSHOT_VERSION:
            raise invalid("unsupported snapshot version")

        seq = data["seq"]
        if not _plain_int(seq) or seq < 0:
            raise invalid("seq must be a non-negative integer")

        summons_data = data["summons"]
        if not isinstance(summons_data, dict):
            raise invalid("summons must be a dictionary")

        summons = {}
        sequences = set()
        max_seq = 0
        for key, record in summons_data.items():
            if not isinstance(key, str) or not isinstance(record, dict):
                raise invalid("each summon must map a string id to a record")
            if set(record.keys()) != RECORD_KEYS:
                raise invalid("summon record has invalid fields")
            if not isinstance(record["summon_id"], str):
                raise invalid("summon_id must be a string")
            if record["summon_id"] != key:
                raise invalid("summon_id must match its snapshot key")

            record_seq = record["seq"]
            if not _plain_int(record_seq) or record_seq <= 0:
                raise invalid("summon seq must be a positive integer")
            if record_seq in sequences:
                raise invalid("summon seq values must be unique")

            owner = record["owner"]
            kind = record["kind"]
            if not isinstance(owner, str) or not owner.strip():
                raise invalid("summon owner must be a non-empty string")
            if not isinstance(kind, str) or not kind.strip():
                raise invalid("summon kind must be a non-empty string")

            remaining = record["remaining"]
            if not _plain_int(remaining) or remaining <= 0:
                raise invalid("remaining must be a positive integer")

            inherit = record["inherit"]
            if (isinstance(inherit, bool)
                    or not isinstance(inherit, (int, float))
                    or not 0 < inherit <= 1):
                raise invalid("inherit must be in (0, 1]")

            if not isinstance(record["created_at"], str):
                raise invalid("created_at must be an ISO8601 string")
            try:
                _parse_iso(record["created_at"])
            except Exception as exc:
                raise invalid("created_at must be an ISO8601 timestamp") from exc

            sequences.add(record_seq)
            max_seq = max(max_seq, record_seq)
            summons[key] = copy.deepcopy(record)

        if seq < max_seq:
            raise invalid("seq must not be behind the newest summon seq")

        owners_data = data["owners"]
        if not isinstance(owners_data, dict):
            raise invalid("owners must be a dictionary")

        owners: dict[str, str | None] = {}
        for owner, profile in owners_data.items():
            if not isinstance(owner, str) or not owner.strip():
                raise invalid("owner key must be a non-empty string")

            if isinstance(profile, dict):
                if set(profile.keys()) != {"offline_at"}:
                    raise invalid("owner profile must contain offline_at")
                offline_at = profile["offline_at"]
            elif profile is None or isinstance(profile, str):
                offline_at = profile
            else:
                raise invalid("owner profile has an invalid type")

            if offline_at is not None:
                if not isinstance(offline_at, str):
                    raise invalid("offline_at must be an ISO8601 string or null")
                try:
                    _parse_iso(offline_at)
                except Exception as exc:
                    raise invalid("offline_at must be an ISO8601 timestamp") from exc

            owners[owner] = offline_at

        cooldowns_data = data["cooldowns"]
        if not isinstance(cooldowns_data, dict):
            raise invalid("cooldowns must be a dictionary")

        cooldowns = {}
        for owner, kinds in cooldowns_data.items():
            if not isinstance(owner, str) or not owner.strip():
                raise invalid("cooldown owner must be a non-empty string")
            if not isinstance(kinds, dict):
                raise invalid("cooldowns for an owner must be a dictionary")

            normalized_kinds = {}
            for kind, remaining in kinds.items():
                if not isinstance(kind, str) or not kind.strip():
                    raise invalid("cooldown kind must be a non-empty string")
                if not _plain_int(remaining) or remaining < 0:
                    raise invalid("cooldown remaining must be a non-negative integer")
                normalized_kinds[kind] = remaining
            cooldowns[owner] = normalized_kinds

        stats_data = data["stats"]
        if not isinstance(stats_data, dict) or set(stats_data.keys()) != set(STATS_KEYS):
            raise invalid("stats must contain exactly the supported counters")

        stats = {}
        for key in STATS_KEYS:
            value = stats_data[key]
            if not _plain_int(value) or value < 0:
                raise invalid(f"stats.{key} must be a non-negative integer")
            stats[key] = value

        return {
            "seq": seq,
            "summons": summons,
            "owners": owners,
            "cooldowns": cooldowns,
            "stats": stats,
        }
