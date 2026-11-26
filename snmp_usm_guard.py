"""SNMPv3 USM authoritative-engine guard: discovery, key localization, replay window."""

from __future__ import annotations

import hashlib
import hmac
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

__all__ = [
    "UsmError",
    "EngineContext",
    "LocalizedKey",
    "UsmReport",
    "UsmDecision",
    "SnmpUsmGuard",
]

MAX_ENGINE_BOOTS = 2147483647

SNAPSHOT_VERSION = 1
SNAPSHOT_KEYS = ("version", "engines", "keys", "window", "counters", "stats")
STAT_FIELDS = (
    "discovered",
    "localized",
    "accepted",
    "not_in_time_window",
    "replays",
    "auth_failures",
    "rotated",
    "expired_keys",
    "rate_limited",
)


class UsmError(ValueError):
    """Raised when a USM operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class EngineContext:
    engine_id: str
    boots: int
    engine_time: int
    restarts: int
    window_entries: int


@dataclass(frozen=True)
class LocalizedKey:
    engine_id: str
    user: str
    generation: int
    digest: str
    created_at: str
    expires_at: str | None
    send: bool
    recv: bool


@dataclass(frozen=True)
class UsmReport:
    msg_id: str
    engine_id: str
    user: str
    reason: str
    boots: int
    engine_time: int


@dataclass(frozen=True)
class UsmDecision:
    msg_id: str
    engine_id: str
    user: str
    accepted: bool
    reason: str
    boots: int
    engine_time: int
    generation: int


def _clamp_boots(value: int) -> int:
    if value < 0:
        return 0
    if value > MAX_ENGINE_BOOTS:
        return MAX_ENGINE_BOOTS
    return value


def _normalise_datetime(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _parse_datetime(value: object) -> datetime | None:
    if isinstance(value, datetime):
        return _normalise_datetime(value)
    if isinstance(value, str):
        text = value.strip()
        if not text:
            return None
        if text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            return _normalise_datetime(datetime.fromisoformat(text))
        except ValueError:
            return None
    return None


class SnmpUsmGuard:
    """Serve SNMPv3 USM discovery and verify authenticated requests per engine."""

    def __init__(self, *, time_window: int = 150, max_window_entries: int = 64,
                 per_user_limit: int = 20, rate_period: float = 60.0,
                 grace_seconds: float = 30.0, clock=None) -> None:
        self.time_window = time_window
        self.max_window_entries = max_window_entries
        self.per_user_limit = per_user_limit
        self.rate_period = rate_period
        self.grace_seconds = grace_seconds
        self._clock = clock or time.monotonic
        self._lock = threading.RLock()

        self._engines: dict[str, dict[str, Any]] = {}
        self._keys: dict[str, dict[str, dict[str, Any]]] = {}
        self._counters: dict[str, dict[str, dict[str, Any]]] = {}
        self._stats: dict[str, int] = {field: 0 for field in STAT_FIELDS}

    # ------------------------------------------------------------------
    # Internal helpers (all callers hold self._lock)
    # ------------------------------------------------------------------

    def _clock_value(self) -> float:
        return float(self._clock())

    def _require_engine(self, engine_id: str) -> dict[str, Any]:
        try:
            return self._engines[engine_id]
        except KeyError:
            raise UsmError("USM_UNKNOWN_ENGINE", engine_id) from None

    def _select_engine(self, engine_id: str | None) -> tuple[str, dict[str, Any]]:
        if engine_id is None:
            if not self._engines:
                raise UsmError("USM_UNKNOWN_ENGINE", engine_id)
            engine_id = next(iter(self._engines))
        return engine_id, self._require_engine(engine_id)

    def _engine_time_at(self, engine: dict[str, Any], now_clock: float) -> int:
        candidate = int(round(now_clock - engine["anchor"]))
        if candidate < 0:
            candidate = 0
        if candidate > engine["engine_time"]:
            engine["engine_time"] = candidate
        return engine["engine_time"]

    def _wall_time_at(self, engine: dict[str, Any],
                      engine_time: float) -> datetime:
        origin = engine.get("wall_origin")
        if isinstance(origin, datetime):
            return origin + timedelta(seconds=engine_time)
        return datetime.now(timezone.utc)

    def _metadata_time(self, engine: dict[str, Any]) -> str:
        return self._wall_time_at(engine, engine["engine_time"]).isoformat()

    def _expiry_metadata(self, engine: dict[str, Any], grace: float) -> str:
        return self._wall_time_at(
            engine, engine["engine_time"] + grace
        ).isoformat()

    def _structure_for_engine(self, engine_id: str) -> None:
        self._keys.setdefault(engine_id, {})
        self._counters.setdefault(
            engine_id, {"rates": {}, "last_rotation": {}}
        )

    def _derive_digest(self, engine_id: str, user: str, secret: str) -> str:
        material = (
            "snmp-usm-localized-key\0"
            + engine_id
            + "\0"
            + user
            + "\0"
            + str(secret)
        ).encode("utf-8")
        return hashlib.sha256(material).hexdigest()

    def _key_dataclass(self, engine_id: str, user: str,
                       key: dict[str, Any]) -> LocalizedKey:
        return LocalizedKey(
            engine_id=engine_id,
            user=user,
            generation=key["generation"],
            digest=key["digest"],
            created_at=key["created_at"],
            expires_at=key.get("expires_at"),
            send=key["send"],
            recv=key["recv"],
        )

    def _make_key(self, engine: dict[str, Any], engine_id: str, user: str,
                  secret: str, generation: int) -> dict[str, Any]:
        return {
            "generation": generation,
            "digest": self._derive_digest(engine_id, user, secret),
            "created_at": self._metadata_time(engine),
            "expires_at": None,
            "expires_clock": None,
            "send": True,
            "recv": True,
        }

    def _auth_failure(self, msg_id: str, engine_id: str, user: str,
                      boots: int, engine_time: int) -> None:
        self._stats["auth_failures"] += 1
        report = UsmReport(
            msg_id=msg_id,
            engine_id=engine_id,
            user=user,
            reason="authFailure",
            boots=boots,
            engine_time=engine_time,
        )
        raise UsmError("USM_AUTH_FAILURE_REPORT", report)

    def _consume_rate(self, engine_id: str, user: str, now_clock: float) -> None:
        counters = self._counters[engine_id]
        attempts = counters["rates"].setdefault(user, [])
        cutoff = now_clock - float(self.rate_period)
        while attempts and attempts[0] <= cutoff:
            attempts.pop(0)
        if len(attempts) >= self.per_user_limit:
            self._stats["rate_limited"] += 1
            raise UsmError(
                "USM_RATE_LIMITED",
                {"engine_id": engine_id, "user": user},
            )
        attempts.append(now_clock)

    def _find_key(self, engine_id: str, user: str, digest: str,
                  now_clock: float | None) -> dict[str, Any] | None:
        entry = self._keys.get(engine_id, {}).get(user)
        if entry is None:
            return None

        current = entry["current"]
        if self._digest_matches(digest, current["digest"]):
            return current

        for retired in reversed(entry["retired"]):
            if now_clock is not None:
                expires_clock = retired.get("expires_clock")
                if expires_clock is not None and now_clock >= expires_clock:
                    continue
            if self._digest_matches(digest, retired["digest"]):
                return retired
        return None

    def _digest_matches(self, candidate: object, expected: str) -> bool:
        if not isinstance(candidate, str):
            return False
        try:
            return hmac.compare_digest(candidate, expected)
        except TypeError:
            return False

    # ------------------------------------------------------------------
    # Engine and key management
    # ------------------------------------------------------------------

    def register_engine(self, engine_id: str, boots: int = 0,
                        now: str | None = None) -> EngineContext:
        with self._lock:
            now_clock = self._clock_value()
            wall_origin = _parse_datetime(now)
            engine = self._engines.get(engine_id)
            restarts = 0
            if engine is None:
                engine = {
                    "boots": _clamp_boots(int(boots)),
                    "restarts": 0,
                    "anchor": now_clock,
                    "engine_time": 0,
                    "wall_origin": wall_origin,
                    "window": OrderedDict(),
                }
                self._engines[engine_id] = engine
            else:
                restarts = engine["restarts"]
                engine["boots"] = _clamp_boots(int(boots))
                engine["anchor"] = now_clock
                engine["engine_time"] = 0
                if now is not None:
                    engine["wall_origin"] = wall_origin
            self._structure_for_engine(engine_id)
            return EngineContext(
                engine_id=engine_id,
                boots=engine["boots"],
                engine_time=engine["engine_time"],
                restarts=restarts,
                window_entries=len(engine["window"]),
            )

    def register_user(self, engine_id: str, user: str,
                      secret: str) -> LocalizedKey:
        with self._lock:
            engine = self._require_engine(engine_id)
            now_clock = self._clock_value()
            self._engine_time_at(engine, now_clock)

            existing = self._keys[engine_id].get(user)
            if existing is not None:
                current = existing["current"]
                wanted = self._derive_digest(engine_id, user, secret)
                if hmac.compare_digest(wanted, current["digest"]):
                    return self._key_dataclass(engine_id, user, current)
                raise UsmError(
                    "USM_KEY_ROTATION_CONFLICT",
                    {"engine_id": engine_id, "user": user},
                )

            key = self._make_key(engine, engine_id, user, secret, 1)
            self._keys[engine_id][user] = {
                "current": key,
                "retired": [],
            }
            return self._key_dataclass(engine_id, user, key)

    def discover(self, engine_id: str | None = None) -> dict:
        with self._lock:
            selected_id, engine = self._select_engine(engine_id)
            now_clock = self._clock_value()
            engine_time = self._engine_time_at(engine, now_clock)
            self._stats["discovered"] += 1
            return {
                "kind": "discovery_report",
                "engine_id": selected_id,
                "boots": engine["boots"],
                "engine_time": engine_time,
            }

    def localize_key(self, engine_id: str, user: str,
                     secret: str | None = None) -> LocalizedKey:
        with self._lock:
            _engine = self._require_engine(engine_id)
            entry = self._keys.get(engine_id, {}).get(user)
            if entry is None:
                raise UsmError("USM_UNKNOWN_USER", user)

            if secret is None:
                key = entry["current"]
            else:
                now_clock = self._clock_value()
                key = self._find_key(
                    engine_id,
                    user,
                    self._derive_digest(engine_id, user, secret),
                    now_clock,
                )
                if key is None:
                    self._auth_failure("", engine_id, user, 0, 0)

            self._stats["localized"] += 1
            return self._key_dataclass(engine_id, user, key)

    # ------------------------------------------------------------------
    # Request verification
    # ------------------------------------------------------------------

    def verify_request(self, msg_id: str, engine_id: str, user: str, boots: int,
                       engine_time: int, digest: str) -> UsmDecision:
        with self._lock:
            engine = self._require_engine(engine_id)
            now_clock = self._clock_value()
            self._consume_rate(engine_id, user, now_clock)

            key = self._find_key(engine_id, user, digest, now_clock)
            if key is None:
                self._auth_failure(
                    msg_id, engine_id, user, boots, engine_time,
                )

            local_time = self._engine_time_at(engine, now_clock)
            if (boots != engine["boots"]
                    or abs(engine_time - local_time) > self.time_window):
                self._stats["not_in_time_window"] += 1
                return UsmDecision(
                    msg_id=msg_id,
                    engine_id=engine_id,
                    user=user,
                    accepted=False,
                    reason="notInTimeWindow",
                    boots=boots,
                    engine_time=engine_time,
                    generation=key["generation"],
                )

            window = engine["window"]
            replay_key = (msg_id, boots, engine_time)
            if replay_key in window:
                self._stats["replays"] += 1
                return UsmDecision(
                    msg_id=msg_id,
                    engine_id=engine_id,
                    user=user,
                    accepted=False,
                    reason="replay",
                    boots=boots,
                    engine_time=engine_time,
                    generation=key["generation"],
                )

            window[replay_key] = None
            while len(window) > self.max_window_entries:
                window.popitem(last=False)

            self._stats["accepted"] += 1
            return UsmDecision(
                msg_id=msg_id,
                engine_id=engine_id,
                user=user,
                accepted=True,
                reason="ok",
                boots=boots,
                engine_time=engine_time,
                generation=key["generation"],
            )

    def rotate_key(self, engine_id: str, user: str,
                   secret: str) -> LocalizedKey:
        with self._lock:
            engine = self._require_engine(engine_id)
            entry = self._keys.get(engine_id, {}).get(user)
            if entry is None:
                raise UsmError("USM_UNKNOWN_USER", user)

            now_clock = self._clock_value()
            self._engine_time_at(engine, now_clock)
            rotation_state = self._counters[engine_id]["last_rotation"]
            last_rotation = rotation_state.get(user)
            if last_rotation is not None and now_clock <= last_rotation:
                raise UsmError(
                    "USM_KEY_ROTATION_CONFLICT",
                    {"engine_id": engine_id, "user": user},
                )

            current = entry["current"]
            retired = dict(current)
            retired["expires_clock"] = now_clock + float(self.grace_seconds)
            retired["expires_at"] = self._expiry_metadata(
                engine, float(self.grace_seconds)
            )
            entry["retired"].append(retired)

            new_generation = current["generation"] + 1
            new_key = self._make_key(
                engine, engine_id, user, secret, new_generation
            )
            entry["current"] = new_key
            rotation_state[user] = now_clock
            self._stats["rotated"] += 1
            return self._key_dataclass(engine_id, user, new_key)

    def expire_keys(self, now: str | None = None) -> int:
        with self._lock:
            now_clock = self._clock_value()
            wall_cutoff: datetime | None = None
            clock_cutoff: float | None = now_clock

            if isinstance(now, datetime):
                wall_cutoff = _normalise_datetime(now)
                clock_cutoff = None
            elif isinstance(now, (int, float)) and not isinstance(now, bool):
                clock_cutoff = float(now)
            elif isinstance(now, str):
                try:
                    clock_cutoff = float(now)
                except ValueError:
                    parsed = _parse_datetime(now)
                    if parsed is not None:
                        wall_cutoff = parsed
                        clock_cutoff = None

            removed = 0
            for users in self._keys.values():
                for entry in users.values():
                    keep: list[dict[str, Any]] = []
                    for retired in entry["retired"]:
                        expired = False
                        if wall_cutoff is not None:
                            expires_at = _parse_datetime(
                                retired.get("expires_at")
                            )
                            expired = (
                                expires_at is not None
                                and expires_at <= wall_cutoff
                            )
                        else:
                            expires_clock = retired.get("expires_clock")
                            expired = (
                                expires_clock is not None
                                and clock_cutoff is not None
                                and expires_clock <= clock_cutoff
                            )
                        if expired:
                            removed += 1
                        else:
                            keep.append(retired)
                    entry["retired"] = keep

            self._stats["expired_keys"] += removed
            return removed

    # ------------------------------------------------------------------
    # Engine lifecycle and windows
    # ------------------------------------------------------------------

    def restart(self, engine_id: str | None = None) -> EngineContext:
        with self._lock:
            selected_id, engine = self._select_engine(engine_id)
            now_clock = self._clock_value()
            engine["boots"] = _clamp_boots(engine["boots"] + 1)
            engine["restarts"] += 1
            engine["anchor"] = now_clock
            engine["engine_time"] = 0
            return EngineContext(
                engine_id=selected_id,
                boots=engine["boots"],
                engine_time=engine["engine_time"],
                restarts=engine["restarts"],
                window_entries=len(engine["window"]),
            )

    def purge_window(self, engine_id: str | None = None) -> int:
        with self._lock:
            if engine_id is not None:
                engine = self._require_engine(engine_id)
                removed = len(engine["window"])
                engine["window"].clear()
                return removed

            removed = 0
            for engine in self._engines.values():
                removed += len(engine["window"])
                engine["window"].clear()
            return removed

    def status(self, engine_id: str | None = None) -> dict:
        with self._lock:
            selected_id, engine = self._select_engine(engine_id)
            now_clock = self._clock_value()
            engine_time = self._engine_time_at(engine, now_clock)
            users = len(self._keys.get(selected_id, {}))
            key_count = sum(
                1 + len(entry["retired"])
                for entry in self._keys.get(selected_id, {}).values()
            )
            return {
                "engine_id": selected_id,
                "boots": engine["boots"],
                "engine_time": engine_time,
                "users": users,
                "keys": key_count,
                "window_entries": len(engine["window"]),
            }

    # ------------------------------------------------------------------
    # Snapshot / restore and counters
    # ------------------------------------------------------------------

    def _key_to_state(self, key: dict[str, Any]) -> dict[str, Any]:
        return {
            "generation": key["generation"],
            "digest": key["digest"],
            "created_at": key["created_at"],
            "expires_at": key.get("expires_at"),
            "expires_clock": key.get("expires_clock"),
            "send": key["send"],
            "recv": key["recv"],
        }

    def snapshot(self) -> dict:
        with self._lock:
            now_clock = self._clock_value()
            engines: dict[str, dict[str, Any]] = {}
            for engine_id, engine in self._engines.items():
                engine_time = self._engine_time_at(engine, now_clock)
                origin = engine.get("wall_origin")
                engines[engine_id] = {
                    "engine_id": engine_id,
                    "boots": engine["boots"],
                    "engine_time": engine_time,
                    "restarts": engine["restarts"],
                    "wall_origin": (
                        origin.isoformat()
                        if isinstance(origin, datetime)
                        else None
                    ),
                }

            keys: dict[str, dict[str, dict[str, Any]]] = {}
            for engine_id, users in self._keys.items():
                keys[engine_id] = {
                    user: {
                        "current": self._key_to_state(entry["current"]),
                        "retired": [
                            self._key_to_state(retired)
                            for retired in entry["retired"]
                        ],
                    }
                    for user, entry in users.items()
                }

            window: dict[str, list[dict[str, Any]]] = {}
            for engine_id, engine in self._engines.items():
                window[engine_id] = [
                    {
                        "msg_id": msg_id,
                        "boots": boots,
                        "engine_time": engine_time,
                    }
                    for msg_id, boots, engine_time in engine["window"]
                ]

            counters: dict[str, dict[str, Any]] = {}
            for engine_id, counter in self._counters.items():
                counters[engine_id] = {
                    "rates": {
                        user: list(attempts)
                        for user, attempts in counter["rates"].items()
                    },
                    "last_rotation": dict(counter["last_rotation"]),
                }

            return {
                "version": SNAPSHOT_VERSION,
                "engines": engines,
                "keys": keys,
                "window": window,
                "counters": counters,
                "stats": dict(self._stats),
            }

    def _snapshot_invalid(self, detail: object = None) -> UsmError:
        return UsmError("USM_SNAPSHOT_INVALID", detail)

    def _validate_key_state(self, key: object) -> dict[str, Any]:
        if not isinstance(key, dict):
            raise self._snapshot_invalid("key entry must be an object")
        generation = key.get("generation")
        digest = key.get("digest")
        created_at = key.get("created_at")
        send = key.get("send")
        recv = key.get("recv")
        expires_at = key.get("expires_at")
        expires_clock = key.get("expires_clock")

        if type(generation) is not int or generation < 1:
            raise self._snapshot_invalid("invalid key generation")
        if (not isinstance(digest, str) or len(digest) != 64
                or any(character not in "0123456789abcdef"
                       for character in digest)):
            raise self._snapshot_invalid("invalid key digest")
        if not isinstance(created_at, str):
            raise self._snapshot_invalid("invalid key created_at")
        if type(send) is not bool or type(recv) is not bool:
            raise self._snapshot_invalid("invalid key flags")
        if expires_at is not None and not isinstance(expires_at, str):
            raise self._snapshot_invalid("invalid key expires_at")
        if expires_clock is not None and (
                not isinstance(expires_clock, (int, float))
                or isinstance(expires_clock, bool)):
            raise self._snapshot_invalid("invalid key expires_clock")
        return {
            "generation": generation,
            "digest": digest,
            "created_at": created_at,
            "expires_at": expires_at,
            "expires_clock": (
                float(expires_clock)
                if expires_clock is not None
                else None
            ),
            "send": send,
            "recv": recv,
        }

    def restore(self, state: dict) -> None:
        try:
            if not isinstance(state, dict):
                raise self._snapshot_invalid("state must be an object")
            if set(state.keys()) != set(SNAPSHOT_KEYS):
                raise self._snapshot_invalid("snapshot keys mismatch")

            version = state.get("version")
            if type(version) is not int or version != SNAPSHOT_VERSION:
                raise self._snapshot_invalid("snapshot version mismatch")

            for name in ("engines", "keys", "window", "counters", "stats"):
                if not isinstance(state.get(name), dict):
                    raise self._snapshot_invalid(f"{name} must be an object")

            stats_in = state["stats"]
            new_stats: dict[str, int] = {}
            for field in STAT_FIELDS:
                value = stats_in.get(field)
                if type(value) is not int or value < 0:
                    raise self._snapshot_invalid(
                        f"invalid stat {field}"
                    )
                new_stats[field] = value

            new_engines: dict[str, dict[str, Any]] = {}
            for engine_id, engine in state["engines"].items():
                if not isinstance(engine_id, str) or not isinstance(engine, dict):
                    raise self._snapshot_invalid("invalid engine entry")
                boots = engine.get("boots")
                engine_time = engine.get("engine_time")
                restarts = engine.get("restarts", 0)
                origin_text = engine.get("wall_origin")
                if (type(boots) is not int
                        or boots < 0 or boots > MAX_ENGINE_BOOTS):
                    raise self._snapshot_invalid("invalid engine boots")
                if type(engine_time) is not int or engine_time < 0:
                    raise self._snapshot_invalid("invalid engine time")
                if type(restarts) is not int or restarts < 0:
                    raise self._snapshot_invalid("invalid engine restarts")
                if origin_text is not None and not isinstance(origin_text, str):
                    raise self._snapshot_invalid("invalid engine wall origin")
                new_engines[engine_id] = {
                    "boots": boots,
                    "restarts": restarts,
                    "anchor": 0.0,
                    "engine_time": engine_time,
                    "wall_origin": _parse_datetime(origin_text),
                    "window": OrderedDict(),
                }

            new_keys: dict[str, dict[str, dict[str, Any]]] = {
                engine_id: {} for engine_id in new_engines
            }
            for engine_id, users in state["keys"].items():
                if engine_id not in new_engines or not isinstance(users, dict):
                    raise self._snapshot_invalid("invalid keys entry")
                for user, entry in users.items():
                    if not isinstance(user, str) or not isinstance(entry, dict):
                        raise self._snapshot_invalid("invalid user key entry")
                    if "current" not in entry or "retired" not in entry:
                        raise self._snapshot_invalid("incomplete user key entry")
                    current = self._validate_key_state(entry["current"])
                    retired_in = entry["retired"]
                    if not isinstance(retired_in, list):
                        raise self._snapshot_invalid("invalid retired keys")
                    retired = [
                        self._validate_key_state(old)
                        for old in retired_in
                    ]
                    new_keys[engine_id][user] = {
                        "current": current,
                        "retired": retired,
                    }

            new_windows: dict[str, OrderedDict] = {
                engine_id: OrderedDict() for engine_id in new_engines
            }
            for engine_id, entries in state["window"].items():
                if engine_id not in new_engines or not isinstance(entries, list):
                    raise self._snapshot_invalid("invalid window entry")
                window = new_windows[engine_id]
                for item in entries:
                    if isinstance(item, dict):
                        msg_id = item.get("msg_id")
                        boots = item.get("boots")
                        engine_time = item.get("engine_time")
                    elif isinstance(item, (list, tuple)) and len(item) == 3:
                        msg_id, boots, engine_time = item
                    else:
                        raise self._snapshot_invalid(
                            "invalid replay window item"
                        )
                    if not isinstance(msg_id, str):
                        raise self._snapshot_invalid(
                            "invalid replay msg id"
                        )
                    if type(boots) is not int or type(engine_time) is not int:
                        raise self._snapshot_invalid(
                            "invalid replay time fields"
                        )
                    window[(msg_id, boots, engine_time)] = None
                while len(window) > self.max_window_entries:
                    window.popitem(last=False)

            new_counters: dict[str, dict[str, dict[str, Any]]] = {
                engine_id: {"rates": {}, "last_rotation": {}}
                for engine_id in new_engines
            }
            for engine_id, counter in state["counters"].items():
                if engine_id not in new_engines or not isinstance(counter, dict):
                    raise self._snapshot_invalid("invalid counters entry")
                rates_in = counter.get("rates", {})
                rotations_in = counter.get("last_rotation", {})
                if not isinstance(rates_in, dict):
                    raise self._snapshot_invalid("invalid rate counters")
                if not isinstance(rotations_in, dict):
                    raise self._snapshot_invalid("invalid rotation counters")

                rates: dict[str, list[float]] = {}
                for user, attempts in rates_in.items():
                    if not isinstance(user, str) or not isinstance(
                            attempts, list):
                        raise self._snapshot_invalid("invalid rate attempts")
                    converted: list[float] = []
                    for attempt in attempts:
                        if (not isinstance(attempt, (int, float))
                                or isinstance(attempt, bool)):
                            raise self._snapshot_invalid(
                                "invalid rate timestamp"
                            )
                        converted.append(float(attempt))
                    rates[user] = converted

                rotations: dict[str, float | None] = {}
                for user, last in rotations_in.items():
                    if not isinstance(user, str):
                        raise self._snapshot_invalid(
                            "invalid rotation user"
                        )
                    if last is not None and (
                            not isinstance(last, (int, float))
                            or isinstance(last, bool)):
                        raise self._snapshot_invalid(
                            "invalid rotation timestamp"
                        )
                    rotations[user] = (
                        float(last) if last is not None else None
                    )

                new_counters[engine_id] = {
                    "rates": rates,
                    "last_rotation": rotations,
                }

            now_clock = self._clock_value()
            for engine_id, engine in new_engines.items():
                engine["anchor"] = now_clock - engine["engine_time"]
                engine["window"] = new_windows[engine_id]

            self._engines = new_engines
            self._keys = new_keys
            self._counters = new_counters
            self._stats = new_stats
        except UsmError:
            raise
        except Exception as exc:
            raise self._snapshot_invalid(str(exc)) from None

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)
