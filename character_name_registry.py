"""Character name registry: normalized uniqueness, reservations, rename cooldowns."""

from __future__ import annotations

import copy
import math
import re
import threading
import unicodedata
from datetime import datetime, timedelta, timezone


class NameRegistryError(ValueError):
    """Raised when a naming operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


_SNAPSHOT_VERSION = 1
_SNAPSHOT_KEYS = frozenset({"version", "tokens", "names", "cooldowns", "stats"})
_STAT_KEYS = frozenset(
    {"reserved", "confirmed", "released", "expired", "renamed", "names"}
)
_TOKEN_PATTERN = re.compile(r"^n(\d+)$")
_WHITESPACE_PATTERN = re.compile(r"\s+")


class CharacterNameRegistry:
    """Reserve and confirm character/guild names in a normalized namespace."""

    MAX_TOTAL_NAMES = 1_000_000

    def __init__(self, *, token_ttl: int = 300, rename_cooldown: int = 86400,
                 max_tokens_per_owner: int = 3, max_name_length: int = 16,
                 min_name_length: int = 2, banned_words=None,
                 reserved_words=None) -> None:
        self.token_ttl = token_ttl
        self.rename_cooldown = rename_cooldown
        self.max_tokens_per_owner = max_tokens_per_owner
        self.max_name_length = max_name_length
        self.min_name_length = min_name_length
        self.banned_words = tuple(banned_words or ())
        self.reserved_words = tuple(reserved_words or ())
        self._banned_keys = frozenset(
            self.normalize(word) for word in self.banned_words
        )
        self._reserved_keys = frozenset(
            self.normalize(word) for word in self.reserved_words
        )
        self._lock = threading.RLock()
        self._clear_state()

    def _clear_state(self) -> None:
        self._tokens: dict[str, dict] = {}
        self._names: dict[str, dict] = {}
        self._cooldowns: dict[str, dict] = {}
        self._stats = {
            "reserved": 0,
            "confirmed": 0,
            "released": 0,
            "expired": 0,
            "renamed": 0,
            "names": 0,
        }
        self._key_tokens: dict[str, set[str]] = {}
        self._owner_tokens: dict[str, set[str]] = {}
        self._owner_names: dict[str, dict[str, None]] = {}

    def normalize(self, name: str) -> str:
        if not isinstance(name, str):
            raise NameRegistryError("NAME_INVALID", "name must be a string")

        normalized = unicodedata.normalize("NFKC", name)
        normalized = normalized.casefold()
        normalized = normalized.strip()
        normalized = _WHITESPACE_PATTERN.sub(" ", normalized)

        if not normalized:
            raise NameRegistryError("NAME_INVALID", "name must not be empty")
        return normalized

    def _validate_name(self, name: object) -> str:
        key = self.normalize(name)

        if len(key) > self.max_name_length:
            raise NameRegistryError(
                "NAME_TOO_LONG",
                {"length": len(key), "max_length": self.max_name_length},
            )

        valid_length = self.min_name_length <= len(key) <= self.max_name_length
        valid_characters = all(
            character.isalnum() or character in " -_"
            for character in key
        )
        if not valid_length or not valid_characters:
            raise NameRegistryError("NAME_INVALID", {"key": key})

        if key in self._banned_keys:
            raise NameRegistryError("NAME_BANNED", {"key": key})
        if key in self._reserved_keys:
            raise NameRegistryError("NAME_RESERVED", {"key": key})

        return key

    @staticmethod
    def _valid_owner(owner: object) -> bool:
        return isinstance(owner, str) and bool(owner.strip())

    @staticmethod
    def _parse_now(now: object) -> tuple[float, object]:
        if now is None:
            moment = datetime.now(timezone.utc)
            return moment.timestamp(), moment

        if isinstance(now, datetime):
            return now.timestamp(), now

        if isinstance(now, (int, float)):
            timestamp = float(now)
            if not math.isfinite(timestamp):
                raise NameRegistryError("NAME_INVALID", "invalid timestamp")
            return timestamp, now

        if isinstance(now, str):
            text = now.strip()
            if text.endswith(("Z", "z")):
                text = text[:-1] + "+00:00"
            moment = datetime.fromisoformat(text)
            return moment.timestamp(), moment

        raise NameRegistryError("NAME_INVALID", "invalid timestamp")

    @classmethod
    def _timestamp(cls, value: object) -> float:
        return cls._parse_now(value)[0]

    @staticmethod
    def _deadline_value(base: object, seconds: int) -> object:
        if isinstance(base, (int, float)):
            return base + seconds
        if isinstance(base, datetime):
            return (base + timedelta(seconds=seconds)).isoformat()
        raise NameRegistryError("NAME_INVALID", "invalid timestamp")

    def _token_is_active(self, token: dict, now_timestamp: float) -> bool:
        try:
            return self._timestamp(token["expires_at"]) > now_timestamp
        except (KeyError, TypeError, ValueError, NameRegistryError):
            return False

    def _active_token_for_key(self, key: str, now_timestamp: float):
        for token_id in tuple(self._key_tokens.get(key, ())):
            token = self._tokens.get(token_id)
            if token is not None and self._token_is_active(token, now_timestamp):
                return token
        return None

    def _active_cooldown(self, key: str, now_timestamp: float):
        cooldown = self._cooldowns.get(key)
        if cooldown is None:
            return None
        try:
            active = self._timestamp(cooldown["cooldown_until"]) > now_timestamp
        except (KeyError, TypeError, ValueError, NameRegistryError):
            active = False
        if not active:
            self._cooldowns.pop(key, None)
            return None
        return cooldown

    def _active_token_count_for_owner(
        self, owner: str, now_timestamp: float
    ) -> int:
        count = 0
        for token_id in tuple(self._owner_tokens.get(owner, ())):
            token = self._tokens.get(token_id)
            if token is not None and self._token_is_active(token, now_timestamp):
                count += 1
        return count

    def _index_token(self, token_id: str, key: str, owner: str) -> None:
        self._key_tokens.setdefault(key, set()).add(token_id)
        self._owner_tokens.setdefault(owner, set()).add(token_id)

    def _unindex_token(self, token_id: str, token: dict) -> None:
        key_ids = self._key_tokens.get(token["key"])
        if key_ids is not None:
            key_ids.discard(token_id)
            if not key_ids:
                self._key_tokens.pop(token["key"], None)

        owner_ids = self._owner_tokens.get(token["owner"])
        if owner_ids is not None:
            owner_ids.discard(token_id)
            if not owner_ids:
                self._owner_tokens.pop(token["owner"], None)

    def _index_name(self, key: str, owner: str) -> None:
        self._owner_names.setdefault(owner, {})[key] = None

    def _unindex_name(self, key: str, owner: str) -> None:
        key_map = self._owner_names.get(owner)
        if key_map is not None:
            key_map.pop(key, None)
            if not key_map:
                self._owner_names.pop(owner, None)

    def _current_name_record(self, owner: object):
        if not isinstance(owner, str):
            return None
        key_map = self._owner_names.get(owner)
        if not key_map:
            return None
        for key in reversed(key_map):
            record = self._names.get(key)
            if record is not None:
                return record
        return None

    def reserve(self, name: str, owner: str, *, now=None) -> dict:
        key = self._validate_name(name)
        if not self._valid_owner(owner):
            raise NameRegistryError("NAME_INVALID", "owner must be a non-empty string")

        now_timestamp, time_base = self._parse_now(now)
        expires_at = self._deadline_value(time_base, self.token_ttl)

        with self._lock:
            if key in self._names:
                raise NameRegistryError("NAME_TAKEN", {"key": key})

            if self._active_token_for_key(key, now_timestamp) is not None:
                raise NameRegistryError("NAME_TAKEN", {"key": key})

            cooldown = self._active_cooldown(key, now_timestamp)
            if cooldown is not None and cooldown.get("owner") != owner:
                raise NameRegistryError("NAME_TAKEN", {"key": key})

            active_tokens = self._active_token_count_for_owner(
                owner, now_timestamp
            )
            if active_tokens >= self.max_tokens_per_owner:
                raise NameRegistryError(
                    "NAME_CAPACITY_EXCEEDED",
                    {"owner": owner, "limit": self.max_tokens_per_owner},
                )

            if len(self._names) >= self.MAX_TOTAL_NAMES:
                raise NameRegistryError(
                    "NAME_CAPACITY_EXCEEDED", "total name limit reached"
                )

            token_number = int(self._stats["reserved"]) + 1
            token_id = f"n{token_number:06d}"
            token = {
                "token": token_id,
                "name": name,
                "key": key,
                "owner": owner,
                "expires_at": expires_at,
            }
            if cooldown is not None and cooldown.get("name"):
                token["canonical_name"] = cooldown["name"]

            self._tokens[token_id] = token
            self._index_token(token_id, key, owner)
            self._stats["reserved"] += 1
            return {
                field: token[field]
                for field in ("token", "name", "key", "owner", "expires_at")
            }

    def confirm(self, token: str, *, display_name=None, now=None) -> dict:
        now_timestamp, time_base = self._parse_now(now)

        with self._lock:
            record = self._tokens.get(token) if isinstance(token, str) else None
            if record is None:
                raise NameRegistryError("NAME_TOKEN_UNKNOWN", {"token": token})

            if not self._token_is_active(record, now_timestamp):
                raise NameRegistryError("NAME_TOKEN_UNKNOWN", {"token": token})

            if display_name is not None:
                display_key = self._validate_name(display_name)
                if display_key != record["key"]:
                    raise NameRegistryError(
                        "NAME_INVALID",
                        {"key": display_key, "expected_key": record["key"]},
                    )

            canonical_name = record.get("canonical_name")
            if canonical_name:
                confirmed_name = canonical_name
            elif display_name is not None:
                confirmed_name = display_name
            else:
                confirmed_name = record["name"]

            key = record["key"]
            if key in self._names:
                raise NameRegistryError("NAME_TAKEN", {"key": key})
            if len(self._names) >= self.MAX_TOTAL_NAMES:
                raise NameRegistryError(
                    "NAME_CAPACITY_EXCEEDED", "total name limit reached"
                )

            cooldown = self._active_cooldown(key, now_timestamp)
            if cooldown is not None and cooldown.get("owner") != record["owner"]:
                raise NameRegistryError("NAME_TAKEN", {"key": key})
            if not canonical_name and cooldown is not None and cooldown.get("name"):
                confirmed_name = cooldown["name"]

            confirmed_at = self._deadline_value(time_base, 0)
            confirmed = {
                "name": confirmed_name,
                "key": key,
                "owner": record["owner"],
                "confirmed_at": confirmed_at,
            }

            token_id = record["token"]
            self._tokens.pop(token_id, None)
            self._unindex_token(token_id, record)
            if cooldown is not None:
                self._cooldowns.pop(key, None)
            self._names[key] = confirmed
            self._index_name(key, confirmed["owner"])

            self._stats["confirmed"] += 1
            self._stats["names"] = len(self._names)
            return dict(confirmed)

    def release(self, token: str, owner: str) -> bool:
        with self._lock:
            record = self._tokens.get(token) if isinstance(token, str) else None
            if record is None:
                raise NameRegistryError("NAME_TOKEN_UNKNOWN", {"token": token})

            if record["owner"] != owner:
                raise NameRegistryError(
                    "NAME_OWNER_MISMATCH",
                    {"token": token, "owner": owner,
                     "token_owner": record["owner"]},
                )

            token_id = record["token"]
            self._tokens.pop(token_id, None)
            self._unindex_token(token_id, record)
            self._stats["released"] += 1
            return True

    def rename(self, owner: str, new_name: str, *, now=None) -> dict:
        now_timestamp, time_base = self._parse_now(now)

        with self._lock:
            current = self._current_name_record(owner)
            if current is None:
                raise NameRegistryError("NAME_OWNER_UNKNOWN", {"owner": owner})

            new_key = self._validate_name(new_name)
            previous_key = current["key"]
            if new_key == previous_key:
                raise NameRegistryError("NAME_UNCHANGED", {"key": new_key})

            if new_key in self._names:
                raise NameRegistryError("NAME_TAKEN", {"key": new_key})

            if self._active_token_for_key(new_key, now_timestamp) is not None:
                raise NameRegistryError("NAME_TAKEN", {"key": new_key})

            cooldown = self._active_cooldown(new_key, now_timestamp)
            if cooldown is not None and cooldown.get("owner") != owner:
                raise NameRegistryError("NAME_TAKEN", {"key": new_key})
            final_display_name = new_name
            if cooldown is not None and cooldown.get("name"):
                final_display_name = cooldown["name"]

            cooldown_until = self._deadline_value(
                time_base, self.rename_cooldown
            )
            renamed = dict(current)
            renamed["name"] = final_display_name
            renamed["key"] = new_key

            self._names.pop(previous_key, None)
            self._unindex_name(previous_key, current["owner"])
            self._names[new_key] = renamed
            self._index_name(new_key, current["owner"])

            self._cooldowns[previous_key] = {
                "owner": owner,
                "name": current["name"],
                "cooldown_until": cooldown_until,
            }
            self._cooldowns.pop(new_key, None)

            self._stats["renamed"] += 1
            self._stats["names"] = len(self._names)

            return {
                "owner": owner,
                "name": final_display_name,
                "key": new_key,
                "previous_key": previous_key,
                "cooldown_until": cooldown_until,
            }

    def lookup(self, name: str) -> dict:
        key = self.normalize(name)
        with self._lock:
            record = self._names.get(key)
            return dict(record) if record is not None else None

    def expire(self, now=None) -> int:
        now_timestamp, _ = self._parse_now(now)

        with self._lock:
            expired_tokens = []
            for token_id, token in list(self._tokens.items()):
                if not self._token_is_active(token, now_timestamp):
                    expired_tokens.append((token_id, token))

            for token_id, token in expired_tokens:
                self._tokens.pop(token_id, None)
                self._unindex_token(token_id, token)

            count = len(expired_tokens)
            self._stats["expired"] += count
            return count

    def owner_names(self, owner: str) -> list:
        with self._lock:
            key_map = self._owner_names.get(owner)
            if not key_map:
                return []
            names = [
                self._names[key]["name"]
                for key in key_map
                if key in self._names
            ]
            return sorted(names)

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": _SNAPSHOT_VERSION,
                "tokens": self._tokens,
                "names": self._names,
                "cooldowns": self._cooldowns,
                "stats": self._stats,
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                candidate = copy.deepcopy(state)
                tokens, names, cooldowns, stats = self._validate_snapshot(candidate)
            except NameRegistryError:
                raise
            except Exception as exc:
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid snapshot structure"
                ) from exc

            self._clear_state()
            self._tokens = tokens
            self._names = names
            self._cooldowns = cooldowns
            self._stats = stats
            self._rebuild_indexes()
            self._stats["names"] = len(self._names)

    def stats(self) -> dict:
        with self._lock:
            stats = dict(self._stats)
            stats["names"] = len(self._names)
            return stats

    def _rebuild_indexes(self) -> None:
        self._key_tokens = {}
        self._owner_tokens = {}
        self._owner_names = {}

        for token_id, token in self._tokens.items():
            self._index_token(token_id, token["key"], token["owner"])

        for key, record in self._names.items():
            self._index_name(key, record["owner"])

    @classmethod
    def _validate_snapshot(cls, state: object):
        if not isinstance(state, dict):
            raise NameRegistryError("NAME_SNAPSHOT_INVALID", "state must be a dict")
        if set(state.keys()) != _SNAPSHOT_KEYS:
            raise NameRegistryError(
                "NAME_SNAPSHOT_INVALID", "invalid top-level keys"
            )

        version = state["version"]
        if not cls._strict_int(version) or version != _SNAPSHOT_VERSION:
            raise NameRegistryError(
                "NAME_SNAPSHOT_INVALID", "unsupported version"
            )

        tokens = cls._validate_tokens(state["tokens"])
        names = cls._validate_names(state["names"])
        cooldowns = cls._validate_cooldowns(state["cooldowns"])
        stats = cls._validate_stats(state["stats"])

        max_token_number = 0
        for token_id in tokens:
            match = _TOKEN_PATTERN.fullmatch(token_id)
            if match is None:
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid token id"
                )
            max_token_number = max(max_token_number, int(match.group(1)))

        if stats["reserved"] < max_token_number:
            raise NameRegistryError(
                "NAME_SNAPSHOT_INVALID",
                "reserved counter is behind token sequence",
            )

        return tokens, names, cooldowns, stats

    @staticmethod
    def _strict_int(value: object) -> bool:
        return (
            isinstance(value, int)
            and not isinstance(value, bool)
            and value >= 0
        )

    @classmethod
    def _valid_timestamp_value(cls, value: object) -> bool:
        if isinstance(value, bool):
            return False
        if isinstance(value, datetime):
            return True
        if isinstance(value, (int, float)):
            return math.isfinite(float(value))
        if isinstance(value, str):
            try:
                cls._timestamp(value)
                return True
            except (NameRegistryError, TypeError, ValueError, OverflowError):
                return False
        return False

    @classmethod
    def _validate_tokens(cls, raw: object) -> dict:
        if not isinstance(raw, dict):
            raise NameRegistryError(
                "NAME_SNAPSHOT_INVALID", "tokens must be a dict"
            )

        tokens = {}
        for token_id, token in raw.items():
            if (
                not isinstance(token_id, str)
                or _TOKEN_PATTERN.fullmatch(token_id) is None
            ):
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid token id"
                )
            if not isinstance(token, dict):
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "token must be a dict"
                )

            required = ("token", "name", "key", "owner", "expires_at")
            if any(field not in token for field in required):
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "missing token field"
                )
            if token["token"] != token_id:
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "token id mismatch"
                )
            if not isinstance(token["name"], str) or not token["name"]:
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid token name"
                )
            if not isinstance(token["key"], str) or not token["key"]:
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid token key"
                )
            if not isinstance(token["owner"], str) or not token["owner"].strip():
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid token owner"
                )
            if not cls._valid_timestamp_value(token["expires_at"]):
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid token expiry"
                )

            cleaned = {field: token[field] for field in required}
            canonical_name = token.get("canonical_name")
            if canonical_name is not None:
                if not isinstance(canonical_name, str) or not canonical_name:
                    raise NameRegistryError(
                        "NAME_SNAPSHOT_INVALID", "invalid canonical token name"
                    )
                cleaned["canonical_name"] = canonical_name
            tokens[token_id] = cleaned
        return tokens

    @classmethod
    def _validate_names(cls, raw: object) -> dict:
        if not isinstance(raw, dict):
            raise NameRegistryError(
                "NAME_SNAPSHOT_INVALID", "names must be a dict"
            )

        names = {}
        for key, record in raw.items():
            if not isinstance(key, str) or not key:
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid name key"
                )
            if not isinstance(record, dict):
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "name must be a dict"
                )

            required = ("name", "key", "owner", "confirmed_at")
            if any(field not in record for field in required):
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "missing name field"
                )
            if record["key"] != key:
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "name key mismatch"
                )
            if not isinstance(record["name"], str) or not record["name"]:
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid display name"
                )
            if not isinstance(record["key"], str) or not record["key"]:
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid record key"
                )
            if not isinstance(record["owner"], str) or not record["owner"].strip():
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid name owner"
                )
            if not cls._valid_timestamp_value(record["confirmed_at"]):
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid confirmation time"
                )

            names[key] = {field: record[field] for field in required}
        return names

    @classmethod
    def _validate_cooldowns(cls, raw: object) -> dict:
        if not isinstance(raw, dict):
            raise NameRegistryError(
                "NAME_SNAPSHOT_INVALID", "cooldowns must be a dict"
            )

        cooldowns = {}
        for key, cooldown in raw.items():
            if not isinstance(key, str) or not key:
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid cooldown key"
                )
            if not isinstance(cooldown, dict):
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "cooldown must be a dict"
                )

            required = ("owner", "cooldown_until")
            if any(field not in cooldown for field in required):
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "missing cooldown field"
                )
            if (
                not isinstance(cooldown["owner"], str)
                or not cooldown["owner"].strip()
            ):
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid cooldown owner"
                )
            if not cls._valid_timestamp_value(cooldown["cooldown_until"]):
                raise NameRegistryError(
                    "NAME_SNAPSHOT_INVALID", "invalid cooldown expiry"
                )

            cleaned = {field: cooldown[field] for field in required}
            display_name = cooldown.get("name")
            if display_name is not None:
                if not isinstance(display_name, str) or not display_name:
                    raise NameRegistryError(
                        "NAME_SNAPSHOT_INVALID", "invalid cooldown name"
                    )
                cleaned["name"] = display_name
            cooldowns[key] = cleaned
        return cooldowns

    @classmethod
    def _validate_stats(cls, raw: object) -> dict:
        if not isinstance(raw, dict) or set(raw.keys()) != _STAT_KEYS:
            raise NameRegistryError(
                "NAME_SNAPSHOT_INVALID", "invalid stats"
            )
        if any(not cls._strict_int(value) for value in raw.values()):
            raise NameRegistryError(
                "NAME_SNAPSHOT_INVALID", "invalid stat value"
            )
        return dict(raw)
