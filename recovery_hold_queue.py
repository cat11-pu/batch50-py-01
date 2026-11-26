"""Delayed account recovery: hold queue, multi-channel confirmation, veto and release."""

from __future__ import annotations

import copy
import hashlib
import hmac
import threading
import time


_STAT_KEYS = ("requests", "merged", "confirmations", "vetoes", "releases", "expired")
_HOLD_STATES = frozenset({"pending", "released", "vetoed", "expired"})


class RecoveryError(ValueError):
    """Refused recovery operation carrying a stable machine-readable code."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _token_digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


class RecoveryHoldQueue:
    """Hold self-service account recovery requests until the waiting period elapses."""

    def __init__(self, *, hold_seconds: int = 172800, confirmations_required: int = 2,
                 max_channels: int = 3, clock=None) -> None:
        self.hold_seconds = hold_seconds
        self.confirmations_required = confirmations_required
        self.max_channels = max_channels
        self._clock = clock
        self._lock = threading.RLock()
        self._holds: dict[str, dict] = {}
        self._next_hold_number = 1
        self._credential_counter = 0
        self._stats = {key: 0 for key in _STAT_KEYS}

    def request(self, account_id: str, channels, *,
                now: int | None = None) -> dict:
        with self._lock:
            current_time = self._time(now)
            normalized_channels = self._validate_channels(account_id, channels)
            existing = self._pending_hold_for_account(account_id)
            if existing is not None:
                existing["merged"] = True
                self._stats["merged"] += 1
                return self._request_payload(existing, merged=True)

            number = self._next_hold_number
            self._next_hold_number += 1
            hold_id = f"hold-{number}"
            tokens = self._tokens_for_channels(normalized_channels)
            hold = {
                "hold_id": hold_id,
                "account_id": account_id,
                "channels": normalized_channels,
                "state": "pending",
                "created_at": current_time,
                "due_at": current_time + int(self.hold_seconds),
                "required": int(self.confirmations_required),
                "confirmations": 0,
                "confirmed_at": {},
                "token_digests": {
                    channel: _token_digest(token)
                    for channel, token in tokens.items()
                },
                "merged": False,
                "vetoed_by": None,
                "veto_reason": None,
                "vetoed_at": None,
                "released_at": None,
                "credential_number": None,
                "expired_at": None,
            }
            self._holds[hold_id] = hold
            self._stats["requests"] += 1
            return self._request_payload(hold, merged=False)

    def confirm_contact(self, hold_id: str, channel: str, token: str, *,
                        now: int | None = None) -> dict:
        with self._lock:
            current_time = self._time(now)
            hold = self._get_hold(hold_id)
            if hold["state"] != "pending":
                raise RecoveryError("RECOVERY_CLOSED", {"hold_id": hold_id})
            if not isinstance(channel, str) or channel not in hold["channels"]:
                raise RecoveryError("RECOVERY_CHANNEL", {
                    "hold_id": hold_id,
                    "channel": channel,
                })

            digest = hold["token_digests"].get(channel)
            supplied_digest = _token_digest(token) if isinstance(token, str) else None
            if (digest is None or supplied_digest is None or
                    not hmac.compare_digest(digest, supplied_digest)):
                raise RecoveryError("RECOVERY_TOKEN", {
                    "hold_id": hold_id,
                    "channel": channel,
                })

            confirmed_at = hold["confirmed_at"]
            already = channel in confirmed_at
            if not already:
                confirmed_at[channel] = current_time
                hold["confirmations"] = len(confirmed_at)
                self._stats["confirmations"] += 1

            return {
                "hold_id": hold_id,
                "channel": channel,
                "confirmed_at": confirmed_at[channel],
                "confirmations": hold["confirmations"],
                "required": hold["required"],
                "already": already,
            }

    def veto(self, hold_id: str, actor: str, reason: str, *,
             now: int | None = None) -> dict:
        with self._lock:
            current_time = self._time(now)
            hold = self._get_hold(hold_id)
            if (not isinstance(actor, str) or not actor.strip() or
                    not isinstance(reason, str) or not reason.strip()):
                raise RecoveryError("RECOVERY_INVALID", {
                    "hold_id": hold_id,
                    "field": "actor/reason",
                })
            return self._apply_veto(hold, actor, reason, current_time)

    def record_login(self, account_or_hold: str | None = None, *,
                     account_id: str | None = None,
                     hold_id: str | None = None,
                     actor: str = "owner-login",
                     reason: str = "owner authenticated during recovery hold",
                     now: int | None = None) -> dict | None:
        """Treat the real owner's login during an active hold as an automatic veto."""
        with self._lock:
            current_time = self._time(now)
            hold = None
            target_hold_id = hold_id
            target_account_id = account_id

            if target_hold_id is None and account_or_hold is not None:
                if isinstance(account_or_hold, str) and account_or_hold in self._holds:
                    target_hold_id = account_or_hold
                else:
                    target_account_id = account_or_hold

            if target_hold_id is not None:
                hold = self._holds.get(target_hold_id)
            elif target_account_id is not None:
                hold = self._pending_hold_for_account(target_account_id)

            if hold is None or hold["state"] != "pending":
                return None
            return self._apply_veto(hold, actor, reason, current_time)

    owner_logged_in = record_login
    owner_login = record_login
    notify_owner_login = record_login
    notify_login = record_login
    register_login = record_login
    report_login = record_login
    handle_login = record_login
    on_login = record_login
    login = record_login

    def release(self, hold_id: str, *, now: int | None = None) -> dict:
        with self._lock:
            current_time = self._time(now)
            hold = self._get_hold(hold_id)
            return self._release_locked(hold, current_time)

    def status(self, hold_id: str, *, now: int | None = None) -> dict:
        with self._lock:
            current_time = self._time(now)
            hold = self._get_hold(hold_id)
            return {
                "hold_id": hold["hold_id"],
                "state": hold["state"],
                "due_at": hold["due_at"],
                "remaining": max(0, hold["due_at"] - current_time),
                "confirmations": hold["confirmations"],
                "required": hold["required"],
                "channels": tuple(hold["channels"]),
            }

    def due_holds(self, *, now: int | None = None) -> list[str]:
        with self._lock:
            current_time = self._time(now)
            due = [
                hold for hold in self._holds.values()
                if hold["state"] == "pending" and hold["due_at"] <= current_time
            ]
            due.sort(key=lambda hold: (hold["due_at"], hold["hold_id"]))
            return [hold["hold_id"] for hold in due]

    def sweep(self, *, now: int | None = None) -> dict:
        released = 0
        expired = 0
        credentials: dict[str, str] = {}

        with self._lock:
            current_time = self._time(now)
            for hold_id in self.due_holds(now=current_time):
                hold = self._holds[hold_id]
                if hold["state"] != "pending" or hold["due_at"] > current_time:
                    continue

                if hold["confirmations"] >= hold["required"]:
                    result = self._release_locked(hold, current_time)
                    released += 1
                    credentials[hold_id] = result["credential"]
                else:
                    hold["state"] = "expired"
                    hold["expired_at"] = current_time
                    self._stats["expired"] += 1
                    expired += 1

        return {
            "released": released,
            "expired": expired,
            "credentials": credentials,
        }

    def hold_view(self, hold_id: str) -> dict:
        with self._lock:
            hold = self._get_hold(hold_id)
            return {
                "hold_id": hold["hold_id"],
                "account_id": hold["account_id"],
                "channels": tuple(hold["channels"]),
                "state": hold["state"],
                "created_at": hold["created_at"],
                "due_at": hold["due_at"],
                "confirmations": hold["confirmations"],
                "required": hold["required"],
                "token_digests": dict(hold["token_digests"]),
                "merged": hold["merged"],
            }

    def snapshot(self) -> dict:
        with self._lock:
            holds = copy.deepcopy(self._holds)
            for hold in holds.values():
                hold["channels"] = list(hold["channels"])

            stats = dict(self._stats)
            counters = {
                "next_hold_number": self._next_hold_number,
                "hold_sequence": self._next_hold_number - 1,
                "holds_created": self._next_hold_number - 1,
                "used_credentials": self._credential_counter,
                "credential_counter": self._credential_counter,
                "used_credential_count": self._credential_counter,
                "credential_count": self._credential_counter,
                "credentials_issued": self._credential_counter,
                **stats,
            }
            return {
                "version": 1,
                "holds": holds,
                "counters": counters,
                "stats": stats,
                "next_hold_number": self._next_hold_number,
                "used_credentials": self._credential_counter,
                "credential_counter": self._credential_counter,
                "used_credential_count": self._credential_counter,
                "credential_count": self._credential_counter,
                "credentials_issued": self._credential_counter,
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                data = copy.deepcopy(state)
            except Exception as exc:
                raise RecoveryError("RECOVERY_SNAPSHOT", {"reason": "unreadable"}) from exc

            if not isinstance(data, dict):
                raise RecoveryError("RECOVERY_SNAPSHOT", {"reason": "state-not-object"})
            if data.get("version", 1) != 1:
                raise RecoveryError("RECOVERY_SNAPSHOT", {"reason": "unsupported-version"})
            if "holds" not in data:
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "holds"})

            try:
                holds = self._holds_from_snapshot(data["holds"])
                next_hold_number, credential_counter, stats = self._counters_from_snapshot(
                    data, holds
                )
            except RecoveryError:
                raise
            except Exception as exc:
                raise RecoveryError("RECOVERY_SNAPSHOT", {"reason": "invalid-state"}) from exc

            self._holds = holds
            self._next_hold_number = next_hold_number
            self._credential_counter = credential_counter
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _time(self, now: int | None) -> int:
        if now is None:
            clock = self._clock
            if callable(clock):
                now = clock()
            elif clock is not None:
                clock_now = getattr(clock, "now", None)
                clock_time = getattr(clock, "time", None)
                if callable(clock_now):
                    now = clock_now()
                elif callable(clock_time):
                    now = clock_time()
                else:
                    now = clock
            else:
                now = time.time()
        try:
            return int(now)
        except (TypeError, ValueError, OverflowError) as exc:
            raise RecoveryError("RECOVERY_INVALID", {"now": now}) from exc

    def _validate_channels(self, account_id: str, channels) -> tuple[str, ...]:
        if not isinstance(account_id, str) or not account_id.strip():
            raise RecoveryError("RECOVERY_INVALID", {"field": "account_id"})

        if channels is None or isinstance(channels, (str, bytes, bytearray)):
            raise RecoveryError("RECOVERY_INVALID", {"field": "channels"})
        try:
            channel_list = list(channels)
        except TypeError as exc:
            raise RecoveryError("RECOVERY_INVALID", {"field": "channels"}) from exc

        if not channel_list:
            raise RecoveryError("RECOVERY_INVALID", {"field": "channels"})
        for channel in channel_list:
            if not isinstance(channel, str) or not channel.strip():
                raise RecoveryError("RECOVERY_INVALID", {"field": "channel"})

        normalized = tuple(sorted(set(channel_list)))
        if len(normalized) > int(self.max_channels):
            raise RecoveryError("RECOVERY_INVALID", {
                "field": "channels",
                "max_channels": self.max_channels,
            })
        return normalized

    def _pending_hold_for_account(self, account_id: str) -> dict | None:
        if not isinstance(account_id, str):
            return None
        for hold in self._holds.values():
            if hold["account_id"] == account_id and hold["state"] == "pending":
                return hold
        return None

    def _get_hold(self, hold_id: str) -> dict:
        hold = self._holds.get(hold_id) if isinstance(hold_id, str) else None
        if hold is None:
            raise RecoveryError("RECOVERY_UNKNOWN", {"hold_id": hold_id})
        return hold

    @staticmethod
    def _hold_number(hold_id: str) -> int:
        try:
            return int(hold_id.rsplit("-", 1)[1])
        except (IndexError, ValueError, AttributeError):
            return 0

    @staticmethod
    def _tokens_for_channels(channels: tuple[str, ...]) -> dict[str, str]:
        return {
            channel: f"tok-{index}"
            for index, channel in enumerate(channels, start=1)
        }

    def _request_payload(self, hold: dict, *, merged: bool) -> dict:
        return {
            "hold_id": hold["hold_id"],
            "account_id": hold["account_id"],
            "channels": tuple(hold["channels"]),
            "state": hold["state"],
            "created_at": hold["created_at"],
            "due_at": hold["due_at"],
            "confirmations": hold["confirmations"],
            "required": hold["required"],
            "tokens": self._tokens_for_channels(tuple(hold["channels"])),
            "merged": merged,
        }

    def _apply_veto(self, hold: dict, actor: str, reason: str,
                    current_time: int) -> dict:
        if hold["state"] != "pending":
            raise RecoveryError("RECOVERY_CLOSED", {"hold_id": hold["hold_id"]})
        hold["state"] = "vetoed"
        hold["vetoed_by"] = actor
        hold["veto_reason"] = reason
        hold["vetoed_at"] = current_time
        self._stats["vetoes"] += 1
        return {
            "hold_id": hold["hold_id"],
            "state": "vetoed",
            "vetoed_by": actor,
            "vetoed_at": current_time,
        }

    def _release_locked(self, hold: dict, current_time: int) -> dict:
        hold_id = hold["hold_id"]
        if hold["state"] != "pending":
            raise RecoveryError("RECOVERY_CLOSED", {"hold_id": hold_id})
        if current_time < hold["due_at"]:
            raise RecoveryError("RECOVERY_HOLD", {
                "hold_id": hold_id,
                "remaining": hold["due_at"] - current_time,
            })
        if hold["confirmations"] < hold["required"]:
            raise RecoveryError("RECOVERY_PENDING", {
                "hold_id": hold_id,
                "confirmations": hold["confirmations"],
                "required": hold["required"],
            })

        self._credential_counter += 1
        credential_number = self._credential_counter
        hold["state"] = "released"
        hold["released_at"] = current_time
        hold["credential_number"] = credential_number
        self._stats["releases"] += 1
        return {
            "hold_id": hold_id,
            "state": "released",
            "released_at": current_time,
            "credential": f"cred-{credential_number}",
        }

    def _holds_from_snapshot(self, raw_holds: object) -> dict[str, dict]:
        if isinstance(raw_holds, dict):
            raw_items = list(raw_holds.items())
        elif isinstance(raw_holds, (list, tuple)):
            raw_items = [(None, item) for item in raw_holds]
        else:
            raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "holds"})

        holds: dict[str, dict] = {}
        for raw_key, raw_hold in raw_items:
            if not isinstance(raw_hold, dict):
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "holds[]"})

            hold_id = raw_hold.get("hold_id")
            if not isinstance(hold_id, str) or not hold_id.strip():
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "hold_id"})
            if raw_key is not None and raw_key != hold_id:
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "holds key"})
            if hold_id in holds:
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "duplicate hold_id"})

            account_id = raw_hold.get("account_id")
            if not isinstance(account_id, str) or not account_id.strip():
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "account_id"})

            raw_channels = raw_hold.get("channels")
            if not isinstance(raw_channels, (list, tuple)) or not raw_channels:
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "channels"})
            if any(not isinstance(channel, str) or not channel.strip()
                   for channel in raw_channels):
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "channels[]"})
            if len(set(raw_channels)) != len(raw_channels):
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "channels duplicate"})
            if list(raw_channels) != sorted(raw_channels):
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "channels order"})
            channels = tuple(raw_channels)

            state = raw_hold.get("state")
            if state not in _HOLD_STATES:
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "state"})

            created_at = self._snapshot_int(raw_hold.get("created_at"), "created_at")
            due_at = self._snapshot_int(raw_hold.get("due_at"), "due_at")
            required_value = raw_hold.get("required", self.confirmations_required)
            required = self._snapshot_int(required_value, "required", minimum=0)

            raw_digests = raw_hold.get("token_digests")
            if not isinstance(raw_digests, dict):
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "token_digests"})
            token_digests = {}
            for channel in channels:
                digest = raw_digests.get(channel)
                if not isinstance(digest, str) or not digest:
                    raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "token_digests"})
                token_digests[channel] = digest

            raw_confirmed = raw_hold.get("confirmed_at", {})
            if not isinstance(raw_confirmed, dict):
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "confirmed_at"})
            confirmed_at = {}
            for channel, confirmed_time in raw_confirmed.items():
                if channel not in channels:
                    raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "confirmed channel"})
                confirmed_at[channel] = self._snapshot_int(
                    confirmed_time, "confirmed_at", minimum=0
                )

            confirmation_count = raw_hold.get("confirmations", len(confirmed_at))
            confirmation_count = self._snapshot_int(
                confirmation_count, "confirmations", minimum=0
            )
            if confirmation_count != len(confirmed_at):
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "confirmations"})

            merged = raw_hold.get("merged", False)
            if not isinstance(merged, bool):
                raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "merged"})

            vetoed_by = raw_hold.get("vetoed_by")
            vetoed_at = raw_hold.get("vetoed_at")
            released_at = raw_hold.get("released_at")
            credential_number = raw_hold.get("credential_number")
            expired_at = raw_hold.get("expired_at")

            if state == "vetoed":
                if not isinstance(vetoed_by, str) or not vetoed_by.strip():
                    raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "vetoed_by"})
                vetoed_at = self._snapshot_int(vetoed_at, "vetoed_at")
            elif vetoed_by is not None:
                if not isinstance(vetoed_by, str):
                    raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "vetoed_by"})
            if vetoed_at is not None:
                vetoed_at = self._snapshot_int(vetoed_at, "vetoed_at")

            if state == "released":
                released_at = self._snapshot_int(released_at, "released_at")
                credential_number = self._snapshot_int(
                    credential_number, "credential_number", minimum=1
                )
            else:
                if released_at is not None:
                    released_at = self._snapshot_int(released_at, "released_at")
                if credential_number is not None:
                    credential_number = self._snapshot_int(
                        credential_number, "credential_number", minimum=1
                    )

            if state == "expired":
                expired_at = self._snapshot_int(expired_at, "expired_at")
            elif expired_at is not None:
                expired_at = self._snapshot_int(expired_at, "expired_at")

            holds[hold_id] = {
                "hold_id": hold_id,
                "account_id": account_id,
                "channels": channels,
                "state": state,
                "created_at": created_at,
                "due_at": due_at,
                "required": required,
                "confirmations": len(confirmed_at),
                "confirmed_at": confirmed_at,
                "token_digests": token_digests,
                "merged": merged,
                "vetoed_by": vetoed_by,
                "veto_reason": raw_hold.get("veto_reason"),
                "vetoed_at": vetoed_at,
                "released_at": released_at,
                "credential_number": credential_number,
                "expired_at": expired_at,
            }

        return holds

    def _counters_from_snapshot(
        self, data: dict, holds: dict[str, dict]
    ) -> tuple[int, int, dict[str, int]]:
        counters = data.get("counters", {})
        if counters is None:
            counters = {}
        if not isinstance(counters, dict):
            raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "counters"})

        stats_source = data.get("stats", {})
        if stats_source is None:
            stats_source = {}
        if not isinstance(stats_source, dict):
            raise RecoveryError("RECOVERY_SNAPSHOT", {"field": "stats"})

        stats = {}
        for key in _STAT_KEYS:
            value = self._lookup_snapshot_value(
                key, (stats_source, counters, data), default=0
            )
            stats[key] = self._snapshot_int(value, f"stats.{key}", minimum=0)

        explicit_next = self._lookup_snapshot_value(
            "next_hold_number", (counters, data), default=None
        )
        if explicit_next is None:
            explicit_next = self._lookup_snapshot_value(
                "next_hold_id", (counters, data), default=1
            )
        next_hold_number = self._snapshot_int(
            explicit_next, "counters.next_hold_number", minimum=1
        )

        last_hold_number = self._lookup_snapshot_value(
            "hold_sequence", (counters, data), default=None
        )
        if last_hold_number is not None:
            next_from_sequence = self._snapshot_int(
                last_hold_number, "counters.hold_sequence", minimum=0
            ) + 1
            next_hold_number = max(next_hold_number, next_from_sequence)

        max_hold_number = max(
            (self._hold_number(hold_id) for hold_id in holds),
            default=0,
        )
        next_hold_number = max(next_hold_number, max_hold_number + 1)

        credential_value = None
        for credential_key in (
            "used_credentials",
            "used_credential_count",
            "credential_counter",
            "credential_count",
            "credentials_issued",
        ):
            credential_value = self._lookup_snapshot_value(
                credential_key, (counters, data), default=None
            )
            if credential_value is not None:
                break
        if credential_value is None:
            credential_value = 0
        credential_counter = self._snapshot_int(
            credential_value, "used_credentials", minimum=0
        )
        credential_counter = max(credential_counter, stats["releases"])
        for hold in holds.values():
            number = hold.get("credential_number")
            if _is_int(number):
                credential_counter = max(credential_counter, number)

        return next_hold_number, credential_counter, stats

    @staticmethod
    def _lookup_snapshot_value(key: str, sources: tuple[dict, ...], default=None):
        for source in sources:
            if isinstance(source, dict) and key in source:
                return source[key]
        return default

    @staticmethod
    def _snapshot_int(value: object, field: str, *, minimum: int | None = None) -> int:
        if not _is_int(value):
            raise RecoveryError("RECOVERY_SNAPSHOT", {"field": field})
        if minimum is not None and value < minimum:
            raise RecoveryError("RECOVERY_SNAPSHOT", {"field": field})
        return value
