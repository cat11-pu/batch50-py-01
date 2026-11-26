"""Canary token registry: issuance, hit dedup windows, batch revocation cascade."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class CanaryError(ValueError):
    """Raised when a registry operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STATE_ACTIVE = "active"
STATE_TRIGGERED = "triggered"
STATE_REVOKED = "revoked"

TOKEN_STATES = (STATE_ACTIVE, STATE_TRIGGERED, STATE_REVOKED)

CODE_BAD_REQUEST = "CANARY_BAD_REQUEST"
CODE_DUPLICATE_TOKEN = "CANARY_DUPLICATE_TOKEN"
CODE_UNKNOWN_TOKEN = "CANARY_UNKNOWN_TOKEN"
CODE_UNKNOWN_BATCH = "CANARY_UNKNOWN_BATCH"
CODE_SNAPSHOT_INVALID = "CANARY_SNAPSHOT_INVALID"

SNAPSHOT_VERSION = 1
HIT_FREEZE_REASON = "canary_hit"
STATS_KEYS = ("issued", "hits", "deduped", "escalated", "revoked", "frozen")
STATE_RANK = {
    STATE_ACTIVE: 0,
    STATE_TRIGGERED: 1,
    STATE_REVOKED: 2,
}


def _nonempty_string(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _parse_datetime(value: Any) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str) and value.strip():
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise CanaryError(CODE_BAD_REQUEST, {"field": "now"}) from exc
    else:
        raise CanaryError(CODE_BAD_REQUEST, {"field": "now"})

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _normalize_time(value: Any) -> str:
    return _parse_datetime(value).isoformat()


def _snapshot_time(value: Any) -> str | None:
    if value is None:
        return None
    try:
        return _normalize_time(value)
    except CanaryError as exc:
        raise CanaryError(CODE_SNAPSHOT_INVALID, {"field": "timestamp"}) from exc


@dataclass(frozen=True)
class CanaryToken:
    token_id: str
    purpose: str
    placement: str
    batch_id: str
    owner: str
    issued_at: str
    state: str
    hits: int
    last_hit_at: str | None
    revoked_at: str | None
    revoke_reason: str | None
    assets: tuple


class CanaryTokenRegistry:
    """Register decoy tokens, dedupe hit reports and cascade revocations."""

    def __init__(self, *, hit_window_seconds: int = 300) -> None:
        if (isinstance(hit_window_seconds, bool)
                or not isinstance(hit_window_seconds, (int, float))
                or hit_window_seconds < 0):
            raise CanaryError(CODE_BAD_REQUEST,
                              {"field": "hit_window_seconds"})
        self.hit_window_seconds = hit_window_seconds
        self._lock = threading.RLock()
        self._tokens: dict[str, dict] = {}
        self._assets: dict[str, list[str]] = {}
        self._frozen: dict[str, dict] = {}
        self._stats = {
            "issued": 0,
            "hits": 0,
            "deduped": 0,
            "escalated": 0,
            "revoked": 0,
            "frozen": 0,
        }

    def issue(self, token_id: str, *, purpose: str, placement: str,
              batch_id: str, owner: str, now: str) -> CanaryToken:
        fields = (
            ("token_id", token_id),
            ("purpose", purpose),
            ("placement", placement),
            ("batch_id", batch_id),
            ("owner", owner),
        )
        for field_name, value in fields:
            if not _nonempty_string(value):
                raise CanaryError(CODE_BAD_REQUEST, {"field": field_name})

        issued_at = _normalize_time(now)

        with self._lock:
            if token_id in self._tokens:
                raise CanaryError(
                    CODE_DUPLICATE_TOKEN, {"token_id": token_id})

            record = {
                "token_id": token_id,
                "purpose": purpose,
                "placement": placement,
                "batch_id": batch_id,
                "owner": owner,
                "issued_at": issued_at,
                "state": STATE_ACTIVE,
                "hits": 0,
                "last_hit_at": None,
                "revoked_at": None,
                "revoke_reason": None,
            }
            self._tokens[token_id] = record
            self._assets[token_id] = []
            self._stats["issued"] += 1
            return self._to_token_locked(record)

    def bind_asset(self, token_id: str, asset_id: str) -> tuple:
        if not _nonempty_string(asset_id):
            raise CanaryError(CODE_BAD_REQUEST, {"field": "asset_id"})

        with self._lock:
            self._get_token_locked(token_id)
            assets = self._assets.setdefault(token_id, [])
            if asset_id not in assets:
                assets.append(asset_id)
                assets.sort()
            return tuple(assets)

    def report_hit(self, token_id: str, *, source: str, now: str) -> dict:
        hit_at = _normalize_time(now)

        with self._lock:
            token = self._get_token_locked(token_id)
            token["hits"] += 1
            self._stats["hits"] += 1

            deduped = self._is_duplicate_hit_locked(token, hit_at)
            token["last_hit_at"] = hit_at

            result = {
                "token_id": token_id,
                "deduped": deduped,
                "hits": token["hits"],
                "cascaded": 0,
            }

            if deduped:
                self._stats["deduped"] += 1
                return result

            self._stats["escalated"] += 1

            if token["state"] == STATE_REVOKED:
                self._freeze_assets_locked(token_id, HIT_FREEZE_REASON)
                return result

            if token["state"] == STATE_ACTIVE:
                token["state"] = STATE_TRIGGERED

            self._freeze_assets_locked(
                token_id, HIT_FREEZE_REASON)
            cascade = self._cascade_batch_locked(
                token["batch_id"],
                reason=HIT_FREEZE_REASON,
                now=hit_at,
                only_active=True,
                exclude_token_id=token_id,
            )
            result["cascaded"] = cascade["revoked"]
            return result

    def revoke(self, token_id: str, *, reason: str, now: str) -> dict:
        if not isinstance(reason, str):
            raise CanaryError(CODE_BAD_REQUEST, {"field": "reason"})
        revoked_at = _normalize_time(now)

        with self._lock:
            token = self._get_token_locked(token_id)
            if token["state"] == STATE_REVOKED:
                frozen_assets = self._freeze_assets_locked(
                    token_id, reason)
                return {
                    "token_id": token_id,
                    "changed": False,
                    "frozen_assets": frozen_assets,
                }

            token["state"] = STATE_REVOKED
            token["revoked_at"] = revoked_at
            token["revoke_reason"] = reason
            self._stats["revoked"] += 1
            frozen_assets = self._freeze_assets_locked(
                token_id, reason)
            return {
                "token_id": token_id,
                "changed": True,
                "frozen_assets": frozen_assets,
            }

    def cascade(self, batch_id: str, *, reason: str, now: str) -> dict:
        if not isinstance(reason, str):
            raise CanaryError(CODE_BAD_REQUEST, {"field": "reason"})
        cascaded_at = _normalize_time(now)

        with self._lock:
            if not any(token["batch_id"] == batch_id
                       for token in self._tokens.values()):
                raise CanaryError(
                    CODE_UNKNOWN_BATCH, {"batch_id": batch_id})

            result = self._cascade_batch_locked(
                batch_id,
                reason=reason,
                now=cascaded_at,
                only_active=False,
            )
            return {
                "batch_id": batch_id,
                "revoked": result["revoked"],
                "already_revoked": result["already_revoked"],
                "frozen_assets": result["frozen_assets"],
            }

    def status(self, token_id: str) -> dict:
        with self._lock:
            token = self._get_token_locked(token_id)
            return {
                "token_id": token["token_id"],
                "purpose": token["purpose"],
                "placement": token["placement"],
                "batch_id": token["batch_id"],
                "owner": token["owner"],
                "issued_at": token["issued_at"],
                "state": token["state"],
                "hits": token["hits"],
                "last_hit_at": token["last_hit_at"],
                "revoked_at": token["revoked_at"],
                "revoke_reason": token["revoke_reason"],
                "assets": tuple(self._assets.get(token_id, [])),
            }

    def tokens(self, *, batch_id: str | None = None) -> list:
        with self._lock:
            records = [
                token for token in self._tokens.values()
                if batch_id is None or token["batch_id"] == batch_id
            ]
            records.sort(key=lambda token: token["token_id"])
            return [self._to_token_locked(token) for token in records]

    def frozen_assets(self) -> list:
        with self._lock:
            asset_ids = sorted(self._frozen)
            return [copy.deepcopy(self._frozen[asset_id])
                    for asset_id in asset_ids]

    def snapshot(self) -> dict:
        with self._lock:
            token_ids = sorted(self._tokens)
            state = {
                "version": SNAPSHOT_VERSION,
                "tokens": [
                    copy.deepcopy(self._tokens[token_id])
                    for token_id in token_ids
                ],
                "assets": {
                    token_id: list(self._assets.get(token_id, []))
                    for token_id in token_ids
                },
                "frozen": [
                    copy.deepcopy(self._frozen[asset_id])
                    for asset_id in sorted(self._frozen)
                ],
                "stats": copy.deepcopy(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        restored = self._parse_snapshot(state)

        with self._lock:
            for token_id, token in restored["tokens"].items():
                current = self._tokens.get(token_id)
                if current is not None and (
                        STATE_RANK[token["state"]]
                        < STATE_RANK[current["state"]]):
                    raise CanaryError(
                        CODE_SNAPSHOT_INVALID,
                        {
                            "token_id": token_id,
                            "reason": "state_would_regress",
                        },
                    )

            self._tokens = restored["tokens"]
            self._assets = restored["assets"]
            self._frozen = restored["frozen"]
            self._stats = restored["stats"]

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _get_token_locked(self, token_id: str) -> dict:
        try:
            return self._tokens[token_id]
        except KeyError:
            raise CanaryError(
                CODE_UNKNOWN_TOKEN, {"token_id": token_id}) from None
        except TypeError:
            raise CanaryError(
                CODE_UNKNOWN_TOKEN, {"token_id": token_id}) from None

    def _to_token_locked(self, token: dict) -> CanaryToken:
        return CanaryToken(
            token_id=token["token_id"],
            purpose=token["purpose"],
            placement=token["placement"],
            batch_id=token["batch_id"],
            owner=token["owner"],
            issued_at=token["issued_at"],
            state=token["state"],
            hits=token["hits"],
            last_hit_at=token["last_hit_at"],
            revoked_at=token["revoked_at"],
            revoke_reason=token["revoke_reason"],
            assets=tuple(self._assets.get(token["token_id"], [])),
        )

    def _is_duplicate_hit_locked(self, token: dict, hit_at: str) -> bool:
        if token["last_hit_at"] is None:
            return False
        previous = _parse_datetime(token["last_hit_at"])
        current = _parse_datetime(hit_at)
        elapsed = (current - previous).total_seconds()
        return elapsed <= self.hit_window_seconds

    def _freeze_assets_locked(
            self, token_id: str, reason: str) -> int:
        newly_frozen = 0
        for asset_id in self._assets.get(token_id, []):
            if asset_id in self._frozen:
                continue
            self._frozen[asset_id] = {
                "asset_id": asset_id,
                "token_id": token_id,
                "reason": reason,
            }
            newly_frozen += 1
            self._stats["frozen"] += 1
        return newly_frozen

    def _cascade_batch_locked(
            self,
            batch_id: str,
            *,
            reason: str,
            now: str,
            only_active: bool,
            exclude_token_id: str | None = None) -> dict:
        revoked = 0
        already_revoked = 0
        frozen_assets = 0

        for token_id in sorted(self._tokens):
            token = self._tokens[token_id]
            if token["batch_id"] != batch_id:
                continue
            if token_id == exclude_token_id:
                continue

            if token["state"] == STATE_REVOKED:
                already_revoked += 1
                frozen_assets += self._freeze_assets_locked(
                    token_id, reason)
                continue

            if only_active and token["state"] != STATE_ACTIVE:
                continue

            token["state"] = STATE_REVOKED
            token["revoked_at"] = now
            token["revoke_reason"] = reason
            self._stats["revoked"] += 1
            revoked += 1
            frozen_assets += self._freeze_assets_locked(
                token_id, reason)

        return {
            "revoked": revoked,
            "already_revoked": already_revoked,
            "frozen_assets": frozen_assets,
        }

    def _parse_snapshot(self, state: Any) -> dict:
        if not isinstance(state, dict):
            raise CanaryError(CODE_SNAPSHOT_INVALID)

        required = {"version", "tokens", "assets", "frozen", "stats"}
        if not required.issubset(state):
            raise CanaryError(CODE_SNAPSHOT_INVALID)

        version = state["version"]
        if isinstance(version, bool) or version != SNAPSHOT_VERSION:
            raise CanaryError(CODE_SNAPSHOT_INVALID, {"field": "version"})

        raw_tokens = state["tokens"]
        if not isinstance(raw_tokens, list):
            raise CanaryError(CODE_SNAPSHOT_INVALID, {"field": "tokens"})

        tokens: dict[str, dict] = {}
        text_fields = (
            "token_id", "purpose", "placement", "batch_id", "owner",
        )
        for raw_token in raw_tokens:
            if not isinstance(raw_token, dict):
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"field": "tokens"})

            for field_name in text_fields:
                if not _nonempty_string(raw_token.get(field_name)):
                    raise CanaryError(
                        CODE_SNAPSHOT_INVALID, {"field": field_name})

            token_id = raw_token["token_id"]
            if token_id in tokens:
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"token_id": token_id})

            state_name = raw_token.get("state")
            if state_name not in TOKEN_STATES:
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"field": "state"})

            hits = raw_token.get("hits")
            if isinstance(hits, bool) or not isinstance(hits, int) \
                    or hits < 0:
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"field": "hits"})

            issued_at = _snapshot_time(raw_token.get("issued_at"))
            if issued_at is None:
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"field": "issued_at"})
            last_hit_at = _snapshot_time(raw_token.get("last_hit_at"))
            revoked_at = _snapshot_time(raw_token.get("revoked_at"))

            revoke_reason = raw_token.get("revoke_reason")
            if revoke_reason is not None and not isinstance(
                    revoke_reason, str):
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"field": "revoke_reason"})

            if state_name == STATE_REVOKED:
                if revoked_at is None or not isinstance(
                        revoke_reason, str):
                    raise CanaryError(CODE_SNAPSHOT_INVALID,
                                      {"field": "revocation"})
            elif revoked_at is not None or revoke_reason is not None:
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"field": "revocation"})

            if last_hit_at is not None and hits == 0:
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"field": "last_hit_at"})
            if state_name == STATE_TRIGGERED and last_hit_at is None:
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"field": "state"})

            tokens[token_id] = {
                "token_id": token_id,
                "purpose": raw_token["purpose"],
                "placement": raw_token["placement"],
                "batch_id": raw_token["batch_id"],
                "owner": raw_token["owner"],
                "issued_at": issued_at,
                "state": state_name,
                "hits": hits,
                "last_hit_at": last_hit_at,
                "revoked_at": revoked_at,
                "revoke_reason": revoke_reason,
            }

        raw_assets = state["assets"]
        if not isinstance(raw_assets, dict):
            raise CanaryError(CODE_SNAPSHOT_INVALID, {"field": "assets"})

        assets: dict[str, list[str]] = {
            token_id: [] for token_id in tokens
        }
        for token_id, raw_asset_ids in raw_assets.items():
            if not isinstance(token_id, str) or token_id not in tokens:
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"field": "assets"})
            if not isinstance(raw_asset_ids, (list, tuple)):
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"token_id": token_id})

            asset_ids: list[str] = []
            for asset_id in raw_asset_ids:
                if not _nonempty_string(asset_id):
                    raise CanaryError(CODE_SNAPSHOT_INVALID,
                                      {"field": "asset_id"})
                if asset_id not in asset_ids:
                    asset_ids.append(asset_id)
            asset_ids.sort()
            assets[token_id] = asset_ids

        raw_frozen = state["frozen"]
        if not isinstance(raw_frozen, (list, tuple)):
            raise CanaryError(CODE_SNAPSHOT_INVALID, {"field": "frozen"})

        frozen: dict[str, dict] = {}
        for raw_freeze in raw_frozen:
            if not isinstance(raw_freeze, dict):
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"field": "frozen"})

            asset_id = raw_freeze.get("asset_id")
            token_id = raw_freeze.get("token_id")
            reason = raw_freeze.get("reason")
            if not _nonempty_string(asset_id) \
                    or not _nonempty_string(token_id) \
                    or not isinstance(reason, str):
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"field": "frozen"})
            if token_id not in tokens \
                    or asset_id not in assets.get(token_id, []):
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"field": "frozen"})
            if tokens[token_id]["state"] == STATE_ACTIVE:
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"field": "frozen"})
            if asset_id in frozen:
                raise CanaryError(CODE_SNAPSHOT_INVALID,
                                  {"asset_id": asset_id})

            freeze = {
                "asset_id": asset_id,
                "token_id": token_id,
                "reason": reason,
            }
            frozen[asset_id] = freeze

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict) \
                or set(raw_stats) != set(STATS_KEYS):
            raise CanaryError(CODE_SNAPSHOT_INVALID, {"field": "stats"})

        stats = {}
        for key in STATS_KEYS:
            value = raw_stats[key]
            if isinstance(value, bool) or not isinstance(value, int) \
                    or value < 0:
                raise CanaryError(CODE_SNAPSHOT_INVALID, {"field": key})
            stats[key] = value

        return {"tokens": tokens, "assets": assets,
                "frozen": frozen, "stats": stats}
