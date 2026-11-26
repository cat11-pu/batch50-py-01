"""SAE commit/confirm pairing, anti-clogging tokens and PMF association gate."""

from __future__ import annotations

import secrets
import threading
import time
from dataclasses import dataclass


class SaeError(ValueError):
    """Raised when an SAE operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CommitOutcome:
    status: str
    mac: str
    handshake_id: int
    token_consumed: bool


@dataclass(frozen=True)
class ConfirmOutcome:
    status: str
    mac: str
    handshake_id: int


@dataclass(frozen=True)
class AssocDecision:
    mac: str
    allowed: bool
    protected: bool
    reason: str


@dataclass
class _PeerRecord:
    state: str
    scalar: int
    handshake_id: int
    created_at: float
    tokenless_commits: int = 0
    associated: bool = False
    protected: bool = False


@dataclass
class _TokenRecord:
    token: str
    issued_at: float
    consumed: bool = False


class SaeCommitWarden:
    """Track SAE handshakes per peer MAC and gate association on PMF."""

    _STAT_KEYS = (
        "commits", "duplicates", "tokens_issued", "tokens_consumed",
        "token_rejections", "confirms", "confirm_failures", "pmf_denied",
        "purged",
    )
    _PEER_FIELDS = frozenset((
        "state", "scalar", "handshake_id", "created_at",
        "tokenless_commits", "associated", "protected",
    ))
    _TOKEN_FIELDS = frozenset(("token", "issued_at", "consumed"))

    def __init__(self, *, commit_threshold: int = 3, token_ttl: int = 30,
                 handshake_ttl: int = 120, max_pending: int = 256,
                 transition_mode: bool = False) -> None:
        self.commit_threshold = commit_threshold
        self.token_ttl = token_ttl
        self.handshake_ttl = handshake_ttl
        self.max_pending = max_pending
        self.transition_mode = transition_mode
        self._lock = threading.RLock()
        self._peers: dict[str, _PeerRecord] = {}
        self._tokens: dict[str, _TokenRecord] = {}
        self._next_handshake_id = 0
        self._counters = {key: 0 for key in self._STAT_KEYS}

    @staticmethod
    def _now(now) -> float:
        return time.monotonic() if now is None else now

    @staticmethod
    def _valid_mac(mac) -> bool:
        return isinstance(mac, str) and bool(mac.strip())

    @staticmethod
    def _is_int(value) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    def _new_handshake_id(self) -> int:
        self._next_handshake_id += 1
        return self._next_handshake_id

    def on_commit(self, mac: str, scalar, token=None, now=None) -> CommitOutcome:
        if not self._valid_mac(mac) or not self._is_int(scalar):
            raise SaeError("SAE_INVALID_REQUEST",
                           {"mac": mac, "scalar": scalar})
        with self._lock:
            current = self._peers.get(mac)
            token_record = self._validate_token(mac, token, now) \
                if token is not None else None

            if (current is not None and current.state == "pending"
                    and current.scalar == scalar):
                self._counters["duplicates"] += 1
                return CommitOutcome("duplicate", mac,
                                     current.handshake_id, False)

            if token_record is None:
                quota_used = current.tokenless_commits if current else 0
                if quota_used >= self.commit_threshold:
                    return CommitOutcome("token_required", mac, 0, False)

            if current is None and len(self._peers) >= self.max_pending:
                raise SaeError("SAE_CAPACITY_EXCEEDED",
                               {"max_pending": self.max_pending})

            handshake_id = self._new_handshake_id()
            self._peers[mac] = _PeerRecord(
                state="pending",
                scalar=scalar,
                handshake_id=handshake_id,
                created_at=self._now(now),
                tokenless_commits=(current.tokenless_commits if current else 0)
                + (0 if token_record is not None else 1),
            )
            if token_record is not None:
                token_record.consumed = True
                self._counters["tokens_consumed"] += 1
            self._counters["commits"] += 1
            return CommitOutcome("accepted", mac, handshake_id,
                                 token_record is not None)

    def _validate_token(self, mac: str, token, now) -> _TokenRecord:
        """Authenticate a presented token; every failure counts once."""
        record = self._tokens.get(mac)
        if not isinstance(token, str) or not token or record is None \
                or record.token != token:
            self._counters["token_rejections"] += 1
            raise SaeError("SAE_TOKEN_INVALID",
                           {"mac": mac, "reason": "unknown_token"})
        if record.consumed:
            self._counters["token_rejections"] += 1
            raise SaeError("SAE_TOKEN_INVALID",
                           {"mac": mac, "reason": "already_consumed"})
        if self._now(now) - record.issued_at > self.token_ttl:
            self._counters["token_rejections"] += 1
            raise SaeError("SAE_TOKEN_INVALID",
                           {"mac": mac, "reason": "expired"})
        return record

    def on_confirm(self, mac: str, send_confirm, now=None) -> ConfirmOutcome:
        if not self._valid_mac(mac) or not self._is_int(send_confirm):
            raise SaeError("SAE_INVALID_REQUEST",
                           {"mac": mac, "send_confirm": send_confirm})
        with self._lock:
            peer = self._peers.get(mac)
            if peer is None or peer.state != "pending":
                self._counters["confirm_failures"] += 1
                raise SaeError("SAE_UNKNOWN_PEER", {"mac": mac})
            if send_confirm != peer.scalar + 1:
                self._counters["confirm_failures"] += 1
                del self._peers[mac]
                raise SaeError("SAE_STATE_CONFLICT",
                               {"mac": mac, "expected": peer.scalar + 1,
                                "received": send_confirm})
            peer.state = "confirmed"
            self._counters["confirms"] += 1
            return ConfirmOutcome("confirmed", mac, peer.handshake_id)

    def issue_token(self, mac: str, now=None) -> str:
        if not self._valid_mac(mac):
            raise SaeError("SAE_INVALID_REQUEST", {"mac": mac})
        with self._lock:
            existing = self._tokens.get(mac)
            if existing is not None and not existing.consumed \
                    and self._now(now) - existing.issued_at <= self.token_ttl:
                return existing.token
            if mac not in self._tokens \
                    and len(self._tokens) >= self.max_pending:
                raise SaeError("SAE_CAPACITY_EXCEEDED",
                               {"max_pending": self.max_pending})
            token = secrets.token_hex(16)
            self._tokens[mac] = _TokenRecord(token, self._now(now))
            self._counters["tokens_issued"] += 1
            return token

    def authorize_assoc(self, mac: str, *, pmf_negotiated: bool,
                        wpa2_client: bool = False) -> AssocDecision:
        if not self._valid_mac(mac):
            raise SaeError("SAE_INVALID_REQUEST", {"mac": mac})
        with self._lock:
            peer = self._peers.get(mac)
            if not pmf_negotiated:
                if (self.transition_mode and wpa2_client
                        and not (peer is not None and peer.protected)):
                    if peer is not None:
                        peer.associated = True
                        peer.protected = False
                    return AssocDecision(mac, True, False, "WPA2_TRANSITION")
                self._counters["pmf_denied"] += 1
                raise SaeError("SAE_PMF_REQUIRED", {"mac": mac})
            if peer is None or peer.state != "confirmed":
                raise SaeError("SAE_STATE_CONFLICT",
                               {"mac": mac,
                                "state": peer.state if peer else "unknown"})
            peer.associated = True
            peer.protected = True
            return AssocDecision(mac, True, True, "PMF_PROTECTED")

    def handshake_state(self, mac: str) -> str:
        with self._lock:
            peer = self._peers.get(mac)
            return peer.state if peer is not None else "unknown"

    def purge_expired(self, now=None) -> int:
        with self._lock:
            expired = [
                mac for mac, peer in self._peers.items()
                if peer.state == "pending"
                and self._now(now) - peer.created_at > self.handshake_ttl
            ]
            for mac in expired:
                del self._peers[mac]
            self._counters["purged"] += len(expired)
            return len(expired)

    def pending_peers(self) -> tuple:
        with self._lock:
            return tuple(
                mac for mac, peer in self._peers.items()
                if peer.state == "pending"
            )

    def close_association(self, mac: str) -> bool:
        with self._lock:
            peer = self._peers.get(mac)
            if peer is None or not peer.associated:
                return False
            peer.associated = False
            peer.protected = False
            return True

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": 1,
                "peers": {
                    mac: {
                        "state": peer.state,
                        "scalar": peer.scalar,
                        "handshake_id": peer.handshake_id,
                        "created_at": peer.created_at,
                        "tokenless_commits": peer.tokenless_commits,
                        "associated": peer.associated,
                        "protected": peer.protected,
                    }
                    for mac, peer in self._peers.items()
                },
                "tokens": {
                    mac: {
                        "token": record.token,
                        "issued_at": record.issued_at,
                        "consumed": record.consumed,
                    }
                    for mac, record in self._tokens.items()
                },
                "stats": dict(self._counters),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            self._validate_snapshot(state)
            peers: dict[str, _PeerRecord] = {}
            for mac, raw in state["peers"].items():
                if raw["state"] != "confirmed":
                    continue
                peers[mac] = _PeerRecord(
                    state="confirmed",
                    scalar=raw["scalar"],
                    handshake_id=raw["handshake_id"],
                    created_at=raw["created_at"],
                    tokenless_commits=raw["tokenless_commits"],
                    associated=raw["associated"],
                    protected=raw["protected"],
                )
            tokens = {
                mac: _TokenRecord(raw["token"], raw["issued_at"],
                                  raw["consumed"])
                for mac, raw in state["tokens"].items()
            }
            self._peers = peers
            self._tokens = tokens
            self._counters = dict(state["stats"])
            self._next_handshake_id = max(
                (peer.handshake_id for peer in peers.values()), default=0)

    def _validate_snapshot(self, state) -> None:
        if not isinstance(state, dict) \
                or set(state.keys()) != {"version", "peers", "tokens",
                                         "stats"}:
            raise SaeError("SAE_SNAPSHOT_INVALID", "bad top-level structure")
        if state["version"] != 1:
            raise SaeError("SAE_SNAPSHOT_INVALID",
                           {"version": state["version"]})
        if not isinstance(state["peers"], dict) \
                or not isinstance(state["tokens"], dict) \
                or not isinstance(state["stats"], dict):
            raise SaeError("SAE_SNAPSHOT_INVALID",
                           "peers/tokens/stats must be mappings")
        if set(state["stats"].keys()) != set(self._STAT_KEYS):
            raise SaeError("SAE_SNAPSHOT_INVALID", "bad stats keys")
        for mac, raw in state["peers"].items():
            if not isinstance(mac, str) or not isinstance(raw, dict) \
                    or set(raw.keys()) != self._PEER_FIELDS:
                raise SaeError("SAE_SNAPSHOT_INVALID", {"peer": mac})
        for mac, raw in state["tokens"].items():
            if not isinstance(mac, str) or not isinstance(raw, dict) \
                    or set(raw.keys()) != self._TOKEN_FIELDS:
                raise SaeError("SAE_SNAPSHOT_INVALID", {"token": mac})

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)
