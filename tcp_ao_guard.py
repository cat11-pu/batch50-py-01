"""TCP-AO guard: per-connection key chains, segment MACs and sequence windows."""

from __future__ import annotations

import copy
import hashlib
import hmac
import threading
from dataclasses import dataclass
from datetime import datetime, timezone

__all__ = [
    "TcpAoError",
    "KeyEntry",
    "ConnectionBinding",
    "SignedSegment",
    "SegmentResult",
    "TcpAoGuard",
]

_SNAPSHOT_VERSION = 1
_SEQUENCE_MODULUS = 1 << 32
_MAX_SEQUENCE = (1 << 64) - 1
_HEX_DIGITS = frozenset("0123456789abcdef")
_CORE_COUNTERS = (
    "installed",
    "bound",
    "signed",
    "verified",
    "mac_mismatches",
    "duplicates",
    "out_of_window",
    "rollovers",
)
_EXTRA_COUNTERS = (
    "removed",
    "unbound",
    "rebinds",
    "key_conflicts",
    "bind_conflicts",
    "capacity_rejections",
)
_COUNTER_NAMES = _CORE_COUNTERS + _EXTRA_COUNTERS


class TcpAoError(ValueError):
    """Raised when a key-chain or segment operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class KeyEntry:
    chain_id: str
    key_id: str
    generation: int
    fingerprint: str
    send: bool
    recv: bool
    created_at: str
    retired_at: str | None


@dataclass(frozen=True)
class ConnectionBinding:
    conn_id: str
    chain_id: str
    peer: str
    src_port: int
    dst_port: int
    bound_at: str
    rebinds: int


@dataclass(frozen=True)
class SignedSegment:
    conn_id: str
    seq: int
    key_id: str
    mac: str


@dataclass(frozen=True)
class SegmentResult:
    conn_id: str
    seq: int
    accepted: bool
    reason: str
    key_id: str | None
    window_floor: int


class TcpAoGuard:
    """Govern TCP-AO key chains and per-connection segment verification."""

    def __init__(self, *, max_chains: int = 8, max_keys_per_chain: int = 8,
                 max_connections: int = 64, window_size: int = 64) -> None:
        for name, value, minimum in (
            ("max_chains", max_chains, 0),
            ("max_keys_per_chain", max_keys_per_chain, 0),
            ("max_connections", max_connections, 0),
            ("window_size", window_size, 1),
        ):
            if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                raise TcpAoError("TCPAO_INVALID_REQUEST", {name: value})
        self.max_chains = max_chains
        self.max_keys_per_chain = max_keys_per_chain
        self.max_connections = max_connections
        self.window_size = window_size
        self._lock = threading.RLock()
        self._chains: dict[str, dict] = {}
        self._connections: dict[str, dict] = {}
        self._sequences: dict[str, dict] = {}
        self._counters = self._new_counters()
        self._stats = self._new_counters()

    @staticmethod
    def _new_counters() -> dict:
        counters = {name: 0 for name in _COUNTER_NAMES}
        counters["peer_failures"] = {}
        return counters

    @staticmethod
    def _request_error(field: str, value: object) -> TcpAoError:
        return TcpAoError("TCPAO_INVALID_REQUEST", {field: value})

    @classmethod
    def _require_text(cls, value: object, field: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise cls._request_error(field, value)
        return value

    @classmethod
    def _require_int(cls, value: object, field: str, minimum: int,
                     maximum: int | None = None) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise cls._request_error(field, value)
        if maximum is not None and value > maximum:
            raise cls._request_error(field, value)
        return value

    @classmethod
    def _require_port(cls, value: object, field: str) -> int:
        return cls._require_int(value, field, 0, 65535)

    @classmethod
    def _require_bool(cls, value: object, field: str) -> bool:
        if not isinstance(value, bool):
            raise cls._request_error(field, value)
        return value

    @staticmethod
    def _require_payload(payload: object) -> bytes:
        if not isinstance(payload, (bytes, bytearray, memoryview)):
            raise TcpAoError("TCPAO_INVALID_REQUEST", {"payload": type(payload).__name__})
        return bytes(payload)

    @classmethod
    def _time_value(cls, now: str | None) -> str:
        if now is None:
            return datetime.now(timezone.utc).isoformat()
        if not isinstance(now, str) or not now.strip():
            raise cls._request_error("now", now)
        return now

    def _bump(self, name: str, amount: int = 1) -> None:
        self._counters[name] += amount
        self._stats[name] += amount

    def _peer_failure(self, peer: str) -> None:
        for counters in (self._counters, self._stats):
            failures = counters["peer_failures"]
            failures[peer] = failures.get(peer, 0) + 1

    @staticmethod
    def _entry(chain_id: str, key: dict) -> KeyEntry:
        return KeyEntry(
            chain_id=chain_id,
            key_id=key["key_id"],
            generation=key["generation"],
            fingerprint=key["fingerprint"],
            send=key["send"],
            recv=key["recv"],
            created_at=key["created_at"],
            retired_at=key["retired_at"],
        )

    @staticmethod
    def _binding(conn_id: str, binding: dict) -> ConnectionBinding:
        return ConnectionBinding(
            conn_id=conn_id,
            chain_id=binding["chain_id"],
            peer=binding["peer"],
            src_port=binding["src_port"],
            dst_port=binding["dst_port"],
            bound_at=binding["bound_at"],
            rebinds=binding["rebinds"],
        )

    @staticmethod
    def _derive_material(secret: str) -> tuple[str, str]:
        digest = hashlib.sha256(secret.encode("utf-8")).hexdigest()
        return digest, digest

    @staticmethod
    def _segment_mac(material: str, conn_id: str, chain_id: str,
                     key_id: str, seq: int, payload: bytes) -> str:
        digest = hmac.new(bytes.fromhex(material), digestmod=hashlib.sha256)
        parts = (
            b"tcp-ao-segment-v1",
            conn_id.encode("utf-8"),
            chain_id.encode("utf-8"),
            key_id.encode("utf-8"),
            seq.to_bytes(8, "big"),
            payload,
        )
        for part in parts:
            digest.update(len(part).to_bytes(4, "big"))
            digest.update(part)
        return digest.hexdigest()

    def _send_key(self, chain_id: str) -> dict:
        chain = self._chains.get(chain_id)
        if chain is None:
            raise TcpAoError("TCPAO_UNKNOWN_CHAIN", chain_id)
        key_id = chain["send_key_id"]
        if key_id is None:
            raise TcpAoError("TCPAO_UNKNOWN_KEY", {"chain_id": chain_id})
        key = chain["keys"].get(key_id)
        if key is None or not key["send"]:
            raise TcpAoError("TCPAO_UNKNOWN_KEY", key_id)
        return key

    def _promote_send_key(self, chain_id: str) -> None:
        chain = self._chains[chain_id]
        candidates = sorted(
            chain["keys"].values(),
            key=lambda key: key["generation"],
            reverse=True,
        )
        if not candidates:
            chain["send_key_id"] = None
            return
        chosen = next((key for key in candidates if key["recv"]), candidates[0])
        chosen["send"] = True
        chosen["retired_at"] = None
        chain["send_key_id"] = chosen["key_id"]

    def install_key(self, chain_id: str, key_id: str, secret: str, *,
                    send: bool = True, recv: bool = True,
                    now: str | None = None) -> KeyEntry:
        chain_id = self._require_text(chain_id, "chain_id")
        key_id = self._require_text(key_id, "key_id")
        if not isinstance(secret, str):
            raise self._request_error("secret", type(secret).__name__)
        send = self._require_bool(send, "send")
        recv = self._require_bool(recv, "recv")
        timestamp = self._time_value(now)

        with self._lock:
            chain = self._chains.get(chain_id)
            if chain is None:
                if len(self._chains) >= self.max_chains:
                    self._bump("capacity_rejections")
                    raise TcpAoError("TCPAO_CAPACITY_EXCEEDED", "chains")
                chain = {
                    "next_generation": 1,
                    "send_key_id": None,
                    "keys": {},
                }
                self._chains[chain_id] = chain

            if key_id in chain["keys"]:
                self._bump("key_conflicts")
                raise TcpAoError("TCPAO_KEY_CONFLICT", key_id)
            if len(chain["keys"]) >= self.max_keys_per_chain:
                self._bump("capacity_rejections")
                raise TcpAoError("TCPAO_CAPACITY_EXCEEDED", "keys")

            material, fingerprint = self._derive_material(secret)
            key = {
                "key_id": key_id,
                "generation": chain["next_generation"],
                "material": material,
                "fingerprint": fingerprint,
                "send": send,
                "recv": recv,
                "created_at": timestamp,
                "retired_at": None,
            }
            chain["next_generation"] += 1
            chain["keys"][key_id] = key
            if chain["send_key_id"] is None and send:
                chain["send_key_id"] = key_id
            self._bump("installed")
            return self._entry(chain_id, key)

    def remove_key(self, chain_id: str, key_id: str, now: str | None = None) -> bool:
        chain_id = self._require_text(chain_id, "chain_id")
        key_id = self._require_text(key_id, "key_id")
        self._time_value(now)

        with self._lock:
            chain = self._chains.get(chain_id)
            if chain is None or key_id not in chain["keys"]:
                return False
            was_send_key = chain["send_key_id"] == key_id
            del chain["keys"][key_id]
            if was_send_key:
                self._promote_send_key(chain_id)
            self._bump("removed")
            return True

    def key_chain(self, chain_id: str) -> tuple[KeyEntry, ...]:
        if not isinstance(chain_id, str) or not chain_id.strip():
            raise self._request_error("chain_id", chain_id)
        with self._lock:
            chain = self._chains.get(chain_id)
            if chain is None:
                return ()
            keys = sorted(chain["keys"].values(), key=lambda key: key["generation"])
            return tuple(self._entry(chain_id, key) for key in keys)

    def bind_connection(self, conn_id: str, chain_id: str, peer: str,
                        src_port: int, dst_port: int,
                        now: str | None = None) -> ConnectionBinding:
        conn_id = self._require_text(conn_id, "conn_id")
        chain_id = self._require_text(chain_id, "chain_id")
        peer = self._require_text(peer, "peer")
        src_port = self._require_port(src_port, "src_port")
        dst_port = self._require_port(dst_port, "dst_port")
        timestamp = self._time_value(now)

        with self._lock:
            existing = self._connections.get(conn_id)
            if existing is not None:
                if existing["chain_id"] != chain_id:
                    self._bump("bind_conflicts")
                    raise TcpAoError(
                        "TCPAO_BINDING_CONFLICT",
                        {"conn_id": conn_id, "chain_id": chain_id},
                    )
                return self._binding(conn_id, existing)
            if chain_id not in self._chains:
                raise TcpAoError("TCPAO_UNKNOWN_CHAIN", chain_id)
            if len(self._connections) >= self.max_connections:
                self._bump("capacity_rejections")
                raise TcpAoError("TCPAO_CAPACITY_EXCEEDED", "connections")

            binding = {
                "chain_id": chain_id,
                "peer": peer,
                "src_port": src_port,
                "dst_port": dst_port,
                "bound_at": timestamp,
                "rebinds": 0,
            }
            self._connections[conn_id] = binding
            self._bump("bound")
            return self._binding(conn_id, binding)

    def rebind_connection(self, conn_id: str, src_port: int, dst_port: int,
                          now: str | None = None) -> ConnectionBinding:
        conn_id = self._require_text(conn_id, "conn_id")
        src_port = self._require_port(src_port, "src_port")
        dst_port = self._require_port(dst_port, "dst_port")
        timestamp = self._time_value(now)

        with self._lock:
            binding = self._connections.get(conn_id)
            if binding is None:
                raise TcpAoError("TCPAO_UNKNOWN_CONNECTION", conn_id)
            binding["src_port"] = src_port
            binding["dst_port"] = dst_port
            binding["bound_at"] = timestamp
            binding["rebinds"] += 1
            self._bump("rebinds")
            return self._binding(conn_id, binding)

    def unbind_connection(self, conn_id: str) -> bool:
        if not isinstance(conn_id, str) or not conn_id.strip():
            return False
        with self._lock:
            existed = self._connections.pop(conn_id, None) is not None
            self._sequences.pop(conn_id, None)
            if existed:
                self._bump("unbound")
            return existed

    def sign_segment(self, conn_id: str, seq: int, payload: bytes,
                     key_id: str | None = None) -> SignedSegment:
        conn_id = self._require_text(conn_id, "conn_id")
        seq = self._require_int(seq, "seq", 0, _MAX_SEQUENCE)
        payload = self._require_payload(payload)
        if key_id is not None:
            key_id = self._require_text(key_id, "key_id")

        with self._lock:
            binding = self._connections.get(conn_id)
            if binding is None:
                raise TcpAoError("TCPAO_UNKNOWN_CONNECTION", conn_id)
            chain_id = binding["chain_id"]
            chain = self._chains.get(chain_id)
            if chain is None:
                raise TcpAoError("TCPAO_UNKNOWN_CHAIN", chain_id)
            if key_id is None:
                key = self._send_key(chain_id)
            else:
                key = chain["keys"].get(key_id)
                if key is None or not key["send"]:
                    raise TcpAoError("TCPAO_UNKNOWN_KEY", key_id)
            mac = self._segment_mac(
                key["material"], conn_id, chain_id, key["key_id"], seq, payload
            )
            self._bump("signed")
            return SignedSegment(
                conn_id=conn_id,
                seq=seq,
                key_id=key["key_id"],
                mac=mac,
            )

    @staticmethod
    def _absolute_sequence(sequence_state: dict | None, seq: int) -> int:
        if seq >= _SEQUENCE_MODULUS or sequence_state is None:
            return seq
        floor = sequence_state["floor"]
        if floor is None:
            return seq
        base = floor // _SEQUENCE_MODULUS
        candidates = []
        for epoch in (base - 1, base, base + 1):
            candidate = seq + epoch * _SEQUENCE_MODULUS
            if 0 <= candidate <= _MAX_SEQUENCE:
                candidates.append(candidate)
        if not candidates:
            return seq
        return min(candidates, key=lambda candidate: (abs(candidate - floor), candidate))

    def verify_segment(self, conn_id: str, seq: int, payload: bytes,
                       mac: str) -> SegmentResult:
        conn_id = self._require_text(conn_id, "conn_id")
        seq = self._require_int(seq, "seq", 0, _MAX_SEQUENCE)
        payload = self._require_payload(payload)
        if not isinstance(mac, str):
            raise self._request_error("mac", type(mac).__name__)

        with self._lock:
            binding = self._connections.get(conn_id)
            if binding is None:
                raise TcpAoError("TCPAO_UNKNOWN_CONNECTION", conn_id)
            chain_id = binding["chain_id"]
            chain = self._chains.get(chain_id)
            if chain is None:
                raise TcpAoError("TCPAO_UNKNOWN_CHAIN", chain_id)

            sequence_state = self._sequences.get(conn_id)
            absolute_seq = self._absolute_sequence(sequence_state, seq)
            floor = sequence_state["floor"] if sequence_state is not None else None
            received = sequence_state["received"] if sequence_state is not None else set()

            if floor is not None:
                lower_bound = floor - self.window_size + 1
                if absolute_seq < lower_bound:
                    self._bump("out_of_window")
                    self._peer_failure(binding["peer"])
                    return SegmentResult(
                        conn_id=conn_id,
                        seq=seq,
                        accepted=False,
                        reason="out_of_window",
                        key_id=None,
                        window_floor=floor,
                    )
                if absolute_seq in received:
                    self._bump("duplicates")
                    self._peer_failure(binding["peer"])
                    return SegmentResult(
                        conn_id=conn_id,
                        seq=seq,
                        accepted=False,
                        reason="duplicate",
                        key_id=None,
                        window_floor=floor,
                    )

            matched_key = None
            for key in sorted(
                chain["keys"].values(),
                key=lambda item: item["generation"],
                reverse=True,
            ):
                if not key["recv"]:
                    continue
                expected = self._segment_mac(
                    key["material"], conn_id, chain_id, key["key_id"], seq, payload
                )
                if hmac.compare_digest(expected, mac):
                    matched_key = key
                    break

            if matched_key is None:
                self._bump("mac_mismatches")
                self._peer_failure(binding["peer"])
                return SegmentResult(
                    conn_id=conn_id,
                    seq=seq,
                    accepted=False,
                    reason="mac_mismatch",
                    key_id=None,
                    window_floor=floor if floor is not None else absolute_seq,
                )

            if sequence_state is None:
                sequence_state = {"floor": None, "received": set()}
                self._sequences[conn_id] = sequence_state
            sequence_state["received"].add(absolute_seq)
            if floor is None or absolute_seq > floor:
                sequence_state["floor"] = absolute_seq
            new_floor = sequence_state["floor"]
            lower_bound = new_floor - self.window_size + 1
            sequence_state["received"] = {
                value for value in sequence_state["received"] if value >= lower_bound
            }
            self._bump("verified")
            return SegmentResult(
                conn_id=conn_id,
                seq=seq,
                accepted=True,
                reason="ok",
                key_id=matched_key["key_id"],
                window_floor=new_floor,
            )

    def rollover(self, chain_id: str, key_id: str,
                 now: str | None = None) -> KeyEntry:
        chain_id = self._require_text(chain_id, "chain_id")
        key_id = self._require_text(key_id, "key_id")
        timestamp = self._time_value(now)

        with self._lock:
            chain = self._chains.get(chain_id)
            if chain is None:
                raise TcpAoError("TCPAO_UNKNOWN_CHAIN", chain_id)
            target = chain["keys"].get(key_id)
            if target is None:
                raise TcpAoError("TCPAO_UNKNOWN_KEY", key_id)
            for key in chain["keys"].values():
                if key is target:
                    continue
                if key["send"]:
                    key["send"] = False
                    key["retired_at"] = timestamp
            target["send"] = True
            target["retired_at"] = None
            chain["send_key_id"] = key_id
            self._bump("rollovers")
            return self._entry(chain_id, target)

    def status(self) -> dict:
        with self._lock:
            return {
                "chains": len(self._chains),
                "connections": len(self._connections),
                "keys": sum(len(chain["keys"]) for chain in self._chains.values()),
                "segments": sum(
                    len(sequence["received"]) for sequence in self._sequences.values()
                ),
            }

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": _SNAPSHOT_VERSION,
                "chains": {
                    chain_id: {
                        "next_generation": chain["next_generation"],
                        "send_key_id": chain["send_key_id"],
                        "keys": {
                            key_id: dict(key) for key_id, key in chain["keys"].items()
                        },
                    }
                    for chain_id, chain in self._chains.items()
                },
                "connections": {
                    conn_id: dict(binding)
                    for conn_id, binding in self._connections.items()
                },
                "sequences": {
                    conn_id: {
                        "floor": sequence["floor"],
                        "received": sorted(sequence["received"]),
                    }
                    for conn_id, sequence in self._sequences.items()
                },
                "counters": copy.deepcopy(self._counters),
                "stats": copy.deepcopy(self._stats),
            }
            return copy.deepcopy(state)

    @staticmethod
    def _snapshot_invalid(detail: object) -> TcpAoError:
        return TcpAoError("TCPAO_SNAPSHOT_INVALID", detail)

    @classmethod
    def _snapshot_hex(cls, value: object, field: str) -> str:
        if (not isinstance(value, str) or len(value) != 64
                or any(character not in _HEX_DIGITS for character in value)):
            raise cls._snapshot_invalid(field)
        return value

    @classmethod
    def _snapshot_int(cls, value: object, field: str, minimum: int,
                      maximum: int | None = None) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise cls._snapshot_invalid(field)
        if maximum is not None and value > maximum:
            raise cls._snapshot_invalid(field)
        return value

    @classmethod
    def _snapshot_counters(cls, value: object, field: str) -> dict:
        if not isinstance(value, dict) or set(value) != set(_COUNTER_NAMES) | {"peer_failures"}:
            raise cls._snapshot_invalid(field)
        result = {}
        for name in _COUNTER_NAMES:
            result[name] = cls._snapshot_int(value[name], f"{field}.{name}", 0)
        peer_failures = value["peer_failures"]
        if not isinstance(peer_failures, dict):
            raise cls._snapshot_invalid(f"{field}.peer_failures")
        result["peer_failures"] = {}
        for peer, count in peer_failures.items():
            if not isinstance(peer, str):
                raise cls._snapshot_invalid(f"{field}.peer_failures")
            result["peer_failures"][peer] = cls._snapshot_int(
                count, f"{field}.peer_failures.{peer}", 0
            )
        return result

    def _parse_snapshot(self, state: object) -> tuple[dict, dict, dict, dict, dict]:
        try:
            state = copy.deepcopy(state)
        except Exception as exc:
            raise self._snapshot_invalid("state") from exc
        if not isinstance(state, dict):
            raise self._snapshot_invalid("state")
        required = {"version", "chains", "connections", "sequences", "counters", "stats"}
        if set(state) != required:
            raise self._snapshot_invalid("keys")
        if (isinstance(state["version"], bool)
                or not isinstance(state["version"], int)
                or state["version"] != _SNAPSHOT_VERSION):
            raise self._snapshot_invalid("version")
        if not isinstance(state["chains"], dict):
            raise self._snapshot_invalid("chains")
        if not isinstance(state["connections"], dict):
            raise self._snapshot_invalid("connections")
        if not isinstance(state["sequences"], dict):
            raise self._snapshot_invalid("sequences")
        if len(state["chains"]) > self.max_chains:
            raise self._snapshot_invalid("chains")
        if len(state["connections"]) > self.max_connections:
            raise self._snapshot_invalid("connections")

        chains: dict[str, dict] = {}
        for chain_id, raw_chain in state["chains"].items():
            if not isinstance(chain_id, str) or not chain_id.strip():
                raise self._snapshot_invalid("chains.id")
            if not isinstance(raw_chain, dict) or set(raw_chain) != {
                "next_generation", "send_key_id", "keys"
            }:
                raise self._snapshot_invalid(f"chains.{chain_id}")
            next_generation = self._snapshot_int(
                raw_chain["next_generation"], f"chains.{chain_id}.next_generation", 1
            )
            raw_keys = raw_chain["keys"]
            if not isinstance(raw_keys, dict) or len(raw_keys) > self.max_keys_per_chain:
                raise self._snapshot_invalid(f"chains.{chain_id}.keys")
            keys: dict[str, dict] = {}
            generations: set[int] = set()
            for key_id, raw_key in raw_keys.items():
                if not isinstance(key_id, str) or not key_id.strip():
                    raise self._snapshot_invalid(f"chains.{chain_id}.keys.id")
                if not isinstance(raw_key, dict) or set(raw_key) != {
                    "key_id", "generation", "material", "fingerprint",
                    "send", "recv", "created_at", "retired_at",
                }:
                    raise self._snapshot_invalid(f"chains.{chain_id}.keys.{key_id}")
                if raw_key["key_id"] != key_id:
                    raise self._snapshot_invalid(f"chains.{chain_id}.keys.{key_id}.key_id")
                generation = self._snapshot_int(
                    raw_key["generation"],
                    f"chains.{chain_id}.keys.{key_id}.generation",
                    1,
                )
                if generation in generations:
                    raise self._snapshot_invalid(f"chains.{chain_id}.generations")
                generations.add(generation)
                material = self._snapshot_hex(
                    raw_key["material"], f"chains.{chain_id}.keys.{key_id}.material"
                )
                fingerprint = self._snapshot_hex(
                    raw_key["fingerprint"], f"chains.{chain_id}.keys.{key_id}.fingerprint"
                )
                if not isinstance(raw_key["send"], bool) or not isinstance(raw_key["recv"], bool):
                    raise self._snapshot_invalid(f"chains.{chain_id}.keys.{key_id}.flags")
                created_at = raw_key["created_at"]
                retired_at = raw_key["retired_at"]
                if not isinstance(created_at, str) or not created_at.strip():
                    raise self._snapshot_invalid(f"chains.{chain_id}.keys.{key_id}.created_at")
                if retired_at is not None and (
                    not isinstance(retired_at, str) or not retired_at.strip()
                ):
                    raise self._snapshot_invalid(f"chains.{chain_id}.keys.{key_id}.retired_at")
                keys[key_id] = {
                    "key_id": key_id,
                    "generation": generation,
                    "material": material,
                    "fingerprint": fingerprint,
                    "send": raw_key["send"],
                    "recv": raw_key["recv"],
                    "created_at": created_at,
                    "retired_at": retired_at,
                }
            if generations and next_generation <= max(generations):
                raise self._snapshot_invalid(f"chains.{chain_id}.next_generation")
            send_key_id = raw_chain["send_key_id"]
            if send_key_id is not None:
                if not isinstance(send_key_id, str) or send_key_id not in keys:
                    raise self._snapshot_invalid(f"chains.{chain_id}.send_key_id")
                if not keys[send_key_id]["send"]:
                    raise self._snapshot_invalid(f"chains.{chain_id}.send_key_id")
            chains[chain_id] = {
                "next_generation": next_generation,
                "send_key_id": send_key_id,
                "keys": keys,
            }

        connections: dict[str, dict] = {}
        for conn_id, raw_binding in state["connections"].items():
            if not isinstance(conn_id, str) or not conn_id.strip():
                raise self._snapshot_invalid("connections.id")
            if not isinstance(raw_binding, dict) or set(raw_binding) != {
                "chain_id", "peer", "src_port", "dst_port", "bound_at", "rebinds"
            }:
                raise self._snapshot_invalid(f"connections.{conn_id}")
            chain_id = raw_binding["chain_id"]
            peer = raw_binding["peer"]
            bound_at = raw_binding["bound_at"]
            if not isinstance(chain_id, str) or chain_id not in chains:
                raise self._snapshot_invalid(f"connections.{conn_id}.chain_id")
            if not isinstance(peer, str) or not peer.strip():
                raise self._snapshot_invalid(f"connections.{conn_id}.peer")
            if not isinstance(bound_at, str) or not bound_at.strip():
                raise self._snapshot_invalid(f"connections.{conn_id}.bound_at")
            connections[conn_id] = {
                "chain_id": chain_id,
                "peer": peer,
                "src_port": self._snapshot_int(
                    raw_binding["src_port"], f"connections.{conn_id}.src_port", 0, 65535
                ),
                "dst_port": self._snapshot_int(
                    raw_binding["dst_port"], f"connections.{conn_id}.dst_port", 0, 65535
                ),
                "bound_at": bound_at,
                "rebinds": self._snapshot_int(
                    raw_binding["rebinds"], f"connections.{conn_id}.rebinds", 0
                ),
            }

        sequences: dict[str, dict] = {}
        for conn_id, raw_sequence in state["sequences"].items():
            if not isinstance(conn_id, str) or conn_id not in connections:
                raise self._snapshot_invalid(f"sequences.{conn_id}")
            if not isinstance(raw_sequence, dict) or set(raw_sequence) != {
                "floor", "received"
            }:
                raise self._snapshot_invalid(f"sequences.{conn_id}")
            raw_floor = raw_sequence["floor"]
            if raw_floor is None:
                floor = None
            else:
                floor = self._snapshot_int(
                    raw_floor, f"sequences.{conn_id}.floor", 0, _MAX_SEQUENCE
                )
            raw_received = raw_sequence["received"]
            if not isinstance(raw_received, list):
                raise self._snapshot_invalid(f"sequences.{conn_id}.received")
            if len(raw_received) > self.window_size:
                raise self._snapshot_invalid(f"sequences.{conn_id}.received")
            received: set[int] = set()
            for value in raw_received:
                sequence = self._snapshot_int(
                    value, f"sequences.{conn_id}.received", 0, _MAX_SEQUENCE
                )
                if sequence in received:
                    raise self._snapshot_invalid(f"sequences.{conn_id}.received")
                received.add(sequence)
            if floor is None:
                if received:
                    raise self._snapshot_invalid(f"sequences.{conn_id}.floor")
            else:
                lower_bound = floor - self.window_size + 1
                if (not received or floor not in received
                        or max(received) != floor
                        or any(value < lower_bound for value in received)):
                    raise self._snapshot_invalid(f"sequences.{conn_id}.window")
            sequences[conn_id] = {"floor": floor, "received": received}

        counters = self._snapshot_counters(state["counters"], "counters")
        stats = self._snapshot_counters(state["stats"], "stats")
        return chains, connections, sequences, counters, stats

    def restore(self, state: dict) -> None:
        with self._lock:
            chains, connections, sequences, counters, stats = self._parse_snapshot(state)
            self._chains = chains
            self._connections = connections
            self._sequences = sequences
            self._counters = counters
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)
