"""Bind SDP fingerprint attributes to DTLS certificate material per media section."""

from __future__ import annotations

import copy
import hashlib
import hmac
import threading
from dataclasses import asdict, dataclass, replace
from typing import Any


class SrtpError(ValueError):
    """Raised when SDP binding or certificate verification is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


SRTP_INVALID_SDP = "SRTP_INVALID_SDP"
SRTP_FINGERPRINT_MISSING = "SRTP_FINGERPRINT_MISSING"
SRTP_ALGORITHM_NOT_ALLOWED = "SRTP_ALGORITHM_NOT_ALLOWED"
SRTP_FINGERPRINT_INVALID = "SRTP_FINGERPRINT_INVALID"
SRTP_SDP_MISMATCH = "SRTP_SDP_MISMATCH"
SRTP_FINGERPRINT_MISMATCH = "SRTP_FINGERPRINT_MISMATCH"
SRTP_SEGMENT_REJECTED = "SRTP_SEGMENT_REJECTED"
SRTP_SEGMENT_NOT_FOUND = "SRTP_SEGMENT_NOT_FOUND"
SRTP_SEGMENT_NOT_VERIFIED = "SRTP_SEGMENT_NOT_VERIFIED"
SRTP_BINDING_CAPACITY = "SRTP_BINDING_CAPACITY"
SRTP_SNAPSHOT_INVALID = "SRTP_SNAPSHOT_INVALID"

_SNAPSHOT_VERSION = 1
_DEFAULT_ROLE = "actpass"
_KEY_LENGTH = 32
_DIGEST_SIZES = {
    "sha-1": 20,
    "sha-224": 28,
    "sha-256": 32,
    "sha-384": 48,
    "sha-512": 64,
}
_HASH_NAMES = {
    "sha-1": "sha1",
    "sha-224": "sha224",
    "sha-256": "sha256",
    "sha-384": "sha384",
    "sha-512": "sha512",
}
_COUNTER_KEYS = (
    "offers",
    "answers",
    "verified",
    "rejected",
    "renegotiations",
)


@dataclass(frozen=True)
class MediaSection:
    mid: str
    media: str
    port: int
    protocol: str
    fingerprint_algorithm: str | None
    fingerprint_value: str | None
    setup: str | None


@dataclass(frozen=True)
class Binding:
    mid: str
    algorithm: str
    fingerprint: str
    role: str
    context_id: int
    verified: bool


class SrtpFingerprintBinder:
    """Track one DTLS-SRTP fingerprint binding per negotiated media section."""

    def __init__(self, *, allowed_algorithms=("sha-256", "sha-384", "sha-512"),
                 max_bindings: int = 16) -> None:
        self.allowed_algorithms = tuple(str(algorithm).lower()
                                        for algorithm in allowed_algorithms)
        self.max_bindings = max_bindings
        self._lock = threading.RLock()
        self._bindings: dict[str, Binding] = {}
        self._keys: dict[str, bytes] = {}
        self._rejected: set[str] = set()
        self._next_context_id = 1
        self._counters: dict[str, int] = {
            key: 0 for key in _COUNTER_KEYS
        }

    def parse_sdp(self, sdp: str) -> tuple[MediaSection, ...]:
        with self._lock:
            return self._parse_sdp(sdp)

    def bind_offer(self, sdp: str) -> dict[str, Binding]:
        with self._lock:
            sections = self._parse_sdp(sdp)
            candidates = self._prepare_candidates(sections)

            existing = set(self._bindings) | self._rejected
            for section, _, _ in candidates:
                if section.mid in existing:
                    raise SrtpError(
                        SRTP_INVALID_SDP,
                        {"mid": section.mid, "reason": "mid already bound"},
                    )

            active_count = sum(
                mid not in self._rejected for mid in self._bindings
            )
            final_count = active_count + len(candidates)
            if final_count > self.max_bindings:
                raise SrtpError(
                    SRTP_BINDING_CAPACITY,
                    {"requested": len(candidates),
                     "current": active_count,
                     "max_bindings": self.max_bindings},
                )

            created = self._create_bindings(candidates)
            for mid, binding, key in created:
                self._bindings[mid] = binding
                self._keys[mid] = key

            self._counters["offers"] += 1
            return {mid: binding for mid, binding, _ in created}

    def accept_answer(self, sdp: str) -> dict[str, Binding]:
        with self._lock:
            sections = self._parse_sdp(sdp)
            answer_mids = [section.mid for section in sections]
            offer_mids = set(self._bindings)

            if set(answer_mids) != offer_mids or len(answer_mids) != len(offer_mids):
                raise SrtpError(
                    SRTP_SDP_MISMATCH,
                    {"expected": tuple(self._bindings),
                     "received": tuple(answer_mids)},
                )

            prepared = []
            for section in sections:
                self._validate_fingerprint(section)
                old_binding = self._bindings[section.mid]
                role = section.setup if section.setup is not None else old_binding.role
                prepared.append(replace(old_binding, role=role))

            result = {}
            for binding in prepared:
                self._bindings[binding.mid] = binding
                result[binding.mid] = binding

            self._counters["answers"] += 1
            return result

    def verify_peer(self, mid: str, cert_der: bytes) -> bool:
        with self._lock:
            self._ensure_usable_segment(mid)
            binding = self._bindings[mid]
            if not isinstance(cert_der, (bytes, bytearray, memoryview)):
                raise SrtpError(
                    SRTP_FINGERPRINT_INVALID,
                    {"mid": mid, "reason": "certificate DER must be bytes"},
                )

            hash_name = _HASH_NAMES.get(binding.algorithm,
                                        binding.algorithm.replace("-", ""))
            try:
                actual = hashlib.new(hash_name, bytes(cert_der)).digest()
            except (ValueError, TypeError) as exc:
                raise SrtpError(
                    SRTP_ALGORITHM_NOT_ALLOWED,
                    {"mid": mid, "algorithm": binding.algorithm},
                ) from exc

            actual_hex = actual.hex().upper()
            expected_hex = binding.fingerprint.replace(":", "").upper()
            if not hmac.compare_digest(actual_hex, expected_hex):
                self._reject_segment(mid)
                self._counters["rejected"] += 1
                raise SrtpError(
                    SRTP_FINGERPRINT_MISMATCH,
                    {"mid": mid, "algorithm": binding.algorithm},
                )

            verified_binding = replace(binding, verified=True)
            self._bindings[mid] = verified_binding
            if mid not in self._keys:
                self._keys[mid] = self._derive_key(
                    verified_binding.context_id,
                    mid,
                    expected_hex,
                )
            self._counters["verified"] += 1
            return True

    def renegotiate(self, sdp: str) -> dict:
        with self._lock:
            sections = self._parse_sdp(sdp)
            candidates = self._prepare_candidates(sections)
            new_by_mid = {
                section.mid: (section, fingerprint_key)
                for section, fingerprint_key, _ in candidates
            }
            new_mids = [section.mid for section in sections]

            for mid in new_mids:
                if mid in self._rejected:
                    raise SrtpError(
                        SRTP_SEGMENT_REJECTED,
                        {"mid": mid, "reason": "segment was rejected"},
                    )

            active_mids = [
                mid for mid in self._bindings if mid not in self._rejected
            ]
            added = tuple(mid for mid in new_mids if mid not in self._bindings)
            removed = tuple(mid for mid in active_mids if mid not in new_by_mid)
            unchanged = tuple(mid for mid in new_mids if mid in self._bindings)

            changed = []
            for mid in unchanged:
                binding = self._bindings[mid]
                _, fingerprint_key = new_by_mid[mid]
                current_key = binding.fingerprint.replace(":", "").upper()
                if (binding.algorithm, current_key) != (
                        new_by_mid[mid][0].fingerprint_algorithm,
                        fingerprint_key):
                    changed.append(mid)

            if changed:
                for mid in changed:
                    self._reject_segment(mid)
                    self._counters["rejected"] += 1
                raise SrtpError(
                    SRTP_FINGERPRINT_MISMATCH,
                    {"mids": tuple(changed), "reason": "fingerprint changed"},
                )

            final_count = len(active_mids) - len(removed) + len(added)
            if final_count > self.max_bindings:
                raise SrtpError(
                    SRTP_BINDING_CAPACITY,
                    {"final": final_count,
                     "max_bindings": self.max_bindings},
                )

            created = self._create_bindings(
                [candidate for candidate in candidates
                 if candidate[0].mid in added]
            )

            for mid in removed:
                self._bindings.pop(mid, None)
                self._keys.pop(mid, None)

            for mid, binding, key in created:
                self._bindings[mid] = binding
                self._keys[mid] = key

            for mid in unchanged:
                section, _ = new_by_mid[mid]
                if section.setup is not None:
                    self._bindings[mid] = replace(
                        self._bindings[mid], role=section.setup
                    )

            for mid in tuple(self._rejected):
                if mid not in new_by_mid:
                    self._rejected.discard(mid)
                    self._bindings.pop(mid, None)
                    self._keys.pop(mid, None)

            self._counters["renegotiations"] += 1
            return {
                "added": added,
                "removed": removed,
                "unchanged": unchanged,
            }

    def key_material(self, mid: str) -> bytes:
        with self._lock:
            if mid in self._rejected:
                raise SrtpError(SRTP_SEGMENT_REJECTED, {"mid": mid})
            if mid not in self._bindings or mid not in self._keys:
                raise SrtpError(SRTP_SEGMENT_NOT_FOUND, {"mid": mid})
            binding = self._bindings[mid]
            if not binding.verified:
                raise SrtpError(SRTP_SEGMENT_NOT_VERIFIED, {"mid": mid})
            return self._keys[mid]

    def release(self, mid: str) -> bool:
        with self._lock:
            existed = mid in self._bindings or mid in self._rejected
            self._bindings.pop(mid, None)
            self._keys.pop(mid, None)
            self._rejected.discard(mid)
            return existed

    def bindings(self) -> tuple[Binding, ...]:
        with self._lock:
            return tuple(
                binding
                for mid, binding in self._bindings.items()
                if mid not in self._rejected
            )

    def snapshot(self) -> dict:
        with self._lock:
            records = []
            for binding in self._bindings.values():
                record = asdict(binding)
                if binding.mid in self._rejected:
                    record["rejected"] = True
                records.append(record)
            for mid in sorted(self._rejected):
                if mid not in self._bindings:
                    records.append({"mid": mid, "rejected": True})

            state = {
                "version": _SNAPSHOT_VERSION,
                "bindings": records,
                "counters": copy.deepcopy(self._counters),
            }
            state["counters"]["context_sequence"] = self._next_context_id
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            restored = self._build_restore_state(state)
            self._bindings = restored["bindings"]
            self._keys = restored["keys"]
            self._rejected = restored["rejected"]
            self._next_context_id = restored["next_context_id"]
            self._counters = restored["counters"]

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._counters)

    def close(self) -> None:
        with self._lock:
            self._bindings.clear()
            self._keys.clear()
            self._rejected.clear()

    def _parse_sdp(self, sdp: Any) -> tuple[MediaSection, ...]:
        if isinstance(sdp, bytes):
            try:
                sdp = sdp.decode("utf-8")
            except UnicodeDecodeError as exc:
                raise SrtpError(SRTP_INVALID_SDP, "SDP is not valid UTF-8") from exc
        if not isinstance(sdp, str):
            raise SrtpError(SRTP_INVALID_SDP, "SDP must be a string")

        sections: list[MediaSection] = []
        current: dict[str, Any] | None = None
        seen_mids: set[str] = set()

        for raw_line in sdp.splitlines():
            line = raw_line.strip()
            if not line:
                continue

            if line.startswith("m="):
                if current is not None and current["mid"] is None:
                    raise SrtpError(
                        SRTP_INVALID_SDP,
                        "media section is missing a=mid",
                    )
                if current is not None:
                    sections.append(self._media_section_from_dict(current))
                current = self._parse_m_line(line)
                continue

            if current is None:
                continue

            if line == "a=mid" or line.startswith("a=mid:"):
                mid = line.split(":", 1)[1].strip() if ":" in line else ""
                if not mid:
                    raise SrtpError(SRTP_INVALID_SDP, "a=mid value is empty")
                if current["mid"] is not None:
                    raise SrtpError(SRTP_INVALID_SDP,
                                    {"mid": mid, "reason": "duplicate a=mid"})
                if mid in seen_mids:
                    raise SrtpError(SRTP_INVALID_SDP,
                                    {"mid": mid, "reason": "duplicate mid"})
                current["mid"] = mid
                seen_mids.add(mid)

            elif line.startswith("a=fingerprint:") or line == "a=fingerprint":
                if current["fingerprint_seen"]:
                    raise SrtpError(
                        SRTP_INVALID_SDP,
                        {"mid": current.get("mid"),
                         "reason": "duplicate a=fingerprint"},
                    )
                current["fingerprint_seen"] = True
                rest = line.split(":", 1)[1].strip() if ":" in line else ""
                parts = rest.split(None, 1)
                if parts:
                    current["fingerprint_algorithm"] = parts[0].strip().lower()
                if len(parts) == 2 and parts[1].strip():
                    current["fingerprint_value"] = parts[1].strip().upper()

            elif line.startswith("a=setup:") or line == "a=setup":
                setup = line.split(":", 1)[1].strip() if ":" in line else ""
                current["setup"] = setup or None

        if current is not None:
            if current["mid"] is None:
                raise SrtpError(SRTP_INVALID_SDP,
                                "media section is missing a=mid")
            sections.append(self._media_section_from_dict(current))

        return tuple(sections)

    @staticmethod
    def _parse_m_line(line: str) -> dict[str, Any]:
        parts = line[2:].strip().split()
        if len(parts) < 3:
            raise SrtpError(SRTP_INVALID_SDP,
                            {"line": line, "reason": "invalid m= line"})

        media = parts[0]
        port_text = parts[1].split("/", 1)[0]
        protocol = parts[2]
        try:
            port = int(port_text)
        except ValueError as exc:
            raise SrtpError(
                SRTP_INVALID_SDP,
                {"line": line, "reason": "invalid media port"},
            ) from exc
        if not 0 <= port <= 65535 or not media or not protocol:
            raise SrtpError(SRTP_INVALID_SDP,
                            {"line": line, "reason": "invalid m= line"})

        return {
            "mid": None,
            "media": media,
            "port": port,
            "protocol": protocol,
            "fingerprint_algorithm": None,
            "fingerprint_value": None,
            "setup": None,
            "fingerprint_seen": False,
        }

    @staticmethod
    def _media_section_from_dict(data: dict[str, Any]) -> MediaSection:
        return MediaSection(
            mid=data["mid"],
            media=data["media"],
            port=data["port"],
            protocol=data["protocol"],
            fingerprint_algorithm=data["fingerprint_algorithm"],
            fingerprint_value=data["fingerprint_value"],
            setup=data["setup"],
        )

    def _prepare_candidates(
        self, sections: tuple[MediaSection, ...]
    ) -> list[tuple[MediaSection, str, str]]:
        candidates = []
        for section in sections:
            fingerprint_key = self._validate_fingerprint(section)
            role = section.setup if section.setup is not None else _DEFAULT_ROLE
            candidates.append((section, fingerprint_key, role))
        return candidates

    def _validate_fingerprint(self, section: MediaSection) -> str:
        algorithm = section.fingerprint_algorithm
        fingerprint = section.fingerprint_value
        if not algorithm or not fingerprint:
            raise SrtpError(
                SRTP_FINGERPRINT_MISSING,
                {"mid": section.mid},
            )

        if algorithm not in self.allowed_algorithms:
            raise SrtpError(
                SRTP_ALGORITHM_NOT_ALLOWED,
                {"mid": section.mid, "algorithm": algorithm,
                 "allowed_algorithms": self.allowed_algorithms},
            )

        digest_size = _DIGEST_SIZES.get(algorithm)
        if digest_size is None:
            hash_name = _HASH_NAMES.get(algorithm, algorithm.replace("-", ""))
            try:
                digest_size = hashlib.new(hash_name).digest_size
            except (ValueError, TypeError) as exc:
                raise SrtpError(
                    SRTP_ALGORITHM_NOT_ALLOWED,
                    {"mid": section.mid, "algorithm": algorithm},
                ) from exc

        hex_digest = fingerprint.replace(":", "")
        if (len(hex_digest) != digest_size * 2
                or any(character not in "0123456789abcdefABCDEF"
                       for character in hex_digest)):
            raise SrtpError(
                SRTP_FINGERPRINT_INVALID,
                {"mid": section.mid, "algorithm": algorithm},
            )
        return hex_digest.upper()

    def _create_bindings(
        self, candidates: list[tuple[MediaSection, str, str]]
    ) -> list[tuple[str, Binding, bytes]]:
        created = []
        context_id = self._next_context_id
        for section, fingerprint_key, role in candidates:
            binding = Binding(
                mid=section.mid,
                algorithm=section.fingerprint_algorithm,
                fingerprint=section.fingerprint_value,
                role=role,
                context_id=context_id,
                verified=False,
            )
            key = self._derive_key(context_id, section.mid, fingerprint_key)
            created.append((section.mid, binding, key))
            context_id += 1

        self._next_context_id = context_id
        return created

    @staticmethod
    def _derive_key(context_id: int, mid: str, fingerprint_key: str) -> bytes:
        message = f"{context_id}\0{mid}\0{fingerprint_key}".encode("utf-8")
        return hmac.new(
            b"srtp-fingerprint-binder-v1",
            message,
            hashlib.sha256,
        ).digest()[:_KEY_LENGTH]

    def _ensure_usable_segment(self, mid: str) -> None:
        if mid in self._rejected:
            raise SrtpError(SRTP_SEGMENT_REJECTED, {"mid": mid})
        if mid not in self._bindings:
            raise SrtpError(SRTP_SEGMENT_NOT_FOUND, {"mid": mid})

    def _reject_segment(self, mid: str) -> None:
        binding = self._bindings.get(mid)
        if binding is not None and binding.verified:
            self._bindings[mid] = replace(binding, verified=False)
        self._keys.pop(mid, None)
        self._rejected.add(mid)

    def _build_restore_state(self, state: Any) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise SrtpError(SRTP_SNAPSHOT_INVALID, "snapshot must be a dict")
        if set(state.keys()) != {"version", "bindings", "counters"}:
            raise SrtpError(SRTP_SNAPSHOT_INVALID,
                            "snapshot has invalid top-level keys")
        if state.get("version") != _SNAPSHOT_VERSION:
            raise SrtpError(SRTP_SNAPSHOT_INVALID, "unsupported snapshot version")

        raw_bindings = self._normalize_snapshot_bindings(state.get("bindings"))
        raw_counters = state.get("counters")
        if raw_bindings is None:
            raise SrtpError(SRTP_SNAPSHOT_INVALID, "bindings must be a list")
        if not isinstance(raw_counters, dict):
            raise SrtpError(SRTP_SNAPSHOT_INVALID, "counters must be a dict")

        counters = {}
        for key in _COUNTER_KEYS:
            value = raw_counters.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise SrtpError(SRTP_SNAPSHOT_INVALID,
                                {"counter": key, "value": value})
            counters[key] = value

        raw_sequence = raw_counters.get("context_sequence")
        max_context_id = 0
        bindings: dict[str, Binding] = {}
        keys: dict[str, bytes] = {}
        rejected: set[str] = set()
        seen_mids: set[str] = set()

        for record in raw_bindings:
            if not isinstance(record, dict):
                raise SrtpError(SRTP_SNAPSHOT_INVALID,
                                "binding record must be a dict")

            mid = record.get("mid")
            if not isinstance(mid, str) or not mid or mid in seen_mids:
                raise SrtpError(SRTP_SNAPSHOT_INVALID, "binding mid is invalid")
            seen_mids.add(mid)

            is_rejected = record.get("rejected", False)
            if not isinstance(is_rejected, bool):
                raise SrtpError(SRTP_SNAPSHOT_INVALID,
                                {"mid": mid, "reason": "invalid rejected flag"})

            algorithm = record.get("algorithm")
            fingerprint = record.get("fingerprint")
            role = record.get("role", _DEFAULT_ROLE)
            context_id = record.get("context_id")
            verified = record.get("verified", False)

            if (not isinstance(algorithm, str) or not algorithm
                    or not isinstance(fingerprint, str) or not fingerprint
                    or not isinstance(role, str)
                    or not isinstance(context_id, int)
                    or isinstance(context_id, bool)
                    or context_id <= 0
                    or not isinstance(verified, bool)):
                raise SrtpError(SRTP_SNAPSHOT_INVALID,
                                {"mid": mid, "reason": "invalid binding fields"})

            fingerprint_key = fingerprint.replace(":", "").upper()
            digest_size = _DIGEST_SIZES.get(algorithm.lower())
            if digest_size is not None:
                if (len(fingerprint_key) != digest_size * 2
                        or any(character not in "0123456789ABCDEF"
                               for character in fingerprint_key)):
                    raise SrtpError(
                        SRTP_SNAPSHOT_INVALID,
                        {"mid": mid, "reason": "invalid fingerprint"},
                    )

            binding = Binding(
                mid=mid,
                algorithm=algorithm.lower(),
                fingerprint=fingerprint.upper(),
                role=role,
                context_id=context_id,
                verified=verified,
            )
            bindings[mid] = binding
            max_context_id = max(max_context_id, context_id)

            if is_rejected:
                rejected.add(mid)
            else:
                raw_key = record.get("key_material")
                if raw_key is not None:
                    if not isinstance(raw_key, str):
                        raise SrtpError(SRTP_SNAPSHOT_INVALID,
                                        {"mid": mid,
                                         "reason": "key_material must be hex"})
                    try:
                        key = bytes.fromhex(raw_key)
                    except ValueError as exc:
                        raise SrtpError(
                            SRTP_SNAPSHOT_INVALID,
                            {"mid": mid, "reason": "invalid key_material"},
                        ) from exc
                    keys[mid] = key
                else:
                    keys[mid] = self._derive_key(
                        context_id, mid, fingerprint_key
                    )

        if raw_sequence is None:
            next_context_id = max_context_id + 1 if max_context_id else 1
        else:
            if (not isinstance(raw_sequence, int)
                    or isinstance(raw_sequence, bool)
                    or raw_sequence <= max_context_id):
                raise SrtpError(SRTP_SNAPSHOT_INVALID,
                                {"context_sequence": raw_sequence})
            next_context_id = raw_sequence

        return {
            "bindings": bindings,
            "keys": keys,
            "rejected": rejected,
            "next_context_id": next_context_id,
            "counters": counters,
        }

    @staticmethod
    def _normalize_snapshot_bindings(raw_bindings: Any) -> list[Any] | None:
        if isinstance(raw_bindings, dict):
            records = []
            for mid, record in raw_bindings.items():
                if hasattr(record, "__dataclass_fields__"):
                    record = asdict(record)
                if isinstance(record, dict):
                    record = dict(record)
                    record.setdefault("mid", mid)
                records.append(record)
            return records

        if isinstance(raw_bindings, (list, tuple)):
            records = []
            for record in raw_bindings:
                if hasattr(record, "__dataclass_fields__"):
                    record = asdict(record)
                records.append(record)
            return list(records)

        return None
