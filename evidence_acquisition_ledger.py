"""Evidence acquisition ledger: source attestation, chained digests, custody chain."""

from __future__ import annotations

import copy
import hashlib
import hmac
import json
import threading
from dataclasses import asdict, dataclass, replace
from typing import Any


class EvidenceError(ValueError):
    """Raised when an evidence ledger operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


SOURCE_PROTECTIONS = ("write-blocker", "readonly-mount")

STATUS_ACTIVE = "active"
STATUS_INTERRUPTED = "interrupted"
STATUS_SEALED = "sealed"
STATUS_CONTAMINATED = "contaminated"
STATUS_UNUSABLE = "unusable"

_BUSY_STATUSES = frozenset((STATUS_ACTIVE, STATUS_INTERRUPTED))
_REPORTABLE_STATUSES = frozenset(
    (STATUS_ACTIVE, STATUS_INTERRUPTED, STATUS_CONTAMINATED, STATUS_UNUSABLE)
)
_CHAIN_KINDS = frozenset(
    ("case_open", "acquire_open", "chunk", "interrupt", "resume", "seal")
)
_SNAPSHOT_VERSION = 1
_GENESIS_DIGEST = hashlib.sha256(b"").hexdigest()


@dataclass(frozen=True)
class CaseRecord:
    case_id: str
    subject: str
    opened_at: str


@dataclass(frozen=True)
class AcquisitionRecord:
    acq_id: str
    case_id: str
    device_id: str
    source_protection: str
    status: str
    chunks: int
    bytes_read: int
    final_hash: str | None
    opened_at: str


@dataclass(frozen=True)
class ChunkRecord:
    index: int
    length: int
    digest: str


@dataclass(frozen=True)
class ChainEntry:
    seq: int
    case_id: str
    acq_id: str
    kind: str
    payload_hash: str
    signer_epoch: int
    signature: str


def _canonical_digest(payload: Any) -> str:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def _as_data_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "__dataclass_fields__"):
        return asdict(value)
    if isinstance(value, dict):
        return value
    raise EvidenceError("EVIDENCE_SNAPSHOT_INVALID", {"reason": "expected_object"})


class EvidenceLedger:
    """Register cases, attest sources, chain digests, and keep custody entries."""

    def __init__(self, *, block_size: int = 4096) -> None:
        self.block_size = block_size
        self._lock = threading.RLock()
        self._cases: dict[str, CaseRecord] = {}
        self._acquisitions: dict[str, AcquisitionRecord] = {}
        self._acq_order: list[str] = []
        self._chunks: dict[str, list[ChunkRecord]] = {}
        self._incidents: dict[str, dict[str, list[dict[str, Any]]]] = {}
        self._chain: list[ChainEntry] = []
        self._keys: dict[int, str] = {1: "ledger-epoch-1"}
        self._current_epoch = 1
        self._counters: dict[str, int] = {"acq_seq": 0}

    def open_case(self, case_id: str, *, subject: str, now: str) -> CaseRecord:
        with self._lock:
            existing = self._cases.get(case_id)
            if existing is not None:
                if existing.subject != subject:
                    raise EvidenceError(
                        "EVIDENCE_CASE_CONFLICT",
                        {"case_id": case_id, "subject": subject},
                    )
                return existing

            record = CaseRecord(case_id=case_id, subject=subject, opened_at=now)
            self._cases[case_id] = record
            payload_hash = _canonical_digest(
                {
                    "kind": "case_open",
                    "case_id": case_id,
                    "subject": subject,
                    "opened_at": now,
                }
            )
            self._append_chain_locked(
                case_id=case_id,
                acq_id="",
                kind="case_open",
                payload_hash=payload_hash,
            )
            return record

    def acquire(
        self,
        case_id: str,
        *,
        device_id: str,
        source_protection: str,
        now: str,
    ) -> AcquisitionRecord:
        with self._lock:
            self._get_case_locked(case_id)
            if source_protection not in SOURCE_PROTECTIONS:
                raise EvidenceError(
                    "EVIDENCE_SOURCE_UNPROTECTED",
                    {"source_protection": source_protection},
                )

            busy = self._busy_acquisition_for_device_locked(device_id)
            if busy is not None:
                raise EvidenceError(
                    "EVIDENCE_DEVICE_BUSY",
                    {"device_id": device_id, "acq_id": busy.acq_id},
                )

            acq_seq = int(self._counters.get("acq_seq", 0)) + 1
            self._counters["acq_seq"] = acq_seq
            acq_id = f"ACQ-{acq_seq}"
            record = AcquisitionRecord(
                acq_id=acq_id,
                case_id=case_id,
                device_id=device_id,
                source_protection=source_protection,
                status=STATUS_ACTIVE,
                chunks=0,
                bytes_read=0,
                final_hash=None,
                opened_at=now,
            )
            self._acquisitions[acq_id] = record
            self._acq_order.append(acq_id)
            self._chunks[acq_id] = []
            self._incidents[acq_id] = {"writes": [], "corruptions": []}

            payload_hash = _canonical_digest(
                {
                    "kind": "acquire_open",
                    "acq_id": acq_id,
                    "case_id": case_id,
                    "device_id": device_id,
                    "source_protection": source_protection,
                    "opened_at": now,
                }
            )
            self._append_chain_locked(
                case_id=case_id,
                acq_id=acq_id,
                kind="acquire_open",
                payload_hash=payload_hash,
            )
            return record

    def chunk(
        self,
        acq_id: str,
        *,
        index: int,
        data: bytes,
        now: str,
    ) -> ChunkRecord:
        with self._lock:
            acquisition = self._get_acquisition_locked(acq_id)
            if acquisition.status != STATUS_ACTIVE:
                raise EvidenceError(
                    "EVIDENCE_STATE_INVALID",
                    {"acq_id": acq_id, "status": acquisition.status, "op": "chunk"},
                )

            chunks = self._chunks[acq_id]
            expected_index = len(chunks)
            if (
                isinstance(index, int)
                and not isinstance(index, bool)
                and 0 <= index < expected_index
            ):
                raise EvidenceError(
                    "EVIDENCE_CHUNK_DUPLICATE",
                    {"acq_id": acq_id, "index": index},
                )
            if (
                isinstance(index, bool)
                or not isinstance(index, int)
                or index != expected_index
            ):
                raise EvidenceError(
                    "EVIDENCE_CHUNK_GAP",
                    {
                        "acq_id": acq_id,
                        "index": index,
                        "expected_index": expected_index,
                    },
                )

            try:
                block = bytes(data)
            except Exception as exc:
                raise EvidenceError(
                    "EVIDENCE_CHUNK_EMPTY",
                    {"acq_id": acq_id, "index": index, "reason": "invalid_data"},
                ) from exc
            if not block:
                raise EvidenceError(
                    "EVIDENCE_CHUNK_EMPTY",
                    {"acq_id": acq_id, "index": index},
                )

            previous_digest = chunks[-1].digest if chunks else _GENESIS_DIGEST
            digest = hashlib.sha256(
                bytes.fromhex(previous_digest) + block
            ).hexdigest()
            record = ChunkRecord(index=index, length=len(block), digest=digest)
            chunks.append(record)

            updated = replace(
                acquisition,
                chunks=len(chunks),
                bytes_read=acquisition.bytes_read + len(block),
            )
            self._acquisitions[acq_id] = updated
            self._append_chain_locked(
                case_id=acquisition.case_id,
                acq_id=acq_id,
                kind="chunk",
                payload_hash=digest,
            )
            return record

    def interrupt(self, acq_id: str, *, now: str) -> AcquisitionRecord:
        with self._lock:
            acquisition = self._get_acquisition_locked(acq_id)
            if acquisition.status != STATUS_ACTIVE:
                raise EvidenceError(
                    "EVIDENCE_STATE_INVALID",
                    {
                        "acq_id": acq_id,
                        "status": acquisition.status,
                        "op": "interrupt",
                    },
                )

            updated = replace(acquisition, status=STATUS_INTERRUPTED)
            self._acquisitions[acq_id] = updated
            payload_hash = _canonical_digest(
                {
                    "kind": "interrupt",
                    "acq_id": acq_id,
                    "at": now,
                    "chunks": updated.chunks,
                    "bytes_read": updated.bytes_read,
                }
            )
            self._append_chain_locked(
                case_id=acquisition.case_id,
                acq_id=acq_id,
                kind="interrupt",
                payload_hash=payload_hash,
            )
            return updated

    def resume(self, acq_id: str, *, now: str) -> AcquisitionRecord:
        with self._lock:
            acquisition = self._get_acquisition_locked(acq_id)
            if acquisition.status != STATUS_INTERRUPTED:
                raise EvidenceError(
                    "EVIDENCE_STATE_INVALID",
                    {
                        "acq_id": acq_id,
                        "status": acquisition.status,
                        "op": "resume",
                    },
                )

            updated = replace(acquisition, status=STATUS_ACTIVE)
            self._acquisitions[acq_id] = updated
            payload_hash = _canonical_digest(
                {
                    "kind": "resume",
                    "acq_id": acq_id,
                    "at": now,
                    "next_index": len(self._chunks[acq_id]),
                }
            )
            self._append_chain_locked(
                case_id=acquisition.case_id,
                acq_id=acq_id,
                kind="resume",
                payload_hash=payload_hash,
            )
            return updated

    def observe_write(
        self,
        acq_id: str,
        *,
        offset: int,
        length: int,
        now: str,
    ) -> AcquisitionRecord:
        with self._lock:
            acquisition = self._get_acquisition_locked(acq_id)
            if acquisition.status not in _REPORTABLE_STATUSES:
                raise EvidenceError(
                    "EVIDENCE_STATE_INVALID",
                    {
                        "acq_id": acq_id,
                        "status": acquisition.status,
                        "op": "observe_write",
                    },
                )

            bucket = self._incidents.setdefault(
                acq_id, {"writes": [], "corruptions": []}
            )
            bucket.setdefault("writes", []).append(
                {"offset": offset, "length": length, "at": now}
            )

            if acquisition.status in (STATUS_ACTIVE, STATUS_INTERRUPTED):
                acquisition = replace(acquisition, status=STATUS_CONTAMINATED)
                self._acquisitions[acq_id] = acquisition
            return self._acquisitions[acq_id]

    def report_corruption(
        self,
        acq_id: str,
        *,
        index: int,
        now: str,
    ) -> AcquisitionRecord:
        with self._lock:
            acquisition = self._get_acquisition_locked(acq_id)
            chunks = self._chunks[acq_id]
            if (
                isinstance(index, bool)
                or not isinstance(index, int)
                or not 0 <= index < len(chunks)
            ):
                raise EvidenceError(
                    "EVIDENCE_CHUNK_UNKNOWN",
                    {"acq_id": acq_id, "index": index},
                )

            bucket = self._incidents.setdefault(
                acq_id, {"writes": [], "corruptions": []}
            )
            bucket.setdefault("corruptions", []).append(
                {"index": index, "at": now, "digest": chunks[index].digest}
            )

            if acquisition.status in (
                STATUS_ACTIVE,
                STATUS_INTERRUPTED,
                STATUS_CONTAMINATED,
            ):
                acquisition = replace(acquisition, status=STATUS_UNUSABLE)
                self._acquisitions[acq_id] = acquisition
            return self._acquisitions[acq_id]

    def close(self, acq_id: str, *, now: str) -> AcquisitionRecord:
        with self._lock:
            acquisition = self._get_acquisition_locked(acq_id)
            if acquisition.status != STATUS_ACTIVE:
                raise EvidenceError(
                    "EVIDENCE_STATE_INVALID",
                    {
                        "acq_id": acq_id,
                        "status": acquisition.status,
                        "op": "close",
                    },
                )

            chunks = self._chunks[acq_id]
            final_hash = chunks[-1].digest if chunks else _GENESIS_DIGEST
            sealed = replace(
                acquisition,
                status=STATUS_SEALED,
                chunks=len(chunks),
                bytes_read=sum(chunk.length for chunk in chunks),
                final_hash=final_hash,
            )
            self._acquisitions[acq_id] = sealed
            self._append_chain_locked(
                case_id=acquisition.case_id,
                acq_id=acq_id,
                kind="seal",
                payload_hash=final_hash,
            )
            return sealed

    def verify_chain(self, case_id: str) -> dict:
        with self._lock:
            self._get_case_locked(case_id)
            rows = self._entries_for_case_locked(case_id)
            previous_signature = ""
            expected_seq = 1
            chunk_cursors: dict[str, int] = {}

            for entry in rows:
                if entry.seq != expected_seq:
                    return {
                        "case_id": case_id,
                        "ok": False,
                        "entries": len(rows),
                        "broken_seq": entry.seq,
                    }

                key = self._keys.get(entry.signer_epoch)
                if key is None:
                    broken_seq = entry.seq
                else:
                    expected_signature = self._signature_for_entry_locked(
                        entry, previous_signature
                    )
                    signature_valid = hmac.compare_digest(
                        expected_signature, entry.signature
                    )
                    state_valid = signature_valid and (
                        self._entry_payload_matches_state_locked(
                            entry, chunk_cursors
                        )
                    )
                    if state_valid:
                        previous_signature = entry.signature
                        expected_seq += 1
                        continue
                    broken_seq = entry.seq

                return {
                    "case_id": case_id,
                    "ok": False,
                    "entries": len(rows),
                    "broken_seq": broken_seq,
                }

            return {
                "case_id": case_id,
                "ok": True,
                "entries": len(rows),
                "broken_seq": None,
            }

    def _entry_payload_matches_state_locked(
        self,
        entry: ChainEntry,
        chunk_cursors: dict[str, int],
    ) -> bool:
        if entry.kind == "chunk":
            chunks = self._chunks.get(entry.acq_id)
            if chunks is None:
                return False
            chunk_index = chunk_cursors.get(entry.acq_id, 0)
            if chunk_index >= len(chunks):
                return False
            chunk_cursors[entry.acq_id] = chunk_index + 1
            return entry.payload_hash == chunks[chunk_index].digest

        if entry.kind == "seal":
            acquisition = self._acquisitions.get(entry.acq_id)
            return (
                acquisition is not None
                and acquisition.status == STATUS_SEALED
                and entry.payload_hash == acquisition.final_hash
            )

        return True

    def rotate_signing_key(self, epoch: int, key: str) -> None:
        with self._lock:
            if isinstance(epoch, bool) or not isinstance(epoch, int) or epoch < 1:
                raise EvidenceError(
                    "EVIDENCE_STATE_INVALID",
                    {"epoch": epoch, "reason": "invalid_epoch"},
                )
            if not isinstance(key, str) or not key:
                raise EvidenceError(
                    "EVIDENCE_STATE_INVALID",
                    {"epoch": epoch, "reason": "invalid_key"},
                )
            existing = self._keys.get(epoch)
            if existing is not None and existing != key:
                raise EvidenceError(
                    "EVIDENCE_STATE_INVALID",
                    {"epoch": epoch, "reason": "epoch_key_immutable"},
                )
            self._keys[epoch] = key
            self._current_epoch = epoch

    def entries(self, case_id: str) -> list[ChainEntry]:
        with self._lock:
            self._get_case_locked(case_id)
            return self._entries_for_case_locked(case_id)

    def chunks(self, acq_id: str) -> list[ChunkRecord]:
        with self._lock:
            self._get_acquisition_locked(acq_id)
            return list(self._chunks[acq_id])

    def cases(self) -> list[CaseRecord]:
        with self._lock:
            return list(self._cases.values())

    def acquisitions(self, case_id: str) -> list[AcquisitionRecord]:
        with self._lock:
            self._get_case_locked(case_id)
            return [
                self._acquisitions[acq_id]
                for acq_id in self._acq_order
                if self._acquisitions[acq_id].case_id == case_id
            ]

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": _SNAPSHOT_VERSION,
                "block_size": self.block_size,
                "cases": {
                    case_id: asdict(record)
                    for case_id, record in self._cases.items()
                },
                "acquisitions": {
                    acq_id: asdict(record)
                    for acq_id, record in self._acquisitions.items()
                },
                "chunks": {
                    acq_id: [asdict(chunk) for chunk in chunks]
                    for acq_id, chunks in self._chunks.items()
                },
                "incidents": copy.deepcopy(self._incidents),
                "chain": [asdict(entry) for entry in self._chain],
                "keys": copy.deepcopy(self._keys),
                "current_epoch": self._current_epoch,
                "counters": copy.deepcopy(self._counters),
                "stats": self.stats(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        candidate = self._build_restore_candidate(state)
        with self._lock:
            self.block_size = candidate["block_size"]
            self._cases = candidate["cases"]
            self._acquisitions = candidate["acquisitions"]
            self._acq_order = candidate["acq_order"]
            self._chunks = candidate["chunks"]
            self._incidents = candidate["incidents"]
            self._chain = candidate["chain"]
            self._keys = candidate["keys"]
            self._current_epoch = candidate["current_epoch"]
            self._counters = candidate["counters"]

    def stats(self) -> dict:
        with self._lock:
            return {
                "cases": len(self._cases),
                "acquisitions": len(self._acquisitions),
                "chunks": sum(len(items) for items in self._chunks.values()),
                "bytes": sum(
                    chunk.length
                    for items in self._chunks.values()
                    for chunk in items
                ),
                "sealed": sum(
                    record.status == STATUS_SEALED
                    for record in self._acquisitions.values()
                ),
                "contaminated": sum(
                    record.status == STATUS_CONTAMINATED
                    or bool(
                        self._incidents.get(record.acq_id, {}).get("writes")
                    )
                    for record in self._acquisitions.values()
                ),
                "unusable": sum(
                    record.status == STATUS_UNUSABLE
                    or bool(
                        self._incidents.get(record.acq_id, {}).get("corruptions")
                    )
                    for record in self._acquisitions.values()
                ),
                "chain_entries": len(self._chain),
            }

    def _get_case_locked(self, case_id: str) -> CaseRecord:
        case = self._cases.get(case_id)
        if case is None:
            raise EvidenceError("EVIDENCE_CASE_UNKNOWN", {"case_id": case_id})
        return case

    def _get_acquisition_locked(self, acq_id: str) -> AcquisitionRecord:
        acquisition = self._acquisitions.get(acq_id)
        if acquisition is None:
            raise EvidenceError("EVIDENCE_ACQ_UNKNOWN", {"acq_id": acq_id})
        return acquisition

    def _busy_acquisition_for_device_locked(
        self, device_id: str
    ) -> AcquisitionRecord | None:
        for acquisition in self._acquisitions.values():
            if (
                acquisition.device_id == device_id
                and acquisition.status in _BUSY_STATUSES
            ):
                return acquisition
        return None

    def _entries_for_case_locked(self, case_id: str) -> list[ChainEntry]:
        return [entry for entry in self._chain if entry.case_id == case_id]

    def _signature_payload_locked(
        self,
        entry: ChainEntry,
        previous_signature: str,
    ) -> dict[str, Any]:
        return {
            "seq": entry.seq,
            "case_id": entry.case_id,
            "acq_id": entry.acq_id,
            "kind": entry.kind,
            "payload_hash": entry.payload_hash,
            "signer_epoch": entry.signer_epoch,
            "previous_signature": previous_signature,
        }

    def _signature_for_entry_locked(
        self,
        entry: ChainEntry,
        previous_signature: str,
    ) -> str:
        key = self._keys[entry.signer_epoch].encode("utf-8")
        payload = self._signature_payload_locked(entry, previous_signature)
        message = json.dumps(
            payload,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return hmac.new(key, message, hashlib.sha256).hexdigest()

    def _append_chain_locked(
        self,
        *,
        case_id: str,
        acq_id: str,
        kind: str,
        payload_hash: str,
    ) -> ChainEntry:
        rows = self._entries_for_case_locked(case_id)
        seq = max((row.seq for row in rows), default=0) + 1
        previous = max(rows, key=lambda row: row.seq, default=None)
        previous_signature = previous.signature if previous is not None else ""
        epoch = self._current_epoch
        entry = ChainEntry(
            seq=seq,
            case_id=case_id,
            acq_id=acq_id,
            kind=kind,
            payload_hash=payload_hash,
            signer_epoch=epoch,
            signature="",
        )
        signature = self._signature_for_entry_locked(entry, previous_signature)
        entry = replace(entry, signature=signature)
        self._chain.append(entry)
        return entry

    def _build_restore_candidate(self, state: object) -> dict[str, Any]:
        try:
            if not isinstance(state, dict):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID",
                    {"reason": "snapshot_not_object"},
                )
            state = copy.deepcopy(state)

            version = state.get("version")
            if isinstance(version, bool) or version != _SNAPSHOT_VERSION:
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID",
                    {"reason": "unsupported_version", "version": version},
                )

            required_keys = (
                "cases",
                "acquisitions",
                "chunks",
                "chain",
                "keys",
                "counters",
                "stats",
            )
            for key in required_keys:
                if key not in state:
                    raise EvidenceError(
                        "EVIDENCE_SNAPSHOT_INVALID",
                        {"reason": "missing_key", "key": key},
                    )

            for key in ("cases", "acquisitions", "chunks", "keys", "counters"):
                if not isinstance(state[key], dict):
                    raise EvidenceError(
                        "EVIDENCE_SNAPSHOT_INVALID",
                        {"reason": "expected_object", "key": key},
                    )
            if not isinstance(state["chain"], list):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID",
                    {"reason": "expected_list", "key": "chain"},
                )

            block_size = state.get("block_size", 4096)
            if (
                isinstance(block_size, bool)
                or not isinstance(block_size, int)
                or block_size <= 0
            ):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID",
                    {"reason": "invalid_block_size"},
                )

            cases = EvidenceLedger._restore_cases(state["cases"])
            acquisitions, acq_order = EvidenceLedger._restore_acquisitions(
                state["acquisitions"], cases
            )
            chunks = EvidenceLedger._restore_chunks(state["chunks"], acquisitions)
            incidents = EvidenceLedger._restore_incidents(
                state.get("incidents", {}), acquisitions
            )
            chain = EvidenceLedger._restore_chain(
                state["chain"], cases, acquisitions
            )
            keys, current_epoch = EvidenceLedger._restore_keys(
                state["keys"], state.get("current_epoch")
            )
            counters = EvidenceLedger._restore_counters(
                state["counters"], acquisitions
            )

            if not isinstance(state["stats"], dict):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID",
                    {"reason": "expected_object", "key": "stats"},
                )

            return {
                "block_size": block_size,
                "cases": cases,
                "acquisitions": acquisitions,
                "acq_order": acq_order,
                "chunks": chunks,
                "incidents": incidents,
                "chain": chain,
                "keys": keys,
                "current_epoch": current_epoch,
                "counters": counters,
            }
        except EvidenceError:
            raise
        except Exception as exc:
            raise EvidenceError(
                "EVIDENCE_SNAPSHOT_INVALID",
                {"reason": "unparseable_snapshot", "error": str(exc)},
            ) from exc

    @staticmethod
    def _restore_cases(raw_cases: dict[Any, Any]) -> dict[str, CaseRecord]:
        cases: dict[str, CaseRecord] = {}
        for raw_id, raw_record in raw_cases.items():
            if not isinstance(raw_id, str):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "invalid_case_id"}
                )
            data = _as_data_dict(raw_record)
            if data.get("case_id", raw_id) != raw_id:
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "case_id_mismatch"}
                )
            subject = data["subject"]
            opened_at = data["opened_at"]
            if not isinstance(subject, str) or not isinstance(opened_at, str):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "invalid_case_fields"}
                )
            cases[raw_id] = CaseRecord(raw_id, subject, opened_at)
        return cases

    @staticmethod
    def _restore_acquisitions(
        raw_acquisitions: dict[Any, Any],
        cases: dict[str, CaseRecord],
    ) -> tuple[dict[str, AcquisitionRecord], list[str]]:
        acquisitions: dict[str, AcquisitionRecord] = {}
        order: list[str] = []
        for raw_id, raw_record in raw_acquisitions.items():
            if not isinstance(raw_id, str):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "invalid_acq_id"}
                )
            data = _as_data_dict(raw_record)
            if data.get("acq_id", raw_id) != raw_id:
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "acq_id_mismatch"}
                )

            case_id = data["case_id"]
            device_id = data["device_id"]
            protection = data["source_protection"]
            status = data["status"]
            opened_at = data["opened_at"]
            chunks_count = data["chunks"]
            bytes_read = data["bytes_read"]
            final_hash = data.get("final_hash")

            if case_id not in cases:
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "unknown_case"}
                )
            if (
                not isinstance(device_id, str)
                or protection not in SOURCE_PROTECTIONS
                or status
                not in (
                    STATUS_ACTIVE,
                    STATUS_INTERRUPTED,
                    STATUS_SEALED,
                    STATUS_CONTAMINATED,
                    STATUS_UNUSABLE,
                )
                or not isinstance(opened_at, str)
                or isinstance(chunks_count, bool)
                or not isinstance(chunks_count, int)
                or chunks_count < 0
                or isinstance(bytes_read, bool)
                or not isinstance(bytes_read, int)
                or bytes_read < 0
                or (final_hash is not None and not isinstance(final_hash, str))
            ):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID",
                    {"reason": "invalid_acquisition_fields", "acq_id": raw_id},
                )

            acquisitions[raw_id] = AcquisitionRecord(
                acq_id=raw_id,
                case_id=case_id,
                device_id=device_id,
                source_protection=protection,
                status=status,
                chunks=chunks_count,
                bytes_read=bytes_read,
                final_hash=final_hash,
                opened_at=opened_at,
            )
            order.append(raw_id)
        return acquisitions, order

    @staticmethod
    def _restore_chunks(
        raw_chunks: dict[Any, Any],
        acquisitions: dict[str, AcquisitionRecord],
    ) -> dict[str, list[ChunkRecord]]:
        chunks: dict[str, list[ChunkRecord]] = {}
        if set(raw_chunks) != set(acquisitions):
            raise EvidenceError(
                "EVIDENCE_SNAPSHOT_INVALID",
                {"reason": "chunks_acquisitions_mismatch"},
            )

        for acq_id, raw_items in raw_chunks.items():
            if not isinstance(acq_id, str) or acq_id not in acquisitions:
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "unknown_chunk_owner"}
                )
            if not isinstance(raw_items, list):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "chunks_not_list"}
                )

            items: list[ChunkRecord] = []
            total_bytes = 0
            for position, raw_chunk in enumerate(raw_items):
                data = _as_data_dict(raw_chunk)
                index = data["index"]
                length = data["length"]
                digest = data["digest"]
                if (
                    isinstance(index, bool)
                    or not isinstance(index, int)
                    or index != position
                    or isinstance(length, bool)
                    or not isinstance(length, int)
                    or length < 0
                    or not isinstance(digest, str)
                ):
                    raise EvidenceError(
                        "EVIDENCE_SNAPSHOT_INVALID",
                        {"reason": "invalid_chunk", "acq_id": acq_id},
                    )
                items.append(ChunkRecord(index=index, length=length, digest=digest))
                total_bytes += length

            record = acquisitions[acq_id]
            if record.chunks != len(items) or record.bytes_read != total_bytes:
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID",
                    {"reason": "chunk_totals_mismatch", "acq_id": acq_id},
                )
            chunks[acq_id] = items
        return chunks

    @staticmethod
    def _restore_incidents(
        raw_incidents: Any,
        acquisitions: dict[str, AcquisitionRecord],
    ) -> dict[str, dict[str, list[dict[str, Any]]]]:
        if raw_incidents is None:
            raw_incidents = {}
        if not isinstance(raw_incidents, dict):
            raise EvidenceError(
                "EVIDENCE_SNAPSHOT_INVALID", {"reason": "invalid_incidents"}
            )

        incidents: dict[str, dict[str, list[dict[str, Any]]]] = {}
        for acq_id, bucket in raw_incidents.items():
            if acq_id not in acquisitions or not isinstance(bucket, dict):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "invalid_incident_bucket"}
                )
            writes = bucket.get("writes", [])
            corruptions = bucket.get("corruptions", [])
            if not isinstance(writes, list) or not isinstance(corruptions, list):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "invalid_incident_list"}
                )
            incidents[acq_id] = {
                "writes": copy.deepcopy(writes),
                "corruptions": copy.deepcopy(corruptions),
            }

        for acq_id in acquisitions:
            incidents.setdefault(acq_id, {"writes": [], "corruptions": []})
        return incidents

    @staticmethod
    def _restore_chain(
        raw_chain: list[Any],
        cases: dict[str, CaseRecord],
        acquisitions: dict[str, AcquisitionRecord],
    ) -> list[ChainEntry]:
        chain: list[ChainEntry] = []
        for raw_entry in raw_chain:
            data = _as_data_dict(raw_entry)
            seq = data["seq"]
            case_id = data["case_id"]
            acq_id = data["acq_id"]
            kind = data["kind"]
            payload_hash = data["payload_hash"]
            signer_epoch = data["signer_epoch"]
            signature = data["signature"]

            if (
                isinstance(seq, bool)
                or not isinstance(seq, int)
                or seq < 1
                or case_id not in cases
                or not isinstance(acq_id, str)
                or (acq_id and acq_id not in acquisitions)
                or kind not in _CHAIN_KINDS
                or not isinstance(payload_hash, str)
                or isinstance(signer_epoch, bool)
                or not isinstance(signer_epoch, int)
                or signer_epoch < 1
                or not isinstance(signature, str)
                or not signature
            ):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "invalid_chain_entry"}
                )
            chain.append(
                ChainEntry(
                    seq=seq,
                    case_id=case_id,
                    acq_id=acq_id,
                    kind=kind,
                    payload_hash=payload_hash,
                    signer_epoch=signer_epoch,
                    signature=signature,
                )
            )
        return chain

    @staticmethod
    def _restore_keys(
        raw_keys: dict[Any, Any],
        raw_current_epoch: Any,
    ) -> tuple[dict[int, str], int]:
        keys: dict[int, str] = {}
        for raw_epoch, key in raw_keys.items():
            if isinstance(raw_epoch, bool):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "invalid_key_epoch"}
                )
            try:
                epoch = int(raw_epoch)
            except (TypeError, ValueError) as exc:
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "invalid_key_epoch"}
                ) from exc
            if epoch < 1 or not isinstance(key, str) or not key:
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "invalid_key"}
                )
            keys[epoch] = key

        if 1 not in keys:
            raise EvidenceError(
                "EVIDENCE_SNAPSHOT_INVALID", {"reason": "missing_initial_key"}
            )

        if raw_current_epoch is None:
            current_epoch = max(keys)
        else:
            current_epoch = raw_current_epoch
        if (
            isinstance(current_epoch, bool)
            or not isinstance(current_epoch, int)
            or current_epoch not in keys
        ):
            raise EvidenceError(
                "EVIDENCE_SNAPSHOT_INVALID",
                {"reason": "invalid_current_epoch"},
            )
        return keys, current_epoch

    @staticmethod
    def _restore_counters(
        raw_counters: dict[Any, Any],
        acquisitions: dict[str, AcquisitionRecord],
    ) -> dict[str, int]:
        counters: dict[str, int] = {}
        for key, value in raw_counters.items():
            if not isinstance(key, str):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "invalid_counter_key"}
                )
            if isinstance(value, bool) or not isinstance(value, int):
                raise EvidenceError(
                    "EVIDENCE_SNAPSHOT_INVALID", {"reason": "invalid_counter_value"}
                )
            counters[key] = value

        max_number = 0
        for acq_id in acquisitions:
            prefix, separator, suffix = acq_id.partition("-")
            if separator and prefix.upper() == "ACQ" and suffix.isdigit():
                max_number = max(max_number, int(suffix))
        counters["acq_seq"] = max(int(counters.get("acq_seq", 0)), max_number)
        return counters
