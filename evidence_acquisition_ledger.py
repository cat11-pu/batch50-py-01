"""Evidence acquisition ledger: source attestation, chained chunk digests, custody chain."""

from __future__ import annotations

import threading
from dataclasses import dataclass


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


class EvidenceLedger:
    """Register cases, attest acquisition sources, chain chunk digests, keep custody entries."""

    def __init__(self, *, block_size: int = 4096) -> None:
        self.block_size = block_size
        self._lock = threading.RLock()
        self._cases: dict[str, CaseRecord] = {}
        self._acquisitions: dict[str, AcquisitionRecord] = {}
        self._acq_order: list[str] = []
        self._chunks: dict[str, list[ChunkRecord]] = {}
        self._chain: list[ChainEntry] = []
        self._keys: dict[int, str] = {1: "ledger-epoch-1"}
        self._counters: dict[str, int] = {}

    def open_case(self, case_id: str, *, subject: str, now: str) -> CaseRecord:
        raise NotImplementedError

    def acquire(self, case_id: str, *, device_id: str,
                source_protection: str, now: str) -> AcquisitionRecord:
        raise NotImplementedError

    def chunk(self, acq_id: str, *, index: int, data: bytes, now: str) -> ChunkRecord:
        raise NotImplementedError

    def interrupt(self, acq_id: str, *, now: str) -> AcquisitionRecord:
        raise NotImplementedError

    def resume(self, acq_id: str, *, now: str) -> AcquisitionRecord:
        raise NotImplementedError

    def observe_write(self, acq_id: str, *, offset: int, length: int,
                      now: str) -> AcquisitionRecord:
        raise NotImplementedError

    def report_corruption(self, acq_id: str, *, index: int, now: str) -> AcquisitionRecord:
        raise NotImplementedError

    def close(self, acq_id: str, *, now: str) -> AcquisitionRecord:
        raise NotImplementedError

    def verify_chain(self, case_id: str) -> dict:
        raise NotImplementedError

    def rotate_signing_key(self, epoch: int, key: str) -> None:
        raise NotImplementedError

    def entries(self, case_id: str) -> list[ChainEntry]:
        raise NotImplementedError

    def chunks(self, acq_id: str) -> list[ChunkRecord]:
        raise NotImplementedError

    def cases(self) -> list[CaseRecord]:
        raise NotImplementedError

    def acquisitions(self, case_id: str) -> list[AcquisitionRecord]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
