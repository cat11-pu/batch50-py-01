import hashlib

import pytest

import evidence_acquisition_ledger as ev

T0 = "2026-11-26T09:00:00+00:00"
T1 = "2026-11-26T09:04:00+00:00"


def ledger(**kwargs):
    return ev.EvidenceLedger(**kwargs)


def opened(lg, case_id="C-1", subject="取证-甲", now=T0):
    return lg.open_case(case_id, subject=subject, now=now)


def started(lg, case_id="C-1", device_id="SSD-1",
            protection="write-blocker", now=T0):
    return lg.acquire(case_id, device_id=device_id,
                      source_protection=protection, now=now)


def test_open_case_returns_record_and_is_idempotent():
    lg = ledger()
    first = opened(lg)
    assert isinstance(first, ev.CaseRecord)
    assert (first.case_id, first.subject) == ("C-1", "取证-甲")
    assert first.opened_at == T0
    again = lg.open_case("C-1", subject="取证-甲", now=T1)
    assert again.opened_at == T0
    assert [row.case_id for row in lg.cases()] == ["C-1"]
    assert lg.stats()["cases"] == 1


def test_open_case_with_different_subject_is_refused():
    lg = ledger()
    opened(lg, subject="取证-甲")
    with pytest.raises(ev.EvidenceError) as exc:
        lg.open_case("C-1", subject="取证-乙", now=T1)
    assert exc.value.code == "EVIDENCE_CASE_CONFLICT"
    assert len(lg.cases()) == 1


def test_acquire_requires_supported_source_protection():
    lg = ledger()
    opened(lg)
    for mode in ("live", "none", ""):
        with pytest.raises(ev.EvidenceError) as exc:
            started(lg, protection=mode)
        assert exc.value.code == "EVIDENCE_SOURCE_UNPROTECTED"
    rec = started(lg, protection="readonly-mount")
    assert rec.source_protection == "readonly-mount"
    assert rec.status == "active"
    assert (rec.case_id, rec.device_id) == ("C-1", "SSD-1")


def test_acquire_unknown_case_is_refused():
    lg = ledger()
    with pytest.raises(ev.EvidenceError) as exc:
        started(lg, case_id="C-404")
    assert exc.value.code == "EVIDENCE_CASE_UNKNOWN"


def test_second_acquisition_on_same_device_is_busy():
    lg = ledger()
    opened(lg)
    first = started(lg, device_id="SSD-1")
    with pytest.raises(ev.EvidenceError) as exc:
        started(lg, device_id="SSD-1", protection="readonly-mount", now=T1)
    assert exc.value.code == "EVIDENCE_DEVICE_BUSY"
    other = started(lg, device_id="SSD-2", now=T1)
    assert first.acq_id != other.acq_id
    assert lg.stats()["acquisitions"] == 2


def test_chunk_indices_must_be_contiguous():
    lg = ledger()
    opened(lg)
    acq = started(lg)
    with pytest.raises(ev.EvidenceError) as exc:
        lg.chunk(acq.acq_id, index=1, data=b"skip", now=T0)
    assert exc.value.code == "EVIDENCE_CHUNK_GAP"
    lg.chunk(acq.acq_id, index=0, data=b"first", now=T0)
    with pytest.raises(ev.EvidenceError) as exc:
        lg.chunk(acq.acq_id, index=2, data=b"tail", now=T0)
    assert exc.value.code == "EVIDENCE_CHUNK_GAP"
    assert [row.index for row in lg.chunks(acq.acq_id)] == [0]


def test_duplicate_and_empty_chunks_are_refused():
    lg = ledger()
    opened(lg)
    acq = started(lg)
    lg.chunk(acq.acq_id, index=0, data=b"first", now=T0)
    with pytest.raises(ev.EvidenceError) as exc:
        lg.chunk(acq.acq_id, index=0, data=b"again", now=T0)
    assert exc.value.code == "EVIDENCE_CHUNK_DUPLICATE"
    with pytest.raises(ev.EvidenceError) as exc:
        lg.chunk(acq.acq_id, index=1, data=b"", now=T0)
    assert exc.value.code == "EVIDENCE_CHUNK_EMPTY"
    assert len(lg.chunks(acq.acq_id)) == 1


def test_chunk_digest_chains_previous_digest():
    lg = ledger()
    opened(lg)
    acq = started(lg)
    first = lg.chunk(acq.acq_id, index=0, data=b"alpha", now=T0)
    second = lg.chunk(acq.acq_id, index=1, data=b"beta", now=T0)
    genesis = hashlib.sha256(b"").hexdigest()
    expected_first = hashlib.sha256(bytes.fromhex(genesis) + b"alpha").hexdigest()
    expected_second = hashlib.sha256(bytes.fromhex(expected_first) + b"beta").hexdigest()
    assert first.digest == expected_first
    assert second.digest == expected_second
    assert (first.index, first.length) == (0, 5)
    assert (second.index, second.length) == (1, 4)


def test_close_seals_final_hash_and_totals():
    lg = ledger()
    opened(lg)
    acq = started(lg)
    lg.chunk(acq.acq_id, index=0, data=b"alpha", now=T0)
    lg.chunk(acq.acq_id, index=1, data=b"beta", now=T0)
    sealed = lg.close(acq.acq_id, now=T1)
    assert sealed.status == "sealed"
    assert sealed.final_hash == lg.chunks(acq.acq_id)[-1].digest
    assert (sealed.chunks, sealed.bytes_read) == (2, 9)
    assert lg.stats()["sealed"] == 1
    assert lg.stats()["bytes"] == 9


def test_interrupt_and_resume_gate_the_acquisition_state():
    lg = ledger()
    opened(lg)
    acq = started(lg)
    lg.chunk(acq.acq_id, index=0, data=b"aa", now=T0)
    with pytest.raises(ev.EvidenceError) as exc:
        lg.resume(acq.acq_id, now=T1)
    assert exc.value.code == "EVIDENCE_STATE_INVALID"
    paused = lg.interrupt(acq.acq_id, now=T1)
    assert paused.status == "interrupted"
    with pytest.raises(ev.EvidenceError) as exc:
        lg.close(acq.acq_id, now=T1)
    assert exc.value.code == "EVIDENCE_STATE_INVALID"
    resumed = lg.resume(acq.acq_id, now=T1)
    assert resumed.status == "active"
    lg.chunk(acq.acq_id, index=1, data=b"bb", now=T1)
    sealed = lg.close(acq.acq_id, now=T1)
    assert (sealed.chunks, sealed.bytes_read) == (2, 4)


def test_chain_entries_are_sequenced_and_verifiable():
    lg = ledger()
    opened(lg)
    acq = started(lg)
    lg.chunk(acq.acq_id, index=0, data=b"alpha", now=T0)
    sealed = lg.close(acq.acq_id, now=T1)
    rows = lg.entries("C-1")
    assert [row.seq for row in rows] == [1, 2, 3, 4]
    assert [row.kind for row in rows] == ["case_open", "acquire_open", "chunk", "seal"]
    assert [row.signer_epoch for row in rows] == [1, 1, 1, 1]
    assert rows[3].payload_hash == sealed.final_hash
    assert all(row.signature for row in rows)
    report = lg.verify_chain("C-1")
    assert report == {"case_id": "C-1", "ok": True, "entries": 4, "broken_seq": None}


def test_snapshot_roundtrip_restores_active_acquisition():
    lg = ledger()
    opened(lg)
    acq = started(lg)
    lg.chunk(acq.acq_id, index=0, data=b"alpha", now=T0)
    state = lg.snapshot()
    clone = ledger()
    clone.restore(state)
    assert [row.case_id for row in clone.cases()] == ["C-1"]
    rows = clone.chunks(acq.acq_id)
    assert [(row.index, row.length, row.digest) for row in rows] == [
        (0, 5, rows[0].digest)]
    assert clone.acquisitions("C-1")[0].status == "active"
    assert clone.verify_chain("C-1")["ok"] is True
    clone.chunk(acq.acq_id, index=1, data=b"beta", now=T1)
    sealed = clone.close(acq.acq_id, now=T1)
    assert sealed.chunks == 2
    state["acquisitions"] = {}
    state["chain"] = []
    assert lg.stats()["chunks"] == 1
    assert lg.verify_chain("C-1")["ok"] is True


def test_restore_rejects_malformed_snapshot_without_touching_state():
    lg = ledger()
    opened(lg)
    acq = started(lg)
    lg.chunk(acq.acq_id, index=0, data=b"alpha", now=T0)
    good = lg.snapshot()
    broken = []
    broken.append(None)
    broken.append({})
    broken.append({"version": 99, "cases": {}, "acquisitions": {}, "chunks": {},
                   "chain": [], "keys": {1: "k"}, "counters": {}, "stats": {}})
    partial = dict(good)
    partial.pop("keys")
    broken.append(partial)
    wrong_type = dict(good)
    wrong_type["chain"] = {"not": "a list"}
    broken.append(wrong_type)
    for bad in broken:
        with pytest.raises(ev.EvidenceError) as exc:
            lg.restore(bad)
        assert exc.value.code == "EVIDENCE_SNAPSHOT_INVALID"
    assert lg.stats()["chunks"] == 1
    assert lg.entries("C-1")[0].seq == 1
    assert lg.verify_chain("C-1")["ok"] is True


def test_stats_counts_each_transition():
    lg = ledger()
    opened(lg, "C-1", "取证-甲")
    opened(lg, "C-2", "取证-乙")
    acq = started(lg, "C-1", "SSD-1")
    lg.chunk(acq.acq_id, index=0, data=b"abc", now=T0)
    lg.chunk(acq.acq_id, index=1, data=b"de", now=T0)
    lg.close(acq.acq_id, now=T1)
    assert lg.stats() == {"cases": 2, "acquisitions": 1, "chunks": 2, "bytes": 5,
                          "sealed": 1, "contaminated": 0, "unusable": 0,
                          "chain_entries": 6}


def test_unknown_acquisition_id_is_refused():
    lg = ledger()
    with pytest.raises(ev.EvidenceError) as exc:
        lg.chunk("ACQ-404", index=0, data=b"x", now=T0)
    assert exc.value.code == "EVIDENCE_ACQ_UNKNOWN"
    with pytest.raises(ev.EvidenceError) as exc:
        lg.close("ACQ-404", now=T0)
    assert exc.value.code == "EVIDENCE_ACQ_UNKNOWN"
