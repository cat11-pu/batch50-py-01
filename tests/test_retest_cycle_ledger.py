import pytest

import retest_cycle_ledger as rc

T0 = "2026-11-26T00:00:00+00:00"
T1 = "2026-11-27T00:00:00+00:00"
T2 = "2026-11-28T00:00:00+00:00"
T3 = "2026-11-29T00:00:00+00:00"


def ledger(**kwargs):
    return rc.RetestCycleLedger(**kwargs)


def opened(*findings, batch_id="b-1"):
    engine = ledger()
    engine.open_batch(batch_id, findings=list(findings), now=T0, owner="av-team")
    return engine


def test_open_batch_registers_findings_and_state():
    engine = ledger()
    view = engine.open_batch("b-1", findings=["VU-1", "VU-2", "VU-3"],
                             now=T0, owner="av-team")
    assert view["batch_id"] == "b-1"
    assert view["state"] == "open"
    assert view["owner"] == "av-team"
    assert view["opened_at"] == T0
    assert view["findings"] == ["VU-1", "VU-2", "VU-3"]
    assert view["rounds"] == 1
    assert view["regressions"] == 0
    assert engine.pending("b-1") == ["VU-1", "VU-2", "VU-3"]
    assert [row["batch_id"] for row in engine.batches()] == ["b-1"]


def test_open_batch_rejects_duplicate_and_bad_input():
    engine = opened("VU-1")
    with pytest.raises(rc.LedgerError) as exc:
        engine.open_batch("b-1", findings=["VU-9"], now=T0)
    assert exc.value.code == "LEDGER_DUPLICATE_BATCH"
    for bad in ([], ["VU-2", ""], ["VU-2", "VU-2"]):
        with pytest.raises(rc.LedgerError) as exc:
            engine.open_batch("b-x", findings=bad, now=T0)
        assert exc.value.code == "LEDGER_BAD_FINDING"
    with pytest.raises(rc.LedgerError) as exc:
        engine.open_batch("   ", findings=["VU-3"], now=T0)
    assert exc.value.code == "LEDGER_BAD_BATCH"
    assert len(engine.batches()) == 1


def test_record_result_accepts_three_conclusions():
    engine = opened("VU-1", "VU-2", "VU-3")
    first = engine.record_result("b-1", "VU-1", conclusion="fixed",
                                 note="patch v2", now=T0)
    engine.record_result("b-1", "VU-2", conclusion="still_present",
                         evidence="reproduced on build 88", now=T0)
    engine.record_result("b-1", "VU-3", conclusion="not_reproducible",
                         note="env mismatch", now=T0)
    assert first["finding_id"] == "VU-1"
    assert first["conclusion"] == "fixed"
    assert first["round"] == 1
    assert first["at"] == T0
    summary = engine.summary("b-1")
    assert summary["counts"] == {"fixed": 1, "still_present": 1,
                                 "not_reproducible": 1}
    assert summary["pending"] == 0
    assert engine.pending("b-1") == []


def test_still_present_requires_evidence():
    engine = opened("VU-1", "VU-2")
    with pytest.raises(rc.LedgerError) as exc:
        engine.record_result("b-1", "VU-1", conclusion="still_present",
                             evidence="   ", now=T0)
    assert exc.value.code == "LEDGER_EVIDENCE_REQUIRED"
    assert engine.pending("b-1") == ["VU-1", "VU-2"]
    out = engine.record_result("b-1", "VU-1", conclusion="still_present",
                               evidence="crash log", now=T0)
    assert out["evidence"] == "crash log"
    assert engine.pending("b-1") == ["VU-2"]


def test_record_result_rejects_unknown_batch_and_finding():
    engine = opened("VU-1")
    with pytest.raises(rc.LedgerError) as exc:
        engine.record_result("b-404", "VU-1", conclusion="fixed", now=T0)
    assert exc.value.code == "LEDGER_UNKNOWN_BATCH"
    with pytest.raises(rc.LedgerError) as exc:
        engine.record_result("b-1", "VU-404", conclusion="fixed", now=T0)
    assert exc.value.code == "LEDGER_UNKNOWN_FINDING"


def test_record_result_rejects_bad_conclusion():
    engine = opened("VU-1")
    for bad in ("fixed-in-dev", "", "FIXED", "  fixed  "):
        with pytest.raises(rc.LedgerError) as exc:
            engine.record_result("b-1", "VU-1", conclusion=bad, now=T0)
        assert exc.value.code == "LEDGER_BAD_CONCLUSION"
    assert engine.pending("b-1") == ["VU-1"]


def test_close_batch_requires_all_conclusions():
    engine = opened("VU-1", "VU-2", "VU-3")
    engine.record_result("b-1", "VU-1", conclusion="fixed", now=T0)
    with pytest.raises(rc.LedgerError) as exc:
        engine.close_batch("b-1", actor="lead", now=T0)
    assert exc.value.code == "LEDGER_INCOMPLETE"
    assert exc.value.detail == ["VU-2", "VU-3"]
    assert engine.summary("b-1")["state"] == "open"
    assert engine.stats()["closed"] == 0


def test_close_batch_marks_closed_and_rejects_second_close():
    engine = opened("VU-1", "VU-2")
    engine.record_result("b-1", "VU-1", conclusion="fixed", now=T0)
    engine.record_result("b-1", "VU-2", conclusion="not_reproducible", now=T0)
    receipt = engine.close_batch("b-1", actor="lead", now=T1)
    assert receipt["batch_id"] == "b-1"
    assert receipt["state"] == "closed"
    assert receipt["closed_by"] == "lead"
    assert receipt["closed_at"] == T1
    assert receipt["counts"] == {"fixed": 1, "still_present": 0,
                                 "not_reproducible": 1}
    assert engine.summary("b-1")["state"] == "closed"
    assert engine.stats()["closed"] == 1
    assert engine.stats()["open"] == 0
    with pytest.raises(rc.LedgerError) as exc:
        engine.close_batch("b-1", actor="lead", now=T1)
    assert exc.value.code == "LEDGER_ALREADY_CLOSED"


def test_pending_lists_only_unconcluded_findings():
    engine = opened("VU-3", "VU-1", "VU-2")
    assert engine.pending("b-1") == ["VU-1", "VU-2", "VU-3"]
    engine.record_result("b-1", "VU-2", conclusion="fixed", now=T0)
    assert engine.pending("b-1") == ["VU-1", "VU-3"]
    with pytest.raises(rc.LedgerError) as exc:
        engine.pending("b-404")
    assert exc.value.code == "LEDGER_UNKNOWN_BATCH"


def test_add_findings_appends_and_ignores_known():
    engine = opened("VU-1")
    view = engine.add_findings("b-1", ["VU-2", "VU-1"], now=T0)
    assert view["findings"] == ["VU-1", "VU-2"]
    assert engine.pending("b-1") == ["VU-1", "VU-2"]
    with pytest.raises(rc.LedgerError) as exc:
        engine.add_findings("b-1", ["VU-4", "VU-4"], now=T0)
    assert exc.value.code == "LEDGER_BAD_FINDING"
    assert engine.summary("b-1")["findings"] == 2


def test_reopen_returns_batch_to_open_and_counts_regression():
    engine = opened("VU-1", "VU-2")
    engine.record_result("b-1", "VU-1", conclusion="fixed", now=T0)
    engine.record_result("b-1", "VU-2", conclusion="fixed", now=T0)
    engine.close_batch("b-1", actor="lead", now=T1)
    receipt = engine.reopen("b-1", "VU-2", reason="customer reproduced it", now=T2)
    assert receipt["finding_id"] == "VU-2"
    assert receipt["state"] == "open"
    assert receipt["rounds"] == 2
    assert receipt["regressions"] == 1
    assert receipt["reason"] == "customer reproduced it"
    assert engine.pending("b-1") == ["VU-2"]
    assert engine.stats()["reopens"] == 1
    assert engine.stats()["regressions"] == 1
    assert engine.summary("b-1")["state"] == "open"


def test_reopen_rejects_open_batch_and_unfixed_finding():
    engine = opened("VU-1", "VU-2")
    with pytest.raises(rc.LedgerError) as exc:
        engine.reopen("b-1", "VU-1", reason="still broken", now=T0)
    assert exc.value.code == "LEDGER_BATCH_OPEN"
    engine.record_result("b-1", "VU-1", conclusion="still_present",
                         evidence="poc", now=T0)
    engine.record_result("b-1", "VU-2", conclusion="fixed", now=T0)
    engine.close_batch("b-1", actor="lead", now=T1)
    with pytest.raises(rc.LedgerError) as exc:
        engine.reopen("b-1", "VU-1", reason="still broken", now=T2)
    assert exc.value.code == "LEDGER_BAD_REOPEN"
    with pytest.raises(rc.LedgerError) as exc:
        engine.reopen("b-1", "VU-2", reason="   ", now=T2)
    assert exc.value.code == "LEDGER_BAD_REOPEN"
    with pytest.raises(rc.LedgerError) as exc:
        engine.reopen("b-1", "VU-9", reason="x", now=T2)
    assert exc.value.code == "LEDGER_UNKNOWN_FINDING"
    assert engine.summary("b-1")["state"] == "closed"
    assert engine.stats()["regressions"] == 0


def test_close_after_reopen_requires_new_conclusion():
    engine = opened("VU-1", "VU-2")
    engine.record_result("b-1", "VU-1", conclusion="fixed", now=T0)
    engine.record_result("b-1", "VU-2", conclusion="fixed", now=T0)
    engine.close_batch("b-1", actor="lead", now=T1)
    engine.reopen("b-1", "VU-1", reason="regressed", now=T2)
    with pytest.raises(rc.LedgerError) as exc:
        engine.close_batch("b-1", actor="lead", now=T3)
    assert exc.value.code == "LEDGER_INCOMPLETE"
    assert exc.value.detail == ["VU-1"]
    engine.record_result("b-1", "VU-1", conclusion="fixed", now=T3)
    second = engine.close_batch("b-1", actor="lead", now=T3)
    assert second["state"] == "closed"
    assert second["rounds"] == 2
    assert second["regressions"] == 1


def test_history_and_summary_follow_current_round():
    engine = opened("VU-1", "VU-2")
    engine.record_result("b-1", "VU-1", conclusion="fixed", note="p1", now=T0)
    engine.record_result("b-1", "VU-2", conclusion="still_present",
                         evidence="e1", now=T0)
    rows = engine.history("b-1")
    assert [row["finding_id"] for row in rows] == ["VU-1", "VU-2"]
    assert [row["conclusion"] for row in rows] == ["fixed", "still_present"]
    assert [row["round"] for row in rows] == [1, 1]
    assert rows[0]["note"] == "p1"
    assert rows[1]["evidence"] == "e1"
    summary = engine.summary("b-1")
    assert summary["batch_id"] == "b-1"
    assert summary["findings"] == 2
    assert summary["pending"] == 0
    assert summary["rounds"] == 1
    assert summary["counts"]["still_present"] == 1
    assert engine.stats()["records"] == 2
    assert engine.stats()["findings"] == 2


def test_snapshot_roundtrip_and_malformed_restore():
    engine = opened("VU-1", "VU-2")
    engine.record_result("b-1", "VU-1", conclusion="fixed", now=T0)
    engine.record_result("b-1", "VU-2", conclusion="fixed", now=T0)
    engine.close_batch("b-1", actor="lead", now=T1)
    engine.reopen("b-1", "VU-2", reason="regressed", now=T2)
    state = engine.snapshot()
    clone = ledger()
    clone.restore(state)
    assert clone.summary("b-1")["state"] == "open"
    assert clone.summary("b-1")["regressions"] == 1
    assert clone.summary("b-1")["rounds"] == 2
    assert clone.pending("b-1") == ["VU-2"]
    assert clone.history("b-1") == engine.history("b-1")
    assert clone.stats() == engine.stats()
    missing = dict(state)
    missing.pop("batches")
    wrong_type = dict(state)
    wrong_type["batches"] = []
    for bad in (None, {}, {"version": 99}, missing, wrong_type):
        with pytest.raises(rc.LedgerError) as exc:
            engine.restore(bad)
        assert exc.value.code == "LEDGER_SNAPSHOT_INVALID"
    assert engine.stats()["reopens"] == 1
