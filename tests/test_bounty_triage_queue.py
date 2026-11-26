import copy
from datetime import datetime, timedelta, timezone

import pytest

import bounty_triage_queue as bq

BASE = datetime(2026, 11, 26, 9, 0, 0, tzinfo=timezone.utc)


def at(seconds=0):
    return (BASE + timedelta(seconds=seconds)).isoformat()


def queue(**kwargs):
    return bq.BountyTriageQueue(**kwargs)


def submitted(q, report_id="R-1", *, target="api.example.com", fingerprint=None,
              reporter="alice", severity="high", now=None):
    if fingerprint is None:
        fingerprint = "fp-" + report_id
    return q.submit(report_id, target=target, fingerprint=fingerprint,
                    reporter=reporter, severity=severity, now=now or at(0))


def triaged(q, report_id="R-1", *, severity="high", verdict="valid", now=at(0)):
    submitted(q, report_id, severity=severity, now=now)
    lease = q.claim_review(report_id, reviewer="bob", now=now)
    return q.record_verdict(report_id, reviewer="bob", lease_id=lease.lease_id,
                            verdict=verdict, severity=severity, now=now)


def test_submit_creates_queued_report_and_counts():
    q = queue()
    report = submitted(q)
    assert isinstance(report, bq.BountyReport)
    assert (report.report_id, report.target, report.fingerprint,
            report.reporter, report.severity) == (
        "R-1", "api.example.com", "fp-R-1", "alice", "high")
    assert report.state == "queued"
    assert report.duplicate_of is None
    assert report.verdict is None
    assert report.award_amount == 0
    assert report.submitted_at == at(0)
    assert report.closed_at is None
    assert q.stats() == {"submitted": 1, "duplicates": 0, "verdicts": 0,
                         "awards": 0, "acknowledged": 0, "adjusted": 0}


def test_submit_rejects_duplicate_report_id():
    q = queue()
    submitted(q, "R-1")
    with pytest.raises(bq.BountyError) as exc:
        submitted(q, "R-1", fingerprint="fp-other")
    assert exc.value.code == "BOUNTY_DUPLICATE_REPORT"
    assert len(q.queue()) == 1
    assert q.stats()["submitted"] == 1


def test_submit_rejects_bad_severity_and_empty_fields():
    q = queue()
    for severity in ("urgent", ""):
        with pytest.raises(bq.BountyError) as exc:
            submitted(q, "R-sev", severity=severity)
        assert exc.value.code == "BOUNTY_BAD_SEVERITY"
    bad = [
        dict(report_id="", target="t", fingerprint="fp", reporter="alice"),
        dict(report_id="R-2", target="  ", fingerprint="fp", reporter="alice"),
        dict(report_id="R-3", target="t", fingerprint="", reporter="alice"),
        dict(report_id="R-4", target="t", fingerprint="fp", reporter=""),
    ]
    for kwargs in bad:
        with pytest.raises(bq.BountyError) as exc:
            q.submit(severity="high", now=at(0), **kwargs)
        assert exc.value.code == "BOUNTY_BAD_REQUEST"
    assert q.queue() == []


def test_submit_marks_live_duplicate_without_review():
    q = queue()
    first = submitted(q, "R-1", fingerprint="fp-dup")
    second = submitted(q, "R-2", fingerprint="fp-dup")
    assert first.state == "queued"
    assert second.state == "duplicate"
    assert second.duplicate_of == "R-1"
    assert [row.report_id for row in q.queue(state="queued")] == ["R-1"]
    assert [row.report_id for row in q.queue()] == ["R-1", "R-2"]
    assert q.stats()["submitted"] == 2
    assert q.stats()["duplicates"] == 1


def test_dedupe_against_matches_target_and_fingerprint_sorted():
    q = queue()
    submitted(q, "R-1", target="api.example.com", fingerprint="fp-a")
    submitted(q, "R-2", target="api.example.com", fingerprint="fp-b")
    submitted(q, "R-3", target="web.example.com", fingerprint="fp-a")
    submitted(q, "R-4", target="api.example.com", fingerprint="fp-a")
    assert q.dedupe_against("api.example.com", "fp-a") == ("R-1", "R-4")
    assert q.dedupe_against("api.example.com", "fp-z") == ()
    assert q.dedupe_against("web.example.com", "fp-a") == ("R-3",)
    assert q.stats()["submitted"] == 4
    assert q.stats()["duplicates"] == 1


def test_claim_review_creates_lease_and_blocks_second_claim():
    q = queue(lease_seconds=900)
    submitted(q, "R-1")
    lease = q.claim_review("R-1", reviewer="bob", now=at(0))
    assert isinstance(lease, bq.ReviewLease)
    assert lease.report_id == "R-1"
    assert lease.reviewer == "bob"
    assert lease.expires_at == at(900)
    assert q.queue()[0].state == "queued"
    with pytest.raises(bq.BountyError) as exc:
        q.claim_review("R-1", reviewer="carol", now=at(10))
    assert exc.value.code == "BOUNTY_LEASE_HELD"


def test_claim_after_lease_expiry_is_allowed():
    q = queue(lease_seconds=600)
    submitted(q, "R-1")
    first = q.claim_review("R-1", reviewer="bob", now=at(0))
    second = q.claim_review("R-1", reviewer="carol", now=at(601))
    assert second.lease_id != first.lease_id
    assert second.reviewer == "carol"
    assert second.expires_at == at(1201)


def test_record_verdict_sets_triaged_state():
    q = queue()
    submitted(q, "R-1")
    lease = q.claim_review("R-1", reviewer="bob", now=at(0))
    report = q.record_verdict("R-1", reviewer="bob", lease_id=lease.lease_id,
                              verdict="valid", severity="critical", now=at(5))
    assert report.state == "triaged"
    assert report.verdict == "valid"
    assert report.severity == "critical"
    assert q.stats()["verdicts"] == 1


def test_record_verdict_rejects_bad_verdict():
    q = queue()
    submitted(q, "R-1")
    lease = q.claim_review("R-1", reviewer="bob", now=at(0))
    with pytest.raises(bq.BountyError) as exc:
        q.record_verdict("R-1", reviewer="bob", lease_id=lease.lease_id,
                         verdict="exploitable", severity="high", now=at(5))
    assert exc.value.code == "BOUNTY_BAD_VERDICT"
    report = q.queue()[0]
    assert report.state == "queued"
    assert report.verdict is None
    assert q.stats()["verdicts"] == 0


def test_award_deducts_budget_and_writes_ledger():
    q = queue(project_budget=10000)
    triaged(q, "R-1", severity="high")
    out = q.award("R-1", amount=1500, now=at(10))
    assert out["report_id"] == "R-1"
    assert out["state"] == "awarded"
    assert out["awarded"] is True
    assert out["amount"] == 1500
    assert out["remaining"] == 8500
    entries = q.ledger()
    assert len(entries) == 1
    assert entries[0]["report_id"] == "R-1"
    assert entries[0]["amount"] == 1500
    assert entries[0]["at"] == at(10)
    assert entries[0]["severity"] == "high"
    assert q.queue(state="awarded")[0].award_amount == 1500
    assert q.stats()["awards"] == 1


def test_award_insufficient_budget_downgrades_without_blocking():
    q = queue(project_budget=1000)
    triaged(q, "R-1")
    out = q.award("R-1", amount=4000, now=at(10))
    assert out["awarded"] is False
    assert out["state"] == "acknowledged"
    assert out["amount"] == 0
    assert out["remaining"] == 1000
    assert q.ledger() == []
    assert q.queue()[0].state == "acknowledged"
    assert q.stats()["acknowledged"] == 1
    assert q.stats()["awards"] == 0

    triaged(q, "R-2", now=at(15))
    second = q.award("R-2", amount=1000, now=at(20))
    assert second["awarded"] is True
    assert second["remaining"] == 0


def test_adjust_severity_upward_once_then_locked():
    q = queue()
    submitted(q, "R-1", severity="high")
    out = q.adjust_severity("R-1", new_severity="critical", actor="lead",
                            now=at(1))
    assert out["old"] == "high"
    assert out["new"] == "critical"
    assert out["actor"] == "lead"
    assert out["at"] == at(1)
    assert q.queue()[0].severity == "critical"
    with pytest.raises(bq.BountyError) as exc:
        q.adjust_severity("R-1", new_severity="critical", actor="lead",
                          now=at(2))
    assert exc.value.code == "BOUNTY_REVIEW_LOCKED"
    assert q.stats()["adjusted"] == 1


def test_adjust_severity_downgrade_is_rejected():
    q = queue()
    submitted(q, "R-1", severity="high")
    with pytest.raises(bq.BountyError) as exc:
        q.adjust_severity("R-1", new_severity="medium", actor="lead",
                          now=at(1))
    assert exc.value.code == "BOUNTY_SEVERITY_DOWNGRADE"
    assert q.queue()[0].severity == "high"
    assert q.stats()["adjusted"] == 0


def test_close_releases_lease_and_clears_queue():
    q = queue()
    submitted(q, "R-1")
    q.claim_review("R-1", reviewer="bob", now=at(0))
    closed = q.close("R-1", reason="duplicate report", now=at(20))
    assert closed.state == "closed"
    assert closed.closed_at == at(20)
    assert q.queue(state="queued") == []
    assert q.queue()[0].state == "closed"
    with pytest.raises(bq.BountyError) as exc:
        q.close("R-1", reason="again", now=at(21))
    assert exc.value.code == "BOUNTY_BAD_STATE"
    with pytest.raises(bq.BountyError) as exc:
        q.claim_review("R-1", reviewer="bob", now=at(22))
    assert exc.value.code == "BOUNTY_BAD_STATE"
    with pytest.raises(bq.BountyError) as exc:
        q.close("R-404", reason="missing", now=at(23))
    assert exc.value.code == "BOUNTY_UNKNOWN_REPORT"


def test_snapshot_is_detached_and_restore_roundtrips():
    q = queue(project_budget=5000)
    triaged(q, "R-1", severity="high")
    first = q.award("R-1", amount=2000, now=at(10))
    assert first["remaining"] == 3000
    state = q.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "reports", "leases", "ledger",
                             "adjustments", "budget", "stats"}

    state["reports"].clear()
    state["ledger"].clear()
    state["budget"] = 0
    state["stats"]["awards"] = 99
    assert q.stats()["awards"] == 1
    assert q.queue()[0].award_amount == 2000

    clone = queue()
    clone.restore(pristine)
    assert clone.stats() == q.stats()
    assert [row.report_id for row in clone.queue()] == ["R-1"]
    assert clone.queue()[0].award_amount == 2000

    triaged(clone, "R-2", now=at(20))
    second = clone.award("R-2", amount=3000, now=at(30))
    assert second["awarded"] is True
    assert second["remaining"] == 0
