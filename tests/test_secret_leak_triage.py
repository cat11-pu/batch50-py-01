import copy
from datetime import datetime, timedelta, timezone

import pytest

import secret_leak_triage as sl

BASE = datetime(2026, 11, 26, 9, 0, 0, tzinfo=timezone.utc)


def at(seconds=0):
    return (BASE + timedelta(seconds=seconds)).isoformat()


def triage(**kwargs):
    return sl.SecretLeakTriage(**kwargs)


def ingested(t, finding_id="F-1", *, fingerprint="fp-1", repo="repo-a",
             commit="c0ffee", path="config/app.env", now=at(0)):
    return t.ingest(finding_id, repo=repo, commit=commit, path=path,
                    fingerprint=fingerprint, now=now)


def test_ingest_creates_pending_record_with_location():
    t = triage()
    out = ingested(t)
    assert out["finding_id"] == "F-1"
    assert out["fingerprint"] == "fp-1"
    assert out["master_state"] == "pending_verification"
    assert out["duplicate_location"] is False
    assert out["occurrences"] == 1
    row = t.status("fp-1")
    assert isinstance(row, dict)
    assert row["fingerprint"] == "fp-1"
    assert row["state"] == "pending_verification"
    assert row["occurrences"] == 1
    assert row["locations"] == (("repo-a", "c0ffee", "config/app.env"),)
    assert row["verdict"] is None
    assert row["verified_at"] is None
    assert row["verify_expires_at"] is None
    assert row["disposed_at"] is None
    assert row["first_seen_at"] == at(0)
    assert row["last_seen_at"] == at(0)
    assert t.stats() == {"ingested": 1, "occurrences": 1,
                         "verified_valid": 0, "verified_invalid": 0,
                         "disposed": 0, "revocations": 0}


def test_ingest_same_fingerprint_appends_location():
    t = triage()
    ingested(t)
    out = ingested(t, "F-2", repo="repo-b", commit="c0ffee2", path="deploy/ci.yml",
                  now=at(5))
    assert out["occurrences"] == 2
    assert out["duplicate_location"] is True
    assert out["master_state"] == "pending_verification"
    assert t.dedupe("fp-1") == (
        ("repo-a", "c0ffee", "config/app.env"),
        ("repo-b", "c0ffee2", "deploy/ci.yml"),
    )
    row = t.status("fp-1")
    assert row["occurrences"] == 2
    assert row["first_seen_at"] == at(0)
    assert row["last_seen_at"] == at(5)
    assert row["state"] == "pending_verification"
    assert t.stats()["ingested"] == 2
    assert t.stats()["occurrences"] == 2


def test_ingest_rejects_duplicate_finding_id():
    t = triage()
    ingested(t)
    with pytest.raises(sl.LeakError) as exc:
        ingested(t, "F-1", fingerprint="fp-other")
    assert exc.value.code == "LEAK_DUPLICATE_FINDING"
    assert t.status("fp-1")["occurrences"] == 1
    assert t.stats()["ingested"] == 1


def test_ingest_rejects_empty_fields():
    t = triage()
    bad = [
        dict(finding_id="", repo="r", commit="c", path="p", fingerprint="fp"),
        dict(finding_id="F-2", repo="  ", commit="c", path="p", fingerprint="fp"),
        dict(finding_id="F-3", repo="r", commit="", path="p", fingerprint="fp"),
        dict(finding_id="F-4", repo="r", commit="c", path=" ", fingerprint="fp"),
        dict(finding_id="F-5", repo="r", commit="c", path="p", fingerprint=""),
    ]
    for kwargs in bad:
        with pytest.raises(sl.LeakError) as exc:
            t.ingest(now=at(0), **kwargs)
        assert exc.value.code == "LEAK_BAD_REQUEST"
    assert t.findings() == []


def test_verify_valid_marks_record_with_expiry():
    t = triage()
    ingested(t)
    record = t.verify_result("fp-1", verdict="valid", now=at(10))
    assert isinstance(record, sl.LeakRecord)
    assert record.state == "valid"
    assert record.verdict == "valid"
    assert record.verified_at == at(10)
    assert record.verify_expires_at == at(3610)
    assert record.disposed_at is None
    row = t.status("fp-1")
    assert row["state"] == "valid"
    assert row["verdict"] == "valid"
    assert row["verify_expires_at"] == at(3610)
    assert t.stats()["verified_valid"] == 1


def test_verify_invalid_marks_record():
    t = triage()
    ingested(t)
    record = t.verify_result("fp-1", verdict="invalid", now=at(20))
    assert record.state == "invalid"
    assert record.verdict == "invalid"
    assert record.verified_at == at(20)
    assert record.verify_expires_at == at(3620)
    assert t.stats()["verified_invalid"] == 1


def test_verify_rejects_unknown_fingerprint_and_bad_verdict():
    t = triage()
    with pytest.raises(sl.LeakError) as exc:
        t.verify_result("fp-none", verdict="valid", now=at(0))
    assert exc.value.code == "LEAK_UNKNOWN"
    ingested(t)
    for verdict in ("maybe", ""):
        with pytest.raises(sl.LeakError) as exc:
            t.verify_result("fp-1", verdict=verdict, now=at(0))
        assert exc.value.code == "LEAK_BAD_VERDICT"
    row = t.status("fp-1")
    assert row["state"] == "pending_verification"
    assert row["verdict"] is None
    assert t.stats()["verified_valid"] == 0


def test_dedupe_returns_sorted_unique_locations():
    t = triage()
    ingested(t, "F-1", repo="repo-b", commit="commit-9", path="path-z")
    ingested(t, "F-2", repo="repo-a", commit="commit-2", path="path-b")
    ingested(t, "F-3", repo="repo-a", commit="commit-1", path="path-a")
    assert t.dedupe("fp-1") == (
        ("repo-a", "commit-1", "path-a"),
        ("repo-a", "commit-2", "path-b"),
        ("repo-b", "commit-9", "path-z"),
    )
    assert t.dedupe("fp-none") == ()


def test_open_revocation_requires_valid_verdict():
    t = triage()
    ingested(t)
    with pytest.raises(sl.LeakError) as exc:
        t.open_revocation("fp-1", provider="aws", owner="secops", now=at(0))
    assert exc.value.code == "LEAK_NOT_REVOCABLE"
    t.verify_result("fp-1", verdict="invalid", now=at(5))
    with pytest.raises(sl.LeakError) as exc:
        t.open_revocation("fp-1", provider="aws", owner="secops", now=at(6))
    assert exc.value.code == "LEAK_NOT_REVOCABLE"
    t.verify_result("fp-1", verdict="valid", now=at(7))
    ticket = t.open_revocation("fp-1", provider="aws", owner="secops", now=at(8))
    assert ticket.state == "open"
    with pytest.raises(sl.LeakError) as exc:
        t.open_revocation("fp-none", provider="aws", owner="secops", now=at(9))
    assert exc.value.code == "LEAK_UNKNOWN"


def test_open_revocation_creates_ticket_and_blocks_duplicate():
    t = triage()
    ingested(t)
    t.verify_result("fp-1", verdict="valid", now=at(10))
    ticket = t.open_revocation("fp-1", provider="aws", owner="secops", now=at(10))
    assert isinstance(ticket, sl.RevocationTicket)
    assert ticket.fingerprint == "fp-1"
    assert ticket.provider == "aws"
    assert ticket.owner == "secops"
    assert ticket.state == "open"
    assert ticket.opened_at == at(10)
    assert ticket.closed_at is None
    assert ticket.resolution is None
    with pytest.raises(sl.LeakError) as exc:
        t.open_revocation("fp-1", provider="aws", owner="secops", now=at(11))
    assert exc.value.code == "LEAK_REVOCATION_EXISTS"
    assert len(t.revocations()) == 1
    assert t.stats()["revocations"] == 1


def test_close_last_revocation_disposes_record():
    t = triage()
    ingested(t)
    t.verify_result("fp-1", verdict="valid", now=at(10))
    ticket = t.open_revocation("fp-1", provider="aws", owner="secops", now=at(10))
    out = t.close_revocation(ticket.ticket_id, resolution="key rotated",
                             now=at(20))
    assert out["ticket_id"] == ticket.ticket_id
    assert out["state"] == "closed"
    assert out["fingerprint"] == "fp-1"
    assert out["record_state"] == "disposed"
    row = t.status("fp-1")
    assert row["state"] == "disposed"
    assert row["disposed_at"] == at(20)
    closed = t.revocations(state="closed")
    assert len(closed) == 1
    assert closed[0].closed_at == at(20)
    assert closed[0].resolution == "key rotated"
    assert t.stats()["disposed"] == 1


def test_close_finding_blocked_by_open_revocation():
    t = triage()
    ingested(t)
    t.verify_result("fp-1", verdict="valid", now=at(10))
    t.open_revocation("fp-1", provider="aws", owner="secops", now=at(10))
    with pytest.raises(sl.LeakError) as exc:
        t.close_finding("fp-1", resolution="manual", now=at(20))
    assert exc.value.code == "LEAK_REVOCATION_OPEN"
    assert t.status("fp-1")["state"] == "valid"


def test_close_invalid_finding_without_revocation():
    t = triage()
    ingested(t)
    t.verify_result("fp-1", verdict="invalid", now=at(10))
    record = t.close_finding("fp-1", resolution="false positive", now=at(30))
    assert record.state == "disposed"
    assert record.disposed_at == at(30)
    assert t.status("fp-1")["state"] == "disposed"
    with pytest.raises(sl.LeakError) as exc:
        t.close_finding("fp-none", resolution="missing", now=at(31))
    assert exc.value.code == "LEAK_UNKNOWN"


def test_snapshot_is_detached_and_restore_roundtrips():
    t = triage()
    ingested(t, "F-1", repo="repo-a")
    ingested(t, "F-2", repo="repo-b", commit="c0ffee2", path="deploy/ci.yml",
            now=at(5))
    t.verify_result("fp-1", verdict="valid", now=at(10))
    ticket = t.open_revocation("fp-1", provider="aws", owner="secops", now=at(10))
    state = t.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "records", "findings", "tickets", "stats"}

    state["records"].clear()
    state["tickets"].clear()
    state["stats"]["occurrences"] = 99
    assert t.status("fp-1")["occurrences"] == 2
    assert t.status("fp-1")["state"] == "valid"

    clone = triage()
    clone.restore(pristine)
    restored = clone.status("fp-1")
    assert restored["occurrences"] == 2
    assert restored["state"] == "valid"
    assert restored["locations"] == (
        ("repo-a", "c0ffee", "config/app.env"),
        ("repo-b", "c0ffee2", "deploy/ci.yml"),
    )
    assert clone.revocations()[0].ticket_id == ticket.ticket_id
    assert clone.revocations()[0].state == "open"
    assert clone.stats() == t.stats()


def test_stats_counts_each_transition():
    t = triage()
    ingested(t)
    ingested(t, "F-2", repo="repo-b", commit="c0ffee2", path="deploy/ci.yml",
             now=at(5))
    t.verify_result("fp-1", verdict="valid", now=at(10))
    ticket = t.open_revocation("fp-1", provider="aws", owner="secops", now=at(10))
    t.close_revocation(ticket.ticket_id, resolution="key rotated", now=at(20))
    assert t.stats() == {"ingested": 2, "occurrences": 2,
                         "verified_valid": 1, "verified_invalid": 0,
                         "disposed": 1, "revocations": 1}
