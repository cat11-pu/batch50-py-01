import copy
import hashlib

import pytest

import xss_callback_correlator as xc

SECRET = "corr-secret"
NOW = "2026-11-26T10:00:00+00:00"
SOON = "2026-11-26T10:05:00+00:00"
EXPIRY = "2026-11-26T10:30:00+00:00"
AFTER = "2026-11-26T10:31:00+00:00"

TARGET = "https://shop.example.test/item/42"
POINT = "comment-body"


def sign(payload_id, secret=SECRET):
    return hashlib.sha256("{}:{}".format(secret, payload_id).encode("utf-8")).hexdigest()[:16]


def correlator(**kwargs):
    return xc.XssCallbackCorrelator(secret=SECRET, **kwargs)


def issue(corr, target=TARGET, point=POINT, *, tenant="t1", now=NOW):
    return corr.issue_payload(target, point, tenant=tenant, now=now)


def callback(corr, payload_id, *, ip="203.0.113.9", ua="ua-1", now=NOW):
    return corr.handle_callback(payload_id, signature=sign(payload_id),
                                source_ip=ip, ua=ua, now=now)


def test_issue_payload_returns_prefixed_id_and_signature():
    corr = correlator()
    lease = issue(corr)
    assert lease.payload_id.startswith("PL-")
    assert len(lease.payload_id) == 15
    assert lease.status == "active"
    assert lease.tenant == "t1"
    assert lease.target == TARGET
    assert lease.injection_point == POINT
    assert lease.issued_at == NOW
    assert lease.expires_at == EXPIRY
    assert lease.signature == sign(lease.payload_id)
    assert corr.report()["issued"] == 1


def test_reissue_same_injection_point_reuses_active_lease():
    corr = correlator()
    first = issue(corr)
    second = issue(corr, now=SOON)
    assert second.payload_id == first.payload_id
    assert second.expires_at == first.expires_at
    assert second.issued_at == first.issued_at
    assert corr.report()["issued"] == 1
    assert corr.report()["reused"] == 1
    assert len(corr.list_payloads()) == 1


def test_issue_after_expiry_creates_new_payload():
    corr = correlator()
    first = issue(corr)
    assert corr.expire(now=EXPIRY) == 1
    second = issue(corr, now=AFTER)
    assert second.payload_id != first.payload_id
    assert corr.report()["issued"] == 2
    assert corr.report()["expired"] == 1
    assert corr.lookup(first.payload_id).status == "expired"
    assert [row.status for row in corr.list_payloads()] == ["expired", "active"]


def test_first_callback_is_confirmed_and_recorded():
    corr = correlator()
    lease = issue(corr)
    result = callback(corr, lease.payload_id)
    assert result.conclusion == "confirmed"
    assert result.payload_id == lease.payload_id
    assert result.tenant == "t1"
    assert corr.report()["callbacks"] == 1
    assert corr.report()["conclusions"] == {"confirmed": 1, "probable": 0, "orphan": 0}


def test_duplicate_callback_same_source_and_ua_is_counted_once():
    corr = correlator()
    lease = issue(corr)
    first = callback(corr, lease.payload_id)
    again = callback(corr, lease.payload_id, now=SOON)
    assert again.conclusion == first.conclusion == "confirmed"
    assert corr.report()["callbacks"] == 1
    assert corr.report()["duplicates"] == 1


def test_second_distinct_source_is_probable():
    corr = correlator()
    lease = issue(corr)
    callback(corr, lease.payload_id, ip="203.0.113.9", ua="ua-1")
    second = callback(corr, lease.payload_id, ip="198.51.100.7", ua="ua-2")
    assert second.conclusion == "probable"
    assert corr.report()["callbacks"] == 2
    assert corr.report()["conclusions"] == {"confirmed": 1, "probable": 1, "orphan": 0}


def test_unknown_payload_callback_raises():
    corr = correlator()
    with pytest.raises(xc.CallbackError) as exc:
        corr.handle_callback("PL-000000000000", signature=sign("PL-000000000000"),
                             source_ip="203.0.113.9", ua="ua-1", now=NOW)
    assert exc.value.code == "CALLBACK_UNKNOWN_PAYLOAD"
    assert corr.report()["callbacks"] == 0


def test_revoked_payload_rejects_callback():
    corr = correlator()
    lease = issue(corr)
    revoked = corr.revoke_payload(lease.payload_id, "retired")
    assert revoked.status == "revoked"
    with pytest.raises(xc.CallbackError) as exc:
        callback(corr, lease.payload_id)
    assert exc.value.code == "CALLBACK_PAYLOAD_REVOKED"
    assert corr.report()["revoked"] == 1
    assert corr.report()["callbacks"] == 0


def test_callback_rate_limit_per_source():
    corr = correlator(per_source_limit=1)
    lease = issue(corr)
    callback(corr, lease.payload_id, ua="ua-1")
    with pytest.raises(xc.CallbackError) as exc:
        callback(corr, lease.payload_id, ua="ua-2")
    assert exc.value.code == "CALLBACK_RATE_LIMITED"
    assert corr.report()["throttled"] == 1
    assert corr.report()["callbacks"] == 1


def test_payload_capacity_cap_raises():
    corr = correlator(max_payloads=1)
    issue(corr)
    with pytest.raises(xc.CallbackError) as exc:
        issue(corr, target="https://other.example.test/page", point="nickname")
    assert exc.value.code == "CALLBACK_CAPACITY_EXCEEDED"
    assert corr.report()["issued"] == 1


def test_expire_marks_only_past_leases_and_orphans_callbacks():
    corr = correlator()
    lease = issue(corr)
    assert corr.expire(now=SOON) == 0
    assert corr.lookup(lease.payload_id).status == "active"
    assert corr.expire(now=AFTER) == 1
    assert corr.lookup(lease.payload_id).status == "expired"
    orphan = callback(corr, lease.payload_id, now=AFTER)
    assert orphan.conclusion == "orphan"
    assert corr.report()["conclusions"]["orphan"] == 1


def test_list_payloads_is_sorted_and_filtered_by_target():
    corr = correlator()
    issue(corr, target="https://b.test/y", point="p1")
    issue(corr, target="https://a.test/x", point="p2")
    issue(corr, target="https://c.test/z", point="p3")
    rows = corr.list_payloads()
    assert len(rows) == 3
    assert list(rows) == sorted(rows, key=lambda row: (row.issued_at, row.payload_id))
    assert {row.target for row in rows} == {"https://a.test/x", "https://b.test/y",
                                            "https://c.test/z"}
    filtered = corr.list_payloads("https://b.test/y")
    assert len(filtered) == 1
    assert filtered[0].target == "https://b.test/y"


def test_report_counts_after_mixed_flow():
    corr = correlator()
    first = issue(corr)
    callback(corr, first.payload_id, ip="203.0.113.9", ua="ua-1")
    callback(corr, first.payload_id, ip="198.51.100.7", ua="ua-2")
    issue(corr, target="https://news.example.test/post/7", point="author-bio")
    assert corr.report()["issued"] == 2
    assert corr.report()["callbacks"] == 2
    assert corr.report()["active"] == 2
    assert corr.expire(now=AFTER) == 2
    report = corr.report()
    assert report["expired"] == 2
    assert report["active"] == 0
    assert report["duplicates"] == 0
    assert report["throttled"] == 0
    assert report["abuse"] == 0
    assert report["conclusions"] == {"confirmed": 1, "probable": 1, "orphan": 0}


def test_snapshot_roundtrips_and_rejects_malformed_state():
    corr = correlator()
    lease = issue(corr)
    callback(corr, lease.payload_id)
    state = corr.snapshot()
    assert set(state) == {"version", "leases", "events", "dedupe", "counters", "seq"}
    pristine = copy.deepcopy(state)
    state["leases"].clear()
    state["counters"]["issued"] = 99
    assert corr.report()["issued"] == 1
    assert corr.lookup(lease.payload_id) is not None

    clone = correlator()
    clone.restore(pristine)
    assert clone.report()["callbacks"] == 1
    assert clone.lookup(lease.payload_id).tenant == "t1"

    for bad in (None, {}, {"version": 1, "leases": [], "events": {}},
                {"version": 1, "leases": "nope", "events": [], "dedupe": [],
                 "counters": {}, "seq": 0}):
        with pytest.raises(xc.CallbackError) as exc:
            clone.restore(bad)
        assert exc.value.code == "CALLBACK_SNAPSHOT_INVALID"
    assert clone.report()["callbacks"] == 1


def test_invalid_issue_arguments_raise():
    corr = correlator()
    bad_calls = [
        dict(target="", injection_point=POINT, tenant="t1"),
        dict(target=TARGET, injection_point="  ", tenant="t1"),
        dict(target=TARGET, injection_point=POINT, tenant=""),
    ]
    for kwargs in bad_calls:
        with pytest.raises(xc.CallbackError) as exc:
            corr.issue_payload(now=NOW, **kwargs)
        assert exc.value.code == "CALLBACK_INVALID_REQUEST"
    assert corr.report()["issued"] == 0
