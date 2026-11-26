import pytest

import mta_sts_enforcer as ms


def make_policy(**overrides):
    policy = {"id": "p1", "mode": "enforce", "max_age": 3600,
              "mx": ["mx1.example.com"]}
    policy.update(overrides)
    return policy


def enforcer(fetcher, **kwargs):
    return ms.MtaStsEnforcer(fetcher=fetcher, **kwargs)


def test_fetch_parses_policy_and_expiry():
    calls = []

    def fetcher(domain):
        calls.append(domain)
        return make_policy()

    e = enforcer(fetcher)
    record = e.fetch("example.com", now=100)
    assert record.domain == "example.com"
    assert record.policy_id == "p1"
    assert record.mode == "enforce"
    assert record.max_age == 3600
    assert record.mx == ("mx1.example.com",)
    assert record.fetched_at == 100
    assert record.expires_at == 3700
    assert calls == ["example.com"]
    assert e.stats()["fetched"] == 1


def test_fetch_uses_cache_before_expiry():
    calls = []

    def fetcher(domain):
        calls.append(domain)
        return make_policy()

    e = enforcer(fetcher)
    first = e.fetch("example.com", now=100)
    second = e.fetch("example.com", now=200)
    assert second.policy_id == first.policy_id
    assert calls == ["example.com"]
    assert e.stats()["cache_hits"] == 1


def test_fetch_refreshes_at_expiry():
    calls = []

    def fetcher(domain):
        calls.append(domain)
        return make_policy()

    e = enforcer(fetcher)
    e.fetch("example.com", now=100)
    e.fetch("example.com", now=3700)
    assert calls == ["example.com", "example.com"]


def test_zero_max_age_invalidates_immediately():
    e = enforcer(lambda domain: make_policy(max_age=0))
    record = e.fetch("example.com", now=100)
    assert record.expires_at == 100
    assert e.policy_for("example.com", now=100) is None
    decision = e.decide("example.com", "mx1.example.com", now=100)
    assert decision.action == "opportunistic"
    assert decision.reason == "NO_POLICY"


def test_enforce_match_delivers():
    e = enforcer(lambda domain: make_policy())
    e.fetch("example.com", now=100)
    decision = e.decide("example.com", "MX1.EXAMPLE.COM", now=200)
    assert decision.action == "deliver"
    assert decision.reason == "POLICY_MATCH"
    assert decision.policy_id == "p1"
    assert e.stats()["delivered"] == 1


def test_enforce_mismatch_defers_and_reports():
    e = enforcer(lambda domain: make_policy())
    e.fetch("example.com", now=100)
    decision = e.decide("example.com", "mx2.example.com", now=200)
    assert decision.action == "defer"
    assert decision.reason == "MX_NOT_ALLOWED"
    assert e.stats()["deferred"] == 1
    assert e.report()["example.com"]["defer"] == 1


def test_testing_mode_delivers_with_mismatch_marker():
    e = enforcer(lambda domain: make_policy(mode="testing"))
    e.fetch("example.com", now=100)
    decision = e.decide("example.com", "mx2.example.com", now=200)
    assert decision.action == "deliver"
    assert decision.reason == "TESTING_MISMATCH"
    assert e.stats()["delivered"] == 1


def test_mode_none_delivers():
    e = enforcer(lambda domain: make_policy(mode="none"))
    e.fetch("example.com", now=100)
    decision = e.decide("example.com", "anything.example", now=200)
    assert decision.action == "deliver"
    assert decision.reason == "POLICY_NONE"


def test_missing_policy_is_opportunistic_without_fetch():
    calls = []

    def fetcher(domain):
        calls.append(domain)
        return make_policy()

    e = enforcer(fetcher)
    decision = e.decide("example.com", "mx1.example.com", now=0)
    assert decision.action == "opportunistic"
    assert decision.reason == "NO_POLICY"
    assert calls == []
    assert e.stats()["opportunistic"] == 1


def test_wildcard_mx_matches_subdomains():
    e = enforcer(lambda domain: make_policy(mx=["*.mail.example.com"]))
    e.fetch("example.com", now=0)
    assert e.mx_matches("example.com", "a.mail.example.com", now=1) is True
    assert e.mx_matches("example.com", "a.b.mail.example.com", now=1) is True
    assert e.mx_matches("example.com", "mail.example.com", now=1) is False
    decision = e.decide("example.com", "a.mail.example.com", now=2)
    assert decision.action == "deliver"


def test_invalid_policy_keeps_old_cache():
    payloads = [make_policy(), {"id": "p2", "mode": "bogus",
                                "max_age": 3600, "mx": []}]

    def fetcher(domain):
        return payloads.pop(0)

    e = enforcer(fetcher)
    e.fetch("example.com", now=100)
    with pytest.raises(ms.StsError) as excinfo:
        e.fetch("example.com", now=200, force=True)
    assert excinfo.value.code == "STS_POLICY_INVALID"
    assert e.policy_for("example.com", now=200).policy_id == "p1"
    assert e.stats()["failures"] == 1


def test_fetch_failure_is_reported():
    def fetcher(domain):
        raise RuntimeError("upstream down")

    e = enforcer(fetcher)
    with pytest.raises(ms.StsError) as excinfo:
        e.fetch("example.com", now=0)
    assert excinfo.value.code == "STS_FETCH_FAILED"
    assert e.policy_for("example.com", now=0) is None
    assert e.stats()["failures"] == 1


def test_report_aggregates_and_respects_capacity():
    e = enforcer(lambda domain: make_policy(), report_capacity=1)
    e.fetch("d1", now=0)
    e.fetch("d2", now=0)
    e.decide("d1", "mx1.example.com", now=1)
    e.decide("d1", "mx2.example.com", now=2)
    e.decide("d2", "mx1.example.com", now=3)
    report = e.report()
    assert set(report) == {"d1"}
    assert report["d1"]["deliver"] == 1
    assert report["d1"]["defer"] == 1
    assert e.stats()["report_dropped"] == 1


def test_cache_capacity_evicts_oldest_domain():
    e = enforcer(lambda domain: make_policy(), cache_capacity=2)
    e.fetch("d1", now=100)
    e.fetch("d2", now=200)
    e.fetch("d3", now=300)
    assert e.policy_for("d1", now=350) is None
    assert e.policy_for("d3", now=350) is not None
    assert e.stats()["evicted"] == 1


def test_snapshot_restore_roundtrip_and_invalid_state():
    e = enforcer(lambda domain: make_policy())
    e.fetch("example.com", now=100)
    e.decide("example.com", "mx2.example.com", now=200)
    snap = e.snapshot()
    assert {"version", "policies", "reports", "failures", "stats"} <= set(snap)
    assert snap["stats"]["fetched"] == 1
    snap["stats"]["fetched"] = 99
    assert e.stats()["fetched"] == 1
    restored = enforcer(lambda domain: make_policy())
    restored.restore(snap)
    assert restored.policy_for("example.com", now=300).policy_id == "p1"
    assert restored.report()["example.com"]["defer"] == 1
    with pytest.raises(ms.StsError) as excinfo:
        restored.restore({"version": 1})
    assert excinfo.value.code == "STS_SNAPSHOT_INVALID"
