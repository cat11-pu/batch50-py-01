import pytest

import dangling_cname_guard as dg

ZONE = "example.test"
OWNER = "acme"
NOW = 1000


def resolution(status="NOERROR", chain=(), addresses=(), ttl=300,
               fetched_at="2026-11-26T09:00:00Z", page=""):
    return {"status": status, "chain": tuple(chain), "addresses": tuple(addresses),
            "ttl": ttl, "fetched_at": fetched_at, "page": page}


class FakeResolver:
    def __init__(self, mapping):
        self.mapping = dict(mapping)
        self.hosts = []

    def __call__(self, host):
        self.hosts.append(host)
        return dict(self.mapping[host])


def guard_with(mapping, *, records=None, **kwargs):
    resolver = FakeResolver(mapping)
    guard = dg.DanglingCnameGuard(resolver=resolver, **kwargs)
    guard.fingerprint("pages", suffixes=[".github.io"],
                      markers=["There isn't a GitHub Pages site here."])
    guard.register_zone(ZONE, records, owner=OWNER)
    return guard, resolver


def test_register_zone_normalizes_records_and_rejects_foreign_hosts():
    guard = dg.DanglingCnameGuard(resolver=FakeResolver({}))
    count = guard.register_zone("Example.Test.", {"WWW.Example.Test.": ["ACME.GitHub.io"]},
                                owner="acme")
    assert count == 1
    assert guard.stats()["domains"] == 1
    with pytest.raises(dg.TakeoverError) as err:
        guard.register_zone("example.test", {"api.other.test": ["x.test"]}, owner="acme")
    assert err.value.code == "ZONE_INVALID"
    assert guard.stats()["domains"] == 1


def test_nxdomain_target_creates_candidate_without_exploitable_flag():
    guard, resolver = guard_with(
        {"www.example.test": resolution(status="NXDOMAIN", chain=["acme.github.io"])},
        records={"www.example.test": ["acme.github.io"]})
    out = guard.scan_domain("www.example.test", now=NOW)
    assert out.state == "candidate"
    assert out.evidence != ()
    assert out.cached is False
    assert out.conflict is False
    conclusion = guard.conclusions()[0]
    assert conclusion.domain == "www.example.test"
    assert conclusion.target == "acme.github.io"
    assert conclusion.exploitable is False
    assert resolver.hosts == ["www.example.test"]


def test_unclaimed_service_and_error_page_evidence():
    guard, _ = guard_with(
        {"www.example.test": resolution(chain=["acme.github.io"], addresses=(),
                                       page="<h1>There isn't a GitHub Pages site here.</h1>")},
        records={"www.example.test": ["acme.github.io"]})
    out = guard.scan_domain("www.example.test", now=NOW)
    assert out.state == "candidate"
    assert len(out.evidence) == 2
    assert guard.conclusions()[0].service == "pages"


def test_resolving_target_is_clean():
    guard, _ = guard_with(
        {"www.example.test": resolution(chain=["acme.github.io"],
                                       addresses=["203.0.113.9"])},
        records={"www.example.test": ["acme.github.io"]})
    out = guard.scan_domain("www.example.test", now=NOW)
    assert out.state == "clean"
    assert out.evidence == ()


def test_unknown_domain_is_rejected():
    guard, resolver = guard_with(
        {"www.example.test": resolution(status="NXDOMAIN", chain=["acme.github.io"])},
        records={"www.example.test": ["acme.github.io"]})
    with pytest.raises(dg.TakeoverError) as err:
        guard.scan_domain("other.example.test", now=NOW)
    assert err.value.code == "DOMAIN_UNKNOWN"
    assert resolver.hosts == []


def test_timeout_and_servfail_use_distinct_codes_and_retry_counter():
    mapping = {
        "a.example.test": resolution(status="TIMEOUT", chain=["acme.github.io"]),
        "b.example.test": resolution(status="SERVFAIL", chain=["acme.github.io"]),
    }
    records = {"a.example.test": ["acme.github.io"], "b.example.test": ["acme.github.io"]}
    guard, _ = guard_with(mapping, records=records)
    with pytest.raises(dg.TakeoverError) as first:
        guard.scan_domain("a.example.test", now=NOW)
    assert first.value.code == "DNS_TIMEOUT"
    with pytest.raises(dg.TakeoverError) as second:
        guard.scan_domain("b.example.test", now=NOW)
    assert second.value.code == "DNS_SERVFAIL"
    assert guard.conclusions() == []


def test_confirm_confirms_candidate_and_marks_exploitable():
    guard, _ = guard_with(
        {"www.example.test": resolution(status="NXDOMAIN", chain=["acme.github.io"])},
        records={"www.example.test": ["acme.github.io"]})
    guard.scan_domain("www.example.test", now=NOW)
    assert guard.confirm("www.example.test", now=NOW + 5) == "confirmed"
    conclusion = guard.conclusions(state="confirmed")[0]
    assert conclusion.state == "confirmed"
    assert conclusion.exploitable is True
    with pytest.raises(dg.TakeoverError) as err:
        guard.confirm("www.example.test", now=NOW + 6)
    assert err.value.code == "STATE_INVALID"


def test_confirm_validates_verdict_and_state():
    mapping = {
        "a.example.test": resolution(status="NXDOMAIN", chain=["acme.github.io"]),
        "b.example.test": resolution(chain=["acme.github.io"], addresses=["203.0.113.9"]),
    }
    records = {"a.example.test": ["acme.github.io"], "b.example.test": ["acme.github.io"]}
    guard, _ = guard_with(mapping, records=records)
    guard.scan_domain("a.example.test", now=NOW)
    guard.scan_domain("b.example.test", now=NOW)
    with pytest.raises(dg.TakeoverError) as err:
        guard.confirm("a.example.test", verdict="exploit", now=NOW + 1)
    assert err.value.code == "VERDICT_INVALID"
    with pytest.raises(dg.TakeoverError) as err:
        guard.confirm("b.example.test", now=NOW + 1)
    assert err.value.code == "STATE_INVALID"
    assert guard.confirm("a.example.test", verdict="ignored", now=NOW + 2) == "ignored"
    assert guard.conclusions(state="ignored")[0].exploitable is False


def test_rescan_inside_interval_returns_cached_conclusion():
    guard, resolver = guard_with(
        {"www.example.test": resolution(status="NXDOMAIN", chain=["acme.github.io"])},
        records={"www.example.test": ["acme.github.io"]})
    guard.scan_domain("www.example.test", now=NOW)
    calls = len(resolver.hosts)
    out = guard.rescan("www.example.test", now=NOW + 60)
    assert out.cached is True
    assert out.state == "candidate"
    assert len(resolver.hosts) == calls


def test_rescan_after_interval_flips_to_fixed():
    guard, resolver = guard_with(
        {"www.example.test": resolution(status="NXDOMAIN", chain=["acme.github.io"])},
        records={"www.example.test": ["acme.github.io"]})
    guard.scan_domain("www.example.test", now=NOW)
    resolver.mapping["www.example.test"] = resolution(chain=["acme.github.io"],
                                                     addresses=["198.51.100.7"])
    out = guard.rescan("www.example.test", now=NOW + 3600)
    assert out.state == "fixed"
    assert out.cached is False
    assert guard.conclusions()[0].state == "fixed"


def test_scan_zone_continues_after_dns_failure():
    records = {"a.example.test": ["acme.github.io"],
               "b.example.test": ["acme.github.io"],
               "c.example.test": ["acme.github.io"]}
    mapping = {
        "a.example.test": resolution(status="NXDOMAIN", chain=["acme.github.io"]),
        "b.example.test": resolution(status="TIMEOUT", chain=["acme.github.io"]),
        "c.example.test": resolution(status="NXDOMAIN", chain=["acme.github.io"]),
    }
    guard, _ = guard_with(mapping, records=records)
    results = guard.scan_zone(ZONE, now=NOW)
    assert [item.domain for item in results] == ["a.example.test", "c.example.test"]
    assert guard.stats()["failed"] == 1


def test_scan_rate_limit_uses_second_window():
    records = {"a.example.test": ["acme.github.io"],
               "b.example.test": ["acme.github.io"],
               "c.example.test": ["acme.github.io"]}
    mapping = {name: resolution(status="NXDOMAIN", chain=["acme.github.io"]) for name in records}
    guard, _ = guard_with(mapping, records=records, scan_rate=2)
    guard.scan_domain("a.example.test", now=NOW)
    guard.scan_domain("b.example.test", now=NOW)
    with pytest.raises(dg.TakeoverError) as err:
        guard.scan_domain("c.example.test", now=NOW)
    assert err.value.code == "SCAN_RATE_LIMITED"


def test_conclusion_table_capacity_is_enforced():
    records = {"a.example.test": ["acme.github.io"],
               "b.example.test": ["acme.github.io"]}
    mapping = {name: resolution(status="NXDOMAIN", chain=["acme.github.io"]) for name in records}
    guard, _ = guard_with(mapping, records=records, max_conclusions=1)
    guard.scan_domain("a.example.test", now=NOW)
    with pytest.raises(dg.TakeoverError) as err:
        guard.scan_domain("b.example.test", now=NOW)
    assert err.value.code == "CAPACITY_EXCEEDED"


def test_evidence_cap_truncates_and_counts_drops():
    guard, _ = guard_with(
        {"www.example.test": resolution(chain=["acme.github.io"], addresses=(),
                                       page="<h1>There isn't a GitHub Pages site here.</h1>")},
        records={"www.example.test": ["acme.github.io"]}, max_evidence=1)
    out = guard.scan_domain("www.example.test", now=NOW)
    assert len(out.evidence) == 1


def test_snapshot_restore_roundtrip_and_rejects_bad_state():
    guard, _ = guard_with(
        {"www.example.test": resolution(status="NXDOMAIN", chain=["acme.github.io"])},
        records={"www.example.test": ["acme.github.io"]})
    guard.scan_domain("www.example.test", now=NOW)
    guard.confirm("www.example.test", now=NOW + 10)
    snap = guard.snapshot()
    assert "conclusions" in snap
    clone = dg.DanglingCnameGuard(resolver=FakeResolver({}))
    clone.restore(snap)
    assert clone.stats() == guard.stats()
    assert [(item.domain, item.state, item.exploitable) for item in clone.conclusions()] == [
        ("www.example.test", "confirmed", True)]
    with pytest.raises(dg.TakeoverError) as err:
        clone.restore({"conclusions": "broken"})
    assert err.value.code == "SNAPSHOT_INVALID"
    assert clone.conclusions()[0].state == "confirmed"
