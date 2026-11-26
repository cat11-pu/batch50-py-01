import copy
from datetime import datetime, timedelta

import pytest

import home_realm_router as hr

NOW = "2026-11-26T10:00:00+00:00"


def at(seconds):
    return (datetime.fromisoformat(NOW) + timedelta(seconds=seconds)).isoformat()


def router(**kwargs):
    return hr.HomeRealmRouter(**kwargs)


def reg(store, domain="example.com", *, tenant="t1", realm="idp-a",
        priority=0, now=NOW):
    return store.register_domain(domain, tenant=tenant, realm=realm,
                                 priority=priority, now=now)


def test_register_normalizes_domain_and_returns_rule():
    store = router()
    rule = reg(store, "  Example.COM. ")
    assert rule.domain == "example.com"
    assert rule.tenant == "t1"
    assert rule.realm == "idp-a"
    assert rule.priority == 0
    assert rule.revision == 1
    assert rule.state == "active"
    assert rule.updated_at == NOW


def test_register_same_tenant_updates_revision():
    store = router()
    reg(store, now=NOW)
    updated = reg(store, realm="idp-b", now=at(10))
    assert updated.revision == 2
    assert updated.realm == "idp-b"
    assert updated.updated_at == at(10)
    rows = store.rules()
    assert len(rows) == 1
    assert rows[0].realm == "idp-b"


def test_register_rejects_malformed_domain_and_blank_fields():
    store = router()
    for domain in ["", "localhost", "a@b.com", ".example.com",
                   "example..com", "exa mple.com", "-bad.com"]:
        with pytest.raises(hr.HomeRealmError) as exc:
            reg(store, domain)
        assert exc.value.code == "ROUTER_BAD_DOMAIN"
    with pytest.raises(hr.HomeRealmError) as exc:
        store.register_domain("example.com", tenant="   ", realm="idp-a",
                              now=NOW)
    assert exc.value.code == "ROUTER_INVALID_REQUEST"
    with pytest.raises(hr.HomeRealmError) as exc:
        store.register_domain("example.com", tenant="t1", realm="",
                              now=NOW)
    assert exc.value.code == "ROUTER_INVALID_REQUEST"


def test_resolve_rejects_malformed_email():
    store = router()
    for email in ["", "user", "@example.com", "user@", "a@b@c.com", "  "]:
        with pytest.raises(hr.HomeRealmError) as exc:
            store.resolve(email, now=NOW)
        assert exc.value.code == "ROUTER_INVALID_EMAIL"


def test_resolve_exact_domain_records_source():
    store = router()
    reg(store)
    out = store.resolve("User@Example.com", now=NOW)
    assert out.email == "user@example.com"
    assert out.domain == "example.com"
    assert out.matched_domain == "example.com"
    assert out.tenant == "t1"
    assert out.realm == "idp-a"
    assert out.source == "registry"
    assert out.conflict is False
    assert out.degraded is False
    assert out.attempted_realm is None
    assert out.reason is None


def test_resolve_uses_suffix_of_registered_domain():
    store = router()
    reg(store)
    out = store.resolve("someone@eu.example.com", now=NOW)
    assert out.domain == "eu.example.com"
    assert out.matched_domain == "example.com"
    assert out.tenant == "t1"
    assert out.realm == "idp-a"
    assert out.source == "registry"


def test_resolve_unknown_domain_uses_default_realm():
    store = router(default_realm="corp-default")
    out = store.resolve("a@other.org", now=NOW)
    assert out.domain == "other.org"
    assert out.matched_domain is None
    assert out.tenant is None
    assert out.realm == "corp-default"
    assert out.source == "default"
    assert out.conflict is False
    assert out.degraded is False


def test_cache_serves_stale_rule_until_ttl_expires():
    store = router(cache_ttl=300)
    reg(store, now=NOW)
    first = store.resolve("a@example.com", now=NOW)
    assert first.realm == "idp-a"
    assert first.source == "registry"
    reg(store, realm="idp-b", now=at(10))
    cached = store.resolve("a@example.com", now=at(100))
    assert cached.realm == "idp-a"
    assert cached.source == "cache"
    fresh = store.resolve("a@example.com", now=at(301))
    assert fresh.realm == "idp-b"
    assert fresh.source == "registry"


def test_refresh_clears_cache_and_reports_entries():
    store = router()
    reg(store, "a.com", realm="r1", now=NOW)
    reg(store, "b.com", realm="r2", now=NOW)
    store.resolve("x@a.com", now=NOW)
    store.resolve("x@b.com", now=at(1))
    assert store.refresh(now=at(2)) == 2
    again = store.resolve("x@a.com", now=at(3))
    assert again.source == "registry"
    assert store.refresh(now=at(4)) == 1
    assert store.refresh(now=at(5)) == 0


def test_unavailable_realm_degrades_and_recovers():
    store = router()
    reg(store)
    assert store.resolve("a@example.com", now=NOW).realm == "idp-a"
    store.mark_unavailable("idp-a")
    degraded = store.resolve("a@example.com", now=at(10))
    assert degraded.realm == "local"
    assert degraded.degraded is True
    assert degraded.attempted_realm == "idp-a"
    assert degraded.matched_domain == "example.com"
    assert degraded.source == "registry"
    store.mark_available("idp-a")
    healthy = store.resolve("a@example.com", now=at(20))
    assert healthy.realm == "idp-a"
    assert healthy.degraded is False
    assert healthy.attempted_realm is None


def test_explicit_fallback_reports_reason_and_original_realm():
    store = router()
    reg(store)
    out = store.fallback("a@sub.example.com", reason="idp-down", now=NOW)
    assert out.domain == "sub.example.com"
    assert out.matched_domain == "example.com"
    assert out.tenant == "t1"
    assert out.realm == "local"
    assert out.source == "fallback"
    assert out.degraded is True
    assert out.attempted_realm == "idp-a"
    assert out.reason == "idp-down"
    with pytest.raises(hr.HomeRealmError) as exc:
        store.fallback("not-an-email", now=NOW)
    assert exc.value.code == "ROUTER_INVALID_EMAIL"


def test_unregister_domain_removes_rule_by_tenant():
    store = router()
    reg(store)
    assert store.unregister_domain("  Example.COM. ", tenant="t1",
                                   now=at(5)) is True
    assert store.unregister_domain("example.com", tenant="t1", now=at(6)) is False
    out = store.resolve("a@example.com", now=at(7))
    assert out.realm == "local"
    assert out.source == "default"
    reg(store, now=at(8))
    assert store.unregister_domain("example.com", tenant="t9",
                                   now=at(9)) is False
    assert len(store.rules()) == 1


def test_domain_capacity_blocks_new_domains_only():
    store = router(max_domains=2)
    reg(store, "a.com", realm="r1", now=NOW)
    reg(store, "b.com", realm="r2", now=at(1))
    with pytest.raises(hr.HomeRealmError) as exc:
        reg(store, "c.com", realm="r3", now=at(2))
    assert exc.value.code == "ROUTER_CAPACITY"
    updated = reg(store, "a.com", realm="r9", now=at(3))
    assert updated.revision == 2
    assert len(store.rules()) == 2


def test_snapshot_is_detached_and_restore_roundtrips():
    store = router()
    reg(store, "a.com", realm="r1", now=NOW)
    reg(store, "b.com", realm="r2", now=NOW)
    store.resolve("x@a.com", now=NOW)
    state = store.snapshot()
    pristine = copy.deepcopy(state)
    assert set(state) == {"version", "rules", "health", "cache", "stats"}
    state["rules"].clear()
    state["health"].clear()
    state["stats"]["registered"] = 99
    assert store.resolve("x@b.com", now=at(1)).realm == "r2"
    assert store.stats()["registered"] == 2

    clone = router()
    clone.restore(pristine)
    restored = clone.resolve("x@a.com", now=at(2))
    assert restored.realm == "r1"
    assert len(clone.rules()) == 2

    live = clone.snapshot()
    for bad in [None, {}, {"version": 2, "rules": [], "health": {},
                           "cache": {}, "stats": {}},
                {"version": 1, "rules": "nope", "health": {}, "cache": {},
                 "stats": {}},
                {"version": 1, "rules": [], "health": [], "cache": {},
                 "stats": {}},
                {"version": 1, "rules": [], "health": {}, "cache": {},
                 "stats": {"registered": 1}}]:
        with pytest.raises(hr.HomeRealmError) as exc:
            clone.restore(bad)
        assert exc.value.code == "ROUTER_SNAPSHOT_INVALID"
    assert clone.snapshot() == live


def test_stats_track_registration_resolution_and_degradation():
    store = router()
    reg(store, now=NOW)
    store.resolve("a@example.com", now=NOW)
    store.resolve("a@example.com", now=at(1))
    store.resolve("a@unknown.org", now=at(2))
    store.mark_unavailable("idp-a")
    store.resolve("a@example.com", now=at(3))
    assert store.stats() == {"registered": 1, "resolved": 4, "cache_hits": 1,
                             "defaults": 1, "degraded": 1}
