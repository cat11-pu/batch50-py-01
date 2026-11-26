import pytest

import split_tunnel_route_policy as sp


def policy(**kwargs):
    return sp.SplitTunnelPolicy(**kwargs)


def test_compile_orders_routes_and_marks_source():
    p = policy()
    p.set_global(includes=["10.0.0.0/8", "192.168.1.0/24", "172.16.0.0/16"])
    plan = p.compile()
    assert tuple(route.cidr for route in plan.routes) == (
        "192.168.1.0/24", "172.16.0.0/16", "10.0.0.0/8")
    assert tuple(route.source for route in plan.routes) == (
        "global", "global", "global")
    assert plan.default_via == "tunnel"
    assert plan.conflicts == 0


def test_specific_include_beats_broader_exclude():
    p = policy()
    p.set_global(includes=["10.1.0.0/16"], excludes=["10.0.0.0/8"])
    plan = p.compile()
    assert [route.cidr for route in plan.routes] == ["10.1.0.0/16"]
    inside = p.explain("10.1.2.3")
    assert inside.egress == "tunnel"
    assert inside.matched_prefix == "10.1.0.0/16"
    outside = p.explain("10.2.2.3")
    assert outside.egress == "local"
    assert outside.matched_prefix == "10.0.0.0/8"


def test_explain_defaults_to_local():
    p = policy()
    p.set_global(includes=["10.1.0.0/16"], excludes=["10.128.0.0/9"])
    unmatched = p.explain("192.0.2.5")
    assert unmatched.egress == "local"
    assert unmatched.matched_prefix is None
    assert unmatched.source == "default"
    excluded = p.explain("10.200.1.1")
    assert excluded.egress == "local"
    assert excluded.matched_prefix == "10.128.0.0/9"


def test_application_order_does_not_change_plan():
    p = policy()
    p.set_tenant("t1", includes=["10.0.0.0/8"])
    p.set_app("vpn-a", includes=["10.10.0.0/16"])
    p.set_app("vpn-b", includes=["10.20.0.0/16"])
    first = p.compile(tenant="t1", apps=["vpn-a", "vpn-b"])
    second = p.compile(tenant="t1", apps=["vpn-b", "vpn-a"])
    assert first.routes == second.routes
    assert first.fingerprint == second.fingerprint
    assert [route.cidr for route in first.routes] == [
        "10.10.0.0/16", "10.20.0.0/16", "10.0.0.0/8"]


def test_default_route_has_single_source():
    p = policy()
    p.set_global(includes=["0.0.0.0/0"])
    p.set_tenant("t1", includes=["0.0.0.0/0"], default_via="tunnel")
    plan = p.compile(tenant="t1")
    defaults = [route for route in plan.routes if route.cidr == "0.0.0.0/0"]
    assert len(defaults) == 1
    assert plan.default_via == "tunnel"
    assert plan.conflicts == 1
    p.set_tenant("t2", includes=["0.0.0.0/0"], default_via="local")
    local_plan = p.compile(tenant="t2")
    assert local_plan.default_via == "local"
    assert all(route.cidr != "0.0.0.0/0" for route in local_plan.routes)


def test_dns_zone_override_and_fallback():
    p = policy()
    p.set_tenant("t1", includes=["10.0.0.0/8"], dns_mode="local")
    p.set_app("corp", includes=["10.1.0.0/16"],
              dns_zones=("corp.example",), dns_mode="tunnel")
    assert p.dns_route("api.corp.example", tenant="t1",
                       apps=["corp"]) == "tunnel"
    assert p.dns_route("www.other.example", tenant="t1",
                       apps=["corp"]) == "local"


def test_explain_reports_application_source():
    p = policy()
    p.set_tenant("t1", includes=["10.0.0.0/8"])
    p.set_app("crm", includes=["10.9.0.0/16"])
    app_hit = p.explain("10.9.1.2", tenant="t1", apps=["crm"])
    assert app_hit.egress == "tunnel"
    assert app_hit.matched_prefix == "10.9.0.0/16"
    assert app_hit.source == "app:crm"
    tenant_hit = p.explain("10.7.1.2", tenant="t1", apps=["crm"])
    assert tenant_hit.source == "tenant"


def test_apply_is_idempotent_for_same_plan():
    p = policy()
    p.set_global(includes=["10.0.0.0/8"])
    plan = p.compile()
    assert p.apply(plan) == 1
    assert p.installed() == ("10.0.0.0/8",)
    assert p.apply(plan) == 0
    assert p.stats()["applied"] == 1


def test_remove_only_touches_application_routes():
    p = policy()
    p.set_global(includes=["10.0.0.0/8"])
    p.set_app("crm", includes=["10.9.0.0/16"])
    p.apply(p.compile(apps=["crm"]))
    assert p.remove(app="crm") == 1
    assert p.installed() == ("10.0.0.0/8",)
    assert p.remove(app="crm") == 0


def test_reclaim_clears_every_installed_route():
    p = policy()
    p.set_global(includes=["10.0.0.0/8"])
    p.set_app("crm", includes=["10.9.0.0/16"])
    p.apply(p.compile(apps=["crm"]))
    assert p.reclaim() == 2
    assert p.installed() == ()
    assert p.stats()["reclaimed"] == 2


def test_route_limit_is_enforced():
    p = policy(max_routes=2)
    p.set_global(includes=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])
    with pytest.raises(sp.RoutePolicyError) as excinfo:
        p.compile()
    assert excinfo.value.code == "ROUTE_LIMIT_EXCEEDED"
    assert p.stats()["limit_rejected"] == 1


def test_invalid_cidr_is_rejected_on_write():
    p = policy()
    with pytest.raises(sp.RoutePolicyError) as excinfo:
        p.set_global(includes=["10.0.0.0/33"])
    assert excinfo.value.code == "ROUTE_INVALID_CIDR"


def test_unknown_or_empty_application_is_rejected():
    p = policy()
    with pytest.raises(sp.RoutePolicyError) as excinfo:
        p.compile(apps=["ghost"])
    assert excinfo.value.code == "ROUTE_UNKNOWN_APP"
    with pytest.raises(sp.RoutePolicyError) as excinfo:
        p.set_app("", includes=["10.0.0.0/8"])
    assert excinfo.value.code == "INVALID_REQUEST"


def test_snapshot_restore_leaves_no_installed_routes():
    p = policy()
    p.set_global(includes=["10.0.0.0/8"])
    p.set_app("crm", includes=["10.9.0.0/16"])
    plan = p.compile(apps=["crm"])
    p.apply(plan)
    snap = p.snapshot()
    assert {"version", "global", "tenants", "apps", "stats"} <= set(snap)
    restored = policy()
    restored.restore(snap)
    assert restored.installed() == ()
    assert restored.compile(apps=["crm"]).fingerprint == plan.fingerprint


def test_invalid_snapshot_is_rejected_without_side_effects():
    p = policy()
    p.set_global(includes=["10.0.0.0/8"])
    with pytest.raises(sp.RoutePolicyError) as excinfo:
        p.restore({"version": 1})
    assert excinfo.value.code == "ROUTE_SNAPSHOT_INVALID"
    assert [route.cidr for route in p.compile().routes] == ["10.0.0.0/8"]
