import copy

import pytest

import icmp_redirect_guard as ic

KEY = ("203.0.113.5", "198.51.100.5", "udp", 5000, 53)


def quoted(dst="198.51.100.5", sport=5000, dport=53, proto="udp"):
    return {
        "src": "203.0.113.5",
        "dst": dst,
        "proto": proto,
        "sport": sport,
        "dport": dport,
    }


def redirect(src="10.0.0.1", gateway="10.0.0.2", quote=None):
    return {
        "kind": "redirect",
        "src": src,
        "dst": "10.0.0.20",
        "gateway": gateway,
        "quoted": quoted() if quote is None else quote,
    }


def guard(**kwargs):
    params = dict(
        local_networks=["10.0.0.0/24", "192.168.50.0/24"],
        gateways=["10.0.0.1"],
        rate_limit=5,
        rate_window=1.0,
        cache_ttl=5.0,
        max_entries=8,
    )
    params.update(kwargs)
    instance = ic.IcmpRedirectGuard(**params)
    instance.route_changed([
        ic.Route("0.0.0.0/0", "10.0.0.1", "eth0"),
        ic.Route("198.51.100.0/24", "10.0.0.1", "eth0"),
        ic.Route("203.0.113.0/24", "10.0.0.1", "eth1"),
    ], now=100.0)
    return instance


def test_redirect_from_non_gateway_is_dropped():
    instance = guard()
    out = instance.on_icmp(redirect(src="10.0.0.99"), now=100.0)
    assert out == ic.Verdict("drop", "not_gateway", "redirect")
    assert instance.stats()["rejected"] == 1


def test_redirect_from_gateway_with_matching_route_is_applied():
    instance = guard()
    out = instance.on_icmp(redirect(gateway="10.0.0.2"), now=100.0)
    assert out == ic.Verdict("accept", "ok", "redirect")
    assert any(route.gateway == "10.0.0.2" for route in instance.routes())
    assert instance.stats()["accepted"] == 1


def test_redirect_for_destination_outside_gateway_route_is_dropped():
    instance = guard()
    out = instance.on_icmp(redirect(quote=quoted(dst="192.0.2.10")), now=100.0)
    assert out == ic.Verdict("drop", "quoted_mismatch", "redirect")


def test_redirect_without_quoted_tuple_is_dropped():
    instance = guard()
    packet = {
        "kind": "redirect",
        "src": "10.0.0.1",
        "dst": "10.0.0.20",
        "gateway": "10.0.0.2",
    }
    out = instance.on_icmp(packet, now=100.0)
    assert out == ic.Verdict("drop", "malformed", "redirect")


def test_fragmentation_needed_updates_path_mtu():
    instance = guard()
    packet = {
        "kind": "frag_needed",
        "src": "10.0.0.1",
        "dst": "10.0.0.20",
        "mtu": 1400,
        "quoted": quoted(),
    }
    out = instance.on_icmp(packet, now=100.0)
    assert out.action == "accept"
    assert out.reason == "path_mtu_updated"
    assert instance.path_mtu("198.51.100.5") == 1400


def test_fragmentation_needed_from_non_gateway_is_dropped():
    instance = guard()
    packet = {
        "kind": "frag_needed",
        "src": "10.0.0.77",
        "mtu": 1400,
        "quoted": quoted(),
    }
    out = instance.on_icmp(packet, now=100.0)
    assert out.action == "drop"
    assert instance.path_mtu("198.51.100.5") is None


def test_unreachable_verdict_is_cached_by_quoted_five_tuple():
    instance = guard()
    packet = {
        "kind": "unreachable",
        "src": "10.0.0.1",
        "dst": "10.0.0.20",
        "code": 3,
        "quoted": quoted(),
    }
    out = instance.on_icmp(packet, now=100.0)
    assert out.kind == "unreachable"
    assert out.action == "accept"
    assert instance.verdict(KEY, now=100.0) == out


def test_cached_verdict_expires_after_ttl():
    instance = guard(cache_ttl=5.0)
    instance.on_icmp(
        {"kind": "unreachable", "src": "10.0.0.1", "quoted": quoted()},
        now=100.0,
    )
    assert instance.verdict(KEY, now=104.0) is not None
    assert instance.verdict(KEY, now=106.0) is None


def test_purge_expired_removes_old_cache_entries():
    instance = guard(cache_ttl=5.0)
    instance.on_icmp(
        {"kind": "unreachable", "src": "10.0.0.1", "quoted": quoted()},
        now=100.0,
    )
    assert instance.purge_expired(now=104.0) == 0
    assert instance.purge_expired(now=106.0) == 1
    assert instance.verdict(KEY, now=106.0) is None


def test_redirect_rate_limit_drops_excess_and_alerts():
    instance = guard(rate_limit=5, rate_window=1.0)
    packet = redirect()
    outcomes = [instance.on_icmp(packet, now=100.0) for _ in range(6)]
    assert [outcome.action for outcome in outcomes] == [
        "accept", "accept", "accept", "accept", "accept", "drop",
    ]
    assert outcomes[-1].reason == "rate_limited"
    assert instance.stats()["alerts"] == 1


def test_rate_window_recovers_after_window_passes():
    instance = guard(rate_limit=2, rate_window=1.0)
    packet = redirect()
    assert instance.on_icmp(packet, now=100.0).action == "accept"
    assert instance.on_icmp(packet, now=100.2).action == "accept"
    assert instance.on_icmp(packet, now=100.5).reason == "rate_limited"
    assert instance.on_icmp(packet, now=102.0).action == "accept"


def test_route_changed_invalidates_cache_and_redirect_routes():
    instance = guard()
    instance.on_icmp(redirect(), now=100.0)
    instance.on_icmp(
        {"kind": "unreachable", "src": "10.0.0.1", "quoted": quoted()},
        now=100.0,
    )
    assert instance.verdict(KEY, now=100.0) is not None
    removed = instance.route_changed([
        ic.Route("0.0.0.0/0", "10.0.0.1", "eth0"),
        ic.Route("198.51.100.0/24", "10.0.0.1", "eth0"),
    ], now=101.0)
    assert removed >= 1
    assert instance.verdict(KEY, now=101.0) is None
    assert all(route.gateway != "10.0.0.2" for route in instance.routes())


def test_cache_capacity_evicts_oldest_entry():
    instance = guard(max_entries=2)
    for index, sport in enumerate([5001, 5002, 5003]):
        instance.on_icmp(
            {
                "kind": "unreachable",
                "src": "10.0.0.1",
                "quoted": quoted(sport=sport),
            },
            now=100.0 + index,
        )
    assert instance.verdict(
        ("203.0.113.5", "198.51.100.5", "udp", 5001, 53), now=103.0
    ) is None
    assert instance.verdict(
        ("203.0.113.5", "198.51.100.5", "udp", 5003, 53), now=103.0
    ) is not None
    assert instance.stats()["evicted"] == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    instance = guard()
    instance.on_icmp(
        {
            "kind": "frag_needed",
            "src": "10.0.0.1",
            "mtu": 1400,
            "quoted": quoted(),
        },
        now=100.0,
    )
    instance.on_icmp(
        {"kind": "unreachable", "src": "10.0.0.1", "quoted": quoted()},
        now=100.0,
    )
    state = instance.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {
        "version", "routes", "redirects", "cache", "mtus", "counters",
    }
    state["cache"].clear()
    state["counters"]["accepted"] = 99
    assert instance.verdict(KEY, now=101.0) is not None
    assert instance.stats()["accepted"] == 2

    clone = guard()
    clone.restore(pristine)
    assert clone.path_mtu("198.51.100.5") == 1400
    assert clone.verdict(KEY, now=101.0) is not None


def test_restore_rejects_malformed_snapshot_without_touching_state():
    instance = guard()
    instance.on_icmp(
        {"kind": "unreachable", "src": "10.0.0.1", "quoted": quoted()},
        now=100.0,
    )
    bad_states = [
        None,
        {},
        {"version": 1, "routes": [], "redirects": [], "cache": {},
         "mtus": {}, "counters": {}},
        {"version": 1, "routes": [], "redirects": {}, "cache": [],
         "mtus": {}, "counters": {}},
        {"version": 1, "routes": [], "redirects": {}, "cache": {},
         "mtus": [], "counters": {}},
        {"version": 2, "routes": [], "redirects": {}, "cache": {},
         "mtus": {}, "counters": {}},
    ]
    for bad in bad_states:
        with pytest.raises(ic.IcmpGuardError) as exc:
            instance.restore(bad)
        assert exc.value.code == "ICMP_SNAPSHOT_INVALID"
    assert instance.verdict(KEY, now=101.0) is not None
