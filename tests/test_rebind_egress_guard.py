import copy
import threading

import pytest

import rebind_egress_guard as rb

NOW = "2026-11-26T09:00:00+00:00"
SOON = "2026-11-26T09:00:30+00:00"
LATER = "2026-11-26T09:01:00+00:00"
PAST_TTL = "2026-11-26T09:03:00+00:00"

PRIMARY = ("93.184.216.34", "93.184.216.100")


def guard(**kwargs):
    return rb.RebindEgressGuard(**kwargs)


def tenant_guard(**kwargs):
    item = guard(**kwargs)
    item.register_tenant("t1")
    return item


def test_resolve_pins_deduplicated_numeric_order_with_ttl():
    item = tenant_guard()
    record = item.resolve("t1", "api.example.com",
                          ["93.184.216.100", "93.184.216.34", "93.184.216.34"],
                          ttl=120, now=NOW)
    assert record.tenant == "t1"
    assert record.host == "api.example.com"
    assert record.addresses == PRIMARY
    assert record.created_at == NOW
    assert record.expires_at == "2026-11-26T09:02:00+00:00"
    assert record.hops == ()
    assert item.status()["pins"] == 1
    assert item.stats()["resolved"] == 1


def test_resolve_same_set_within_ttl_is_stable():
    item = tenant_guard()
    first = item.resolve("t1", "api.example.com", ["93.184.216.34"], ttl=120, now=NOW)
    second = item.resolve("t1", "api.example.com", ["93.184.216.34"], now=LATER)
    assert second.addresses == first.addresses
    assert second.created_at == NOW
    assert second.expires_at == first.expires_at
    assert item.status()["pins"] == 1
    assert item.stats()["reused"] == 1


def test_resolve_shift_within_ttl_raises_address_shift():
    item = tenant_guard()
    item.resolve("t1", "api.example.com", PRIMARY, ttl=120, now=NOW)
    with pytest.raises(rb.RebindError) as exc:
        item.resolve("t1", "api.example.com", ["93.184.216.34", "8.8.8.8"], now=LATER)
    assert exc.value.code == "REBIND_ADDRESS_SHIFT"
    assert item.stats()["address_shifts"] == 1
    decision = item.check_connect("t1", "api.example.com", "93.184.216.100", now=LATER)
    assert decision.accepted is True
    assert decision.pinned_addresses == PRIMARY


def test_resolve_blocks_non_global_addresses_unless_policy_allows():
    item = tenant_guard()
    for host, address in (
        ("intranet.example.com", "10.0.0.5"),
        ("loopback.example.com", "127.0.0.1"),
        ("metadata.example.com", "169.254.169.254"),
    ):
        with pytest.raises(rb.RebindError) as exc:
            item.resolve("t1", host, [address], now=NOW)
        assert exc.value.code == "REBIND_FORBIDDEN_ADDRESS"

    item.register_tenant("t2", allow_private=True)
    private = item.resolve("t2", "intranet.example.com", ["10.0.0.5"], now=NOW)
    assert private.addresses == ("10.0.0.5",)

    item.register_tenant("t3", allow_metadata=True)
    metadata = item.resolve("t3", "metadata.example.com", ["169.254.169.254"], now=NOW)
    assert metadata.addresses == ("169.254.169.254",)

    with pytest.raises(rb.RebindError) as exc:
        item.resolve("t3", "mixed.example.com", ["169.254.169.254", "10.0.0.5"], now=NOW)
    assert exc.value.code == "REBIND_FORBIDDEN_ADDRESS"


def test_resolve_invalid_input_is_rejected():
    item = tenant_guard()
    cases = [
        ("t9", "api.example.com", ["93.184.216.34"], "REBIND_UNKNOWN_TENANT"),
        ("t1", "", ["93.184.216.34"], "REBIND_INVALID_REQUEST"),
        ("t1", "api.example.com", [], "REBIND_INVALID_REQUEST"),
        ("t1", "api.example.com", ["not-an-ip"], "REBIND_INVALID_REQUEST"),
    ]
    for tenant, host, addresses, code in cases:
        with pytest.raises(rb.RebindError) as exc:
            item.resolve(tenant, host, addresses, now=NOW)
        assert exc.value.code == code
    assert item.status()["pins"] == 0


def test_check_connect_requires_pin_then_accepts_pinned_peer():
    item = tenant_guard()
    with pytest.raises(rb.RebindError) as exc:
        item.check_connect("t1", "api.example.com", "93.184.216.34", now=NOW)
    assert exc.value.code == "REBIND_PIN_MISSING"

    item.resolve("t1", "api.example.com", PRIMARY, now=NOW)
    decision = item.check_connect("t1", "api.example.com", "93.184.216.34", now=NOW)
    assert decision.accepted is True
    assert decision.reason == "ok"
    assert decision.peer_address == "93.184.216.34"
    assert decision.pinned_addresses == PRIMARY


def test_check_connect_rejects_unpinned_peer_and_counts():
    item = tenant_guard()
    item.resolve("t1", "api.example.com", ["93.184.216.34"], now=NOW)
    decision = item.check_connect("t1", "api.example.com", "8.8.8.8", now=NOW)
    assert decision.accepted is False
    assert decision.reason == "peer_not_pinned"
    assert decision.pinned_addresses == ("93.184.216.34",)
    assert item.stats()["peer_rejections"] == 1


def test_check_connect_after_pin_expiry_is_rejected():
    item = tenant_guard()
    item.resolve("t1", "api.example.com", ["93.184.216.34"], ttl=60, now=NOW)
    decision = item.check_connect("t1", "api.example.com", "93.184.216.34", now=PAST_TTL)
    assert decision.accepted is False
    assert decision.reason == "pin_expired"
    assert item.stats()["pin_expired"] == 1


def test_pin_release_and_purge_track_counts():
    item = tenant_guard()
    record = item.pin("t1", "cdn.example.com", ["1.1.1.1"], ttl=30, now=NOW)
    assert record.addresses == ("1.1.1.1",)
    assert item.release("t1", "cdn.example.com") == 1
    assert item.release("t1", "cdn.example.com") == 0
    assert item.stats()["released"] == 1

    item.pin("t1", "short.example.com", ["8.8.8.8"], ttl=30, now=NOW)
    item.pin("t1", "long.example.com", ["8.8.4.4"], ttl=300, now=NOW)
    assert item.purge(now=LATER) == 1
    assert item.status()["pins"] == 1
    assert item.stats()["purged"] == 1


def test_blocked_address_classification():
    item = guard()
    assert item.blocked_address("127.0.0.1") is True
    assert item.blocked_address("169.254.169.254") is True
    assert item.blocked_address("10.1.2.3") is True
    assert item.blocked_address("192.168.1.5") is True
    assert item.blocked_address("::1") is True
    assert item.blocked_address("8.8.8.8") is False
    assert item.blocked_address("93.184.216.34") is False
    assert item.blocked_address("2606:4700::1111") is False


def test_tenant_pin_capacity_is_capped():
    item = tenant_guard(max_pins_per_tenant=2)
    item.resolve("t1", "a.example.com", ["8.8.8.8"], now=NOW)
    item.resolve("t1", "b.example.com", ["8.8.4.4"], now=NOW)
    with pytest.raises(rb.RebindError) as exc:
        item.resolve("t1", "c.example.com", ["1.1.1.1"], now=NOW)
    assert exc.value.code == "REBIND_CAPACITY_EXCEEDED"
    assert item.status()["pins"] == 2


def test_rejection_rate_limit_is_aggregated_per_host():
    item = tenant_guard(max_rejects_per_host=3, reject_window=60.0)
    item.resolve("t1", "api.example.com", ["93.184.216.34"], now=NOW)
    for _ in range(3):
        decision = item.check_connect("t1", "api.example.com", "8.8.8.8", now=NOW)
        assert decision.accepted is False
    with pytest.raises(rb.RebindError) as exc:
        item.check_connect("t1", "api.example.com", "8.8.8.8", now=NOW)
    assert exc.value.code == "REBIND_REJECT_LIMIT"
    assert item.stats()["peer_rejections"] == 3
    assert item.stats()["rate_limited"] == 1


def test_concurrent_resolves_keep_single_pin():
    item = tenant_guard()
    records = []
    errors = []
    barrier = threading.Barrier(6)

    def worker():
        try:
            barrier.wait(timeout=5)
            records.append(item.resolve("t1", "api.example.com",
                                        ["93.184.216.100", "93.184.216.34"],
                                        ttl=120, now=NOW))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(records) == 6
    assert {record.addresses for record in records} == {PRIMARY}
    assert item.status()["pins"] == 1


def test_snapshot_roundtrip_keeps_live_pins():
    item = tenant_guard()
    item.resolve("t1", "api.example.com", PRIMARY, ttl=120, now=NOW)
    state = item.snapshot()
    assert set(state) == {"version", "tenants", "pins", "rejections", "counters", "stats"}
    pristine = copy.deepcopy(state)
    state["pins"].clear()
    state["stats"]["peer_rejections"] = 99
    assert item.status()["pins"] == 1
    assert item.stats()["peer_rejections"] == 0

    clone = guard()
    clone.restore(pristine)
    decision = clone.check_connect("t1", "api.example.com", "93.184.216.34", now=LATER)
    assert decision.accepted is True
    assert decision.pinned_addresses == PRIMARY


def test_restore_rejects_malformed_state_without_touching_live_pins():
    item = tenant_guard()
    item.resolve("t1", "api.example.com", ["93.184.216.34"], now=NOW)
    bad_states = [
        None,
        {},
        {"version": 9, "tenants": {}, "pins": {}, "rejections": {}, "counters": {}, "stats": {}},
        {"version": 1, "tenants": [], "pins": {}, "rejections": {}, "counters": {}, "stats": {}},
        {"version": 1, "tenants": {}, "pins": [], "rejections": {}, "counters": {}, "stats": {}},
        {"version": 1, "tenants": {}, "pins": {}, "rejections": {}, "counters": {}, "stats": {"resolved": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(rb.RebindError) as exc:
            item.restore(bad)
        assert exc.value.code == "REBIND_SNAPSHOT_INVALID"
    assert item.status()["pins"] == 1
    decision = item.check_connect("t1", "api.example.com", "93.184.216.34", now=NOW)
    assert decision.accepted is True
