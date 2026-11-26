import pytest

import tls_inspection_broker as tb


def broker(**kwargs):
    return tb.InspectionBroker(**kwargs)


def test_default_decision_inspects_with_root_ca():
    b = broker()
    decision = b.decide("c1", sni="www.example.com", tenant="t1", now=0)
    assert decision.action == "inspect"
    assert decision.reason == "DEFAULT_INSPECT"
    assert decision.ca_id == "ca-root"
    assert decision.generation == 1
    assert b.decision_for("c1") == decision
    assert b.stats()["inspected"] == 1


def test_longest_suffix_selects_ca():
    b = broker()
    assert b.reload_ca({"ca-a": ["example.com"],
                        "ca-b": ["api.example.com"]}) == 2
    assert b.ca_for_sni("api.example.com") == "ca-b"
    assert b.ca_for_sni("www.example.com") == "ca-a"
    assert b.ca_generation() == 2


def test_equal_length_patterns_break_by_ca_id():
    b = broker()
    b.reload_ca({"ca-z": ["svc.example.com"], "ca-a": ["svc.example.com"]})
    assert b.ca_for_sni("svc.example.com") == "ca-a"


def test_tenant_bypass_mode():
    b = broker()
    b.set_tenant_policy("t2", mode="bypass")
    decision = b.decide("c9", sni="secret.example.com", tenant="t2", now=0)
    assert decision.action == "bypass"
    assert decision.reason == "TENANT_BYPASS"
    assert decision.ca_id is None
    assert b.stats()["bypassed"] == 1


def test_decision_is_cached_per_connection():
    b = broker()
    first = b.decide("c1", sni="a.example.com", tenant="t1", now=0)
    again = b.decide("c1", sni="a.example.com", tenant="t1", now=5)
    assert again == first
    assert b.stats()["decisions"] == 1


def test_conflicting_decision_is_rejected():
    b = broker()
    b.decide("c1", sni="a.example.com", tenant="t1", now=0)
    with pytest.raises(tb.BrokerError) as excinfo:
        b.decide("c1", sni="b.example.com", tenant="t1", now=1)
    assert excinfo.value.code == "CONN_DECISION_CONFLICT"
    assert b.stats()["conflicts"] == 1
    assert b.decision_for("c1").action == "inspect"


def test_pinned_host_bypass_window_expires():
    b = broker(window_seconds=900)
    b.set_tenant_policy("t1", mode="inspect",
                        pinned_hosts=("pinned.example.com",))
    decision = b.decide("c1", sni="pinned.example.com", tenant="t1", now=0)
    assert decision.action == "bypass"
    assert decision.reason == "PINNED_CERT"
    assert b.stats()["windows_open"] == 1
    assert b.expire_windows(now=899) == 0
    assert b.expire_windows(now=900) == 1
    assert b.decision_for("c1") is None
    assert b.stats()["windows_expired"] == 1


def test_reissue_requires_inspect_decision():
    b = broker()
    b.set_tenant_policy("t2", mode="bypass")
    b.decide("c2", sni="x.example.com", tenant="t2", now=0)
    with pytest.raises(tb.BrokerError) as excinfo:
        b.reissue_context("c2")
    assert excinfo.value.code == "NO_INSPECTION_DECISION"
    with pytest.raises(tb.BrokerError) as excinfo:
        b.reissue_context("missing")
    assert excinfo.value.code == "NO_INSPECTION_DECISION"


def test_reissue_san_covers_sni_and_stays_stable():
    b = broker()
    b.decide("c1", sni="www.example.com", tenant="t1", now=0)
    first = b.reissue_context("c1", now=1)
    again = b.reissue_context("c1", now=2)
    assert first.san == ("www.example.com",)
    assert first.ca_id == "ca-root"
    assert first.serial == again.serial
    assert b.stats()["reissues"] == 1


def test_reload_ca_keeps_one_overlap_generation():
    b = broker()
    assert b.ca_generation() == 1
    assert b.reload_ca({"ca-new": ["new.example.com"]}) == 2
    assert b.ca_ids() == ("ca-new", "ca-root")
    assert b.reload_ca({"ca-final": ["final.example.com"]}) == 3
    assert b.ca_ids() == ("ca-final", "ca-new")
    assert b.stats()["reloads"] == 2
    assert b.stats()["ca_retired"] == 1


def test_invalid_bundle_keeps_previous_ca_set():
    b = broker()
    with pytest.raises(tb.BrokerError) as excinfo:
        b.reload_ca({"ca-x": "example.com"})
    assert excinfo.value.code == "CA_BUNDLE_INVALID"
    assert b.ca_generation() == 1
    assert b.ca_ids() == ("ca-root",)


def test_decision_capacity_limit():
    b = broker(max_decisions=2)
    b.decide("c1", sni="a.example.com", tenant="t1", now=0)
    b.decide("c2", sni="b.example.com", tenant="t1", now=1)
    with pytest.raises(tb.BrokerError) as excinfo:
        b.decide("c3", sni="c.example.com", tenant="t1", now=2)
    assert excinfo.value.code == "DECISION_CAPACITY_EXCEEDED"
    assert b.decision_for("c3") is None
    assert b.stats()["decisions"] == 2


def test_invalid_request_arguments():
    b = broker()
    with pytest.raises(tb.BrokerError) as excinfo:
        b.decide("", sni="a.example.com", tenant="t1")
    assert excinfo.value.code == "INVALID_REQUEST"
    with pytest.raises(tb.BrokerError) as excinfo:
        b.decide("c1", sni="", tenant="t1")
    assert excinfo.value.code == "INVALID_REQUEST"
    with pytest.raises(tb.BrokerError) as excinfo:
        b.decide("c1", sni="a.example.com", tenant="t1", transport="sctp")
    assert excinfo.value.code == "INVALID_REQUEST"
    with pytest.raises(tb.BrokerError) as excinfo:
        b.set_tenant_policy("t1", mode="monitor")
    assert excinfo.value.code == "INVALID_REQUEST"


def test_snapshot_restore_roundtrip():
    b = broker()
    b.set_tenant_policy("t1", mode="inspect",
                        pinned_hosts=("pinned.example.com",))
    b.decide("c1", sni="a.example.com", tenant="t1", now=0)
    b.decide("c2", sni="pinned.example.com", tenant="t1", now=0)
    snap = b.snapshot()
    assert {"version", "cas", "tenants", "decisions",
            "windows", "stats"} <= set(snap)
    assert snap["stats"]["decisions"] == 2
    snap["stats"]["decisions"] = 99
    assert b.stats()["decisions"] == 2
    restored = broker()
    restored.restore(snap)
    assert restored.decision_for("c1").action == "inspect"
    assert restored.decision_for("c2").action == "bypass"
    assert restored.expire_windows(now=900) == 1


def test_invalid_snapshot_is_rejected_without_side_effects():
    b = broker()
    b.decide("c1", sni="a.example.com", tenant="t1", now=0)
    with pytest.raises(tb.BrokerError) as excinfo:
        b.restore({"version": 1})
    assert excinfo.value.code == "BROKER_SNAPSHOT_INVALID"
    assert b.decision_for("c1").action == "inspect"
