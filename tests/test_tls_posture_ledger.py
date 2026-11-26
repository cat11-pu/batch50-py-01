import pytest

import tls_posture_ledger as tl

FAR = 2000000000
DAY = 86400


def ledger(**kwargs):
    return tl.TlsPostureLedger(**kwargs)


def ep(endpoint, protocols, suites, issuer="issuer-a", not_after=FAR):
    return {"endpoint": endpoint, "protocols": list(protocols),
            "suites": list(suites), "cert_issuer": issuer,
            "cert_not_after": not_after}


def base_endpoints():
    return [
        ep("api.example:443", ["TLSv1.2", "TLSv1.3"], ["A", "B"]),
        ep("mail.example:465", ["TLSv1.2"], ["C"]),
    ]


def test_record_first_round_and_report_endpoint_state():
    app = ledger()
    out = app.record_scan(1, endpoints=base_endpoints(), now=1000)
    assert out["round"] == 1
    assert out["endpoints"] == 2
    assert out["pruned"] == 0

    summary = app.summary(1)
    assert summary["round"] == 1
    assert summary["endpoints"] == 2
    assert summary["protocols"] == {"TLSv1.0": 0, "TLSv1.1": 0,
                                    "TLSv1.2": 2, "TLSv1.3": 1}
    assert summary["open_regressions"] == 0
    assert summary["waived_regressions"] == 0

    state = app.endpoint_state("api.example:443")
    assert state["protocols"] == ("TLSv1.2", "TLSv1.3")
    assert state["suites"] == ("A", "B")
    assert state["cert_issuer"] == "issuer-a"
    assert state["cert_not_after"] == FAR
    assert state["last_round"] == 1
    assert state["unreachable"] is False


def test_record_scan_rejects_malformed_endpoints():
    app = ledger()
    bad_scans = [
        (0, base_endpoints()),
        (1, []),
        (1, [ep("api.example:443", ["TLSv1.2"], ["A"]),
             ep("api.example:443", ["TLSv1.2"], ["B"])]),
        (1, [ep("api.example:443", ["SSLv3"], ["A"])]),
        (1, [ep("api.example:443", [], ["A"])]),
        (1, [ep("api.example:443", ["TLSv1.2"], [])]),
        (1, [ep("api.example:443", ["TLSv1.2"], ["A"], not_after=0)]),
        (1, [{"endpoint": "api.example:443"}]),
    ]
    for round_no, endpoints in bad_scans:
        with pytest.raises(tl.LedgerError) as exc:
            app.record_scan(round_no, endpoints=endpoints, now=1000)
        assert exc.value.code == "TLS_INVALID_SCAN"
    assert app.history() == ()


def test_rounds_must_strictly_increase():
    app = ledger()
    app.record_scan(5, endpoints=base_endpoints(), now=1000)
    for round_no in (5, 3):
        with pytest.raises(tl.LedgerError) as exc:
            app.record_scan(round_no, endpoints=base_endpoints(), now=1001)
        assert exc.value.code == "TLS_ROUND_ORDER"
    assert app.record_scan(6, endpoints=base_endpoints(), now=1002)["round"] == 6
    assert app.history() == (5, 6)


def test_unchanged_round_produces_no_changes_or_regressions():
    app = ledger()
    app.record_scan(1, endpoints=base_endpoints(), now=1000)
    app.record_scan(2, endpoints=base_endpoints(), now=2000)
    first = app.diff_round(1)
    assert first["previous"] is None
    assert first["changes"] == ()
    second = app.diff_round(2)
    assert second["previous"] == 1
    assert second["changes"] == ()
    assert app.regress(2) == ()

    app.record_scan(3, endpoints=base_endpoints(), now=3000)
    assert app.regress(3) == ()
    assert app.regressions() == ()


def test_protocol_downgrade_opens_a_regression():
    app = ledger()
    app.record_scan(1, endpoints=base_endpoints(), now=1000)
    changed = [
        ep("api.example:443", ["TLSv1.3"], ["A", "B"]),
        ep("mail.example:465", ["TLSv1.2"], ["C"]),
    ]
    app.record_scan(2, endpoints=changed, now=2000)
    changes = app.diff_round(2)["changes"]
    assert {"endpoint": "api.example:443", "kind": "protocol_removed",
            "detail": ("TLSv1.2",)} in changes

    rows = app.regress(2)
    assert len(rows) == 1
    row = rows[0]
    assert row["regression_id"] == "REG-0001"
    assert row["endpoint"] == "api.example:443"
    assert row["kind"] == tl.KIND_DOWNGRADE
    assert row["state"] == tl.STATE_OPEN
    assert row["opened_round"] == 2
    assert row["detail"] == ("TLSv1.2",)


def test_removed_suites_open_a_regression():
    app = ledger()
    app.record_scan(1, endpoints=[ep("api.example:443", ["TLSv1.3"],
                                     ["A", "B", "C"])], now=1000)
    app.record_scan(2, endpoints=[ep("api.example:443", ["TLSv1.3"], ["A"])],
                    now=2000)
    rows = [row for row in app.regress(2) if row["kind"] == tl.KIND_SUITE_REMOVED]
    assert len(rows) == 1
    assert rows[0]["detail"] == ("B", "C")
    assert rows[0]["regression_id"] == "REG-0001"


def test_certificate_issuer_change_is_tracked():
    app = ledger()
    app.record_scan(1, endpoints=[ep("api.example:443", ["TLSv1.3"], ["A"],
                                     issuer="issuer-a")], now=1000)
    app.record_scan(2, endpoints=[ep("api.example:443", ["TLSv1.3"], ["A"],
                                     issuer="issuer-b")], now=2000)
    changes = app.diff_round(2)["changes"]
    assert {"endpoint": "api.example:443", "kind": tl.KIND_ISSUER_CHANGED,
            "detail": {"from": "issuer-a", "to": "issuer-b"}} in changes
    rows = app.regress(2)
    assert len(rows) == 1
    assert rows[0]["kind"] == tl.KIND_ISSUER_CHANGED
    assert rows[0]["detail"] == {"from": "issuer-a", "to": "issuer-b"}


def test_certificate_nearing_expiry_is_flagged_once():
    app = ledger(cert_warning_days=30)
    now = 1_700_000_000
    endpoints = [
        ep("soon.example:443", ["TLSv1.3"], ["A"], not_after=now + 10 * DAY),
        ep("later.example:443", ["TLSv1.3"], ["A"], not_after=now + 400 * DAY),
    ]
    app.record_scan(1, endpoints=endpoints, now=now)
    rows = app.regress(1)
    assert len(rows) == 1
    assert rows[0]["endpoint"] == "soon.example:443"
    assert rows[0]["kind"] == tl.KIND_CERT_EXPIRING
    assert rows[0]["detail"] == {"not_after": now + 10 * DAY, "days_left": 10}


def test_additions_are_reported_without_regressions_and_resolve_works():
    app = ledger()
    app.record_scan(1, endpoints=[ep("api.example:443", ["TLSv1.2"], ["A"])],
                    now=1000)
    app.record_scan(2, endpoints=[ep("api.example:443",
                                     ["TLSv1.2", "TLSv1.3"], ["A", "B"])],
                    now=2000)
    kinds = [change["kind"] for change in app.diff_round(2)["changes"]]
    assert kinds == ["protocol_added", "suite_added"]
    assert app.regress(2) == ()

    app.record_scan(3, endpoints=[ep("api.example:443", ["TLSv1.2"], ["A"])],
                    now=3000)
    rows = app.regress(3)
    assert [row["kind"] for row in rows] == [tl.KIND_DOWNGRADE]
    regression_id = rows[0]["regression_id"]
    resolved = app.resolve(regression_id, now=3100)
    assert resolved["state"] == tl.STATE_RESOLVED
    assert resolved["resolved_at"] == 3100
    assert app.regressions(state=tl.STATE_OPEN) == ()
    assert [row["regression_id"] for row in
            app.regressions(state=tl.STATE_RESOLVED)] == [regression_id]

    with pytest.raises(tl.LedgerError) as exc:
        app.resolve("REG-9999", now=3200)
    assert exc.value.code == "TLS_REGRESSION_UNKNOWN"
    with pytest.raises(tl.LedgerError) as exc:
        app.resolve(regression_id, now=3200)
    assert exc.value.code == "TLS_REGRESSION_STATE"


def test_regressions_are_numbered_in_order_and_filterable():
    app = ledger()
    app.record_scan(1, endpoints=[
        ep("api.example:443", ["TLSv1.2", "TLSv1.3"], ["A", "B"]),
        ep("mail.example:465", ["TLSv1.2"], ["C"]),
    ], now=1000)
    app.record_scan(2, endpoints=[
        ep("api.example:443", ["TLSv1.3"], ["A"]),
        ep("mail.example:465", ["TLSv1.2"], ["D"]),
    ], now=2000)
    rows = app.regress(2)
    assert [row["regression_id"] for row in rows] == ["REG-0001", "REG-0002"]
    assert [row["kind"] for row in rows] == [tl.KIND_DOWNGRADE,
                                             tl.KIND_SUITE_REMOVED]
    assert [row["endpoint"] for row in rows] == ["api.example:443",
                                                 "mail.example:465"]
    assert len(app.regressions()) == 2
    assert len(app.regressions(state=tl.STATE_OPEN)) == 2


def test_waive_validates_window_and_reason():
    app = ledger()
    app.record_scan(1, endpoints=[ep("api.example:443",
                                     ["TLSv1.2", "TLSv1.3"], ["A"])], now=1000)
    app.record_scan(2, endpoints=[ep("api.example:443", ["TLSv1.3"], ["A"])],
                    now=2000)
    regression_id = app.regress(2)[0]["regression_id"]

    with pytest.raises(tl.LedgerError) as exc:
        app.waive("REG-9999", until=5000, reason="ok", now=2500)
    assert exc.value.code == "TLS_REGRESSION_UNKNOWN"
    with pytest.raises(tl.LedgerError) as exc:
        app.waive(regression_id, until=5000, reason="   ", now=2500)
    assert exc.value.code == "TLS_BAD_WAIVER"
    with pytest.raises(tl.LedgerError) as exc:
        app.waive(regression_id, until=2500, reason="ok", now=2500)
    assert exc.value.code == "TLS_BAD_WAIVER"

    waived = app.waive(regression_id, until=5000,
                       reason="change_window", now=2600)
    assert waived["state"] == tl.STATE_WAIVED
    assert waived["waived_until"] == 5000
    assert waived["waive_reason"] == "change_window"
    assert [row["regression_id"] for row in
            app.regressions(state=tl.STATE_WAIVED)] == [regression_id]

    with pytest.raises(tl.LedgerError) as exc:
        app.waive(regression_id, until=6000, reason="again", now=2700)
    assert exc.value.code == "TLS_BAD_WAIVER"


def test_history_is_trimmed_to_the_configured_rounds():
    app = ledger(history_rounds=2)
    for round_no in (1, 2):
        out = app.record_scan(round_no, endpoints=base_endpoints(),
                              now=round_no * 1000)
        assert out["pruned"] == 0
    out = app.record_scan(3, endpoints=base_endpoints(), now=3000)
    assert out["pruned"] == 1
    assert app.history() == (2, 3)
    assert app.history(endpoint="api.example:443") == (2, 3)
    assert app.history(endpoint="never.example:443") == ()
    assert app.diff_round(2)["previous"] is None
    with pytest.raises(tl.LedgerError) as exc:
        app.summary(1)
    assert exc.value.code == "TLS_ROUND_UNKNOWN"


def test_unknown_rounds_and_endpoints_are_refused():
    app = ledger()
    app.record_scan(1, endpoints=base_endpoints(), now=1000)
    for call in (app.diff_round, app.regress, app.summary):
        with pytest.raises(tl.LedgerError) as exc:
            call(99)
        assert exc.value.code == "TLS_ROUND_UNKNOWN"
    with pytest.raises(tl.LedgerError) as exc:
        app.endpoint_state("nope.example:443")
    assert exc.value.code == "TLS_ENDPOINT_UNKNOWN"
    assert app.sweep(now=2000) == {"reopened": 0, "pruned_rounds": 0}


def test_snapshot_is_detached_and_restore_roundtrips():
    app = ledger()
    app.record_scan(1, endpoints=base_endpoints(), now=1000)
    app.record_scan(2, endpoints=[
        ep("api.example:443", ["TLSv1.3"], ["A", "B"]),
        ep("mail.example:465", ["TLSv1.2"], ["C"]),
    ], now=2000)
    regression_id = app.regress(2)[0]["regression_id"]
    app.waive(regression_id, until=9000, reason="vendor_fix", now=2100)

    state = app.snapshot()
    assert set(state) == {"format", "rounds", "regressions", "counters"}
    state["rounds"].clear()
    state["regressions"].clear()
    assert app.history() == (1, 2)
    assert len(app.regressions()) == 1

    clone = ledger()
    clone.restore(app.snapshot())
    assert clone.history() == (1, 2)
    assert clone.regressions(state=tl.STATE_WAIVED)[0]["waived_until"] == 9000
    assert clone.endpoint_state("api.example:443")["protocols"] == ("TLSv1.3",)
    assert clone.stats() == {"rounds": 2, "endpoints": 2, "regressions": 1,
                             "waived": 1, "reopened": 0}


def test_restore_rejects_malformed_state_without_touching_live_data():
    app = ledger()
    app.record_scan(1, endpoints=base_endpoints(), now=1000)
    good = app.snapshot()
    bad_states = [
        None,
        {},
        dict(good, format="other"),
        dict(good, rounds=[]),
        dict(good, regressions="nope"),
        dict(good, counters={}),
    ]
    for bad in bad_states:
        with pytest.raises(tl.LedgerError) as exc:
            app.restore(bad)
        assert exc.value.code == "TLS_SNAPSHOT_INVALID"
    assert app.history() == (1,)
    assert app.endpoint_state("api.example:443")["last_round"] == 1
