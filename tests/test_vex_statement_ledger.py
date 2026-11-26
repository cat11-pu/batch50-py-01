import copy

import pytest

import vex_statement_ledger as vx

NOW = "2026-11-26T10:00:00+00:00"
SOON = "2026-11-26T10:30:00+00:00"
LATE = "2026-11-26T11:00:00+00:00"

CVE = "CVE-2026-1111"
PRODUCT = "payments"
COMPONENT = "libcrypto"


def ledger(**kwargs):
    return vx.VexStatementLedger(**kwargs)


def declare(obj, **overrides):
    kwargs = dict(product=PRODUCT, component=COMPONENT, vulnerability=CVE,
                  status="affected", now=NOW)
    kwargs.update(overrides)
    return obj.assert_statement(**kwargs)


def ask(obj, version, *, product=PRODUCT, component=COMPONENT, vulnerability=CVE):
    return obj.query(product=product, component=component, version=version,
                     vulnerability=vulnerability)


def test_not_affected_requires_justification_and_evidence():
    obj = ledger()
    with pytest.raises(vx.VexError) as exc:
        declare(obj, status="not_affected", evidence_ref="report://soc/2026/17")
    assert exc.value.code == "VEX_MISSING_JUSTIFICATION"

    with pytest.raises(vx.VexError) as exc:
        declare(obj, status="not_affected", justification="component_not_present")
    assert exc.value.code == "VEX_MISSING_EVIDENCE"

    record = declare(obj, status="not_affected", justification="component_not_present",
                     evidence_ref="report://soc/2026/17")
    assert record.statement_id == "VX-0001"
    assert record.status == "not_affected"
    assert record.justification == "component_not_present"
    assert record.evidence_ref == "report://soc/2026/17"
    assert record.revision == 1
    assert obj.stats()["statements"] == 1


def test_invalid_status_is_rejected():
    obj = ledger()
    for bad in ("unknown", "", "NOT_AFFECTED"):
        with pytest.raises(vx.VexError) as exc:
            declare(obj, status=bad)
        assert exc.value.code == "VEX_INVALID_STATUS"
    assert obj.stats()["statements"] == 0


def test_identical_range_requires_supersede():
    obj = ledger()
    first = declare(obj, introduced="0.0.0", until="2.0.0")
    with pytest.raises(vx.VexError) as exc:
        declare(obj, status="fixed", fixed="1.9.0", introduced="0.0.0", until="2.0.0")
    assert exc.value.code == "VEX_RANGE_CONFLICT"
    assert len(obj.export()) == 1
    assert obj.export()[0]["statement_id"] == first.statement_id


def test_supersede_creates_revision_and_keeps_history():
    obj = ledger()
    first = declare(obj, status="not_affected", justification="component_not_present",
                    evidence_ref="report://soc/2026/17", introduced="0.0.0", until="2.0.0")
    second = obj.supersede(first.statement_id, status="affected", now=SOON)
    assert second.statement_id != first.statement_id
    assert second.revision == 2
    assert second.status == "affected"
    assert second.component == COMPONENT
    assert second.until == "2.0.0"
    rows = obj.export()
    assert len(rows) == 1
    assert rows[0]["statement_id"] == second.statement_id
    assert len(obj.history()) == 2
    assert [row.statement_id for row in obj.history()] == ["VX-0001", "VX-0002"]
    assert obj.stats()["superseded"] == 1


def test_query_inside_range_returns_affected():
    obj = ledger()
    record = declare(obj, introduced="1.0.0", until="2.5.0")
    result = ask(obj, "1.9.0")
    assert result.verdict == "affected"
    assert result.statement_id == record.statement_id
    assert result.chain == (COMPONENT,)


def test_fixed_statement_compares_actual_version():
    obj = ledger()
    declare(obj, status="fixed", fixed="2.5.0", introduced="0.0.0", until="3.0.0")
    assert ask(obj, "2.4.9").verdict == "affected"
    assert ask(obj, "2.5.0").verdict == "fixed"
    assert ask(obj, "2.9.9").verdict == "fixed"


def test_version_outside_range_is_unknown():
    obj = ledger()
    declare(obj, introduced="1.0.0", until="2.5.0")
    result = ask(obj, "3.1.0")
    assert result.verdict == "unknown"
    assert result.statement_id is None
    assert result.chain == (COMPONENT,)


def test_evidence_expiry_downgrades_statement():
    obj = ledger()
    declare(obj, status="not_affected", justification="component_not_present",
            evidence_ref="report://soc/2026/17", introduced="0.0.0", until="2.0.0",
            expires_at=LATE)
    assert obj.expire(now=SOON) == 0
    assert ask(obj, "1.0.0").verdict == "not_affected"
    assert obj.expire(now=LATE) == 1
    result = ask(obj, "1.0.0")
    assert result.verdict == "under_investigation"
    assert obj.stats()["downgraded"] == 1


def test_export_is_sorted_and_repeatable():
    obj = ledger()
    declare(obj, product="storefront", component="zed", vulnerability="CVE-2026-3000")
    declare(obj, product="payments", component="libjson", vulnerability="CVE-2026-2000")
    declare(obj, product="payments", component="libcrypto", vulnerability="CVE-2026-1000")
    first = obj.export()
    second = obj.export()
    assert first == second
    assert [(row["product"], row["vulnerability"]) for row in first] == [
        ("payments", "CVE-2026-1000"),
        ("payments", "CVE-2026-2000"),
        ("storefront", "CVE-2026-3000"),
    ]
    assert set(first[0]) == {"statement_id", "product", "component", "vulnerability",
                             "status", "justification", "evidence_ref", "introduced",
                             "until", "fixed", "expires_at", "revision"}


def test_history_is_append_only():
    obj = ledger()
    first = declare(obj, component="libcrypto")
    declare(obj, component="libjson", vulnerability="CVE-2026-2222")
    obj.supersede(first.statement_id, status="fixed", fixed="2.1.0", now=SOON)
    entries = obj.history()
    assert len(entries) == 3
    assert [row.statement_id for row in entries] == ["VX-0001", "VX-0002", "VX-0003"]
    assert entries[0].status == "affected"
    assert entries[2].status == "fixed"


def test_dependency_propagation_takes_worst_verdict():
    obj = ledger()
    declare(obj, component="libcrypto", status="affected")
    declare(obj, component="libjson", status="fixed", fixed="2.0.0")
    obj.register_dependency("storefront", "checkout-ui", "libcrypto")
    obj.register_dependency("storefront", "checkout-ui", "libjson")
    result = obj.query(product="storefront", component="checkout-ui",
                       version="1.5.0", vulnerability=CVE)
    assert result.verdict == "affected"
    assert result.chain == ("checkout-ui", "libcrypto", "libjson")
    assert result.statement_id == "VX-0001"


def test_stats_track_operation_counts():
    obj = ledger()
    first = declare(obj, component="libcrypto")
    declare(obj, component="libjson", vulnerability="CVE-2026-2222")
    obj.supersede(first.statement_id, status="fixed", fixed="2.1.0", now=SOON)
    ask(obj, "1.0.0")
    ask(obj, "1.0.0", component="libjson")
    assert obj.stats() == {"statements": 3, "active": 2, "superseded": 1,
                           "downgraded": 0, "queries": 2}


def test_snapshot_roundtrips_and_rejects_malformed_state():
    obj = ledger()
    record = declare(obj, introduced="1.0.0", until="2.5.0")
    state = obj.snapshot()
    assert set(state) == {"version", "statements", "dependencies", "counters"}
    pristine = copy.deepcopy(state)

    state["statements"].clear()
    state["counters"]["statements"] = 99
    assert obj.stats()["statements"] == 1
    assert ask(obj, "1.5.0").verdict == "affected"

    clone = ledger()
    clone.restore(pristine)
    assert clone.stats()["statements"] == 1
    restored = ask(clone, "1.5.0")
    assert restored.verdict == "affected"
    assert restored.statement_id == record.statement_id

    for bad in (None, {}, {"version": 1, "statements": [], "dependencies": {}},
                {"version": 1, "statements": "nope", "dependencies": {},
                 "counters": {}}):
        with pytest.raises(vx.VexError) as exc:
            clone.restore(bad)
        assert exc.value.code == "VEX_SNAPSHOT_INVALID"
    assert ask(clone, "1.5.0").verdict == "affected"


def test_supersede_unknown_statement_is_rejected():
    obj = ledger()
    with pytest.raises(vx.VexError) as exc:
        obj.supersede("VX-9999", status="affected", now=NOW)
    assert exc.value.code == "VEX_STATEMENT_UNKNOWN"
    assert obj.stats()["statements"] == 0
    assert obj.history() == ()


def test_invalid_version_strings_are_rejected():
    obj = ledger()
    with pytest.raises(vx.VexError) as exc:
        declare(obj, introduced="1.x")
    assert exc.value.code == "VEX_INVALID_VERSION"

    declare(obj, introduced="1.0.0", until="2.5.0")
    with pytest.raises(vx.VexError) as exc:
        ask(obj, "latest")
    assert exc.value.code == "VEX_INVALID_VERSION"
