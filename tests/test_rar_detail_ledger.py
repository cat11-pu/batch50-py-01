import copy
import threading

import pytest

import rar_detail_ledger as rr

NOW = "2026-11-26T09:00:00+00:00"
SOON = "2026-11-26T09:10:00+00:00"
LATER = "2026-11-26T09:20:00+00:00"
PAY = {"type": "payment", "amount_max": 1000, "currency": "EUR", "payee": "acme"}
INFO = {"type": "account_info", "actions": ["write", "read", "read"]}
REGION = {"type": "region", "countries": ["FR", "DE"]}


def ledger(**kwargs):
    return rr.RarDetailLedger(**kwargs)


def submit(b, details, *, tenant="t1", client_id="c1", now=NOW):
    return b.submit(details, tenant=tenant, client_id=client_id, now=now)


def test_submit_normalizes_details_into_first_version():
    b = ledger()
    view = submit(b, [REGION, PAY, INFO])
    assert view.tenant == "t1"
    assert view.client_id == "c1"
    assert view.version == 1
    assert view.status == "active"
    assert view.created_at == NOW
    assert view.updated_at == NOW
    assert view.grant_id
    assert list(view.details) == [
        {"type": "account_info", "actions": ["read", "write"]},
        PAY,
        {"type": "region", "countries": ["DE", "FR"]},
    ]
    assert view.fingerprint.startswith("sha256:")
    assert b.grant_view(view.grant_id) == view
    assert b.stats()["submitted"] == 1


def test_validate_reports_typed_violations():
    b = ledger()
    cases = [
        ([{"type": "payment", "amount_max": 1000, "currency": "EUR"}], "payee"),
        ([{"type": "payment", "amount_max": 0, "currency": "EUR", "payee": "acme"}],
         "amount_max"),
        ([{"type": "payment", "amount_max": 100, "currency": "eur", "payee": "acme"}],
         "currency"),
        ([{"type": "account_info", "actions": []}], "actions"),
        ([{"type": "account_info", "actions": ["sudo"]}], "actions"),
        ([{"type": "region", "countries": ["de"]}], "countries"),
        ([{"type": "invoice", "amount_max": 1}], "type"),
    ]
    for details, field in cases:
        with pytest.raises(rr.RarError) as exc:
            b.validate(details)
        assert exc.value.code == "RAR_INVALID_DETAIL"
        assert exc.value.detail == field
    assert b.stats()["submitted"] == 0


def test_submit_rejects_malformed_request():
    b = ledger()
    with pytest.raises(rr.RarError) as exc:
        b.submit([], tenant="t1", client_id="c1", now=NOW)
    assert exc.value.code == "RAR_INVALID_DETAIL"
    assert exc.value.detail == "details"
    with pytest.raises(rr.RarError) as exc:
        b.submit("nope", tenant="t1", client_id="c1", now=NOW)
    assert exc.value.code == "RAR_INVALID_REQUEST"
    with pytest.raises(rr.RarError) as exc:
        b.submit([PAY], tenant="  ", client_id="c1", now=NOW)
    assert exc.value.code == "RAR_INVALID_REQUEST"
    with pytest.raises(rr.RarError) as exc:
        b.submit([PAY], tenant="t1", client_id="", now=NOW)
    assert exc.value.code == "RAR_INVALID_REQUEST"
    assert b.stats()["submitted"] == 0


def test_submit_enforces_count_and_client_capacity():
    b = ledger(max_details_per_grant=2)
    with pytest.raises(rr.RarError) as exc:
        submit(b, [PAY, INFO, REGION])
    assert exc.value.code == "RAR_CAPACITY_EXCEEDED"
    assert exc.value.detail == "details"
    assert b.stats()["submitted"] == 0

    c = ledger(max_grants_per_client=1)
    submit(c, [PAY])
    with pytest.raises(rr.RarError) as exc:
        submit(c, [INFO])
    assert exc.value.code == "RAR_CAPACITY_EXCEEDED"
    assert exc.value.detail == "client_id"
    assert c.stats()["submitted"] == 1


def test_validate_does_not_mutate_the_caller_list():
    b = ledger()
    source = [REGION, INFO, PAY]
    original = copy.deepcopy(source)
    first = b.validate(source)
    assert [entry["type"] for entry in first] == ["account_info", "payment", "region"]
    assert first[0]["actions"] == ["read", "write"]
    assert first[2]["countries"] == ["DE", "FR"]
    assert source == original
    assert b.validate(source) == first


def test_fingerprint_is_stable_and_changes_with_limits():
    b = ledger()
    fingerprint = b.fingerprint([PAY, INFO])
    assert fingerprint.startswith("sha256:")
    assert len(fingerprint) == len("sha256:") + 64
    assert fingerprint == b.fingerprint([PAY, INFO])
    assert b.fingerprint(b.validate([PAY, INFO])) == fingerprint
    raised = dict(PAY, amount_max=2000)
    assert b.fingerprint([raised, INFO]) != fingerprint
    with pytest.raises(rr.RarError) as exc:
        b.fingerprint([{"type": "payment"}])
    assert exc.value.code == "RAR_INVALID_DETAIL"


def test_display_lines_render_canonical_summary():
    b = ledger()
    assert b.display_lines([PAY, INFO, REGION]) == (
        "account_info: read, write",
        "payment: 10.00 EUR -> acme",
        "region: DE, FR",
    )
    assert b.display_lines([]) == ()


def test_merge_unions_details_and_bumps_version_once():
    b = ledger()
    view = submit(b, [INFO])
    merged = b.merge(view.grant_id, [PAY], now=SOON)
    assert merged.version == 2
    assert merged.created_at == NOW
    assert merged.updated_at == SOON
    assert [entry["type"] for entry in merged.details] == ["account_info", "payment"]
    assert merged.fingerprint == b.fingerprint([INFO, PAY])

    deduped = b.merge(view.grant_id, [PAY, dict(INFO)], now=LATER)
    assert deduped.version == 2
    assert deduped.updated_at == SOON
    assert deduped.fingerprint == merged.fingerprint
    assert b.stats()["merged"] == 1
    assert b.stats()["deduped"] == 1


def test_merge_rejects_unknown_and_revoked_grants():
    b = ledger()
    with pytest.raises(rr.RarError) as exc:
        b.merge("rar-9999", [PAY], now=SOON)
    assert exc.value.code == "RAR_UNKNOWN_GRANT"
    view = submit(b, [PAY])
    assert b.revoke(view.grant_id) is True
    with pytest.raises(rr.RarError) as exc:
        b.merge(view.grant_id, [INFO], now=SOON)
    assert exc.value.code == "RAR_GRANT_REVOKED"


def test_compare_classifies_narrower_same_and_different():
    b = ledger()
    view = submit(b, [PAY, INFO])
    assert b.compare(view.grant_id, [PAY, INFO]) == "same"
    narrow = [dict(PAY, amount_max=500), {"type": "account_info", "actions": ["read"]}]
    assert b.compare(view.grant_id, narrow) == "narrower"
    moved = [dict(PAY, amount_max=500, payee="other")]
    assert b.compare(view.grant_id, moved) == "different"
    assert b.grant_view(view.grant_id).version == 1
    with pytest.raises(rr.RarError) as exc:
        b.compare("rar-9999", [PAY])
    assert exc.value.code == "RAR_UNKNOWN_GRANT"


def test_refresh_keeps_same_set_and_advances_narrowed_one():
    b = ledger()
    view = submit(b, [PAY])
    same = b.refresh(view.grant_id, [PAY], now=SOON)
    assert same.version == 1
    assert same.updated_at == NOW
    assert same.fingerprint == view.fingerprint

    narrowed_details = [dict(PAY, amount_max=400)]
    narrowed = b.refresh(view.grant_id, narrowed_details, now=LATER)
    assert narrowed.version == 2
    assert narrowed.updated_at == LATER
    assert narrowed.details == (dict(PAY, amount_max=400),)
    assert narrowed.fingerprint == b.fingerprint(narrowed_details)
    assert b.stats()["refreshed"] == 1
    assert b.grant_view(view.grant_id).version == 2


def test_refresh_rejects_unknown_revoked_and_expired_grants():
    b = ledger()
    with pytest.raises(rr.RarError) as exc:
        b.refresh("rar-9999", [PAY], now=SOON)
    assert exc.value.code == "RAR_UNKNOWN_GRANT"

    revoked = submit(b, [PAY])
    b.revoke(revoked.grant_id)
    with pytest.raises(rr.RarError) as exc:
        b.refresh(revoked.grant_id, [PAY], now=SOON)
    assert exc.value.code == "RAR_GRANT_REVOKED"

    c = ledger(grant_ttl=60)
    expiring = submit(c, [PAY])
    assert c.sweep_expired(now=NOW) == 0
    assert c.sweep_expired(now=SOON) == 1
    assert c.grant_view(expiring.grant_id).status == "expired"
    with pytest.raises(rr.RarError) as exc:
        c.refresh(expiring.grant_id, [PAY], now=SOON)
    assert exc.value.code == "RAR_GRANT_EXPIRED"
    assert c.stats()["expired"] == 1


def test_concurrent_merge_bumps_version_once():
    b = ledger()
    view = submit(b, [INFO])
    results = []
    failures = []
    barrier = threading.Barrier(10)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(b.merge(view.grant_id, [PAY], now=SOON))
        except Exception as exc:  # noqa: BLE001 - reported through failures
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert len(results) == 10
    final = b.grant_view(view.grant_id)
    assert final.version == 2
    assert final.fingerprint == b.fingerprint([INFO, PAY])
    assert all(row.fingerprint == final.fingerprint for row in results)
    assert b.stats()["merged"] == 1
    assert b.stats()["deduped"] == 9


def test_revoke_is_idempotent_and_frees_client_capacity():
    b = ledger()
    view = submit(b, [PAY])
    assert b.revoke(view.grant_id) is True
    assert b.revoke(view.grant_id) is False
    assert b.grant_view(view.grant_id).status == "revoked"
    assert b.stats()["revoked"] == 1
    with pytest.raises(rr.RarError) as exc:
        b.revoke("rar-9999")
    assert exc.value.code == "RAR_UNKNOWN_GRANT"

    tight = ledger(max_grants_per_client=1)
    first = submit(tight, [PAY])
    with pytest.raises(rr.RarError) as exc:
        submit(tight, [INFO])
    assert exc.value.code == "RAR_CAPACITY_EXCEEDED"
    tight.revoke(first.grant_id)
    submit(tight, [INFO])
    assert tight.stats()["revoked"] == 1


def test_snapshot_roundtrip_and_malformed_rejection():
    b = ledger()
    view = submit(b, [PAY, INFO])
    b.merge(view.grant_id, [REGION], now=SOON)
    state = b.snapshot()
    assert set(state) == {"version", "grants", "stats"}
    pristine = copy.deepcopy(state)
    state["grants"].clear()
    state["stats"]["submitted"] = 99
    assert b.stats()["submitted"] == 1
    assert b.grant_view(view.grant_id).version == 2

    clone = ledger()
    clone.restore(pristine)
    assert clone.stats()["submitted"] == 1
    restored = clone.grant_view(view.grant_id)
    assert restored.version == 2
    assert restored.fingerprint == b.fingerprint([PAY, INFO, REGION])
    assert [entry["type"] for entry in restored.details] == [
        "account_info", "payment", "region"]

    bad_snapshots = [
        None,
        {},
        {"version": 5, "grants": [], "stats": {}},
        {"version": 1, "grants": {}, "stats": {}},
        {"version": 1, "grants": [], "stats": []},
    ]
    for snapshot in bad_snapshots:
        with pytest.raises(rr.RarError) as exc:
            clone.restore(snapshot)
        assert exc.value.code == "RAR_SNAPSHOT_INVALID"
    assert clone.grant_view(view.grant_id).version == 2
