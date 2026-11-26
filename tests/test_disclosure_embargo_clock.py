import copy

import pytest

import disclosure_embargo_clock as ec

REPORTED = "2026-11-23T09:00:00+00:00"
ACK = "2026-11-27T10:00:00+00:00"
MONDAY = "2026-11-30T09:00:00+00:00"
SATURDAY = "2026-11-28T10:00:00+00:00"


def clock(**kwargs):
    return ec.DisclosureEmbargoClock(**kwargs)


def opened(instance, advisory_id="ADV-1", *, window=2, product="edge-gateway"):
    return instance.open(advisory_id, product=product, fix_window_days=window,
                         reported_at=REPORTED)


def acknowledged(instance, advisory_id="ADV-1"):
    opened(instance, advisory_id)
    return instance.ack(advisory_id, now=ACK)


def test_open_creates_reported_entry_and_counts():
    instance = clock()
    state = opened(instance)
    assert isinstance(state, ec.AdvisoryState)
    assert (state.advisory_id, state.product, state.state) == (
        "ADV-1", "edge-gateway", "reported")
    assert state.reported_at == REPORTED
    assert state.acknowledged_at is None
    assert state.fix_due is None
    assert state.lifted_at is None
    assert state.extensions_used == 0
    assert state.extension_days == 0
    assert state.public_approved is False
    assert state.public_actor is None
    assert instance.stats() == {"opened": 1, "acknowledged": 0, "extended": 0,
                                "lifted": 0, "extension_days": 0}


def test_open_rejects_duplicates_and_bad_window():
    instance = clock()
    opened(instance)
    with pytest.raises(ec.EmbargoError) as exc:
        opened(instance)
    assert exc.value.code == "EMBARGO_DUPLICATE"
    for index, window in enumerate((0, 181, "30")):
        with pytest.raises(ec.EmbargoError) as exc:
            opened(instance, f"ADV-{index}", window=window)
        assert exc.value.code == "EMBARGO_BAD_WINDOW"
    assert instance.state_of("ADV-1").fix_due is None
    assert instance.stats()["opened"] == 1


def test_open_rejects_empty_fields():
    instance = clock()
    cases = [("", "edge-gateway"), ("ADV-9", "   ")]
    for advisory_id, product in cases:
        with pytest.raises(ec.EmbargoError) as exc:
            instance.open(advisory_id, product=product, fix_window_days=2,
                          reported_at=REPORTED)
        assert exc.value.code == "EMBARGO_BAD_REQUEST"
    assert instance.stats()["opened"] == 0


def test_ack_sets_due_date_skipping_weekends():
    instance = clock()
    opened(instance, window=2)
    state = instance.ack("ADV-1", now=ACK)
    assert state.state == "acknowledged"
    assert state.acknowledged_at == ACK
    assert state.fix_due == "2026-12-01"
    assert instance.stats()["acknowledged"] == 1


def test_ack_skips_registered_holidays():
    instance = clock()
    assert instance.set_holidays(["2026-11-30"]) == 1
    assert instance.set_holidays(["2026-11-30"]) == 1
    assert instance.is_business_day("2026-11-27") is True
    assert instance.is_business_day("2026-11-29") is False
    assert instance.is_business_day("2026-11-30") is False
    opened(instance, window=2)
    state = instance.ack("ADV-1", now=ACK)
    assert state.fix_due == "2026-12-02"


def test_ack_requires_reported_state():
    instance = clock()
    acknowledged(instance)
    with pytest.raises(ec.EmbargoError) as exc:
        instance.ack("ADV-1", now=MONDAY)
    assert exc.value.code == "EMBARGO_BAD_STATE"
    assert instance.state_of("ADV-1").acknowledged_at == ACK
    with pytest.raises(ec.EmbargoError) as exc:
        instance.ack("ADV-404", now=MONDAY)
    assert exc.value.code == "EMBARGO_UNKNOWN"
    assert instance.stats()["acknowledged"] == 1


def test_extend_requires_acknowledged_state():
    instance = clock()
    opened(instance)
    with pytest.raises(ec.EmbargoError) as exc:
        instance.extend("ADV-1", days=3, now=MONDAY)
    assert exc.value.code == "EMBARGO_BAD_STATE"
    state = instance.state_of("ADV-1")
    assert state.fix_due is None
    assert state.extensions_used == 0
    assert instance.stats()["extended"] == 0


def test_extend_moves_due_date_and_tracks_usage():
    instance = clock()
    acknowledged(instance)
    out = instance.extend("ADV-1", days=3, now=MONDAY)
    assert out["advisory_id"] == "ADV-1"
    assert out["granted_days"] == 3
    assert out["extension_days"] == 3
    assert out["extensions_used"] == 1
    assert out["fix_due"] == "2026-12-04"
    assert out["truncated"] is False
    state = instance.state_of("ADV-1")
    assert state.extensions_used == 1
    assert state.extension_days == 3
    assert state.fix_due == "2026-12-04"
    assert instance.days_remaining(
        "ADV-1", now="2026-12-01T00:00:00+00:00") == 3
    assert instance.stats()["extended"] == 1
    assert instance.stats()["extension_days"] == 3


def test_extend_rejects_non_positive_days():
    instance = clock()
    acknowledged(instance)
    for days in (0, -4, "2"):
        with pytest.raises(ec.EmbargoError) as exc:
            instance.extend("ADV-1", days=days, now=MONDAY)
        assert exc.value.code == "EMBARGO_BAD_REQUEST"
    state = instance.state_of("ADV-1")
    assert state.extensions_used == 0
    assert state.extension_days == 0
    assert state.fix_due == "2026-12-01"


def test_request_public_records_agreement_without_lifting():
    instance = clock()
    acknowledged(instance)
    out = instance.request_public("ADV-1", actor="vendor-poc", now=SATURDAY)
    assert out["advisory_id"] == "ADV-1"
    assert out["public_approved"] is True
    assert out["actor"] == "vendor-poc"
    assert out["at"] == SATURDAY
    state = instance.state_of("ADV-1")
    assert state.public_approved is True
    assert state.public_actor == "vendor-poc"
    assert state.state == "acknowledged"


def test_lift_after_due_date_is_allowed():
    instance = clock()
    acknowledged(instance)
    state = instance.lift("ADV-1", now="2026-12-01T08:00:00+00:00")
    assert state.state == "embargo_lifted"
    assert state.lifted_at == "2026-12-01T08:00:00+00:00"
    assert instance.stats()["lifted"] == 1


def test_request_public_then_lift_before_due():
    instance = clock()
    acknowledged(instance)
    instance.request_public("ADV-1", actor="vendor-poc", now=SATURDAY)
    state = instance.lift("ADV-1", now="2026-11-28T11:00:00+00:00")
    assert state.state == "embargo_lifted"
    assert state.lifted_at == "2026-11-28T11:00:00+00:00"
    assert state.public_approved is True


def test_lift_gate_rejects_early_request_and_history_order():
    instance = clock()
    acknowledged(instance)
    with pytest.raises(ec.EmbargoError) as exc:
        instance.lift("ADV-1", now=SATURDAY)
    assert exc.value.code == "EMBARGO_NOT_ELIGIBLE"
    with pytest.raises(ec.EmbargoError) as exc:
        instance.state_of("ADV-404")
    assert exc.value.code == "EMBARGO_UNKNOWN"
    instance.extend("ADV-1", days=2, now=MONDAY)
    rows = instance.history("ADV-1")
    assert [row["action"] for row in rows] == ["ack", "extend"]
    assert rows[0]["at"] == ACK
    assert rows[1]["detail"]["granted_days"] == 2


def test_snapshot_is_detached_and_restore_roundtrips():
    instance = clock()
    instance.set_holidays(["2026-11-30"])
    acknowledged(instance)
    instance.extend("ADV-1", days=3, now=MONDAY)
    state = instance.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "advisories", "holidays", "stats"}

    state["advisories"].clear()
    state["holidays"].clear()
    state["stats"]["extended"] = 99
    assert instance.state_of("ADV-1").extensions_used == 1
    assert instance.is_business_day("2026-11-30") is False

    clone = clock()
    clone.restore(pristine)
    restored = clone.state_of("ADV-1")
    assert restored.fix_due == "2026-12-04"
    assert restored.extensions_used == 1
    assert restored.extension_days == 3
    assert clone.is_business_day("2026-11-30") is False
    assert clone.stats() == instance.stats()


def test_restore_rejects_malformed_state_without_touching_live():
    instance = clock()
    acknowledged(instance)
    full_stats = {"opened": 1, "acknowledged": 1, "extended": 0,
                  "lifted": 0, "extension_days": 0}
    bad_states = [
        None,
        {},
        {"version": 2, "advisories": [], "holidays": [], "stats": full_stats},
        {"version": 1, "advisories": "nope", "holidays": [], "stats": full_stats},
        {"version": 1, "advisories": [], "holidays": {}, "stats": full_stats},
        {"version": 1, "advisories": [], "holidays": [], "stats": {"opened": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(ec.EmbargoError) as exc:
            instance.restore(bad)
        assert exc.value.code == "EMBARGO_SNAPSHOT_INVALID"
    assert instance.state_of("ADV-1").state == "acknowledged"
    assert instance.stats()["acknowledged"] == 1
