import copy
from datetime import datetime, timedelta

import pytest

import mfa_rollout_governor as mg

NOW = "2026-11-26T12:00:00+00:00"
DAY = 86400


def at(seconds):
    return (datetime.fromisoformat(NOW) + timedelta(seconds=seconds)).isoformat()


def governor(**kwargs):
    return mg.MfaRolloutGovernor(**kwargs)


def stage(store, *, stage=3, percent=100, tenant="t1", now=NOW):
    return store.set_stage(tenant, stage=stage, percent=percent, now=now)


def user_below(store, threshold, tenant="t1"):
    for index in range(500):
        user_id = f"u{index}"
        if store.bucket_of(tenant, user_id) < threshold:
            return user_id
    raise AssertionError("no user below threshold")


def test_set_stage_returns_configuration():
    store = governor()
    record = stage(store, stage=2, percent=50)
    assert record.tenant == "t1"
    assert record.stage == 2
    assert record.percent == 50
    assert record.updated_at == NOW
    assert store.stats()["stage_changes"] == 1


def test_set_stage_validates_ranges_and_tenant():
    store = governor()
    for bad_stage in [4, -1, 10]:
        with pytest.raises(mg.MfaRolloutError) as exc:
            stage(store, stage=bad_stage)
        assert exc.value.code == "MFA_BAD_STAGE"
    for bad_percent in [101, -1, 250]:
        with pytest.raises(mg.MfaRolloutError) as exc:
            stage(store, percent=bad_percent)
        assert exc.value.code == "MFA_BAD_PERCENT"
    with pytest.raises(mg.MfaRolloutError) as exc:
        store.set_stage("   ", stage=1, percent=10, now=NOW)
    assert exc.value.code == "MFA_INVALID_REQUEST"


def test_bucket_is_stable_and_bounded():
    first = governor()
    second = governor()
    for user_id in ["u1", "u2", "u3", "u4"]:
        low = first.bucket_of("t1", user_id)
        high = second.bucket_of("t1", user_id)
        assert low == high
        assert 0 <= low < 100


def test_zero_percent_leaves_everyone_out():
    store = governor()
    decision = store.evaluate("t1", "u1", now=NOW)
    assert decision.stage == 0
    assert decision.percent == 0
    assert decision.cohort is False
    assert decision.state == "not_required"
    assert decision.requires_mfa is False
    assert decision.grace_until is None
    assert decision.exemption_until is None


def test_full_percent_starts_one_day_grace():
    store = governor()
    stage(store, percent=100)
    decision = store.evaluate("t1", "u1", now=NOW)
    assert decision.bucket < 100
    assert decision.cohort is True
    assert decision.state == "grace"
    assert decision.requires_mfa is False
    assert decision.grace_until == at(DAY)
    assert decision.exemption_until is None


def test_grace_length_shrinks_with_percent():
    store = governor(base_grace_days=10)
    user_id = user_below(store, 40)
    stage(store, percent=40)
    decision = store.evaluate("t1", user_id, now=NOW)
    assert decision.cohort is True
    assert decision.state == "grace"
    assert decision.grace_until == at(6 * DAY)


def test_grace_expiry_forces_registration():
    store = governor()
    stage(store, percent=100)
    first = store.evaluate("t1", "u1", now=NOW)
    assert first.state == "grace"
    expired = store.evaluate("t1", "u1", now=at(DAY))
    assert expired.state == "enforced"
    assert expired.requires_mfa is True
    assert expired.grace_until == at(DAY)
    later = store.evaluate("t1", "u1", now=at(5 * DAY))
    assert later.state == "enforced"
    assert later.requires_mfa is True
    assert store.stats()["enforced"] == 1


def test_stage_rollback_keeps_forced_users():
    store = governor()
    stage(store, percent=100)
    store.evaluate("t1", "u1", now=NOW)
    assert store.evaluate("t1", "u1", now=at(DAY)).state == "enforced"
    stage(store, stage=0, percent=0, now=at(DAY + 1))
    after = store.evaluate("t1", "u1", now=at(DAY + 2))
    assert after.state == "enforced"
    assert after.requires_mfa is True
    assert after.cohort is False


def test_grant_grace_extends_from_current_deadline():
    store = governor()
    stage(store, percent=100)
    store.evaluate("t1", "u1", now=NOW)
    granted = store.grant_grace("t1", "u1", days=5, now=NOW)
    assert granted["user_id"] == "u1"
    assert granted["grace_until"] == at(6 * DAY)
    decision = store.evaluate("t1", "u1", now=at(10))
    assert decision.state == "grace"
    assert decision.grace_until == at(6 * DAY)
    with pytest.raises(mg.MfaRolloutError) as exc:
        store.grant_grace("t1", "u1", days=0, now=NOW)
    assert exc.value.code == "MFA_INVALID_REQUEST"
    stage(store, stage=0, percent=0, now=at(11))
    with pytest.raises(mg.MfaRolloutError) as exc:
        store.grant_grace("t1", "u1", days=3, now=at(12))
    assert exc.value.code == "MFA_STATE_INVALID"


def test_exemption_holds_until_deadline():
    store = governor()
    stage(store, percent=100)
    granted = store.exempt("t1", "u1", until=at(2 * DAY), reason="travel",
                           now=NOW)
    assert granted["user_id"] == "u1"
    assert granted["until"] == at(2 * DAY)
    assert granted["reason"] == "travel"
    decision = store.evaluate("t1", "u1", now=at(10))
    assert decision.state == "exempt"
    assert decision.requires_mfa is False
    assert decision.exemption_until == at(2 * DAY)
    assert store.evaluate("t1", "u1", now=at(2 * DAY - 1)).state == "exempt"


def test_revoke_exemption_returns_to_grace():
    store = governor()
    stage(store, percent=100)
    store.exempt("t1", "u1", until=at(2 * DAY), reason="travel", now=NOW)
    assert store.evaluate("t1", "u1", now=NOW).state == "exempt"
    assert store.revoke_exemption("t1", "u1") is True
    decision = store.evaluate("t1", "u1", now=at(10))
    assert decision.state == "grace"
    assert decision.exemption_until is None
    assert store.revoke_exemption("t1", "u1") is False
    assert store.revoke_exemption("t1", "nobody") is False


def test_exemption_requires_future_deadline_and_reason():
    store = governor()
    stage(store, percent=100)
    for until, reason in [(NOW, "travel"), (at(-1), "travel"),
                          (at(DAY), "   "), ("not-a-time", "travel")]:
        with pytest.raises(mg.MfaRolloutError) as exc:
            store.exempt("t1", "u1", until=until, reason=reason, now=NOW)
        assert exc.value.code == "MFA_INVALID_REQUEST"


def test_report_counts_states_without_extra_evaluations():
    store = governor()
    stage(store, percent=100)
    store.evaluate("t1", "u1", now=NOW)
    store.evaluate("t1", "u2", now=NOW)
    store.exempt("t1", "u3", until=at(2 * DAY), reason="travel", now=NOW)
    counts = store.report("t1", now=NOW)
    assert counts == {"not_required": 0, "grace": 2, "enforced": 0,
                      "exempt": 1, "satisfied": 0}
    assert store.stats()["evaluations"] == 2


def test_snapshot_is_detached_and_restore_roundtrips():
    store = governor()
    stage(store, percent=100)
    store.evaluate("t1", "u1", now=NOW)
    store.evaluate("t1", "u1", now=at(DAY))
    store.evaluate("t1", "u2", now=NOW)
    store.exempt("t1", "u3", until=at(3 * DAY), reason="travel", now=NOW)
    state = store.snapshot()
    pristine = copy.deepcopy(state)
    assert set(state) == {"version", "stages", "users", "grace",
                          "enrollments", "exemptions", "forced", "stats"}
    state["stages"].clear()
    state["forced"].clear()
    state["stats"]["enforced"] = 99
    assert store.stats()["enforced"] == 1
    assert store.evaluate("t1", "u1", now=at(2 * DAY)).state == "enforced"

    clone = governor()
    clone.restore(pristine)
    assert clone.evaluate("t1", "u1", now=at(2 * DAY)).state == "enforced"
    assert clone.evaluate("t1", "u2", now=at(10)).state == "grace"
    assert clone.evaluate("t1", "u3", now=at(10)).state == "exempt"
    assert clone.stats()["enforced"] == 1

    live = clone.snapshot()
    for bad in [None, {}, {"version": 2, "stages": {}, "users": [], "grace": {},
                           "enrollments": [], "exemptions": {}, "forced": [],
                           "stats": {}},
                {"version": 1, "stages": [], "users": [], "grace": {},
                 "enrollments": [], "exemptions": {}, "forced": [],
                 "stats": {}},
                {"version": 1, "stages": {}, "users": "nope", "grace": {},
                 "enrollments": [], "exemptions": {}, "forced": [],
                 "stats": {}},
                {"version": 1, "stages": {}, "users": [], "grace": [],
                 "enrollments": [], "exemptions": {}, "forced": [],
                 "stats": {}},
                {"version": 1, "stages": {}, "users": [], "grace": {},
                 "enrollments": [], "exemptions": {}, "forced": [],
                 "stats": {"evaluations": 1}}]:
        with pytest.raises(mg.MfaRolloutError) as exc:
            clone.restore(bad)
        assert exc.value.code == "MFA_SNAPSHOT_INVALID"
    assert clone.snapshot() == live


def test_stats_track_stage_grace_enforcement_and_exemptions():
    store = governor()
    stage(store, percent=100)
    store.evaluate("t1", "u1", now=NOW)
    store.evaluate("t1", "u2", now=NOW)
    store.evaluate("t1", "u3", now=NOW)
    store.evaluate("t1", "u1", now=at(DAY))
    store.exempt("t1", "u4", until=at(2 * DAY), reason="travel", now=NOW)
    store.evaluate("t1", "u4", now=at(10))
    assert store.stats() == {"evaluations": 5, "grace_started": 3,
                             "enforced": 1, "exemptions_granted": 1,
                             "stage_changes": 1}
