import copy

import pytest

import regex_dos_guard as rg

NOW = "2026-11-26T10:00:00+00:00"
SOON = "2026-11-26T10:05:00+00:00"
LATE = "2026-11-26T10:11:00+00:00"


def guard(**kwargs):
    return rg.RegexDosGuard(**kwargs)


def test_register_assigns_sequential_ids_and_dedupes_identical():
    obj = guard()
    first = obj.register("(a+)+$")
    second = obj.register("(a+)+$")
    third = obj.register("^[a-z]+$")
    assert first.rule_id == "R-0001"
    assert second.rule_id == "R-0001"
    assert third.rule_id == "R-0002"
    assert len(first.fingerprint) == 16
    assert first.fingerprint == second.fingerprint
    assert obj.stats()["registered"] == 2
    assert obj.stats()["deduped"] == 1


def test_register_rejects_empty_or_non_string_pattern():
    obj = guard()
    for bad in ("", None, 17):
        with pytest.raises(rg.RegexSafetyError) as exc:
            obj.register(bad)
        assert exc.value.code == "REGEX_INVALID_REQUEST"
    assert obj.stats()["registered"] == 0


def test_nested_quantifier_is_scored_high():
    analysis = guard().analyze("(a+)+$")
    assert analysis.score == 70
    assert analysis.findings == ("NESTED_QUANTIFIER",)
    assert analysis.verdict == "high"


def test_plain_character_class_pattern_scores_zero():
    analysis = guard().analyze("^[a-z]+$")
    assert analysis.score == 0
    assert analysis.findings == ()
    assert analysis.verdict == "low"


def test_overlapping_alternation_is_scored_medium():
    analysis = guard().analyze("(a|ab)*")
    assert analysis.score == 40
    assert analysis.findings == ("OVERLAPPING_ALTERNATION",)
    assert analysis.verdict == "medium"


def test_repeated_dot_star_is_reported():
    analysis = guard().analyze("^.*.*x$")
    assert analysis.score == 35
    assert analysis.findings == ("REPEATED_DOT_STAR",)
    assert analysis.verdict == "low"


def test_quarantine_removes_rule_from_ruleset():
    obj = guard()
    record = obj.register("(a+)+$")
    obj.load_ruleset()
    assert obj.effective_rules() == ()
    moved = obj.quarantine(record.rule_id, "prod-incident")
    assert moved.state == "quarantined"
    assert obj.load_ruleset()["loaded"] == ()
    assert obj.effective_rules() == ()


def test_approve_binds_expiry_and_loads_high_risk_rule():
    obj = guard()
    record = obj.register("(a+)+$")
    assert obj.load_ruleset()["loaded"] == ()
    approved = obj.approve(record.rule_id, approved_by="soc-lead", ttl_seconds=3600, now=NOW)
    assert approved.state == "approved"
    assert approved.approved_by == "soc-lead"
    assert approved.approved_until == "2026-11-26T11:00:00+00:00"
    assert obj.load_ruleset()["loaded"] == ("R-0001",)
    assert obj.effective_rules() == ("R-0001",)


def test_load_ruleset_keeps_low_and_medium_and_excludes_high():
    obj = guard()
    high = obj.register("(a+)+$")
    low = obj.register("^[a-z]+$")
    medium = obj.register("(a|ab)*")
    loaded = obj.load_ruleset()
    assert loaded["loaded"] == (low.rule_id, medium.rule_id)
    assert loaded["excluded"] == (high.rule_id,)
    assert loaded["compile_failures"] == ()
    assert obj.effective_rules() == (low.rule_id, medium.rule_id)


def test_expire_approvals_returns_rules_to_quarantine():
    obj = guard()
    record = obj.register("(a+)+$")
    obj.approve(record.rule_id, approved_by="soc-lead", ttl_seconds=600, now=NOW)
    assert obj.expire_approvals(now=SOON) == 0
    assert obj.effective_rules() == ("R-0001",)
    assert obj.expire_approvals(now=LATE) == 1
    assert obj.stats()["approvals_expired"] == 1
    assert obj.effective_rules() == ()
    assert obj.load_ruleset()["loaded"] == ()


def test_benchmark_records_samples_with_injected_executor():
    obj = guard(executor=lambda pattern, sample: 1.5)
    record = obj.register("^[a-z]+$")
    result = obj.benchmark(record.rule_id, ["aaa", "bbb"])
    assert result["rule_id"] == "R-0001"
    assert result["samples"] == [1.5, 1.5]
    assert result["total_ms"] == 3.0
    assert result["sample_count"] == 2
    assert result["status"] == "within_budget"


def test_benchmark_rejects_oversized_or_empty_sample_sets():
    obj = guard(max_samples=2)
    record = obj.register("^[a-z]+$")
    with pytest.raises(rg.RegexSafetyError) as exc:
        obj.benchmark(record.rule_id, ["a", "b", "c"])
    assert exc.value.code == "REGEX_SAMPLE_LIMIT"

    with pytest.raises(rg.RegexSafetyError) as exc:
        obj.benchmark(record.rule_id, [])
    assert exc.value.code == "REGEX_INVALID_REQUEST"


def test_ruleset_capacity_cap_is_enforced():
    obj = guard(max_rules=1)
    obj.register("^[a-z]+$")
    with pytest.raises(rg.RegexSafetyError) as exc:
        obj.register("^[0-9]+$")
    assert exc.value.code == "REGEX_CAPACITY_EXCEEDED"
    assert obj.stats()["registered"] == 1


def test_snapshot_roundtrips_and_rejects_malformed_state():
    obj = guard()
    record = obj.register("(a+)+$")
    obj.approve(record.rule_id, approved_by="soc-lead", ttl_seconds=3600, now=NOW)
    obj.load_ruleset()
    state = obj.snapshot()
    assert set(state) == {"version", "rules", "counters", "loaded"}
    pristine = copy.deepcopy(state)

    state["rules"].clear()
    state["counters"]["registered"] = 99
    assert obj.stats()["registered"] == 1
    assert obj.effective_rules() == ("R-0001",)

    clone = guard()
    clone.restore(pristine)
    assert clone.stats()["registered"] == 1
    assert clone.effective_rules() == ("R-0001",)
    assert clone.load_ruleset()["loaded"] == ("R-0001",)

    for bad in (None, {}, {"version": 1, "rules": {}, "counters": {}},
                {"version": 1, "rules": "nope", "counters": {}, "loaded": ()}):
        with pytest.raises(rg.RegexSafetyError) as exc:
            clone.restore(bad)
        assert exc.value.code == "REGEX_SNAPSHOT_INVALID"
    assert clone.effective_rules() == ("R-0001",)


def test_invalid_state_transitions_raise():
    obj = guard()
    record = obj.register("(a+)+$")
    with pytest.raises(rg.RegexSafetyError) as exc:
        obj.approve("R-9999", approved_by="soc-lead", ttl_seconds=600, now=NOW)
    assert exc.value.code == "REGEX_RULE_UNKNOWN"

    with pytest.raises(rg.RegexSafetyError) as exc:
        obj.approve(record.rule_id, approved_by="soc-lead", ttl_seconds=0, now=NOW)
    assert exc.value.code == "REGEX_APPROVAL_TTL_INVALID"

    with pytest.raises(rg.RegexSafetyError) as exc:
        obj.quarantine("R-9999", "typo")
    assert exc.value.code == "REGEX_RULE_UNKNOWN"

    assert obj.stats()["registered"] == 1
    assert obj.stats()["quarantined"] == 0
