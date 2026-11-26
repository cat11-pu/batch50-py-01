import copy
import threading

import pytest

import dmarc_policy_evaluator as dm

NOW = "2026-11-26T09:00:00+00:00"
LATER = "2026-11-26T09:02:00+00:00"


def evaluator(**kwargs):
    return dm.DmarcPolicyEvaluator(**kwargs)


def message(**overrides):
    data = {
        "from_domain": "example.com",
        "dkim_domain": "example.com",
        "spf_domain": "example.com",
        "message_id": "m-1",
    }
    data.update(overrides)
    return data


def test_parse_record_applies_defaults_and_sorts_rua():
    ev = evaluator()
    policy = ev.parse_record(
        "example.com",
        "v=DMARC1; rua=mailto:b@example.test,mailto:a@example.test",
    )
    assert policy.domain == "example.com"
    assert (policy.p, policy.sp, policy.pct, policy.adkim, policy.aspf) == (
        "none", "inherit", 100, "r", "r",
    )
    assert policy.rua == ("mailto:a@example.test", "mailto:b@example.test")


def test_parse_record_rejects_invalid_tags():
    ev = evaluator()
    texts = [
        "v=DMARC1; p=maybe",
        "p=none; rua=mailto:a@example.test",
        "v=DMARC1; pct=150",
    ]
    for text in texts:
        with pytest.raises(dm.DmarcError) as exc:
            ev.parse_record("example.com", text)
        assert exc.value.code == "DMARC_INVALID_RECORD"


def test_policy_for_resolves_once_then_serves_cache():
    calls = []

    def resolver(domain):
        calls.append(domain)
        return "v=DMARC1; p=reject"

    ev = evaluator(resolver=resolver)
    first = ev.policy_for("example.com", now=NOW)
    second = ev.policy_for("example.com", now=NOW)
    assert first.p == "reject"
    assert second.p == "reject"
    assert calls == ["example.com"]
    assert ev.stats()["resolver_calls"] == 1


def test_invalidate_and_negative_cache_expiry():
    replies = {"example.com": "v=DMARC1; p=none"}
    calls = []

    def resolver(domain):
        calls.append(domain)
        return replies.get(domain)

    ev = evaluator(resolver=resolver, cache_ttl=300, negative_ttl=60)
    ev.cache_policy("example.com", "v=DMARC1; p=none", now=NOW)
    assert ev.policy_for("example.com", now=NOW).p == "none"
    assert ev.invalidate("example.com") is True
    assert ev.invalidate("example.com") is False
    replies["example.com"] = "v=DMARC1; p=quarantine"
    assert ev.policy_for("example.com", now=NOW).p == "quarantine"
    assert ev.policy_for("empty.test", now=NOW) is None
    assert calls == ["example.com", "empty.test"]
    assert ev.purge_expired(now=LATER) == 1
    assert ev.policy_for("empty.test", now=LATER) is None
    assert calls == ["example.com", "empty.test", "empty.test"]


def test_dkim_aligned_strict_passes_without_action():
    ev = evaluator()
    ev.cache_policy("example.com", "v=DMARC1; p=reject; adkim=s", now=NOW)
    out = ev.evaluate(message(dkim_domain="example.com", spf_domain=None), now=NOW)
    assert out.result == "pass"
    assert out.dkim_aligned is True
    assert out.disposition == "none"
    assert out.sampled is True


def test_relaxed_dkim_alignment_accepts_subdomain():
    ev = evaluator()
    ev.cache_policy("example.com", "v=DMARC1; p=reject; adkim=r", now=NOW)
    out = ev.evaluate(message(dkim_domain="mail.example.com", spf_domain=None), now=NOW)
    assert out.dkim_aligned is True
    assert out.result == "pass"


def test_strict_dkim_mismatch_fails_and_rejects():
    ev = evaluator()
    ev.cache_policy("example.com", "v=DMARC1; p=reject; adkim=s; pct=100", now=NOW)
    out = ev.evaluate(message(dkim_domain="mail.example.com", spf_domain=None), now=NOW)
    assert out.result == "fail"
    assert out.dkim_aligned is False
    assert out.disposition == "reject"


def test_relaxed_spf_alignment_passes():
    ev = evaluator()
    ev.cache_policy("example.com", "v=DMARC1; p=quarantine; aspf=r", now=NOW)
    out = ev.evaluate(message(dkim_domain=None, spf_domain="bounce.example.com"), now=NOW)
    assert out.spf_aligned is True
    assert out.result == "pass"
    assert out.disposition == "none"


def test_both_mechanisms_fail_under_quarantine():
    ev = evaluator()
    ev.cache_policy("example.com", "v=DMARC1; p=quarantine", now=NOW)
    out = ev.evaluate(message(dkim_domain="other.test", spf_domain="other.test"), now=NOW)
    assert out.dkim_aligned is False
    assert out.spf_aligned is False
    assert out.result == "fail"
    assert out.disposition == "quarantine"


def test_missing_policy_yields_none_result():
    ev = evaluator(resolver=lambda domain: None)
    out = ev.evaluate(message(from_domain="nopolicy.test"), now=NOW)
    assert out.result == "none"
    assert out.disposition == "none"
    assert out.policy_source == "none"


def test_repeated_evaluation_keeps_same_sampling_verdict():
    ev = evaluator()
    ev.cache_policy("example.com", "v=DMARC1; p=reject; pct=37", now=NOW)
    msg = message(
        dkim_domain="bad.test",
        spf_domain="bad.test",
        message_id="stable-7",
    )
    first = ev.evaluate(msg, now=NOW)
    second = ev.evaluate(msg, now=NOW)
    assert first.result == "fail"
    assert second.result == "fail"
    assert first.sampled == second.sampled
    assert first.disposition == second.disposition


def test_report_aggregate_totals_and_dispositions():
    ev = evaluator()
    ev.cache_policy("example.com", "v=DMARC1; p=quarantine", now=NOW)
    ev.evaluate(message(), now=NOW)
    ev.evaluate(
        message(dkim_domain="bad.test", spf_domain="bad.test", message_id="m-2"),
        now=NOW,
    )
    ev.evaluate(message(from_domain="other.test", message_id="m-3"), now=NOW)
    report = ev.report_aggregate()
    assert report["total"] == 3
    assert (report["pass"], report["fail"], report["none"]) == (1, 1, 1)
    assert report["by_disposition"] == {"none": 2, "quarantine": 1, "reject": 0}
    assert report["domains"]["example.com"]["total"] == 2
    assert report["domains"]["example.com"]["fail"] == 1
    assert report["domains"]["other.test"]["none"] == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    ev = evaluator()
    ev.cache_policy("example.com", "v=DMARC1; p=reject", now=NOW)
    ev.evaluate(message(), now=NOW)
    state = ev.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "policies", "aggregates", "stats"}

    state["policies"].clear()
    state["aggregates"]["total"] = 999
    state["stats"]["evaluations"] = 999
    assert ev.stats()["evaluations"] == 1
    assert ev.evaluate(message(message_id="m-2"), now=NOW).result == "pass"

    clone = evaluator()
    clone.restore(pristine)
    assert clone.stats()["evaluations"] == 1
    assert clone.policy_for("example.com", now=NOW).p == "reject"
    assert clone.report_aggregate()["total"] == 1


def test_restore_rejects_malformed_snapshot_without_touching_state():
    ev = evaluator()
    ev.cache_policy("example.com", "v=DMARC1; p=reject", now=NOW)
    ev.evaluate(message(), now=NOW)
    bad_states = [
        None,
        {},
        {"version": 1, "policies": [], "aggregates": {}, "stats": {}},
        {"version": 1, "policies": {}, "aggregates": [], "stats": {}},
        {"version": 1, "policies": {}, "aggregates": {}, "stats": []},
        {"version": 99, "policies": {}, "aggregates": {}, "stats": {}},
        {"version": 1, "policies": {}, "aggregates": {}},
    ]
    for bad in bad_states:
        with pytest.raises(dm.DmarcError) as exc:
            ev.restore(bad)
        assert exc.value.code == "DMARC_SNAPSHOT_INVALID"
    assert ev.stats()["evaluations"] == 1
    assert ev.evaluate(message(message_id="m-2"), now=NOW).result == "pass"


def test_concurrent_evaluations_load_policy_once():
    calls = []
    lock = threading.Lock()

    def resolver(domain):
        with lock:
            calls.append(domain)
        return "v=DMARC1; p=reject"

    ev = evaluator(resolver=resolver)
    errors = []
    barrier = threading.Barrier(10)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            out = ev.evaluate(message(message_id=f"m-{index}"), now=NOW)
            if out.result != "pass":
                errors.append(out.result)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert calls == ["example.com"]
    assert ev.stats()["evaluations"] == 10
