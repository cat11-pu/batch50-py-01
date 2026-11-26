import copy
import threading

import pytest

import rule_backtest_gate as rb

SAMPLES = [
    {"sample_id": "s1", "label": "malicious", "tags": ["exec"], "baseline_state": "hit"},
    {"sample_id": "s2", "label": "benign", "tags": ["exec"], "baseline_state": "miss"},
    {"sample_id": "s3", "label": "benign", "tags": ["net"], "baseline_state": "hit"},
    {"sample_id": "s4", "label": "malicious", "tags": ["crypt"], "baseline_state": "miss"},
    {"sample_id": "s5", "label": "benign", "tags": ["net", "exec"], "baseline_state": "miss"},
    {"sample_id": "s6", "label": "malicious", "tags": [], "baseline_state": "hit"},
    {"sample_id": "s7", "label": "malicious", "tags": ["net"], "baseline_state": "miss"},
]


def rows(count=6):
    return [dict(row, tags=list(row["tags"])) for row in SAMPLES[:count]]


def loaded(gate, count=6, *, baseline_version=3):
    gate.load_baseline("prod", version=baseline_version)
    gate.load_candidate("hotfix", version=7, selectors=["exec"])
    gate.load_samples("hist", version=5, baseline_version=baseline_version,
                      samples=rows(count))


def run(gate, **kwargs):
    return gate.run_backtest(candidate="hotfix", baseline="prod", sampleset="hist",
                             **kwargs)


def test_load_rules_normalizes_selectors_and_validates_versions():
    gate = rb.RuleBacktestGate()
    base = gate.load_baseline("prod-rule", version=3)
    assert base == {"rule_id": "prod-rule", "version": 3}
    cand = gate.load_candidate("hotfix", version=7,
                               selectors=["exec", " crypt ", "exec"])
    assert cand["rule_id"] == "hotfix"
    assert cand["version"] == 7
    assert cand["selectors"] == ("crypt", "exec")
    bad_calls = [
        ("", 1, ["exec"]),
        ("hotfix", 0, ["exec"]),
        ("hotfix", 1, []),
        ("hotfix", 1, ["exec", 5]),
    ]
    for rule_id, version, selectors in bad_calls:
        with pytest.raises(rb.BacktestError) as exc:
            gate.load_candidate(rule_id, version=version, selectors=selectors)
        assert exc.value.code == "BACKTEST_INVALID_RULE"


def test_load_samples_validates_each_row_and_reports_total():
    gate = rb.RuleBacktestGate()
    gate.load_baseline("prod", version=3)
    record = gate.load_samples("hist", version=5, baseline_version=3, samples=rows())
    assert record["sampleset_id"] == "hist"
    assert record["version"] == 5
    assert record["baseline_version"] == 3
    assert record["total"] == 6

    duplicated = rows() + [dict(rows()[0], tags=["exec"])]
    with pytest.raises(rb.BacktestError) as exc:
        gate.load_samples("hist2", version=1, baseline_version=3,
                          samples=duplicated)
    assert exc.value.code == "BACKTEST_INVALID_SAMPLES"

    broken = [
        [dict(rows()[0], label="unknown")],
        [dict(rows()[0], baseline_state="maybe")],
        [dict(rows()[0], tags="exec")],
        [{"sample_id": "only"}],
    ]
    for samples in broken:
        with pytest.raises(rb.BacktestError) as exc:
            gate.load_samples("hist3", version=1, baseline_version=3,
                              samples=samples)
        assert exc.value.code == "BACKTEST_INVALID_SAMPLES"


def test_run_backtest_counts_hits_across_batches():
    gate = rb.RuleBacktestGate()
    loaded(gate)
    record = run(gate, batch_size=2)
    assert record["run_id"] == "BT-0001"
    assert record["status"] == rb.RUN_COMPLETED
    assert record["total"] == 6
    assert record["total_batches"] == 3
    assert record["next_batch"] == 3
    progress = gate.progress("BT-0001")
    assert progress["processed"] == 6
    assert progress["candidate_hits"] == 3
    assert progress["baseline_hits"] == 3


def test_run_backtest_rejects_unknown_or_mismatched_inputs():
    gate = rb.RuleBacktestGate()
    loaded(gate)
    with pytest.raises(rb.BacktestError) as exc:
        gate.run_backtest(candidate="ghost", baseline="prod", sampleset="hist")
    assert exc.value.code == "BACKTEST_UNKNOWN_RULE"

    with pytest.raises(rb.BacktestError) as exc:
        gate.run_backtest(candidate="hotfix", baseline="prod", sampleset="ghost")
    assert exc.value.code == "BACKTEST_UNKNOWN_SAMPLES"

    other = rb.RuleBacktestGate()
    other.load_baseline("prod", version=3)
    other.load_candidate("hotfix", version=7, selectors=["exec"])
    other.load_samples("hist", version=5, baseline_version=2, samples=rows())
    with pytest.raises(rb.BacktestError) as exc:
        other.run_backtest(candidate="hotfix", baseline="prod", sampleset="hist")
    assert exc.value.code == "BACKTEST_BASELINE_MISMATCH"


def test_report_lists_every_batch_exactly_once():
    gate = rb.RuleBacktestGate()
    loaded(gate)
    run(gate, batch_size=2)
    report = gate.report("BT-0001")
    assert [item["batch_no"] for item in report["batches"]] == [1, 2, 3]
    assert [item["processed"] for item in report["batches"]] == [2, 2, 2]
    assert [item["candidate_hits"] for item in report["batches"]] == [2, 0, 1]
    assert report["decision"] is None
    assert report["candidate_version"] == 7
    assert report["sampleset_version"] == 5


def test_batch_limit_pauses_and_resume_advances_the_cursor():
    gate = rb.RuleBacktestGate()
    loaded(gate, count=7)
    first = run(gate, batch_size=3, batch_limit=1)
    assert first["status"] == rb.RUN_PAUSED
    assert first["next_batch"] == 1
    assert first["total_batches"] == 3

    second = gate.resume(first["run_id"], batch_limit=1)
    assert second["status"] == rb.RUN_PAUSED
    assert second["next_batch"] == 2

    third = gate.resume(first["run_id"])
    assert third["status"] == rb.RUN_COMPLETED
    assert third["next_batch"] == 3
    assert gate.progress(first["run_id"])["total_batches"] == 3


def test_interrupt_is_idempotent_and_rejects_finished_runs():
    gate = rb.RuleBacktestGate()
    loaded(gate, count=7)
    paused = run(gate, batch_size=3, batch_limit=1)
    out = gate.interrupt(paused["run_id"])
    assert out["status"] == rb.RUN_INTERRUPTED
    again = gate.interrupt(paused["run_id"])
    assert again["status"] == rb.RUN_INTERRUPTED
    assert gate.resume(paused["run_id"])["status"] == rb.RUN_COMPLETED

    with pytest.raises(rb.BacktestError) as exc:
        gate.interrupt(paused["run_id"])
    assert exc.value.code == "BACKTEST_RUN_STATE"

    with pytest.raises(rb.BacktestError) as exc:
        gate.interrupt("BT-9999")
    assert exc.value.code == "BACKTEST_UNKNOWN_RUN"


def test_compare_baseline_reports_hit_and_false_positive_delta():
    gate = rb.RuleBacktestGate()
    loaded(gate)
    run(gate, batch_size=2)
    compared = gate.compare_baseline("BT-0001")
    assert compared["scored"] == 6
    assert compared["candidate_hits"] == 3
    assert compared["baseline_hits"] == 3
    assert compared["new_hits"] == 2
    assert compared["candidate_fp"] == 2
    assert compared["baseline_fp"] == 1
    assert compared["fp_delta"] == 1


def test_compare_and_decide_require_a_finished_run():
    gate = rb.RuleBacktestGate()
    loaded(gate, count=7)
    paused = run(gate, batch_size=3, batch_limit=1)
    for call in (gate.compare_baseline, gate.decide):
        with pytest.raises(rb.BacktestError) as exc:
            call(paused["run_id"])
        assert exc.value.code == "BACKTEST_RUN_NOT_READY"


def test_decide_accepts_within_thresholds_and_stamps_versions():
    gate = rb.RuleBacktestGate()
    loaded(gate)
    run(gate, batch_size=2)
    decision = gate.decide("BT-0001")
    assert decision["verdict"] == rb.VERDICT_ACCEPT
    assert decision["reasons"] == ()
    assert decision["run_id"] == "BT-0001"
    assert decision["candidate_version"] == 7
    assert decision["baseline_version"] == 3
    assert decision["sampleset_version"] == 5
    assert decision["new_hits"] == 2
    assert decision["fp_delta"] == 1
    assert gate.report("BT-0001")["decision"]["verdict"] == rb.VERDICT_ACCEPT


def test_decide_rejects_when_new_hits_exceed_limit():
    gate = rb.RuleBacktestGate(max_new_hits=1)
    loaded(gate)
    run(gate, batch_size=2)
    decision = gate.decide("BT-0001")
    assert decision["verdict"] == rb.VERDICT_REJECT
    assert decision["reasons"] == (rb.REASON_NEW_HITS,)


def test_decide_rejects_on_false_positive_delta_and_lists_both_reasons():
    gate = rb.RuleBacktestGate(max_fp_delta=0)
    loaded(gate)
    run(gate, batch_size=2)
    assert gate.decide("BT-0001")["reasons"] == (rb.REASON_FP_DELTA,)

    strict = rb.RuleBacktestGate(max_new_hits=0, max_fp_delta=0)
    loaded(strict)
    run(strict, batch_size=2)
    decision = strict.decide("BT-0001")
    assert decision["reasons"] == (rb.REASON_NEW_HITS, rb.REASON_FP_DELTA)


def test_concurrent_runs_keep_separate_cursors_and_counters():
    gate = rb.RuleBacktestGate()
    errors = []
    results = []
    barrier = threading.Barrier(4)

    def worker(index):
        try:
            gate.load_baseline(f"base-{index}", version=1)
            gate.load_candidate(f"cand-{index}", version=1,
                                selectors=[f"tag-{index}"])
            gate.load_samples(
                f"set-{index}", version=1, baseline_version=1,
                samples=[
                    {"sample_id": f"{index}-a", "label": "malicious",
                     "tags": [f"tag-{index}"], "baseline_state": "hit"},
                    {"sample_id": f"{index}-b", "label": "malicious",
                     "tags": [f"tag-{index}"], "baseline_state": "miss"},
                    {"sample_id": f"{index}-c", "label": "benign",
                     "tags": ["other"], "baseline_state": "hit"},
                    {"sample_id": f"{index}-d", "label": "malicious",
                     "tags": ["other"], "baseline_state": "miss"},
                ])
            barrier.wait(timeout=10)
            record = gate.run_backtest(candidate=f"cand-{index}",
                                       baseline=f"base-{index}",
                                       sampleset=f"set-{index}",
                                       batch_size=2)
            compared = gate.compare_baseline(record["run_id"])
            results.append((compared["new_hits"], compared["fp_delta"],
                            len(gate.report(record["run_id"])["batches"])))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert results == [(-1, -1, 2)] * 4
    assert gate.stats()["runs"] == 4


def test_snapshot_is_detached_and_restore_roundtrips():
    gate = rb.RuleBacktestGate()
    loaded(gate)
    run(gate, batch_size=2)
    gate.decide("BT-0001")
    state = gate.snapshot()
    assert set(state) == {"format", "baselines", "candidates", "samplesets",
                          "runs", "counters"}
    pristine = copy.deepcopy(state)

    state["runs"].clear()
    state["counters"]["accepted"] = 99
    assert gate.stats()["accepted"] == 1
    assert gate.compare_baseline("BT-0001")["new_hits"] == 2
    assert gate.decide("BT-0001")["verdict"] == rb.VERDICT_ACCEPT

    clone = rb.RuleBacktestGate()
    clone.restore(pristine)
    assert clone.stats()["accepted"] == 1
    assert clone.compare_baseline("BT-0001")["fp_delta"] == 1
    assert clone.decide("BT-0001")["reasons"] == ()
    assert clone.progress("BT-0001")["processed"] == 6


def test_restore_rejects_malformed_state_without_touching_live_data():
    gate = rb.RuleBacktestGate()
    loaded(gate)
    run(gate, batch_size=2)

    good = gate.snapshot()
    bad_states = [
        None,
        {},
        dict(good, format="other"),
        dict(good, runs=[]),
        dict(good, counters={}),
        dict(good, baselines="nope"),
    ]
    for bad in bad_states:
        with pytest.raises(rb.BacktestError) as exc:
            gate.restore(bad)
        assert exc.value.code == "BACKTEST_SNAPSHOT_INVALID"

    assert gate.stats()["runs"] == 1
    assert gate.compare_baseline("BT-0001")["new_hits"] == 2
