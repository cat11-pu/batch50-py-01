import pytest

import patch_baseline_rollout as pb

T0 = "2026-11-26T08:00:00+00:00"
T1 = "2026-11-26T08:30:00+00:00"
T2 = "2026-11-26T09:00:00+00:00"


def rollout(**kwargs):
    return pb.PatchBaselineRollout(**kwargs)


def seeded(*, batch_size=2, success_ratio=0.9, hosts=("h1", "h2", "h3", "h4"),
           patches=("KB1",), installed=None):
    engine = rollout(batch_size=batch_size, success_ratio=success_ratio)
    engine.define_baseline("cis-2026-11", list(patches))
    for host in hosts:
        engine.register_host(host, installed=(installed or {}).get(host, ()))
    return engine


def test_define_baseline_returns_revision_and_is_idempotent():
    engine = rollout()
    assert engine.define_baseline("cis-2026-11", ["KB2", "KB1"]) == 1
    assert engine.define_baseline("cis-2026-11", ["KB1", "KB2"]) == 1
    with pytest.raises(pb.RolloutError) as exc:
        engine.define_baseline("cis-2026-11", ["KB1"])
    assert exc.value.code == "ROLLOUT_BASELINE_CONFLICT"
    with pytest.raises(pb.RolloutError) as exc:
        engine.define_baseline("cis-2026-12", ["KB9"])
    assert exc.value.code == "ROLLOUT_BASELINE_CONFLICT"


def test_missing_for_subtracts_installed_and_sorts():
    engine = rollout()
    engine.define_baseline("cis-2026-11", ["KB3", "KB1", "KB2"])
    engine.register_host("h1", installed=["KB2"])
    engine.register_host("h2")
    assert engine.missing_for("h1", now=T0) == ("KB1", "KB3")
    assert engine.missing_for("h2", now=T0) == ("KB1", "KB2", "KB3")
    with pytest.raises(pb.RolloutError) as exc:
        engine.missing_for("h404", now=T0)
    assert exc.value.code == "ROLLOUT_HOST_UNKNOWN"


def test_exemption_expires_and_patch_returns():
    engine = rollout()
    engine.define_baseline("cis-2026-11", ["KB1", "KB2"])
    engine.register_host("h1", exemptions={"KB1": "2026-12-01"})
    assert engine.missing_for("h1", now=T0) == ("KB2",)
    assert engine.missing_for("h1", now="2026-12-01T00:00:00+00:00") == ("KB1", "KB2")
    assert engine.missing_for("h1", now="2026-12-02T00:00:00+00:00") == ("KB1", "KB2")


def test_plan_batches_hosts_in_sorted_order():
    engine = seeded(hosts=("h3", "h1", "h4", "h2"))
    layout = engine.plan(now=T0)
    assert layout == {0: ["h1", "h2"], 1: ["h3", "h4"]}
    assert engine.batches() == {0: ["h1", "h2"], 1: ["h3", "h4"]}
    assert engine.status()["dispatched_batches"] == 0
    assert engine.status()["batches"] == 2


def test_plan_skips_hosts_without_missing_patches():
    engine = rollout(batch_size=2)
    engine.define_baseline("cis-2026-11", ["KB1", "KB2"])
    engine.register_host("h1", installed=["KB1", "KB2"])
    engine.register_host("h2", installed=["KB1"])
    assert engine.plan(now=T0) == {0: ["h2"]}
    assert engine.missing_for("h1", now=T0) == ()


def test_dispatch_must_follow_batch_order():
    engine = seeded()
    engine.plan(now=T0)
    with pytest.raises(pb.RolloutError) as exc:
        engine.dispatch(1, now=T0)
    assert exc.value.code == "ROLLOUT_BATCH_OUT_OF_ORDER"
    first = engine.dispatch(0, now=T0)
    assert first == [{"host_id": "h1", "patches": ["KB1"]},
                     {"host_id": "h2", "patches": ["KB1"]}]
    with pytest.raises(pb.RolloutError) as exc:
        engine.dispatch(0, now=T1)
    assert exc.value.code == "ROLLOUT_BATCH_ALREADY_DISPATCHED"
    assert engine.status()["dispatched_batches"] == 1


def test_dispatch_before_plan_is_refused():
    engine = seeded()
    with pytest.raises(pb.RolloutError) as exc:
        engine.dispatch(0, now=T0)
    assert exc.value.code == "ROLLOUT_NOT_PLANNED"
    assert engine.stats()["dispatched"] == 0


def test_result_unknown_assignment_is_refused():
    engine = seeded()
    engine.plan(now=T0)
    engine.dispatch(0, now=T0)
    with pytest.raises(pb.RolloutError) as exc:
        engine.on_result("h2", "KB1", status="installed", now=T1)
    assert exc.value.code == "ROLLOUT_RESULT_UNKNOWN"
    with pytest.raises(pb.RolloutError) as exc:
        engine.on_result("h1", "KB9", status="installed", now=T1)
    assert exc.value.code == "ROLLOUT_RESULT_UNKNOWN"
    with pytest.raises(pb.RolloutError) as exc:
        engine.on_result("h1", "KB1", status="half-done", now=T1)
    assert exc.value.code == "ROLLOUT_RESULT_INVALID"
    assert engine.stats()["installed"] == 0


def test_duplicate_result_is_idempotent():
    engine = seeded()
    engine.plan(now=T0)
    engine.dispatch(0, now=T0)
    assert engine.on_result("h1", "KB1", status="installed", now=T1) is True
    assert engine.on_result("h1", "KB1", status="installed", now=T2) is False
    assert engine.stats()["duplicate_results"] == 1
    assert engine.stats()["installed"] == 1
    assert engine.status()["fixed"] == 1


def test_gate_passes_and_next_batch_unlocks():
    engine = seeded(batch_size=2, success_ratio=0.5)
    engine.plan(now=T0)
    engine.dispatch(0, now=T0)
    engine.on_result("h1", "KB1", status="installed", now=T1)
    engine.on_result("h2", "KB1", status="installed", now=T1)
    assert engine.gate(0) == {"batch": 0, "installed": 2, "failed": 0,
                              "total": 2, "ratio": 1.0, "passed": True}
    second = engine.dispatch(1, now=T1)
    assert [row["host_id"] for row in second] == ["h3", "h4"]
    assert engine.status()["halted"] is False


def test_failed_host_blocks_next_batch():
    engine = seeded(batch_size=2, success_ratio=1.0)
    engine.plan(now=T0)
    engine.dispatch(0, now=T0)
    engine.on_result("h1", "KB1", status="installed", now=T1)
    engine.on_result("h2", "KB1", status="failed", now=T1)
    gate = engine.gate(0)
    assert (gate["installed"], gate["failed"], gate["total"]) == (1, 1, 2)
    assert gate["ratio"] == 0.5
    assert gate["passed"] is False
    with pytest.raises(pb.RolloutError) as exc:
        engine.dispatch(1, now=T2)
    assert exc.value.code == "ROLLOUT_GATE_NOT_MET"
    assert engine.status()["halted"] is True
    assert engine.stats()["failed"] == 1


def test_rollback_of_undispatched_or_unknown_batch_is_refused():
    engine = seeded()
    engine.plan(now=T0)
    with pytest.raises(pb.RolloutError) as exc:
        engine.rollback(0, now=T1)
    assert exc.value.code == "ROLLOUT_BATCH_NOT_DISPATCHED"
    with pytest.raises(pb.RolloutError) as exc:
        engine.rollback(7, now=T1)
    assert exc.value.code == "ROLLOUT_BATCH_UNKNOWN"
    assert engine.stats()["rolled_back"] == 0


def test_replan_after_install_skips_delivered_patches():
    engine = seeded(batch_size=2, patches=("KB1", "KB2"))
    engine.plan(now=T0)
    engine.dispatch(0, now=T0)
    engine.on_result("h1", "KB1", status="installed", now=T1)
    engine.on_result("h1", "KB2", status="installed", now=T1)
    engine.on_result("h2", "KB1", status="installed", now=T1)
    assert engine.missing_for("h1", now=T2) == ()
    layout = engine.plan(now=T2)
    assert layout == {0: ["h2"], 1: ["h3"], 2: ["h4"]}
    assert engine.status()["fixed"] == 3


def test_snapshot_roundtrip_keeps_results_and_halt():
    engine = seeded(batch_size=2, success_ratio=1.0)
    engine.plan(now=T0)
    engine.dispatch(0, now=T0)
    engine.on_result("h1", "KB1", status="installed", now=T1)
    engine.on_result("h2", "KB1", status="failed", now=T1)
    state = engine.snapshot()

    clone = rollout()
    clone.restore(state)
    assert clone.missing_for("h1", now=T2) == ()
    assert clone.missing_for("h2", now=T2) == ("KB1",)
    assert clone.batches() == engine.batches()
    assert clone.status() == engine.status()
    assert clone.stats() == engine.stats()
    with pytest.raises(pb.RolloutError) as exc:
        clone.dispatch(1, now=T2)
    assert exc.value.code == "ROLLOUT_GATE_NOT_MET"

    state["results"] = []
    assert engine.stats()["installed"] == 1


def test_restore_rejects_malformed_snapshot():
    engine = seeded()
    engine.plan(now=T0)
    good = engine.snapshot()
    broken = [None, {},
              {"version": 4, "baseline": (), "baseline_name": "x", "hosts": {},
               "batches": {}, "dispatched": {}, "results": [], "halted": False,
               "counters": {}, "stats": {}}]
    partial = dict(good)
    partial.pop("dispatched")
    broken.append(partial)
    wrong_type = dict(good)
    wrong_type["results"] = {}
    broken.append(wrong_type)
    for bad in broken:
        with pytest.raises(pb.RolloutError) as exc:
            engine.restore(bad)
        assert exc.value.code == "ROLLOUT_SNAPSHOT_INVALID"
    assert engine.batches() == {0: ["h1", "h2"], 1: ["h3", "h4"]}
    assert engine.status()["dispatched_batches"] == 0
