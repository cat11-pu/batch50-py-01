import pytest

import declick_repair_planner as dp


def planner(**kwargs):
    return dp.DeclickRepairPlanner(**kwargs)


def test_feed_block_returns_index_and_counts_samples():
    p = planner()
    assert p.feed_block([0.0, 0.0, 0.0, 0.0]) == 0
    assert p.feed_block([0.0, 0.0, 0.0, 0.0]) == 1
    stats = p.repair_stats()
    assert stats["blocks"] == 2
    assert stats["samples"] == 8
    assert stats["sample_rate"] == 48000
    assert p.committed_blocks() == 0


def test_feed_block_rejects_non_numeric_sample():
    p = planner()
    with pytest.raises(dp.DeclickError) as exc:
        p.feed_block([0.0, 0.5, "loud"])
    assert exc.value.code == "INVALID_SAMPLE"
    assert p.repair_stats()["blocks"] == 0
    assert p.repair_stats()["samples"] == 0


def test_detect_clicks_finds_short_run_with_bounds():
    p = planner()
    p.feed_block([0.0, 0.0, 0.8, 0.7, 0.0, 0.0])
    clicks = p.detect_clicks()
    assert [(c.start, c.end, c.kind) for c in clicks] == [(2, 3, "click")]
    assert abs(clicks[0].peak - 0.8) < 1e-9
    assert p.repair_stats()["clicks"] == 1
    assert p.repair_stats()["clips"] == 0


def test_detect_clicks_merges_runs_within_gap():
    p = planner(merge_gap=2)
    p.feed_block([0.9, 0.9, 0.0, 0.0, 0.8, 0.8])
    clicks = p.detect_clicks()
    assert [(c.start, c.end) for c in clicks] == [(0, 5)]
    assert abs(clicks[0].peak - 0.9) < 1e-9

    q = planner(merge_gap=1)
    q.feed_block([0.9, 0.9, 0.0, 0.0, 0.8, 0.8])
    assert [(c.start, c.end) for c in q.detect_clicks()] == [(0, 1), (4, 5)]


def test_detect_clicks_marks_clipping_plateau():
    p = planner()
    p.feed_block([0.0, 0.99, 1.0, 0.99, 0.0])
    clicks = p.detect_clicks()
    assert [(c.start, c.end, c.kind) for c in clicks] == [(1, 3, "clip")]
    assert clicks[0].peak == 1.0
    assert p.repair_stats()["clips"] == 1


def test_detect_clicks_skips_loud_run_without_clipping():
    p = planner(threshold=0.5)
    p.feed_block([0.0, 0.7, 0.75, 0.72, 0.0])
    assert p.detect_clicks() == []


def test_plan_repair_maps_modes_per_kind():
    p = planner()
    p.feed_block([0.0, 0.8, 0.8, 0.0])
    p.feed_block([0.0, 0.99, 1.0, 0.99, 0.0])
    spans = p.plan_repair(p.detect_clicks())
    assert [(s.start, s.end, s.mode) for s in spans] == [
        (1, 2, "linear"),
        (5, 7, "envelope"),
    ]


def test_plan_repair_rejects_span_over_length_limit():
    p = planner(max_repair_len=4)
    p.feed_block([0.0, 0.99, 1.0, 0.99, 0.98, 0.99, 0.0])
    with pytest.raises(dp.DeclickError) as exc:
        p.plan_repair(p.detect_clicks())
    assert exc.value.code == "REPAIR_TOO_LONG"
    assert p.repair_stats()["spans"] == 0


def test_plan_repair_enforces_block_point_budget():
    p = planner(merge_gap=0, max_points_per_block=1)
    p.feed_block([0.8, 0.8, 0.0, 0.8, 0.8])
    with pytest.raises(dp.DeclickError) as exc:
        p.plan_repair(p.detect_clicks())
    assert exc.value.code == "POINT_BUDGET_EXCEEDED"
    assert p.repair_stats()["spans"] == 0


def test_apply_repair_replaces_span_and_reports_count():
    p = planner()
    p.feed_block([0.0, 0.8, 0.7, 0.0])
    p.feed_block([0.0, 0.0, 0.0])
    spans = p.plan_repair(p.detect_clicks())
    assert p.apply_repair(spans) == 2
    residual = p.verify_residual()
    assert len(residual["spans"]) == 1
    assert residual["spans"][0]["start"] == 1
    assert residual["spans"][0]["residual"] == 0.0
    assert residual["ok"] is True
    assert p.committed_blocks() == 1


def test_apply_repair_is_idempotent():
    p = planner()
    p.feed_block([0.0, 0.8, 0.7, 0.0])
    spans = p.plan_repair(p.detect_clicks())
    assert p.apply_repair(spans) == 2
    assert p.apply_repair(spans) == 0
    assert p.repair_stats()["applied"] == 2
    assert len(p.verify_residual()["spans"]) == 1


def test_verify_residual_before_any_repair_is_empty():
    p = planner()
    p.feed_block([0.0, 0.8, 0.7, 0.0])
    out = p.verify_residual()
    assert out["spans"] == []
    assert out["ok"] is True


def test_configuration_validation_and_rate_change():
    p = planner()
    with pytest.raises(dp.DeclickError) as exc:
        p.set_threshold(0.0)
    assert exc.value.code == "INVALID_CONFIG"
    with pytest.raises(dp.DeclickError) as exc:
        p.set_sample_rate(0)
    assert exc.value.code == "INVALID_CONFIG"
    p.set_sample_rate(44100)
    assert p.repair_stats()["sample_rate"] == 44100
    p.set_threshold(0.4)
    assert p.repair_stats()["threshold"] == 0.4
    p.set_limits(max_repair_len=8, max_points_per_block=2)
    assert p.repair_stats()["max_repair_len"] == 8


def test_snapshot_restore_keeps_detection_and_counters():
    p = planner()
    p.feed_block([0.0, 0.8, 0.7, 0.0])
    p.feed_block([0.0, 0.0, 0.0, 0.0])
    spans = p.plan_repair(p.detect_clicks())
    p.apply_repair(spans)
    snap = p.snapshot()
    clone = planner()
    clone.restore(snap)
    assert clone.committed_blocks() == p.committed_blocks()
    assert clone.repair_stats() == p.repair_stats()
    assert [(c.start, c.end) for c in clone.detect_clicks()] == [(1, 2)]
    assert clone.verify_residual()["spans"] == p.verify_residual()["spans"]


def test_restore_rejects_malformed_state_without_touching_live_data():
    p = planner()
    p.feed_block([0.0, 0.8, 0.7, 0.0])
    before = p.repair_stats()
    for bad in (None, {}, {"version": 1}, {"version": 1, "samples": "loud"}):
        with pytest.raises(dp.DeclickError) as exc:
            p.restore(bad)
        assert exc.value.code == "SNAPSHOT_INVALID"
    assert p.repair_stats() == before
    assert [(c.start, c.end) for c in p.detect_clicks()] == [(1, 2)]
