import pytest

import fuzz_budget_allocator as fb


def allocator(**kwargs):
    return fb.FuzzBudgetAllocator(**kwargs)


def test_register_validates_and_lists_targets():
    engine = allocator()
    view = engine.register("libpng", weight=2.0, note="image decoder")
    assert view["target"] == "libpng"
    assert view["weight"] == 2.0
    assert view["state"] == "active"
    assert view["zero_streak"] == 0
    assert view["yield_points"] == 0
    engine.register("libtiff")
    assert [row["target"] for row in engine.targets()] == ["libpng", "libtiff"]
    assert engine.states() == {"libpng": "active", "libtiff": "active"}
    with pytest.raises(fb.AllocError) as exc:
        engine.register("libpng")
    assert exc.value.code == "ALLOC_DUPLICATE_TARGET"
    with pytest.raises(fb.AllocError) as exc:
        engine.register("   ")
    assert exc.value.code == "ALLOC_BAD_TARGET"
    for weight in (0, -1, 100.5):
        with pytest.raises(fb.AllocError) as exc:
            engine.register("w-{0}".format(weight), weight=weight)
        assert exc.value.code == "ALLOC_BAD_WEIGHT"
    assert len(engine.targets()) == 2


def test_allocate_splits_budget_and_sums_exactly():
    engine = allocator()
    for name in ("zeta", "alpha", "mid"):
        engine.register(name)
    alloc = engine.allocate(1000)
    assert sorted(alloc) == ["alpha", "mid", "zeta"]
    assert list(alloc) == ["alpha", "mid", "zeta"]
    assert sum(alloc.values()) == 1000
    assert engine.round_no() == 1


def test_allocate_is_deterministic_for_same_sequence():
    def run():
        engine = allocator()
        for name in ("alpha", "beta", "gamma"):
            engine.register(name, weight=1.0)
        engine.allocate(900)
        engine.report_yield("beta", new_coverage=2, crashes=1)
        engine.allocate(900)
        engine.report_yield("alpha", crashes=1)
        return engine.allocate(900)

    first = run()
    second = run()
    assert first == second
    assert sum(first.values()) == 900
    assert sorted(first) == ["alpha", "beta", "gamma"]


def test_floor_is_granted_to_every_target():
    engine = allocator()
    for name in ("a", "b", "c"):
        engine.register(name)
    engine.allocate(1000)
    alloc = engine.allocate(192)
    assert alloc == {"a": 64, "b": 64, "c": 64}


def test_equal_targets_get_equal_share():
    engine = allocator()
    engine.register("a")
    engine.register("b")
    engine.allocate(1000)
    engine.allocate(1000)
    alloc = engine.allocate(1000)
    assert alloc == {"a": 500, "b": 500}


def test_weights_scale_remaining_budget():
    engine = allocator()
    engine.register("a", weight=1.0)
    engine.register("b", weight=3.0)
    engine.allocate(1000)
    engine.allocate(1000)
    alloc = engine.allocate(1000)
    assert alloc == {"a": 282, "b": 718}


def test_zero_yield_target_decays_below_producer():
    engine = allocator()
    engine.register("producer")
    engine.register("idle")
    engine.allocate(1028)
    engine.report_yield("producer", new_coverage=5, crashes=1)
    second = engine.allocate(1028)
    third = engine.allocate(1028)
    assert second["producer"] > second["idle"]
    assert third["idle"] < second["idle"]
    assert third["producer"] > third["idle"]
    assert third["idle"] >= 64
    assert third["producer"] + third["idle"] == 1028


def test_long_zero_yield_enters_observing_state():
    engine = allocator()
    engine.register("producer")
    engine.register("idle")
    for _ in range(3):
        engine.allocate(1028)
        engine.report_yield("producer", new_coverage=1)
    assert engine.states()["idle"] == "observing"
    assert engine.states()["producer"] == "active"
    assert engine.stats()["observing"] == 1
    alloc = engine.allocate(1028)
    assert alloc["idle"] >= 64
    assert alloc["idle"] < alloc["producer"]


def test_positive_yield_resets_zero_streak():
    engine = allocator()
    for name in ("a", "b", "c"):
        engine.register(name)
    engine.allocate(1000)
    engine.allocate(1000)
    assert engine.states()["c"] == "active"
    engine.report_yield("a", new_coverage=1)
    engine.report_yield("b", new_coverage=1)
    alloc = engine.allocate(1000)
    assert alloc["a"] == alloc["b"]
    assert alloc["c"] < alloc["a"]
    assert sum(alloc.values()) == 1000


def test_report_yield_validates_input():
    engine = allocator()
    engine.register("a")
    with pytest.raises(fb.AllocError) as exc:
        engine.report_yield("zz")
    assert exc.value.code == "ALLOC_UNKNOWN_TARGET"
    for kwargs in ({"new_coverage": -1}, {"crashes": -2}, {"new_coverage": "3"}):
        with pytest.raises(fb.AllocError) as exc:
            engine.report_yield("a", **kwargs)
        assert exc.value.code == "ALLOC_BAD_YIELD"
    out = engine.report_yield("a", new_coverage=4, crashes=2)
    assert out["score"] == 22
    assert out["yield_points"] == 22
    assert out["zero_streak"] == 0
    assert engine.stats()["yield_reports"] == 1


def test_consume_tracks_usage_and_rejects_overdraw():
    engine = allocator()
    engine.register("a")
    engine.register("b")
    alloc = engine.allocate(1000)
    usage = engine.usage()
    assert usage["round"] == 1
    assert usage["allocated"] == alloc
    assert usage["consumed"] == {"a": 0, "b": 0}
    assert usage["remaining"] == alloc
    left = engine.consume("a", 100)
    assert left == alloc["a"] - 100
    assert engine.usage()["consumed"]["a"] == 100
    with pytest.raises(fb.AllocError) as exc:
        engine.consume("a", 10 ** 6)
    assert exc.value.code == "ALLOC_BUDGET_EXHAUSTED"
    assert engine.usage()["consumed"]["a"] == 100
    for units in (0, -5, "7"):
        with pytest.raises(fb.AllocError) as exc:
            engine.consume("a", units)
        assert exc.value.code == "ALLOC_BAD_UNITS"
    with pytest.raises(fb.AllocError) as exc:
        engine.consume("zz", 1)
    assert exc.value.code == "ALLOC_UNKNOWN_TARGET"


def test_allocate_rejects_empty_pool_and_bad_budget():
    engine = allocator()
    with pytest.raises(fb.AllocError) as exc:
        engine.allocate(1000)
    assert exc.value.code == "ALLOC_NO_TARGETS"
    engine.register("a")
    for budget in (0, -10, "1000", 1.5):
        with pytest.raises(fb.AllocError) as exc:
            engine.allocate(budget)
        assert exc.value.code == "ALLOC_BAD_BUDGET"
    assert engine.round_no() == 0


def test_rebalance_matches_next_allocation():
    engine = allocator()
    engine.register("a")
    engine.register("b", weight=2.0)
    engine.allocate(1000)
    engine.report_yield("a", crashes=2)
    projection = engine.rebalance(total_budget=1000)
    assert engine.round_no() == 1
    assert engine.rebalance(total_budget=1000) == projection
    actual = engine.allocate(1000)
    assert actual == projection
    assert engine.round_no() == 2


def test_stats_track_rounds_and_totals():
    engine = allocator()
    engine.register("a")
    engine.register("b")
    first = engine.allocate(1000)
    engine.report_yield("a", new_coverage=2)
    second = engine.allocate(1000)
    engine.consume("b", 10)
    stats = engine.stats()
    assert stats["rounds"] == 2
    assert stats["targets"] == 2
    assert stats["observing"] == 0
    assert stats["yield_reports"] == 1
    assert stats["allocated_total"] == sum(first.values()) + sum(second.values())
    assert stats["consumed_total"] == 10


def test_snapshot_roundtrip_and_malformed_restore():
    engine = allocator()
    engine.register("a")
    engine.register("b")
    engine.allocate(1000)
    engine.report_yield("a", new_coverage=3)
    engine.allocate(1000)
    engine.consume("a", 50)
    state = engine.snapshot()
    clone = allocator()
    clone.restore(state)
    assert clone.usage() == engine.usage()
    assert clone.states() == engine.states()
    assert clone.stats() == engine.stats()
    assert clone.round_no() == 2
    missing = dict(state)
    missing.pop("targets")
    wrong_type = dict(state)
    wrong_type["targets"] = []
    for bad in (None, {}, {"version": 99}, missing, wrong_type):
        with pytest.raises(fb.AllocError) as exc:
            engine.restore(bad)
        assert exc.value.code == "ALLOC_SNAPSHOT_INVALID"
    assert engine.round_no() == 2
    assert clone.allocate(1000) == engine.allocate(1000)
