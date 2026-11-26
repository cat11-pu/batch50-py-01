import pytest

import io_budget_partitioner as io

DEV = "nvme0"
NOW = "2026-11-26T09:00:00+00:00"
T15 = "2026-11-26T09:00:15+00:00"
T40 = "2026-11-26T09:00:40+00:00"
EXPIRED = "2026-11-26T09:00:31+00:00"


def tree(**kwargs):
    planner = io.IoBudgetPartitioner()
    planner.add_device(DEV, capacity=4000, **kwargs)
    planner.add_group("root")
    planner.add_group("app", parent="root")
    planner.add_group("batch", parent="root")
    return planner


def test_limits_and_weighted_shares():
    planner = tree()
    planner.set_limit(DEV, "app", limit=4000, weight=1)
    planner.set_limit(DEV, "batch", limit=4000, weight=3)
    app = planner.status(DEV, "app")
    batch = planner.status(DEV, "batch")
    assert app["limit"] == 4000
    assert app["weight"] == 1
    assert app["share"] == 1000
    assert batch["share"] == 3000
    assert app["used"] == 0
    assert app["effective_limit"] == 4000
    assert app["available"] == 4000
    assert planner.stats()["devices"] == 1
    assert planner.stats()["groups"] == 3


def test_argument_and_identity_validation():
    planner = tree()
    with pytest.raises(io.IoBudgetError) as err:
        planner.set_limit(DEV, "app", limit=0)
    assert err.value.code == "IO_BUDGET_BAD_LIMIT"
    with pytest.raises(io.IoBudgetError) as err:
        planner.set_limit(DEV, "app", limit=-1)
    assert err.value.code == "IO_BUDGET_BAD_LIMIT"
    with pytest.raises(io.IoBudgetError) as err:
        planner.set_limit(DEV, "app", limit=100, weight=0)
    assert err.value.code == "IO_BUDGET_BAD_WEIGHT"
    with pytest.raises(io.IoBudgetError) as err:
        planner.set_limit(DEV, "ghost", limit=100)
    assert err.value.code == "IO_BUDGET_UNKNOWN"
    with pytest.raises(io.IoBudgetError) as err:
        planner.add_device(DEV, capacity=1)
    assert err.value.code == "IO_BUDGET_EXISTS"
    assert planner.stats()["denied"] == 5


def test_child_limits_cannot_exceed_parent():
    planner = tree()
    planner.set_limit(DEV, "root", limit=2000)
    planner.set_limit(DEV, "app", limit=1500)
    with pytest.raises(io.IoBudgetError) as err:
        planner.set_limit(DEV, "batch", limit=600)
    assert err.value.code == "IO_BUDGET_HIERARCHY"
    with pytest.raises(io.IoBudgetError) as err:
        planner.status(DEV, "batch")
    assert err.value.code == "IO_BUDGET_NO_LIMIT"
    planner.set_limit(DEV, "batch", limit=500)
    assert planner.status(DEV, "batch")["limit"] == 500
    assert planner.status(DEV, "app")["limit"] == 1500


def test_share_is_capped_and_leftover_redistributed():
    planner = tree()
    planner.set_limit(DEV, "app", limit=500, weight=1)
    planner.set_limit(DEV, "batch", limit=4000, weight=3)
    assert planner.status(DEV, "app")["share"] == 500
    assert planner.status(DEV, "batch")["share"] == 3500


def test_accounting_uses_actual_bytes():
    planner = tree()
    planner.set_limit(DEV, "app", limit=2000, weight=1)
    first = planner.account(DEV, "app", bytes_done=500, now=NOW)
    assert first["used"] == 500
    assert first["window_used"] == 500
    second = planner.account(DEV, "app", bytes_done=300, now=NOW)
    assert second["used"] == 800
    assert second["window_used"] == 800
    assert planner.status(DEV, "app")["available"] == 1200
    with pytest.raises(io.IoBudgetError) as err:
        planner.account(DEV, "app", bytes_done=0, now=NOW)
    assert err.value.code == "IO_BUDGET_BAD_ACCOUNT"


def test_usage_window_rolls_forward():
    planner = tree(window_seconds=10, windows=2)
    planner.set_limit(DEV, "app", limit=2000, weight=1)
    planner.account(DEV, "app", bytes_done=100, now=NOW)
    planner.account(DEV, "app", bytes_done=200, now=T15)
    assert planner.status(DEV, "app")["window_used"] == 300
    planner.account(DEV, "app", bytes_done=50, now=T40)
    assert planner.status(DEV, "app")["window_used"] == 50


def test_borrow_records_lenders_and_expiry():
    planner = tree()
    planner.set_limit(DEV, "app", limit=3000, weight=1)
    planner.set_limit(DEV, "batch", limit=1000, weight=1)
    planner.account(DEV, "app", bytes_done=500, now=NOW)
    grant = planner.borrow(DEV, "batch", amount=2500, ttl=30, now=NOW)
    assert grant["borrower"] == "batch"
    assert grant["amount"] == 2500
    assert grant["lenders"] == {"app": 2500}
    assert grant["expires_at"] == "2026-11-26T09:00:30+00:00"
    batch = planner.status(DEV, "batch")
    assert batch["borrowed_in"] == 2500
    assert batch["effective_limit"] == 3500
    app = planner.status(DEV, "app")
    assert app["borrowed_out"] == 2500
    assert app["available"] == 0


def test_borrow_beyond_spare_is_refused_without_side_effects():
    planner = tree()
    planner.set_limit(DEV, "app", limit=3000, weight=1)
    planner.set_limit(DEV, "batch", limit=1000, weight=1)
    planner.account(DEV, "app", bytes_done=2000, now=NOW)
    with pytest.raises(io.IoBudgetError) as err:
        planner.borrow(DEV, "batch", amount=1500, ttl=30, now=NOW)
    assert err.value.code == "IO_BUDGET_INSUFFICIENT"
    assert planner.status(DEV, "batch")["borrowed_in"] == 0
    assert planner.status(DEV, "app")["borrowed_out"] == 0
    assert planner.stats()["borrow_denied"] == 1


def test_status_reports_overuse_against_effective_limit():
    planner = tree()
    planner.set_limit(DEV, "app", limit=3000, weight=1)
    planner.set_limit(DEV, "batch", limit=1000, weight=1)
    planner.account(DEV, "app", bytes_done=500, now=NOW)
    planner.borrow(DEV, "batch", amount=2500, ttl=30, now=NOW)
    planner.account(DEV, "batch", bytes_done=4000, now=NOW)
    batch = planner.status(DEV, "batch")
    assert batch["used"] == 4000
    assert batch["over"] == 500
    assert batch["available"] == 0


def test_expired_grants_are_returned_to_lenders():
    planner = tree()
    planner.set_limit(DEV, "app", limit=3000, weight=1)
    planner.set_limit(DEV, "batch", limit=1000, weight=1)
    planner.account(DEV, "app", bytes_done=500, now=NOW)
    planner.borrow(DEV, "batch", amount=2500, ttl=30, now=NOW)
    early = planner.reclaim(DEV, now=NOW)
    assert early["expired"] == []
    assert early["returned"] == 0
    late = planner.reclaim(DEV, now=EXPIRED)
    assert late["expired"] == ["grant-1"]
    assert late["returned"] == 2500
    assert planner.status(DEV, "batch")["borrowed_in"] == 0
    assert planner.status(DEV, "batch")["effective_limit"] == 1000
    assert planner.status(DEV, "app")["borrowed_out"] == 0
    assert planner.stats()["reclaimed_grants"] == 1


def test_shrinking_a_limit_recalls_loans_first():
    planner = tree()
    planner.set_limit(DEV, "app", limit=3000, weight=1)
    planner.set_limit(DEV, "batch", limit=1000, weight=1)
    planner.account(DEV, "app", bytes_done=500, now=NOW)
    planner.borrow(DEV, "batch", amount=2500, ttl=30, now=NOW)
    out = planner.set_limit(DEV, "app", limit=1000)
    assert out["recalled"] == 1
    assert out["returned"] == 2500
    assert out["clamped"] is False
    assert planner.status(DEV, "app")["limit"] == 1000
    assert planner.status(DEV, "app")["borrowed_out"] == 0
    assert planner.status(DEV, "batch")["borrowed_in"] == 0


def test_hot_removing_a_device_leaves_other_devices_intact():
    planner = tree()
    planner.add_device("nvme1", capacity=8000)
    planner.set_limit(DEV, "app", limit=2000, weight=1)
    planner.set_limit("nvme1", "app", limit=6000, weight=1)
    planner.remove_device(DEV)
    with pytest.raises(io.IoBudgetError) as err:
        planner.status(DEV, "app")
    assert err.value.code == "IO_BUDGET_UNKNOWN"
    assert planner.status("nvme1", "app")["limit"] == 6000
    assert planner.stats()["devices"] == 1


def test_group_removal_requires_children_and_loans_settled():
    planner = tree()
    planner.add_group("worker", parent="app")
    with pytest.raises(io.IoBudgetError) as err:
        planner.remove_group("app")
    assert err.value.code == "IO_BUDGET_HAS_CHILDREN"
    planner.remove_group("worker")
    planner.set_limit(DEV, "app", limit=2000, weight=1)
    planner.set_limit(DEV, "batch", limit=1000, weight=1)
    planner.borrow(DEV, "batch", amount=500, ttl=30, now=NOW)
    with pytest.raises(io.IoBudgetError) as err:
        planner.remove_group("batch")
    assert err.value.code == "IO_BUDGET_UNSETTLED"
    planner.reclaim(DEV, now=EXPIRED)
    planner.remove_group("batch")
    planner.remove_group("app")
    with pytest.raises(io.IoBudgetError) as err:
        planner.status(DEV, "app")
    assert err.value.code == "IO_BUDGET_UNKNOWN"


def test_snapshot_round_trips_limits_usage_and_loans():
    planner = tree()
    planner.set_limit(DEV, "app", limit=3000, weight=1)
    planner.set_limit(DEV, "batch", limit=1000, weight=1)
    planner.account(DEV, "app", bytes_done=500, now=NOW)
    planner.borrow(DEV, "batch", amount=2500, ttl=30, now=NOW)
    snap = planner.snapshot()
    planner.reclaim(DEV, now=EXPIRED)
    assert planner.status(DEV, "batch")["borrowed_in"] == 0
    fresh = io.IoBudgetPartitioner()
    fresh.restore(snap)
    assert fresh.status(DEV, "app")["used"] == 500
    assert fresh.status(DEV, "app")["limit"] == 3000
    assert fresh.status(DEV, "app")["borrowed_out"] == 2500
    assert fresh.status(DEV, "batch")["borrowed_in"] == 2500
    assert fresh.status(DEV, "batch")["effective_limit"] == 3500


def test_invalid_snapshot_keeps_current_budget_table():
    planner = tree()
    planner.set_limit(DEV, "app", limit=2000, weight=1)
    planner.account(DEV, "app", bytes_done=400, now=NOW)
    with pytest.raises(io.IoBudgetError) as err:
        planner.restore({"devices": "not-a-table"})
    assert err.value.code == "IO_BUDGET_SNAPSHOT_INVALID"
    assert planner.status(DEV, "app")["limit"] == 2000
    assert planner.status(DEV, "app")["used"] == 400
    assert planner.stats()["devices"] == 1
    assert planner.stats()["groups"] == 3
