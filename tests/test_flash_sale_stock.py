import threading

import pytest

import flash_sale_stock as fs

NOW = 1_800_000_000


def sale(**kwargs):
    kwargs.setdefault("total_stock", 5)
    kwargs.setdefault("per_account_limit", 2)
    kwargs.setdefault("hold_ttl", 600)
    return fs.FlashSaleStock(**kwargs)


def opened(**kwargs):
    instance = sale(**kwargs)
    instance.open_session("flash-1", now=NOW)
    return instance


def test_open_session_publishes_stock_and_quota():
    instance = sale()
    info = instance.open_session("flash-1", now=NOW)
    assert info["session_id"] == "flash-1"
    assert info["total_stock"] == 5
    assert info["per_account_limit"] == 2
    assert info["hold_ttl"] == 600
    assert info["status"] == "open"
    assert info["closed_at"] is None
    assert instance.stock_of() == 5
    assert instance.quota_of("acct-a") == 2
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.open_session("flash-2", now=NOW + 1)
    assert exc.value.code == "FLASH_SESSION_ACTIVE"
    broken = fs.FlashSaleStock(total_stock=0, per_account_limit=2,
                               hold_ttl=600)
    with pytest.raises(fs.FlashSaleError) as exc:
        broken.open_session("flash-1", now=NOW)
    assert exc.value.code == "FLASH_INVALID_CONFIG"


def test_reserve_holds_stock_and_quota():
    instance = opened()
    reservation = instance.reserve("o-1", "acct-a", 2, now=NOW)
    assert reservation.order_id == "o-1"
    assert reservation.account == "acct-a"
    assert reservation.qty == 2
    assert reservation.status == "held"
    assert reservation.created_at == NOW
    assert reservation.expires_at == NOW + 600
    assert instance.stock_of() == 3
    assert instance.quota_of("acct-a") == 0
    assert instance.order_of("o-1") == reservation
    assert instance.stats()["reservations"] == 1


def test_reserve_validates_quantity_and_order_id():
    instance = opened()
    for qty in (0, -1, "two"):
        with pytest.raises(fs.FlashSaleError) as exc:
            instance.reserve("o-1", "acct-a", qty, now=NOW)
        assert exc.value.code == "FLASH_INVALID_REQUEST"
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.reserve("", "acct-a", 1, now=NOW)
    assert exc.value.code == "FLASH_INVALID_REQUEST"
    assert instance.stock_of() == 5


def test_reserve_beyond_stock_is_refused():
    instance = opened()
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.reserve("o-1", "acct-a", 6, now=NOW)
    assert exc.value.code == "FLASH_INSUFFICIENT_STOCK"
    assert instance.stock_of() == 5
    assert instance.quota_of("acct-a") == 2
    assert instance.stats()["stock_refusals"] == 1


def test_reserve_beyond_account_quota_is_refused():
    instance = opened(total_stock=10)
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.reserve("o-1", "acct-a", 3, now=NOW)
    assert exc.value.code == "FLASH_QUOTA_EXCEEDED"
    assert instance.stock_of() == 10
    assert instance.quota_of("acct-a") == 2
    assert instance.stats()["quota_refusals"] == 1


def test_duplicate_order_id_is_refused():
    instance = opened()
    instance.reserve("o-1", "acct-a", 1, now=NOW)
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.reserve("o-1", "acct-b", 1, now=NOW + 10)
    assert exc.value.code == "FLASH_DUPLICATE_ORDER"
    assert instance.stock_of() == 4
    assert instance.stats()["duplicate_orders"] == 1


def test_commit_deducts_stock_and_is_not_repeatable():
    instance = opened()
    instance.reserve("o-1", "acct-a", 2, now=NOW)
    committed = instance.commit("o-1", now=NOW + 10)
    assert committed.status == "committed"
    assert instance.stock_of() == 3
    assert instance.quota_of("acct-a") == 0
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.commit("o-1", now=NOW + 20)
    assert exc.value.code == "FLASH_ALREADY_COMMITTED"
    assert instance.stats()["committed_orders"] == 1


def test_unknown_order_and_release_of_committed_order():
    instance = opened()
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.commit("ghost", now=NOW)
    assert exc.value.code == "FLASH_UNKNOWN_ORDER"
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.order_of("ghost")
    assert exc.value.code == "FLASH_UNKNOWN_ORDER"
    instance.reserve("o-1", "acct-a", 1, now=NOW)
    instance.commit("o-1", now=NOW + 10)
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.release("o-1", now=NOW + 20)
    assert exc.value.code == "FLASH_NOT_HELD"


def test_release_returns_stock_and_quota():
    instance = opened()
    instance.reserve("o-1", "acct-a", 2, now=NOW)
    released = instance.release("o-1", now=NOW + 10)
    assert released.status == "released"
    assert instance.stock_of() == 5
    assert instance.quota_of("acct-a") == 2
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.release("o-1", now=NOW + 20)
    assert exc.value.code == "FLASH_NOT_HELD"
    assert instance.stats()["released_orders"] == 1


def test_expire_reservations_releases_only_due_holds():
    instance = opened()
    instance.reserve("o-1", "acct-a", 2, now=NOW)
    instance.reserve("o-2", "acct-b", 1, now=NOW + 300)
    assert instance.stock_of() == 2
    released = instance.expire_reservations(now=NOW + 600)
    assert released == 1
    assert instance.order_of("o-1").status == "expired"
    assert instance.order_of("o-2").status == "held"
    assert instance.stock_of() == 4
    assert instance.stats()["expired_orders"] == 1
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.commit("o-1", now=NOW + 610)
    assert exc.value.code == "FLASH_NOT_HELD"


def test_close_session_blocks_new_reservations():
    instance = opened()
    info = instance.close_session(now=NOW + 60)
    assert info["status"] == "closed"
    assert info["closed_at"] == NOW + 60
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.reserve("o-1", "acct-a", 1, now=NOW + 70)
    assert exc.value.code == "FLASH_SESSION_CLOSED"
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.close_session(now=NOW + 80)
    assert exc.value.code == "FLASH_SESSION_CLOSED"


def test_stats_track_reservation_outcomes():
    instance = opened(total_stock=10)
    instance.reserve("o-1", "acct-a", 2, now=NOW)
    instance.commit("o-1", now=NOW + 10)
    instance.reserve("o-2", "acct-b", 1, now=NOW + 20)
    instance.release("o-2", now=NOW + 30)
    with pytest.raises(fs.FlashSaleError):
        instance.reserve("o-1", "acct-b", 1, now=NOW + 40)
    with pytest.raises(fs.FlashSaleError):
        instance.reserve("o-3", "acct-b", 3, now=NOW + 50)
    with pytest.raises(fs.FlashSaleError):
        instance.reserve("o-4", "acct-c", 11, now=NOW + 60)
    counters = instance.stats()
    assert counters["sessions"] == 1
    assert counters["reservations"] == 2
    assert counters["committed_orders"] == 1
    assert counters["released_orders"] == 1
    assert counters["expired_orders"] == 0
    assert counters["duplicate_orders"] == 1
    assert counters["quota_refusals"] == 1
    assert counters["stock_refusals"] == 1


def test_account_quotas_are_independent():
    instance = opened(total_stock=10)
    instance.reserve("o-1", "acct-a", 2, now=NOW)
    instance.reserve("o-2", "acct-b", 2, now=NOW)
    assert instance.stock_of() == 6
    assert instance.quota_of("acct-a") == 0
    assert instance.quota_of("acct-b") == 0
    with pytest.raises(fs.FlashSaleError) as exc:
        instance.reserve("o-3", "acct-a", 1, now=NOW + 10)
    assert exc.value.code == "FLASH_QUOTA_EXCEEDED"


def test_snapshot_roundtrip_and_invalid_restore():
    instance = opened()
    instance.reserve("o-1", "acct-a", 2, now=NOW)
    instance.commit("o-1", now=NOW + 10)
    instance.reserve("o-2", "acct-b", 1, now=NOW + 20)
    snap = instance.snapshot()
    fresh = sale()
    fresh.restore(snap)
    assert fresh.stock_of() == instance.stock_of()
    assert fresh.quota_of("acct-a") == instance.quota_of("acct-a")
    assert fresh.order_of("o-2").status == "held"
    instance.commit("o-2", now=NOW + 30)
    assert fresh.order_of("o-2").status == "held"
    before = fresh.stock_of()
    with pytest.raises(fs.FlashSaleError) as exc:
        fresh.restore({"orders": [], "session": {}})
    assert exc.value.code == "FLASH_SNAPSHOT_INVALID"
    assert fresh.stock_of() == before


def test_concurrent_reserves_do_not_oversell():
    instance = sale(total_stock=1, per_account_limit=1, hold_ttl=600)
    instance.open_session("flash-1", now=NOW)
    barrier = threading.Barrier(10)
    granted = []
    refused = []
    errors = []
    lock = threading.Lock()

    def worker(index):
        try:
            barrier.wait(timeout=5)
            order = instance.reserve(f"o-{index}", f"acct-{index}", 1,
                                     now=NOW)
            with lock:
                granted.append(order.order_id)
        except fs.FlashSaleError as exc:
            with lock:
                refused.append(exc.code)
        except BaseException as exc:  # noqa: BLE001 - collected for assert
            with lock:
                errors.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == []
    assert len(granted) == 1
    assert refused == ["FLASH_INSUFFICIENT_STOCK"] * 9
    assert instance.stock_of() == 0
    assert instance.stats()["reservations"] == 1
