import pytest

import mlock_budget_ledger as ml

NOW = "2026-11-26T09:00:00+00:00"
LATER = "2026-11-26T09:00:30+00:00"
EXPIRED_AT = "2026-11-26T09:01:01+00:00"


def ledger(**kwargs):
    return ml.MlockBudgetLedger(**kwargs)


def unit(led, unit_id="u1", *, soft=4096, hard=65536, priority=0,
         privileged=False):
    return led.register_unit(unit_id, soft_limit=soft, hard_limit=hard,
                             priority=priority, privileged=privileged, now=NOW)


def hold(led, size=4096, *, unit_id="u1", pid=100, start_time=111,
         exe="/usr/bin/worker"):
    return led.reserve(unit_id, pid=pid, start_time=start_time, exe=exe,
                       size=size, now=NOW)


def test_register_unit_sorted_and_duplicate():
    led = ledger()
    unit(led, "beta")
    unit(led, "alpha")
    assert [u.unit_id for u in led.units()] == ["alpha", "beta"]
    with pytest.raises(ml.MlockError) as exc:
        unit(led, "alpha")
    assert exc.value.code == "MLOCK_DUPLICATE_UNIT"
    assert led.stats()["units"] == 2


def test_unknown_unit_rejected():
    led = ledger()
    with pytest.raises(ml.MlockError) as exc:
        hold(led, unit_id="ghost")
    assert exc.value.code == "MLOCK_UNKNOWN_UNIT"
    with pytest.raises(ml.MlockError) as second:
        led.status("ghost")
    assert second.value.code == "MLOCK_UNKNOWN_UNIT"


def test_reserve_holds_bytes_without_commit():
    led = ledger()
    unit(led)
    reservation = hold(led, 4096)
    assert reservation.size == 4096
    assert reservation.pid == 100
    assert reservation.start_time == 111
    assert reservation.committed is False
    state = led.status("u1")
    assert state.reserved == 4096
    assert state.committed == 0


def test_commit_moves_reserved_to_committed():
    led = ledger()
    unit(led)
    reservation = hold(led, 4096)
    assert led.commit(reservation.reservation_id, now=LATER) == 4096
    state = led.status("u1")
    assert state.committed == 4096
    assert state.reserved == 0


def test_hard_limit_rejected():
    led = ledger()
    unit(led, soft=8192, hard=8192)
    with pytest.raises(ml.MlockError) as exc:
        hold(led, 9000)
    assert exc.value.code == "MLOCK_HARD_LIMIT"
    assert led.status("u1").reserved == 0
    assert led.status("u1").committed == 0


def test_soft_limit_warns_but_allows():
    led = ledger()
    unit(led, soft=4096, hard=16384)
    reservation = hold(led, 8192)
    led.commit(reservation.reservation_id, now=LATER)
    state = led.status("u1")
    assert state.committed == 8192
    assert state.over_soft is True
    assert led.stats()["soft_warnings"] == 1


def test_host_limit_rejected():
    led = ledger(host_limit=8192, reserved_pool=2048)
    unit(led, soft=4096, hard=8192)
    with pytest.raises(ml.MlockError) as exc:
        hold(led, 7000)
    assert exc.value.code == "MLOCK_HOST_LIMIT"
    assert led.status("u1").reserved == 0


def test_release_committed_returns_bytes():
    led = ledger()
    unit(led)
    reservation = hold(led, 4096)
    led.commit(reservation.reservation_id, now=LATER)
    assert led.release(reservation.reservation_id, now=LATER) == 4096
    state = led.status("u1")
    assert state.committed == 0
    assert state.reserved == 0


def test_release_uncommitted_returns_zero():
    led = ledger()
    unit(led)
    reservation = hold(led, 4096)
    assert led.release(reservation.reservation_id, now=LATER) == 0
    state = led.status("u1")
    assert state.reserved == 0
    assert state.committed == 0


def test_expired_reservation_reclaimed():
    led = ledger()
    unit(led)
    reservation = hold(led, 4096)
    expired = led.expire_reservations(now=EXPIRED_AT)
    assert expired == [reservation.reservation_id]
    assert led.status("u1").reserved == 0
    assert led.stats()["expired"] == 1


def test_unknown_reservation_rejected():
    led = ledger()
    unit(led)
    with pytest.raises(ml.MlockError) as exc:
        led.commit("no-such-reservation", now=LATER)
    assert exc.value.code == "MLOCK_UNKNOWN_RESERVATION"
    with pytest.raises(ml.MlockError) as second:
        led.release("no-such-reservation", now=LATER)
    assert second.value.code == "MLOCK_UNKNOWN_RESERVATION"


def test_process_exit_reclaims_committed():
    led = ledger()
    unit(led)
    reservation = hold(led, 4096, pid=4242, start_time=999)
    led.commit(reservation.reservation_id, now=LATER)
    freed = led.process_exit(4242, start_time=999, exe="/usr/bin/worker", now=LATER)
    assert freed == [reservation.reservation_id]
    assert led.status("u1").committed == 0
    assert led.stats()["reclaimed"] == 1


def test_remove_unit_requires_zero_usage():
    led = ledger()
    unit(led)
    reservation = hold(led, 4096)
    led.commit(reservation.reservation_id, now=LATER)
    with pytest.raises(ml.MlockError) as exc:
        led.remove_unit("u1")
    assert exc.value.code == "MLOCK_UNIT_NOT_EMPTY"
    led.release(reservation.reservation_id, now=LATER)
    assert led.remove_unit("u1") == 1
    assert led.units() == []


def test_status_reports_remaining_hard():
    led = ledger()
    unit(led, soft=4096, hard=16384)
    committed = hold(led, 4096)
    led.commit(committed.reservation_id, now=LATER)
    hold(led, 2048, pid=101, start_time=222)
    state = led.status("u1")
    assert state.hard_limit == 16384
    assert state.committed == 4096
    assert state.reserved == 2048
    assert state.remaining_hard == 10240
    assert state.over_soft is False


def test_snapshot_roundtrip_and_invalid_state():
    led = ledger()
    unit(led)
    committed = hold(led, 4096)
    led.commit(committed.reservation_id, now=LATER)
    hold(led, 2048, pid=101, start_time=222)
    state = led.snapshot()
    clone = ledger()
    clone.restore(state)
    assert [u.unit_id for u in clone.units()] == ["u1"]
    assert clone.status("u1").committed == 4096
    assert clone.status("u1").reserved == 2048
    with pytest.raises(ml.MlockError) as exc:
        clone.restore({"bogus": True})
    assert exc.value.code == "MLOCK_SNAPSHOT_INVALID"
    assert clone.status("u1").committed == 4096
