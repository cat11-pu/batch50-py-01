import copy
import threading

import pytest

import pkg_transaction_ledger as pt


def ledger():
    return pt.PkgTransactionLedger(lock_lease_ms=1000)


def seeded():
    led = ledger()
    led.seed_installed("nginx", "1.2.0")
    led.seed_installed("redis", "6.0.0")
    return led


def test_begin_validates_requests():
    led = seeded()
    cases = [
        (("", [{"op": "install", "package": "vim", "version": "9.0"}]),
         "PKG_INVALID_REQUEST"),
        (("ops", []), "PKG_INVALID_REQUEST"),
        (("ops", [{"op": "install", "package": "vim", "version": "9.0"},
                  {"op": "install", "package": "vim", "version": "9.1"}]),
         "PKG_INVALID_REQUEST"),
        (("ops", [{"op": "frobnicate", "package": "vim", "version": "9.0"}]),
         "PKG_INVALID_REQUEST"),
        (("ops", [{"op": "install", "package": "vim", "version": "9.x"}]),
         "PKG_INVALID_REQUEST"),
        (("ops", [{"op": "install", "version": "9.0"}]), "PKG_INVALID_REQUEST"),
        (("ops", [{"op": "install", "package": "nginx", "version": "1.3.0"}]),
         "PKG_ALREADY_INSTALLED"),
        (("ops", [{"op": "upgrade", "package": "vim", "version": "9.0"}]),
         "PKG_NOT_INSTALLED"),
        (("ops", [{"op": "upgrade", "package": "nginx", "version": "1.2.0"}]),
         "PKG_VERSION_CONFLICT"),
        (("ops", [{"op": "upgrade", "package": "nginx", "version": "1.1.0"}]),
         "PKG_VERSION_CONFLICT"),
        (("ops", [{"op": "remove", "package": "vim"}]), "PKG_NOT_INSTALLED"),
        (("ops", [{"op": "remove", "package": "nginx", "version": "1.3.0"}]),
         "PKG_VERSION_CONFLICT"),
    ]
    for (owner, requests), code in cases:
        with pytest.raises(pt.PkgError) as exc:
            led.begin(owner, requests, now=1000)
        assert exc.value.code == code
    assert led.holders() is None
    assert led.stats()["begun"] == 0


def test_begin_plans_steps_and_takes_lock():
    led = seeded()
    txid = led.begin("ops-a", [
        {"op": "install", "package": "vim", "version": "9.0"},
        {"op": "upgrade", "package": "nginx", "version": "1.3.0"},
        {"op": "remove", "package": "redis"},
    ], now=1000)
    assert txid == "tx-1"
    view = led.status(txid)
    assert (view.txid, view.owner, view.state) == ("tx-1", "ops-a", "open")
    assert (view.step_total, view.applied, view.lock_expires_at) == (3, 0, 2000)
    assert led.holders() == {"owner": "ops-a", "txid": "tx-1", "expires_at": 2000}
    steps = led.journal(txid)
    assert [(s.seq, s.op, s.package, s.from_version, s.to_version, s.state)
            for s in steps] == [
        (0, "install", "vim", None, "9.0", "pending"),
        (1, "upgrade", "nginx", "1.2.0", "1.3.0", "pending"),
        (2, "remove", "redis", "6.0.0", None, "pending"),
    ]
    assert led.installed() == {"nginx": "1.2.0", "redis": "6.0.0"}
    assert led.stats()["begun"] == 1


def test_global_lock_rejects_concurrent_begin_until_expiry():
    led = seeded()
    first = led.begin("ops-a", [{"op": "install", "package": "vim", "version": "9.0"}],
                      now=1000)
    with pytest.raises(pt.PkgError) as exc:
        led.begin("ops-b", [{"op": "install", "package": "git", "version": "2.0"}],
                  now=1500)
    assert exc.value.code == "PKG_LOCK_HELD"
    assert exc.value.detail["owner"] == "ops-a"
    assert exc.value.detail["txid"] == first
    assert exc.value.detail["expires_at"] == 2000

    second = led.begin("ops-b", [{"op": "install", "package": "git", "version": "2.0"}],
                       now=2001)
    assert second == "tx-2"
    assert led.status(first).state == "abandoned"
    assert led.holders()["owner"] == "ops-b"
    assert led.stats()["seized"] == 1


def test_stage_writes_intent_for_next_step_only():
    led = seeded()
    txid = led.begin("ops-a", [
        {"op": "install", "package": "vim", "version": "9.0"},
        {"op": "upgrade", "package": "nginx", "version": "1.3.0"},
    ], now=1000)
    first = led.stage(txid, now=1100)
    assert (first.seq, first.state, first.intent_at, first.applied_at) == (
        0, "staged", 1100, None)
    with pytest.raises(pt.PkgError) as exc:
        led.stage(txid, now=1150)
    assert exc.value.code == "PKG_STEP_STATE"
    assert led.installed("vim") is None
    assert led.stats()["staged"] == 1
    assert led.stats()["applied"] == 0


def test_commit_applies_steps_in_order_and_releases_lock():
    led = seeded()
    txid = led.begin("ops-a", [
        {"op": "install", "package": "vim", "version": "9.0"},
        {"op": "upgrade", "package": "nginx", "version": "1.3.0"},
        {"op": "remove", "package": "redis"},
    ], now=1000)
    out = led.commit(txid, now=1200)
    assert out == {"state": "committed", "applied": 3, "total": 3}
    assert led.status(txid).state == "committed"
    assert led.holders() is None
    assert led.installed() == {"vim": "9.0", "nginx": "1.3.0"}
    steps = led.journal(txid)
    assert [s.state for s in steps] == ["applied", "applied", "applied"]
    assert [s.applied_at for s in steps] == [1200, 1200, 1200]
    assert led.stats() == {"begun": 1, "staged": 3, "applied": 3, "committed": 1,
                           "aborted": 0, "recovered": 0, "seized": 0,
                           "reverted": 0}


def test_unknown_transaction_and_closed_operations():
    led = seeded()
    for call in [lambda: led.status("tx-99"), lambda: led.journal("tx-99"),
                 lambda: led.commit("tx-99", now=1), lambda: led.abort("tx-99", now=1),
                 lambda: led.recover("tx-99", now=1),
                 lambda: led.stage("tx-99", now=1)]:
        with pytest.raises(pt.PkgError) as exc:
            call()
        assert exc.value.code == "PKG_UNKNOWN_TRANSACTION"

    txid = led.begin("ops-a", [{"op": "install", "package": "vim", "version": "9.0"}],
                     now=10)
    led.commit(txid, now=20)
    with pytest.raises(pt.PkgError) as exc:
        led.commit(txid, now=30)
    assert exc.value.code == "PKG_TX_CLOSED"
    with pytest.raises(pt.PkgError) as exc:
        led.stage(txid, now=30)
    assert exc.value.code == "PKG_TX_CLOSED"


def test_commit_with_limit_stops_before_marker():
    led = seeded()
    txid = led.begin("ops-a", [
        {"op": "install", "package": "vim", "version": "9.0"},
        {"op": "upgrade", "package": "nginx", "version": "1.3.0"},
        {"op": "remove", "package": "redis"},
    ], now=1000)
    first = led.commit(txid, now=1100, limit=1)
    assert first == {"state": "applying", "applied": 1, "total": 3}
    assert led.status(txid).state == "applying"
    assert led.holders()["owner"] == "ops-a"
    assert led.installed() == {"vim": "9.0", "nginx": "1.2.0", "redis": "6.0.0"}
    assert [s.state for s in led.journal(txid)] == ["applied", "pending", "pending"]

    second = led.commit(txid, now=1200, limit=1)
    assert second == {"state": "applying", "applied": 2, "total": 3}
    assert led.installed() == {"vim": "9.0", "nginx": "1.3.0", "redis": "6.0.0"}

    final = led.commit(txid, now=1300)
    assert final == {"state": "committed", "applied": 3, "total": 3}
    assert led.installed() == {"vim": "9.0", "nginx": "1.3.0"}


def test_abort_reverts_applied_steps_in_reverse():
    led = seeded()
    txid = led.begin("ops-a", [
        {"op": "install", "package": "vim", "version": "9.0"},
        {"op": "upgrade", "package": "nginx", "version": "1.3.0"},
        {"op": "remove", "package": "redis"},
    ], now=1000)
    led.commit(txid, now=1100, limit=2)
    assert led.installed() == {"vim": "9.0", "nginx": "1.3.0", "redis": "6.0.0"}
    assert led.abort(txid, now=1200) == 2
    assert led.status(txid).state == "rolled_back"
    assert led.holders() is None
    assert led.installed() == {"nginx": "1.2.0", "redis": "6.0.0"}
    assert [s.state for s in led.journal(txid)] == ["reverted", "reverted", "pending"]
    assert led.stats()["reverted"] == 2
    assert led.stats()["aborted"] == 1


def test_abort_open_transaction_releases_lock_without_changes():
    led = seeded()
    txid = led.begin("ops-a", [{"op": "install", "package": "vim", "version": "9.0"}],
                     now=1000)
    assert led.abort(txid, now=1010) == 0
    assert led.status(txid).state == "rolled_back"
    assert led.holders() is None
    assert led.installed() == {"nginx": "1.2.0", "redis": "6.0.0"}
    assert led.abort(txid, now=1020) == 0
    assert led.stats()["aborted"] == 1


def test_recover_rolls_back_partially_applied_transaction():
    led = seeded()
    txid = led.begin("ops-a", [
        {"op": "install", "package": "vim", "version": "9.0"},
        {"op": "upgrade", "package": "nginx", "version": "1.3.0"},
    ], now=1000)
    led.commit(txid, now=1100, limit=1)
    out = led.recover(txid, now=5000)
    assert out == {"outcome": "rolled_back", "reverted": 1, "applied": 1}
    assert led.status(txid).state == "rolled_back"
    assert led.holders() is None
    assert led.installed() == {"nginx": "1.2.0", "redis": "6.0.0"}
    assert led.stats()["recovered"] == 1
    assert led.stats()["reverted"] == 1


def test_recover_discards_untouched_transaction():
    led = seeded()
    txid = led.begin("ops-a", [{"op": "install", "package": "vim", "version": "9.0"}],
                     now=1000)
    led.stage(txid, now=1050)
    out = led.recover(txid, now=4000)
    assert out == {"outcome": "discarded", "reverted": 0, "applied": 0}
    assert led.status(txid).state == "abandoned"
    assert led.holders() is None
    assert led.journal(txid)[0].state == "staged"


def test_recover_rejects_closed_transaction():
    led = seeded()
    txid = led.begin("ops-a", [{"op": "install", "package": "vim", "version": "9.0"}],
                     now=10)
    led.commit(txid, now=20)
    with pytest.raises(pt.PkgError) as exc:
        led.recover(txid, now=30)
    assert exc.value.code == "PKG_TX_CLOSED"


def test_snapshot_restore_resumes_after_restart():
    led = seeded()
    txid = led.begin("ops-a", [
        {"op": "install", "package": "vim", "version": "9.0"},
        {"op": "upgrade", "package": "nginx", "version": "1.3.0"},
    ], now=1000)
    led.commit(txid, now=1100, limit=1)
    state = led.snapshot()
    assert set(state) == {"version", "installed", "transactions", "steps",
                          "lock", "counters", "next_tx"}
    assert state["lock"]["txid"] == txid

    fresh = pt.PkgTransactionLedger(lock_lease_ms=1000)
    fresh.restore(copy.deepcopy(state))
    assert fresh.holders() == {"owner": "ops-a", "txid": txid, "expires_at": 2000}
    assert fresh.installed() == {"vim": "9.0", "nginx": "1.2.0", "redis": "6.0.0"}
    out = fresh.commit(txid, now=1200)
    assert out == {"state": "committed", "applied": 2, "total": 2}
    assert fresh.installed() == {"vim": "9.0", "nginx": "1.3.0"}
    assert fresh.journal(txid)[0].applied_at == 1100

    state["installed"].clear()
    assert led.installed() == {"vim": "9.0", "nginx": "1.2.0", "redis": "6.0.0"}


def test_restore_rejects_malformed_snapshot():
    led = seeded()
    txid = led.begin("ops-a", [{"op": "install", "package": "vim", "version": "9.0"}],
                     now=1000)
    bad_states = [
        None,
        {},
        {"version": 2, "installed": {}, "transactions": {}, "steps": {},
         "lock": None, "counters": {}, "next_tx": 1},
        {"version": 1, "installed": [], "transactions": {}, "steps": {},
         "lock": None, "counters": {}, "next_tx": 1},
        {"version": 1, "installed": {}, "transactions": [], "steps": {},
         "lock": None, "counters": {}, "next_tx": 1},
        {"version": 1, "installed": {}, "transactions": {}, "steps": {},
         "lock": None, "counters": [], "next_tx": 1},
    ]
    for bad in bad_states:
        with pytest.raises(pt.PkgError) as exc:
            led.restore(bad)
        assert exc.value.code == "PKG_SNAPSHOT_INVALID"
    assert led.status(txid).state == "open"
    assert led.holders()["txid"] == txid
    assert led.installed() == {"nginx": "1.2.0", "redis": "6.0.0"}


def test_concurrent_begin_allows_single_lock_holder():
    led = seeded()
    owners = [f"ops-{index}" for index in range(8)]
    txids = []
    errors = []
    barrier = threading.Barrier(len(owners))

    def worker(owner):
        try:
            barrier.wait(timeout=5)
            txids.append(led.begin(
                owner, [{"op": "install", "package": "vim", "version": "9.0"}],
                now=1000))
        except pt.PkgError as exc:
            errors.append(exc.code)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(owner,)) for owner in owners]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(txids) == 1
    assert errors == ["PKG_LOCK_HELD"] * 7
    assert led.stats()["begun"] == 1
    assert led.holders()["owner"] in owners
