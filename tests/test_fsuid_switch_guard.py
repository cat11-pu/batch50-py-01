import copy
import threading

import pytest

import fsuid_switch_guard as fg

BASE = (1000, 1000)


def guard(**kwargs):
    return fg.FsuidSwitchGuard(**kwargs)


def test_push_and_pop_restore_baseline():
    g = guard()
    handle = g.push_scope((1100, 1100), reason="scan")
    assert isinstance(handle, fg.ScopeHandle)
    assert handle.target == (1100, 1100)
    assert handle.depth == 1
    assert handle.deadline is None
    assert g.current_identity() == (1100, 1100)
    assert g.scope_depth() == 1
    assert g.pop_scope(handle) == BASE
    assert g.current_identity() == BASE
    assert g.scope_depth() == 0


def test_nested_scopes_pop_back_layer_by_layer():
    g = guard()
    outer = g.push_scope((1100, 1100))
    inner = g.push_scope((1200, 1200))
    assert g.current_identity() == (1200, 1200)
    assert g.scope_depth() == 2
    assert g.pop_scope(inner) == (1100, 1100)
    assert g.current_identity() == (1100, 1100)
    assert g.pop_scope(outer) == BASE
    assert g.current_identity() == BASE


def test_out_of_order_pop_is_rejected():
    g = guard()
    outer = g.push_scope((1100, 1100))
    g.push_scope((1200, 1200))
    with pytest.raises(fg.GuardError) as exc:
        g.pop_scope(outer)
    assert exc.value.code == "SCOPE_OUT_OF_ORDER"
    assert g.scope_depth() == 2
    assert g.current_identity() == (1200, 1200)
    assert g.audit_trail()[-1].ok is False


def test_invalid_targets_and_timeouts_are_rejected():
    g = guard()
    for bad in ("1000", (1000,), (1000, 1000, 0), (True, 1000), (-1, 1000), None,
                [1000, -2]):
        with pytest.raises(fg.GuardError) as exc:
            g.push_scope(bad)
        assert exc.value.code == "IDENTITY_INVALID"
    for kwargs in (dict(timeout=-1, now=1000), dict(timeout=10), dict(now=1000)):
        with pytest.raises(fg.GuardError) as exc:
            g.push_scope((1100, 1100), **kwargs)
        assert exc.value.code == "SCOPE_INVALID"
    assert g.scope_depth() == 0
    assert g.current_identity() == BASE


def test_elevation_denied_for_unprivileged_guard():
    g = guard()
    for target in ((0, 0), (500, 500)):
        with pytest.raises(fg.GuardError) as exc:
            g.push_scope(target)
        assert exc.value.code == "ELEVATION_DENIED"
    assert g.current_identity() == BASE
    assert g.scope_depth() == 0
    denied = [entry for entry in g.audit_trail() if not entry.ok]
    assert [entry.action for entry in denied] == ["denied", "denied"]
    assert [entry.identity_to for entry in denied] == [(0, 0), (500, 500)]


def test_privileged_guard_may_drop_to_root_and_plain_guard_may_lower():
    g = guard(privileged=True)
    handle = g.push_scope((0, 0), reason="setuid helper")
    assert g.current_identity() == (0, 0)
    assert g.pop_scope(handle) == BASE

    plain = guard()
    plain.push_scope((1100, 1100))
    assert plain.current_identity() == (1100, 1100)


def test_max_depth_is_enforced():
    g = guard(max_depth=2)
    g.push_scope((1100, 1100))
    g.push_scope((1200, 1200))
    with pytest.raises(fg.GuardError) as exc:
        g.push_scope((1300, 1300))
    assert exc.value.code == "DEPTH_EXCEEDED"
    assert g.scope_depth() == 2
    assert g.current_identity() == (1200, 1200)
    assert g.stats()["denied"] == 1


def test_audit_trail_order_identity_and_limit():
    g = guard()
    g.push_scope((1100, 1100), reason="open")
    inner = g.push_scope((1200, 1200), reason="write")
    g.pop_scope(inner)
    g.push_scope((1300, 1300), reason="verify")

    entries = g.audit_trail()
    assert [entry.action for entry in entries] == ["push", "push", "pop", "push"]
    assert [entry.seq for entry in entries] == [1, 2, 3, 4]
    assert all(entry.ok for entry in entries)
    assert entries[0].identity_from == BASE
    assert entries[0].identity_to == (1100, 1100)
    assert entries[2].identity_from == (1200, 1200)
    assert entries[2].identity_to == (1100, 1100)
    assert entries[0].reason == "open"

    tail = g.audit_trail(limit=2)
    assert [entry.seq for entry in tail] == [3, 4]
    assert [entry.action for entry in tail] == ["pop", "push"]


def test_tick_expires_scopes_and_forces_baseline():
    g = guard()
    handle = g.push_scope((1100, 1100), timeout=30, now=1000)
    assert handle.deadline == 1030
    assert g.tick(1029) == 0
    assert g.current_identity() == (1100, 1100)
    assert g.tick(1030) == 1
    assert g.current_identity() == BASE
    assert g.scope_depth() == 0
    assert g.tick(1200) == 0
    assert g.stats()["expired_scopes"] == 1
    assert g.stats()["forced_returns"] == 1


def test_force_baseline_unwinds_all_scopes_once():
    g = guard()
    g.push_scope((1100, 1100))
    g.push_scope((1200, 1200))
    stale = g.push_scope((1300, 1300))
    assert g.force_baseline(reason="shutdown") == BASE
    assert g.current_identity() == BASE
    assert g.scope_depth() == 0
    assert g.stats()["forced_returns"] == 1
    assert g.audit_trail()[-1].action == "force_baseline"
    count = len(g.audit_trail())

    assert g.force_baseline() == BASE
    assert g.stats()["forced_returns"] == 1
    assert len(g.audit_trail()) == count
    with pytest.raises(fg.GuardError) as exc:
        g.pop_scope(stale)
    assert exc.value.code == "SCOPE_OUT_OF_ORDER"


def test_set_baseline_only_when_idle():
    g = guard()
    handle = g.push_scope((1100, 1100))
    with pytest.raises(fg.GuardError) as exc:
        g.set_baseline(1300, 1300)
    assert exc.value.code == "GUARD_BUSY"
    assert g.baseline == BASE

    g.pop_scope(handle)
    assert g.set_baseline(1300, 1300) == (1300, 1300)
    assert g.current_identity() == (1300, 1300)
    g.push_scope((1400, 1400))
    assert g.current_identity() == (1400, 1400)
    with pytest.raises(fg.GuardError) as exc:
        g.push_scope((1200, 1200))
    assert exc.value.code == "ELEVATION_DENIED"


def test_stats_count_each_action():
    g = guard()
    g.push_scope((1100, 1100))
    second = g.push_scope((1200, 1200))
    with pytest.raises(fg.GuardError):
        g.push_scope((0, 0))
    g.pop_scope(second)
    g.force_baseline()
    g.push_scope((1300, 1300), timeout=10, now=1000)
    assert g.tick(1010) == 1
    g.inject_fault("gid", times=2)
    assert g.stats() == {
        "pushes": 3,
        "pops": 1,
        "denied": 1,
        "forced_returns": 2,
        "expired_scopes": 1,
        "depth_peak": 2,
        "faults_injected": 2,
    }


def test_snapshot_is_detached_and_restore_validates():
    g = guard()
    g.push_scope((1100, 1100))
    g.push_scope((1200, 1200))
    state = g.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"schema", "baseline", "workers", "seq", "stats"}
    assert pristine["schema"] == fg.SCHEMA_VERSION

    state["workers"].clear()
    state["stats"]["pushes"] = 99
    assert g.scope_depth() == 2
    assert g.current_identity() == (1200, 1200)

    clone = guard()
    clone.restore(pristine)
    assert clone.current_identity() == (1200, 1200)
    assert clone.scope_depth() == 2
    assert clone.stats()["pushes"] == 2
    assert clone.audit_trail()[0].seq == 1

    for bad in (None, {}, {"schema": 1, "baseline": [1000, 1000], "workers": {},
                           "seq": 0},
                {"schema": 1, "baseline": [1000, 1000], "workers": [], "seq": 0,
                 "stats": g.stats()}):
        with pytest.raises(fg.GuardError) as exc:
            g.restore(bad)
        assert exc.value.code == "SNAPSHOT_INVALID"
    assert g.scope_depth() == 2


def test_threads_have_isolated_scopes():
    g = guard()
    outer = g.push_scope((1100, 1100))
    seen = {}
    ready = threading.Event()
    release = threading.Event()

    def worker():
        g.push_scope((1200, 1200))
        seen["inside"] = g.current_identity()
        seen["depth"] = g.scope_depth()
        g.force_baseline()
        seen["after"] = g.current_identity()
        ready.set()
        release.wait(timeout=5)

    thread = threading.Thread(target=worker)
    thread.start()
    assert ready.wait(timeout=5)
    assert seen == {"inside": (1200, 1200), "depth": 1, "after": BASE}
    assert g.current_identity() == (1100, 1100)
    assert g.scope_depth() == 1
    release.set()
    thread.join()

    assert g.pop_scope(outer) == BASE
    assert g.stats()["pushes"] == 2
    assert g.stats()["forced_returns"] == 1


def test_concurrent_pushes_keep_audit_sequence_dense():
    g = guard()
    workers = 8
    rounds = 3
    barrier = threading.Barrier(workers)
    errors = []

    def worker():
        try:
            barrier.wait(timeout=5)
            for _ in range(rounds):
                handle = g.push_scope((1100, 1100))
                assert g.current_identity() == (1100, 1100)
                g.pop_scope(handle)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert g.current_identity() == BASE
    stats = g.stats()
    assert stats["pushes"] == workers * rounds
    assert stats["pops"] == workers * rounds
    assert stats["depth_peak"] == 1
    entries = g.audit_trail()
    assert len(entries) == workers * rounds * 2
    assert [entry.seq for entry in entries] == list(range(1, len(entries) + 1))

