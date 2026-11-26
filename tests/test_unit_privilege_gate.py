import copy
import threading

import pytest

import unit_privilege_gate as u


def gate(**kwargs):
    return u.UnitPrivilegeGate(**kwargs)


def unit(g, name, *, user="root", capabilities=(), no_new_privs=True,
         requires=()):
    return g.register_unit(name, user=user, capabilities=list(capabilities),
                           no_new_privs=no_new_privs, requires=list(requires))


def test_register_validates_name_and_duplicates():
    g = gate()
    unit(g, "base")
    with pytest.raises(u.UnitGateError) as exc:
        unit(g, "base")
    assert exc.value.code == "UNIT_ALREADY_REGISTERED"
    for bad in ("", "Bad", "has space", "x" * 65):
        with pytest.raises(u.UnitGateError) as exc:
            unit(g, bad)
        assert exc.value.code == "UNIT_INVALID_REQUEST"
    assert g.units() == ("base",)

    small = gate(max_units=2)
    unit(small, "a")
    unit(small, "b")
    with pytest.raises(u.UnitGateError) as exc:
        unit(small, "c")
    assert exc.value.code == "UNIT_CAPACITY_EXCEEDED"


def test_register_rejects_unknown_capability_and_bad_types():
    g = gate()
    with pytest.raises(u.UnitGateError) as exc:
        unit(g, "a", capabilities=["CAP_MAGIC"])
    assert exc.value.code == "UNIT_UNKNOWN_CAPABILITY"
    with pytest.raises(u.UnitGateError) as exc:
        g.register_unit("a", user="root", capabilities="CAP_KILL")
    assert exc.value.code == "UNIT_INVALID_REQUEST"
    with pytest.raises(u.UnitGateError) as exc:
        g.register_unit("a", user="root", capabilities=["CAP_KILL", ""])
    assert exc.value.code == "UNIT_INVALID_REQUEST"

    spec = unit(g, "worker", user="app",
                capabilities=["CAP_NET_BIND_SERVICE", "CAP_KILL"])
    assert spec.capabilities == ("CAP_KILL", "CAP_NET_BIND_SERVICE")
    assert spec.no_new_privs is True
    assert spec.requires == ()


def test_privilege_escalation_and_no_new_privs_are_refused():
    g = gate()
    with pytest.raises(u.UnitGateError) as exc:
        unit(g, "evil", user="app", capabilities=["CAP_SYS_ADMIN"])
    assert exc.value.code == "UNIT_PRIVILEGE_ESCALATION"
    with pytest.raises(u.UnitGateError) as exc:
        unit(g, "lax", user="app", capabilities=["CAP_KILL"], no_new_privs=False)
    assert exc.value.code == "UNIT_NO_NEW_PRIVS_REQUIRED"
    assert g.units() == ()

    root_spec = unit(g, "engine", capabilities=["CAP_SYS_ADMIN"])
    assert root_spec.capabilities == ("CAP_SYS_ADMIN",)


def test_plan_start_expands_dependencies_in_order():
    g = gate()
    unit(g, "base")
    unit(g, "cache")
    unit(g, "db", requires=["base", "cache"])
    unit(g, "api", requires=["db"])

    plan = g.plan_start("api")
    assert plan.target == "api"
    assert plan.ordered == ("base", "cache", "db", "api")
    assert plan.effective["db"] == ()
    with pytest.raises(u.UnitGateError) as exc:
        g.plan_start("missing")
    assert exc.value.code == "UNIT_UNKNOWN_UNIT"


def test_plan_detects_dependency_cycle():
    g = gate()
    unit(g, "a", requires=["b"])
    unit(g, "b", requires=["a"])
    with pytest.raises(u.UnitGateError) as exc:
        g.plan_start("a")
    assert exc.value.code == "UNIT_DEPENDENCY_CYCLE"


def test_plan_rejects_unknown_dependency():
    g = gate()
    unit(g, "api", requires=["ghost"])
    with pytest.raises(u.UnitGateError) as exc:
        g.plan_start("api")
    assert exc.value.code == "UNIT_UNKNOWN_DEPENDENCY"
    with pytest.raises(u.UnitGateError) as exc:
        g.start_unit("ghost")
    assert exc.value.code == "UNIT_UNKNOWN_UNIT"


def test_start_unit_requires_dependencies_running():
    g = gate()
    unit(g, "db")
    unit(g, "api", requires=["db"])
    with pytest.raises(u.UnitGateError) as exc:
        g.start_unit("api")
    assert exc.value.code == "UNIT_DEPENDENCY_NOT_RUNNING"
    assert g.unit_state("api") == "registered"

    g.start_unit("db")
    result = g.start_unit("api")
    assert result.started is True
    assert result.state == "running"


def test_start_unit_records_effective_caps_and_state():
    g = gate()
    unit(g, "engine", capabilities=["CAP_SYS_ADMIN", "CAP_NET_BIND_SERVICE"])
    result = g.start_unit("engine")
    assert result.started is True
    assert result.unit == "engine"
    assert result.effective_caps == ("CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN")
    assert g.effective_capabilities("engine") == (
        "CAP_NET_BIND_SERVICE", "CAP_SYS_ADMIN")
    assert g.unit_state("engine") == "running"
    assert g.running_units() == ("engine",)


def test_start_is_idempotent_and_counts_once():
    g = gate()
    unit(g, "worker", user="app", capabilities=["CAP_KILL"])
    assert g.start_unit("worker").started is True
    again = g.start_unit("worker")
    assert again.started is False
    assert again.state == "running"
    assert again.effective_caps == ("CAP_KILL",)
    assert g.stats()["started"] == 1
    assert g.stats()["already_running"] == 1


def test_stop_refused_while_dependents_running():
    g = gate()
    unit(g, "db")
    unit(g, "api", requires=["db"])
    g.start_unit("db")
    g.start_unit("api")
    with pytest.raises(u.UnitGateError) as exc:
        g.stop_unit("db")
    assert exc.value.code == "UNIT_DEPENDENTS_RUNNING"
    assert g.unit_state("db") == "running"
    assert g.unit_state("api") == "running"


def test_stop_cascade_stops_subtree():
    g = gate()
    unit(g, "base")
    unit(g, "api", requires=["base"])
    unit(g, "worker", requires=["api"])
    for name in ("base", "api", "worker"):
        g.start_unit(name)

    result = g.stop_unit("base", cascade=True)
    assert result.outcome == "stopped"
    assert set(result.stopped) == {"base", "api", "worker"}
    for name in ("base", "api", "worker"):
        assert g.unit_state(name) == "stopped"
    assert g.running_units() == ()
    assert g.stats()["stopped"] == 3


def test_start_batch_rolls_back_on_unknown_dependency():
    g = gate()
    unit(g, "base")
    unit(g, "api", requires=["base"])
    unit(g, "orphan", requires=["ghost"])

    result = g.start_batch(["api", "orphan"])
    assert result.status == "rolled_back"
    assert result.failed == "orphan"
    assert result.code == "UNIT_UNKNOWN_DEPENDENCY"
    assert set(result.started) == {"base", "api"}
    assert set(result.rolled_back) == {"base", "api"}
    assert g.unit_state("base") == "stopped"
    assert g.unit_state("api") == "stopped"
    assert g.running_units() == ()
    assert g.stats()["rolled_back"] == 2


def test_concurrent_start_of_same_unit_yields_one_started():
    g = gate()
    unit(g, "worker")
    workers = 10
    results = []
    errors = []
    barrier = threading.Barrier(workers)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(g.start_unit("worker"))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert sum(1 for item in results if item.started) == 1
    assert all(item.state == "running" for item in results)
    assert g.stats()["started"] == 1
    assert g.stats()["already_running"] == workers - 1


def test_snapshot_restore_roundtrip():
    g = gate()
    unit(g, "base")
    unit(g, "api", requires=["base"])
    g.start_unit("base")
    g.start_unit("api")

    snap = g.snapshot()
    assert set(snap) == {"version", "units", "audit", "counters", "stats"}
    pristine = copy.deepcopy(snap)

    snap["stats"]["started"] = 99
    snap["units"].clear()
    assert g.stats()["started"] == 2
    assert len(g.audit_entries()) == 2

    clone = gate()
    clone.restore(pristine)
    assert clone.unit_state("base") == "running"
    assert clone.unit_state("api") == "running"
    assert clone.running_units() == ("api", "base")
    assert clone.stats() == g.stats()

    before = len(clone.audit_entries())
    result = clone.stop_unit("api")
    assert result.outcome == "stopped"
    assert len(clone.audit_entries()) == before + 1
    assert clone.audit_entries()[-1].seq == before + 1


def test_restore_rejects_malformed_snapshot():
    g = gate()
    unit(g, "base")
    unit(g, "api", requires=["base"])
    g.start_unit("base")
    g.start_unit("api")
    snap = g.snapshot()

    missing_stats = copy.deepcopy(snap)
    missing_stats.pop("stats")
    bad_units = copy.deepcopy(snap)
    bad_units["units"] = "nope"
    bad_audit = copy.deepcopy(snap)
    bad_audit["audit"] = "nope"
    bad_counters = copy.deepcopy(snap)
    bad_counters["counters"] = {"audit_seq": "x"}
    bad_version = copy.deepcopy(snap)
    bad_version["version"] = 99
    bad_states = [None, {}, missing_stats, bad_units, bad_audit, bad_counters,
                  bad_version]

    for bad in bad_states:
        with pytest.raises(u.UnitGateError) as exc:
            g.restore(bad)
        assert exc.value.code == "UNIT_SNAPSHOT_INVALID"

    assert g.unit_state("base") == "running"
    assert g.unit_state("api") == "running"
    assert g.stats()["started"] == 2
