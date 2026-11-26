import copy
import threading

import pytest

import credential_watch_supervisor as cw

FP_APP = "3f9a0c7d21b84e55"
FP_DB = "aa11bb22cc33dd44"
FP_OLD = "0123456789abcdef"
FP_NEW = "fedcba9876543210"
FP_OTHER = "5e6f7a8b9c0d1e2f"


def supervisor(**kwargs):
    return cw.CredentialWatchSupervisor(**kwargs)


def test_register_returns_healthy_view_with_deadline():
    sup = supervisor()
    sup.register_credential("app-key", FP_APP)
    view = sup.register_process("api", pid=4242, credential_ids=["app-key"], now=100)
    assert view.name == "api"
    assert view.pid == 4242
    assert view.state == "healthy"
    assert view.deadline_at == 5100
    assert view.credential_ids == ("app-key",)
    assert view.restart_count == 0
    assert view.consecutive_crashes == 0
    assert view.restart_due_at is None
    assert view.containment_reason is None
    assert sup.process_views() == (view,)


def test_register_rejects_duplicate_and_invalid_input():
    sup = supervisor()
    sup.register_credential("app-key", FP_APP)
    sup.register_process("api", pid=10, credential_ids=["app-key"], now=0)

    with pytest.raises(cw.CredentialWatchError) as exc:
        sup.register_process("api", pid=11)
    assert exc.value.code == "CW_DUPLICATE_PROCESS"

    with pytest.raises(cw.CredentialWatchError) as exc:
        sup.register_process("", pid=12)
    assert exc.value.code == "CW_INVALID_REQUEST"

    with pytest.raises(cw.CredentialWatchError) as exc:
        sup.register_process("oops", pid=0)
    assert exc.value.code == "CW_INVALID_REQUEST"

    with pytest.raises(cw.CredentialWatchError) as exc:
        sup.register_process("oops", pid=13, credential_ids=["ghost"])
    assert exc.value.code == "CW_INVALID_REQUEST"

    assert [row.name for row in sup.process_views()] == ["api"]


def test_scan_environment_records_finding_and_contains_process():
    sup = supervisor()
    sup.register_credential("db-password", FP_DB)
    sup.register_process("worker", pid=77, now=0)

    found = sup.scan_environment("worker", {"DB_PASSWORD": f"x-{FP_DB}-y"}, now=10)
    assert len(found) == 1
    finding = found[0]
    assert finding.process == "worker"
    assert finding.credential_id == "db-password"
    assert finding.fingerprint == FP_DB
    assert finding.source == "env"
    assert finding.location == "DB_PASSWORD"
    assert finding.fd is None
    assert finding.status == "active"

    view = sup.process_view("worker")
    assert view.state == "contained"
    assert view.containment_reason == "credential_leak"
    assert sup.findings() == (finding,)

    actions = sup.tick(6000)
    assert [row.action for row in actions if row.action == "restart"] == []
    assert sup.process_view("worker").state == "contained"
    assert sup.process_view("worker").restart_count == 0


def test_scan_environment_ignores_benign_values():
    sup = supervisor()
    sup.register_credential("db-password", FP_DB)
    sup.register_process("worker", pid=78, now=0)

    assert sup.scan_environment(
        "worker", {"PATH": "/usr/local/bin:/usr/bin", "TOKEN_ID": "tk-000"}, now=10
    ) == ()
    assert sup.findings() == ()
    assert sup.process_view("worker").state == "healthy"
    assert sup.stats()["findings"] == 0


def test_scan_descriptors_dedupes_repeated_fd():
    sup = supervisor()
    sup.register_credential("db-password", FP_DB)
    sup.register_process("worker", pid=79, now=0)
    path = f"/var/run/worker/{FP_DB}.sock"

    first = sup.scan_descriptors("worker", [(7, path)], now=20)
    assert len(first) == 1
    assert first[0].source == "fd"
    assert first[0].location == path
    assert first[0].fd == 7

    assert sup.scan_descriptors("worker", [(7, path)], now=30) == ()
    assert len(sup.findings("worker")) == 1
    assert sup.process_view("worker").state == "contained"


def test_rotate_credential_activates_new_fingerprint():
    sup = supervisor()
    sup.register_credential("db-password", FP_OLD)
    sup.rotate_credential("db-password", FP_NEW, now=5)

    sup.register_process("worker", pid=80, now=0)
    found = sup.scan_environment("worker", {"DB_PASSWORD": FP_NEW}, now=10)
    assert [item.fingerprint for item in found] == [FP_NEW]

    with pytest.raises(cw.CredentialWatchError) as exc:
        sup.rotate_credential("missing", FP_OTHER, now=10)
    assert exc.value.code == "CW_UNKNOWN_CREDENTIAL"


def test_heartbeat_extends_deadline_before_timeout():
    sup = supervisor(heartbeat_timeout_ms=1000)
    sup.register_process("worker", pid=81, now=0)
    assert sup.heartbeat("worker", now=400) == 1400
    assert sup.tick(1399) == ()

    with pytest.raises(cw.CredentialWatchError) as exc:
        sup.heartbeat("worker", now=100)
    assert exc.value.code == "CW_INVALID_REQUEST"

    assert sup.heartbeat("worker", now=900) == 1900
    assert sup.tick(1899) == ()
    view = sup.process_view("worker")
    assert view.heartbeat_count == 2
    assert view.last_heartbeat_at == 900
    assert view.state == "healthy"


def test_missed_deadline_schedules_backoff_then_restarts():
    sup = supervisor(heartbeat_timeout_ms=1000)
    sup.register_process("worker", pid=82, now=0)

    first = sup.tick(1001)
    assert len(first) == 1
    assert (first[0].process, first[0].action) == ("worker", "missed")
    assert first[0].due_at == 2001

    view = sup.process_view("worker")
    assert view.state == "waiting_restart"
    assert view.deadline_at == 1000
    assert view.restart_due_at == 2001
    assert view.consecutive_crashes == 1
    assert view.restart_count == 0

    assert sup.tick(2000) == ()
    second = sup.tick(2001)
    assert [row.action for row in second] == ["restart"]

    after = sup.process_view("worker")
    assert after.state == "healthy"
    assert after.restart_count == 1
    assert after.deadline_at == 3001
    assert after.restart_due_at is None


def test_backoff_grows_exponentially_up_to_cap():
    sup = supervisor(heartbeat_timeout_ms=1000, backoff_base_ms=1000,
                     backoff_cap_ms=4000, crash_threshold=10)
    sup.register_process("worker", pid=83, now=0)

    dues = []
    for step in (1001, 3002, 6003, 11004):
        actions = sup.tick(step)
        assert len(actions) == 1 and actions[0].action == "missed"
        dues.append(actions[0].due_at)
        restart = sup.tick(actions[0].due_at)
        assert [row.action for row in restart] == ["restart"]

    assert dues == [2001, 5002, 10003, 15004]
    assert sup.process_view("worker").restart_count == 4


def test_crash_loop_opens_circuit_and_freezes_restarts():
    sup = supervisor(heartbeat_timeout_ms=1000, backoff_base_ms=100,
                     crash_threshold=3)
    sup.register_process("worker", pid=84, now=0)

    sup.tick(1001)
    sup.tick(1101)
    sup.tick(2102)
    sup.tick(2302)
    third = sup.tick(3303)
    assert [row.action for row in third] == ["circuit_open"]

    view = sup.process_view("worker")
    assert view.state == "circuit_open"
    assert view.consecutive_crashes == 3
    assert view.restart_due_at is None
    assert view.restart_count == 2

    later = sup.tick(9999)
    assert [row.action for row in later if row.action == "restart"] == []
    assert sup.process_view("worker").restart_count == 2


def test_release_guards_and_counter_reset():
    sup = supervisor()
    sup.register_credential("db-password", FP_DB)
    sup.register_process("worker", pid=85, now=0)
    sup.tick(1001)

    with pytest.raises(cw.CredentialWatchError) as exc:
        sup.release("worker", operator="oncall", now=1100)
    assert exc.value.code == "CW_NOT_QUARANTINED"

    sup.scan_environment("worker", {"DB_PASSWORD": FP_DB}, now=1200)
    assert sup.process_view("worker").state == "contained"

    with pytest.raises(cw.CredentialWatchError) as exc:
        sup.release("worker", operator="   ", now=1300)
    assert exc.value.code == "CW_INVALID_REQUEST"

    sup.release("worker", operator="oncall-lin", now=2000)
    view = sup.process_view("worker")
    assert view.state == "healthy"
    assert view.deadline_at == 7000
    assert view.consecutive_crashes == 0
    assert view.restart_due_at is None
    assert view.containment_reason is None
    assert sup.stats()["releases"] == 1

    with pytest.raises(cw.CredentialWatchError) as exc:
        sup.release("worker", operator="oncall-lin", now=2100)
    assert exc.value.code == "CW_NOT_QUARANTINED"


def test_unknown_process_operations_are_refused():
    sup = supervisor()
    calls = [
        lambda: sup.heartbeat("ghost", now=0),
        lambda: sup.scan_environment("ghost", {}, now=0),
        lambda: sup.scan_descriptors("ghost", [], now=0),
        lambda: sup.process_view("ghost"),
        lambda: sup.findings("ghost"),
        lambda: sup.release("ghost", operator="ops", now=0),
    ]
    for call in calls:
        with pytest.raises(cw.CredentialWatchError) as exc:
            call()
        assert exc.value.code == "CW_UNKNOWN_PROCESS"
    assert sup.process_views() == ()


def test_stats_track_scans_findings_and_restarts():
    sup = supervisor(heartbeat_timeout_ms=1000, backoff_base_ms=500,
                     crash_threshold=2)
    sup.register_credential("app-key", FP_APP)
    sup.register_process("alpha", pid=101, credential_ids=["app-key"], now=0)
    sup.register_process("beta", pid=102, now=0)

    sup.scan_environment("alpha", {"SERVICE_TOKEN": f"pre-{FP_APP}-post"}, now=10)
    sup.tick(2000)
    sup.heartbeat("beta", now=2400)
    sup.release("alpha", operator="oncall-lin", now=3000)

    assert sup.stats() == {
        "processes": 2,
        "healthy": 2,
        "contained": 0,
        "circuit_open": 0,
        "restarts": 0,
        "missed": 1,
        "findings": 1,
        "rotations": 0,
        "releases": 1,
    }


def test_snapshot_is_detached_and_restore_resumes_state():
    sup = supervisor(heartbeat_timeout_ms=1000, backoff_base_ms=500)
    sup.register_credential("db-password", FP_DB)
    sup.register_process("leaky", pid=90, now=0)
    sup.register_process("sick", pid=91, now=0)
    sup.scan_environment("leaky", {"DB_PASSWORD": FP_DB}, now=10)
    sup.tick(1001)

    state = sup.snapshot()
    assert set(state) == {"version", "processes", "credentials", "retired",
                          "findings", "counters", "stats"}
    pristine = copy.deepcopy(state)

    state["processes"].clear()
    assert sup.process_view("sick").state == "waiting_restart"
    assert sup.process_view("leaky").state == "contained"
    assert sup.stats()["findings"] == 1

    clone = supervisor(heartbeat_timeout_ms=1000, backoff_base_ms=500)
    clone.restore(pristine)
    assert clone.process_views() == sup.process_views()
    assert clone.findings() == sup.findings()
    assert clone.tick(1501) == sup.tick(1501)
    assert clone.stats() == sup.stats()


def test_restore_rejects_malformed_state_without_mutation():
    sup = supervisor()
    sup.register_credential("db-password", FP_DB)
    sup.register_process("worker", pid=92, now=0)
    sup.scan_environment("worker", {"DB_PASSWORD": FP_DB}, now=10)
    before = sup.stats()

    bad_states = [
        None,
        {},
        {"version": 2},
        {"version": 1, "processes": []},
        {"version": 1, "processes": {}, "credentials": [], "retired": [],
         "findings": [], "counters": {}, "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(cw.CredentialWatchError) as exc:
            sup.restore(bad)
        assert exc.value.code == "CW_SNAPSHOT_INVALID"

    assert sup.stats() == before
    assert sup.process_view("worker").state == "contained"
    assert len(sup.findings("worker")) == 1
