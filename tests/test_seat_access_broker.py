import copy
import threading

import pytest

import seat_access_broker as sb


def broker():
    b = sb.SeatAccessBroker()
    b.register_session("s1", seat="seat0", active=True)
    b.register_session("s2", seat="seat0", active=False)
    b.register_session("s3", seat="seat1", active=True)
    for device in ("/dev/dri/card0", "/dev/dri/card1", "/dev/dri/card2"):
        b.register_device(device)
    return b


def test_registration_validates_names_and_paths():
    b = broker()
    cases = [
        (lambda: b.register_session("s1", seat="seat0"), "SEAT_DUPLICATE_SESSION"),
        (lambda: b.register_session("   ", seat="seat0"), "SEAT_INVALID_REQUEST"),
        (lambda: b.register_session("s9", seat=" "), "SEAT_INVALID_REQUEST"),
        (lambda: b.register_device("/dev/dri/./card0"), "SEAT_DUPLICATE_DEVICE"),
        (lambda: b.register_device("dri/card9"), "SEAT_INVALID_REQUEST"),
        (lambda: b.register_device("/tmp/card9"), "SEAT_INVALID_REQUEST"),
    ]
    for call, code in cases:
        with pytest.raises(sb.SeatError) as exc:
            call()
        assert exc.value.code == code
    assert b.holders() == {}
    assert b.stats() == {"grants": 0, "revokes": 0, "switches": 0,
                         "swept": 0, "refused": 0}


def test_lookup_normalizes_paths_and_unknown_identifiers():
    b = broker()
    b.register_device("/dev/dri/../dri/card3")
    assert b.holders("/dev/dri/./card3") is None
    assert b.device_view("/dev/dri/x/../card3").path == "/dev/dri/card3"
    cases = [
        (lambda: b.attach_session("ghost", "/dev/dri/card0", now=1),
         "SEAT_UNKNOWN_SESSION"),
        (lambda: b.attach_session("s1", "/dev/dri/ghost", now=1),
         "SEAT_UNKNOWN_DEVICE"),
        (lambda: b.holders("/dev/dri/ghost"), "SEAT_UNKNOWN_DEVICE"),
        (lambda: b.set_device_state("/dev/dri/ghost", state="ready"),
         "SEAT_UNKNOWN_DEVICE"),
        (lambda: b.set_device_state("/dev/dri/card0", state="sleeping"),
         "SEAT_INVALID_REQUEST"),
        (lambda: b.set_session_alive("ghost", alive=True), "SEAT_UNKNOWN_SESSION"),
        (lambda: b.detach_session("ghost", now=1), "SEAT_UNKNOWN_SESSION"),
        (lambda: b.detach_session("s1", now=1, device="/dev/dri/ghost"),
         "SEAT_UNKNOWN_DEVICE"),
        (lambda: b.switch_active("seat9", "s1", now=1), "SEAT_UNKNOWN_SEAT"),
        (lambda: b.switch_active("seat0", "ghost", now=1), "SEAT_UNKNOWN_SESSION"),
        (lambda: b.switch_active("seat0", "s3", now=1), "SEAT_WRONG_SEAT"),
    ]
    for call, code in cases:
        with pytest.raises(sb.SeatError) as exc:
            call()
        assert exc.value.code == code
    assert b.holders("/dev/dri/card0") is None


def test_attach_grants_device_to_active_session():
    b = broker()
    assert b.attach_session("s1", "/dev/dri/card0", now=100) is True
    assert b.attach_session("s1", "/dev/dri/card1", now=110) is True
    assert b.holders("/dev/dri/card0") == "s1"
    assert b.holders() == {"/dev/dri/card0": "s1", "/dev/dri/card1": "s1"}
    view = b.session_view("s1")
    assert (view.name, view.seat, view.active, view.alive) == (
        "s1", "seat0", True, True)
    assert view.devices == ("/dev/dri/card0", "/dev/dri/card1")
    assert b.device_view("/dev/dri/card1").holder == "s1"
    assert b.stats() == {"grants": 2, "revokes": 0, "switches": 0,
                         "swept": 0, "refused": 0}
    assert [(e.op, e.session, e.device, e.at) for e in b.audit_log()] == [
        ("grant", "s1", "/dev/dri/card0", 100),
        ("grant", "s1", "/dev/dri/card1", 110),
    ]


def test_attach_requires_active_session():
    b = broker()
    with pytest.raises(sb.SeatError) as exc:
        b.attach_session("s2", "/dev/dri/card0", now=100)
    assert exc.value.code == "SEAT_SESSION_INACTIVE"
    assert b.holders("/dev/dri/card0") is None
    assert b.stats()["refused"] == 1


def test_second_session_cannot_take_busy_device():
    b = broker()
    b.attach_session("s1", "/dev/dri/card0", now=100)
    with pytest.raises(sb.SeatError) as exc:
        b.attach_session("s3", "/dev/dri/card0", now=110)
    assert exc.value.code == "SEAT_DEVICE_BUSY"
    assert b.holders("/dev/dri/card0") == "s1"
    assert b.session_view("s3").devices == ()
    assert b.stats()["refused"] == 1


def test_attach_refuses_faulted_device():
    b = broker()
    b.set_device_state("/dev/dri/card2", state="faulted")
    assert b.device_view("/dev/dri/card2").state == "faulted"
    with pytest.raises(sb.SeatError) as exc:
        b.attach_session("s1", "/dev/dri/card2", now=100)
    assert exc.value.code == "SEAT_DEVICE_FAULTED"
    b.set_device_state("/dev/dri/card2", state="ready")
    assert b.attach_session("s1", "/dev/dri/card2", now=120) is True


def test_detach_frees_device_for_another_session():
    b = broker()
    b.attach_session("s1", "/dev/dri/card0", now=100)
    assert b.detach_session("s1", now=150, device="/dev/dri/card0") == 1
    assert b.holders("/dev/dri/card0") is None
    assert b.attach_session("s3", "/dev/dri/card0", now=200) is True
    assert b.holders("/dev/dri/card0") == "s3"
    assert b.session_view("s1").devices == ()
    assert b.stats()["revokes"] == 1
    assert b.audit_log()[-1] == sb.AuditEntry("grant", "s3", "/dev/dri/card0", 200)


def test_detach_all_returns_count_and_is_idempotent():
    b = broker()
    b.attach_session("s1", "/dev/dri/card0", now=1)
    b.attach_session("s1", "/dev/dri/card1", now=2)
    b.attach_session("s3", "/dev/dri/card2", now=3)
    assert b.detach_session("s1", now=4) == 2
    assert b.session_view("s1").devices == ()
    assert b.holders("/dev/dri/card2") == "s3"
    assert b.detach_session("s1", now=5) == 0
    assert b.stats()["revokes"] == 2


def test_switch_active_revokes_old_before_granting_new():
    b = broker()
    b.attach_session("s1", "/dev/dri/card0", now=10)
    b.attach_session("s1", "/dev/dri/card1", now=11)
    before = len(b.audit_log())
    result = b.switch_active("seat0", "s2", now=20)
    assert result == {"revoked": 2, "granted": 2, "session": "s2"}
    assert b.session_view("s1").active is False
    assert b.session_view("s2").active is True
    assert b.session_view("s1").devices == ()
    assert b.session_view("s2").devices == ("/dev/dri/card0", "/dev/dri/card1")
    assert b.holders() == {"/dev/dri/card0": "s2", "/dev/dri/card1": "s2"}
    entries = b.audit_log()[before:]
    assert [e.op for e in entries] == ["revoke", "revoke", "grant", "grant"]
    assert [e.session for e in entries] == ["s1", "s1", "s2", "s2"]
    assert [e.device for e in entries] == ["/dev/dri/card0", "/dev/dri/card1",
                                           "/dev/dri/card0", "/dev/dri/card1"]
    assert b.stats()["switches"] == 1
    assert b.stats()["revokes"] == 2
    assert b.stats()["grants"] == 4


def test_switch_to_current_active_session_is_noop():
    b = broker()
    b.attach_session("s1", "/dev/dri/card0", now=10)
    before = len(b.audit_log())
    assert b.switch_active("seat0", "s1", now=20) == {
        "revoked": 0, "granted": 0, "session": "s1"}
    assert b.holders("/dev/dri/card0") == "s1"
    assert len(b.audit_log()) == before
    assert b.stats()["switches"] == 0


def test_sweep_removes_grants_of_dead_sessions():
    b = broker()
    b.attach_session("s1", "/dev/dri/card1", now=1)
    b.attach_session("s1", "/dev/dri/card0", now=2)
    b.attach_session("s3", "/dev/dri/card2", now=3)
    b.set_session_alive("s1", alive=False)
    report = b.sweep(now=100)
    assert report.removed == (("/dev/dri/card0", "s1"), ("/dev/dri/card1", "s1"))
    assert report.kept == 1
    assert b.holders("/dev/dri/card0") is None
    assert b.holders("/dev/dri/card2") == "s3"
    assert b.stats()["swept"] == 2
    assert b.stats()["revokes"] == 0


def test_sweep_without_residue_reports_zero():
    b = broker()
    b.attach_session("s1", "/dev/dri/card0", now=1)
    report = b.sweep(now=50)
    assert report.removed == ()
    assert report.kept == 1
    assert b.holders("/dev/dri/card0") == "s1"
    assert b.stats()["swept"] == 0


def test_snapshot_restore_roundtrip_is_detached():
    b = broker()
    b.attach_session("s1", "/dev/dri/card0", now=1)
    b.set_device_state("/dev/dri/card2", state="faulted")
    b.set_session_alive("s3", alive=False)
    state = b.snapshot()
    assert set(state) == {"version", "devices", "sessions", "grants",
                          "counters", "audit"}
    pristine = copy.deepcopy(state)
    clone = sb.SeatAccessBroker()
    clone.restore(pristine)
    assert clone.holders() == {"/dev/dri/card0": "s1"}
    assert clone.device_view("/dev/dri/card2").state == "faulted"
    assert clone.session_view("s3").alive is False
    assert clone.stats() == b.stats()
    assert len(clone.audit_log()) == 1

    state["grants"].clear()
    assert b.holders("/dev/dri/card0") == "s1"
    assert pristine["grants"] == {"/dev/dri/card0": "s1"}


def test_restore_rejects_malformed_snapshot():
    b = broker()
    b.attach_session("s1", "/dev/dri/card0", now=1)
    bad_states = [
        None,
        {},
        {"version": 2, "devices": {}, "sessions": {}, "grants": {},
         "counters": {}, "audit": []},
        {"version": 1, "devices": [], "sessions": {}, "grants": {},
         "counters": {}, "audit": []},
        {"version": 1, "devices": {}, "sessions": [], "grants": {},
         "counters": {}, "audit": []},
        {"version": 1, "devices": {}, "sessions": {}, "grants": [],
         "counters": {}, "audit": []},
        {"version": 1, "devices": {}, "sessions": {}, "grants": {},
         "counters": [], "audit": []},
    ]
    for bad in bad_states:
        with pytest.raises(sb.SeatError) as exc:
            b.restore(bad)
        assert exc.value.code == "SEAT_SNAPSHOT_INVALID"
    assert b.holders("/dev/dri/card0") == "s1"
    assert b.stats()["grants"] == 1


def test_concurrent_attach_has_single_winner():
    b = broker()
    names = [f"x{index}" for index in range(8)]
    for name in names:
        b.register_session(name, seat="seat0", active=True)
    won = []
    errors = []
    barrier = threading.Barrier(len(names))

    def worker(name):
        try:
            barrier.wait(timeout=5)
            if b.attach_session(name, "/dev/dri/card0", now=10):
                won.append(name)
        except sb.SeatError as exc:
            errors.append(exc.code)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(name,)) for name in names]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(won) == 1
    assert errors == ["SEAT_DEVICE_BUSY"] * 7
    assert b.holders("/dev/dri/card0") == won[0]
    assert b.stats()["grants"] == 1
    assert b.stats()["refused"] == 7
    assert len([entry for entry in b.audit_log() if entry.op == "grant"]) == 1
