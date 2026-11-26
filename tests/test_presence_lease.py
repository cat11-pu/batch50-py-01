import copy
import threading

import pytest

import presence_lease as pl

NOW = 1000


def make(**kwargs):
    return pl.PresenceLease(**kwargs)


def test_acquire_creates_online_session():
    book = make()
    view = book.acquire("u1", "s1", device="pc", shard=1, now=NOW)
    assert view.status == "online"
    assert (view.account, view.device, view.shard) == ("u1", "pc", 1)
    assert view.expires_at == NOW + 60
    assert view.grace_until is None
    assert view.preemptable is False
    assert book.session_of("s1").status == "online"
    assert book.stats()["acquired"] == 1
    assert book.stats()["online"] == 1


def test_duplicate_session_id_is_rejected():
    book = make()
    book.acquire("u1", "s1", device="pc", now=NOW)
    with pytest.raises(pl.PresenceError) as exc:
        book.acquire("u2", "s1", device="pc", now=NOW + 1)
    assert exc.value.code == "PRESENCE_SESSION_EXISTS"


def test_new_device_login_demotes_older_sessions():
    book = make()
    book.acquire("u1", "s1", device="pc", now=NOW)
    second = book.acquire("u1", "s2", device="phone", now=NOW + 10)
    assert second.preemptable is False
    assert book.session_of("s1").preemptable is True
    assert book.session_of("s2").preemptable is False


def test_renew_extends_lease_from_current_time():
    book = make()
    book.acquire("u1", "s1", device="pc", now=NOW)
    view = book.renew("s1", now=NOW + 20)
    assert view.status == "online"
    assert view.expires_at == NOW + 20 + 60
    assert book.stats()["renewed"] == 1


def test_renew_rejects_non_online_and_unknown_sessions():
    book = make()
    book.acquire("u1", "s1", device="pc", now=NOW)
    book.release("s1", now=NOW + 10)
    with pytest.raises(pl.PresenceError) as exc:
        book.renew("s1", now=NOW + 20)
    assert exc.value.code == "PRESENCE_NOT_ONLINE"
    with pytest.raises(pl.PresenceError) as exc:
        book.renew("ghost", now=NOW + 20)
    assert exc.value.code == "PRESENCE_SESSION_UNKNOWN"


def test_release_enters_reconnect_grace():
    book = make()
    book.acquire("u1", "s1", device="pc", now=NOW)
    view = book.release("s1", now=NOW + 10)
    assert view.status == "grace"
    assert view.grace_until == NOW + 10 + 30
    assert view.expires_at == NOW + 60
    assert book.stats()["online"] == 0
    assert book.stats()["grace"] == 1


def test_resume_within_grace_restores_same_session():
    book = make()
    book.acquire("u1", "s1", device="pc", now=NOW)
    book.release("s1", now=NOW + 10)
    view = book.resume("s1", now=NOW + 20)
    assert view.status == "online"
    assert view.session_id == "s1"
    assert view.expires_at == NOW + 20 + 60
    assert view.grace_until is None
    assert book.stats()["resumed"] == 1


def test_resume_after_grace_expiry_is_refused():
    book = make()
    book.acquire("u1", "s1", device="pc", now=NOW)
    book.release("s1", now=NOW + 10)
    with pytest.raises(pl.PresenceError) as exc:
        book.resume("s1", now=NOW + 41)
    assert exc.value.code == "PRESENCE_GRACE_EXPIRED"
    assert book.session_of("s1").status == "grace"


def test_sweep_moves_online_session_into_grace():
    book = make()
    book.acquire("u1", "s1", device="pc", now=NOW)
    events = book.expire_sweep(now=NOW + 61)
    assert events == ()
    view = book.session_of("s1")
    assert view.status == "grace"
    assert view.grace_until == NOW + 61 + 30
    assert book.stats()["swept"] == 1
    assert book.stats()["offline"] == 0


def test_sweep_emits_offline_events_sorted_by_lease_expiry():
    book = make()
    book.acquire("u1", "s1", device="pc", now=NOW)
    book.acquire("u2", "s2", device="pc", now=NOW + 5)
    book.release("s1", now=NOW + 10)
    book.release("s2", now=NOW + 10)
    events = book.expire_sweep(now=NOW + 45)
    assert [event.session_id for event in events] == ["s1", "s2"]
    assert [event.lease_expired_at for event in events] == [NOW + 60, NOW + 65]
    assert {event.reason for event in events} == {"grace_expired"}
    assert book.session_of("s1").status == "offline"
    assert book.session_of("s2").status == "offline"
    assert book.stats()["offline"] == 2


def test_sessions_on_filters_offline_and_sorts():
    book = make()
    book.acquire("u1", "s2", device="pc", now=NOW)
    book.acquire("u1", "s1", device="tablet", now=NOW + 5)
    book.acquire("u2", "s3", device="pc", now=NOW + 5)
    book.release("s3", now=NOW + 10)
    book.expire_sweep(now=NOW + 45)
    assert book.session_of("s3").status == "offline"
    assert [view.session_id for view in book.sessions_on("u1")] == ["s1", "s2"]
    assert book.sessions_on("u2") == ()


def test_concurrent_acquire_allows_single_winner():
    book = make()
    winners = []
    errors = []
    barrier = threading.Barrier(12)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            winners.append(book.acquire(f"u{index:02d}", "hot", device="pc",
                                        now=NOW).session_id)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(getattr(exc, "code", repr(exc)))

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert winners == ["hot"]
    assert sorted(errors) == ["PRESENCE_SESSION_EXISTS"] * 11


def test_snapshot_is_detached_from_live_state():
    book = make()
    book.acquire("u1", "s1", device="pc", now=NOW)
    state = book.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "sessions", "counters"}
    state["sessions"].clear()
    state["counters"]["acquired"] = 42
    assert book.session_of("s1").status == "online"
    assert book.stats()["acquired"] == 1
    assert len(pristine["sessions"]) == 1


def test_restore_roundtrip_and_malformed_rejection():
    book = make()
    book.acquire("u1", "s1", device="pc", shard=2, now=NOW)
    book.renew("s1", now=NOW + 10)
    book.release("s1", now=NOW + 20)
    state = book.snapshot()
    clone = make()
    clone.restore(state)
    assert clone.stats() == book.stats()
    view = clone.session_of("s1")
    assert view.status == "grace"
    assert view.grace_until == NOW + 20 + 30
    assert view.expires_at == NOW + 10 + 60
    assert [item.session_id for item in clone.sessions_on("u1")] == ["s1"]
    bad_states = [
        None,
        {},
        {"version": 2, "sessions": {}, "counters": {}},
        {"version": 1, "sessions": [], "counters": {}},
        {"version": 1, "sessions": {}, "counters": []},
        {"version": 1, "sessions": {}, "counters": {"acquired": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(pl.PresenceError) as exc:
            clone.restore(bad)
        assert exc.value.code == "PRESENCE_SNAPSHOT_INVALID"
    assert clone.session_of("s1").status == "grace"


def test_stats_track_presence_counters():
    book = make()
    book.acquire("u1", "s1", device="pc", now=NOW)
    book.renew("s1", now=NOW + 10)
    book.release("s1", now=NOW + 20)
    book.resume("s1", now=NOW + 30)
    assert book.stats() == {"acquired": 1, "renewed": 1, "released": 1,
                            "resumed": 1, "swept": 0, "offline": 0,
                            "online": 1, "grace": 0}
