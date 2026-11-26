import copy
import threading

import pytest

import name_reservation as nr

NOW = 1000


def make(**kwargs):
    return nr.NameReservation(**kwargs)


def test_reserve_creates_active_owner_with_history():
    book = make()
    state = book.reserve("alpha", "u1", now=NOW)
    assert state.status == "active"
    assert state.owner == "u1"
    assert state.held_until is None
    assert book.lookup("alpha") == "active"
    assert book.owner_of("alpha") == "u1"
    history = book.history_of("alpha")
    assert len(history) == 1
    assert (history[0].name, history[0].account, history[0].action,
            history[0].at) == ("alpha", "u1", "reserve", NOW)


def test_reserve_is_idempotent_for_current_owner():
    book = make()
    book.reserve("alpha", "u1", now=NOW)
    again = book.reserve("alpha", "u1", now=NOW + 5)
    assert again.status == "active"
    assert again.owner == "u1"
    assert book.stats()["reserved"] == 1
    assert len(book.history_of("alpha")) == 1


def test_reserve_rejects_name_owned_by_another_account():
    book = make()
    book.reserve("alpha", "u1", now=NOW)
    with pytest.raises(nr.ReservationError) as exc:
        book.reserve("alpha", "u2", now=NOW + 1)
    assert exc.value.code == "NAME_TAKEN"
    assert book.owner_of("alpha") == "u1"


def test_invalid_names_and_accounts_are_rejected():
    book = make()
    for name in ("ab", "Alpha", "1abc", "has space", "toolongnamexxxxxxxx", ""):
        with pytest.raises(nr.ReservationError) as exc:
            book.reserve(name, "u1", now=NOW)
        assert exc.value.code == "NAME_INVALID"
    with pytest.raises(nr.ReservationError) as exc:
        book.reserve("valid_name", "   ", now=NOW)
    assert exc.value.code == "NAME_INVALID"
    assert book.stats()["reserved"] == 0


def test_release_parks_name_in_retention():
    book = make()
    book.reserve("alpha", "u1", now=NOW)
    state = book.release("alpha", "u1", now=NOW + 10)
    assert state.status == "retention"
    assert state.owner is None
    assert state.last_owner == "u1"
    assert state.held_until == NOW + 10 + 604800
    assert book.owner_of("alpha") is None
    assert book.lookup("alpha") == "retention"


def test_retention_blocks_others_until_sweep():
    book = make()
    book.reserve("alpha", "u1", now=NOW)
    book.release("alpha", "u1", now=NOW)
    with pytest.raises(nr.ReservationError) as exc:
        book.reserve("alpha", "u2", now=NOW + 10)
    assert exc.value.code == "NAME_RETENTION_HELD"
    assert book.expire_sweep(now=NOW + 604800) == 1
    assert book.lookup("alpha") == "free"
    assert book.reserve("alpha", "u2", now=NOW + 604801).owner == "u2"


def test_previous_owner_reclaims_name_during_retention():
    book = make()
    book.reserve("alpha", "u1", now=NOW)
    book.release("alpha", "u1", now=NOW)
    state = book.reserve("alpha", "u1", now=NOW + 100)
    assert state.status == "active"
    assert state.owner == "u1"
    assert book.lookup("alpha") == "active"


def test_rename_moves_ownership_and_holds_old_name():
    book = make()
    book.reserve("alpha", "u1", now=NOW)
    result = book.rename("u1", "beta", now=NOW + 10)
    assert result.renamed is True
    assert result.replayed is False
    assert (result.old_name, result.new_name) == ("alpha", "beta")
    assert result.cooldown_until == NOW + 10 + 2592000
    assert book.owner_of("beta") == "u1"
    assert book.lookup("alpha") == "retention"
    assert book.rename_ready_at("u1") == NOW + 10 + 2592000
    assert [entry.action for entry in book.history_of("beta")] == ["rename"]


def test_rename_enforces_cooldown():
    book = make()
    book.reserve("alpha", "u1", now=NOW)
    book.rename("u1", "beta", now=NOW + 10)
    with pytest.raises(nr.ReservationError) as exc:
        book.rename("u1", "gamma", now=NOW + 20)
    assert exc.value.code == "NAME_COOLDOWN"
    assert book.owner_of("beta") == "u1"
    assert book.rename_ready_at("u1") == NOW + 10 + 2592000


def test_request_id_replays_and_rejects_payload_change():
    book = make()
    book.reserve("alpha", "u1", now=NOW, request_id="req-1")
    replay = book.reserve("alpha", "u1", now=NOW + 1, request_id="req-1")
    assert replay.owner == "u1"
    assert replay.status == "active"
    assert book.stats()["reserved"] == 1
    with pytest.raises(nr.ReservationError) as exc:
        book.reserve("beta", "u1", now=NOW + 2, request_id="req-1")
    assert exc.value.code == "NAME_REQUEST_CONFLICT"
    assert book.lookup("beta") == "free"


def test_concurrent_reserve_allows_single_winner():
    book = make()
    winners = []
    errors = []
    barrier = threading.Barrier(12)

    def worker(account):
        try:
            barrier.wait(timeout=5)
            winners.append(book.reserve("shared", account, now=NOW).owner)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(getattr(exc, "code", repr(exc)))

    threads = [threading.Thread(target=worker, args=(f"u{index:02d}",))
               for index in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(winners) == 1
    assert sorted(errors) == ["NAME_TAKEN"] * 11


def test_snapshot_is_detached_from_live_state():
    book = make()
    book.reserve("alpha", "u1", now=NOW)
    state = book.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "names", "history", "cooldowns",
                             "requests", "counters"}
    state["names"].clear()
    state["counters"]["reserved"] = 42
    assert book.owner_of("alpha") == "u1"
    assert book.stats()["reserved"] == 1
    assert "alpha" in pristine["names"]


def test_restore_roundtrip_preserves_book_state():
    book = make()
    book.reserve("alpha", "u1", now=NOW)
    book.rename("u1", "beta", now=NOW + 10)
    state = book.snapshot()
    clone = make()
    clone.restore(state)
    assert clone.stats() == book.stats()
    assert clone.owner_of("beta") == "u1"
    assert clone.lookup("alpha") == "retention"
    assert clone.rename_ready_at("u1") == book.rename_ready_at("u1")
    assert clone.history_of("alpha") == book.history_of("alpha")


def test_restore_rejects_malformed_state_without_touching_live_data():
    book = make()
    book.reserve("alpha", "u1", now=NOW)
    bad_states = [
        None,
        {},
        {"version": 2, "names": {}, "history": {}, "cooldowns": {},
         "requests": {}, "counters": {}},
        {"version": 1, "names": [], "history": {}, "cooldowns": {},
         "requests": {}, "counters": {}},
        {"version": 1, "names": {}, "history": {}, "cooldowns": {},
         "requests": {}, "counters": {"reserved": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(nr.ReservationError) as exc:
            book.restore(bad)
        assert exc.value.code == "NAME_SNAPSHOT_INVALID"
    assert book.owner_of("alpha") == "u1"
    assert book.stats()["reserved"] == 1


def test_stats_track_names_by_status():
    book = make()
    book.reserve("alpha", "u1", now=NOW)
    book.reserve("beta", "u2", now=NOW)
    book.release("alpha", "u1", now=NOW + 10)
    assert book.stats() == {"reserved": 2, "released": 1, "renamed": 0,
                            "expired": 0, "active": 1, "retention": 1}
    assert book.expire_sweep(now=NOW + 10 + 604800) == 1
    assert book.stats()["expired"] == 1
    assert book.stats()["retention"] == 0
