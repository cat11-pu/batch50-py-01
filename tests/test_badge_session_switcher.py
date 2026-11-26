import threading

import pytest

import badge_session_switcher as bs

BASE = 1_800_000_000


def switcher(**kwargs):
    return bs.BadgeSessionSwitcher(**kwargs)


def tapped(sw, terminal="t1", badge="badge-x", seq=1, now=BASE):
    return sw.tap(terminal, badge, seq, now=now)


def test_tap_opens_active_session():
    sw = switcher()
    first = tapped(sw)
    assert first.session_id == "sess-1"
    assert first.terminal_id == "t1"
    assert first.badge_serial == "badge-x"
    assert first.state == "active"
    assert first.status == "opened"
    assert first.replayed is False
    active = sw.list_active()
    assert [item.session_id for item in active] == ["sess-1"]
    assert sw.stats()["taps"] == 1
    assert sw.stats()["opened"] == 1
    assert sw.stats()["replays"] == 0


def test_repeated_event_with_same_sequence_is_idempotent():
    sw = switcher()
    first = tapped(sw)
    again = tapped(sw)
    assert again.replayed is True
    assert again.session_id == first.session_id
    assert sw.stats()["taps"] == 2
    assert sw.stats()["replays"] == 1
    assert sw.stats()["opened"] == 1
    assert len(sw.list_active()) == 1


def test_older_sequence_is_refused_as_stale():
    sw = switcher()
    tapped(sw, seq=5)
    with pytest.raises(bs.BadgeError) as stale:
        tapped(sw, seq=3, now=BASE + 1)
    assert stale.value.code == "BADGE_STALE"
    assert sw.stats()["refused"] == 1
    assert sw.stats()["opened"] == 1


def test_newer_sequence_on_same_terminal_reuses_session():
    sw = switcher()
    first = tapped(sw, seq=1)
    second = tapped(sw, seq=2, now=BASE + 4)
    assert second.status == "existing"
    assert second.session_id == first.session_id
    assert second.replayed is False
    assert sw.stats()["opened"] == 1
    assert sw.stats()["replays"] == 0
    assert len(sw.list_active()) == 1


def test_suspend_seals_active_session_with_ttl():
    sw = switcher()
    first = tapped(sw)
    result = sw.suspend("t1", now=BASE + 1)
    assert result["terminal_id"] == "t1"
    assert result["count"] == 1
    assert result["suspended"] == [first.session_id]
    view = sw.session_view(first.session_id)
    assert view.state == "suspended"
    assert view.expires_at == BASE + 1 + 900
    assert sw.list_active() == []
    assert sw.stats()["suspended"] == 1


def test_resume_reactivates_the_same_session():
    sw = switcher()
    first = tapped(sw)
    sw.suspend("t1", now=BASE + 1)
    resumed = sw.resume("t1", "badge-x", now=BASE + 10)
    assert resumed.session_id == first.session_id
    assert resumed.state == "active"
    assert resumed.expires_at is None
    assert [item.session_id for item in sw.list_active()] == [first.session_id]
    assert sw.stats()["resumed"] == 1


def test_resume_of_unknown_badge_or_session_is_refused():
    sw = switcher()
    tapped(sw)
    with pytest.raises(bs.BadgeError) as missing:
        sw.resume("t1", "badge-other", now=BASE + 1)
    assert missing.value.code == "BADGE_RESUME"
    with pytest.raises(bs.BadgeError) as unknown:
        sw.session_view("sess-999")
    assert unknown.value.code == "BADGE_SESSION_UNKNOWN"


def test_resume_at_expired_ttl_fails_and_sweep_purges():
    sw = switcher()
    first = tapped(sw)
    sw.suspend("t1", now=BASE + 10)
    with pytest.raises(bs.BadgeError) as expired:
        sw.resume("t1", "badge-x", now=BASE + 910)
    assert expired.value.code == "BADGE_RESUME"
    swept = sw.sweep(now=BASE + 910)
    assert swept["purged"] == 1
    assert sw.stats()["purged"] == 1
    with pytest.raises(bs.BadgeError) as gone:
        sw.session_view(first.session_id)
    assert gone.value.code == "BADGE_SESSION_UNKNOWN"


def test_idle_sweep_uses_timeout_boundary():
    sw = switcher()
    first = tapped(sw)
    early = sw.sweep(now=BASE + 299)
    assert early["suspended"] == 0
    assert sw.session_view(first.session_id).state == "active"
    late = sw.sweep(now=BASE + 300)
    assert late["suspended"] == 1
    view = sw.session_view(first.session_id)
    assert view.state == "suspended"
    assert view.expires_at == BASE + 300 + 900


def test_logout_removes_active_and_suspended_sessions():
    sw = switcher()
    first = tapped(sw, terminal="t1", badge="badge-x")
    sw.suspend("t1", now=BASE + 1)
    tapped(sw, terminal="t2", badge="badge-y", now=BASE + 2)
    assert sw.logout("t1") == 1
    assert sw.logout("t2") == 1
    assert sw.logout("t1") == 0
    assert sw.list_active() == []
    assert sw.stats()["logouts"] == 2
    with pytest.raises(bs.BadgeError) as gone:
        sw.session_view(first.session_id)
    assert gone.value.code == "BADGE_SESSION_UNKNOWN"


def test_badge_terminal_cap_is_enforced():
    sw = switcher()
    for terminal in ("t1", "t2", "t3"):
        tapped(sw, terminal=terminal, badge="badge-x")
        sw.suspend(terminal, now=BASE + 1)
    with pytest.raises(bs.BadgeError) as capped:
        tapped(sw, terminal="t4", badge="badge-x", now=BASE + 2)
    assert capped.value.code == "BADGE_TERMINAL_LIMIT"
    assert sw.stats()["refused"] == 1
    assert sw.stats()["opened"] == 3


def test_invalid_arguments_are_refused():
    sw = switcher()
    with pytest.raises(bs.BadgeError) as blank_terminal:
        sw.tap("", "badge-x", 1, now=BASE)
    assert blank_terminal.value.code == "BADGE_INVALID"
    with pytest.raises(bs.BadgeError) as blank_badge:
        sw.tap("t1", "   ", 1, now=BASE)
    assert blank_badge.value.code == "BADGE_INVALID"
    with pytest.raises(bs.BadgeError) as bad_seq:
        sw.tap("t1", "badge-x", 0, now=BASE)
    assert bad_seq.value.code == "BADGE_INVALID"
    with pytest.raises(bs.BadgeError) as blank_offline:
        sw.mark_offline("", now=BASE)
    assert blank_offline.value.code == "BADGE_INVALID"


def test_offline_and_online_marks_are_recorded():
    sw = switcher()
    tapped(sw, terminal="t1", badge="badge-x")
    offline = sw.mark_offline("t1", now=BASE + 1)
    assert offline["terminal_id"] == "t1"
    assert offline["offline_since"] == BASE + 1
    online = sw.mark_online("t1", now=BASE + 30)
    assert online["terminal_id"] == "t1"
    assert online["online"] is True
    sw.suspend("t1", now=BASE + 40)
    resumed = sw.resume("t1", "badge-x", now=BASE + 60)
    assert resumed.state == "active"


def test_snapshot_restore_keeps_states_ttl_and_replay():
    sw = switcher()
    first = tapped(sw, terminal="t1", badge="badge-x")
    sw.suspend("t1", now=BASE + 10)
    tapped(sw, terminal="t2", badge="badge-y", now=BASE + 20)
    clone = switcher()
    clone.restore(sw.snapshot())
    assert clone.session_view(first.session_id).state == "suspended"
    assert clone.session_view(first.session_id).expires_at == BASE + 910
    assert [item.session_id for item in clone.list_active()] == ["sess-2"]
    assert clone.stats() == sw.stats()
    replay = clone.tap("t1", "badge-x", 1, now=BASE + 30)
    assert replay.replayed is True
    assert replay.session_id == first.session_id
    other = switcher()
    other.restore(sw.snapshot())
    with pytest.raises(bs.BadgeError) as expired:
        other.resume("t1", "badge-x", now=BASE + 910)
    assert expired.value.code == "BADGE_RESUME"
    with pytest.raises(bs.BadgeError) as broken:
        other.restore({"version": 1, "sessions": None})
    assert broken.value.code == "BADGE_SNAPSHOT"
    assert other.session_view(first.session_id).state == "suspended"


def test_concurrent_duplicate_taps_open_one_session():
    sw = switcher()
    results = []
    failures = []
    guard = threading.Lock()

    def worker():
        try:
            result = sw.tap("t1", "badge-x", 1, now=BASE)
        except Exception as err:  # noqa: BLE001 - collect refusal reason
            with guard:
                failures.append(getattr(err, "code", type(err).__name__))
        else:
            with guard:
                results.append(result)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == []
    assert len(results) == 8
    assert len({item.session_id for item in results}) == 1
    assert sum(1 for item in results if item.replayed is False) == 1
    assert sum(1 for item in results if item.replayed is True) == 7
    assert len(sw.list_active()) == 1
    assert sw.stats()["opened"] == 1
    assert sw.stats()["replays"] == 7
