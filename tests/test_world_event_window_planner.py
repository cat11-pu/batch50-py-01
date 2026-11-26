import threading
from datetime import datetime, timedelta, timezone

import pytest

import world_event_window_planner as wp

BASE = int(datetime(2026, 3, 2, tzinfo=timezone.utc).timestamp())  # Monday
DAY = 86400
WEEK = 7 * DAY


def local_ts(weekday, start_minute, *, offset_minutes=0):
    moment = datetime(2026, 3, 2, tzinfo=timezone.utc) + timedelta(days=weekday)
    moment = moment.replace(hour=start_minute // 60, minute=start_minute % 60)
    return int(moment.timestamp()) - offset_minutes * 60


def planner(**kwargs):
    kwargs.setdefault("start_ts", BASE)
    return wp.WorldEventWindowPlanner(**kwargs)


def test_schedule_registers_weekly_event():
    instance = planner()
    spec = instance.schedule("moonfall", weekday=0, start_minute=600,
                             duration_minutes=45)
    assert spec.event_id == "moonfall"
    assert spec.weekday == 0
    assert spec.start_minute == 600
    assert spec.duration_minutes == 45
    assert spec.cancelled is False
    assert spec.first_start_ts == BASE + 600 * 60
    assert instance.event_record("moonfall") == spec
    with pytest.raises(wp.WorldEventError) as exc:
        instance.schedule("moonfall", weekday=1, start_minute=60)
    assert exc.value.code == "WORLD_EVENT_DUPLICATE_EVENT"
    for weekday, start_minute, duration in ((7, 60, 30), (-1, 60, 30),
                                            (0, 1440, 30), (0, 60, 0)):
        with pytest.raises(wp.WorldEventError) as exc:
            instance.schedule(f"bad-{weekday}-{start_minute}-{duration}",
                              weekday=weekday, start_minute=start_minute,
                              duration_minutes=duration)
        assert exc.value.code == "WORLD_EVENT_INVALID_REQUEST"


def test_unknown_event_is_rejected():
    instance = planner()
    with pytest.raises(wp.WorldEventError) as exc:
        instance.event_record("ghost")
    assert exc.value.code == "WORLD_EVENT_UNKNOWN_EVENT"
    with pytest.raises(wp.WorldEventError) as exc:
        instance.cancel_event("ghost")
    assert exc.value.code == "WORLD_EVENT_UNKNOWN_EVENT"


def test_advance_refuses_clock_rewind():
    instance = planner()
    instance.advance(BASE + 60)
    with pytest.raises(wp.WorldEventError) as exc:
        instance.advance(BASE)
    assert exc.value.code == "WORLD_EVENT_CLOCK_REWIND"
    assert instance.stats()["clock_rewinds"] == 1


def test_advance_opens_window_at_start():
    instance = planner()
    instance.schedule("moonfall", weekday=0, start_minute=600,
                      duration_minutes=30)
    start = BASE + 600 * 60
    assert instance.advance(start - 1) == ()
    created = instance.advance(start)
    assert len(created) == 1
    window = created[0]
    assert window.event_id == "moonfall"
    assert window.start_ts == start
    assert window.end_ts == start + 1800
    assert window.status == "open"
    assert window.compensated is False
    assert window.claims == ()
    assert instance.open_windows() == (window,)
    assert instance.windows_between(BASE, BASE + DAY) == (window,)


def test_advance_same_timestamp_is_idempotent():
    instance = planner()
    instance.schedule("moonfall", weekday=0, start_minute=600,
                      duration_minutes=30)
    start = BASE + 600 * 60
    assert len(instance.advance(start)) == 1
    assert instance.advance(start) == ()
    assert len(instance.windows_between(BASE, BASE + DAY)) == 1
    assert instance.stats()["windows"] == 1


def test_windows_between_orders_and_validates():
    instance = planner()
    instance.schedule("early", weekday=0, start_minute=600,
                      duration_minutes=30)
    instance.schedule("late", weekday=0, start_minute=900,
                      duration_minutes=30)
    instance.advance(BASE + 900 * 60 + 60)
    windows = instance.windows_between(BASE, BASE + DAY)
    assert tuple(item.event_id for item in windows) == ("early", "late")
    with pytest.raises(wp.WorldEventError) as exc:
        instance.windows_between(BASE + DAY, BASE)
    assert exc.value.code == "WORLD_EVENT_INVALID_RANGE"


def test_claim_window_awards_points_once():
    instance = planner()
    instance.schedule("moonfall", weekday=0, start_minute=600,
                      duration_minutes=30)
    start = BASE + 600 * 60
    window = instance.advance(start + 60)[0]
    result = instance.claim_window(window.window_id, "acct-1")
    assert result.window_id == window.window_id
    assert result.event_id == "moonfall"
    assert result.account == "acct-1"
    assert result.points == 100
    assert result.compensated is False
    assert instance.window_of(window.window_id).status == "claimed"
    assert instance.stats()["claims"] == 1


def test_claim_rejects_duplicate_and_claimed_window():
    instance = planner()
    instance.schedule("moonfall", weekday=0, start_minute=600,
                      duration_minutes=30)
    start = BASE + 600 * 60
    window = instance.advance(start + 60)[0]
    instance.claim_window(window.window_id, "acct-1")
    with pytest.raises(wp.WorldEventError) as exc:
        instance.claim_window(window.window_id, "acct-1")
    assert exc.value.code == "WORLD_EVENT_DUPLICATE_CLAIM"
    with pytest.raises(wp.WorldEventError) as exc:
        instance.claim_window(window.window_id, "acct-2")
    assert exc.value.code == "WORLD_EVENT_WINDOW_CLOSED"
    assert instance.stats()["duplicates"] == 1
    assert instance.stats()["closed"] == 1


def test_claim_after_window_end_is_refused():
    instance = planner()
    instance.schedule("moonfall", weekday=0, start_minute=600,
                      duration_minutes=30)
    start = BASE + 600 * 60
    window = instance.advance(start + 60)[0]
    instance.advance(start + 1800 + 1)
    assert instance.open_windows() == ()
    assert instance.window_of(window.window_id).status == "closed"
    with pytest.raises(wp.WorldEventError) as exc:
        instance.claim_window(window.window_id, "acct-1")
    assert exc.value.code == "WORLD_EVENT_WINDOW_CLOSED"


def test_cancel_event_stops_future_windows():
    instance = planner()
    instance.schedule("moonfall", weekday=0, start_minute=600,
                      duration_minutes=30)
    start = BASE + 600 * 60
    assert len(instance.advance(start + 60)) == 1
    cancelled = instance.cancel_event("moonfall")
    assert cancelled.cancelled is True
    assert instance.advance(start + WEEK + 60) == ()
    assert instance.event_record("moonfall").cancelled is True
    assert instance.stats()["cancelled"] == 1
    with pytest.raises(wp.WorldEventError) as exc:
        instance.cancel_event("moonfall")
    assert exc.value.code == "WORLD_EVENT_EVENT_CANCELLED"


def test_timezone_shift_places_window_on_server_calendar():
    offset = 480
    instance = planner(utc_offset_minutes=offset)
    spec = instance.schedule("night-market", weekday=6, start_minute=1430,
                             duration_minutes=30)
    expected = local_ts(6, 1430, offset_minutes=offset)
    assert spec.first_start_ts == expected
    window = instance.advance(expected + 60)[0]
    assert window.start_ts == expected
    assert window.end_ts == expected + 1800
    result = instance.claim_window(window.window_id, "acct-9")
    assert result.points == 100
    assert instance.windows_between(expected, expected + 1800) == (window,)


def test_stats_counters_track_activity():
    instance = planner()
    instance.schedule("moonfall", weekday=0, start_minute=600,
                      duration_minutes=30)
    start = BASE + 600 * 60
    window = instance.advance(start + 60)[0]
    instance.claim_window(window.window_id, "acct-1")
    with pytest.raises(wp.WorldEventError):
        instance.claim_window(window.window_id, "acct-1")
    with pytest.raises(wp.WorldEventError):
        instance.advance(BASE)
    counters = instance.stats()
    assert counters["events"] == 1
    assert counters["windows"] == 1
    assert counters["opened"] == 1
    assert counters["claims"] == 1
    assert counters["duplicates"] == 1
    assert counters["clock_rewinds"] == 1


def test_snapshot_roundtrip_keeps_claims():
    instance = planner()
    instance.schedule("moonfall", weekday=0, start_minute=600,
                      duration_minutes=30)
    start = BASE + 600 * 60
    window = instance.advance(start + 60)[0]
    instance.claim_window(window.window_id, "acct-1")
    snap = instance.snapshot()
    fresh = planner()
    fresh.restore(snap)
    restored = fresh.windows_between(BASE, BASE + DAY)
    assert len(restored) == 1
    assert restored[0].status == "claimed"
    assert restored[0].claims == ("acct-1",)
    instance.cancel_event("moonfall")
    assert fresh.event_record("moonfall").cancelled is False
    with pytest.raises(wp.WorldEventError) as exc:
        fresh.claim_window(window.window_id, "acct-1")
    assert exc.value.code == "WORLD_EVENT_DUPLICATE_CLAIM"


def test_restore_rejects_malformed_state():
    instance = planner()
    instance.schedule("moonfall", weekday=0, start_minute=600,
                      duration_minutes=30)
    start = BASE + 600 * 60
    instance.advance(start)
    before = instance.windows_between(BASE, BASE + DAY)
    with pytest.raises(wp.WorldEventError) as exc:
        instance.restore({"clock": "soon", "events": {}, "windows": {}})
    assert exc.value.code == "WORLD_EVENT_SNAPSHOT_INVALID"
    assert instance.windows_between(BASE, BASE + DAY) == before
    with pytest.raises(wp.WorldEventError) as exc:
        instance.restore({"clock": BASE + 10, "events": [], "windows": {}})
    assert exc.value.code == "WORLD_EVENT_SNAPSHOT_INVALID"


def test_concurrent_advance_materializes_window_once():
    instance = planner()
    instance.schedule("moonfall", weekday=0, start_minute=600,
                      duration_minutes=30)
    target = BASE + 600 * 60 + 60
    barrier = threading.Barrier(8)
    created = []
    errors = []
    lock = threading.Lock()

    def worker():
        try:
            barrier.wait(timeout=5)
            windows = instance.advance(target)
            with lock:
                created.extend(windows)
        except BaseException as exc:  # noqa: BLE001 - collected for assert
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == []
    assert len(created) == 1
    assert len(instance.windows_between(BASE, BASE + DAY)) == 1
