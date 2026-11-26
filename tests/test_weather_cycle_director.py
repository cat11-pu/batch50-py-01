import copy
import threading

import pytest

import weather_cycle_director as wcd

DURATIONS = {"clear": 20, "cloudy": 20, "rain": 20, "storm": 20}
STATES = ("clear", "cloudy", "rain", "storm")


def director(**kwargs):
    kwargs.setdefault("durations", dict(DURATIONS))
    kwargs.setdefault("seed", 11)
    return wcd.WeatherCycleDirector(**kwargs)


def test_register_region_defaults_and_counters():
    sky = director()
    out = sky.register_region("harbor")
    assert out["region"] == "harbor"
    assert out["state"] == "clear"
    assert out["remaining"] == 20
    assert out["seed"] == 11
    assert out["overridden"] is False
    assert sky.list_regions() == ["harbor"]
    assert sky.stats() == {"ticks": 0, "regions": 1, "switches": 0,
                           "overrides": 0, "cleared": 0, "expired": 0,
                           "forecasts": 0}
    with pytest.raises(wcd.WeatherError) as exc:
        sky.register_region("harbor")
    assert exc.value.code == "WEATHER_REGION_EXISTS"


def test_register_region_rejects_bad_input():
    sky = director()
    bad_calls = [
        dict(region_id=""),
        dict(region_id="   "),
        dict(region_id="harbor", state="snow"),
        dict(region_id="harbor", remaining=0),
        dict(region_id="harbor", remaining=-5),
        dict(region_id="harbor", remaining="10"),
        dict(region_id="harbor", seed="x"),
    ]
    for kwargs in bad_calls:
        with pytest.raises(wcd.WeatherError) as exc:
            sky.register_region(**kwargs)
        assert exc.value.code == "WEATHER_INVALID_REQUEST"
    assert sky.list_regions() == []
    assert sky.stats()["regions"] == 0


def test_region_capacity_is_enforced():
    sky = director(max_regions=2)
    sky.register_region("a")
    sky.register_region("b", state="rain", remaining=15)
    with pytest.raises(wcd.WeatherError) as exc:
        sky.register_region("c")
    assert exc.value.code == "WEATHER_CAPACITY_EXCEEDED"
    assert sky.list_regions() == ["a", "b"]
    assert sky.stats()["regions"] == 2


def test_advance_burns_remaining_without_switching():
    sky = director()
    sky.register_region("harbor")
    assert sky.advance(5) == []
    row = sky.current("harbor")
    assert row["state"] == "clear"
    assert row["remaining"] == 15
    assert sky.advance(3) == []
    assert sky.current("harbor")["remaining"] == 12
    assert sky.stats()["ticks"] == 8
    assert sky.stats()["switches"] == 0


def test_advance_reports_switch_tick_and_carries_leftover():
    sky = director()
    sky.register_region("harbor")
    events = sky.advance(25)
    assert len(events) == 1
    event = events[0]
    assert event["tick"] == 20
    assert event["region"] == "harbor"
    assert event["from"] == "clear"
    assert event["to"] in STATES and event["to"] != "clear"
    row = sky.current("harbor")
    assert row["state"] == event["to"]
    assert row["remaining"] == 15
    assert sky.stats()["switches"] == 1
    assert sky.stats()["ticks"] == 25


def test_advance_rejects_non_positive_or_non_integer_ticks():
    sky = director()
    sky.register_region("harbor")
    for bad in (0, -3, 1.5, "4", None):
        with pytest.raises(wcd.WeatherError) as exc:
            sky.advance(bad)
        assert exc.value.code == "WEATHER_INVALID_REQUEST"
    assert sky.stats()["ticks"] == 0
    assert sky.current("harbor")["remaining"] == 20


def test_blend_progresses_from_zero_to_full_over_transition():
    sky = director(transition_ticks=4)
    sky.register_region("harbor")
    sky.advance(20)
    row = sky.current("harbor")
    assert row["blend"] == 0.0
    sky.advance(2)
    row = sky.current("harbor")
    assert row["blend"] == 0.5
    step = sky.transition_state("harbor")
    assert step["elapsed"] == 2
    assert step["total"] == 4
    assert step["blend"] == 0.5
    assert step["from"] == "clear"
    assert step["to"] == row["state"]
    sky.advance(5)
    step = sky.transition_state("harbor")
    assert step["elapsed"] == 4
    assert step["blend"] == 1.0


def test_forecast_is_pure_and_deterministic():
    sky = director(max_forecast=4)
    sky.register_region("harbor")
    rows = sky.forecast("harbor", slots=3)
    assert [row["slot"] for row in rows] == [1, 2, 3]
    assert rows[0]["state"] == "clear"
    assert len(rows) == 3
    for row in rows:
        assert row["state"] in STATES
        assert row["ticks"] == 20
    again = sky.forecast("harbor", slots=3)
    assert again == rows
    assert sky.current("harbor")["state"] == "clear"
    assert sky.current("harbor")["remaining"] == 20
    assert sky.stats()["forecasts"] == 2


def test_forecast_rejects_out_of_range_slots_and_unknown_region():
    sky = director(max_forecast=4)
    sky.register_region("harbor")
    for bad in (0, 5, -1, "2"):
        with pytest.raises(wcd.WeatherError) as exc:
            sky.forecast("harbor", slots=bad)
        assert exc.value.code == "WEATHER_INVALID_REQUEST"
    for call in (sky.current, sky.transition_state, sky.active_overrides,
                 lambda region: sky.forecast(region),
                 lambda region: sky.override(region, "rain")):
        with pytest.raises(wcd.WeatherError) as exc:
            call("nowhere")
        assert exc.value.code == "WEATHER_UNKNOWN_REGION"


def test_override_wins_by_priority_then_recency():
    sky = director()
    sky.register_region("harbor")
    sky.override("harbor", "storm", priority=1, source="event-A")
    row = sky.current("harbor")
    assert row["state"] == "storm"
    assert row["overridden"] is True
    assert row["source"] == "event-A"
    sky.override("harbor", "rain", priority=5, source="admin-B")
    assert sky.current("harbor")["state"] == "rain"
    sky.override("harbor", "cloudy", priority=5, source="admin-C")
    assert sky.current("harbor")["state"] == "cloudy"
    assert sky.current("harbor")["source"] == "admin-C"
    assert [layer["state"] for layer in sky.active_overrides("harbor")] == [
        "cloudy", "rain", "storm"]
    assert sky.stats()["overrides"] == 3


def test_clear_override_removes_selected_layers_only():
    sky = director()
    sky.register_region("harbor")
    sky.override("harbor", "storm", priority=1, source="event-A")
    sky.override("harbor", "rain", priority=5, source="admin-B")
    assert sky.clear_override("harbor", priority=5) == 1
    row = sky.current("harbor")
    assert row["overridden"] is True
    assert row["source"] == "event-A"
    assert sky.clear_override("harbor", source="event-A") == 1
    assert sky.current("harbor")["overridden"] is False
    assert sky.active_overrides("harbor") == []
    assert sky.stats()["cleared"] == 2
    with pytest.raises(wcd.WeatherError) as exc:
        sky.clear_override("harbor")
    assert exc.value.code == "WEATHER_OVERRIDE_EMPTY"


def test_override_duration_expires_with_advance():
    sky = director()
    sky.register_region("harbor")
    layer = sky.override("harbor", "storm", priority=2,
                         source="festival", duration=3)
    assert layer["remaining"] == 3
    sky.advance(2)
    assert sky.current("harbor")["overridden"] is True
    assert sky.active_overrides("harbor")[0]["remaining"] == 1
    sky.advance(1)
    assert sky.current("harbor")["overridden"] is False
    assert sky.active_overrides("harbor") == []
    assert sky.stats()["expired"] == 1
    assert sky.stats()["overrides"] == 1


def test_snapshot_is_detached_and_restore_keeps_forecast():
    source = director()
    source.register_region("harbor")
    source.register_region("desert", state="rain")
    source.advance(25)
    source.override("harbor", "storm", priority=3, source="festival")
    source.forecast("desert", slots=2)
    state = source.snapshot()
    assert set(state) == {"version", "tick", "regions", "stats"}
    assert state["version"] == 1
    pristine = copy.deepcopy(state)
    state["regions"].clear()
    state["stats"]["ticks"] = 999
    assert source.stats()["ticks"] == 25
    assert source.list_regions() == ["desert", "harbor"]

    clone = director()
    clone.restore(pristine)
    assert clone.stats() == source.stats()
    assert clone.current("harbor") == source.current("harbor")
    assert clone.current("desert") == source.current("desert")
    assert clone.active_overrides("harbor") == source.active_overrides("harbor")
    assert clone.forecast("desert", slots=3) == source.forecast("desert", slots=3)
    assert clone.advance(2) == []
    assert clone.stats()["ticks"] == 27


def test_restore_rejects_malformed_state_without_touching_live_data():
    sky = director()
    sky.register_region("harbor")
    sky.advance(3)
    good = sky.snapshot()
    bad_states = [
        None,
        {},
        {key: value for key, value in good.items() if key != "regions"},
        {**good, "version": 2},
        {**good, "regions": []},
        {**good, "tick": "3"},
        {**good, "stats": {"ticks": 3}},
    ]
    for bad in bad_states:
        with pytest.raises(wcd.WeatherError) as exc:
            sky.restore(bad)
        assert exc.value.code == "WEATHER_SNAPSHOT_INVALID"
    assert sky.stats()["ticks"] == 3
    assert sky.current("harbor")["remaining"] == 17


def test_concurrent_advance_adds_up_exactly():
    sky = director()
    sky.register_region("harbor")
    errors = []
    barrier = threading.Barrier(6)

    def worker():
        try:
            barrier.wait(timeout=5)
            sky.advance(2)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert sky.stats()["ticks"] == 12
    assert sky.current("harbor")["state"] == "clear"
    assert sky.current("harbor")["remaining"] == 8
