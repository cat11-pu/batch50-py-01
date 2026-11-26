import copy
import threading

import pytest

import resurrect_ledger as rl

NOW = "2026-11-26T10:00:00+00:00"
LATER = "2026-11-26T10:00:10+00:00"
WINDOW_END = "2026-11-26T10:01:01+00:00"
SECOND_END = "2026-11-26T10:02:01+00:00"
FREE_COOLDOWNS = {"in_place": 0, "town": 0, "teammate": 0}


def ledger(**kwargs):
    return rl.ResurrectLedger(**kwargs)


def test_register_character_and_initial_state():
    led = ledger()
    initial = led.register_character("c1", gold=100)
    assert initial == {"character": "c1", "state": "alive", "gold": 100,
                       "stacks": 0, "deaths": 0}
    assert led.state_of("c1") == initial
    assert led.stats() == {"registered": 1, "deaths": 0, "resurrected": 0,
                           "requests": 0, "expired": 0, "cancelled": 0}
    with pytest.raises(rl.ResurrectError) as exc:
        led.register_character("   ")
    assert exc.value.code == "RESURRECT_INVALID_REQUEST"
    with pytest.raises(rl.ResurrectError) as exc:
        led.register_character("c1")
    assert exc.value.code == "RESURRECT_INVALID_REQUEST"
    with pytest.raises(rl.ResurrectError) as exc:
        led.state_of("ghost")
    assert exc.value.code == "RESURRECT_UNKNOWN_CHARACTER"


def test_die_enters_soul_state_and_stacks_penalty():
    led = ledger()
    led.register_character("c1", gold=50)
    out = led.die("c1", now=NOW)
    assert out == {"character": "c1", "state": "soul", "gold": 50,
                   "stacks": 1, "deaths": 1}
    with pytest.raises(rl.ResurrectError) as exc:
        led.die("c1", now=NOW)
    assert exc.value.code == "RESURRECT_ALREADY_DEAD"
    assert led.stats()["deaths"] == 1


def test_in_place_resurrect_charges_gold_and_cooldown():
    led = ledger()
    led.register_character("c1", gold=100)
    led.die("c1", now=NOW)
    out = led.resurrect("c1", "in_place", now=NOW)
    assert out == {"character": "c1", "mode": "in_place", "state": "alive",
                   "gold": 50, "cost": 50, "stacks": 1, "deaths": 1}
    assert led.penalty_of("c1", now=NOW) == {"stacks": 1, "remaining": 60}
    assert led.cooldown_of("c1", "in_place", now=NOW) == 20
    assert led.stats()["resurrected"] == 1


def test_insufficient_gold_leaves_soul_state():
    led = ledger()
    led.register_character("c1", gold=20)
    led.die("c1", now=NOW)
    with pytest.raises(rl.ResurrectError) as exc:
        led.resurrect("c1", "in_place", now=NOW)
    assert exc.value.code == "RESURRECT_INSUFFICIENT_FUNDS"
    assert led.state_of("c1") == {"character": "c1", "state": "soul",
                                  "gold": 20, "stacks": 1, "deaths": 1}
    assert led.stats()["resurrected"] == 0
    cheap = led.resurrect("c1", "town", now=NOW)
    assert cheap["gold"] == 10
    assert cheap["cost"] == 10


def test_resurrect_rejects_living_character_and_unknown_mode():
    led = ledger()
    led.register_character("c1", gold=100)
    with pytest.raises(rl.ResurrectError) as exc:
        led.resurrect("c1", "in_place", now=NOW)
    assert exc.value.code == "RESURRECT_NOT_DEAD"
    led.die("c1", now=NOW)
    with pytest.raises(rl.ResurrectError) as exc:
        led.resurrect("c1", "necromancy", now=NOW)
    assert exc.value.code == "RESURRECT_INVALID_REQUEST"
    assert led.state_of("c1")["state"] == "soul"
    assert led.state_of("c1")["gold"] == 100


def test_mode_cooldown_blocks_same_mode_only():
    led = ledger()
    led.register_character("c1", gold=200)
    led.die("c1", now=NOW)
    led.resurrect("c1", "in_place", now=NOW)
    led.die("c1", now=NOW)
    with pytest.raises(rl.ResurrectError) as exc:
        led.resurrect("c1", "in_place", now=NOW)
    assert exc.value.code == "RESURRECT_COOLDOWN_ACTIVE"
    assert led.state_of("c1")["gold"] == 150
    town = led.resurrect("c1", "town", now=NOW)
    assert town["gold"] == 140
    assert led.cooldown_of("c1", "in_place", now=NOW) == 20
    assert led.cooldown_of("c1", "town", now=NOW) == 5
    assert led.stats()["resurrected"] == 2


def test_teammate_resurrect_consumes_pending_request():
    led = ledger()
    led.register_character("c1", gold=30)
    led.register_character("h1")
    led.die("c1", now=NOW)
    with pytest.raises(rl.ResurrectError) as exc:
        led.resurrect("c1", "teammate", now=NOW)
    assert exc.value.code == "RESURRECT_REQUEST_MISSING"
    request = led.request_help("c1", "h1", now=NOW)
    assert request == {"target": "c1", "helper": "h1", "issued_at": NOW}
    out = led.resurrect("c1", "teammate", now=NOW)
    assert out == {"character": "c1", "mode": "teammate", "state": "alive",
                   "gold": 30, "cost": 0, "stacks": 1, "deaths": 1}
    assert led.pending_request("c1") is None


def test_request_issued_before_death_is_discarded():
    led = ledger()
    led.register_character("c1")
    led.register_character("h1")
    led.request_help("c1", "h1", now=NOW)
    assert led.pending_request("c1")["helper"] == "h1"
    led.die("c1", now=NOW)
    assert led.pending_request("c1") is None
    with pytest.raises(rl.ResurrectError) as exc:
        led.resurrect("c1", "teammate", now=NOW)
    assert exc.value.code == "RESURRECT_REQUEST_MISSING"
    assert led.stats()["requests"] == 1
    assert led.stats()["deaths"] == 1


def test_request_validation_and_cancel():
    led = ledger()
    led.register_character("c1")
    led.register_character("h1")
    with pytest.raises(rl.ResurrectError) as exc:
        led.request_help("c1", "c1", now=NOW)
    assert exc.value.code == "RESURRECT_INVALID_REQUEST"
    with pytest.raises(rl.ResurrectError) as exc:
        led.request_help("c1", "ghost", now=NOW)
    assert exc.value.code == "RESURRECT_UNKNOWN_CHARACTER"
    with pytest.raises(rl.ResurrectError) as exc:
        led.request_help("ghost", "h1", now=NOW)
    assert exc.value.code == "RESURRECT_UNKNOWN_CHARACTER"
    led.request_help("c1", "h1", now=NOW)
    assert led.cancel_request("c1") is True
    assert led.pending_request("c1") is None
    assert led.cancel_request("c1") is False
    assert led.stats()["requests"] == 1
    assert led.stats()["cancelled"] == 1


def test_penalty_stacks_are_capped():
    led = ledger(max_stacks=3, cooldowns=FREE_COOLDOWNS)
    led.register_character("c1", gold=1000)
    for _ in range(4):
        led.die("c1", now=NOW)
        led.resurrect("c1", "in_place", now=NOW)
    assert led.state_of("c1") == {"character": "c1", "state": "alive",
                                  "gold": 800, "stacks": 3, "deaths": 4}
    assert led.penalty_of("c1", now=NOW) == {"stacks": 3, "remaining": 60}


def test_expire_penalty_peels_one_layer_per_window():
    led = ledger(cooldowns=FREE_COOLDOWNS)
    led.register_character("c1", gold=1000)
    for _ in range(3):
        led.die("c1", now=NOW)
        led.resurrect("c1", "in_place", now=NOW)
    assert led.penalty_of("c1", now=NOW) == {"stacks": 3, "remaining": 60}
    assert led.expire_penalty(now=WINDOW_END) == 1
    assert led.penalty_of("c1", now=WINDOW_END) == {"stacks": 2, "remaining": 1}
    assert led.expire_penalty(now=WINDOW_END) == 0
    assert led.expire_penalty(now=SECOND_END) == 1
    assert led.penalty_of("c1", now=SECOND_END) == {"stacks": 1, "remaining": 1}
    assert led.stats()["expired"] == 2


def test_snapshot_is_detached_and_restore_roundtrips():
    led = ledger()
    led.register_character("c1", gold=100)
    led.register_character("h1")
    led.die("c1", now=NOW)
    led.resurrect("c1", "in_place", now=NOW)
    led.die("c1", now=LATER)
    led.request_help("c1", "h1", now=LATER)
    state = led.snapshot()
    assert set(state) == {"version", "characters", "stats"}
    pristine = copy.deepcopy(state)
    state["characters"].clear()
    state["stats"]["deaths"] = 99
    assert led.state_of("c1")["deaths"] == 2
    assert led.pending_request("c1")["helper"] == "h1"

    clone = ledger()
    clone.restore(pristine)
    assert clone.state_of("c1") == {"character": "c1", "state": "soul",
                                    "gold": 50, "stacks": 2, "deaths": 2}
    assert clone.penalty_of("c1", now=LATER) == {"stacks": 2, "remaining": 60}
    assert clone.cooldown_of("c1", "in_place", now=LATER) == 10
    assert clone.pending_request("c1") == {"target": "c1", "helper": "h1",
                                           "issued_at": LATER}
    out = clone.resurrect("c1", "teammate", now=LATER)
    assert out["state"] == "alive"
    assert out["gold"] == 50


def test_restore_rejects_malformed_state_without_touching_live_data():
    led = ledger()
    led.register_character("c1", gold=100)
    led.die("c1", now=NOW)
    good = led.snapshot()
    bad_states = [
        None,
        {},
        {**good, "version": 2},
        {key: value for key, value in good.items() if key != "stats"},
        {**good, "characters": []},
        {**good, "characters": {"c1": "soul"}},
        {**good, "characters": {"c1": {"state": "soul"}}},
        {**good, "stats": {"registered": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(rl.ResurrectError) as exc:
            led.restore(bad)
        assert exc.value.code == "RESURRECT_SNAPSHOT_INVALID"
    assert led.state_of("c1")["state"] == "soul"
    assert led.stats()["deaths"] == 1
    assert led.state_of("c1")["gold"] == 100


def test_stats_track_mixed_death_sequence():
    led = ledger()
    led.register_character("c1", gold=100)
    led.register_character("h1")
    led.request_help("c1", "h1", now=NOW)
    led.die("c1", now=NOW)
    led.resurrect("c1", "in_place", now=NOW)
    led.die("c1", now=NOW)
    led.expire_penalty(now=WINDOW_END)
    led.resurrect("c1", "town", now=NOW)
    assert led.stats() == {"registered": 2, "deaths": 2, "resurrected": 2,
                           "requests": 1, "expired": 1, "cancelled": 0}


def test_concurrent_resurrection_settles_once():
    led = ledger()
    led.register_character("c1", gold=100)
    led.register_character("h1")
    led.die("c1", now=NOW)
    led.request_help("c1", "h1", now=NOW)
    outcomes = []
    barrier = threading.Barrier(2)

    def worker(mode):
        try:
            barrier.wait(timeout=5)
            led.resurrect("c1", mode, now=NOW)
            outcomes.append("ok")
        except rl.ResurrectError as exc:
            outcomes.append(exc.code)

    threads = [threading.Thread(target=worker, args=(mode,))
               for mode in ("in_place", "teammate")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert outcomes.count("ok") == 1
    assert outcomes.count("RESURRECT_NOT_DEAD") == 1
    assert led.state_of("c1")["state"] == "alive"
    assert led.stats()["resurrected"] == 1
