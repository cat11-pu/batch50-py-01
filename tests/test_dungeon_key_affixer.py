import copy
import threading

import pytest

import dungeon_key_affixer as dk

POOL = ("raging", "bolstering", "bursting", "sanguine", "necrotic", "tyrannical")


def make(**kwargs):
    return dk.DungeonKeyAffixer(affix_pool=POOL, **kwargs)


def test_roll_key_builds_sorted_affix_triple():
    affixer = make()
    record = affixer.roll_key("k1", "party-a", 7, week=1)
    assert (record.key_id, record.party, record.level, record.week) == (
        "k1", "party-a", 7, 1,
    )
    assert record.status == "fresh"
    assert record.time_limit == 600
    assert record.time_spent == 0
    assert record.attempts_left == 5
    assert record.completions == 0
    assert len(record.affixes) == 3
    assert tuple(sorted(record.affixes)) == record.affixes
    assert len(set(record.affixes)) == 3
    assert set(record.affixes) <= set(POOL)


def test_affixes_are_deterministic_per_party_week_level():
    first = make()
    second = make()
    expected = first.affixes_for("party-a", 5, week=3)
    assert expected == first.affixes_for("party-a", 5, week=3)
    assert expected == second.affixes_for("party-a", 5, week=3)
    assert len(expected) == 3
    assert list(expected) == sorted(expected)
    assert set(expected) <= set(POOL)


def test_keys_for_same_party_week_level_share_affixes():
    affixer = make()
    one = affixer.roll_key("k1", "party-b", 4, week=2)
    two = affixer.roll_key("k2", "party-b", 4, week=2)
    assert one.affixes == two.affixes == affixer.affixes_for("party-b", 4, week=2)
    assert affixer.level_of("k1") == 4
    assert affixer.level_of("k2") == 4
    assert affixer.key_of("k2").key_id == "k2"


def test_roll_key_rejects_bad_level_and_duplicate_id():
    affixer = make()
    for level in (0, 16, -3):
        with pytest.raises(dk.DungeonKeyError) as exc:
            affixer.roll_key("bad", "party", level, week=1)
        assert exc.value.code == "KEY_LEVEL_OUT_OF_RANGE"
    affixer.roll_key("dup", "party", 3, week=1)
    with pytest.raises(dk.DungeonKeyError) as exc:
        affixer.roll_key("dup", "party", 4, week=1)
    assert exc.value.code == "KEY_DUPLICATE"


def test_enter_requires_fresh_key():
    affixer = make()
    affixer.roll_key("k1", "party", 3, week=1)
    entered = affixer.enter("k1")
    assert entered.status == "active"
    with pytest.raises(dk.DungeonKeyError) as exc:
        affixer.enter("k1")
    assert exc.value.code == "KEY_STATE_CONFLICT"
    assert affixer.stats()["entered"] == 1


def test_complete_within_limit_grants_bonus_time():
    affixer = make()
    affixer.roll_key("k1", "party", 3, week=1)
    affixer.enter("k1")
    outcome = affixer.complete("k1", elapsed=500)
    assert outcome.within_limit is True
    assert outcome.downgraded is False
    assert outcome.bonus_granted == 90
    assert outcome.level == 3
    assert outcome.completions == 1
    record = affixer.key_of("k1")
    assert record.status == "fresh"
    assert record.time_limit == 690
    assert record.time_spent == 0


def test_fail_consumes_attempts_and_depletes_key():
    affixer = make(attempts=2)
    affixer.roll_key("k1", "party", 2, week=1)
    affixer.enter("k1")
    record = affixer.fail("k1")
    assert record.status == "fresh"
    assert record.attempts_left == 1
    affixer.enter("k1")
    record = affixer.fail("k1")
    assert record.status == "depleted"
    assert record.attempts_left == 0
    with pytest.raises(dk.DungeonKeyError) as exc:
        affixer.enter("k1")
    assert exc.value.code == "KEY_ATTEMPTS_EXHAUSTED"


def test_weekly_reset_downgrades_unused_keys_only():
    affixer = make(start_week=1)
    affixer.roll_key("unused", "party", 5, week=1)
    affixer.roll_key("active", "party", 5, week=1)
    affixer.enter("active")
    result = affixer.weekly_reset(week=2)
    assert result["week"] == 2
    assert result["downgraded"] == 1
    assert result["deferred"] == 1
    reset_key = affixer.key_of("unused")
    assert reset_key.level == 4
    assert reset_key.week == 2
    assert reset_key.affixes == affixer.affixes_for("party", 4, week=2)
    assert reset_key.time_limit == 600
    assert affixer.key_of("active").level == 5


def test_weekly_reset_rejects_stale_week():
    affixer = make(start_week=2)
    with pytest.raises(dk.DungeonKeyError) as exc:
        affixer.weekly_reset(week=2)
    assert exc.value.code == "KEY_WEEK_INVALID"
    affixer.weekly_reset(week=3)
    with pytest.raises(dk.DungeonKeyError) as exc:
        affixer.weekly_reset(week=3)
    assert exc.value.code == "KEY_WEEK_INVALID"
    with pytest.raises(dk.DungeonKeyError) as exc:
        affixer.weekly_reset(week=1)
    assert exc.value.code == "KEY_WEEK_INVALID"


def test_unknown_key_operations_raise_not_found():
    affixer = make()
    calls = (
        lambda: affixer.level_of("nope"),
        lambda: affixer.key_of("nope"),
        lambda: affixer.enter("nope"),
        lambda: affixer.complete("nope", elapsed=10),
    )
    for call in calls:
        with pytest.raises(dk.DungeonKeyError) as exc:
            call()
        assert exc.value.code == "KEY_NOT_FOUND"


def test_concurrent_enter_allows_single_winner():
    affixer = make()
    affixer.roll_key("k1", "party", 3, week=1)
    winners = []
    errors = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            winners.append(affixer.enter("k1").status)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(getattr(exc, "code", repr(exc)))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert winners == ["active"]
    assert sorted(errors) == ["KEY_STATE_CONFLICT"] * 7


def test_snapshot_is_detached_from_live_state():
    affixer = make()
    affixer.roll_key("k1", "party", 4, week=2)
    affixer.enter("k1")
    state = affixer.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "week", "keys", "counters"}
    state["keys"].clear()
    state["counters"]["entered"] = 99
    assert affixer.level_of("k1") == 4
    assert affixer.stats()["entered"] == 1
    assert len(pristine["keys"]) == 1


def test_restore_roundtrip_preserves_keys_and_counters():
    affixer = make()
    affixer.roll_key("k1", "party", 6, week=3)
    affixer.enter("k1")
    affixer.complete("k1", elapsed=120)
    state = affixer.snapshot()
    clone = make()
    clone.restore(state)
    assert clone.stats() == affixer.stats()
    assert clone.level_of("k1") == 6
    record = clone.key_of("k1")
    assert record.affixes == affixer.key_of("k1").affixes
    assert record.time_limit == 690
    assert record.completions == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    affixer = make()
    affixer.roll_key("k1", "party", 2, week=1)
    affixer.enter("k1")
    bad_states = [
        None,
        {},
        {"version": 2, "week": 1, "keys": [], "counters": {}},
        {"version": 1, "week": 1, "keys": "nope", "counters": {}},
        {"version": 1, "week": 1, "keys": [], "counters": []},
        {"version": 1, "week": 1, "keys": [], "counters": {"entered": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(dk.DungeonKeyError) as exc:
            affixer.restore(bad)
        assert exc.value.code == "KEY_SNAPSHOT_INVALID"
    assert affixer.level_of("k1") == 2
    assert affixer.stats()["entered"] == 1


def test_stats_track_operations_exactly():
    affixer = make()
    affixer.roll_key("k1", "party", 2, week=1)
    affixer.roll_key("k2", "party", 2, week=1)
    affixer.enter("k1")
    affixer.fail("k1")
    affixer.enter("k2")
    affixer.complete("k2", elapsed=100)
    assert affixer.stats() == {
        "keys": 2,
        "fresh": 2,
        "active": 0,
        "depleted": 0,
        "entered": 2,
        "clears": 1,
        "failures": 1,
        "resets": 0,
        "week": 1,
    }
