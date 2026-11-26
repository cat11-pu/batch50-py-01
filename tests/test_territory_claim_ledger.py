import threading

import pytest

import territory_claim_ledger as tl

SITE = "stone-ford"


def ledger(**kwargs):
    return tl.TerritoryClaimLedger(**kwargs)


def with_site(**kwargs):
    instance = ledger(**kwargs)
    instance.add_site(SITE)
    return instance


def test_add_site_creates_neutral_site():
    instance = ledger(claim_threshold=40, cooldown_ticks=3)
    state = instance.add_site(SITE)
    assert state.site_id == SITE
    assert state.owner is None
    assert state.claim_threshold == 40
    assert state.cooldown_ticks == 3
    assert state.cooldown_left == 0
    assert state.contenders == ()
    assert dict(state.progress) == {}
    assert state.suspended is False
    assert instance.owner_of(SITE) is None
    with pytest.raises(tl.TerritoryError) as exc:
        instance.add_site(SITE, owner="iron")
    assert exc.value.code == "TERRITORY_SITE_EXISTS"
    with pytest.raises(tl.TerritoryError) as exc:
        instance.add_site("   ", owner="iron")
    assert exc.value.code == "TERRITORY_INVALID_REQUEST"


def test_missing_site_lookups_are_rejected():
    instance = ledger()
    calls = [
        lambda: instance.owner_of("nowhere"),
        lambda: instance.cooldown_left("nowhere"),
        lambda: instance.state_of("nowhere"),
        lambda: instance.progress_of("nowhere", "iron"),
        lambda: instance.contenders("nowhere"),
    ]
    for call in calls:
        with pytest.raises(tl.TerritoryError) as exc:
            call()
        assert exc.value.code == "TERRITORY_UNKNOWN_SITE"


def test_join_contest_tracks_members_without_duplicates():
    instance = with_site()
    first = instance.join_contest(SITE, "iron", members=7)
    assert first.contenders == ("iron",)
    assert dict(first.progress) == {"iron": 0}
    second = instance.join_contest(SITE, "ash", members=3)
    assert second.contenders == ("iron", "ash")
    third = instance.join_contest(SITE, "iron", members=9)
    assert third.contenders == ("iron", "ash")
    assert instance.stats()["joins"] == 3
    instance.tick(SITE)
    assert instance.progress_of(SITE, "iron") == 9


def test_join_contest_validates_input():
    instance = with_site()
    for members in (0, -2):
        with pytest.raises(tl.TerritoryError) as exc:
            instance.join_contest(SITE, "iron", members=members)
        assert exc.value.code == "TERRITORY_INVALID_REQUEST"
    for guild in ("", "   "):
        with pytest.raises(tl.TerritoryError) as exc:
            instance.join_contest(SITE, guild, members=1)
        assert exc.value.code == "TERRITORY_INVALID_REQUEST"
    with pytest.raises(tl.TerritoryError) as exc:
        instance.join_contest(SITE, "iron", members="three")
    assert exc.value.code == "TERRITORY_INVALID_REQUEST"
    with pytest.raises(tl.TerritoryError) as exc:
        instance.join_contest("nowhere", "iron", members=1)
    assert exc.value.code == "TERRITORY_UNKNOWN_SITE"


def test_tick_accumulates_members_once_per_round():
    instance = ledger(claim_threshold=50)
    instance.add_site(SITE)
    instance.join_contest(SITE, "iron", members=6)
    instance.join_contest(SITE, "ash", members=4)
    first = instance.tick(SITE)
    assert first["site_id"] == SITE
    assert first["window_seq"] == 1
    assert first["cooldown_left"] == 0
    assert first["progress"] == {"iron": 6, "ash": 4}
    assert first["ready"] == ()
    assert first["suspended"] is False
    second = instance.tick(SITE)
    assert second["window_seq"] == 2
    assert second["progress"] == {"iron": 12, "ash": 8}
    assert instance.progress_of(SITE, "iron") == 12
    assert instance.progress_of(SITE, "nobody") == 0


def test_tick_caps_progress_at_threshold():
    instance = ledger(claim_threshold=10)
    instance.add_site(SITE)
    instance.join_contest(SITE, "iron", members=7)
    assert instance.tick(SITE)["progress"] == {"iron": 7}
    capped = instance.tick(SITE)
    assert capped["progress"] == {"iron": 10}
    assert capped["ready"] == ("iron",)
    assert instance.tick(SITE)["progress"] == {"iron": 10}


def test_tick_ready_order_is_alphabetical():
    instance = ledger(claim_threshold=5)
    instance.add_site(SITE)
    instance.join_contest(SITE, "zulu", members=9)
    instance.join_contest(SITE, "ash", members=5)
    instance.join_contest(SITE, "ember", members=5)
    result = instance.tick(SITE)
    assert result["ready"] == ("ash", "ember", "zulu")
    assert {"site_id", "owner", "window_seq", "cooldown_left", "progress",
            "ready", "suspended"} <= set(result)


def test_settle_requires_threshold_and_contender():
    instance = ledger(claim_threshold=5)
    instance.add_site(SITE)
    instance.join_contest(SITE, "iron", members=2)
    instance.tick(SITE)
    with pytest.raises(tl.TerritoryError) as exc:
        instance.settle(SITE, "iron")
    assert exc.value.code == "TERRITORY_NOT_READY"
    with pytest.raises(tl.TerritoryError) as exc:
        instance.settle(SITE, "ash")
    assert exc.value.code == "TERRITORY_NOT_CONTENDING"
    with pytest.raises(tl.TerritoryError) as exc:
        instance.settle("nowhere", "iron")
    assert exc.value.code == "TERRITORY_UNKNOWN_SITE"


def test_settle_transfers_ownership_and_starts_cooldown():
    instance = ledger(claim_threshold=4, cooldown_ticks=3)
    instance.add_site(SITE)
    instance.join_contest(SITE, "iron", members=4)
    instance.tick(SITE)
    event = instance.settle(SITE, "iron")
    assert event.site_id == SITE
    assert event.guild == "iron"
    assert event.previous_owner is None
    assert event.transferred is False
    assert instance.owner_of(SITE) == "iron"
    state = instance.state_of(SITE)
    assert state.cooldown_left == 3
    assert dict(state.progress) == {"iron": 0}
    assert instance.stats()["claims"] == 1
    assert instance.stats()["transfers"] == 0


def test_settle_by_current_owner_is_refused():
    instance = ledger(claim_threshold=3, cooldown_ticks=1)
    instance.add_site(SITE)
    instance.join_contest(SITE, "iron", members=3)
    instance.tick(SITE)
    instance.settle(SITE, "iron")
    instance.tick(SITE)
    assert instance.cooldown_left(SITE) == 0
    instance.tick(SITE)
    assert instance.progress_of(SITE, "iron") == 3
    with pytest.raises(tl.TerritoryError) as exc:
        instance.settle(SITE, "iron")
    assert exc.value.code == "TERRITORY_ALREADY_OWNER"


def test_cooldown_counts_down_with_ticks():
    instance = ledger(claim_threshold=2, cooldown_ticks=4)
    instance.add_site(SITE)
    instance.join_contest(SITE, "iron", members=2)
    instance.tick(SITE)
    instance.settle(SITE, "iron")
    assert instance.cooldown_left(SITE) == 4
    for expected in (3, 2, 1, 0):
        assert instance.tick(SITE)["cooldown_left"] == expected
    assert instance.tick(SITE)["cooldown_left"] == 0


def test_leave_contest_forfeits_progress_and_frees_slot():
    instance = ledger(claim_threshold=50, max_contenders_per_site=2)
    instance.add_site(SITE)
    instance.join_contest(SITE, "iron", members=5)
    instance.join_contest(SITE, "ash", members=5)
    instance.tick(SITE)
    state = instance.leave_contest(SITE, "ash")
    assert state.contenders == ("iron",)
    assert instance.progress_of(SITE, "ash") == 0
    assert instance.stats()["leaves"] == 1
    instance.join_contest(SITE, "zulu", members=1)
    assert instance.contenders(SITE) == ("iron", "zulu")
    with pytest.raises(tl.TerritoryError) as exc:
        instance.leave_contest(SITE, "ash")
    assert exc.value.code == "TERRITORY_NOT_CONTENDING"


def test_contender_capacity_is_enforced():
    instance = ledger(max_contenders_per_site=2)
    instance.add_site(SITE)
    instance.join_contest(SITE, "iron", members=1)
    instance.join_contest(SITE, "ash", members=1)
    with pytest.raises(tl.TerritoryError) as exc:
        instance.join_contest(SITE, "zulu", members=1)
    assert exc.value.code == "TERRITORY_CAPACITY_EXCEEDED"
    assert instance.contenders(SITE) == ("iron", "ash")
    assert instance.stats()["capacity_refusals"] == 1


def test_snapshot_roundtrip_and_invalid_restore():
    instance = ledger(claim_threshold=6, cooldown_ticks=3)
    instance.add_site(SITE)
    instance.join_contest(SITE, "iron", members=6)
    instance.tick(SITE)
    instance.settle(SITE, "iron")
    instance.join_contest(SITE, "ash", members=4)
    instance.tick(SITE)
    snap = instance.snapshot()
    fresh = ledger(claim_threshold=6, cooldown_ticks=3)
    fresh.restore(snap)
    assert fresh.owner_of(SITE) == "iron"
    assert fresh.progress_of(SITE, "ash") == 4
    assert fresh.cooldown_left(SITE) == instance.cooldown_left(SITE)
    assert fresh.contenders(SITE) == ("iron", "ash")
    instance.join_contest(SITE, "zulu", members=1)
    assert fresh.contenders(SITE) == ("iron", "ash")
    before = fresh.state_of(SITE)
    with pytest.raises(tl.TerritoryError) as exc:
        fresh.restore({"sites": "not-a-mapping"})
    assert exc.value.code == "TERRITORY_SNAPSHOT_INVALID"
    assert fresh.state_of(SITE) == before


def test_concurrent_joins_and_settles_stay_consistent():
    instance = ledger(claim_threshold=3, cooldown_ticks=1,
                      max_contenders_per_site=8)
    instance.add_site(SITE)
    barrier = threading.Barrier(6)
    errors = []

    def join(guild):
        try:
            barrier.wait(timeout=5)
            instance.join_contest(SITE, guild, members=3)
        except BaseException as exc:  # noqa: BLE001 - collected for assert
            errors.append(exc)

    threads = [threading.Thread(target=join, args=(f"g{i}",))
               for i in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == []
    assert len(instance.contenders(SITE)) == 6
    instance.tick(SITE)

    outcomes = []
    lock = threading.Lock()
    gate = threading.Barrier(2)

    def settle(guild):
        try:
            gate.wait(timeout=5)
            event = instance.settle(SITE, guild)
            with lock:
                outcomes.append(event)
        except tl.TerritoryError as exc:
            with lock:
                outcomes.append(exc.code)

    racers = [threading.Thread(target=settle, args=(g,))
              for g in ("g0", "g1")]
    for thread in racers:
        thread.start()
    for thread in racers:
        thread.join(timeout=10)
    events = [item for item in outcomes if not isinstance(item, str)]
    codes = [item for item in outcomes if isinstance(item, str)]
    assert len(events) == 1
    assert instance.owner_of(SITE) == events[0].guild
    assert codes and codes[0] in ("TERRITORY_NOT_READY",
                                  "TERRITORY_IN_COOLDOWN")
    assert instance.stats()["claims"] == 1
