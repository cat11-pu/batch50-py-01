import copy
import threading

import pytest

import wanted_heat_ledger as whl

NOW = "2026-11-22T08:00:00+00:00"
T10 = "2026-11-22T08:00:10+00:00"
T60 = "2026-11-22T08:01:00+00:00"
T120 = "2026-11-22T08:02:00+00:00"
T130 = "2026-11-22T08:02:10+00:00"
T175 = "2026-11-22T08:02:55+00:00"
T185 = "2026-11-22T08:03:05+00:00"


def ledger(**kwargs):
    return whl.WantedHeatLedger(**kwargs)


def test_add_heat_accumulates_per_region():
    book = ledger()
    first = book.add_heat("cowboy", "harbor", 40, now=NOW)
    assert first == {"player": "cowboy", "region": "harbor", "heat": 40,
                     "last_event": NOW}
    second = book.add_heat("cowboy", "harbor", 35, now=T10)
    assert second["heat"] == 75
    assert second["last_event"] == T10
    assert book.heat("cowboy") == 75
    assert book.heat("cowboy", "harbor") == 75
    assert book.heat("cowboy", "desert") == 0
    assert book.stats() == {"events": 2, "witnesses": 0, "decays": 0,
                            "claims": 0, "cleared": 0, "paid": 0}


def test_add_heat_rejects_bad_arguments():
    book = ledger()
    bad_calls = [
        dict(player="", region="harbor", amount=10),
        dict(player="  ", region="harbor", amount=10),
        dict(player="cowboy", region="", amount=10),
        dict(player="cowboy", region="harbor", amount=0),
        dict(player="cowboy", region="harbor", amount=-5),
        dict(player="cowboy", region="harbor", amount=1.5),
        dict(player="cowboy", region="harbor", amount=10, now="yesterday"),
    ]
    for kwargs in bad_calls:
        with pytest.raises(whl.WantedError) as exc:
            book.add_heat(now=NOW, **kwargs)
        assert exc.value.code == "WANTED_INVALID_REQUEST"
    assert book.stats()["events"] == 0
    assert book.records("cowboy") == []


def test_add_heat_clamps_at_region_cap():
    book = ledger(heat_cap=100)
    book.add_heat("cowboy", "harbor", 60, now=NOW)
    out = book.add_heat("cowboy", "harbor", 70, now=T10)
    assert out["heat"] == 100
    assert book.heat("cowboy", "harbor") == 100
    assert book.stats()["events"] == 2


def test_region_capacity_per_player():
    book = ledger(max_regions=2)
    book.add_heat("cowboy", "a", 10, now=NOW)
    book.add_heat("cowboy", "b", 10, now=NOW)
    with pytest.raises(whl.WantedError) as exc:
        book.add_heat("cowboy", "c", 10, now=NOW)
    assert exc.value.code == "WANTED_CAPACITY_EXCEEDED"
    assert [row["region"] for row in book.records("cowboy")] == ["a", "b"]
    book.add_heat("ranger", "c", 10, now=NOW)
    assert book.heat("ranger", "c") == 10


def test_witness_keeps_unique_sorted_ids():
    book = ledger()
    book.add_heat("cowboy", "harbor", 50, now=NOW)
    assert book.witness("cowboy", "harbor", "w2", now=NOW)["witnesses"] == 1
    assert book.witness("cowboy", "harbor", "w1", now=NOW)["witnesses"] == 2
    assert book.witness("cowboy", "harbor", "w2", now=NOW)["witnesses"] == 2
    assert book.records("cowboy") == [
        {"region": "harbor", "heat": 50, "witnesses": ["w1", "w2"],
         "last_event": NOW}]
    assert book.stats()["witnesses"] == 2


def test_witness_requires_known_region_and_valid_id():
    book = ledger()
    book.add_heat("cowboy", "harbor", 50, now=NOW)
    with pytest.raises(whl.WantedError) as exc:
        book.witness("cowboy", "desert", "w1", now=NOW)
    assert exc.value.code == "WANTED_UNKNOWN_REGION"
    with pytest.raises(whl.WantedError) as exc:
        book.witness("cowboy", "harbor", "   ", now=NOW)
    assert exc.value.code == "WANTED_INVALID_REQUEST"


def test_bounty_counts_witnesses_and_heat_blocks():
    book = ledger()
    book.add_heat("cowboy", "harbor", 250, now=NOW)
    book.witness("cowboy", "harbor", "w1", now=NOW)
    out = book.bounty("cowboy")
    assert out["player"] == "cowboy"
    assert out["regions"] == {"harbor": 2550}
    assert out["total"] == 2550
    book.witness("cowboy", "harbor", "w2", now=NOW)
    assert book.bounty("cowboy") == {"player": "cowboy", "total": 2600,
                                     "regions": {"harbor": 2600}}


def test_bounty_total_is_capped():
    book = ledger(bounty_cap=500)
    book.add_heat("cowboy", "harbor", 1000, now=NOW)
    book.witness("cowboy", "harbor", "w1", now=NOW)
    assert book.bounty("cowboy")["total"] == 500


def test_decay_removes_heat_by_whole_intervals():
    book = ledger(decay_interval=60, decay_step=10)
    book.add_heat("cowboy", "harbor", 50, now=NOW)
    assert book.decay("cowboy", now=T130) == 20
    assert book.heat("cowboy", "harbor") == 30
    assert book.decay("cowboy", now=T175) == 0
    assert book.heat("cowboy", "harbor") == 30
    assert book.decay("cowboy", now=T185) == 10
    assert book.heat("cowboy", "harbor") == 20
    assert book.stats()["decays"] == 2


def test_decay_to_zero_drops_region_records():
    book = ledger(decay_interval=60, decay_step=10)
    book.add_heat("cowboy", "harbor", 15, now=NOW)
    book.decay("cowboy", now=T60)
    assert book.heat("cowboy", "harbor") == 5
    book.decay("cowboy", now=T120)
    assert book.records("cowboy") == []
    assert book.heat("cowboy") == 0
    assert book.list_wanted() == []


def test_decay_rejects_clock_regression():
    book = ledger()
    book.add_heat("cowboy", "harbor", 50, now=T10)
    with pytest.raises(whl.WantedError) as exc:
        book.decay("cowboy", now=NOW)
    assert exc.value.code == "WANTED_CLOCK_REGRESSION"
    assert book.heat("cowboy", "harbor") == 50


def test_claim_bounty_pays_only_once():
    book = ledger()
    book.add_heat("cowboy", "harbor", 250, now=NOW)
    book.witness("cowboy", "harbor", "w1", now=NOW)
    paid = book.claim_bounty("cowboy", "harbor", "ranger", now=NOW)
    assert paid == {"player": "cowboy", "region": "harbor", "amount": 2550,
                    "claimant": "ranger"}
    assert book.bounty("cowboy")["total"] == 0
    with pytest.raises(whl.WantedError) as exc:
        book.claim_bounty("cowboy", "harbor", "ranger", now=NOW)
    assert exc.value.code == "WANTED_NO_BOUNTY"
    book.add_heat("cowboy", "desert", 60, now=NOW)
    book.witness("cowboy", "desert", "w3", now=NOW)
    with pytest.raises(whl.WantedError) as exc:
        book.claim_bounty("cowboy", "desert", "  ", now=NOW)
    assert exc.value.code == "WANTED_INVALID_REQUEST"
    assert book.stats()["claims"] == 1


def test_clear_needs_cooldown_or_payment():
    book = ledger(clear_cooldown=120, fine_per_heat=5)
    book.add_heat("cowboy", "harbor", 40, now=NOW)
    with pytest.raises(whl.WantedError) as exc:
        book.clear("cowboy", "harbor", now=T10)
    assert exc.value.code == "WANTED_COOLDOWN_ACTIVE"
    out = book.clear("cowboy", "harbor", now=T10, payment=200)
    assert out == {"player": "cowboy", "region": "harbor", "cleared": True,
                   "paid": 200, "heat_removed": 40}
    assert book.records("cowboy") == []
    book.add_heat("cowboy", "desert", 20, now=T10)
    free = book.clear("cowboy", "desert", now=T130)
    assert free["paid"] == 0
    assert free["heat_removed"] == 20
    assert book.stats() == {"events": 2, "witnesses": 0, "decays": 0,
                            "claims": 0, "cleared": 2, "paid": 200}


def test_snapshot_is_detached_and_restore_roundtrips():
    source = ledger()
    source.add_heat("cowboy", "harbor", 250, now=NOW)
    source.witness("cowboy", "harbor", "w1", now=NOW)
    source.add_heat("cowboy", "desert", 40, now=NOW)
    before = source.bounty("cowboy")
    state = source.snapshot()
    assert set(state) == {"version", "players", "stats"}
    assert state["version"] == 1
    pristine = copy.deepcopy(state)
    state["players"].clear()
    state["stats"]["events"] = 99
    assert source.stats()["events"] == 2
    assert source.heat("cowboy") == 290

    clone = ledger()
    clone.restore(pristine)
    assert clone.stats() == source.stats()
    assert clone.heat("cowboy") == 290
    assert clone.bounty("cowboy") == before
    assert clone.records("cowboy") == source.records("cowboy")
    clone.add_heat("cowboy", "harbor", 10, now=NOW)
    assert clone.heat("cowboy", "harbor") == 260

    for bad in (None, {}, {**pristine, "version": 2},
                {**pristine, "players": []},
                {key: value for key, value in pristine.items()
                 if key != "stats"},
                {**pristine, "stats": {"events": 2}}):
        with pytest.raises(whl.WantedError) as exc:
            clone.restore(bad)
        assert exc.value.code == "WANTED_SNAPSHOT_INVALID"
    assert clone.heat("cowboy") == 300


def test_concurrent_events_sum_up_below_cap():
    book = ledger(heat_cap=1000)
    errors = []
    barrier = threading.Barrier(10)

    def worker():
        try:
            barrier.wait(timeout=5)
            book.add_heat("cowboy", "harbor", 30, now=NOW)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(10)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert book.stats()["events"] == 10
    assert book.heat("cowboy", "harbor") == 300
