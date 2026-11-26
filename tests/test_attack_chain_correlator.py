import copy
from datetime import datetime, timedelta, timezone

import pytest

import attack_chain_correlator as ac

BASE = datetime(2026, 11, 26, 9, 0, 0, tzinfo=timezone.utc)


def at(seconds=0):
    return (BASE + timedelta(seconds=seconds)).isoformat()


def correlator(**kwargs):
    return ac.AttackChainCorrelator(**kwargs)


def ingest(cor, event_id, *, src="10.0.0.7", dst="db-01",
           stage="reconnaissance", ts=at(0)):
    return cor.ingest(event_id, src=src, dst=dst, stage=stage, ts=ts)


def test_ingest_opens_chain_for_new_key():
    cor = correlator()
    out = ingest(cor, "ev-1")
    assert out["event_id"] == "ev-1"
    assert out["attached"] is False
    assert out["isolated"] is False
    assert out["stage"] == "reconnaissance"
    chain = cor.chain_of(out["chain_id"])
    assert isinstance(chain, ac.Chain)
    assert (chain.src, chain.dst) == ("10.0.0.7", "db-01")
    assert chain.state == "open"
    assert chain.stage == "reconnaissance"
    assert chain.stages == ("reconnaissance",)
    assert chain.events == 1
    assert chain.isolated is False
    assert chain.opened_at == at(0)
    assert chain.last_event_at == at(0)
    assert chain.closed_at is None
    assert chain.close_reason is None
    assert cor.stages() == ("reconnaissance", "initial_access", "execution",
                            "persistence", "exfiltration", "impact")


def test_ingest_rejects_unknown_stage():
    cor = correlator()
    with pytest.raises(ac.ChainError) as exc:
        ingest(cor, "ev-1", stage="lateral_movement")
    assert exc.value.code == "CHAIN_BAD_STAGE"
    assert cor.chains() == []
    assert cor.stats()["ingested"] == 0


def test_ingest_rejects_empty_identifiers():
    cor = correlator()
    bad = [
        dict(event_id="", src="s", dst="d", stage="reconnaissance"),
        dict(event_id="ev-1", src="   ", dst="d", stage="reconnaissance"),
        dict(event_id="ev-2", src="s", dst="", stage="reconnaissance"),
    ]
    for kwargs in bad:
        with pytest.raises(ac.ChainError) as exc:
            cor.ingest(ts=at(0), **kwargs)
        assert exc.value.code == "CHAIN_BAD_REQUEST"
    assert cor.chains() == []


def test_ingest_rejects_duplicate_event_id():
    cor = correlator()
    ingest(cor, "ev-1")
    with pytest.raises(ac.ChainError) as exc:
        ingest(cor, "ev-1", src="10.0.0.8", dst="db-02", stage="execution",
               ts=at(5))
    assert exc.value.code == "CHAIN_DUPLICATE_EVENT"
    assert len(cor.chains()) == 1
    assert cor.stats()["ingested"] == 1


def test_progressive_stages_advance_and_append_sequence():
    cor = correlator()
    first = ingest(cor, "ev-1", stage="reconnaissance", ts=at(0))
    second = ingest(cor, "ev-2", stage="initial_access", ts=at(10))
    third = ingest(cor, "ev-3", stage="execution", ts=at(20))
    assert first["chain_id"] == second["chain_id"] == third["chain_id"]
    assert first["attached"] is False
    assert second["attached"] is True
    assert third["attached"] is True
    chain = cor.chain_of(first["chain_id"])
    assert chain.stage == "execution"
    assert chain.stages == ("reconnaissance", "initial_access", "execution")
    assert chain.events == 3
    assert chain.last_event_at == at(20)
    assert chain.opened_at == at(0)


def test_watermark_advance_is_monotonic():
    cor = correlator()
    assert cor.watermark() is None
    assert cor.advance_watermark(ts=at(100)) == at(100)
    assert cor.advance_watermark(ts=at(100)) == at(100)
    with pytest.raises(ac.ChainError) as exc:
        cor.advance_watermark(ts=at(99))
    assert exc.value.code == "CHAIN_WATERMARK_REGRESSION"
    assert cor.watermark() == at(100)


def test_event_inside_reorder_window_attaches_to_open_chain():
    cor = correlator(reorder_window=120)
    first = ingest(cor, "ev-1", stage="reconnaissance", ts=at(100))
    cor.advance_watermark(ts=at(400))
    out = ingest(cor, "ev-2", stage="execution", ts=at(350))
    assert out["attached"] is True
    assert out["isolated"] is False
    assert out["chain_id"] == first["chain_id"]
    chain = cor.chain_of(first["chain_id"])
    assert chain.stage == "execution"
    assert chain.stages == ("reconnaissance", "execution")
    assert chain.events == 2
    assert chain.last_event_at == at(350)


def test_event_beyond_reorder_window_becomes_isolated_chain():
    cor = correlator(reorder_window=120)
    first = ingest(cor, "ev-1", stage="reconnaissance", ts=at(100))
    cor.advance_watermark(ts=at(500))
    out = ingest(cor, "ev-2", stage="impact", ts=at(200))
    assert out["attached"] is False
    assert out["isolated"] is True
    assert out["chain_id"] != first["chain_id"]
    original = cor.chain_of(first["chain_id"])
    assert original.events == 1
    assert original.stage == "reconnaissance"
    assert original.isolated is False
    isolated = cor.chain_of(out["chain_id"])
    assert isolated.isolated is True
    assert isolated.stage == "impact"
    assert isolated.stages == ("impact",)


def test_close_stale_closes_only_silent_chains():
    cor = correlator(silence_timeout=600)
    first = ingest(cor, "ev-1", src="s1", dst="d1", ts=at(0))
    second = ingest(cor, "ev-2", src="s2", dst="d2", ts=at(1100))
    closed = cor.close_stale(now=at(1200))
    assert closed == (first["chain_id"],)
    stale = cor.chain_of(first["chain_id"])
    assert stale.state == "closed"
    assert stale.closed_at == at(1200)
    assert stale.stages == ("reconnaissance",)
    assert cor.chain_of(second["chain_id"]).state == "open"
    assert cor.close_stale(now=at(1300)) == ()


def test_close_chain_manual_close_and_errors():
    cor = correlator()
    out = ingest(cor, "ev-1")
    with pytest.raises(ac.ChainError) as exc:
        cor.close_chain("chain-999", reason="handoff", now=at(1))
    assert exc.value.code == "CHAIN_UNKNOWN_CHAIN"
    chain = cor.close_chain(out["chain_id"], reason="handoff", now=at(10))
    assert chain.state == "closed"
    assert chain.closed_at == at(10)
    assert chain.close_reason == "handoff"
    with pytest.raises(ac.ChainError) as exc:
        cor.close_chain(out["chain_id"], reason="again", now=at(20))
    assert exc.value.code == "CHAIN_ALREADY_CLOSED"


def test_chains_filter_by_state_and_sort_by_id():
    cor = correlator()
    first = ingest(cor, "ev-1", src="s1", dst="d", ts=at(0))
    second = ingest(cor, "ev-2", src="s2", dst="d", ts=at(1))
    third = ingest(cor, "ev-3", src="s3", dst="d", ts=at(2))
    cor.close_chain(second["chain_id"], reason="handoff", now=at(3))
    expected = [first["chain_id"], second["chain_id"], third["chain_id"]]
    assert [row.chain_id for row in cor.chains()] == expected
    assert [row.chain_id for row in cor.chains(state="open")] == [
        first["chain_id"], third["chain_id"]]
    assert [row.chain_id for row in cor.chains(state="closed")] == [
        second["chain_id"]]


def test_chain_for_event_maps_every_event():
    cor = correlator(reorder_window=60)
    first = ingest(cor, "ev-1", ts=at(0))
    cor.advance_watermark(ts=at(1000))
    late = ingest(cor, "ev-2", src="s2", dst="d2", stage="impact", ts=at(100))
    assert cor.chain_for_event("ev-1") == first["chain_id"]
    assert cor.chain_for_event("ev-2") == late["chain_id"]
    with pytest.raises(ac.ChainError) as exc:
        cor.chain_for_event("ev-404")
    assert exc.value.code == "CHAIN_UNKNOWN_EVENT"


def test_stats_counts_ingested_opened_isolated_and_closed():
    cor = correlator(reorder_window=60, silence_timeout=300)
    first = ingest(cor, "ev-1", ts=at(0))
    ingest(cor, "ev-2", stage="execution", ts=at(10))
    cor.advance_watermark(ts=at(1000))
    late = ingest(cor, "ev-3", src="s2", dst="d2", stage="reconnaissance",
                  ts=at(100))
    closed = cor.close_stale(now=at(2000))
    assert closed == tuple(sorted([first["chain_id"], late["chain_id"]]))
    assert cor.stats() == {"ingested": 3, "opened": 2,
                           "isolated": 1, "closed": 2}
    assert all(row.state == "closed" for row in cor.chains())


def test_snapshot_is_detached_and_restore_roundtrips():
    cor = correlator(reorder_window=120, silence_timeout=600)
    out = ingest(cor, "ev-1", ts=at(0))
    cor.advance_watermark(ts=at(500))
    cor.close_chain(out["chain_id"], reason="handoff", now=at(600))
    state = cor.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "chains", "events", "watermark", "stats"}

    state["chains"].clear()
    state["watermark"] = None
    state["stats"]["ingested"] = 99
    assert cor.chain_of(out["chain_id"]).state == "closed"
    assert cor.watermark() == at(500)

    clone = correlator()
    clone.restore(pristine)
    assert clone.watermark() == at(500)
    assert clone.chain_for_event("ev-1") == out["chain_id"]
    restored = clone.chain_of(out["chain_id"])
    assert restored.state == "closed"
    assert restored.close_reason == "handoff"
    assert restored.closed_at == at(600)
    assert clone.stats() == cor.stats()


def test_restore_rejects_malformed_state_without_touching_live():
    cor = correlator()
    out = ingest(cor, "ev-1")
    full_stats = {"ingested": 1, "opened": 1, "isolated": 0, "closed": 0}
    bad_states = [
        None,
        {},
        {"version": 2, "chains": [], "events": {}, "watermark": None,
         "stats": full_stats},
        {"version": 1, "chains": "nope", "events": {}, "watermark": None,
         "stats": full_stats},
        {"version": 1, "chains": [], "events": [], "watermark": None,
         "stats": full_stats},
        {"version": 1, "chains": [], "events": {}, "watermark": None,
         "stats": {"ingested": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(ac.ChainError) as exc:
            cor.restore(bad)
        assert exc.value.code == "CHAIN_SNAPSHOT_INVALID"

    assert cor.chain_of(out["chain_id"]).state == "open"
    assert cor.stats()["ingested"] == 1
