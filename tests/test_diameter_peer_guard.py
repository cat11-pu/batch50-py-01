import threading

import pytest

import diameter_peer_guard as dg

NOW = "2026-11-26T08:00:00+00:00"
LATER = "2026-11-26T08:01:00+00:00"
LATER2 = "2026-11-26T08:02:00+00:00"

APPS = ("base", "credit", "auth")


def guard(**kwargs):
    return dg.DiameterPeerGuard(**kwargs)


def opened(**kwargs):
    g = guard(**kwargs)
    g.open_peer("peer-a", origin_host="gw-a.example", now=NOW)
    g.exchange_capabilities("peer-a", offered=list(APPS), wanted=list(APPS), now=NOW)
    return g


def test_open_peer_enters_wait_conn_ack_and_rejects_duplicate():
    g = guard()
    record = g.open_peer("peer-a", origin_host="gw-a.example", now=NOW)
    assert record.peer == "peer-a"
    assert record.origin_host == "gw-a.example"
    assert record.state == "WaitConnAck"
    assert record.applications == ()
    assert record.opened_at == NOW
    assert g.peer_state("peer-a") == "WaitConnAck"
    with pytest.raises(dg.DiameterError) as exc:
        g.open_peer("peer-a", origin_host="gw-b.example", now=LATER)
    assert exc.value.code == "PEER_DUPLICATE"
    assert g.stats()["peers_opened"] == 1


def test_capability_exchange_opens_peer_and_publishes_routes():
    g = guard()
    g.open_peer("peer-a", origin_host="gw-a.example", now=NOW)
    report = g.exchange_capabilities("peer-a", offered=["credit", "base", "auth"],
                                     wanted=["credit", "base"], now=LATER)
    assert report.peer == "peer-a"
    assert report.state == "Open"
    assert report.granted == ("base", "credit")
    assert report.rejected == ()
    assert g.peer_state("peer-a") == "Open"
    assert g.routes("credit") == ("peer-a",)
    assert g.routes("auth") == ()
    assert g.stats()["capability_rounds"] == 1


def test_capability_mismatch_closes_peer_and_counts_rejection():
    g = guard()
    g.open_peer("peer-a", origin_host="gw-a.example", now=NOW)
    with pytest.raises(dg.DiameterError) as exc:
        g.exchange_capabilities("peer-a", offered=["base"], wanted=["base", "credit"],
                                now=LATER)
    assert exc.value.code == "CAPABILITY_MISMATCH"
    assert g.peer_state("peer-a") == "Closed"
    assert g.routes("credit") == ()
    assert g.stats()["capability_rejected"] == 1
    assert g.stats()["capability_rounds"] == 0


def test_capability_exchange_guards_peer_state_and_identity():
    g = guard()
    with pytest.raises(dg.DiameterError) as exc:
        g.exchange_capabilities("ghost", offered=["base"], wanted=["base"], now=NOW)
    assert exc.value.code == "PEER_UNKNOWN"
    opened()
    g.exchange_capabilities("peer-a", offered=list(APPS), wanted=["base"], now=NOW)
    with pytest.raises(dg.DiameterError) as exc:
        g.exchange_capabilities("peer-a", offered=list(APPS), wanted=["base"], now=NOW)
    assert exc.value.code == "PEER_STATE_INVALID"


def test_send_ccr_generates_identifiers_and_reserves_units():
    g = opened()
    ticket = g.send_ccr("sess-1", subscriber="sub-1", peer="peer-a", requested=100, now=NOW)
    assert ticket.session_id == "sess-1"
    assert ticket.hop_by_hop == "h-1"
    assert ticket.end_to_end == "e-1"
    assert ticket.peer == "peer-a"
    assert ticket.requested == 100
    assert ticket.reserved == 100
    assert ticket.state == "sent"
    status = g.session_status("sess-1")
    assert status["state"] == "pending"
    assert status["reserved"] == 100
    assert status["used"] == 0
    assert g.stats()["ccr_sent"] == 1
    assert g.stats()["units_reserved"] == 100


def test_repeated_hop_returns_cached_ticket_without_reserving_again():
    g = opened()
    first = g.send_ccr("sess-1", subscriber="sub-1", peer="peer-a", requested=100,
                       hop_by_hop="h-77", end_to_end="e-77", now=NOW)
    again = g.send_ccr("sess-1", subscriber="sub-1", peer="peer-a", requested=100,
                       hop_by_hop="h-77", end_to_end="e-77", now=LATER)
    assert first.state == "sent"
    assert again.state == "retransmitted"
    assert again.hop_by_hop == "h-77"
    assert again.reserved == 100
    assert g.session_status("sess-1")["reserved"] == 100
    assert g.stats()["ccr_sent"] == 1
    assert g.stats()["retransmit"] == 1
    assert g.stats()["units_reserved"] == 100


def test_retransmit_budget_closes_session_and_releases_reservation():
    g = opened(max_retransmit=2)
    g.send_ccr("sess-1", subscriber="sub-1", peer="peer-a", requested=40,
               hop_by_hop="h-9", now=NOW)
    g.send_ccr("sess-1", subscriber="sub-1", peer="peer-a", requested=40,
               hop_by_hop="h-9", now=LATER)
    g.send_ccr("sess-1", subscriber="sub-1", peer="peer-a", requested=40,
               hop_by_hop="h-9", now=LATER2)
    with pytest.raises(dg.DiameterError) as exc:
        g.send_ccr("sess-1", subscriber="sub-1", peer="peer-a", requested=40,
                   hop_by_hop="h-9", now=LATER2)
    assert exc.value.code == "TRANSMIT_EXHAUSTED"
    status = g.session_status("sess-1")
    assert status["state"] == "closed"
    assert status["reserved"] == 0
    assert g.stats()["transmit_exhausted"] == 1
    assert g.stats()["units_returned"] == 40


def test_success_answer_settles_granted_units():
    g = opened()
    g.send_ccr("sess-1", subscriber="sub-1", peer="peer-a", requested=100,
               hop_by_hop="h-5", now=NOW)
    settlement = g.handle_answer("sess-1", hop_by_hop="h-5", result="success",
                                 granted=100, now=LATER)
    assert settlement.state == "answered"
    assert settlement.requested == 100
    assert settlement.used == 100
    assert settlement.returned == 0
    status = g.session_status("sess-1")
    assert status["state"] == "answered"
    assert status["reserved"] == 0
    assert status["used"] == 100
    assert g.stats()["answers_settled"] == 1
    assert g.stats()["units_returned"] == 0


def test_failed_answer_returns_whole_reservation():
    g = opened()
    g.send_ccr("sess-1", subscriber="sub-1", peer="peer-a", requested=60,
               hop_by_hop="h-6", now=NOW)
    settlement = g.handle_answer("sess-1", hop_by_hop="h-6", result="failure", now=LATER)
    assert settlement.state == "failed"
    assert settlement.used == 0
    assert settlement.returned == 60
    assert g.session_status("sess-1")["reserved"] == 0
    assert g.stats()["units_returned"] == 60


def test_answer_with_unknown_hop_is_rejected_as_stale():
    g = opened()
    g.send_ccr("sess-1", subscriber="sub-1", peer="peer-a", requested=100,
               hop_by_hop="h-5", now=NOW)
    with pytest.raises(dg.DiameterError) as exc:
        g.handle_answer("sess-1", hop_by_hop="h-404", result="success", granted=100,
                        now=LATER)
    assert exc.value.code == "ANSWER_STALE"
    assert g.session_status("sess-1")["reserved"] == 100
    assert g.stats()["answers_settled"] == 0


def test_reclaim_returns_unused_reservation_and_is_idempotent():
    g = opened()
    g.send_ccr("sess-1", subscriber="sub-1", peer="peer-a", requested=80,
               hop_by_hop="h-2", now=NOW)
    first = g.reclaim("sess-1", now=LATER)
    assert first.state == "closed"
    assert first.returned == 80
    second = g.reclaim("sess-1", now=LATER2)
    assert second.state == "closed"
    assert second.returned == 0
    assert g.session_status("sess-1")["reserved"] == 0
    assert g.stats()["reclaimed"] == 1
    assert g.stats()["units_returned"] == 80


def test_invalid_credit_requests_are_refused_without_side_effects():
    g = opened()
    bad = [
        dict(session_id="", subscriber="sub-1", peer="peer-a", requested=10),
        dict(session_id="sess-1", subscriber="sub-1", peer="peer-a", requested=0),
        dict(session_id="sess-1", subscriber="sub-1", peer="peer-a", requested=-3),
    ]
    for kwargs in bad:
        with pytest.raises(dg.DiameterError) as exc:
            g.send_ccr(now=NOW, **kwargs)
        assert exc.value.code == "REQUEST_INVALID"
    g.open_peer("peer-b", origin_host="gw-b.example", now=NOW)
    with pytest.raises(dg.DiameterError) as exc:
        g.send_ccr("sess-9", subscriber="sub-9", peer="peer-b", requested=10, now=NOW)
    assert exc.value.code == "PEER_NOT_OPEN"
    assert g.stats()["ccr_sent"] == 0
    assert g.stats()["units_reserved"] == 0


def test_peer_and_session_capacity_are_enforced():
    g = guard(max_peers=1)
    g.open_peer("peer-a", origin_host="gw-a.example", now=NOW)
    with pytest.raises(dg.DiameterError) as exc:
        g.open_peer("peer-b", origin_host="gw-b.example", now=NOW)
    assert exc.value.code == "PEER_CAPACITY_EXCEEDED"

    limited = opened(max_sessions=1)
    limited.send_ccr("sess-1", subscriber="sub-1", peer="peer-a", requested=10, now=NOW)
    with pytest.raises(dg.DiameterError) as exc:
        limited.send_ccr("sess-2", subscriber="sub-2", peer="peer-a", requested=10, now=NOW)
    assert exc.value.code == "SESSION_CAPACITY_EXCEEDED"
    limited.reclaim("sess-1", now=LATER)
    ticket = limited.send_ccr("sess-2", subscriber="sub-2", peer="peer-a", requested=10,
                              now=LATER2)
    assert ticket.state == "sent"
    assert limited.stats()["ccr_sent"] == 2


def test_concurrent_ccr_on_distinct_sessions_is_counted_exactly():
    g = opened()
    errors = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            g.send_ccr(f"sess-{index}", subscriber=f"sub-{index}", peer="peer-a",
                       requested=10, now=NOW)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert g.stats()["ccr_sent"] == 8
    assert g.stats()["units_reserved"] == 80
    for index in range(8):
        assert g.session_status(f"sess-{index}")["reserved"] == 10


def test_snapshot_is_detached_and_restore_roundtrips():
    g = opened()
    g.send_ccr("sess-1", subscriber="sub-1", peer="peer-a", requested=50,
               hop_by_hop="h-3", now=NOW)
    state = g.snapshot()
    assert set(state) == {"version", "peers", "sessions", "dedup", "counters"}
    pristine = g.snapshot()
    state["peers"].clear()
    state["sessions"].clear()
    state["counters"]["ccr_sent"] = 999
    assert g.stats()["ccr_sent"] == 1
    assert g.session_status("sess-1")["reserved"] == 50

    clone = guard()
    clone.restore(pristine)
    assert clone.peer_state("peer-a") == "Open"
    assert clone.session_status("sess-1")["reserved"] == 50
    assert clone.stats()["ccr_sent"] == 1
    for bad in (None, {}, {"version": 2, "peers": [], "sessions": [], "dedup": [],
                           "counters": {}}):
        with pytest.raises(dg.DiameterError) as exc:
            clone.restore(bad)
        assert exc.value.code == "SNAPSHOT_INVALID"
    assert clone.session_status("sess-1")["reserved"] == 50
