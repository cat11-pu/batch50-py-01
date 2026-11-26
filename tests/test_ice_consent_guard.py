import threading

import pytest

import ice_consent_guard as ic


def cand(foundation, *, priority, address="10.0.0.1", port=5000,
         transport="udp", component="host"):
    return {"foundation": foundation, "component": component,
            "transport": transport, "address": address, "port": port,
            "priority": priority}


def guard(**kwargs):
    return ic.IceConsentGuard(**kwargs)


def paired(**kwargs):
    g = guard(**kwargs)
    g.add_candidates([cand("f1", priority=100, address="10.0.0.1", port=5000)],
                     side="local", now=0)
    g.add_candidates([cand("g1", priority=100, address="10.0.1.1", port=6000)],
                     side="remote", now=0)
    return g


def test_add_candidates_builds_keys_and_reports_counts():
    g = guard()
    added = g.add_candidates(
        [cand("f1", priority=100, address="10.0.0.1", port=5000),
         cand("f2", priority=50, address="10.0.0.2", port=5001)],
        side="local", now=0)
    assert [row.key for row in added] == ["udp://10.0.0.1:5000", "udp://10.0.0.2:5001"]
    assert [row.foundation for row in added] == ["f1", "f2"]
    assert [row.side for row in added] == ["local", "local"]
    assert [row.priority for row in added] == [100, 50]
    assert g.status()["candidates"] == 2
    assert g.status()["pairs"] == 0
    assert g.stats()["candidates_added"] == 2
    assert g.stats()["pairs_created"] == 0


def test_same_foundation_keeps_highest_priority_candidate():
    g = guard()
    g.add_candidates([cand("f1", priority=100, address="10.0.0.1", port=5000)],
                     side="local", now=0)
    added = g.add_candidates([cand("f1", priority=150, address="10.0.0.9", port=5002)],
                             side="local", now=0)
    assert len(added) == 1
    assert added[0].priority == 150
    assert added[0].key == "udp://10.0.0.9:5002"
    assert g.status()["candidates"] == 1
    assert g.stats()["candidates_added"] == 1
    assert g.stats()["candidates_replaced"] == 1


def test_candidate_capacity_is_checked_before_adding():
    g = guard(max_candidates=2)
    with pytest.raises(ic.IceError) as exc:
        g.add_candidates([cand(f"f{index}", priority=100) for index in range(3)],
                         side="local", now=0)
    assert exc.value.code == "ICE_CANDIDATE_LIMIT"
    assert g.status()["candidates"] == 0
    assert g.stats()["candidates_added"] == 0


def test_pairs_follow_priority_order_and_start_waiting():
    g = guard()
    g.add_candidates([cand("f1", priority=100, address="10.0.0.1", port=5000),
                      cand("f2", priority=50, address="10.0.0.2", port=5000)],
                     side="local", now=0)
    g.add_candidates([cand("g1", priority=200, address="10.0.1.1", port=6000),
                      cand("g2", priority=10, address="10.0.1.2", port=6000)],
                     side="remote", now=0)
    rows = g.pairs()
    assert [row.pair_id for row in rows] == ["p-1", "p-2", "p-3", "p-4"]
    priorities = [row.priority for row in rows]
    assert priorities == sorted(priorities, reverse=True)
    assert {row.state for row in rows} == {"waiting"}
    assert all(row.nominated is False for row in rows)
    assert all(row.consent_until is None for row in rows)
    assert g.status()["pairs"] == 4
    assert g.stats()["pairs_created"] == 4


def test_pair_capacity_rejects_the_whole_candidate_batch():
    g = guard(max_pairs=2)
    g.add_candidates([cand("f1", priority=100, address="10.0.0.1", port=5000),
                      cand("f2", priority=90, address="10.0.0.2", port=5000)],
                     side="local", now=0)
    with pytest.raises(ic.IceError) as exc:
        g.add_candidates([cand("g1", priority=80, address="10.0.1.1", port=6000),
                          cand("g2", priority=70, address="10.0.1.2", port=6000)],
                         side="remote", now=0)
    assert exc.value.code == "ICE_PAIR_LIMIT"
    assert g.status()["pairs"] == 0
    assert g.status()["candidates"] == 2


def test_check_pair_needs_a_response_before_valid():
    g = paired()
    pending = g.check_pair("p-1", responded=False, now=0)
    assert pending.state == "in-progress"
    assert pending.consent_until is None
    valid = g.check_pair("p-1", responded=True, now=1)
    assert valid.state == "valid"
    assert valid.consent_until == 7
    assert valid.priority == 100100
    with pytest.raises(ic.IceError) as exc:
        g.check_pair("p-404", now=1)
    assert exc.value.code == "ICE_UNKNOWN_PAIR"
    assert g.stats()["checks"] == 2
    assert g.stats()["valid"] == 1


def test_failed_check_marks_pair_and_blocks_selection():
    g = paired()
    failed = g.check_pair("p-1", failed=True, now=0)
    assert failed.state == "failed"
    assert failed.consent_until is None
    assert g.stats()["failed"] == 1
    with pytest.raises(ic.IceError) as exc:
        g.select(now=0)
    assert exc.value.code == "NO_VALID_PAIR"


def test_concurrent_pair_checks_keep_exact_validity_count():
    g = guard()
    g.add_candidates([cand(f"f{index}", priority=10 + index,
                           address=f"10.0.0.{index + 1}", port=5000)
                      for index in range(8)], side="local", now=0)
    g.add_candidates([cand("g0", priority=20, address="10.0.1.1", port=6000)],
                     side="remote", now=0)
    assert g.status()["pairs"] == 8
    errors = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            g.check_pair(f"p-{index + 1}", responded=True, now=0)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert g.stats()["valid"] == 8
    assert g.status()["valid"] == 8


def test_role_conflict_is_settled_by_tie_breaker():
    g = guard()
    assert g.resolve_role("controlling", 10, "controlling", 5) == "controlling"
    assert g.resolve_role("controlling", 5, "controlling", 10) == "controlled"
    assert g.resolve_role("controlling", 7, "controlled", 0) == "controlling"
    assert g.resolve_role("controlled", 7, "controlling", 0) == "controlled"
    with pytest.raises(ic.IceError) as exc:
        g.resolve_role("both", 1, "controlling", 0)
    assert exc.value.code == "ICE_INVALID_ROLE"


def test_controlled_side_may_not_nominate():
    g = paired()
    g.check_pair("p-1", responded=True, now=0)
    assert g.resolve_role("controlling", 5, "controlling", 9) == "controlled"
    with pytest.raises(ic.IceError) as exc:
        g.nominate("p-1", now=0)
    assert exc.value.code == "NOMINATION_FORBIDDEN"
    assert g.stats()["nominations"] == 0


def test_nominate_requires_valid_pair_and_records_choice():
    g = paired()
    with pytest.raises(ic.IceError) as exc:
        g.nominate("p-1", now=0)
    assert exc.value.code == "ICE_PAIR_NOT_VALID"
    g.check_pair("p-1", responded=True, now=0)
    report = g.nominate("p-1", now=1)
    assert report.pair_id == "p-1"
    assert report.nominated is True
    assert report.state == "valid"
    assert report.role == "controlling"
    assert g.status()["nominated"] == "p-1"
    assert g.stats()["nominations"] == 1


def test_second_nomination_needs_explicit_replacement():
    g = guard()
    g.add_candidates([cand("f1", priority=100, address="10.0.0.1", port=5000)],
                     side="local", now=0)
    g.add_candidates([cand("g1", priority=100, address="10.0.1.1", port=6000),
                      cand("g2", priority=50, address="10.0.1.2", port=6000)],
                     side="remote", now=0)
    g.check_pair("p-1", responded=True, now=0)
    g.check_pair("p-2", responded=True, now=0)
    g.nominate("p-1", now=1)
    with pytest.raises(ic.IceError) as exc:
        g.nominate("p-2", now=1)
    assert exc.value.code == "NOMINATION_CONFLICT"
    replaced = g.nominate("p-2", replace=True, now=2)
    assert replaced.pair_id == "p-2"
    assert g.status()["nominated"] == "p-2"
    states = {row.pair_id: row.nominated for row in g.pairs()}
    assert states == {"p-1": False, "p-2": True}


def test_selected_path_survives_late_trickle_until_reselect():
    g = guard()
    g.add_candidates([cand("f1", priority=100, address="10.0.0.1", port=5000)],
                     side="local", now=0)
    g.add_candidates([cand("g1", priority=100, address="10.0.1.1", port=6000)],
                     side="remote", now=0)
    g.check_pair("p-1", responded=True, now=0)
    first = g.select(now=0)
    assert first.pair_id == "p-1"
    assert first.state == "valid"
    assert first.consent_until == 6

    g.add_candidates([cand("f2", priority=200, address="10.0.0.2", port=5000)],
                     side="local", now=1)
    g.add_candidates([cand("g2", priority=200, address="10.0.1.2", port=6000)],
                     side="remote", now=1)
    g.check_pair("p-4", responded=True, now=1)
    assert g.select(now=1).pair_id == "p-1"

    g.consent("p-1", ok=False, now=2)
    g.consent("p-1", ok=False, now=3)
    assert g.status()["selected"] is None
    assert g.select(now=3).pair_id == "p-4"
    assert g.stats()["reselects"] == 1


def test_consent_failures_invalidate_pair_and_clear_selection():
    g = paired()
    with pytest.raises(ic.IceError) as exc:
        g.consent("p-1", ok=True, now=0)
    assert exc.value.code == "ICE_PAIR_NOT_VALID"
    g.check_pair("p-1", responded=True, now=0)
    g.select(now=0)
    refreshed = g.consent("p-1", ok=True, now=1)
    assert refreshed.failures == 0
    assert refreshed.consent_until == 7
    assert refreshed.selected == "p-1"
    assert g.stats()["consents"] == 1
    dropped = g.consent("p-1", ok=False, now=2)
    assert dropped.failures == 1
    assert dropped.state == "valid"
    broken = g.consent("p-1", ok=False, now=3)
    assert broken.state == "invalid"
    assert broken.consent_until is None
    assert broken.selected is None
    with pytest.raises(ic.IceError) as exc:
        g.select(now=3)
    assert exc.value.code == "NO_VALID_PAIR"


def test_snapshot_is_detached_and_restore_roundtrips():
    g = paired()
    g.check_pair("p-1", responded=True, now=0)
    g.select(now=0)
    state = g.snapshot()
    assert set(state) == {"version", "candidates", "pairs", "role", "selection",
                          "counters"}
    pristine = g.snapshot()
    state["candidates"].clear()
    state["pairs"].clear()
    state["selection"] = None
    state["counters"]["valid"] = 0
    assert g.status()["selected"] == "p-1"
    assert g.stats()["valid"] == 1

    clone = guard()
    clone.restore(pristine)
    assert clone.status()["selected"] == "p-1"
    assert clone.status()["valid"] == 1
    assert len(clone.pairs()) == 1
    assert clone.stats()["valid"] == 1
    for bad in (None, {}, {"version": 2, "candidates": [], "pairs": [],
                           "role": "controlling", "selection": None,
                           "counters": {}}):
        with pytest.raises(ic.IceError) as exc:
            clone.restore(bad)
        assert exc.value.code == "ICE_SNAPSHOT_INVALID"
    assert clone.status()["selected"] == "p-1"
