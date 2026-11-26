import hashlib
import threading

import pytest

import upload_scan_gate as sg

PAYLOAD = b"invoice-2026-11.pdf"


def digest_of(payload):
    return hashlib.sha256(payload).hexdigest()


def gate(**kwargs):
    return sg.UploadScanGate(**kwargs)


def test_submit_hashes_payload_and_queues_one_job():
    app = gate()
    ticket = app.submit("up-1", PAYLOAD, now=1000)
    assert ticket["upload_id"] == "up-1"
    assert ticket["digest"] == digest_of(PAYLOAD)
    assert ticket["state"] == sg.STATE_QUEUED
    detail = app.verdict("up-1")
    assert detail["decision"] == sg.DECISION_PENDING
    assert detail["source"] == "queue"
    assert app.queue() == (digest_of(PAYLOAD),)
    assert app.stats() == {"submitted": 1, "queued": 1, "scanned": 0,
                           "cache_hits": 0, "timed_out": 0, "released": 0}


def test_submit_rejects_malformed_or_oversized_payloads():
    app = gate(max_bytes=8)
    bad_calls = [
        ("", b"abc"),
        ("up-1", "abc"),
        ("up-1", b""),
        ("up-1", b"0123456789"),
    ]
    for upload_id, data in bad_calls:
        with pytest.raises(sg.ScanGateError) as exc:
            app.submit(upload_id, data, now=1000)
        assert exc.value.code == "SCAN_INVALID_REQUEST"
    assert app.queue() == ()
    assert app.stats()["submitted"] == 0


def test_duplicate_digest_shares_a_single_queue_entry():
    app = gate()
    first = app.submit("up-1", PAYLOAD, now=1000)
    second = app.submit("up-2", PAYLOAD, now=1001)
    assert first["digest"] == second["digest"] == digest_of(PAYLOAD)
    assert app.queue() == (digest_of(PAYLOAD),)
    assert app.verdict("up-1")["decision"] == sg.DECISION_PENDING
    assert app.verdict("up-2")["decision"] == sg.DECISION_PENDING
    assert app.stats()["submitted"] == 2
    assert app.stats()["queued"] == 1


def test_claim_pops_jobs_in_submission_order():
    app = gate()
    app.submit("up-1", b"one", now=1000)
    app.submit("up-2", b"two", now=1001)
    app.submit("up-3", b"three", now=1002)

    first = app.claim(now=1010)
    assert first["digest"] == digest_of(b"one")
    assert first["upload_ids"] == ["up-1"]
    assert first["started_at"] == 1010
    assert app.verdict("up-1")["state"] == sg.STATE_SCANNING

    assert app.claim(now=1011)["digest"] == digest_of(b"two")
    assert app.claim(now=1012)["digest"] == digest_of(b"three")
    assert app.claim(now=1013) is None
    assert app.queue() == ()


def test_complete_scan_allows_clean_payload_and_denies_malicious_one():
    app = gate()
    app.submit("up-1", b"clean", now=1000)
    app.claim(now=1000)
    done = app.complete_scan(digest_of(b"clean"), outcome="benign", now=1005)
    assert done["outcome"] == "benign"
    assert done["cached"] is True
    clean = app.verdict("up-1")
    assert clean["decision"] == sg.DECISION_ALLOW
    assert clean["source"] == "scan"
    assert clean["state"] == sg.STATE_DECIDED

    app.submit("up-2", b"payload-x", now=1010)
    app.claim(now=1010)
    app.complete_scan(digest_of(b"payload-x"), outcome="malicious", now=1015)
    bad = app.verdict("up-2")
    assert bad["decision"] == sg.DECISION_DENY
    assert bad["reason"] == "malicious_content"
    assert app.cache_lookup(digest_of(b"payload-x"), now=1020) is None

    again = app.submit("up-3", b"payload-x", now=1021)
    assert again["state"] == sg.STATE_QUEUED
    assert app.stats()["scanned"] == 2


def test_fresh_cache_hit_answers_without_queueing():
    app = gate(cache_ttl=300)
    app.submit("up-1", PAYLOAD, now=1000)
    app.claim(now=1000)
    app.complete_scan(digest_of(PAYLOAD), outcome="benign", now=1002)
    assert app.queue() == ()

    ticket = app.submit("up-2", PAYLOAD, now=1100)
    assert ticket["state"] == sg.STATE_DECIDED
    assert ticket["digest"] == digest_of(PAYLOAD)
    cache = app.verdict("up-2")
    assert cache["decision"] == sg.DECISION_ALLOW
    assert cache["source"] == "cache"
    assert app.queue() == ()
    assert app.stats()["cache_hits"] == 1


def test_complete_scan_enforces_digest_and_state_machine():
    app = gate()
    with pytest.raises(sg.ScanGateError) as exc:
        app.complete_scan("f" * 64, outcome="benign", now=1000)
    assert exc.value.code == "SCAN_UNKNOWN_DIGEST"

    app.submit("up-1", b"queued-only", now=1000)
    with pytest.raises(sg.ScanGateError) as exc:
        app.complete_scan(digest_of(b"queued-only"), outcome="benign", now=1001)
    assert exc.value.code == "SCAN_STATE_INVALID"

    app.claim(now=1002)
    with pytest.raises(sg.ScanGateError) as exc:
        app.complete_scan(digest_of(b"queued-only"), outcome="clean", now=1003)
    assert exc.value.code == "SCAN_INVALID_REQUEST"

    app.complete_scan(digest_of(b"queued-only"), outcome="benign", now=1004)
    with pytest.raises(sg.ScanGateError) as exc:
        app.complete_scan(digest_of(b"queued-only"), outcome="benign", now=1005)
    assert exc.value.code == "SCAN_STATE_INVALID"


def test_scan_timeout_quarantines_and_denies():
    app = gate(scan_timeout=60)
    app.submit("up-1", b"slow", now=1000)
    app.claim(now=1000)
    assert app.sweep(now=1059) == {"expired_cache": 0, "timed_out": 0}
    assert app.sweep(now=1060) == {"expired_cache": 0, "timed_out": 1}
    detail = app.verdict("up-1")
    assert detail["state"] == sg.STATE_QUARANTINED
    assert detail["decision"] == sg.DECISION_DENY
    assert detail["reason"] == "scan_timeout"
    assert app.stats()["timed_out"] == 1


def test_manual_quarantine_denies_and_leaves_queue():
    app = gate()
    app.submit("up-1", PAYLOAD, now=1000)
    out = app.quarantine(digest_of(PAYLOAD), reason="policy_hold", now=1001)
    assert out["state"] == sg.STATE_QUARANTINED
    assert out["reason"] == "policy_hold"
    detail = app.verdict("up-1")
    assert detail["decision"] == sg.DECISION_DENY
    assert detail["reason"] == "policy_hold"
    assert app.queue() == ()
    assert app.claim(now=1002) is None


def test_release_needs_an_actor_and_stays_single_use():
    app = gate(scan_timeout=10)
    app.submit("up-1", b"blocked", now=1000)
    app.claim(now=1000)
    app.sweep(now=1010)

    with pytest.raises(sg.ScanGateError) as exc:
        app.release(digest_of(b"blocked"), actor="  ", now=1020)
    assert exc.value.code == "SCAN_ACTOR_REQUIRED"

    out = app.release(digest_of(b"blocked"), actor="alice", now=1021)
    assert out["state"] == "released"
    assert out["actor"] == "alice"
    detail = app.verdict("up-1")
    assert detail["decision"] == sg.DECISION_ALLOW
    assert detail["reason"] == "manual_release"
    assert detail["source"] == "manual_release"
    assert app.stats()["released"] == 1

    with pytest.raises(sg.ScanGateError) as exc:
        app.release(digest_of(b"blocked"), actor="bob", now=1022)
    assert exc.value.code == "SCAN_ALREADY_RELEASED"

    with pytest.raises(sg.ScanGateError) as exc:
        app.release("e" * 64, actor="bob", now=1023)
    assert exc.value.code == "SCAN_UNKNOWN_DIGEST"

    app.submit("up-2", b"fresh", now=1030)
    with pytest.raises(sg.ScanGateError) as exc:
        app.release(digest_of(b"fresh"), actor="bob", now=1031)
    assert exc.value.code == "SCAN_STATE_INVALID"


def test_queue_capacity_is_freed_by_claiming():
    app = gate(max_queue=2)
    app.submit("up-1", b"one", now=1000)
    app.submit("up-2", b"two", now=1001)
    with pytest.raises(sg.ScanGateError) as exc:
        app.submit("up-3", b"three", now=1002)
    assert exc.value.code == "SCAN_QUEUE_FULL"
    assert app.stats()["submitted"] == 2

    app.claim(now=1003)
    ticket = app.submit("up-3", b"three", now=1004)
    assert ticket["state"] == sg.STATE_QUEUED
    assert app.queue() == (digest_of(b"two"), digest_of(b"three"))


def test_concurrent_submits_of_same_digest_share_one_scan():
    app = gate()
    errors = []
    ids = [f"up-{index}" for index in range(12)]
    barrier = threading.Barrier(len(ids))

    def worker(upload_id):
        try:
            barrier.wait(timeout=10)
            app.submit(upload_id, PAYLOAD, now=1000)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(upload_id,))
               for upload_id in ids]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert app.queue() == (digest_of(PAYLOAD),)
    job = app.claim(now=1005)
    assert sorted(job["upload_ids"]) == sorted(ids)
    app.complete_scan(digest_of(PAYLOAD), outcome="benign", now=1006)
    assert [app.verdict(upload_id)["decision"] for upload_id in ids] == \
        [sg.DECISION_ALLOW] * len(ids)


def test_snapshot_is_detached_and_restore_roundtrips():
    app = gate(scan_timeout=10)
    app.submit("up-1", b"clean", now=1000)
    app.claim(now=1000)
    app.complete_scan(digest_of(b"clean"), outcome="benign", now=1001)
    app.submit("up-2", b"slow", now=1002)
    app.claim(now=1003)
    app.sweep(now=1013)

    state = app.snapshot()
    assert set(state) == {"format", "tickets", "jobs", "queue", "cache",
                          "counters"}
    assert state["counters"] == {"submitted": 2, "queued": 2, "scanned": 1,
                                 "cache_hits": 0, "timed_out": 1,
                                 "released": 0}

    state["tickets"].clear()
    state["cache"].clear()
    assert app.verdict("up-1")["decision"] == sg.DECISION_ALLOW
    assert app.cache_lookup(digest_of(b"clean"), now=1005)["decision"] == \
        sg.DECISION_ALLOW

    clone = gate(scan_timeout=10)
    clone.restore(app.snapshot())
    assert clone.verdict("up-1")["source"] == "scan"
    assert clone.verdict("up-2")["state"] == sg.STATE_QUARANTINED
    assert clone.verdict("up-2")["reason"] == "scan_timeout"
    assert clone.cache_lookup(digest_of(b"clean"), now=1005)["decision"] == \
        sg.DECISION_ALLOW
    assert clone.stats()["timed_out"] == 1


def test_restore_rejects_malformed_state_without_touching_live_data():
    app = gate()
    app.submit("up-1", PAYLOAD, now=1000)
    good = app.snapshot()
    bad_states = [
        None,
        {},
        dict(good, format="other"),
        dict(good, jobs=[]),
        dict(good, tickets="nope"),
        dict(good, counters={"submitted": 1}),
    ]
    for bad in bad_states:
        with pytest.raises(sg.ScanGateError) as exc:
            app.restore(bad)
        assert exc.value.code == "SCAN_SNAPSHOT_INVALID"

    assert app.verdict("up-1")["state"] == sg.STATE_QUEUED
    assert app.queue() == (digest_of(PAYLOAD),)


def test_sweep_expires_only_due_cache_entries():
    app = gate(cache_ttl=100)
    app.submit("up-1", PAYLOAD, now=1000)
    app.claim(now=1000)
    app.complete_scan(digest_of(PAYLOAD), outcome="benign", now=1000)
    assert app.sweep(now=1099) == {"expired_cache": 0, "timed_out": 0}
    assert app.sweep(now=1100) == {"expired_cache": 1, "timed_out": 0}
    assert app.sweep(now=1200) == {"expired_cache": 0, "timed_out": 0}
