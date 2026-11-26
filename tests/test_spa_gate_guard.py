import hashlib
import hmac
import threading

import pytest

import spa_gate_guard as sg

NOW = 1000
LATER = 1010
KEY1 = b"gateway-shared-key-one"
KEY2 = b"gateway-shared-key-two"


def digest(key, client, port, timestamp, nonce):
    payload = f"{client}|{port}|{timestamp}|{nonce}".encode("utf-8")
    return hmac.new(key, payload, hashlib.sha256).hexdigest()


def packet(client, port, timestamp, nonce, *, key=KEY1, generation=1,
           source="10.1.2.3"):
    return {"client": client, "port": port, "timestamp": timestamp,
            "nonce": nonce, "generation": generation, "source": source,
            "mac": digest(key, client, port, timestamp, nonce)}


def guard(**kwargs):
    return sg.SpaGateGuard(**kwargs)


def enrolled(**kwargs):
    g = guard(**kwargs)
    g.enroll("c1", ports=[5060, 5061], generation=1, key=KEY1, now=NOW)
    return g


def test_enroll_records_sorted_ports_and_rejects_duplicate():
    g = guard()
    record = g.enroll("c1", ports=[5061, 5060, 5060], generation=1, key=KEY1, now=NOW)
    assert record.client == "c1"
    assert record.generation == 1
    assert record.ports == (5060, 5061)
    assert record.enrolled_at == NOW
    with pytest.raises(sg.SpaError) as exc:
        g.enroll("c1", ports=[5060], generation=1, key=KEY1, now=LATER)
    assert exc.value.code == "SPA_CLIENT_EXISTS"
    assert g.stats()["enrollments"] == 1


def test_enroll_validates_ports_and_enforces_client_capacity():
    g = guard(max_clients=1)
    for bad in ([], [0], [70000], ["5060"], [5060, 5060.5]):
        with pytest.raises(sg.SpaError) as exc:
            g.enroll("c1", ports=bad, generation=1, key=KEY1, now=NOW)
        assert exc.value.code == "SPA_INVALID_REQUEST"
    with pytest.raises(sg.SpaError) as exc:
        g.enroll("", ports=[5060], generation=1, key=KEY1, now=NOW)
    assert exc.value.code == "SPA_INVALID_REQUEST"
    g.enroll("c1", ports=[5060], generation=1, key=KEY1, now=NOW)
    with pytest.raises(sg.SpaError) as exc:
        g.enroll("c2", ports=[5060], generation=1, key=KEY1, now=NOW)
    assert exc.value.code == "SPA_CAPACITY_EXCEEDED"


def test_verify_accepts_signed_packet_and_reports_identifiers():
    g = enrolled()
    verdict = g.verify(packet("c1", 5060, NOW, "n-1"), now=NOW)
    assert verdict.status == "accepted"
    assert verdict.client == "c1"
    assert verdict.port == 5060
    assert verdict.nonce == "n-1"
    assert verdict.generation == 1
    assert verdict.source == "10.1.2.3"
    assert g.stats()["accepted"] == 1
    assert g.stats()["verifications"] == 1


def test_verify_rejects_bad_mac_and_counts_failure():
    g = enrolled()
    forged = packet("c1", 5060, NOW, "n-2")
    forged["mac"] = digest(KEY2, "c1", 5060, NOW, "n-2")
    with pytest.raises(sg.SpaError) as exc:
        g.verify(forged, now=NOW)
    assert exc.value.code == "SPA_BAD_MAC"
    assert g.stats()["failures"] == 1
    assert g.stats()["accepted"] == 0
    assert g.verify(packet("c1", 5060, NOW, "n-3"), now=NOW).status == "accepted"


def test_verify_enforces_time_window_with_one_step_tolerance():
    g = enrolled()
    assert g.verify(packet("c1", 5060, NOW - 1, "n-4"), now=NOW).status == "accepted"
    assert g.verify(packet("c1", 5060, NOW + 1, "n-5"), now=NOW).status == "accepted"
    for timestamp in (NOW - 2, NOW + 2):
        with pytest.raises(sg.SpaError) as exc:
            g.verify(packet("c1", 5060, timestamp, f"n-{timestamp}"), now=NOW)
        assert exc.value.code == "SPA_TIME_WINDOW"


def test_verify_rejects_nonce_replay_within_window():
    g = enrolled()
    signed = packet("c1", 5060, NOW, "n-6")
    g.verify(signed, now=NOW)
    with pytest.raises(sg.SpaError) as exc:
        g.verify(signed, now=NOW + 1)
    assert exc.value.code == "SPA_REPLAY"
    assert g.stats()["replays"] == 1
    assert g.verify(packet("c1", 5060, NOW, "n-7"), now=NOW).status == "accepted"


def test_grant_issues_one_ticket_per_nonce():
    g = enrolled()
    ticket = g.grant(packet("c1", 5060, NOW, "n-8"), ttl=120, now=NOW)
    assert ticket.ticket_id == "tk-1"
    assert ticket.client == "c1"
    assert ticket.port == 5060
    assert ticket.source == "10.1.2.3"
    assert ticket.nonce == "n-8"
    assert ticket.generation == 1
    assert ticket.issued_at == NOW
    assert ticket.expires_at == NOW + 120
    assert ticket.state == "active"
    assert len(g.tickets("c1")) == 1
    with pytest.raises(sg.SpaError) as exc:
        g.grant(packet("c1", 5060, NOW, "n-8"), now=NOW)
    assert exc.value.code == "SPA_REPLAY"
    assert len(g.tickets("c1")) == 1
    assert g.stats()["tickets_issued"] == 1


def test_concurrent_grants_with_distinct_nonces_all_succeed():
    g = enrolled()
    errors = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            g.grant(packet("c1", 5061, NOW, f"n-conc-{index}"), now=NOW)
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(g.tickets("c1")) == 8
    assert g.stats()["tickets_issued"] == 8


def test_grant_refuses_unknown_client_and_unlisted_port():
    g = enrolled()
    with pytest.raises(sg.SpaError) as exc:
        g.grant(packet("ghost", 5060, NOW, "n-9"), now=NOW)
    assert exc.value.code == "SPA_UNKNOWN_CLIENT"
    with pytest.raises(sg.SpaError) as exc:
        g.grant(packet("c1", 8080, NOW, "n-10"), now=NOW)
    assert exc.value.code == "SPA_PORT_DENIED"
    assert g.stats()["tickets_issued"] == 0


def test_revoke_closes_ticket_and_clears_active_port():
    g = enrolled()
    ticket = g.grant(packet("c1", 5060, NOW, "n-11"), now=NOW)
    assert g.status("c1")["active_ports"] == (5060,)
    assert g.revoke(ticket.ticket_id, now=LATER) == 1
    status = g.status("c1")
    assert status["active_ports"] == ()
    assert status["tickets"] == 1
    assert g.tickets("c1")[0].state == "revoked"
    assert g.stats()["tickets_revoked"] == 1


def test_ticket_expires_on_ttl_and_is_reported_expired():
    g = enrolled()
    g.grant(packet("c1", 5061, NOW, "n-12"), ttl=10, now=NOW)
    assert g.status("c1", now=NOW)["active_ports"] == (5061,)
    later = NOW + 11
    assert g.status("c1", now=later)["active_ports"] == ()
    assert g.tickets("c1", now=later)[0].state == "expired"
    assert g.stats()["tickets_expired"] == 1


def test_key_rotation_keeps_old_generation_read_only():
    g = enrolled()
    record = g.rotate_key(2, key=KEY2, now=LATER)
    assert record.generation == 2
    assert record.state == "active"
    assert record.created_at == LATER
    assert g.verify(packet("c1", 5060, LATER, "n-13", key=KEY2, generation=2),
                    now=LATER).status == "accepted"
    assert g.verify(packet("c1", 5060, LATER, "n-14"), now=LATER).status == "accepted"
    with pytest.raises(sg.SpaError) as exc:
        g.grant(packet("c1", 5060, LATER, "n-15"), now=LATER)
    assert exc.value.code == "SPA_KEY_READONLY"
    fresh = g.grant(packet("c1", 5060, LATER, "n-16", key=KEY2, generation=2), now=LATER)
    assert fresh.generation == 2
    assert g.stats()["keys_rotated"] == 1


def test_unknown_generation_and_key_limit_are_reported():
    g = enrolled()
    with pytest.raises(sg.SpaError) as exc:
        g.verify(packet("c1", 5060, NOW, "n-17", key=KEY2, generation=9), now=NOW)
    assert exc.value.code == "SPA_UNKNOWN_GENERATION"
    limited = guard(max_keys=1)
    limited.enroll("c1", ports=[5060], generation=1, key=KEY1, now=NOW)
    with pytest.raises(sg.SpaError) as exc:
        limited.rotate_key(2, key=KEY2, now=LATER)
    assert exc.value.code == "SPA_KEY_LIMIT"


def test_repeated_failures_put_source_prefix_into_cooldown():
    g = guard(max_failures=3)
    g.enroll("c1", ports=[5060], generation=1, key=KEY1, now=NOW)
    g.enroll("c2", ports=[5060], generation=1, key=KEY1, now=NOW)
    for index in range(3):
        bad = packet("c1", 5060, NOW, f"n-bad-{index}")
        bad["mac"] = "00" * 32
        with pytest.raises(sg.SpaError) as exc:
            g.verify(bad, now=NOW)
        assert exc.value.code == "SPA_BAD_MAC"
    with pytest.raises(sg.SpaError) as exc:
        g.verify(packet("c1", 5060, NOW, "n-good-1"), now=NOW)
    assert exc.value.code == "SPA_COOLDOWN"
    assert g.stats()["cooldown_hits"] == 1
    other = packet("c2", 5060, NOW, "n-good-2", source="10.9.9.9")
    assert g.verify(other, now=NOW).status == "accepted"


def test_snapshot_is_detached_and_restore_roundtrips():
    g = enrolled()
    ticket = g.grant(packet("c1", 5060, NOW, "n-18"), now=NOW)
    state = g.snapshot()
    assert set(state) == {"version", "clients", "keys", "tickets", "nonces",
                          "failures", "counters"}
    pristine = g.snapshot()
    state["clients"].clear()
    state["tickets"].clear()
    state["nonces"].clear()
    state["counters"]["tickets_issued"] = 0
    assert g.status("c1")["tickets"] == 1
    assert g.stats()["tickets_issued"] == 1

    clone = guard()
    clone.restore(pristine)
    assert clone.status("c1")["active_ports"] == (5060,)
    assert clone.tickets("c1")[0].ticket_id == ticket.ticket_id
    with pytest.raises(sg.SpaError) as exc:
        clone.verify(packet("c1", 5060, NOW, "n-18"), now=NOW)
    assert exc.value.code == "SPA_REPLAY"
    for bad in (None, {}, {"version": 2, "clients": {}, "keys": {},
                           "tickets": {}, "nonces": {}, "failures": {},
                           "counters": {}}):
        with pytest.raises(sg.SpaError) as exc:
            clone.restore(bad)
        assert exc.value.code == "SPA_SNAPSHOT_INVALID"
    assert clone.status("c1")["tickets"] == 1
