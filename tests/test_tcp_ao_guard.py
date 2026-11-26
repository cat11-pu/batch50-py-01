import copy
import threading

import pytest

import tcp_ao_guard as ao

NOW = "2026-11-26T09:00:00+00:00"
LATER = "2026-11-26T09:05:00+00:00"
PEER = "198.51.100.7"


def guard(**kwargs):
    return ao.TcpAoGuard(**kwargs)


def bound_guard(**kwargs):
    item = guard(**kwargs)
    item.install_key("chain-a", "k-001", "secret-one", now=NOW)
    item.bind_connection("c-1", "chain-a", PEER, 40000, 179, now=NOW)
    return item


def test_install_key_assigns_generations_and_fingerprints():
    item = guard()
    first = item.install_key("chain-a", "k-001", "secret-one", now=NOW)
    assert first.chain_id == "chain-a"
    assert first.key_id == "k-001"
    assert first.generation == 1
    assert first.send is True
    assert first.recv is True
    assert first.created_at == NOW
    assert first.retired_at is None
    assert len(first.fingerprint) == 64
    assert all(character in "0123456789abcdef" for character in first.fingerprint)
    assert "secret-one" not in first.fingerprint
    second = item.install_key("chain-a", "k-002", "secret-two", now=NOW)
    assert second.generation == 2
    chain = item.key_chain("chain-a")
    assert [entry.key_id for entry in chain] == ["k-001", "k-002"]
    assert [entry.generation for entry in chain] == [1, 2]
    assert item.stats()["installed"] == 2


def test_install_duplicate_key_id_is_rejected():
    item = guard()
    item.install_key("chain-a", "k-001", "secret-one", now=NOW)
    with pytest.raises(ao.TcpAoError) as exc:
        item.install_key("chain-a", "k-001", "secret-other", now=NOW)
    assert exc.value.code == "TCPAO_KEY_CONFLICT"
    assert len(item.key_chain("chain-a")) == 1


def test_install_key_capacity_is_capped():
    item = guard(max_keys_per_chain=2)
    item.install_key("chain-a", "k-001", "secret-one", now=NOW)
    item.install_key("chain-a", "k-002", "secret-two", now=NOW)
    with pytest.raises(ao.TcpAoError) as exc:
        item.install_key("chain-a", "k-003", "secret-three", now=NOW)
    assert exc.value.code == "TCPAO_CAPACITY_EXCEEDED"
    assert len(item.key_chain("chain-a")) == 2


def test_bind_connection_records_endpoint_state():
    item = guard()
    item.install_key("chain-a", "k-001", "secret-one", now=NOW)
    binding = item.bind_connection("c-1", "chain-a", PEER, 40000, 179, now=NOW)
    assert binding.conn_id == "c-1"
    assert binding.chain_id == "chain-a"
    assert binding.peer == PEER
    assert (binding.src_port, binding.dst_port) == (40000, 179)
    assert binding.bound_at == NOW
    assert binding.rebinds == 0
    assert item.status()["connections"] == 1


def test_bind_conflicting_chain_or_unknown_chain_is_rejected():
    item = guard()
    item.install_key("chain-a", "k-001", "secret-one", now=NOW)
    item.install_key("chain-b", "k-101", "secret-two", now=NOW)
    item.bind_connection("c-1", "chain-a", PEER, 40000, 179, now=NOW)
    with pytest.raises(ao.TcpAoError) as exc:
        item.bind_connection("c-1", "chain-b", PEER, 40000, 179, now=NOW)
    assert exc.value.code == "TCPAO_BINDING_CONFLICT"
    with pytest.raises(ao.TcpAoError) as other:
        item.bind_connection("c-2", "chain-z", PEER, 40001, 179, now=NOW)
    assert other.value.code == "TCPAO_UNKNOWN_CHAIN"
    assert item.status()["connections"] == 1


def test_sign_and_verify_roundtrip_accepts_segment():
    item = bound_guard()
    segment = item.sign_segment("c-1", 1, b"hello-ao")
    assert segment.conn_id == "c-1"
    assert segment.seq == 1
    assert segment.key_id == "k-001"
    assert len(segment.mac) == 64
    result = item.verify_segment("c-1", 1, b"hello-ao", segment.mac)
    assert result.accepted is True
    assert result.reason == "ok"
    assert result.key_id == "k-001"
    assert result.window_floor == 1
    assert item.stats()["verified"] == 1


def test_tampered_payload_fails_mac_check():
    item = bound_guard()
    segment = item.sign_segment("c-1", 3, b"payload-ok")
    result = item.verify_segment("c-1", 3, b"payload-bad", segment.mac)
    assert result.accepted is False
    assert result.reason == "mac_mismatch"
    assert result.key_id is None
    assert item.stats()["mac_mismatches"] == 1


def test_duplicate_sequence_is_rejected():
    item = bound_guard()
    segment = item.sign_segment("c-1", 5, b"once")
    assert item.verify_segment("c-1", 5, b"once", segment.mac).accepted is True
    again = item.verify_segment("c-1", 5, b"once", segment.mac)
    assert again.accepted is False
    assert again.reason == "duplicate"
    assert item.stats()["duplicates"] == 1


def test_sequence_below_window_is_rejected():
    item = bound_guard(window_size=8)
    segment = item.sign_segment("c-1", 10, b"ten")
    assert item.verify_segment("c-1", 10, b"ten", segment.mac).accepted is True
    old = item.sign_segment("c-1", 2, b"two")
    stale = item.verify_segment("c-1", 2, b"two", old.mac)
    assert stale.accepted is False
    assert stale.reason == "out_of_window"
    assert item.stats()["out_of_window"] == 1
    inside = item.sign_segment("c-1", 9, b"nine")
    assert item.verify_segment("c-1", 9, b"nine", inside.mac).accepted is True


def test_rollover_switches_send_key_and_keeps_previous_receive_only():
    item = guard()
    item.install_key("chain-a", "k-001", "secret-one", now=NOW)
    item.install_key("chain-a", "k-002", "secret-two", now=NOW)
    item.bind_connection("c-1", "chain-a", PEER, 40000, 179, now=NOW)
    before = item.sign_segment("c-1", 1, b"first")
    assert before.key_id == "k-001"
    entry = item.rollover("chain-a", "k-002", now=LATER)
    assert entry.key_id == "k-002"
    assert entry.send is True
    assert entry.recv is True
    flags = {current.key_id: current for current in item.key_chain("chain-a")}
    assert flags["k-001"].send is False
    assert flags["k-001"].recv is True
    after = item.sign_segment("c-1", 2, b"second")
    assert after.key_id == "k-002"
    assert item.stats()["rollovers"] == 1


def test_rollover_unknown_key_is_rejected():
    item = guard()
    item.install_key("chain-a", "k-001", "secret-one", now=NOW)
    with pytest.raises(ao.TcpAoError) as exc:
        item.rollover("chain-a", "k-404", now=NOW)
    assert exc.value.code == "TCPAO_UNKNOWN_KEY"


def test_verify_on_unbound_connection_is_rejected():
    item = guard()
    item.install_key("chain-a", "k-001", "secret-one", now=NOW)
    with pytest.raises(ao.TcpAoError) as exc:
        item.verify_segment("c-404", 1, b"payload", "0" * 64)
    assert exc.value.code == "TCPAO_UNKNOWN_CONNECTION"


def test_concurrent_install_of_same_key_has_single_winner():
    item = guard()
    successes = []
    conflicts = []
    errors = []
    barrier = threading.Barrier(4)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            entry = item.install_key("chain-a", "k-dup", f"secret-{index}", now=NOW)
            successes.append(entry.key_id)
        except ao.TcpAoError as exc:
            conflicts.append(exc.code)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert successes == ["k-dup"]
    assert conflicts == ["TCPAO_KEY_CONFLICT"] * 3
    assert len(item.key_chain("chain-a")) == 1


def test_snapshot_roundtrip_keeps_chain_and_sequence_state():
    item = bound_guard()
    segment = item.sign_segment("c-1", 1, b"hello-ao")
    assert item.verify_segment("c-1", 1, b"hello-ao", segment.mac).accepted is True
    state = item.snapshot()
    assert set(state) == {"version", "chains", "connections", "sequences", "counters", "stats"}
    pristine = copy.deepcopy(state)
    state["chains"].clear()
    state["stats"]["installed"] = 99
    assert item.status()["keys"] == 1
    assert item.stats()["installed"] == 1

    clone = guard()
    clone.restore(pristine)
    replay = clone.verify_segment("c-1", 1, b"hello-ao", segment.mac)
    assert replay.accepted is False
    assert replay.reason == "duplicate"
    assert clone.sign_segment("c-1", 2, b"again").key_id == "k-001"


def test_restore_rejects_malformed_state_without_touching_live_state():
    item = bound_guard()
    bad_states = [
        None,
        {},
        {"version": 7, "chains": {}, "connections": {}, "sequences": {},
         "counters": {}, "stats": {}},
        {"version": 1, "chains": [], "connections": {}, "sequences": {},
         "counters": {}, "stats": {}},
        {"version": 1, "chains": {}, "connections": [], "sequences": {},
         "counters": {}, "stats": {}},
        {"version": 1, "chains": {}, "connections": {}, "sequences": [],
         "counters": {}, "stats": {}},
        {"version": 1, "chains": {}, "connections": {}, "sequences": {},
         "counters": {}, "stats": {"installed": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(ao.TcpAoError) as exc:
            item.restore(bad)
        assert exc.value.code == "TCPAO_SNAPSHOT_INVALID"
    assert item.status()["connections"] == 1
    assert item.sign_segment("c-1", 7, b"still-alive").key_id == "k-001"
