import copy
import threading

import pytest

import snmp_usm_guard as usm

ENGINE = "80004fb8056e69636f6c6173"
SECRET = "auth-secret-7c31"
NEW_SECRET = "auth-secret-9b02"
NOW = "2026-11-26T09:00:00+00:00"


class FakeClock:
    def __init__(self, start=1000.0):
        self.value = start

    def __call__(self):
        return self.value


def make_guard(**kwargs):
    clock = FakeClock()
    guard = usm.SnmpUsmGuard(clock=clock, **kwargs)
    guard.register_engine(ENGINE, boots=0, now=NOW)
    return guard, clock


def seeded_guard(**kwargs):
    guard, clock = make_guard(**kwargs)
    guard.register_user(ENGINE, "monitor", SECRET)
    digest = guard.localize_key(ENGINE, "monitor").digest
    return guard, clock, digest


def test_discovery_report_does_not_consume_rate_quota():
    guard, clock = make_guard(per_user_limit=2)
    guard.register_user(ENGINE, "monitor", SECRET)
    for _ in range(6):
        report = guard.discover()
        assert report["kind"] == "discovery_report"
        assert report["engine_id"] == ENGINE
        assert report["boots"] == 0
        assert report["engine_time"] == int(round(clock.value - 1000.0))
    digest = guard.localize_key(ENGINE, "monitor").digest
    decision = guard.verify_request("m-1", ENGINE, "monitor", 0, 0, digest)
    assert decision.accepted is True
    assert decision.reason == "ok"


def test_unknown_engine_and_unknown_user_are_reported():
    guard, _clock = make_guard()
    with pytest.raises(usm.UsmError) as exc:
        guard.discover("80004fb8056e69636f6c6179")
    assert exc.value.code == "USM_UNKNOWN_ENGINE"
    with pytest.raises(usm.UsmError) as other:
        guard.localize_key(ENGINE, "ghost")
    assert other.value.code == "USM_UNKNOWN_USER"


def test_localized_digest_is_stable_hex_without_secret():
    guard, _clock = make_guard()
    guard.register_user(ENGINE, "monitor", SECRET)
    key = guard.localize_key(ENGINE, "monitor")
    assert key.engine_id == ENGINE
    assert key.user == "monitor"
    assert key.generation == 1
    assert len(key.digest) == 64
    assert all(character in "0123456789abcdef" for character in key.digest)
    assert SECRET not in key.digest
    again = guard.localize_key(ENGINE, "monitor", SECRET)
    assert again.digest == key.digest
    assert again.generation == 1


def test_fresh_request_is_accepted_with_generation():
    guard, _clock, digest = seeded_guard()
    decision = guard.verify_request("m-1", ENGINE, "monitor", 0, 0, digest)
    assert decision.accepted is True
    assert decision.reason == "ok"
    assert decision.generation == 1
    assert decision.boots == 0
    assert (decision.msg_id, decision.engine_id, decision.user) == ("m-1", ENGINE, "monitor")
    assert guard.stats()["accepted"] == 1


def test_request_outside_time_window_is_rejected():
    guard, clock, digest = seeded_guard(time_window=150)
    late = guard.verify_request("m-late", ENGINE, "monitor", 0, 151, digest)
    assert late.accepted is False
    assert late.reason == "notInTimeWindow"
    stale_boots = guard.verify_request("m-boots", ENGINE, "monitor", 3, 0, digest)
    assert stale_boots.accepted is False
    assert stale_boots.reason == "notInTimeWindow"
    clock.value += 400.0
    current = int(clock.value - 1000.0)
    assert guard.verify_request("m-ok", ENGINE, "monitor", 0, current, digest).accepted is True
    assert guard.stats()["not_in_time_window"] == 2


def test_duplicate_message_is_replay():
    guard, _clock, digest = seeded_guard()
    first = guard.verify_request("m-dup", ENGINE, "monitor", 0, 0, digest)
    second = guard.verify_request("m-dup", ENGINE, "monitor", 0, 0, digest)
    assert first.accepted is True
    assert second.accepted is False
    assert second.reason == "replay"
    assert guard.stats()["replays"] == 1


def test_authentication_failure_and_unknown_user_share_report():
    guard, _clock = make_guard()
    guard.register_user(ENGINE, "monitor", SECRET)
    bad_digest = "0" * 64
    with pytest.raises(usm.UsmError) as first:
        guard.verify_request("m-a", ENGINE, "monitor", 0, 0, bad_digest)
    with pytest.raises(usm.UsmError) as second:
        guard.verify_request("m-b", ENGINE, "intruder", 0, 0, bad_digest)
    assert first.value.code == "USM_AUTH_FAILURE_REPORT"
    assert second.value.code == "USM_AUTH_FAILURE_REPORT"
    assert isinstance(first.value.detail, usm.UsmReport)
    assert isinstance(second.value.detail, usm.UsmReport)
    assert type(first.value.detail) is type(second.value.detail)
    assert first.value.detail.reason == second.value.detail.reason
    assert set(vars(first.value.detail)) == set(vars(second.value.detail))
    assert guard.status()["users"] == 1


def test_rotation_bumps_generation_and_conflicts_in_same_instant():
    guard, clock, _digest = seeded_guard()
    rotated = guard.rotate_key(ENGINE, "monitor", NEW_SECRET)
    assert rotated.generation == 2
    assert rotated.send is True
    assert rotated.recv is True
    with pytest.raises(usm.UsmError) as exc:
        guard.rotate_key(ENGINE, "monitor", "another-secret")
    assert exc.value.code == "USM_KEY_ROTATION_CONFLICT"
    clock.value += 5.0
    third = guard.rotate_key(ENGINE, "monitor", "third-secret")
    assert third.generation == 3
    assert guard.stats()["rotated"] == 2


def test_previous_generation_verifies_inside_grace_then_expires():
    guard, clock, old_digest = seeded_guard(grace_seconds=30.0)
    guard.rotate_key(ENGINE, "monitor", NEW_SECRET)
    during = guard.verify_request("m-g1", ENGINE, "monitor", 0, 0, old_digest)
    assert during.accepted is True
    assert during.generation == 1
    clock.value += 31.0
    assert guard.expire_keys() == 1
    with pytest.raises(usm.UsmError) as exc:
        guard.verify_request("m-g2", ENGINE, "monitor", 0, 31, old_digest)
    assert exc.value.code == "USM_AUTH_FAILURE_REPORT"
    assert guard.stats()["expired_keys"] == 1


def test_per_user_rate_limit_rejects_excess():
    guard, _clock, digest = seeded_guard(per_user_limit=3, rate_period=60.0)
    for index in range(3):
        assert guard.verify_request(f"m-{index}", ENGINE, "monitor", 0, 0, digest).accepted is True
    with pytest.raises(usm.UsmError) as exc:
        guard.verify_request("m-over", ENGINE, "monitor", 0, 0, digest)
    assert exc.value.code == "USM_RATE_LIMITED"
    assert guard.stats()["rate_limited"] == 1


def test_window_entries_are_capped_and_oldest_evicted():
    guard, _clock, digest = seeded_guard(max_window_entries=2)
    for index in range(5):
        assert guard.verify_request(f"m-{index}", ENGINE, "monitor", 0, 0, digest).accepted is True
    assert guard.status()["window_entries"] == 2
    assert guard.purge_window() == 2
    assert guard.status()["window_entries"] == 0


def test_restart_bumps_boots_and_resets_engine_time():
    guard, clock, _digest = seeded_guard()
    clock.value += 40.0
    assert guard.status()["engine_time"] == 40
    context = guard.restart()
    assert context.engine_id == ENGINE
    assert context.boots == 1
    assert guard.status()["boots"] == 1
    assert guard.status()["engine_time"] == 0


def test_concurrent_verification_accepts_shared_message_once():
    guard, _clock, digest = seeded_guard()
    accepted = []
    errors = []
    barrier = threading.Barrier(4)

    def worker():
        try:
            barrier.wait(timeout=5)
            decision = guard.verify_request("m-shared", ENGINE, "monitor", 0, 0, digest)
            accepted.append(decision.accepted)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(accepted) == 4
    assert accepted.count(True) == 1
    assert accepted.count(False) == 3


def test_snapshot_roundtrip_keeps_boots_and_replay_window():
    guard, _clock, digest = seeded_guard()
    assert guard.verify_request("m-keep", ENGINE, "monitor", 0, 0, digest).accepted is True
    state = guard.snapshot()
    assert set(state) == {"version", "engines", "keys", "window", "counters", "stats"}
    pristine = copy.deepcopy(state)
    state["engines"].clear()
    state["stats"]["accepted"] = 999
    assert guard.stats()["accepted"] == 1
    assert guard.status()["boots"] == 0

    clone, _other_clock = make_guard()
    clone.restore(pristine)
    assert clone.status()["boots"] == 0
    replay = clone.verify_request("m-keep", ENGINE, "monitor", 0, 0, digest)
    assert replay.accepted is False
    assert replay.reason == "replay"


def test_restore_rejects_malformed_snapshot_without_touching_state():
    guard, _clock = make_guard()
    guard.register_user(ENGINE, "monitor", SECRET)
    bad_states = [
        None,
        {},
        {"version": 2, "engines": {}, "keys": {}, "window": {}, "counters": {}, "stats": {}},
        {"version": 1, "engines": [], "keys": {}, "window": {}, "counters": {}, "stats": {}},
        {"version": 1, "engines": {}, "keys": [], "window": {}, "counters": {}, "stats": {}},
        {"version": 1, "engines": {}, "keys": {}, "window": {}, "counters": {}, "stats": {"accepted": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(usm.UsmError) as exc:
            guard.restore(bad)
        assert exc.value.code == "USM_SNAPSHOT_INVALID"
    assert guard.status()["boots"] == 0
    assert guard.localize_key(ENGINE, "monitor").generation == 1
