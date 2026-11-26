import copy
import threading

import pytest

import oidc_silent_auth_broker as ob

NOW = "2026-11-26T09:00:00+00:00"
SOON = "2026-11-26T09:01:00+00:00"
DEADLINE = "2026-11-26T09:05:00+00:00"
AFTER_TTL = "2026-11-26T09:05:01+00:00"
CB = "https://rp.example/cb"
CB_ALT = "https://rp.example/alt"


def broker(**kwargs):
    return ob.SilentAuthBroker(**kwargs)


def ready(**kwargs):
    b = broker(**kwargs)
    b.register_client("rp-1", tenant="t1", redirect_uris=[CB], now=NOW)
    b.register_session("s-1", user="alice", tenant="t1", auth_time=NOW, now=NOW)
    return b


def start(b, **kwargs):
    kwargs.setdefault("redirect_uri", CB)
    kwargs.setdefault("session_id", "s-1")
    return b.begin("rp-1", now=NOW, **kwargs)


def test_register_client_normalizes_redirect_uris():
    b = broker()
    reg = b.register_client("rp-1", tenant="t1",
                            redirect_uris=[f"  {CB_ALT}  ", CB, CB], now=NOW)
    assert reg.client_id == "rp-1"
    assert reg.tenant == "t1"
    assert reg.redirect_uris == (CB_ALT, CB)
    assert reg.created_at == NOW
    assert b.client_record("rp-1") == reg
    with pytest.raises(ob.SilentAuthError) as exc:
        b.register_client("rp-1", tenant="t1", redirect_uris=[CB], now=SOON)
    assert exc.value.code == "SILENT_AUTH_INVALID_REQUEST"
    with pytest.raises(ob.SilentAuthError) as exc:
        b.client_record("rp-9")
    assert exc.value.code == "SILENT_AUTH_UNKNOWN_CLIENT"


def test_begin_opens_pending_request_with_deadline():
    b = ready()
    req = start(b)
    assert req.status == "pending"
    assert req.client_id == "rp-1"
    assert req.tenant == "t1"
    assert req.redirect_uri == CB
    assert req.login_hint is None
    assert req.max_age is None
    assert req.session_id == "s-1"
    assert req.created_at == NOW
    assert req.expires_at == DEADLINE
    assert len(req.state) >= 16
    assert b.state_status(req.state) == "pending"
    assert b.pending_for_session("s-1") == [req]
    assert b.stats()["begun"] == 1
    assert b.stats()["completed"] == 0


def test_begin_rejects_unregistered_redirect_and_client():
    b = ready()
    with pytest.raises(ob.SilentAuthError) as exc:
        b.begin("rp-1", redirect_uri="https://evil.example/cb", now=NOW)
    assert exc.value.code == "SILENT_AUTH_REDIRECT_MISMATCH"
    with pytest.raises(ob.SilentAuthError) as exc:
        b.begin("rp-9", redirect_uri=CB, now=NOW)
    assert exc.value.code == "SILENT_AUTH_UNKNOWN_CLIENT"
    assert b.stats()["begun"] == 0


def test_begin_rejects_malformed_parameters():
    b = ready()
    bad = [
        dict(redirect_uri=""),
        dict(redirect_uri="   "),
        dict(max_age=-1),
        dict(max_age=30.5),
        dict(login_hint="   "),
        dict(session_id=""),
    ]
    for kwargs in bad:
        kwargs.setdefault("redirect_uri", CB)
        with pytest.raises(ob.SilentAuthError) as exc:
            b.begin("rp-1", now=NOW, **kwargs)
        assert exc.value.code == "SILENT_AUTH_INVALID_REQUEST"
    assert b.stats()["begun"] == 0


def test_complete_reuses_active_session():
    b = ready()
    req = start(b)
    res = b.complete(req.state, now=SOON)
    assert res.state == req.state
    assert res.client_id == "rp-1"
    assert res.status == "success"
    assert res.subject == "alice"
    assert res.session_id == "s-1"
    assert res.reason == "session_reused"
    assert res.issued_at == SOON
    assert b.state_status(req.state) == "completed"
    assert b.pending_for_session("s-1") == []
    assert b.stats()["completed"] == 1
    assert b.stats()["login_required"] == 0


def test_complete_without_active_session_requires_login():
    b = ready()
    anonymous = start(b, session_id=None)
    res = b.complete(anonymous.state, now=SOON)
    assert res.status == "login_required"
    assert res.subject is None
    assert res.session_id is None
    assert res.reason == "no_session"
    assert b.state_status(anonymous.state) == "completed"
    assert b.stats()["login_required"] == 1

    assert b.end_session("s-1", now=SOON) is True
    assert b.end_session("s-1", now=SOON) is False
    stale = start(b)
    res2 = b.complete(stale.state, now=SOON)
    assert res2.status == "login_required"
    assert res2.reason == "no_session"
    assert b.stats()["login_required"] == 2


def test_complete_reports_tenant_mismatch_as_interaction():
    b = ready()
    b.register_session("s-2", user="bob", tenant="t2", auth_time=NOW, now=NOW)
    req = start(b, session_id="s-2")
    res = b.complete(req.state, now=SOON)
    assert res.status == "interaction_required"
    assert res.reason == "tenant_mismatch"
    assert res.subject is None
    assert res.session_id is None
    assert b.stats()["interaction_required"] == 1
    assert b.stats()["login_required"] == 0


def test_cancel_is_terminal_for_the_state():
    b = ready()
    req = start(b)
    assert b.cancel(req.state, now=SOON) is True
    assert b.state_status(req.state) == "cancelled"
    assert b.cancel(req.state, now=SOON) is False
    with pytest.raises(ob.SilentAuthError) as exc:
        b.complete(req.state, now=SOON)
    assert exc.value.code == "SILENT_AUTH_STATE_CANCELLED"
    assert b.stats()["cancelled"] == 1
    assert b.pending_for_session("s-1") == []


def test_expire_sweeps_and_blocks_late_completion():
    b = ready(pending_ttl=300)
    first = start(b)
    second = start(b)
    assert b.expire(now=NOW) == 0
    assert b.expire(now=AFTER_TTL) == 2
    assert b.state_status(first.state) == "expired"
    assert b.state_status(second.state) == "expired"
    assert b.expire(now=AFTER_TTL) == 0
    assert b.stats()["expired"] == 2

    c = ready()
    late = start(c)
    with pytest.raises(ob.SilentAuthError) as exc:
        c.complete(late.state, now=AFTER_TTL)
    assert exc.value.code == "SILENT_AUTH_STATE_EXPIRED"
    assert c.state_status(late.state) == "expired"
    assert c.stats()["expired"] == 1


def test_capacity_limits_are_enforced_and_released():
    b = broker(max_pending_per_client=1, max_pending_per_tenant=2)
    b.register_client("rp-1", tenant="t1", redirect_uris=[CB], now=NOW)
    b.register_client("rp-2", tenant="t1", redirect_uris=[CB], now=NOW)
    b.register_client("rp-3", tenant="t1", redirect_uris=[CB], now=NOW)
    b.register_session("s-1", user="alice", tenant="t1", auth_time=NOW, now=NOW)
    first = b.begin("rp-1", redirect_uri=CB, session_id="s-1", now=NOW)
    with pytest.raises(ob.SilentAuthError) as exc:
        b.begin("rp-1", redirect_uri=CB, now=NOW)
    assert exc.value.code == "SILENT_AUTH_CAPACITY_EXCEEDED"
    b.begin("rp-2", redirect_uri=CB, now=NOW)
    with pytest.raises(ob.SilentAuthError) as exc:
        b.begin("rp-3", redirect_uri=CB, now=NOW)
    assert exc.value.code == "SILENT_AUTH_CAPACITY_EXCEEDED"
    b.complete(first.state, now=SOON)
    b.begin("rp-3", redirect_uri=CB, now=SOON)
    assert b.stats()["begun"] == 3


def test_pending_for_session_is_scoped_and_ordered():
    b = ready()
    b.register_session("s-2", user="bob", tenant="t1", auth_time=NOW, now=NOW)
    left = b.begin("rp-1", redirect_uri=CB, session_id="s-1", now=NOW)
    other = b.begin("rp-1", redirect_uri=CB, session_id="s-2", now=NOW)
    right = b.begin("rp-1", redirect_uri=CB, session_id="s-1", now=NOW)
    anonymous = b.begin("rp-1", redirect_uri=CB, now=NOW)
    rows = b.pending_for_session("s-1")
    assert [row.state for row in rows] == sorted([left.state, right.state])
    assert [row.state for row in b.pending_for_session("s-2")] == [other.state]
    assert b.pending_for_session("s-3") == []
    assert anonymous.state not in [row.state for row in rows]


def test_concurrent_completion_writes_single_success():
    b = ready()
    req = start(b)
    outcomes = []
    failures = []
    barrier = threading.Barrier(12)

    def worker():
        try:
            barrier.wait(timeout=5)
            outcomes.append(b.complete(req.state, now=SOON))
        except Exception as exc:  # noqa: BLE001 - reported through failures
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(outcomes) + len(failures) == 12
    assert len(outcomes) == 1
    assert outcomes[0].status == "success"
    assert b.stats()["completed"] == 1


def test_snapshot_roundtrip_restores_pending_and_counters():
    b = ready()
    pending = start(b)
    done = start(b)
    b.complete(done.state, now=SOON)
    state = b.snapshot()
    assert set(state) == {"version", "clients", "sessions", "requests", "stats"}
    pristine = copy.deepcopy(state)
    state["stats"]["begun"] = 999
    state["requests"].clear()
    assert b.stats()["begun"] == 2
    assert b.state_status(pending.state) == "pending"

    clone = broker()
    clone.restore(pristine)
    assert clone.stats()["begun"] == 2
    assert clone.stats()["completed"] == 1
    assert clone.state_status(pending.state) == "pending"
    assert clone.state_status(done.state) == "completed"
    assert [row.state for row in clone.pending_for_session("s-1")] == [pending.state]
    resumed = clone.complete(pending.state, now=SOON)
    assert resumed.status == "success"
    assert resumed.subject == "alice"


def test_restore_rejects_malformed_snapshot():
    b = ready()
    req = start(b)
    bad_snapshots = [
        None,
        {},
        {"version": 2, "clients": [], "sessions": [], "requests": [], "stats": {}},
        {"version": 1, "clients": {}, "sessions": [], "requests": [], "stats": {}},
        {"version": 1, "clients": [], "sessions": [], "requests": "nope", "stats": {}},
        {"version": 1, "clients": [], "sessions": [], "requests": [], "stats": []},
    ]
    for snapshot in bad_snapshots:
        with pytest.raises(ob.SilentAuthError) as exc:
            b.restore(snapshot)
        assert exc.value.code == "SILENT_AUTH_SNAPSHOT_INVALID"
    assert b.state_status(req.state) == "pending"
    assert b.stats()["begun"] == 1
    with pytest.raises(ob.SilentAuthError) as exc:
        b.complete("no-such-state", now=SOON)
    assert exc.value.code == "SILENT_AUTH_UNKNOWN_STATE"


def test_stats_track_each_outcome():
    b = broker()
    b.register_client("rp-1", tenant="t1", redirect_uris=[CB], now=NOW)
    b.register_client("rp-2", tenant="t2", redirect_uris=[CB], now=NOW)
    b.register_session("s-1", user="alice", tenant="t1", auth_time=NOW, now=NOW)
    b.register_session("s-2", user="bob", tenant="t2", auth_time=NOW, now=NOW)
    success = b.begin("rp-1", redirect_uri=CB, session_id="s-1", now=NOW)
    anonymous = b.begin("rp-1", redirect_uri=CB, now=NOW)
    mismatch = b.begin("rp-1", redirect_uri=CB, session_id="s-2", now=NOW)
    cancelled = b.begin("rp-1", redirect_uri=CB, now=NOW)
    expired = b.begin("rp-1", redirect_uri=CB, now=NOW)
    b.complete(success.state, now=SOON)
    b.complete(anonymous.state, now=SOON)
    b.complete(mismatch.state, now=SOON)
    b.cancel(cancelled.state, now=SOON)
    b.expire(now=AFTER_TTL)
    stats = b.stats()
    assert stats["clients"] == 2
    assert stats["sessions"] == 2
    assert stats["begun"] == 5
    assert stats["completed"] == 3
    assert stats["login_required"] == 1
    assert stats["interaction_required"] == 1
    assert stats["cancelled"] == 1
    assert stats["expired"] == 1
    assert stats["replayed"] == 0
