import pytest

import dbus_policy_broker as dbp

NOW = "2026-11-26T09:00:00+00:00"
LATER = "2026-11-26T09:00:10+00:00"
TIMEOUT_AT = "2026-11-26T09:00:31+00:00"


def broker(**kwargs):
    return dbp.DbusPolicyBroker(**kwargs)


def connect(b, conn_id, *, uid=1000, pid=100, groups=(), now=NOW):
    return b.add_connection(conn_id, uid=uid, pid=pid, groups=groups, now=now)


def policy(subject, *, subject_kind="user", target="*", message_type="any",
           verdict="deny", source="site"):
    return dbp.PolicyRule(source=source, subject=subject,
                          subject_kind=subject_kind, target=target,
                          message_type=message_type, verdict=verdict)


def test_add_connection_assigns_unique_names():
    b = broker()
    first = connect(b, "c1", uid=1000, pid=101)
    second = connect(b, "c2", uid=1001, pid=102)
    assert first.unique_name == ":1.1"
    assert second.unique_name == ":1.2"
    assert first.uid == 1000
    assert first.pid == 101
    assert b.names() == []
    assert b.stats()["connections"] == 2


def test_duplicate_connection_rejected():
    b = broker()
    connect(b, "c1")
    with pytest.raises(dbp.DbusPolicyError) as exc:
        connect(b, "c1", uid=2000)
    assert exc.value.code == "DBUS_DUPLICATE_CONNECTION"
    assert b.stats()["connections"] == 1


def test_connection_capacity_rejected():
    b = broker(max_connections=1)
    connect(b, "c1")
    with pytest.raises(dbp.DbusPolicyError) as exc:
        connect(b, "c2")
    assert exc.value.code == "DBUS_CAPACITY_EXCEEDED"


def test_unknown_connection_rejected():
    b = broker()
    with pytest.raises(dbp.DbusPolicyError) as exc:
        b.evaluate_send("ghost", target=":1.1", now=NOW)
    assert exc.value.code == "DBUS_UNKNOWN_CONNECTION"
    with pytest.raises(dbp.DbusPolicyError) as second:
        b.request_name("ghost", "org.example.Service", now=NOW)
    assert second.value.code == "DBUS_UNKNOWN_CONNECTION"


def test_send_deny_rule_blocks():
    b = broker()
    connect(b, "c1")
    b.load_policy([policy("alice", target=":1.9", verdict="deny")], now=NOW)
    verdict = b.evaluate_send("c1", target=":1.9", now=NOW)
    assert verdict.allowed is False
    assert verdict.reason == "rule_deny"
    assert verdict.source == "site"


def test_send_allow_rule_allows():
    b = broker()
    connect(b, "c1")
    b.load_policy([policy("alice", target=":1.9", verdict="allow")], now=NOW)
    verdict = b.evaluate_send("c1", target=":1.9", now=NOW)
    assert verdict.allowed is True
    assert verdict.reason == "rule_allow"


def test_default_allow_for_method_call():
    b = broker()
    connect(b, "c1")
    verdict = b.evaluate_send("c1", target=":1.9", now=NOW)
    assert verdict.allowed is True
    assert verdict.reason == "default_allow"
    assert verdict.source is None


def test_eavesdrop_denied_by_default():
    b = broker()
    connect(b, "c1")
    verdict = b.evaluate_send("c1", target=":1.9", message_type="signal",
                              eavesdrop=True, now=NOW)
    assert verdict.allowed is False
    assert verdict.reason == "eavesdrop_denied"


def test_eavesdrop_allowed_with_explicit_rule():
    b = broker()
    connect(b, "c1")
    b.load_policy([policy("alice", target=":1.9", verdict="allow")], now=NOW)
    verdict = b.evaluate_send("c1", target=":1.9", message_type="signal",
                              eavesdrop=True, now=NOW)
    assert verdict.allowed is True
    assert verdict.reason == "rule_allow"


def test_receive_side_evaluated_separately():
    b = broker()
    connect(b, "c1", uid=1000, groups=("staff",))
    connect(b, "c2", uid=1001, groups=("guests",))
    b.load_policy([policy("eve", target="*", verdict="deny")], now=NOW)
    sent = b.evaluate_send("c1", target=":1.2", now=NOW)
    received = b.evaluate_receive("c2", sender=":1.1", now=NOW)
    assert sent.allowed is True
    assert received.allowed is False
    assert received.reason == "rule_deny"


def test_request_name_and_queue_when_taken():
    b = broker()
    connect(b, "c1")
    connect(b, "c2")
    assert b.request_name("c1", "org.example.Service", now=NOW) == "owner"
    assert b.request_name("c2", "org.example.Service", now=LATER) == "queued:1"
    records = b.names()
    assert len(records) == 1
    assert records[0].name == "org.example.Service"
    assert records[0].owner == "c1"
    assert records[0].queue == ("c2",)
    assert b.stats()["names"] == 1


def test_release_name_returns_count():
    b = broker()
    connect(b, "c1")
    b.request_name("c1", "org.example.Service", now=NOW)
    assert b.release_name("c1", "org.example.Service", now=LATER) == 1
    record = b.names()[0]
    assert record.owner is None
    assert record.queue == ()


def test_record_call_deduplicates_by_sequence():
    b = broker()
    connect(b, "c1")
    first = b.record_call("c1", seq=7, target=":1.2", method="Ping", now=NOW)
    second = b.record_call("c1", seq=7, target=":1.2", method="Ping", now=LATER)
    assert second == first
    assert b.stats()["deduplicated"] == 1
    assert b.stats()["pending"] == 1


def test_expire_calls_returns_timed_out():
    b = broker()
    connect(b, "c1")
    b.record_call("c1", seq=7, target=":1.2", method="Ping", now=NOW)
    expired = b.expire_calls(now=TIMEOUT_AT)
    assert len(expired) == 1
    assert expired[0]["seq"] == 7
    assert expired[0]["reason"] == "timeout"
    assert b.stats()["pending"] == 0
    assert b.stats()["expired"] == 1


def test_snapshot_roundtrip_and_invalid_state():
    b = broker()
    connect(b, "c1", uid=1000, groups=("staff",))
    b.load_policy([policy("alice", target="*", verdict="allow")], now=NOW)
    b.request_name("c1", "org.example.Service", now=NOW)
    b.record_call("c1", seq=3, target=":1.2", method="Ping", now=NOW)
    state = b.snapshot()
    clone = broker()
    clone.restore(state)
    assert clone.stats()["connections"] == 1
    assert clone.stats()["names"] == 1
    assert clone.stats()["pending"] == 1
    assert clone.stats()["rules_version"] == 1
    with pytest.raises(dbp.DbusPolicyError) as exc:
        clone.restore({"bogus": True})
    assert exc.value.code == "DBUS_SNAPSHOT_INVALID"
    assert clone.stats()["connections"] == 1
