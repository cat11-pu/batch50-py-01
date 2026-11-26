import pytest

import netconf_commit_guard as ng


def guard(**kwargs):
    return ng.ConfirmedCommitGuard(**kwargs)


def test_commit_applies_candidate_and_starts_timer():
    g = guard()
    ticket = g.commit("s1", {"ntp": "a"}, timeout=30, now=0)
    assert ticket.commit_id == 1
    assert ticket.datastore == "running"
    assert ticket.session_id == "s1"
    assert ticket.version == 1
    assert ticket.expires_at == 30
    assert ticket.persist_id is None
    assert g.config_for() == {"ntp": "a"}
    assert g.version_for() == 1
    assert g.stats()["commits"] == 1


def test_confirm_cancels_rollback():
    g = guard()
    g.commit("s1", {"a": "1"}, timeout=30, now=0)
    assert g.confirm("s1", now=5) == 1
    assert g.pending_for() is None
    assert g.expire(now=100) == 0
    assert g.config_for() == {"a": "1"}
    assert g.stats()["confirms"] == 1


def test_second_commit_while_pending_is_rejected():
    g = guard()
    g.commit("s1", {"a": "1"}, now=0)
    with pytest.raises(ng.NetconfError) as excinfo:
        g.commit("s2", {"a": "2"}, now=1)
    assert excinfo.value.code == "NETCONF_COMMIT_IN_PROGRESS"
    assert g.version_for() == 1
    assert g.config_for() == {"a": "1"}


def test_datastores_are_independent():
    g = guard()
    g.commit("s1", {"a": "1"}, datastore="running", now=0)
    g.commit("s1", {"b": "2"}, datastore="candidate", now=1)
    assert g.version_for("running") == 1
    assert g.version_for("candidate") == 1
    assert g.config_for("running") == {"a": "1"}
    assert g.config_for("candidate") == {"b": "2"}
    assert g.pending_for("running") is not None
    assert g.pending_for("candidate") is not None


def test_confirm_from_other_session_is_refused():
    g = guard()
    ticket = g.commit("s1", {"a": "1"}, now=0)
    with pytest.raises(ng.NetconfError) as excinfo:
        g.confirm("s2", commit_id=ticket.commit_id, now=1)
    assert excinfo.value.code == "NETCONF_WRONG_SESSION"
    assert g.pending_for() is not None
    assert g.confirm("s1", commit_id=ticket.commit_id, now=2) == 1


def test_unknown_commit_id_is_refused():
    g = guard()
    with pytest.raises(ng.NetconfError) as excinfo:
        g.confirm("s1", now=0)
    assert excinfo.value.code == "NETCONF_UNKNOWN_COMMIT"
    ticket = g.commit("s1", {"a": "1"}, now=0)
    with pytest.raises(ng.NetconfError) as excinfo:
        g.confirm("s1", commit_id=ticket.commit_id + 1, now=1)
    assert excinfo.value.code == "NETCONF_UNKNOWN_COMMIT"
    assert g.pending_for() is not None


def test_expire_rolls_back_at_deadline():
    g = guard()
    g.commit("s1", {"a": "1"}, timeout=10, now=0)
    assert g.expire(now=9) == 0
    assert g.pending_for() is not None
    assert g.expire(now=10) == 1
    assert g.config_for() == {}
    assert g.version_for() == 2
    assert g.pending_for() is None
    assert g.stats()["rollbacks"] == 1
    assert g.stats()["expired"] == 1


def test_manual_rollback_before_deadline():
    g = guard()
    ticket = g.commit("s1", {"a": "1"}, now=0)
    assert g.rollback("s1", commit_id=ticket.commit_id, now=5) == 2
    assert g.config_for() == {}
    assert g.version_for() == 2
    assert g.pending_for() is None
    assert g.stats()["rollbacks"] == 1


def test_persist_id_allows_cross_session_confirm():
    g = guard()
    g.commit("s1", {"a": "1"}, timeout=60, now=0)
    persist_id = g.persist("s1")
    assert isinstance(persist_id, str) and persist_id
    assert g.pending_for().persist_id == persist_id
    assert g.confirm("s2", persist_id=persist_id, now=5) == 1
    assert g.pending_for() is None
    assert g.stats()["confirms"] == 1


def test_adopt_rebinds_owner():
    g = guard()
    g.commit("s1", {"a": "1"}, persist_id="pid-x", now=0)
    ticket = g.adopt("s2", "pid-x")
    assert ticket.session_id == "s2"
    assert ticket.persist_id == "pid-x"
    with pytest.raises(ng.NetconfError) as excinfo:
        g.adopt("s2", "missing")
    assert excinfo.value.code == "NETCONF_UNKNOWN_PERSIST"
    assert g.confirm("s2", persist_id="pid-x", now=2) == 1


def test_lock_owner_is_enforced():
    g = guard()
    g.lock_datastore("s1")
    g.lock_datastore("s1")
    with pytest.raises(ng.NetconfError) as excinfo:
        g.lock_datastore("s2")
    assert excinfo.value.code == "NETCONF_LOCK_HELD"
    with pytest.raises(ng.NetconfError) as excinfo:
        g.unlock_datastore("s2")
    assert excinfo.value.code == "NETCONF_NOT_OWNER"
    with pytest.raises(ng.NetconfError) as excinfo:
        g.commit("s2", {"a": "1"}, now=0)
    assert excinfo.value.code == "NETCONF_LOCK_HELD"
    g.unlock_datastore("s1")
    g.commit("s2", {"a": "1"}, now=1)
    assert g.version_for() == 1
    assert g.stats()["lock_denied"] == 2


def test_invalid_candidate_or_timeout_changes_nothing():
    g = guard()
    with pytest.raises(ng.NetconfError) as excinfo:
        g.commit("s1", ["a"], now=0)
    assert excinfo.value.code == "NETCONF_INVALID_CANDIDATE"
    with pytest.raises(ng.NetconfError) as excinfo:
        g.commit("s1", {"a": object()}, now=0)
    assert excinfo.value.code == "NETCONF_INVALID_CANDIDATE"
    with pytest.raises(ng.NetconfError) as excinfo:
        g.commit("s1", {"a": "1"}, timeout=0, now=0)
    assert excinfo.value.code == "NETCONF_INVALID_REQUEST"
    assert g.config_for() == {}
    assert g.version_for() == 0


def test_config_and_ticket_reads_are_copies():
    g = guard()
    g.commit("s1", {"a": "1"}, now=0)
    config = g.config_for()
    config["a"] = "tampered"
    assert g.config_for() == {"a": "1"}
    ticket = g.pending_for()
    assert ticket.expires_at == 60
    assert ticket.persist_id is None


def test_snapshot_restore_keeps_remaining_timer():
    g = guard()
    g.commit("s1", {"a": "1"}, timeout=60, now=0)
    snap = g.snapshot()
    assert {"version", "stores", "pendings", "stats"} <= set(snap)
    assert snap["stats"]["commits"] == 1
    snap["stats"]["commits"] = 99
    assert g.stats()["commits"] == 1
    restored = guard()
    restored.restore(snap)
    assert restored.config_for() == {"a": "1"}
    assert restored.version_for() == 1
    assert restored.expire(now=59) == 0
    assert restored.expire(now=60) == 1
    assert restored.config_for() == {}
    assert restored.version_for() == 2


def test_invalid_snapshot_is_rejected_without_side_effects():
    g = guard()
    g.commit("s1", {"a": "1"}, now=0)
    with pytest.raises(ng.NetconfError) as excinfo:
        g.restore({"version": 1})
    assert excinfo.value.code == "NETCONF_SNAPSHOT_INVALID"
    assert g.pending_for() is not None
    assert g.config_for() == {"a": "1"}
