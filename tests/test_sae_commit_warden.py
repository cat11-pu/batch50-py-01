import pytest

import sae_commit_warden as sw


def warden(**kwargs):
    return sw.SaeCommitWarden(**kwargs)


def commit(w, mac="aa:01", scalar=10, **kwargs):
    return w.on_commit(mac, scalar, **kwargs)


def test_first_commit_creates_pending_handshake():
    w = warden()
    out = commit(w)
    assert out.status == "accepted"
    assert out.mac == "aa:01"
    assert out.handshake_id == 1
    assert out.token_consumed is False
    assert w.handshake_state("aa:01") == "pending"
    assert w.stats()["commits"] == 1


def test_duplicate_commit_is_idempotent():
    w = warden()
    first = commit(w)
    again = commit(w)
    assert again.status == "duplicate"
    assert again.handshake_id == first.handshake_id
    assert again.token_consumed is False
    assert w.stats()["duplicates"] == 1
    assert w.stats()["commits"] == 1


def test_threshold_requires_token_after_quota():
    w = warden(commit_threshold=2)
    for scalar in (10, 12):
        out = commit(w, scalar=scalar)
        assert out.status == "accepted"
        w.on_confirm("aa:01", scalar + 1)
    out = commit(w, scalar=14)
    assert out.status == "token_required"
    assert out.handshake_id == 0
    assert w.stats()["commits"] == 2


def test_token_is_single_use():
    w = warden()
    token = w.issue_token("aa:01", now=0)
    assert isinstance(token, str) and token
    out = commit(w, token=token, now=1)
    assert out.status == "accepted"
    assert out.token_consumed is True
    assert w.stats()["tokens_issued"] == 1
    assert w.stats()["tokens_consumed"] == 1
    with pytest.raises(sw.SaeError) as excinfo:
        commit(w, token=token, now=2)
    assert excinfo.value.code == "SAE_TOKEN_INVALID"
    assert w.stats()["token_rejections"] == 1


def test_token_cannot_be_used_by_another_mac():
    w = warden()
    token = w.issue_token("aa:01", now=0)
    with pytest.raises(sw.SaeError) as excinfo:
        w.on_commit("aa:02", 10, token=token, now=1)
    assert excinfo.value.code == "SAE_TOKEN_INVALID"
    assert w.handshake_state("aa:02") == "unknown"
    out = w.on_commit("aa:01", 10, token=token, now=2)
    assert out.status == "accepted"
    assert out.token_consumed is True


def test_wrong_send_confirm_discards_handshake():
    w = warden()
    commit(w, scalar=41)
    with pytest.raises(sw.SaeError) as excinfo:
        w.on_confirm("aa:01", 41)
    assert excinfo.value.code == "SAE_STATE_CONFLICT"
    assert w.handshake_state("aa:01") == "unknown"
    assert w.stats()["confirm_failures"] == 1


def test_confirm_completes_pending_handshake():
    w = warden()
    out = commit(w, scalar=41)
    confirmed = w.on_confirm("aa:01", 42, now=5)
    assert confirmed.status == "confirmed"
    assert confirmed.mac == "aa:01"
    assert confirmed.handshake_id == out.handshake_id
    assert w.handshake_state("aa:01") == "confirmed"
    assert w.stats()["confirms"] == 1


def test_pmf_is_required_for_association():
    w = warden()
    with pytest.raises(sw.SaeError) as excinfo:
        w.authorize_assoc("aa:01", pmf_negotiated=False)
    assert excinfo.value.code == "SAE_PMF_REQUIRED"
    assert w.stats()["pmf_denied"] == 1
    w.on_commit("aa:02", 10)
    w.on_confirm("aa:02", 11)
    with pytest.raises(sw.SaeError) as excinfo:
        w.authorize_assoc("aa:02", pmf_negotiated=False)
    assert excinfo.value.code == "SAE_PMF_REQUIRED"


def test_association_requires_confirmed_handshake():
    w = warden()
    w.on_commit("aa:01", 10)
    with pytest.raises(sw.SaeError) as excinfo:
        w.authorize_assoc("aa:01", pmf_negotiated=True)
    assert excinfo.value.code == "SAE_STATE_CONFLICT"
    w.on_confirm("aa:01", 11)
    decision = w.authorize_assoc("aa:01", pmf_negotiated=True)
    assert decision.allowed is True
    assert decision.protected is True
    assert decision.reason == "PMF_PROTECTED"


def test_transition_mode_allows_declared_wpa2_only():
    w = warden(transition_mode=True)
    decision = w.authorize_assoc("aa:09", pmf_negotiated=False, wpa2_client=True)
    assert decision.allowed is True
    assert decision.protected is False
    assert decision.reason == "WPA2_TRANSITION"
    with pytest.raises(sw.SaeError) as excinfo:
        w.authorize_assoc("aa:10", pmf_negotiated=False, wpa2_client=False)
    assert excinfo.value.code == "SAE_PMF_REQUIRED"


def test_purge_expired_handshakes():
    w = warden(handshake_ttl=60)
    w.on_commit("aa:01", 10, now=100)
    assert w.purge_expired(now=160) == 0
    assert w.handshake_state("aa:01") == "pending"
    assert w.purge_expired(now=161) == 1
    assert w.handshake_state("aa:01") == "unknown"
    assert w.stats()["purged"] == 1


def test_pending_table_capacity():
    w = warden(max_pending=2)
    assert commit(w, mac="aa:01").status == "accepted"
    assert commit(w, mac="aa:02").status == "accepted"
    with pytest.raises(sw.SaeError) as excinfo:
        commit(w, mac="aa:03")
    assert excinfo.value.code == "SAE_CAPACITY_EXCEEDED"
    assert w.handshake_state("aa:03") == "unknown"
    assert w.stats()["commits"] == 2


def test_invalid_arguments_and_unknown_peer():
    w = warden()
    with pytest.raises(sw.SaeError) as excinfo:
        w.on_commit("", 10)
    assert excinfo.value.code == "SAE_INVALID_REQUEST"
    with pytest.raises(sw.SaeError) as excinfo:
        w.on_commit("aa:01", "10")
    assert excinfo.value.code == "SAE_INVALID_REQUEST"
    with pytest.raises(sw.SaeError) as excinfo:
        w.on_confirm("aa:99", 11)
    assert excinfo.value.code == "SAE_UNKNOWN_PEER"


def test_snapshot_restore_drops_unfinished_handshakes():
    w = warden()
    w.on_commit("aa:01", 10, now=0)
    w.on_confirm("aa:01", 11, now=1)
    w.on_commit("aa:02", 20, now=2)
    snap = w.snapshot()
    assert {"version", "peers", "tokens", "stats"} <= set(snap)
    assert snap["stats"]["commits"] == 2
    snap["stats"]["commits"] = 99
    assert w.stats()["commits"] == 2
    restored = warden()
    restored.restore(snap)
    assert restored.handshake_state("aa:01") == "confirmed"
    assert restored.handshake_state("aa:02") == "unknown"
    assert restored.stats()["confirms"] == 1


def test_invalid_snapshot_is_rejected_without_side_effects():
    w = warden()
    w.on_commit("aa:01", 10)
    with pytest.raises(sw.SaeError) as excinfo:
        w.restore({"version": 1})
    assert excinfo.value.code == "SAE_SNAPSHOT_INVALID"
    assert w.handshake_state("aa:01") == "pending"
