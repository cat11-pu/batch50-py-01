import copy
import re
from datetime import datetime, timedelta

import pytest

import magic_link_issuer as ml

NOW = "2026-11-26T08:00:00+00:00"


def at(seconds):
    return (datetime.fromisoformat(NOW) + timedelta(seconds=seconds)).isoformat()


def issuer(**kwargs):
    return ml.MagicLinkIssuer(**kwargs)


def issue(iss, email="user@example.com", *, fingerprint="fp-a",
          purpose="login", ttl=None, now=NOW):
    return iss.issue(email, device_fingerprint=fingerprint, purpose=purpose,
                     ttl=ttl, now=now)


def test_issue_normalizes_email_and_returns_ticket():
    iss = issuer()
    ticket = issue(iss, "  User@Example.COM ")
    assert ticket.email == "user@example.com"
    assert re.fullmatch(r"ml_[0-9a-f]{16}", ticket.token_id)
    assert ticket.purpose == "login"
    assert ticket.device_fingerprint == "fp-a"
    assert ticket.issued_at == NOW
    assert ticket.expires_at == at(900)
    assert ticket.state == "pending"


def test_issue_rejects_malformed_email():
    iss = issuer()
    for email in ["", "   ", "user.example.com", "@example.com", "user@",
                  "a@b@c.com"]:
        with pytest.raises(ml.MagicLinkError) as exc:
            issue(iss, email)
        assert exc.value.code == "MAGIC_LINK_INVALID_EMAIL"


def test_issue_rejects_bad_ttl_and_uses_default():
    iss = issuer(default_ttl=120)
    assert issue(iss).expires_at == at(120)
    for ttl in [0, -1, 86401, 1.5, "60"]:
        with pytest.raises(ml.MagicLinkError) as exc:
            issue(iss, ttl=ttl)
        assert exc.value.code == "MAGIC_LINK_BAD_TTL"


def test_redeem_from_issuing_device_consumes_token():
    iss = issuer()
    ticket = issue(iss)
    result = iss.redeem(ticket.token_id, device_fingerprint="fp-a", now=NOW)
    assert result.status == "redeemed"
    assert result.token_id == ticket.token_id
    assert result.email == "user@example.com"
    assert result.purpose == "login"
    assert result.requires_confirmation is False
    assert result.redeemed_at == NOW
    assert iss.status(ticket.token_id)["state"] == "consumed"
    assert iss.active_links("user@example.com", now=NOW) == []


def test_second_redeem_reports_consumed_and_unknown_token_raises():
    iss = issuer()
    ticket = issue(iss)
    iss.redeem(ticket.token_id, device_fingerprint="fp-a", now=NOW)
    again = iss.redeem(ticket.token_id, device_fingerprint="fp-a", now=at(30))
    assert again.status == "consumed"
    assert again.redeemed_at == NOW
    with pytest.raises(ml.MagicLinkError) as exc:
        iss.redeem("ml_0000000000000000", device_fingerprint="fp-a", now=NOW)
    assert exc.value.code == "MAGIC_LINK_UNKNOWN"


def test_expired_link_is_refused_and_purged_once():
    iss = issuer(default_ttl=60)
    ticket = issue(iss)
    with pytest.raises(ml.MagicLinkError) as exc:
        iss.redeem(ticket.token_id, device_fingerprint="fp-a", now=at(61))
    assert exc.value.code == "MAGIC_LINK_EXPIRED"
    assert iss.purge_expired(now=at(61)) == 1
    assert iss.purge_expired(now=at(61)) == 0
    assert iss.status(ticket.token_id)["state"] == "expired"
    with pytest.raises(ml.MagicLinkError) as exc:
        iss.redeem(ticket.token_id, device_fingerprint="fp-a", now=at(62))
    assert exc.value.code == "MAGIC_LINK_EXPIRED"


def test_other_device_needs_confirmation_and_does_not_consume():
    iss = issuer()
    ticket = issue(iss)
    result = iss.redeem(ticket.token_id, device_fingerprint="fp-b", now=at(5))
    assert result.status == "confirmation_required"
    assert result.requires_confirmation is True
    assert result.redeemed_at is None
    record = iss.status(ticket.token_id)
    assert record["state"] == "pending"
    assert record["pending_device"] == "fp-b"
    original = iss.redeem(ticket.token_id, device_fingerprint="fp-a", now=at(6))
    assert original.status == "redeemed"
    assert original.redeemed_at == at(6)
    assert iss.status(ticket.token_id)["pending_device"] is None


def test_confirm_requires_matching_pending_device():
    iss = issuer()
    ticket = issue(iss)
    iss.redeem(ticket.token_id, device_fingerprint="fp-b", now=at(5))
    with pytest.raises(ml.MagicLinkError) as exc:
        iss.confirm(ticket.token_id, device_fingerprint="fp-c", now=at(10))
    assert exc.value.code == "MAGIC_LINK_DEVICE_MISMATCH"
    result = iss.confirm(ticket.token_id, device_fingerprint="fp-b", now=at(10))
    assert result.status == "redeemed"
    assert result.redeemed_at == at(10)
    assert iss.status(ticket.token_id)["state"] == "consumed"
    with pytest.raises(ml.MagicLinkError) as exc:
        iss.confirm(ticket.token_id, device_fingerprint="fp-b", now=at(11))
    assert exc.value.code == "MAGIC_LINK_CONSUMED"


def test_confirm_without_pending_request_is_refused():
    iss = issuer()
    ticket = issue(iss)
    with pytest.raises(ml.MagicLinkError) as exc:
        iss.confirm(ticket.token_id, device_fingerprint="fp-a", now=NOW)
    assert exc.value.code == "MAGIC_LINK_NO_PENDING"


def test_revoke_policy_invalidates_old_link_of_same_purpose_only():
    iss = issuer(resend_policy="revoke")
    first = issue(iss, purpose="login", now=NOW)
    second = issue(iss, purpose="login", now=at(1))
    third = issue(iss, purpose="reset", now=at(2))
    with pytest.raises(ml.MagicLinkError) as exc:
        iss.redeem(first.token_id, device_fingerprint="fp-a", now=at(3))
    assert exc.value.code == "MAGIC_LINK_REVOKED"
    redeemed = iss.redeem(second.token_id, device_fingerprint="fp-a", now=at(3))
    assert redeemed.status == "redeemed"
    assert iss.status(third.token_id)["state"] == "pending"


def test_invalidate_all_only_touches_one_email():
    iss = issuer()
    tokens = [issue(iss, purpose=purpose, now=at(index))
              for index, purpose in enumerate(["login", "reset", "verify"])]
    other = issue(iss, "other@example.com", now=NOW)
    assert iss.invalidate(tokens[0].token_id) is True
    assert iss.invalidate(tokens[0].token_id) is False
    assert iss.invalidate_all("user@example.com") == 2
    assert iss.active_links("user@example.com", now=at(4)) == []
    assert iss.active_links("other@example.com", now=at(4)) == [other.token_id]
    with pytest.raises(ml.MagicLinkError) as exc:
        iss.redeem(tokens[1].token_id, device_fingerprint="fp-a", now=at(4))
    assert exc.value.code == "MAGIC_LINK_REVOKED"
    fresh = issue(iss, now=at(5))
    assert fresh.state == "pending"


def test_issue_is_rate_limited_per_email():
    iss = issuer(min_issue_interval=120)
    issue(iss, now=NOW)
    with pytest.raises(ml.MagicLinkError) as exc:
        issue(iss, now=at(30))
    assert exc.value.code == "MAGIC_LINK_RATE_LIMITED"
    later = issue(iss, now=at(120))
    assert later.state == "pending"
    assert iss.stats()["rate_limited"] == 1


def test_active_link_cap_blocks_issue_until_one_is_used():
    iss = issuer(max_active_per_email=2, resend_policy="revoke")
    first = issue(iss, purpose="login", now=NOW)
    issue(iss, purpose="reset", now=at(1))
    with pytest.raises(ml.MagicLinkError) as exc:
        issue(iss, purpose="verify", now=at(2))
    assert exc.value.code == "MAGIC_LINK_TOO_MANY_ACTIVE"
    assert len(iss.active_links("user@example.com", now=at(2))) == 2
    iss.redeem(first.token_id, device_fingerprint="fp-a", now=at(3))
    made = issue(iss, purpose="verify", now=at(3))
    assert made.purpose == "verify"
    assert len(iss.active_links("user@example.com", now=at(3))) == 2


def test_snapshot_is_detached_and_restore_roundtrips():
    iss = issuer()
    kept = issue(iss, purpose="login", now=NOW)
    used = issue(iss, purpose="reset", now=at(1))
    iss.redeem(used.token_id, device_fingerprint="fp-a", now=at(2))
    state = iss.snapshot()
    pristine = copy.deepcopy(state)
    assert set(state) == {"version", "links", "counters", "stats"}
    state["links"].clear()
    state["stats"]["issued"] = 99
    assert iss.stats()["issued"] == 2
    assert iss.status(kept.token_id)["state"] == "pending"

    clone = issuer()
    clone.restore(pristine)
    assert clone.status(used.token_id)["state"] == "consumed"
    assert clone.status(kept.token_id)["state"] == "pending"
    consumed = clone.redeem(used.token_id, device_fingerprint="fp-a", now=at(9))
    assert consumed.status == "consumed"
    assert consumed.redeemed_at == at(2)

    live = clone.snapshot()
    for bad in [None, {}, {"version": 2, "links": [], "counters": {}, "stats": {}},
                {"version": 1, "links": "nope", "counters": {}, "stats": {}},
                {"version": 1, "links": [], "counters": [], "stats": {}},
                {"version": 1, "links": [], "counters": {}, "stats": {"issued": 1}}]:
        with pytest.raises(ml.MagicLinkError) as exc:
            clone.restore(bad)
        assert exc.value.code == "MAGIC_LINK_SNAPSHOT_INVALID"
    assert clone.snapshot() == live


def test_stats_track_each_outcome():
    iss = issuer(min_issue_interval=60)
    first = issue(iss, now=NOW)
    iss.redeem(first.token_id, device_fingerprint="fp-a", now=NOW)
    iss.redeem(first.token_id, device_fingerprint="fp-a", now=at(1))
    second = issue(iss, now=at(61))
    iss.invalidate(second.token_id, now=at(62))
    third = issue(iss, now=at(122), ttl=5)
    assert iss.purge_expired(now=at(130)) == 1
    with pytest.raises(ml.MagicLinkError) as exc:
        issue(iss, now=at(123))
    assert exc.value.code == "MAGIC_LINK_RATE_LIMITED"
    assert iss.status(third.token_id)["state"] == "expired"
    assert iss.stats() == {"issued": 3, "redeemed": 1, "consumed": 1,
                           "revoked": 1, "expired": 1, "rate_limited": 1}
