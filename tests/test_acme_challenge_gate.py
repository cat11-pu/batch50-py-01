import copy
import threading

import pytest

import acme_challenge_gate as acme

NOW = "2026-11-26T09:00:00+00:00"
LATER = "2026-11-26T09:10:00+00:00"
THUMB = "thumb-aaa111"
IDENT = "a.example.com"


def gate(**kwargs):
    return acme.AcmeChallengeGate(**kwargs)


def ready_order(item, identifiers=(IDENT,), thumbprint=THUMB):
    item.register_account("acct-1", thumbprint, now=NOW)
    order = item.new_order("acct-1", list(identifiers), now=NOW)
    for identifier in identifiers:
        item.authorize(order.order_id, identifier, now=NOW)
    return order


def test_new_order_creates_pending_order_with_authorizations():
    item = gate()
    item.register_account("acct-1", THUMB, now=NOW)
    order = item.new_order("acct-1", ["a.example.com"], now=NOW)
    assert order.account_id == "acct-1"
    assert order.identifiers == (IDENT,)
    assert order.status == "pending"
    assert order.certificate_serial is None
    assert order.created_at == NOW
    authorization = item.authorization_for(order.order_id, IDENT)
    assert authorization.identifier == IDENT
    assert authorization.status == "pending"
    assert authorization.challenge_type == "http-01"
    assert len(authorization.token) >= 32
    assert authorization.attempts == 0
    assert authorization.next_at is None
    assert item.status()["authorizations"] == 1
    assert item.stats()["orders_created"] == 1


def test_new_order_rejects_bad_identifiers_and_unknown_account():
    item = gate()
    item.register_account("acct-1", THUMB, now=NOW)
    with pytest.raises(acme.AcmeError) as exc:
        item.new_order("acct-1", [], now=NOW)
    assert exc.value.code == "ACME_INVALID_REQUEST"
    with pytest.raises(acme.AcmeError) as other:
        item.new_order("acct-1", ["a.example.com", "a.example.com"], now=NOW)
    assert other.value.code == "ACME_INVALID_REQUEST"
    with pytest.raises(acme.AcmeError) as unknown:
        item.new_order("acct-9", ["a.example.com"], now=NOW)
    assert unknown.value.code == "ACME_UNKNOWN_ACCOUNT"


def test_authorize_issues_token_only_once_per_identifier():
    item = gate()
    order = ready_order(item)
    first = item.authorization_for(order.order_id, IDENT)
    with pytest.raises(acme.AcmeError) as exc:
        item.authorize(order.order_id, IDENT, now=NOW)
    assert exc.value.code == "ACME_TOKEN_REUSED"
    with pytest.raises(acme.AcmeError) as other:
        item.authorize(order.order_id, "b.example.com", now=NOW)
    assert other.value.code == "ACME_UNKNOWN_AUTHORIZATION"
    assert item.authorization_for(order.order_id, IDENT).token == first.token


def test_http01_validation_success_moves_order_to_ready():
    item = gate()
    order = ready_order(item)
    authorization = item.authorization_for(order.order_id, IDENT)
    value = f"{authorization.token}.{THUMB}"
    result = item.validate(order.order_id, IDENT, "nonce-1", value, now=NOW)
    assert result.accepted is True
    assert result.status == "valid"
    assert result.attempts == 0
    assert result.next_at is None
    assert item.authorization_for(order.order_id, IDENT).status == "valid"
    assert item.order_status(order.order_id).status == "ready"
    assert item.stats()["validated"] == 1


def test_http01_wrong_value_counts_attempt_and_schedules_retry():
    item = gate()
    order = ready_order(item)
    result = item.validate(order.order_id, IDENT, "nonce-1", "wrong-value", now=NOW)
    assert result.accepted is False
    assert result.status == "pending"
    assert result.attempts == 1
    assert result.next_at == "2026-11-26T09:00:02+00:00"
    assert item.order_status(order.order_id).status == "pending"
    assert item.stats()["failed"] == 1


def test_attempt_budget_exhaustion_invalidates_whole_order():
    item = gate(max_attempts=2)
    order = ready_order(item)
    first = item.validate(order.order_id, IDENT, "nonce-1", "wrong-one", now=NOW)
    assert first.attempts == 1
    with pytest.raises(acme.AcmeError) as exc:
        item.validate(order.order_id, IDENT, "nonce-2", "wrong-two", now=NOW)
    assert exc.value.code == "ACME_ATTEMPTS_EXHAUSTED"
    assert item.order_status(order.order_id).status == "invalid"
    assert item.authorization_for(order.order_id, IDENT).status == "invalid"
    assert item.stats()["exhausted"] == 1


def test_finalize_requires_every_authorization_valid():
    item = gate()
    identifiers = ("a.example.com", "b.example.com")
    order = ready_order(item, identifiers)
    authorization = item.authorization_for(order.order_id, IDENT)
    value = f"{authorization.token}.{THUMB}"
    assert item.validate(order.order_id, IDENT, "nonce-1", value, now=NOW).accepted is True
    with pytest.raises(acme.AcmeError) as exc:
        item.finalize(order.order_id, "csr-1", now=LATER)
    assert exc.value.code == "ACME_ORDER_NOT_READY"
    assert item.order_status(order.order_id).status == "pending"
    assert item.authorization_for(order.order_id, "b.example.com").status == "pending"


def test_finalize_issues_certificate_and_order_is_immutable():
    item = gate()
    order = ready_order(item)
    authorization = item.authorization_for(order.order_id, IDENT)
    value = f"{authorization.token}.{THUMB}"
    item.validate(order.order_id, IDENT, "nonce-1", value, now=NOW)
    certificate = item.finalize(order.order_id, "csr-1", now=LATER)
    assert len(certificate.serial) == 40
    assert all(character in "0123456789abcdef" for character in certificate.serial)
    assert certificate.order_id == order.order_id
    assert certificate.account_id == "acct-1"
    assert certificate.issued_at == LATER
    assert certificate.revoked_at is None
    current = item.order_status(order.order_id)
    assert current.status == "valid"
    assert current.certificate_serial == certificate.serial
    with pytest.raises(acme.AcmeError) as exc:
        item.finalize(order.order_id, "csr-2", now=LATER)
    assert exc.value.code == "ACME_ORDER_IMMUTABLE"
    assert item.stats()["finalized"] == 1


def test_revoke_marks_certificate_and_is_idempotent():
    item = gate()
    order = ready_order(item)
    authorization = item.authorization_for(order.order_id, IDENT)
    item.validate(order.order_id, IDENT, "nonce-1", f"{authorization.token}.{THUMB}", now=NOW)
    certificate = item.finalize(order.order_id, "csr-1", now=LATER)
    assert item.revoke(certificate.serial, reason="keyCompromise", now=LATER) is True
    assert item.revoke(certificate.serial, now=LATER) is False
    assert item.order_status(order.order_id).status == "invalid"
    assert item.stats()["revoked"] == 1
    with pytest.raises(acme.AcmeError) as exc:
        item.revoke("f" * 40, now=LATER)
    assert exc.value.code == "ACME_UNKNOWN_CERTIFICATE"


def test_nonce_cannot_be_replayed_even_after_failure():
    item = gate()
    order = ready_order(item)
    item.validate(order.order_id, IDENT, "nonce-x", "wrong-value", now=NOW)
    with pytest.raises(acme.AcmeError) as exc:
        item.validate(order.order_id, IDENT, "nonce-x", "wrong-value", now=NOW)
    assert exc.value.code == "ACME_NONCE_REPLAY"
    assert item.stats()["nonce_replays"] == 1


def test_account_key_rotation_replaces_thumbprint():
    item = gate()
    item.register_account("acct-1", THUMB, now=NOW)
    rotated = item.rotate_account_key("acct-1", "thumb-bbb222", now=LATER)
    assert rotated.account_id == "acct-1"
    assert rotated.thumbprint == "thumb-bbb222"
    assert rotated.rotated_at == LATER
    assert item.account_for("acct-1").thumbprint == "thumb-bbb222"
    assert item.stats()["rotated"] == 1


def test_order_capacity_is_capped_per_account():
    item = gate(max_orders_per_account=2)
    item.register_account("acct-1", THUMB, now=NOW)
    item.new_order("acct-1", ["a.example.com"], now=NOW)
    item.new_order("acct-1", ["b.example.com"], now=NOW)
    with pytest.raises(acme.AcmeError) as exc:
        item.new_order("acct-1", ["c.example.com"], now=NOW)
    assert exc.value.code == "ACME_CAPACITY_EXCEEDED"
    assert item.status()["orders"] == 2


def test_concurrent_validation_with_same_nonce_has_single_winner():
    item = gate()
    order = ready_order(item)
    authorization = item.authorization_for(order.order_id, IDENT)
    value = f"{authorization.token}.{THUMB}"
    accepted = []
    failures = []
    errors = []
    barrier = threading.Barrier(4)

    def worker():
        try:
            barrier.wait(timeout=5)
            outcome = item.validate(order.order_id, IDENT, "nonce-shared", value, now=NOW)
            accepted.append(outcome.accepted)
        except acme.AcmeError as exc:
            failures.append(exc.code)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert accepted == [True]
    assert failures == ["ACME_NONCE_REPLAY"] * 3
    assert item.order_status(order.order_id).status == "ready"


def test_snapshot_roundtrip_keeps_orders_tokens_and_attempts():
    item = gate()
    order = ready_order(item)
    item.validate(order.order_id, IDENT, "nonce-used", "wrong-value", now=NOW)
    state = item.snapshot()
    assert set(state) == {"version", "accounts", "orders", "authorizations",
                          "certificates", "counters", "stats"}
    pristine = copy.deepcopy(state)
    state["orders"].clear()
    state["stats"]["validated"] = 99
    assert item.status()["orders"] == 1
    assert item.stats()["validated"] == 0

    clone = gate()
    clone.restore(pristine)
    restored = clone.authorization_for(order.order_id, IDENT)
    assert restored.attempts == 1
    assert restored.token == item.authorization_for(order.order_id, IDENT).token
    assert clone.order_status(order.order_id).status == "pending"
    with pytest.raises(acme.AcmeError) as exc:
        clone.validate(order.order_id, IDENT, "nonce-used", "wrong-value", now=NOW)
    assert exc.value.code == "ACME_NONCE_REPLAY"


def test_restore_rejects_malformed_state_without_touching_live_orders():
    item = gate()
    order = ready_order(item)
    bad_states = [
        None,
        {},
        {"version": 5, "accounts": {}, "orders": {}, "authorizations": {},
         "certificates": {}, "counters": {}, "stats": {}},
        {"version": 1, "accounts": [], "orders": {}, "authorizations": {},
         "certificates": {}, "counters": {}, "stats": {}},
        {"version": 1, "accounts": {}, "orders": [], "authorizations": {},
         "certificates": {}, "counters": {}, "stats": {}},
        {"version": 1, "accounts": {}, "orders": {}, "authorizations": {},
         "certificates": {}, "counters": {}, "stats": {"validated": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(acme.AcmeError) as exc:
            item.restore(bad)
        assert exc.value.code == "ACME_SNAPSHOT_INVALID"
    assert item.order_status(order.order_id).status == "pending"
    assert item.authorization_for(order.order_id, IDENT).status == "pending"
