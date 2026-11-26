import threading

import pytest

import impersonation_session_broker as ib

BASE = 1_800_000_000
SCOPES = ["read_orders", "read_profile", "read_orders"]


def broker(**kwargs):
    return ib.ImpersonationBroker(**kwargs)


def requester(led, *, cs="cs-1", target="user-9", reason="客户来电核对订单",
              actions=None, now=BASE):
    return led.request(cs, target, reason, SCOPES if actions is None else actions,
                       now=now)


def live_session(led, *, cs="cs-1", target="user-9", actions=None, now=BASE):
    req = requester(led, cs=cs, target=target, actions=actions, now=now)
    led.grant_approver("lead-1")
    led.approve(req["request_id"], "lead-1", now=now + 1)
    return led.start(req["request_id"], now=now + 2)


def test_request_creates_pending_record_with_sorted_actions():
    led = broker()
    req = requester(led)
    assert req["request_id"] == "req-1"
    assert req["cs_id"] == "cs-1"
    assert req["target_id"] == "user-9"
    assert req["actions"] == ("read_orders", "read_profile")
    assert req["state"] == "pending"
    assert req["approved_by"] is None
    assert req["session_id"] is None
    assert led.stats()["requests"] == 1


def test_request_validates_reason_actions_and_self_target():
    led = broker()
    with pytest.raises(ib.ImpersonationError) as blank_reason:
        led.request("cs-1", "user-9", "   ", ["read_orders"], now=BASE)
    assert blank_reason.value.code == "IMP_INVALID"
    with pytest.raises(ib.ImpersonationError) as no_actions:
        led.request("cs-1", "user-9", "客户来电", [], now=BASE)
    assert no_actions.value.code == "IMP_INVALID"
    with pytest.raises(ib.ImpersonationError) as bad_action:
        led.request("cs-1", "user-9", "客户来电", ["read_orders", "  "], now=BASE)
    assert bad_action.value.code == "IMP_INVALID"
    with pytest.raises(ib.ImpersonationError) as same_person:
        led.request("cs-1", "cs-1", "客户来电", ["read_orders"], now=BASE)
    assert same_person.value.code == "IMP_SELF"
    assert led.stats()["requests"] == 0


def test_second_in_flight_request_for_same_pair_is_refused():
    led = broker()
    requester(led)
    with pytest.raises(ib.ImpersonationError) as limited:
        requester(led, now=BASE + 5)
    assert limited.value.code == "IMP_LIMIT"
    assert led.stats()["requests"] == 1


def test_requester_cannot_approve_own_request():
    led = broker()
    req = requester(led)
    led.grant_approver("cs-1")
    with pytest.raises(ib.ImpersonationError) as self_approval:
        led.approve(req["request_id"], "cs-1", now=BASE + 1)
    assert self_approval.value.code == "IMP_SELF"
    assert led.stats()["approvals"] == 0


def test_only_registered_approver_can_release_request():
    led = broker()
    req = requester(led)
    with pytest.raises(ib.ImpersonationError) as stranger:
        led.approve(req["request_id"], "lead-1", now=BASE + 1)
    assert stranger.value.code == "IMP_NOT_APPROVER"
    granted = led.grant_approver("lead-1")
    assert granted["principal"] == "lead-1"
    assert granted["approver"] is True
    approved = led.approve(req["request_id"], "lead-1", now=BASE + 2)
    assert approved["state"] == "approved"
    assert approved["approved_by"] == "lead-1"
    assert led.stats()["approvals"] == 1


def test_start_requires_approval_then_binds_session_ttl():
    led = broker()
    req = requester(led)
    with pytest.raises(ib.ImpersonationError) as early:
        led.start(req["request_id"], now=BASE + 1)
    assert early.value.code == "IMP_REQUEST_STATE"
    led.grant_approver("lead-1")
    led.approve(req["request_id"], "lead-1", now=BASE + 2)
    session = led.start(req["request_id"], now=BASE + 10)
    assert session["session_id"] == "imp-1"
    assert session["state"] == "active"
    assert session["expires_at"] == BASE + 910
    assert session["request_id"] == req["request_id"]
    assert led.stats()["sessions"] == 1


def test_act_honours_scope_and_counts_denied_actions():
    led = broker()
    session = live_session(led)
    allowed = led.act(session["session_id"], "read_orders", now=BASE + 20)
    assert allowed["allowed"] is True
    assert allowed["count"] == 1
    assert led.stats()["actions"] == 1
    with pytest.raises(ib.ImpersonationError) as denied:
        led.act(session["session_id"], "issue_refund", now=BASE + 21)
    assert denied.value.code == "IMP_SCOPE"
    assert led.stats()["denied_actions"] == 1
    assert led.stats()["actions"] == 1


def test_session_expiry_blocks_actions_and_expire_counts():
    led = broker()
    session = live_session(led)
    with pytest.raises(ib.ImpersonationError) as expired:
        led.act(session["session_id"], "read_orders", now=BASE + 910)
    assert expired.value.code == "IMP_SESSION_EXPIRED"
    assert led.expire(now=BASE + 910) == 1
    assert led.session_view(session["session_id"])["state"] == "expired"
    assert led.stats()["expired"] == 1


def test_revoke_is_idempotent_and_blocks_further_actions():
    led = broker()
    session = live_session(led)
    first = led.revoke(session["session_id"], "user-9", "本人要求终止", now=BASE + 30)
    assert first["state"] == "revoked"
    second = led.revoke(session["session_id"], "user-9", "重复撤销", now=BASE + 31)
    assert second["state"] == "revoked"
    assert led.stats()["revocations"] == 1
    with pytest.raises(ib.ImpersonationError) as revoked:
        led.act(session["session_id"], "read_orders", now=BASE + 32)
    assert revoked.value.code == "IMP_SESSION_REVOKED"


def test_ticket_is_redeemable_once():
    led = broker()
    session = live_session(led)
    ticket = led.issue_ticket(session["session_id"], "read_orders", now=BASE + 20)
    assert ticket["ticket_id"] == "tkt-1"
    assert ticket["expires_at"] == BASE + 140
    assert ticket["state"] == "unused"
    used = led.redeem_ticket(ticket["ticket_id"], now=BASE + 30)
    assert used["ticket_id"] == "tkt-1"
    assert used["action"] == "read_orders"
    assert used["redeemed_at"] == BASE + 30
    assert led.stats()["redeemed"] == 1
    with pytest.raises(ib.ImpersonationError) as spent:
        led.redeem_ticket(ticket["ticket_id"], now=BASE + 31)
    assert spent.value.code == "IMP_TICKET_SPENT"


def test_ticket_expires_at_ttl_boundary():
    led = broker()
    session = live_session(led)
    ticket = led.issue_ticket(session["session_id"], "read_profile", now=BASE + 20)
    with pytest.raises(ib.ImpersonationError) as expired:
        led.redeem_ticket(ticket["ticket_id"], now=BASE + 140)
    assert expired.value.code == "IMP_TICKET_EXPIRED"
    assert led.stats()["redeemed"] == 0


def test_unknown_request_session_and_ticket_are_refused():
    led = broker()
    with pytest.raises(ib.ImpersonationError) as unknown_request:
        led.start("req-404", now=BASE)
    assert unknown_request.value.code == "IMP_REQUEST_UNKNOWN"
    with pytest.raises(ib.ImpersonationError) as unknown_session:
        led.session_view("imp-404")
    assert unknown_session.value.code == "IMP_SESSION_UNKNOWN"
    with pytest.raises(ib.ImpersonationError) as unknown_ticket:
        led.redeem_ticket("tkt-404", now=BASE)
    assert unknown_ticket.value.code == "IMP_TICKET_UNKNOWN"


def test_revoked_approver_cannot_release_later_requests():
    led = broker()
    led.grant_approver("lead-1")
    led.grant_approver("lead-2")
    first = requester(led, cs="cs-1", target="user-9")
    assert led.revoke_approver("lead-2") is True
    assert led.revoke_approver("lead-2") is False
    with pytest.raises(ib.ImpersonationError) as gone:
        led.approve(first["request_id"], "lead-2", now=BASE + 1)
    assert gone.value.code == "IMP_NOT_APPROVER"
    second = requester(led, cs="cs-2", target="user-8")
    approved = led.approve(second["request_id"], "lead-1", now=BASE + 2)
    assert approved["state"] == "approved"


def test_snapshot_restore_keeps_sessions_tickets_and_counters():
    led = broker()
    session = live_session(led)
    ticket = led.issue_ticket(session["session_id"], "read_profile", now=BASE + 20)
    clone = broker()
    clone.restore(led.snapshot())
    assert clone.session_view(session["session_id"])["state"] == "active"
    assert clone.stats() == led.stats()
    with pytest.raises(ib.ImpersonationError) as expired:
        clone.act(session["session_id"], "read_profile", now=BASE + 910)
    assert expired.value.code == "IMP_SESSION_EXPIRED"
    redeemed = clone.redeem_ticket(ticket["ticket_id"], now=BASE + 40)
    assert redeemed["ticket_id"] == ticket["ticket_id"]
    with pytest.raises(ib.ImpersonationError) as broken:
        clone.restore({"version": 1, "sessions": 7})
    assert broken.value.code == "IMP_SNAPSHOT"
    assert clone.session_view(session["session_id"])["state"] == "active"


def test_concurrent_redeem_of_one_ticket_yields_single_success():
    led = broker()
    session = live_session(led)
    ticket = led.issue_ticket(session["session_id"], "read_orders", now=BASE + 20)
    wins = []
    refused = []
    guard = threading.Lock()

    def worker():
        try:
            led.redeem_ticket(ticket["ticket_id"], now=BASE + 30)
        except Exception as err:  # noqa: BLE001 - collect refusal reason
            with guard:
                refused.append(getattr(err, "code", type(err).__name__))
        else:
            with guard:
                wins.append(1)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(wins) == 1
    assert refused.count("IMP_TICKET_SPENT") == 7
    assert led.stats()["redeemed"] == 1
