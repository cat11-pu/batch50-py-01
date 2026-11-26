import threading

import pytest

import recovery_hold_queue as rq

BASE = 1_800_000_000


def queue(**kwargs):
    return rq.RecoveryHoldQueue(**kwargs)


def opened(q, account="acct-1", channels=("sms", "email"), now=BASE):
    return q.request(account, list(channels), now=now)


def confirm_all(q, hold, now=BASE + 10):
    tokens = hold["tokens"]
    for offset, channel in enumerate(sorted(tokens)):
        q.confirm_contact(hold["hold_id"], channel, tokens[channel],
                          now=now + offset)


def code_of(exc_info):
    return exc_info.value.code


def test_request_creates_pending_hold_with_sorted_channels():
    q = queue()
    hold = q.request("acct-1", ["sms", "email", "sms"], now=BASE)
    assert hold["hold_id"] == "hold-1"
    assert hold["account_id"] == "acct-1"
    assert hold["channels"] == ("email", "sms")
    assert hold["state"] == "pending"
    assert hold["created_at"] == BASE
    assert hold["due_at"] == BASE + 172800
    assert hold["confirmations"] == 0
    assert hold["required"] == 2
    assert hold["merged"] is False
    assert hold["tokens"] == {"email": "tok-1", "sms": "tok-2"}
    view = q.hold_view("hold-1")
    assert "tokens" not in view
    assert sorted(view["token_digests"]) == ["email", "sms"]
    assert q.stats()["requests"] == 1


def test_request_validates_account_and_channels():
    q = queue()
    with pytest.raises(rq.RecoveryError) as blank_account:
        q.request("", ["sms"], now=BASE)
    assert code_of(blank_account) == "RECOVERY_INVALID"
    with pytest.raises(rq.RecoveryError) as no_channel:
        q.request("acct-1", [], now=BASE)
    assert code_of(no_channel) == "RECOVERY_INVALID"
    with pytest.raises(rq.RecoveryError) as too_many:
        q.request("acct-1", ["sms", "email", "voice", "fax"], now=BASE)
    assert code_of(too_many) == "RECOVERY_INVALID"
    with pytest.raises(rq.RecoveryError) as bad_type:
        q.request("acct-1", ["sms", 7], now=BASE)
    assert code_of(bad_type) == "RECOVERY_INVALID"
    assert q.stats()["requests"] == 0


def test_second_request_merges_without_restarting_timer():
    q = queue()
    first = q.request("acct-1", ["sms"], now=BASE)
    second = q.request("acct-1", ["sms", "email"], now=BASE + 50)
    assert second["hold_id"] == first["hold_id"]
    assert second["due_at"] == first["due_at"]
    assert second["channels"] == ("sms",)
    assert second["merged"] is True
    assert q.stats()["requests"] == 1
    assert q.stats()["merged"] == 1
    assert q.hold_view(first["hold_id"])["state"] == "pending"


def test_confirm_contact_records_progress():
    q = queue()
    hold = opened(q)
    result = q.confirm_contact(hold["hold_id"], "email",
                               hold["tokens"]["email"], now=BASE + 10)
    assert result["hold_id"] == hold["hold_id"]
    assert result["channel"] == "email"
    assert result["confirmed_at"] == BASE + 10
    assert result["confirmations"] == 1
    assert result["required"] == 2
    assert result["already"] is False
    assert q.stats()["confirmations"] == 1
    assert q.hold_view(hold["hold_id"])["confirmations"] == 1


def test_repeated_confirmation_on_same_channel_is_idempotent():
    q = queue()
    hold = opened(q)
    tokens = hold["tokens"]
    q.confirm_contact(hold["hold_id"], "sms", tokens["sms"], now=BASE + 10)
    again = q.confirm_contact(hold["hold_id"], "sms", tokens["sms"], now=BASE + 20)
    assert again["already"] is True
    assert again["confirmations"] == 1
    assert q.stats()["confirmations"] == 1


def test_confirm_rejects_wrong_channel_and_wrong_token():
    q = queue()
    hold = opened(q)
    with pytest.raises(rq.RecoveryError) as wrong_channel:
        q.confirm_contact(hold["hold_id"], "voice", "tok-1", now=BASE + 10)
    assert code_of(wrong_channel) == "RECOVERY_CHANNEL"
    with pytest.raises(rq.RecoveryError) as wrong_token:
        q.confirm_contact(hold["hold_id"], "sms", "tok-999", now=BASE + 11)
    assert code_of(wrong_token) == "RECOVERY_TOKEN"
    assert q.stats()["confirmations"] == 0


def test_release_before_due_time_is_refused():
    q = queue(hold_seconds=1000)
    hold = q.request("acct-1", ["sms", "email"], now=BASE)
    confirm_all(q, hold, now=BASE + 10)
    with pytest.raises(rq.RecoveryError) as too_early:
        q.release(hold["hold_id"], now=BASE + 999)
    assert code_of(too_early) == "RECOVERY_HOLD"
    assert q.hold_view(hold["hold_id"])["state"] == "pending"


def test_status_reports_remaining_time_without_changing_state():
    q = queue(hold_seconds=1000)
    hold = q.request("acct-1", ["sms", "email"], now=BASE)
    confirm_all(q, hold, now=BASE + 10)
    current = q.status(hold["hold_id"], now=BASE + 400)
    assert current["state"] == "pending"
    assert current["due_at"] == BASE + 1000
    assert current["remaining"] == 600
    assert current["confirmations"] == 2
    assert current["required"] == 2
    assert current["channels"] == ("email", "sms")


def test_release_at_due_time_hands_out_one_credential():
    q = queue(hold_seconds=1000)
    hold = q.request("acct-1", ["sms", "email"], now=BASE)
    confirm_all(q, hold, now=BASE + 10)
    released = q.release(hold["hold_id"], now=BASE + 1000)
    assert released["hold_id"] == hold["hold_id"]
    assert released["state"] == "released"
    assert released["released_at"] == BASE + 1000
    assert released["credential"] == "cred-1"
    assert q.stats()["releases"] == 1
    assert q.hold_view(hold["hold_id"])["state"] == "released"


def test_veto_closes_hold_and_blocks_later_release():
    q = queue()
    hold = opened(q)
    vetoed = q.veto(hold["hold_id"], "user-1", "本人未申请", now=BASE + 20)
    assert vetoed["state"] == "vetoed"
    assert vetoed["vetoed_by"] == "user-1"
    assert vetoed["vetoed_at"] == BASE + 20
    with pytest.raises(rq.RecoveryError) as again:
        q.veto(hold["hold_id"], "user-1", "再撤一次", now=BASE + 21)
    assert code_of(again) == "RECOVERY_CLOSED"
    with pytest.raises(rq.RecoveryError) as closed:
        q.release(hold["hold_id"], now=BASE + 172800)
    assert code_of(closed) == "RECOVERY_CLOSED"
    assert q.stats()["vetoes"] == 1


def test_sweep_releases_confirmed_due_hold_once():
    q = queue(hold_seconds=100)
    hold = q.request("acct-1", ["sms", "email"], now=BASE)
    confirm_all(q, hold, now=BASE + 10)
    out = q.sweep(now=BASE + 100)
    assert out["released"] == 1
    assert sorted(out["credentials"]) == ["hold-1"]
    assert out["credentials"]["hold-1"].startswith("cred-")
    assert q.status(hold["hold_id"], now=BASE + 150)["state"] == "released"
    assert q.sweep(now=BASE + 200)["released"] == 0
    assert q.stats()["releases"] == 1


def test_due_holds_lists_only_due_pending_holds_in_order():
    q = queue(hold_seconds=100)
    first = q.request("acct-1", ["sms"], now=BASE)
    second = q.request("acct-2", ["sms"], now=BASE + 50)
    assert q.due_holds(now=BASE + 99) == []
    assert q.due_holds(now=BASE + 100) == [first["hold_id"]]
    assert q.due_holds(now=BASE + 150) == [first["hold_id"], second["hold_id"]]


def test_unknown_hold_is_refused_everywhere():
    q = queue()
    with pytest.raises(rq.RecoveryError) as unknown_confirm:
        q.confirm_contact("hold-404", "sms", "tok-1", now=BASE)
    assert code_of(unknown_confirm) == "RECOVERY_UNKNOWN"
    with pytest.raises(rq.RecoveryError) as unknown_release:
        q.release("hold-404", now=BASE)
    assert code_of(unknown_release) == "RECOVERY_UNKNOWN"
    with pytest.raises(rq.RecoveryError) as unknown_status:
        q.status("hold-404", now=BASE)
    assert code_of(unknown_status) == "RECOVERY_UNKNOWN"
    with pytest.raises(rq.RecoveryError) as unknown_view:
        q.hold_view("hold-404")
    assert code_of(unknown_view) == "RECOVERY_UNKNOWN"


def test_snapshot_restore_keeps_deadline_progress_and_tokens():
    q = queue(hold_seconds=1000)
    hold = q.request("acct-1", ["sms", "email"], now=BASE)
    q.confirm_contact(hold["hold_id"], "email", hold["tokens"]["email"],
                      now=BASE + 10)
    clone = queue(hold_seconds=1000)
    clone.restore(q.snapshot())
    assert clone.status(hold["hold_id"], now=BASE + 400)["remaining"] == 600
    assert clone.hold_view(hold["hold_id"])["confirmations"] == 1
    assert clone.stats() == q.stats()
    progressed = clone.confirm_contact(hold["hold_id"], "sms",
                                       hold["tokens"]["sms"], now=BASE + 20)
    assert progressed["confirmations"] == 2
    with pytest.raises(rq.RecoveryError) as broken:
        clone.restore({"version": 1, "holds": "nope"})
    assert code_of(broken) == "RECOVERY_SNAPSHOT"
    assert clone.hold_view(hold["hold_id"])["state"] == "pending"


def test_concurrent_release_yields_single_credential():
    q = queue(hold_seconds=100)
    hold = q.request("acct-1", ["sms", "email"], now=BASE)
    confirm_all(q, hold, now=BASE + 10)
    wins = []
    refused = []
    guard = threading.Lock()

    def worker():
        try:
            result = q.release(hold["hold_id"], now=BASE + 100)
        except Exception as err:  # noqa: BLE001 - collect refusal reason
            with guard:
                refused.append(getattr(err, "code", type(err).__name__))
        else:
            with guard:
                wins.append(result["credential"])

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(wins) == 1
    assert len(refused) == 7
    assert q.stats()["releases"] == 1
