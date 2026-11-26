import copy
import threading

import pytest

import mail_attachment_claim as mc

HERO = "hero-7"
SENDER = "gm-ops"


def service(**kwargs):
    return mc.MailAttachmentClaim(**kwargs)


def rows(*spec):
    return [
        {"item_id": item, "count": count, "slots": slots}
        for item, count, slots in spec
    ]


def send(svc, mail_id="mail-1", *, sender=SENDER, recipient=HERO,
         items=(("iron-sword", 1, 1),), sent_at=0, expires_at=None):
    return svc.send_mail(
        mail_id,
        sender=sender,
        recipient=recipient,
        attachments=rows(*items),
        sent_at=sent_at,
        expires_at=expires_at,
    )


def test_send_mail_registers_active_mail_with_attachments():
    svc = service()
    view = send(svc, items=(("iron-sword", 1, 1), ("heal-potion", 5, 1)))
    assert view.mail_id == "mail-1"
    assert view.sender == SENDER
    assert view.recipient == HERO
    assert view.status == "active"
    assert view.expires_at is None
    assert view.claimed_count == 0
    assert view.unclaimed_count == 2
    assert [(a.attachment_id, a.item_id, a.count, a.slots, a.claimed)
            for a in view.attachments] == [
        (1, "iron-sword", 1, 1, False),
        (2, "heal-potion", 5, 1, False),
    ]
    assert svc.inbox(HERO) == (view,)
    assert svc.inbox("hero-8") == ()


def test_send_mail_rejects_duplicate_and_invalid_input():
    svc = service(max_attachments=2)
    send(svc)

    with pytest.raises(mc.MailError) as exc:
        send(svc)
    assert exc.value.code == "MAIL_DUPLICATE_ID"

    bad_calls = [
        dict(sender="", recipient=HERO, items=(("iron-sword", 1, 1),)),
        dict(sender=SENDER, recipient="", items=(("iron-sword", 1, 1),)),
        dict(sender=SENDER, recipient=HERO, items=()),
        dict(sender=SENDER, recipient=HERO, items=(("iron-sword", 0, 1),)),
        dict(sender=SENDER, recipient=HERO, items=(("iron-sword", 1, 0),)),
        dict(sender=SENDER, recipient=HERO,
             items=(("a", 1, 1), ("b", 1, 1), ("c", 1, 1))),
    ]
    for index, kwargs in enumerate(bad_calls):
        with pytest.raises(mc.MailError) as exc:
            send(svc, f"bad-{index}", **kwargs)
        assert exc.value.code == "MAIL_INVALID_REQUEST"

    with pytest.raises(mc.MailError) as exc:
        send(svc, "bad-expiry", sent_at=100, expires_at=100)
    assert exc.value.code == "MAIL_INVALID_REQUEST"

    assert [view.mail_id for view in svc.inbox(HERO)] == ["mail-1"]
    assert svc.stats()["mails"] == 1


def test_claim_attachment_moves_item_into_bag():
    svc = service()
    send(svc, items=(("iron-sword", 1, 2), ("heal-potion", 5, 1)))

    out = svc.claim_attachment("mail-1", player=HERO, attachment_id=1, now=50)
    assert out.mail_id == "mail-1"
    assert out.player == HERO
    assert out.status == "active"
    assert out.slots_used == 2
    assert [(a.attachment_id, a.claimed) for a in out.claimed] == [(1, True)]

    assert svc.bag_of(HERO) == mc.BagView(
        player=HERO, used_slots=2, free_slots=38, items=(("iron-sword", 1),)
    )
    view = svc.mail_view("mail-1")
    assert view.claimed_count == 1
    assert view.unclaimed_count == 1
    assert [a.claimed for a in view.attachments] == [True, False]
    assert svc.stats()["claims"] == 1
    assert svc.stats()["claimed_items"] == 1


def test_claim_attachment_requires_recipient():
    svc = service()
    send(svc)

    with pytest.raises(mc.MailError) as exc:
        svc.claim_attachment("mail-1", player="intruder", attachment_id=1, now=10)
    assert exc.value.code == "MAIL_NOT_RECIPIENT"

    assert svc.mail_view("mail-1").claimed_count == 0
    assert svc.bag_of("intruder").used_slots == 0
    assert svc.stats()["claims"] == 0


def test_claim_same_attachment_twice_is_refused():
    svc = service()
    send(svc)
    svc.claim_attachment("mail-1", player=HERO, attachment_id=1, now=10)

    with pytest.raises(mc.MailError) as exc:
        svc.claim_attachment("mail-1", player=HERO, attachment_id=1, now=20)
    assert exc.value.code == "MAIL_ALREADY_CLAIMED"

    assert svc.bag_of(HERO).used_slots == 1
    assert svc.stats()["claims"] == 1

    with pytest.raises(mc.MailError) as exc:
        svc.claim_attachment("mail-1", player=HERO, attachment_id=9, now=20)
    assert exc.value.code == "MAIL_NOT_FOUND"


def test_claim_all_requires_enough_bag_capacity():
    svc = service(bag_slots=2)
    send(svc, items=(("a", 1, 1), ("b", 1, 1), ("c", 1, 1)))

    with pytest.raises(mc.MailError) as exc:
        svc.claim_all("mail-1", player=HERO, now=10)
    assert exc.value.code == "MAIL_BAG_FULL"

    view = svc.mail_view("mail-1")
    assert view.claimed_count == 0
    assert view.status == "active"
    assert svc.bag_of(HERO) == mc.BagView(HERO, 0, 2, ())
    assert svc.stats()["claims"] == 0


def test_claim_all_claims_every_attachment_and_marks_mail_empty():
    svc = service(bag_slots=10)
    send(svc, items=(("iron-sword", 1, 2), ("heal-potion", 5, 3)))

    out = svc.claim_all("mail-1", player=HERO, now=10)
    assert out.status == "empty"
    assert out.slots_used == 5
    assert [(a.attachment_id, a.claimed) for a in out.claimed] == [
        (1, True), (2, True)
    ]

    view = svc.mail_view("mail-1")
    assert view.status == "empty"
    assert view.claimed_count == 2
    assert view.unclaimed_count == 0
    assert svc.bag_of(HERO) == mc.BagView(
        HERO, 5, 5, (("heal-potion", 5), ("iron-sword", 1))
    )


def test_claim_expired_mail_is_refused():
    svc = service()
    send(svc, sent_at=0, expires_at=100)

    with pytest.raises(mc.MailError) as exc:
        svc.claim_attachment("mail-1", player=HERO, attachment_id=1, now=101)
    assert exc.value.code == "MAIL_EXPIRED"

    assert svc.mail_view("mail-1").claimed_count == 0
    assert svc.bag_of(HERO).used_slots == 0
    assert svc.stats()["claims"] == 0


def test_expire_mail_returns_unclaimed_to_sender():
    svc = service()
    send(svc, items=(("iron-sword", 1, 1), ("heal-potion", 5, 2),
                     ("gold-pouch", 100, 1)))

    out = svc.expire_mail("mail-1", now=101)
    assert out.mail_id == "mail-1"
    assert out.status == "expired"
    assert [(row.return_id, row.item_id, row.count, row.slots)
            for row in out.returned] == [
        ("mail-1:1", "iron-sword", 1, 1),
        ("mail-1:2", "heal-potion", 5, 2),
        ("mail-1:3", "gold-pouch", 100, 1),
    ]
    assert [row.sender for row in out.returned] == [SENDER, SENDER, SENDER]
    assert [row.returned_at for row in out.returned] == [101, 101, 101]
    assert svc.returns_for(SENDER) == out.returned
    assert svc.mail_view("mail-1").status == "expired"
    assert svc.stats()["returned_items"] == 106
    assert svc.stats()["expiries"] == 1


def test_expire_mail_is_idempotent():
    svc = service()
    send(svc, sent_at=0, expires_at=100)
    first = svc.expire_mail("mail-1", now=101)
    assert len(first.returned) == 1

    second = svc.expire_mail("mail-1", now=102)
    assert second.mail_id == "mail-1"
    assert second.returned == ()
    assert second.status == "expired"

    assert len(svc.returns_for(SENDER)) == 1
    assert svc.stats()["expiries"] == 1
    assert svc.stats()["returned_items"] == 1


def test_expire_due_sweeps_only_due_mails():
    svc = service()
    send(svc, "mail-a", items=(("a", 2, 1),), sent_at=0, expires_at=100)
    send(svc, "mail-b", items=(("b", 2, 1),), sent_at=0, expires_at=200)
    send(svc, "mail-c", items=(("c", 2, 1),), sent_at=0)
    send(svc, "mail-d", recipient="hero-8", items=(("d", 2, 1),),
         sent_at=0, expires_at=100)

    results = svc.expire_due(now=150)
    assert [row.mail_id for row in results] == ["mail-a", "mail-d"]
    assert [len(row.returned) for row in results] == [1, 1]
    assert svc.mail_view("mail-b").status == "active"
    assert svc.mail_view("mail-c").status == "active"
    assert [row.return_id for row in svc.returns_for(SENDER)] == [
        "mail-a:1", "mail-d:1"
    ]


def test_concurrent_claims_allow_single_winner():
    svc = service()
    send(svc)
    successes = []
    failures = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            successes.append(
                svc.claim_attachment("mail-1", player=HERO, attachment_id=1, now=10)
            )
        except mc.MailError as exc:
            failures.append(exc.code)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(successes) == 1
    assert failures == ["MAIL_ALREADY_CLAIMED"] * 7
    assert svc.bag_of(HERO).used_slots == 1
    assert svc.stats()["claims"] == 1


def test_stats_track_claims_expiries_and_returns():
    svc = service()
    send(svc, items=(("iron-sword", 1, 1), ("heal-potion", 5, 1)))
    svc.claim_attachment("mail-1", player=HERO, attachment_id=1, now=10)
    send(svc, "mail-2", sender="event-gm", items=(("a", 7, 1),),
         sent_at=0, expires_at=100)
    svc.expire_mail("mail-2", now=101)

    assert svc.stats() == {
        "mails": 2,
        "active": 1,
        "empty": 0,
        "expired": 1,
        "claims": 1,
        "claimed_items": 1,
        "returned_items": 7,
        "expiries": 1,
        "bag_write_failures": 0,
    }


def test_snapshot_is_detached_and_restore_roundtrips():
    svc = service(bag_slots=8)
    send(svc, items=(("iron-sword", 1, 1), ("heal-potion", 5, 1)))
    svc.claim_attachment("mail-1", player=HERO, attachment_id=1, now=10)
    send(svc, "mail-2", sender="event-gm", items=(("a", 7, 1),),
         sent_at=0, expires_at=100)
    svc.expire_mail("mail-2", now=101)

    state = svc.snapshot()
    assert set(state) == {"version", "mails", "bags", "returns", "counters", "stats"}
    pristine = copy.deepcopy(state)

    state["mails"].clear()
    state["bags"].clear()
    assert svc.mail_view("mail-1").claimed_count == 1
    assert svc.bag_of(HERO).used_slots == 1
    assert len(svc.returns_for("event-gm")) == 1
    assert svc.stats()["mails"] == 2

    clone = service(bag_slots=8)
    clone.restore(pristine)
    assert clone.mail_view("mail-1") == svc.mail_view("mail-1")
    assert clone.mail_view("mail-2") == svc.mail_view("mail-2")
    assert clone.inbox(HERO) == svc.inbox(HERO)
    assert clone.bag_of(HERO) == svc.bag_of(HERO)
    assert clone.returns_for("event-gm") == svc.returns_for("event-gm")
    assert clone.stats() == svc.stats()


def test_restore_rejects_malformed_state_without_mutation():
    svc = service()
    send(svc)
    svc.claim_attachment("mail-1", player=HERO, attachment_id=1, now=10)
    before_mail = svc.mail_view("mail-1")
    before_bag = svc.bag_of(HERO)
    before_stats = svc.stats()

    bad_states = [
        None,
        {},
        {"version": 2},
        {"version": 1, "mails": []},
        {"version": 1, "mails": {}, "bags": {}, "returns": [],
         "counters": {}},
    ]
    for bad in bad_states:
        with pytest.raises(mc.MailError) as exc:
            svc.restore(bad)
        assert exc.value.code == "MAIL_SNAPSHOT_INVALID"

    assert svc.mail_view("mail-1") == before_mail
    assert svc.bag_of(HERO) == before_bag
    assert svc.stats() == before_stats
