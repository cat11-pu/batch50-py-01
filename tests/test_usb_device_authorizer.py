import pytest

import usb_device_authorizer as uda

T0 = "2026-11-26T10:00:00+00:00"
T59 = "2026-11-26T10:00:59+00:00"
T60 = "2026-11-26T10:01:00+00:00"
LATER = "2026-11-26T11:00:00+00:00"


def auth(**kwargs):
    kwargs.setdefault("temp_window", 300)
    return uda.UsbDeviceAuthorizer(**kwargs)


def insert(a, *, vid=0x046D, pid=0xC52B, interfaces=("hid",), port_path="1-1",
           serial="S1", now=T0):
    return a.on_insert(vid=vid, pid=pid, interfaces=interfaces,
                       port_path=port_path, serial=serial, now=now)


def test_allow_rule_authorizes_matching_device():
    a = auth()
    rule = a.add_rule("allow-keyboard", vid=0x046D, pid=0xC52B, decision="allow")
    assert (rule.rule_id, rule.decision) == ("allow-keyboard", "allow")
    rec = insert(a)
    assert rec.state == "authorized"
    assert rec.prompt is False
    assert rec.matched_rule == "allow-keyboard"
    assert rec.expires_at is None
    assert rec.interfaces == ("hid",)
    assert a.stats()["authorized"] == 1


def test_unknown_device_is_pending_and_prompts_once():
    a = auth()
    first = insert(a)
    assert (first.state, first.prompt, first.matched_rule) == ("pending", True, None)
    second = insert(a)
    assert (second.state, second.prompt) == ("pending", False)
    assert second.fingerprint == first.fingerprint
    assert len(a.devices()) == 1
    assert a.stats()["prompts"] == 1
    assert a.stats()["deduped"] == 1


def test_deny_rule_on_one_interface_denies_composite():
    a = auth()
    a.add_rule("deny-hid", vid=0x1234, decision="deny", interfaces=("hid",))
    rec = insert(a, vid=0x1234, pid=0x0001, interfaces=("audio", "hid"), serial="C1")
    assert rec.state == "denied"
    assert rec.matched_rule == "deny-hid"
    assert rec.prompt is False
    assert a.stats()["denied"] == 1
    audio_only = insert(a, vid=0x1234, pid=0x0001, interfaces=("audio",), serial="C2")
    assert audio_only.state == "pending"


def test_allow_rule_scoped_interfaces_requires_full_cover():
    a = auth()
    a.add_rule("allow-storage-hid", vid=0x1111, decision="allow",
               interfaces=("hid", "storage"))
    partial = insert(a, vid=0x1111, pid=0x0002, interfaces=("hid", "network"), serial="D1")
    assert partial.state == "pending"
    full = insert(a, vid=0x1111, pid=0x0002, interfaces=("storage", "hid"), serial="D2")
    assert full.state == "authorized"
    assert full.matched_rule == "allow-storage-hid"
    assert full.interfaces == ("hid", "storage")


def test_serial_rule_beats_generic_deny():
    a = auth()
    a.add_rule("deny-model", vid=0x2222, pid=0x0003, decision="deny")
    a.add_rule("allow-one", vid=0x2222, pid=0x0003, serial="S1", decision="allow")
    allowed = insert(a, vid=0x2222, pid=0x0003, serial="S1")
    blocked = insert(a, vid=0x2222, pid=0x0003, serial="S2")
    assert (allowed.state, allowed.matched_rule) == ("authorized", "allow-one")
    assert (blocked.state, blocked.matched_rule) == ("denied", "deny-model")


def test_authorize_sets_expiry_and_expire_revokes():
    a = auth()
    rec = insert(a)
    temp = a.authorize(rec.fingerprint, ttl=60, now=T0)
    assert temp.state == "temp"
    assert temp.expires_at == T60
    early = a.expire(now=T59)
    assert (early.revoked, early.handles_closed) == (0, 0)
    assert a.devices()[0].state == "temp"
    late = a.expire(now=T60)
    assert (late.revoked, late.handles_closed) == (1, 0)
    assert a.devices()[0].state == "expired"
    assert a.stats()["expired"] == 1


def test_expire_closes_open_handles():
    a = auth()
    rec = insert(a)
    a.authorize(rec.fingerprint, ttl=60, now=T0)
    assert a.attach(rec.fingerprint, "h-1") == 1
    assert a.attach(rec.fingerprint, "h-2") == 2
    report = a.expire(now=T60)
    assert (report.revoked, report.handles_closed) == (1, 2)
    assert a.handles(rec.fingerprint) == 0
    with pytest.raises(uda.UsbError) as exc:
        a.attach(rec.fingerprint, "h-3")
    assert exc.value.code == "USB_NOT_AUTHORIZED"


def test_authorize_persistent_has_no_expiry():
    a = auth()
    rec = insert(a)
    granted = a.authorize(rec.fingerprint, now=T0)
    assert (granted.state, granted.expires_at, granted.prompt) == ("authorized", None, False)
    assert a.expire(now=LATER).revoked == 0
    assert a.devices()[0].state == "authorized"


def test_revoke_closes_handles_and_stays_revoked():
    a = auth()
    rec = insert(a)
    a.authorize(rec.fingerprint, now=T0)
    a.attach(rec.fingerprint, "h-1")
    a.attach(rec.fingerprint, "h-2")
    assert a.revoke(rec.fingerprint) == 2
    assert a.revoke(rec.fingerprint) == 0
    again = insert(a)
    assert (again.state, again.prompt) == ("revoked", False)
    assert a.handles(rec.fingerprint) == 0
    assert a.stats()["revoked"] == 1


def test_remove_rule_only_affects_new_inserts():
    a = auth()
    a.add_rule("allow-model", vid=0x3333, pid=0x0004, decision="allow")
    first = insert(a, vid=0x3333, pid=0x0004, serial="E1")
    assert first.state == "authorized"
    assert a.remove_rule("allow-model") is True
    assert a.remove_rule("allow-model") is False
    assert a.devices()[0].state == "authorized"
    second = insert(a, vid=0x3333, pid=0x0004, serial="E2")
    assert second.state == "pending"


def test_fingerprint_stable_for_serial_device():
    a = auth()
    one = insert(a, serial="K1", port_path="1-1")
    moved = insert(a, serial="K1", port_path="1-9")
    other = insert(a, serial="K2", port_path="1-1")
    assert one.fingerprint == moved.fingerprint
    assert other.fingerprint != one.fingerprint
    assert len(a.devices()) == 2
    assert a.stats()["prompts"] == 2


def test_serialless_fingerprint_stable_on_same_port():
    a = auth()
    one = insert(a, serial=None, port_path="2-1")
    two = insert(a, serial=None, port_path="2-1")
    assert one.fingerprint == two.fingerprint
    assert len(a.devices()) == 1
    assert a.stats()["prompts"] == 1
    assert a.stats()["deduped"] == 1


def test_snapshot_restore_keeps_authorization_without_prompt():
    a = auth()
    a.add_rule("allow-hub", vid=0x4444, pid=0x0005, decision="allow")
    rec = insert(a, vid=0x4444, pid=0x0005, serial="F1")
    state = a.snapshot()
    clone = auth()
    clone.restore(state)
    again = clone.on_insert(vid=0x4444, pid=0x0005, interfaces=("hid",),
                            port_path="1-1", serial="F1", now=T0)
    assert (again.state, again.prompt) == ("authorized", False)
    assert again.fingerprint == rec.fingerprint
    assert len(clone.devices()) == 1
    assert clone.stats()["prompts"] == 0


def test_restore_rejects_malformed_state():
    a = auth()
    rec = insert(a)
    for bad in (None, {}, "nope"):
        with pytest.raises(uda.UsbError) as exc:
            a.restore(bad)
        assert exc.value.code == "USB_SNAPSHOT_INVALID"
    assert len(a.devices()) == 1
    assert a.devices()[0].fingerprint == rec.fingerprint


def test_status_and_stats_lifecycle():
    a = auth()
    a.add_rule("allow-hid", vid=0x046D, pid=0xC52B, decision="allow")
    insert(a)
    insert(a)
    pending = insert(a, vid=0x1234, pid=0x0001, interfaces=("audio",), serial="S2")
    assert pending.prompt is True
    a.authorize(pending.fingerprint, ttl=60, now=T0)
    a.attach(pending.fingerprint, "h1")
    a.attach(pending.fingerprint, "h2")
    report = a.expire(now=T60)
    assert (report.revoked, report.handles_closed) == (1, 2)
    assert a.status()["devices"] == 2
    assert a.status()["authorized"] == 1
    assert a.status()["expired"] == 1
    assert a.status()["handles"] == 0
    assert a.status()["rules"] == 1
    assert a.stats() == {
        "inserts": 3,
        "deduped": 1,
        "prompts": 1,
        "authorized": 2,
        "denied": 0,
        "revoked": 0,
        "expired": 1,
        "handles_opened": 2,
    }
