import dataclasses

import pytest

import luks_keyslot_guard as lk

NOW = "2026-11-26T09:00:00+00:00"
LATER = "2026-11-26T09:10:00+00:00"
EXPIRED = "2026-11-26T09:05:01+00:00"


def guard(**kwargs):
    return lk.LuksKeyslotGuard(**kwargs)


def volume(g, *, vid="vol1", uuid="1111-2222-3333", path="/dev/sda3"):
    return g.register_volume(vid, uuid=uuid, device_path=path, now=NOW)


def test_register_volume_records_identity():
    g = guard()
    info = volume(g)
    assert info.volume_id == "vol1"
    assert info.uuid == "1111-2222-3333"
    assert info.device_path == "/dev/sda3"
    assert info.header_version == 1
    assert info.slots == ()
    assert g.keyslots("vol1") == []


def test_duplicate_volume_rejected():
    g = guard()
    volume(g)
    with pytest.raises(lk.KeyslotError) as exc:
        g.register_volume("vol1", uuid="9999", device_path="/dev/sdb1", now=LATER)
    assert exc.value.code == "KEYSLOT_DUPLICATE_VOLUME"


def test_unknown_volume_rejected():
    g = guard()
    with pytest.raises(lk.KeyslotError) as exc:
        g.add_key("missing", passphrase="pw", now=NOW)
    assert exc.value.code == "KEYSLOT_UNKNOWN_VOLUME"
    with pytest.raises(lk.KeyslotError) as second:
        g.keyslots("missing")
    assert second.value.code == "KEYSLOT_UNKNOWN_VOLUME"


def test_add_key_uses_lowest_free_slot():
    g = guard()
    volume(g)
    first = g.add_key("vol1", passphrase="alpha", label="ops", now=NOW)
    second = g.add_key("vol1", passphrase="beta", now=LATER)
    third = g.add_key("vol1", passphrase="gamma", now=LATER)
    assert (first.slot, second.slot, third.slot) == (0, 1, 2)
    assert first.key_type == "luks2"
    assert first.label == "ops"
    assert [s.slot for s in g.keyslots("vol1")] == [0, 1, 2]


def test_duplicate_passphrase_rejected():
    g = guard()
    volume(g)
    g.add_key("vol1", passphrase="same", now=NOW)
    with pytest.raises(lk.KeyslotError) as exc:
        g.add_key("vol1", passphrase="same", now=LATER)
    assert exc.value.code == "KEYSLOT_DUPLICATE_KEY"
    assert len(g.keyslots("vol1")) == 1


def test_slot_exhaustion_rejected():
    g = guard(max_slots=2)
    volume(g)
    g.add_key("vol1", passphrase="one", now=NOW)
    g.add_key("vol1", passphrase="two", now=NOW)
    with pytest.raises(lk.KeyslotError) as exc:
        g.add_key("vol1", passphrase="three", now=NOW)
    assert exc.value.code == "KEYSLOT_EXHAUSTED"
    assert [s.slot for s in g.keyslots("vol1")] == [0, 1]


def test_change_key_rejects_wrong_old_passphrase():
    g = guard()
    volume(g)
    g.add_key("vol1", passphrase="old", now=NOW)
    with pytest.raises(lk.KeyslotError) as exc:
        g.change_key("vol1", slot=0, old_passphrase="nope",
                     new_passphrase="fresh", now=LATER)
    assert exc.value.code == "KEYSLOT_WRONG_PASSPHRASE"
    assert [s.slot for s in g.keyslots("vol1")] == [0]


def test_change_key_writes_new_slot_then_drops_old():
    g = guard()
    volume(g)
    g.add_key("vol1", passphrase="old", label="ops", now=NOW)
    created = g.change_key("vol1", slot=0, old_passphrase="old",
                           new_passphrase="fresh", now=LATER)
    assert created.slot == 1
    assert created.key_type == "luks2"
    assert len(created.fingerprint) == 64
    assert "fresh" not in created.fingerprint
    assert [s.slot for s in g.keyslots("vol1")] == [1]


def test_remove_key_checks_passphrase():
    g = guard()
    volume(g)
    g.add_key("vol1", passphrase="keep", now=NOW)
    g.add_key("vol1", passphrase="drop", label="old", now=NOW)
    with pytest.raises(lk.KeyslotError) as exc:
        g.remove_key("vol1", slot=1, passphrase="bad", now=LATER)
    assert exc.value.code == "KEYSLOT_WRONG_PASSPHRASE"
    assert len(g.keyslots("vol1")) == 2
    remaining = g.remove_key("vol1", slot=1, passphrase="drop", now=LATER)
    assert remaining == 1
    assert [s.slot for s in g.keyslots("vol1")] == [0]


def test_invalid_slot_rejected():
    g = guard()
    volume(g)
    g.add_key("vol1", passphrase="one", now=NOW)
    with pytest.raises(lk.KeyslotError) as exc:
        g.remove_key("vol1", slot=6, passphrase="one", now=LATER)
    assert exc.value.code == "KEYSLOT_INVALID_SLOT"


def test_backup_header_carries_version_and_checksum():
    g = guard()
    volume(g)
    backup = g.backup_header("vol1", now=NOW)
    assert backup.volume_id == "vol1"
    assert backup.uuid == "1111-2222-3333"
    assert backup.version == 1
    assert len(backup.checksum) == 64
    assert g.verify_header("vol1", backup) is True


def test_restore_rejects_stale_backup():
    g = guard()
    volume(g)
    backup = g.backup_header("vol1", now=NOW)
    g.add_key("vol1", passphrase="later", now=LATER)
    with pytest.raises(lk.KeyslotError) as exc:
        g.restore_header("vol1", backup, now=LATER)
    assert exc.value.code == "KEYSLOT_BACKUP_STALE"
    assert len(g.keyslots("vol1")) == 1


def test_restore_rejects_corrupt_backup():
    g = guard()
    volume(g)
    backup = g.backup_header("vol1", now=NOW)
    tampered = dataclasses.replace(backup, payload=backup.payload + "x")
    with pytest.raises(lk.KeyslotError) as exc:
        g.restore_header("vol1", tampered, now=NOW)
    assert exc.value.code == "KEYSLOT_BACKUP_CORRUPT"


def test_audit_log_records_actions_in_order():
    g = guard()
    volume(g)
    g.add_key("vol1", passphrase="one", now=NOW)
    g.backup_header("vol1", now=LATER)
    log = g.audit_log("vol1")
    assert [entry["action"] for entry in log] == ["register", "add_key", "backup"]
    assert log[1]["slot"] == 0
    assert log[1]["result"] == "ok"
    assert all(entry["at"] for entry in log)


def test_snapshot_roundtrip_and_invalid_state():
    g = guard()
    volume(g)
    g.add_key("vol1", passphrase="one", label="ops", now=NOW)
    g.backup_header("vol1", now=LATER)
    state = g.snapshot()
    clone = guard()
    clone.restore(state)
    assert [s.slot for s in clone.keyslots("vol1")] == [0]
    assert clone.keyslots("vol1")[0].label == "ops"
    assert clone.stats()["volumes"] == 1
    with pytest.raises(lk.KeyslotError) as exc:
        clone.restore({"bogus": True})
    assert exc.value.code == "KEYSLOT_SNAPSHOT_INVALID"
    assert len(clone.keyslots("vol1")) == 1
