import pytest

import fscrypt_policy_warden as fp


def make(**kwargs):
    warden = fp.FscryptPolicyWarden(**kwargs)
    warden.mkdir("/vol")
    return warden


def with_policy(**kwargs):
    warden = make(**kwargs)
    warden.set_policy("/vol", mode="aes256-cts", key_desc="k1")
    return warden


def unlocked(**kwargs):
    warden = with_policy(**kwargs)
    warden.add_key("k1", policy_id="pol-1")
    warden.unlock("/vol", "k1")
    return warden


def test_set_policy_records_identity_and_initial_state():
    warden = make()
    record = warden.set_policy("/vol", mode="aes256-cts", key_desc="k1")
    assert record.path == "/vol"
    assert record.policy_id == "pol-1"
    assert record.mode == "aes256-cts"
    assert record.key_desc == "k1"
    assert record.key_state == "locked"
    assert record.rotation_state == "idle"
    assert record.rotation_pending == 0
    stats = warden.stats()
    assert stats["policies"] == 1
    assert stats["dirs"] == 1
    assert stats["files"] == 0


def test_unsupported_mode_is_refused_before_any_change():
    warden = make()
    with pytest.raises(fp.FscryptError) as err:
        warden.set_policy("/vol", mode="rot13", key_desc="k1")
    assert err.value.code == "FSCRYPT_UNSUPPORTED_MODE"
    assert warden.policies() == []
    assert warden.stats()["denied"] == 1


def test_non_empty_directory_requires_recursive_apply():
    warden = make()
    warden.mkdir("/vol/a")
    warden.register_file("/vol", "x.bin")
    with pytest.raises(fp.FscryptError) as err:
        warden.set_policy("/vol", mode="aes256-cts", key_desc="k1")
    assert err.value.code == "FSCRYPT_DIR_NOT_EMPTY"
    record = warden.set_policy("/vol", mode="aes256-cts", key_desc="k1",
                               recursive=True)
    assert record.path == "/vol"
    assert [item.path for item in warden.policies()] == ["/vol", "/vol/a"]
    assert warden.status("/vol")["files"] == 1


def test_child_inherits_policy_and_may_narrow_mode():
    warden = with_policy()
    warden.mkdir("/vol/a")
    warden.mkdir("/vol/a/b")
    child = warden.set_policy("/vol/a", mode="aes256-cts", key_desc="k1")
    assert child.policy_id == "pol-1"
    narrowed = warden.set_policy("/vol/a/b", mode="aes256-xts", key_desc="k1")
    assert narrowed.policy_id == "pol-1"
    assert narrowed.mode == "aes256-xts"
    assert warden.stats()["policies"] == 3


def test_child_policy_conflicts_are_refused():
    warden = with_policy()
    warden.mkdir("/vol/a")
    with pytest.raises(fp.FscryptError) as err:
        warden.set_policy("/vol/a", mode="aes256-cts", key_desc="k2")
    assert err.value.code == "FSCRYPT_KEY_MISMATCH"
    with pytest.raises(fp.FscryptError) as err:
        warden.set_policy("/vol/a", mode="aes128-cts", key_desc="k1")
    assert err.value.code == "FSCRYPT_MODE_WIDEN"
    with pytest.raises(fp.FscryptError) as err:
        warden.set_policy("/vol/a", mode="aes256-cts", key_desc="k1",
                          policy_id="pol-9")
    assert err.value.code == "FSCRYPT_POLICY_MISMATCH"
    assert warden.stats()["denied"] == 3
    assert [item.path for item in warden.policies()] == ["/vol"]


def test_policy_count_limit_per_volume():
    warden = make(max_policies=2)
    warden.mkdir("/vol/a")
    warden.mkdir("/vol/b")
    warden.set_policy("/vol", mode="aes256-cts", key_desc="k1")
    warden.set_policy("/vol/a", mode="aes256-cts", key_desc="k1")
    with pytest.raises(fp.FscryptError) as err:
        warden.set_policy("/vol/b", mode="aes256-cts", key_desc="k1")
    assert err.value.code == "FSCRYPT_POLICY_LIMIT"
    assert len(warden.policies()) == 2


def test_unlock_requires_registered_key_and_counts_subtree():
    warden = with_policy()
    warden.mkdir("/vol/a")
    warden.set_policy("/vol/a", mode="aes256-cts", key_desc="k1")
    with pytest.raises(fp.FscryptError) as err:
        warden.unlock("/vol", "k1")
    assert err.value.code == "FSCRYPT_KEY_UNAVAILABLE"
    assert warden.status("/vol")["key_state"] == "locked"
    assert warden.add_key("k1", policy_id="pol-1") == 1
    assert warden.unlock("/vol", "k1") == 2
    assert warden.status("/vol/a")["key_state"] == "unlocked"
    assert warden.stats()["unlocked"] == 2


def test_locked_directory_returns_explicit_error():
    warden = unlocked()
    assert warden.write_file("/vol", "a.bin", "payload") == "k1"
    assert warden.read_file("/vol", "a.bin") == "payload"
    assert warden.lock("/vol") == 1
    with pytest.raises(fp.FscryptError) as err:
        warden.read_file("/vol", "a.bin")
    assert err.value.code == "FSCRYPT_LOCKED"
    assert warden.status("/vol")["key_state"] == "locked"


def test_missing_policy_missing_file_and_locked_write():
    warden = make()
    with pytest.raises(fp.FscryptError) as err:
        warden.read_file("/vol", "a.bin")
    assert err.value.code == "FSCRYPT_NO_POLICY"
    opened = unlocked()
    with pytest.raises(fp.FscryptError) as err:
        opened.read_file("/vol", "ghost.bin")
    assert err.value.code == "FSCRYPT_NOT_FOUND"
    opened.lock("/vol")
    with pytest.raises(fp.FscryptError) as err:
        opened.write_file("/vol", "b.bin")
    assert err.value.code == "FSCRYPT_LOCKED"
    assert opened.stats()["files"] == 0


def test_full_rotation_moves_every_file_and_drops_old_key():
    warden = unlocked()
    for name in ("a.bin", "b.bin", "c.bin"):
        warden.write_file("/vol", name)
    plan = warden.rotate("/vol", "k2")
    assert plan["old_key_desc"] == "k1"
    assert plan["new_key_desc"] == "k2"
    assert plan["total"] == 3
    assert plan["pending"] == 0
    assert plan["state"] == "done"
    assert [warden.file_key("/vol", name)
            for name in ("a.bin", "b.bin", "c.bin")] == ["k2", "k2", "k2"]
    assert ("pol-1", "k1") not in warden.keys()
    assert ("pol-1", "k2") in warden.keys()
    assert warden.stats()["rotations_done"] == 1


def test_interrupted_rotation_keeps_old_key_and_resumes():
    warden = unlocked()
    for name in ("a.bin", "b.bin", "c.bin"):
        warden.write_file("/vol", name)
    plan = warden.rotate("/vol", "k2", interrupt_after=1)
    assert plan["state"] == "partial"
    assert plan["total"] == 3
    assert plan["pending"] == 2
    assert warden.file_key("/vol", "a.bin") == "k2"
    assert warden.file_key("/vol", "b.bin") == "k1"
    assert ("pol-1", "k1") in warden.keys()
    assert ("pol-1", "k2") in warden.keys()
    with pytest.raises(fp.FscryptError) as err:
        warden.rotate("/vol", "k3")
    assert err.value.code == "FSCRYPT_ROTATION_BUSY"
    done = warden.resume_rotation("/vol")
    assert done["state"] == "done"
    assert done["pending"] == 0
    assert [warden.file_key("/vol", name)
            for name in ("a.bin", "b.bin", "c.bin")] == ["k2", "k2", "k2"]
    assert ("pol-1", "k1") not in warden.keys()
    assert warden.stats()["rotations_done"] == 1


def test_rotation_guards_reject_locked_and_same_key():
    warden = with_policy()
    with pytest.raises(fp.FscryptError) as err:
        warden.rotate("/vol", "k2")
    assert err.value.code == "FSCRYPT_LOCKED"
    warden.add_key("k1", policy_id="pol-1")
    warden.unlock("/vol", "k1")
    with pytest.raises(fp.FscryptError) as err:
        warden.rotate("/vol", "k1")
    assert err.value.code == "FSCRYPT_BAD_ROTATION"
    warden.mkdir("/vol/plain")
    with pytest.raises(fp.FscryptError) as err:
        warden.rotate("/vol/plain", "k2")
    assert err.value.code == "FSCRYPT_NO_POLICY"


def test_key_slots_are_capped_and_keys_in_use_cannot_go():
    warden = with_policy(key_slots=2)
    assert warden.add_key("k1", policy_id="pol-1") == 1
    assert warden.add_key("k9", policy_id="pol-1") == 2
    with pytest.raises(fp.FscryptError) as err:
        warden.add_key("k8", policy_id="pol-1")
    assert err.value.code == "FSCRYPT_KEY_SLOT_EXHAUSTED"
    with pytest.raises(fp.FscryptError) as err:
        warden.add_key("k1", policy_id="pol-1")
    assert err.value.code == "FSCRYPT_KEY_EXISTS"
    with pytest.raises(fp.FscryptError) as err:
        warden.drop_key("k1", policy_id="pol-1")
    assert err.value.code == "FSCRYPT_KEY_IN_USE"
    assert warden.drop_key("k9", policy_id="pol-1") == 1
    assert warden.keys() == (("pol-1", "k1"),)


def test_snapshot_round_trips_partial_rotation():
    warden = unlocked()
    for name in ("a.bin", "b.bin", "c.bin"):
        warden.write_file("/vol", name)
    warden.rotate("/vol", "k2", interrupt_after=1)
    snap = warden.snapshot()
    warden.resume_rotation("/vol")
    assert warden.status("/vol")["rotation_state"] == "done"
    warden.restore(snap)
    assert warden.status("/vol")["rotation_state"] == "partial"
    assert warden.status("/vol")["rotation_pending"] == 2
    assert warden.file_key("/vol", "a.bin") == "k2"
    assert warden.file_key("/vol", "b.bin") == "k1"
    assert ("pol-1", "k1") in warden.keys()


def test_invalid_snapshot_leaves_state_untouched():
    warden = unlocked()
    warden.write_file("/vol", "a.bin", "x")
    before = warden.stats()
    with pytest.raises(fp.FscryptError) as err:
        warden.restore({"policies": "not-a-list"})
    assert err.value.code == "FSCRYPT_SNAPSHOT_INVALID"
    assert warden.stats() == before
    assert warden.read_file("/vol", "a.bin") == "x"
