import pytest

import account_db_transaction as adb

NOW = "2026-11-26T09:00:00+00:00"
LATER = "2026-11-26T09:30:00+00:00"

BASE_FILES = {
    "passwd": (
        "root:x:0:0:root:/root:/bin/bash\n"
        "alice:x:1000:1000::/home/alice:/bin/bash\n"
    ),
    "shadow": (
        "root:!:19000:0:99999:7:::\n"
        "alice:!:19000:0:99999:7:::\n"
    ),
    "group": (
        "root:x:0:\n"
        "alice:x:1000:\n"
        "staff:x:2000:alice\n"
    ),
    "gshadow": (
        "root:!::\n"
        "alice:!::\n"
        "staff:!::alice\n"
    ),
}


def database(**kwargs):
    db = adb.AccountDbTransaction(**kwargs)
    db.load(BASE_FILES)
    return db


def change(kind, name, **fields):
    return adb.AccountChange(kind=kind, name=name, fields=dict(fields))


def test_load_parses_all_four_files():
    db = adb.AccountDbTransaction()
    counts = db.load(BASE_FILES)
    assert counts == {"passwd": 2, "shadow": 2, "group": 3, "gshadow": 3}
    users = db.users()
    assert [u["name"] for u in users] == ["alice", "root"]
    assert users[0]["uid"] == 1000
    assert users[0]["gid"] == 1000
    assert users[0]["shell"] == "/bin/bash"
    groups = db.groups()
    assert [g["name"] for g in groups] == ["alice", "root", "staff"]
    staff = [g for g in groups if g["name"] == "staff"][0]
    assert staff["gid"] == 2000
    assert staff["members"] == ("alice",)


def test_plan_records_files_version_and_lock_order():
    db = database()
    plan = db.plan([change("add_user", "bob", shell="/bin/zsh")])
    assert plan.files == ("passwd", "shadow", "group", "gshadow")
    assert plan.lock_order == ("passwd", "shadow", "group", "gshadow")
    assert plan.version == 1
    assert plan.changes[0].name == "bob"
    assert db.stats()["plans"] == 1


def test_plan_rejects_unknown_kind():
    db = database()
    with pytest.raises(adb.AccountDbError) as exc:
        db.plan([change("rename_user", "alice")])
    assert exc.value.code == "ACCOUNTDB_INVALID_CHANGE"


def test_apply_add_user_writes_all_files():
    db = database()
    plan = db.plan([change("add_user", "bob", shell="/bin/zsh")])
    result = db.apply(plan.plan_id, now=NOW)
    assert result.files_written == ("passwd", "shadow", "group", "gshadow")
    assert result.cache_invalidated == 4
    assert result.version == 1
    assert result.committed_at == NOW
    files = db.files()
    assert "bob:x:1001:1001:" in files["passwd"]
    bob = [u for u in db.users() if u["name"] == "bob"][0]
    assert bob["uid"] == 1001
    assert bob["gid"] == 1001
    assert bob["shell"] == "/bin/zsh"
    assert "bob:!:" in files["shadow"]
    assert "bob:x:1001:" in files["group"]
    assert "bob:!::" in files["gshadow"]


def test_allocate_uid_skips_used_numbers():
    db = adb.AccountDbTransaction()
    db.load({
        "passwd": (
            "alice:x:1000:1000::/home/alice:/bin/bash\n"
            "bob:x:1001:1001::/home/bob:/bin/bash\n"
            "dave:x:1003:1003::/home/dave:/bin/bash\n"
        ),
        "shadow": (
            "alice:!:19000:0:99999:7:::\n"
            "bob:!:19000:0:99999:7:::\n"
            "dave:!:19000:0:99999:7:::\n"
        ),
        "group": "alice:x:1000:\nbob:x:1001:\ndave:x:1003:\n",
        "gshadow": "alice:!::\nbob:!::\ndave:!::\n",
    })
    assert db.allocate_uid("erin") == 1002
    assert db.allocate_gid("erin") == 1002


def test_allocate_uid_exhaustion_rejected():
    db = adb.AccountDbTransaction(uid_floor=1000, uid_ceiling=1001)
    db.load({
        "passwd": "alice:x:1000:1000::/home/alice:/bin/bash\n",
        "shadow": "alice:!:19000:0:99999:7:::\n",
        "group": "alice:x:1000:\n",
        "gshadow": "alice:!::\n",
    })
    with pytest.raises(adb.AccountDbError) as exc:
        db.allocate_uid("bob")
    assert exc.value.code == "ACCOUNTDB_UID_EXHAUSTED"


def test_duplicate_uid_rejected_by_verify_and_apply():
    duplicated = dict(BASE_FILES)
    duplicated["passwd"] = BASE_FILES["passwd"] + "bob:x:1000:1000::/home/bob:/bin/bash\n"
    duplicated["shadow"] = BASE_FILES["shadow"] + "bob:!:19000:0:99999:7:::\n"
    duplicated["group"] = BASE_FILES["group"] + "bob:x:1001:\n"
    duplicated["gshadow"] = BASE_FILES["gshadow"] + "bob:!::\n"
    db = adb.AccountDbTransaction()
    db.load(duplicated)
    report = db.verify()
    assert report.ok is False
    assert report.duplicate_uids == ("alice", "bob")
    before = db.files()
    plan = db.plan([change("add_user", "carol")])
    with pytest.raises(adb.AccountDbError) as exc:
        db.apply(plan.plan_id, now=NOW)
    assert exc.value.code == "ACCOUNTDB_DUPLICATE_UID"
    assert db.files() == before


def test_dangling_gid_rejected():
    dangling = dict(BASE_FILES)
    dangling["passwd"] = BASE_FILES["passwd"] + "bob:x:1001:4242::/home/bob:/bin/bash\n"
    dangling["shadow"] = BASE_FILES["shadow"] + "bob:!:19000:0:99999:7:::\n"
    dangling["group"] = BASE_FILES["group"] + "bob:x:1001:\n"
    dangling["gshadow"] = BASE_FILES["gshadow"] + "bob:!::\n"
    db = adb.AccountDbTransaction()
    db.load(dangling)
    assert db.verify().dangling_gids == ("bob",)
    before = db.files()
    plan = db.plan([change("add_user", "carol")])
    with pytest.raises(adb.AccountDbError) as exc:
        db.apply(plan.plan_id, now=NOW)
    assert exc.value.code == "ACCOUNTDB_DANGLING_GID"
    assert db.files() == before


def test_delete_user_removes_private_group_and_membership():
    db = database()
    plan = db.plan([change("delete_user", "alice")])
    db.apply(plan.plan_id, now=NOW)
    assert [u["name"] for u in db.users()] == ["root"]
    assert "alice" not in db.files()["passwd"]
    assert "alice" not in db.files()["shadow"]
    assert not any(line.startswith("alice:") for line in db.files()["group"].splitlines())
    staff = [g for g in db.groups() if g["name"] == "staff"][0]
    assert staff["members"] == ()


def test_duplicate_name_in_one_plan_rejected_atomically():
    db = database()
    before = db.files()
    plan = db.plan([change("add_user", "bob"), change("add_user", "bob")])
    with pytest.raises(adb.AccountDbError) as exc:
        db.apply(plan.plan_id, now=NOW)
    assert exc.value.code == "ACCOUNTDB_DUPLICATE_NAME"
    assert db.files() == before
    assert db.stats()["commits"] == 0


def test_unknown_plan_rejected():
    db = database()
    with pytest.raises(adb.AccountDbError) as exc:
        db.apply("no-such-plan", now=NOW)
    assert exc.value.code == "ACCOUNTDB_PLAN_UNKNOWN"


def test_apply_twice_rejected():
    db = database()
    plan = db.plan([change("add_user", "bob")])
    db.apply(plan.plan_id, now=NOW)
    with pytest.raises(adb.AccountDbError) as exc:
        db.apply(plan.plan_id, now=LATER)
    assert exc.value.code == "ACCOUNTDB_PLAN_APPLIED"


def test_rollback_restores_previous_files():
    db = database()
    before = db.files()
    plan = db.plan([change("set_shell", "alice", shell="/bin/zsh")])
    db.apply(plan.plan_id, now=NOW)
    assert "/bin/zsh" in db.files()["passwd"]
    assert db.rollback(plan.plan_id, now=LATER) == 1
    assert db.files() == before
    assert db.stats()["rollbacks"] == 1


def test_snapshot_roundtrip_and_invalid_state():
    db = database()
    plan = db.plan([change("add_user", "bob")])
    db.apply(plan.plan_id, now=NOW)
    state = db.snapshot()
    clone = adb.AccountDbTransaction()
    clone.restore(state)
    assert clone.files() == db.files()
    assert [u["name"] for u in clone.users()] == ["alice", "bob", "root"]
    assert clone.stats()["commits"] == 1
    with pytest.raises(adb.AccountDbError) as exc:
        clone.restore({"bogus": True})
    assert exc.value.code == "ACCOUNTDB_SNAPSHOT_INVALID"
    assert clone.files() == db.files()


def test_cache_invalidation_follows_touched_files():
    db = database()
    first = db.plan([change("set_shell", "alice", shell="/bin/zsh")])
    assert first.files == ("passwd",)
    result = db.apply(first.plan_id, now=NOW)
    assert result.cache_invalidated == 1
    assert db.stats()["cache_invalidations"] == 1
    second = db.plan([change("add_user", "bob")])
    again = db.apply(second.plan_id, now=LATER)
    assert again.cache_invalidated == 4
    assert db.stats()["cache_invalidations"] == 5
