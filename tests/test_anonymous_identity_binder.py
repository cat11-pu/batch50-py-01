import copy
import re

import pytest

import anonymous_identity_binder as ab

NOW = "2026-11-26T09:00:00+00:00"


def binder(**kwargs):
    return ab.AnonymousIdentityBinder(**kwargs)


def seed_account(store, account_id="acc"):
    holder = store.create_anon(device_id="seed-device", now=NOW)
    store.attach_resource(holder.anon_id, kind="cart", key="sku2",
                          value="blue", now=NOW)
    store.attach_resource(holder.anon_id, kind="preference", key="theme",
                          value="dark", now=NOW)
    store.bind_to_account(holder.anon_id, account_id=account_id, now=NOW)


def by_key(rows):
    return {(row["kind"], row["key"]): row for row in rows}


def test_create_anon_returns_active_session():
    store = binder()
    session = store.create_anon(device_id="device-1", now=NOW)
    assert re.fullmatch(r"anon_[0-9a-f]{12}", session.anon_id)
    assert session.device_id == "device-1"
    assert session.state == "active"
    assert session.created_at == NOW
    assert session.resource_count == 0
    assert store.list_anonymous() == [session.anon_id]


def test_create_anon_rejects_blank_device():
    store = binder()
    for device in ["", "   ", None]:
        with pytest.raises(ab.AnonymousBindError) as exc:
            store.create_anon(device_id=device, now=NOW)
        assert exc.value.code == "ANON_INVALID_REQUEST"


def test_attach_resource_sorts_and_counts():
    store = binder()
    session = store.create_anon(device_id="device-1", now=NOW)
    first = store.attach_resource(session.anon_id, kind="draft", key="note",
                                  value="hello", now=NOW)
    second = store.attach_resource(session.anon_id, kind="cart", key="sku1",
                                   value="red", now=NOW)
    assert first["revision"] == 1
    assert second["revision"] == 1
    rows = store.anon_resources(session.anon_id)
    assert [(row["kind"], row["key"]) for row in rows] == [
        ("cart", "sku1"), ("draft", "note")]
    assert store.status(session.anon_id)["resource_count"] == 2


def test_attach_same_key_updates_revision():
    store = binder()
    session = store.create_anon(device_id="device-1", now=NOW)
    store.attach_resource(session.anon_id, kind="preference", key="theme",
                          value="light", now=NOW)
    updated = store.attach_resource(session.anon_id, kind="preference",
                                    key="theme", value="dark", now=NOW)
    assert updated["revision"] == 2
    assert updated["value"] == "dark"
    rows = store.anon_resources(session.anon_id)
    assert len(rows) == 1
    assert rows[0]["revision"] == 2


def test_attach_resource_validates_kind_and_text_fields():
    store = binder()
    session = store.create_anon(device_id="device-1", now=NOW)
    with pytest.raises(ab.AnonymousBindError) as exc:
        store.attach_resource(session.anon_id, kind="session", key="k",
                              value="v", now=NOW)
    assert exc.value.code == "ANON_BAD_KIND"
    for key, value in [("", "v"), ("k", "  ")]:
        with pytest.raises(ab.AnonymousBindError) as exc:
            store.attach_resource(session.anon_id, kind="cart", key=key,
                                  value=value, now=NOW)
        assert exc.value.code == "ANON_INVALID_REQUEST"


def test_resource_cap_counts_distinct_keys_only():
    store = binder(max_resources_per_anon=2)
    session = store.create_anon(device_id="device-1", now=NOW)
    store.attach_resource(session.anon_id, kind="cart", key="a", value="1",
                          now=NOW)
    store.attach_resource(session.anon_id, kind="cart", key="b", value="2",
                          now=NOW)
    with pytest.raises(ab.AnonymousBindError) as exc:
        store.attach_resource(session.anon_id, kind="draft", key="c",
                              value="3", now=NOW)
    assert exc.value.code == "ANON_RESOURCE_LIMIT"
    again = store.attach_resource(session.anon_id, kind="cart", key="a",
                                  value="9", now=NOW)
    assert again["revision"] == 2


def test_detach_resource_is_idempotent_for_missing_key():
    store = binder()
    session = store.create_anon(device_id="device-1", now=NOW)
    store.attach_resource(session.anon_id, kind="cart", key="sku1",
                          value="red", now=NOW)
    store.attach_resource(session.anon_id, kind="draft", key="note",
                          value="hello", now=NOW)
    assert store.detach_resource(session.anon_id, kind="cart", key="sku1") is True
    assert store.status(session.anon_id)["resource_count"] == 1
    assert store.detach_resource(session.anon_id, kind="cart", key="sku1") is False
    with pytest.raises(ab.AnonymousBindError) as exc:
        store.detach_resource("anon_ffffffffffff", kind="cart", key="sku1")
    assert exc.value.code == "ANON_UNKNOWN"


def test_merge_state_is_preview_only():
    store = binder()
    seed_account(store)
    session = store.create_anon(device_id="device-2", now=NOW)
    store.attach_resource(session.anon_id, kind="preference", key="theme",
                          value="light", now=NOW)
    store.attach_resource(session.anon_id, kind="cart", key="sku1",
                          value="red", now=NOW)
    store.attach_resource(session.anon_id, kind="draft", key="note",
                          value="hello", now=NOW)
    preview = store.merge_state(session.anon_id, account_id="acc", now=NOW)
    assert preview["migrated"] == 3
    assert preview["added"] == 2
    assert preview["conflicts"] == 1
    assert preview["overwritten"] == 0
    assert preview["keys"] == ["cart:sku1", "cart:sku2", "draft:note",
                               "preference:theme"]
    assert store.status(session.anon_id)["state"] == "active"
    assert store.status(session.anon_id)["resource_count"] == 3
    assert len(store.account_resources("acc")) == 2


def test_bind_migrates_resources_and_closes_anon_session():
    store = binder()
    seed_account(store)
    session = store.create_anon(device_id="device-2", now=NOW)
    store.attach_resource(session.anon_id, kind="preference", key="theme",
                          value="light", now=NOW)
    store.attach_resource(session.anon_id, kind="cart", key="sku1",
                          value="red", now=NOW)
    store.attach_resource(session.anon_id, kind="draft", key="note",
                          value="hello", now=NOW)
    result = store.bind_to_account(session.anon_id, account_id="acc", now=NOW)
    assert re.fullmatch(r"bind_[0-9a-f]{12}", result.bind_id)
    assert result.status == "bound"
    assert result.migrated == 3
    assert result.added == 2
    assert result.conflicts == 1
    assert result.overwritten == 0
    assert result.bound_at == NOW
    record = store.status(session.anon_id)
    assert record["state"] == "bound"
    assert record["account_id"] == "acc"
    assert record["resource_count"] == 0
    assert store.anon_resources(session.anon_id) == []
    rows = by_key(store.account_resources("acc"))
    assert len(rows) == 4
    assert rows[("cart", "sku1")]["value"] == "red"
    assert rows[("draft", "note")]["value"] == "hello"


def test_bind_validates_identifiers():
    store = binder()
    session = store.create_anon(device_id="device-1", now=NOW)
    with pytest.raises(ab.AnonymousBindError) as exc:
        store.bind_to_account("anon_ffffffffffff", account_id="acc", now=NOW)
    assert exc.value.code == "ANON_UNKNOWN"
    with pytest.raises(ab.AnonymousBindError) as exc:
        store.bind_to_account(session.anon_id, account_id="  ", now=NOW)
    assert exc.value.code == "ANON_INVALID_REQUEST"


def test_frozen_account_keeps_both_sides_untouched():
    store = binder()
    session = store.create_anon(device_id="device-1", now=NOW)
    store.attach_resource(session.anon_id, kind="cart", key="sku1",
                          value="red", now=NOW)
    store.attach_resource(session.anon_id, kind="draft", key="note",
                          value="hello", now=NOW)
    store.freeze_account("acc")
    with pytest.raises(ab.AnonymousBindError) as exc:
        store.bind_to_account(session.anon_id, account_id="acc", now=NOW)
    assert exc.value.code == "ANON_ACCOUNT_FROZEN"
    record = store.status(session.anon_id)
    assert record["state"] == "active"
    assert record["resource_count"] == 2
    assert store.anon_resources(session.anon_id)[0]["value"] == "red"
    assert store.account_resources("acc") == []


def test_rollback_restores_anon_and_clears_added_account_keys():
    store = binder()
    session = store.create_anon(device_id="device-1", now=NOW)
    store.attach_resource(session.anon_id, kind="cart", key="sku1",
                          value="red", now=NOW)
    store.attach_resource(session.anon_id, kind="draft", key="note",
                          value="hello", now=NOW)
    result = store.bind_to_account(session.anon_id, account_id="acc", now=NOW)
    undone = store.rollback("acc", now=NOW)
    assert undone["bind_id"] == result.bind_id
    assert undone["anon_id"] == session.anon_id
    assert undone["restored"] == 2
    assert store.account_resources("acc") == []
    record = store.status(session.anon_id)
    assert record["state"] == "active"
    assert record["account_id"] is None
    assert record["resource_count"] == 2
    assert {row["key"] for row in store.anon_resources(session.anon_id)} == {
        "sku1", "note"}
    again = store.bind_to_account(session.anon_id, account_id="acc2", now=NOW)
    assert again.status == "bound"


def test_rollback_without_bind_is_refused():
    store = binder()
    with pytest.raises(ab.AnonymousBindError) as exc:
        store.rollback("acc", now=NOW)
    assert exc.value.code == "ANON_ROLLBACK_UNAVAILABLE"


def test_snapshot_is_detached_and_restore_roundtrips():
    store = binder()
    session = store.create_anon(device_id="device-1", now=NOW)
    store.attach_resource(session.anon_id, kind="cart", key="sku1",
                          value="red", now=NOW)
    store.bind_to_account(session.anon_id, account_id="acc", now=NOW)
    idle = store.create_anon(device_id="device-2", now=NOW)
    store.attach_resource(idle.anon_id, kind="draft", key="note",
                          value="hello", now=NOW)
    state = store.snapshot()
    pristine = copy.deepcopy(state)
    assert set(state) == {"version", "anonymous", "accounts", "binds", "stats"}
    state["anonymous"].clear()
    state["accounts"].clear()
    state["stats"]["bound"] = 99
    assert store.status(session.anon_id)["state"] == "bound"
    assert store.status(idle.anon_id)["state"] == "active"
    assert store.stats()["bound"] == 1

    clone = binder()
    clone.restore(pristine)
    assert clone.status(session.anon_id)["state"] == "bound"
    assert len(clone.account_resources("acc")) == 1
    assert clone.status(idle.anon_id)["resource_count"] == 1
    assert clone.stats()["bound"] == 1

    live = clone.snapshot()
    for bad in [None, {}, {"version": 2, "anonymous": {}, "accounts": {},
                           "binds": [], "stats": {}},
                {"version": 1, "anonymous": "nope", "accounts": {},
                 "binds": [], "stats": {}},
                {"version": 1, "anonymous": {}, "accounts": [],
                 "binds": [], "stats": {}},
                {"version": 1, "anonymous": {}, "accounts": {},
                 "binds": [], "stats": {"bound": 1}}]:
        with pytest.raises(ab.AnonymousBindError) as exc:
            clone.restore(bad)
        assert exc.value.code == "ANON_SNAPSHOT_INVALID"
    assert clone.snapshot() == live


def test_stats_track_creates_mounts_binds_and_rollbacks():
    store = binder()
    first = store.create_anon(device_id="device-1", now=NOW)
    store.attach_resource(first.anon_id, kind="preference", key="theme",
                          value="light", now=NOW)
    store.bind_to_account(first.anon_id, account_id="acc", now=NOW)
    second = store.create_anon(device_id="device-2", now=NOW)
    store.attach_resource(second.anon_id, kind="preference", key="theme",
                          value="dark", now=NOW)
    store.attach_resource(second.anon_id, kind="draft", key="note",
                          value="hello", now=NOW)
    store.bind_to_account(second.anon_id, account_id="acc", now=NOW)
    store.rollback("acc", now=NOW)
    assert store.stats() == {"anonymous_created": 2, "resources_attached": 3,
                             "bound": 2, "rolled_back": 1, "conflicts": 1}
