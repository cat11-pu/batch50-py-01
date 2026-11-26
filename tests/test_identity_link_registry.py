import copy
from datetime import datetime, timedelta

import pytest

import identity_link_registry as ir

NOW = "2026-11-26T11:00:00+00:00"


def at(seconds):
    return (datetime.fromisoformat(NOW) + timedelta(seconds=seconds)).isoformat()


def registry(**kwargs):
    return ir.IdentityLinkRegistry(**kwargs)


def acct(store, account_id="a1", now=NOW):
    return store.create_account(account_id, now=now)


def link(store, account_id="a1", provider="email", external_id="e1",
         now=NOW):
    return store.link(account_id, provider=provider, external_id=external_id,
                      now=now)


def test_create_account_is_idempotent():
    store = registry()
    first = acct(store)
    assert first.account_id == "a1"
    assert first.state == "active"
    assert first.created_at == NOW
    assert first.link_count == 0
    again = acct(store, now=at(30))
    assert again.created_at == NOW
    assert again.state == "active"
    assert store.stats()["accounts_created"] == 1


def test_create_account_rejects_blank_id():
    store = registry()
    for account_id in ["", "   ", None]:
        with pytest.raises(ir.IdentityLinkError) as exc:
            store.create_account(account_id, now=NOW)
        assert exc.value.code == "IDENTITY_INVALID_REQUEST"


def test_link_records_identity_and_resolves():
    store = registry()
    acct(store)
    record = link(store)
    assert record.account_id == "a1"
    assert record.provider == "email"
    assert record.external_id == "e1"
    assert record.sequence == 1
    assert record.linked_at == NOW
    found = store.resolve("email", "e1")
    assert found == {"account_id": "a1", "provider": "email",
                     "external_id": "e1"}
    status = store.status("a1")
    assert status["link_count"] == 1
    assert status["providers"] == ["email"]
    assert store.stats()["links_created"] == 1


def test_link_rejects_identity_owned_by_another_account():
    store = registry()
    acct(store, "a1")
    acct(store, "a2")
    link(store, "a1", external_id="e1")
    with pytest.raises(ir.IdentityLinkError) as exc:
        link(store, "a2", external_id="e1")
    assert exc.value.code == "IDENTITY_LINK_TAKEN"
    assert store.list_links("a2") == []


def test_link_same_pair_is_idempotent():
    store = registry()
    acct(store)
    first = link(store)
    second = link(store, now=at(10))
    assert second.sequence == first.sequence
    assert second.linked_at == NOW
    assert len(store.list_links("a1")) == 1
    assert store.stats()["links_created"] == 1


def test_link_rejects_unknown_and_tombstoned_accounts():
    store = registry()
    acct(store, "a1")
    acct(store, "a2")
    link(store, "a2", external_id="e2")
    store.merge_accounts("a2", "a1", now=NOW)
    with pytest.raises(ir.IdentityLinkError) as exc:
        link(store, "missing")
    assert exc.value.code == "IDENTITY_ACCOUNT_UNKNOWN"
    with pytest.raises(ir.IdentityLinkError) as exc:
        link(store, "a2", external_id="e3")
    assert exc.value.code == "IDENTITY_ACCOUNT_TOMBSTONED"


def test_per_provider_cap_blocks_only_that_provider():
    store = registry(max_links_per_provider=2)
    acct(store)
    link(store, external_id="e1")
    link(store, external_id="e2", now=at(1))
    with pytest.raises(ir.IdentityLinkError) as exc:
        link(store, external_id="e3", now=at(2))
    assert exc.value.code == "IDENTITY_LINK_LIMIT"
    other = link(store, provider="oidc", external_id="o1", now=at(3))
    assert other.sequence == 3
    assert link(store, external_id="e1", now=at(4)).sequence == 1


def test_unlink_last_login_method_is_refused():
    store = registry()
    acct(store)
    link(store)
    with pytest.raises(ir.IdentityLinkError) as exc:
        store.unlink("a1", provider="email", external_id="e1", now=at(5))
    assert exc.value.code == "IDENTITY_LAST_LOGIN"
    assert store.resolve("email", "e1")["account_id"] == "a1"
    assert len(store.list_links("a1")) == 1


def test_unlink_one_of_two_releases_identity():
    store = registry()
    acct(store)
    link(store, external_id="e1")
    link(store, external_id="e2", now=at(1))
    assert store.unlink("a1", provider="email", external_id="e1",
                        now=at(2)) is True
    assert store.resolve("email", "e1") is None
    assert [row.external_id for row in store.list_links("a1")] == ["e2"]
    assert store.unlink("a1", provider="email", external_id="e1",
                        now=at(3)) is False
    assert store.stats()["links_removed"] == 1


def test_unlink_validates_account_and_missing_pair():
    store = registry()
    acct(store)
    link(store, external_id="e1")
    with pytest.raises(ir.IdentityLinkError) as exc:
        store.unlink("missing", provider="email", external_id="e1", now=NOW)
    assert exc.value.code == "IDENTITY_ACCOUNT_UNKNOWN"
    assert store.unlink("a1", provider="email", external_id="nope",
                        now=NOW) is False


def test_link_rejects_blank_identity_and_create_on_tombstone():
    store = registry()
    acct(store, "a1")
    acct(store, "a2")
    link(store, "a2", external_id="e2")
    store.merge_accounts("a2", "a1", now=NOW)
    for provider, external_id in [("", "x"), ("email", ""), ("  ", "  ")]:
        with pytest.raises(ir.IdentityLinkError) as exc:
            store.link("a1", provider=provider, external_id=external_id,
                       now=at(1))
        assert exc.value.code == "IDENTITY_INVALID_REQUEST"
    with pytest.raises(ir.IdentityLinkError) as exc:
        store.create_account("a2", now=at(2))
    assert exc.value.code == "IDENTITY_ACCOUNT_TOMBSTONED"


def test_merge_moves_links_and_leaves_tombstone():
    store = registry()
    acct(store, "a1")
    acct(store, "a2")
    link(store, "a1", external_id="e1")
    link(store, "a1", provider="oidc", external_id="o1", now=at(1))
    link(store, "a2", external_id="e2", now=at(2))
    result = store.merge_accounts("a2", "a1", now=at(3))
    assert result.source == "a2"
    assert result.target == "a1"
    assert result.state == "merged"
    assert result.moved == 1
    assert result.dropped == 0
    assert result.merged_at == at(3)
    rows = store.list_links("a1")
    assert [(row.provider, row.external_id) for row in rows] == [
        ("email", "e1"), ("email", "e2"), ("oidc", "o1")]
    source = store.status("a2")
    assert source["state"] == "tombstoned"
    assert source["merged_into"] == "a1"
    assert source["link_count"] == 0
    mark = store.tombstone_of("a2")
    assert mark["merged_into"] == "a1"
    assert mark["merged_at"] == at(3)
    assert store.accounts() == ["a1", "a2"]
    assert store.stats()["merges"] == 1


def test_merge_rejects_invalid_targets_and_cap_overflow_is_atomic():
    store = registry(max_links_per_provider=2)
    acct(store, "a1")
    acct(store, "a2")
    link(store, "a1", external_id="e1")
    link(store, "a2", external_id="e2")
    with pytest.raises(ir.IdentityLinkError) as exc:
        store.merge_accounts("a1", "a1", now=NOW)
    assert exc.value.code == "IDENTITY_MERGE_INVALID"
    store.merge_accounts("a2", "a1", now=NOW)
    with pytest.raises(ir.IdentityLinkError) as exc:
        store.merge_accounts("a1", "a2", now=at(1))
    assert exc.value.code == "IDENTITY_ACCOUNT_TOMBSTONED"
    with pytest.raises(ir.IdentityLinkError) as exc:
        store.merge_accounts("missing", "a1", now=at(2))
    assert exc.value.code == "IDENTITY_ACCOUNT_UNKNOWN"

    acct(store, "a3")
    acct(store, "a4")
    link(store, "a3", external_id="e3")
    link(store, "a3", external_id="e4", now=at(3))
    link(store, "a4", external_id="e5", now=at(4))
    with pytest.raises(ir.IdentityLinkError) as exc:
        store.merge_accounts("a4", "a3", now=at(5))
    assert exc.value.code == "IDENTITY_LINK_LIMIT"
    assert store.status("a4")["state"] == "active"
    assert [row.external_id for row in store.list_links("a4")] == ["e5"]


def test_snapshot_is_detached_and_restore_roundtrips():
    store = registry()
    acct(store, "a1")
    acct(store, "a2")
    link(store, "a1", external_id="e1")
    link(store, "a2", external_id="e2", now=at(1))
    store.merge_accounts("a2", "a1", now=at(2))
    state = store.snapshot()
    pristine = copy.deepcopy(state)
    assert set(state) == {"version", "accounts", "links", "tombstones",
                          "cooldowns", "stats"}
    state["accounts"].clear()
    state["links"].clear()
    state["stats"]["merges"] = 99
    assert store.status("a2")["state"] == "tombstoned"
    assert len(store.list_links("a1")) == 2
    assert store.stats()["merges"] == 1

    clone = registry()
    clone.restore(pristine)
    assert clone.status("a2")["merged_into"] == "a1"
    assert len(clone.list_links("a1")) == 2
    assert clone.tombstone_of("a2")["merged_into"] == "a1"
    assert clone.stats()["merges"] == 1

    live = clone.snapshot()
    for bad in [None, {}, {"version": 2, "accounts": {}, "links": [],
                           "tombstones": {}, "cooldowns": {}, "stats": {}},
                {"version": 1, "accounts": [], "links": [], "tombstones": {},
                 "cooldowns": {}, "stats": {}},
                {"version": 1, "accounts": {}, "links": "nope",
                 "tombstones": {}, "cooldowns": {}, "stats": {}},
                {"version": 1, "accounts": {}, "links": [], "tombstones": [],
                 "cooldowns": {}, "stats": {}},
                {"version": 1, "accounts": {}, "links": [], "tombstones": {},
                 "cooldowns": {}, "stats": {"merges": 1}}]:
        with pytest.raises(ir.IdentityLinkError) as exc:
            clone.restore(bad)
        assert exc.value.code == "IDENTITY_SNAPSHOT_INVALID"
    assert clone.snapshot() == live


def test_stats_track_links_unlinks_merges_and_cooldowns():
    store = registry()
    acct(store, "a1")
    acct(store, "a2")
    link(store, "a1", external_id="e1")
    link(store, "a1", provider="oidc", external_id="o1", now=at(1))
    link(store, "a2", external_id="e2", now=at(2))
    store.unlink("a1", provider="email", external_id="e1", now=at(3))
    store.merge_accounts("a2", "a1", now=at(5))
    assert store.stats() == {"accounts_created": 2, "links_created": 3,
                             "links_removed": 1, "merges": 1,
                             "cooldown_hits": 0}
