import copy
import threading

import pytest

import character_name_registry as cnr

NOW = "2026-11-23T09:00:00+00:00"
LATER = "2026-11-23T09:10:00+00:00"
JUST_BEFORE = "2026-11-23T09:04:59+00:00"


def registry(**kwargs):
    kwargs.setdefault("banned_words", ["admin"])
    kwargs.setdefault("reserved_words", ["system"])
    return cnr.CharacterNameRegistry(**kwargs)


def test_normalize_folds_width_case_and_whitespace():
    reg = registry()
    assert reg.normalize("Ａｌｉｃｅ") == "alice"
    assert reg.normalize("  Mary   Ann ") == "mary ann"
    assert reg.normalize("BOB") == "bob"
    assert reg.normalize("a\tb") == "a b"
    for bad in ("", "   ", None, 5):
        with pytest.raises(cnr.NameRegistryError) as exc:
            reg.normalize(bad)
        assert exc.value.code == "NAME_INVALID"


def test_reserve_issues_sequential_tokens_with_expiry():
    reg = registry()
    out = reg.reserve("Alice", "u1", now=NOW)
    assert out == {"token": "n000001", "name": "Alice", "key": "alice",
                   "owner": "u1", "expires_at": "2026-11-23T09:05:00+00:00"}
    second = reg.reserve("Bob", "u1", now=NOW)
    assert second["token"] == "n000002"
    assert second["key"] == "bob"
    assert reg.stats() == {"reserved": 2, "confirmed": 0, "released": 0,
                           "expired": 0, "renamed": 0, "names": 0}


def test_reserve_rejects_equivalent_spellings():
    reg = registry()
    reg.reserve("Alice", "u1", now=NOW)
    with pytest.raises(cnr.NameRegistryError) as exc:
        reg.reserve("ＡＬＩＣＥ", "u2", now=NOW)
    assert exc.value.code == "NAME_TAKEN"
    with pytest.raises(cnr.NameRegistryError) as exc:
        reg.reserve("alice", "u1", now=NOW)
    assert exc.value.code == "NAME_TAKEN"
    token = reg.reserve("Bob", "u1", now=NOW)["token"]
    reg.confirm(token, now=NOW)
    with pytest.raises(cnr.NameRegistryError) as exc:
        reg.reserve("BOB", "u2", now=NOW)
    assert exc.value.code == "NAME_TAKEN"
    assert reg.stats()["reserved"] == 2


def test_reserve_validates_name_rules():
    reg = registry()
    cases = [
        ("", "u1", "NAME_INVALID"),
        ("a", "u1", "NAME_INVALID"),
        ("a" * 17, "u1", "NAME_TOO_LONG"),
        ("Al!ce", "u1", "NAME_INVALID"),
        ("Admin", "u1", "NAME_BANNED"),
        ("system", "u1", "NAME_RESERVED"),
        ("Alice", "   ", "NAME_INVALID"),
    ]
    for name, owner, code in cases:
        with pytest.raises(cnr.NameRegistryError) as exc:
            reg.reserve(name, owner, now=NOW)
        assert exc.value.code == code
    assert reg.stats()["reserved"] == 0


def test_token_cap_is_per_owner():
    reg = registry(max_tokens_per_owner=2)
    reg.reserve("Alice", "u1", now=NOW)
    reg.reserve("Bob", "u1", now=NOW)
    with pytest.raises(cnr.NameRegistryError) as exc:
        reg.reserve("Carol", "u1", now=NOW)
    assert exc.value.code == "NAME_CAPACITY_EXCEEDED"
    assert reg.reserve("Carol", "u2", now=NOW)["token"] == "n000003"
    assert reg.stats()["reserved"] == 3


def test_confirm_publishes_record_and_lookup_is_normalized():
    reg = registry()
    token = reg.reserve("Alice", "u1", now=NOW)["token"]
    record = reg.confirm(token, now=NOW)
    assert record == {"name": "Alice", "key": "alice", "owner": "u1",
                      "confirmed_at": NOW}
    assert reg.lookup("ＡＬＩＣＥ") == record
    assert reg.lookup("alice")["owner"] == "u1"
    assert reg.owner_names("u1") == ["Alice"]
    assert reg.stats()["confirmed"] == 1
    assert reg.stats()["names"] == 1


def test_confirm_rejects_unknown_token_and_mismatched_display_name():
    reg = registry()
    with pytest.raises(cnr.NameRegistryError) as exc:
        reg.confirm("n099999", now=NOW)
    assert exc.value.code == "NAME_TOKEN_UNKNOWN"
    token = reg.reserve("Alice", "u1", now=NOW)["token"]
    with pytest.raises(cnr.NameRegistryError) as exc:
        reg.confirm(token, display_name="Bob", now=NOW)
    assert exc.value.code == "NAME_INVALID"
    reg.confirm(token, now=NOW)
    with pytest.raises(cnr.NameRegistryError) as exc:
        reg.confirm(token, now=NOW)
    assert exc.value.code == "NAME_TOKEN_UNKNOWN"
    assert reg.lookup("Alice")["owner"] == "u1"


def test_release_frees_the_name_for_others():
    reg = registry()
    token = reg.reserve("Alice", "u1", now=NOW)["token"]
    with pytest.raises(cnr.NameRegistryError) as exc:
        reg.release(token, "u2")
    assert exc.value.code == "NAME_OWNER_MISMATCH"
    assert reg.release(token, "u1") is True
    with pytest.raises(cnr.NameRegistryError) as exc:
        reg.release(token, "u1")
    assert exc.value.code == "NAME_TOKEN_UNKNOWN"
    assert reg.reserve("alice", "u2", now=NOW)["token"] == "n000002"
    assert reg.stats()["released"] == 1


def test_expire_drops_stale_tokens_but_keeps_confirmed_names():
    reg = registry(token_ttl=300)
    reg.reserve("Alice", "u1", now=NOW)
    token = reg.reserve("Bob", "u1", now=NOW)["token"]
    reg.confirm(token, now=NOW)
    assert reg.expire(now=JUST_BEFORE) == 0
    assert reg.expire(now=LATER) == 1
    assert reg.stats()["expired"] == 1
    assert reg.lookup("Alice") is None
    assert reg.lookup("Bob")["owner"] == "u1"
    assert reg.owner_names("u1") == ["Bob"]


def test_rename_publishes_new_name_and_returns_previous():
    reg = registry()
    token = reg.reserve("Alice", "u1", now=NOW)["token"]
    reg.confirm(token, now=NOW)
    out = reg.rename("u1", "Alicia", now=NOW)
    assert out["owner"] == "u1"
    assert out["name"] == "Alicia"
    assert out["key"] == "alicia"
    assert out["previous_key"] == "alice"
    assert out["cooldown_until"] == "2026-11-24T09:00:00+00:00"
    assert reg.lookup("Alicia")["owner"] == "u1"
    assert reg.lookup("alice") is None
    assert reg.owner_names("u1") == ["Alicia"]
    assert reg.stats()["renamed"] == 1


def test_rename_rejects_unknown_owner_taken_and_unchanged_names():
    reg = registry()
    reg.reserve("Ghost", "u1", now=NOW)
    with pytest.raises(cnr.NameRegistryError) as exc:
        reg.rename("u1", "Phantom", now=NOW)
    assert exc.value.code == "NAME_OWNER_UNKNOWN"
    token = reg.reserve("Alice", "u2", now=NOW)["token"]
    reg.confirm(token, now=NOW)
    bob_token = reg.reserve("Bob", "u3", now=NOW)["token"]
    reg.confirm(bob_token, now=NOW)
    with pytest.raises(cnr.NameRegistryError) as exc:
        reg.rename("u2", "bob", now=NOW)
    assert exc.value.code == "NAME_TAKEN"
    with pytest.raises(cnr.NameRegistryError) as exc:
        reg.rename("u2", "ＡＬＩＣＥ", now=NOW)
    assert exc.value.code == "NAME_UNCHANGED"


def test_lookup_owner_names_and_counters():
    reg = registry()
    for name, owner in (("Zed", "u1"), ("Alice", "u1"), ("Bob", "u2")):
        token = reg.reserve(name, owner, now=NOW)["token"]
        reg.confirm(token, now=NOW)
    assert reg.lookup("Nobody") is None
    assert reg.owner_names("u1") == ["Alice", "Zed"]
    assert reg.owner_names("u2") == ["Bob"]
    assert reg.owner_names("u3") == []
    assert reg.stats() == {"reserved": 3, "confirmed": 3, "released": 0,
                           "expired": 0, "renamed": 0, "names": 3}


def test_concurrent_reserve_of_one_name_yields_a_single_token():
    reg = registry()
    errors = []
    barrier = threading.Barrier(8)
    tokens = []

    def worker(index):
        try:
            barrier.wait(timeout=5)
            tokens.append(reg.reserve("Contested", f"u{index}", now=NOW)["token"])
        except Exception as exc:  # pragma: no cover - surfaced through errors
            errors.append(getattr(exc, "code", repr(exc)))

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert tokens == ["n000001"]
    assert errors == ["NAME_TAKEN"] * 7
    assert reg.stats()["reserved"] == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    source = registry(token_ttl=300)
    first = source.reserve("Alice", "u1", now=NOW)["token"]
    source.confirm(first, now=NOW)
    pending = source.reserve("Bob", "u2", now=NOW)["token"]
    state = source.snapshot()
    assert set(state) == {"version", "tokens", "names", "cooldowns", "stats"}
    assert state["version"] == 1
    pristine = copy.deepcopy(state)
    state["names"].clear()
    state["stats"]["names"] = 9
    assert source.lookup("Alice")["owner"] == "u1"
    assert source.stats()["names"] == 1

    clone = registry(token_ttl=300)
    clone.restore(pristine)
    assert clone.stats() == source.stats()
    assert clone.lookup("ＡＬＩＣＥ") == source.lookup("alice")
    assert clone.owner_names("u1") == ["Alice"]
    record = clone.confirm(pending, now=NOW)
    assert record["key"] == "bob"
    assert clone.stats()["names"] == 2


def test_restore_rejects_malformed_state_without_touching_live_data():
    reg = registry()
    token = reg.reserve("Alice", "u1", now=NOW)["token"]
    reg.confirm(token, now=NOW)
    good = reg.snapshot()
    bad_states = [
        None,
        {},
        {key: value for key, value in good.items() if key != "tokens"},
        {**good, "version": 2},
        {**good, "tokens": []},
        {**good, "names": []},
        {**good, "stats": {"names": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(cnr.NameRegistryError) as exc:
            reg.restore(bad)
        assert exc.value.code == "NAME_SNAPSHOT_INVALID"
    assert reg.lookup("Alice")["owner"] == "u1"
    assert reg.stats()["names"] == 1
