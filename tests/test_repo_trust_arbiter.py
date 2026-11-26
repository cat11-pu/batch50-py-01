import hashlib

import pytest

import repo_trust_arbiter as rta

KEY_A = "key-main-0001"
KEY_B = "key-mirror-0002"
MAT_A = "material-alpha-0123456789"
MAT_B = "material-bravo-0123456789"
NOW = "2026-11-26T00:00:00+00:00"
VALID = "2026-12-26T00:00:00+00:00"
PAST = "2026-10-01T00:00:00+00:00"


def sig(origin, suite, valid_until, material):
    body = f"{origin}:{suite}:{valid_until}:{material}".encode()
    return hashlib.sha256(body).hexdigest()


def arbiter(**kwargs):
    kwargs.setdefault("installed_versions", {})
    return rta.RepoTrustArbiter(**kwargs)


def source(a, source_id="src-a", *, origin="Example", suite="stable",
           priority=100, key=KEY_A, material=MAT_A):
    a.add_key(key, material)
    return a.add_source(source_id, origin=origin, suite=suite,
                        components=("main", "updates"), priority=priority,
                        keys=(key,))


def verify(a, source_id="src-a", *, origin="Example", suite="stable",
           valid_until=VALID, material=MAT_A, key=KEY_A):
    return a.verify_release(source_id, suite=suite, origin=origin,
                            valid_until=valid_until, now=NOW, key_id=key,
                            signature=sig(origin, suite, valid_until, material))


def publish(a, source_id="src-a", name="pkg", version="1.2", component="main"):
    a.publish_package(source_id, name=name, version=version, component=component)


def test_add_source_with_unknown_key_is_atomic():
    a = arbiter()
    a.add_key(KEY_A, MAT_A)
    with pytest.raises(rta.RepoError) as exc:
        a.add_source("src-x", origin="Example", suite="stable",
                     components=("main",), priority=50, keys=("key-missing",))
    assert exc.value.code == "REPO_KEY_UNKNOWN"
    assert a.status(source_id="src-x") is None
    assert a.audit()["sources_total"] == 0
    assert a.stats()["sources_added"] == 0


def test_key_cannot_bind_to_two_sources():
    a = arbiter()
    source(a)
    with pytest.raises(rta.RepoError) as exc:
        a.add_source("src-b", origin="Mirror", suite="stable",
                     components=("main",), priority=20, keys=(KEY_A,))
    assert exc.value.code == "REPO_KEY_ALREADY_BOUND"
    assert a.status(source_id="src-b") is None
    assert a.audit()["sources_total"] == 1
    assert a.audit()["keys"] == 1


def test_duplicate_source_id_is_refused():
    a = arbiter()
    source(a)
    with pytest.raises(rta.RepoError) as exc:
        a.add_source("src-a", origin="Hijack", suite="testing",
                     components=("main",), priority=400, keys=(KEY_A,))
    assert exc.value.code == "REPO_SOURCE_DUPLICATE"
    info = a.status(source_id="src-a")
    assert (info["origin"], info["priority"], info["suite"]) == ("Example", 100, "stable")


def test_verify_release_requires_bound_key():
    a = arbiter()
    source(a)
    a.add_key(KEY_B, MAT_B)
    with pytest.raises(rta.RepoError) as exc:
        verify(a, key=KEY_B, material=MAT_B)
    assert exc.value.code == "REPO_KEY_NOT_BOUND"
    assert a.status(source_id="src-a")["state"] == "unverified"
    assert a.stats()["verified"] == 0


def test_verified_source_yields_candidates():
    a = arbiter()
    source(a)
    publish(a)
    assert a.candidates("pkg", now=NOW) == []
    report = verify(a)
    assert report["state"] == "usable"
    assert report["valid_until"] == VALID
    rows = a.candidates("pkg", now=NOW)
    assert [(c.name, c.version, c.source_id, c.priority, c.suite) for c in rows] == [
        ("pkg", "1.2", "src-a", 100, "stable"),
    ]
    assert a.status(source_id="src-a")["state"] == "usable"
    assert a.stats()["verified"] == 1


def test_unverified_source_yields_no_candidates():
    a = arbiter()
    source(a)
    publish(a)
    assert a.candidates("pkg", now=NOW) == []
    with pytest.raises(rta.RepoError) as exc:
        a.resolve("pkg", now=NOW)
    assert exc.value.code == "REPO_NO_CANDIDATE"
    assert a.stats()["resolved"] == 0


def test_expired_release_excludes_source():
    a = arbiter()
    source(a)
    publish(a)
    with pytest.raises(rta.RepoError) as exc:
        verify(a, valid_until=PAST)
    assert exc.value.code == "REPO_RELEASE_EXPIRED"
    assert a.candidates("pkg", now=NOW) == []
    assert a.status(source_id="src-a")["state"] == "expired"
    assert a.audit(now=NOW)["expired"] == 1


def test_bad_release_signature_leaves_source_unverified():
    a = arbiter()
    source(a)
    publish(a)
    with pytest.raises(rta.RepoError) as exc:
        a.verify_release("src-a", suite="stable", origin="Example",
                         valid_until=VALID, now=NOW, key_id=KEY_A,
                         signature="0" * 64)
    assert exc.value.code == "REPO_RELEASE_SIGNATURE_INVALID"
    assert a.status(source_id="src-a")["state"] == "unverified"
    assert a.candidates("pkg", now=NOW) == []
    assert a.stats()["verified"] == 0


def test_candidates_ordered_by_source_priority():
    a = arbiter()
    source(a, "src-a", origin="Example", priority=10, key=KEY_A, material=MAT_A)
    publish(a, "src-a", version="1.0")
    source(a, "src-b", origin="Mirror", priority=20, key=KEY_B, material=MAT_B)
    publish(a, "src-b", version="1.1")
    verify(a, "src-a", origin="Example", material=MAT_A, key=KEY_A)
    verify(a, "src-b", origin="Mirror", material=MAT_B, key=KEY_B)
    rows = a.candidates("pkg", now=NOW)
    assert [(c.source_id, c.version, c.priority) for c in rows] == [
        ("src-b", "1.1", 20),
        ("src-a", "1.0", 10),
    ]


def test_resolve_prefers_high_priority_source():
    a = arbiter()
    source(a, "src-a", origin="Example", priority=10, key=KEY_A, material=MAT_A)
    publish(a, "src-a", version="1.0")
    source(a, "src-b", origin="Mirror", priority=20, key=KEY_B, material=MAT_B)
    publish(a, "src-b", version="1.1")
    verify(a, "src-a", origin="Example", material=MAT_A, key=KEY_A)
    verify(a, "src-b", origin="Mirror", material=MAT_B, key=KEY_B)
    result = a.resolve("pkg", now=NOW)
    assert (result.name, result.version, result.source_id, result.priority,
            result.action) == ("pkg", "1.1", "src-b", 20, "install")
    assert a.stats()["resolved"] == 1


def test_pin_overrides_source_priority():
    a = arbiter()
    source(a, "src-a", origin="Example", priority=10, key=KEY_A, material=MAT_A)
    publish(a, "src-a", version="1.0")
    source(a, "src-b", origin="Mirror", priority=20, key=KEY_B, material=MAT_B)
    publish(a, "src-b", version="1.1")
    verify(a, "src-a", origin="Example", material=MAT_A, key=KEY_A)
    verify(a, "src-b", origin="Mirror", material=MAT_B, key=KEY_B)
    a.pin("pkg", source_id="src-a", priority=60, reason="vendor hold")
    result = a.resolve("pkg", now=NOW)
    assert (result.version, result.source_id, result.priority) == ("1.0", "src-a", 60)
    assert a.unpin("pkg", source_id="src-a") is True
    assert a.unpin("pkg", source_id="src-a") is False
    assert a.resolve("pkg", now=NOW).source_id == "src-b"


def test_resolve_refuses_downgrade():
    a = arbiter(installed_versions={"pkg": "1.10"})
    source(a)
    publish(a, version="1.9")
    verify(a)
    with pytest.raises(rta.RepoError) as exc:
        a.resolve("pkg", now=NOW)
    assert exc.value.code == "REPO_DOWNGRADE_REFUSED"
    assert a.stats()["downgrades_refused"] == 1
    downgraded = a.resolve("pkg", now=NOW, allow_downgrade=True)
    assert (downgraded.version, downgraded.action) == ("1.9", "downgrade")


def test_resolve_same_version_is_keep():
    a = arbiter(installed_versions={"pkg": "2.0"})
    source(a)
    publish(a, version="2.0")
    verify(a)
    result = a.resolve("pkg", now=NOW)
    assert (result.version, result.action) == ("2.0", "keep")


def test_remove_source_frees_key_and_drops_packages():
    a = arbiter()
    source(a)
    publish(a)
    verify(a)
    assert len(a.candidates("pkg", now=NOW)) == 1
    assert a.remove_source("src-a") is True
    assert a.candidates("pkg", now=NOW) == []
    assert a.remove_source("src-a") is False
    a.add_source("src-c", origin="Vendor", suite="stable",
                 components=("main",), priority=5, keys=(KEY_A,))
    info = a.status(source_id="src-c")
    assert (info["priority"], info["state"]) == (5, "unverified")
    assert a.stats()["sources_removed"] == 1


def test_snapshot_restore_roundtrip_and_invalid_state():
    a = arbiter()
    source(a)
    publish(a)
    verify(a)
    a.pin("pkg", source_id="src-a", priority=70)
    a.mark_installed("pkg", "1.0")
    state = a.snapshot()
    clone = arbiter()
    clone.restore(state)
    rows = clone.candidates("pkg", now=NOW)
    assert [(c.version, c.source_id, c.priority) for c in rows] == [("1.2", "src-a", 70)]
    assert clone.status(source_id="src-a")["state"] == "usable"
    assert clone.resolve("pkg", now=NOW).action == "install"
    for bad in (None, {}, "nope"):
        with pytest.raises(rta.RepoError) as exc:
            clone.restore(bad)
        assert exc.value.code == "REPO_SNAPSHOT_INVALID"
    assert len(clone.candidates("pkg", now=NOW)) == 1
