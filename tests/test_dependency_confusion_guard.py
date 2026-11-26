import pytest

import dependency_confusion_guard as dg

NOW = 2_000_000
DAY = 86400


def make_guard(**kwargs):
    guard = dg.DependencyConfusionGuard(**kwargs)
    guard.add_source("private-registry", priority=5, kind="private")
    guard.add_source("public-a", priority=1, kind="public")
    guard.add_source("public-b", priority=2, kind="public")
    return guard


def ingest(guard, package, *, source="public-a", version="1.0.0", publisher="alice",
           publisher_since=NOW - 90 * DAY, ecosystem="pypi"):
    guard.ingest({"package": package, "ecosystem": ecosystem, "source": source,
                  "version": version, "publisher": publisher,
                  "publisher_since": publisher_since})


def test_plain_package_allow_uses_top_priority_source():
    guard = make_guard()
    ingest(guard, "requests")
    out = guard.evaluate("requests", version="1.0.0", now=NOW)
    assert out.decision == "allow"
    assert out.source == "public-a"
    assert out.similarity == 0.0
    assert out.cached is False
    assert guard.stats()["evaluations"] == 1


def test_internal_namespace_only_accepts_private_source():
    guard = make_guard()
    ingest(guard, "corp-utils", source="public-a", version="9.0.0")
    ingest(guard, "corp-utils", source="private-registry", version="1.0.0")
    out = guard.evaluate("corp-utils", version="1.0.0", now=NOW)
    assert out.decision == "allow"
    assert out.source == "private-registry"


def test_lookalike_name_is_blocked_with_similarity_score():
    guard = make_guard()
    ingest(guard, "corp-payments", source="private-registry")
    out = guard.evaluate("corppaymants", version="1.0.0", now=NOW)
    assert out.decision == "block"
    assert out.similarity >= 0.85
    assert out.source is None


def test_allowlist_skips_similarity_check():
    guard = make_guard()
    ingest(guard, "corp-payments", source="private-registry")
    ingest(guard, "corppaymants", source="public-a")
    guard.allowlist("corppaymants", note="vendor exception")
    out = guard.evaluate("corppaymants", version="1.0.0", now=NOW)
    assert out.decision == "allow"
    assert out.source == "public-a"


def test_recent_publisher_change_requires_confirmation():
    guard = make_guard()
    ingest(guard, "left-pad", publisher="eve", publisher_since=NOW - DAY)
    changed = guard.evaluate("left-pad", version="1.0.0", now=NOW)
    assert changed.decision == "confirm"
    ingest(guard, "requests", publisher="alice", publisher_since=NOW - 90 * DAY)
    stable = guard.evaluate("requests", version="1.0.0", now=NOW)
    assert stable.decision == "allow"


def test_source_priority_beats_newer_version():
    guard = make_guard()
    ingest(guard, "requests", source="public-a", version="1.0.0")
    ingest(guard, "requests", source="public-b", version="9.0.0")
    out = guard.evaluate("requests", now=NOW)
    assert out.source == "public-a"
    assert out.version == "1.0.0"
    assert out.decision == "allow"


def test_quarantine_blocks_and_release_restores():
    guard = make_guard()
    ingest(guard, "evil-pkg")
    assert guard.quarantine("evil-pkg", version="1.0.0", reason="manual", now=NOW) == 1
    blocked = guard.evaluate("evil-pkg", version="1.0.0", now=NOW)
    assert blocked.decision == "block"
    assert guard.stats()["quarantined"] == 1
    assert guard.quarantine("evil-pkg", version="1.0.0", reason="duplicate", now=NOW + 10) == 1
    assert guard.release("evil-pkg", version="1.0.0") is True
    assert guard.release("evil-pkg", version="1.0.0") is False
    assert guard.evaluate("evil-pkg", version="1.0.0", now=NOW + 20).decision == "allow"


def test_quarantine_capacity_is_enforced():
    guard = make_guard(max_quarantine=1)
    guard.quarantine("a-pkg", version="1.0.0", now=NOW)
    with pytest.raises(dg.DependencyGuardError) as err:
        guard.quarantine("b-pkg", version="1.0.0", now=NOW)
    assert err.value.code == "CAPACITY_EXCEEDED"


def test_purge_expired_clears_quarantine_entries():
    guard = make_guard()
    guard.quarantine("old-pkg", version="1.0.0", ttl=60, now=NOW)
    ingest(guard, "old-pkg")
    assert guard.purge_expired(now=NOW + 61) == 1
    assert guard.stats()["quarantined"] == 0
    assert guard.evaluate("old-pkg", version="1.0.0", now=NOW + 62).decision == "allow"


def test_package_without_metadata_is_blocked():
    guard = make_guard()
    out = guard.evaluate("never-seen", version="1.0.0", now=NOW)
    assert out.decision == "block"
    assert out.source is None


def test_verdict_cache_hits_and_publisher_change_invalidates():
    guard = make_guard()
    ingest(guard, "requests")
    first = guard.evaluate("requests", version="1.0.0", now=NOW)
    second = guard.evaluate("requests", version="1.0.0", now=NOW + 1)
    assert first.cached is False
    assert second.cached is True
    ingest(guard, "requests", publisher="eve", publisher_since=NOW - DAY)
    third = guard.evaluate("requests", version="1.0.0", now=NOW + 2)
    assert third.cached is False
    assert third.decision == "confirm"


def test_batch_resolution_orders_dependencies_first():
    guard = make_guard()
    for name in ("a-pkg", "b-pkg", "c-pkg"):
        ingest(guard, name)
    requests = [
        {"package": "a-pkg", "version": "1.0.0", "depends_on": ["b-pkg"]},
        {"package": "b-pkg", "version": "1.0.0", "depends_on": ["c-pkg"]},
        {"package": "c-pkg", "version": "1.0.0"},
    ]
    out = guard.resolve_batch(requests, now=NOW)
    assert [item.package for item in out] == ["c-pkg", "b-pkg", "a-pkg"]
    assert all(item.decision == "allow" for item in out)


def test_batch_rejection_names_the_root_package():
    guard = make_guard()
    ingest(guard, "corp-payments", source="private-registry")
    ingest(guard, "a-pkg")
    requests = [
        {"package": "a-pkg", "version": "1.0.0"},
        {"package": "corppaymants", "version": "1.0.0"},
    ]
    with pytest.raises(dg.DependencyGuardError) as err:
        guard.resolve_batch(requests, now=NOW)
    assert err.value.code == "BATCH_REJECTED"
    assert "corppaymants" in str(err.value.detail)


def test_policy_change_bumps_version_and_clears_cache():
    guard = make_guard()
    assert guard.policy()["policy_version"] == 1
    ingest(guard, "requests")
    guard.evaluate("requests", version="1.0.0", now=NOW)
    assert guard.evaluate("requests", version="1.0.0", now=NOW).cached is True
    updated = guard.policy(similarity_threshold=0.5)
    assert updated["similarity_threshold"] == 0.5
    assert updated["policy_version"] == 2
    assert guard.evaluate("requests", version="1.0.0", now=NOW).cached is False


def test_snapshot_restore_roundtrip_and_rejects_bad_state():
    guard = make_guard()
    ingest(guard, "requests")
    guard.allowlist("requests", note="ok")
    guard.quarantine("evil-pkg", version="1.0.0", reason="manual", now=NOW)
    guard.evaluate("requests", version="1.0.0", now=NOW)
    snap = guard.snapshot()
    clone = dg.DependencyConfusionGuard()
    clone.restore(snap)
    assert clone.stats() == guard.stats()
    assert clone.policy() == guard.policy()
    assert clone.evaluate("requests", version="1.0.0", now=NOW + 1).decision == "allow"
    with pytest.raises(dg.DependencyGuardError) as err:
        clone.restore({"quarantine": "broken"})
    assert err.value.code == "SNAPSHOT_INVALID"
    assert clone.stats()["quarantined"] == 1
