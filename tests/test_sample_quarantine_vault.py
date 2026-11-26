import pytest

import sample_quarantine_vault as sv

T0 = "2026-11-26T00:00:00+00:00"
T_NEXT_DAY = "2026-11-27T00:00:00+00:00"


def digest(n):
    return "{0:064x}".format(n)


def vault(**kwargs):
    kwargs.setdefault("quota_bytes", 1000000)
    return sv.SampleQuarantineVault(**kwargs)


def seeded(**kwargs):
    engine = vault(**kwargs)
    engine.admit(digest(1), size_bytes=100, source="feed-a", now=T0)
    engine.admit(digest(2), size_bytes=200, source="feed-b", now=T0)
    return engine


def test_admit_records_metadata_and_expiry():
    engine = vault()
    rec = engine.admit(digest(1), size_bytes=100, source="feed-a", now=T0)
    assert isinstance(rec, sv.SampleRecord)
    assert rec.content_hash == digest(1)
    assert rec.size_bytes == 100
    assert rec.source == "feed-a"
    assert rec.admitted_at == T0
    assert rec.retain_until == "2026-12-26T00:00:00+00:00"
    assert rec.priority == 0
    assert rec.refcount == 0
    assert rec.admissions == 1
    assert rec.status == "active"
    assert [item.content_hash for item in engine.samples()] == [digest(1)]
    assert engine.stats()["active"] == 1
    assert engine.stats()["total_bytes"] == 100


def test_admit_rejects_bad_hash_size_and_retention():
    engine = vault()
    for bad_hash in ("", "abc", digest(1).upper(), "z" * 64):
        with pytest.raises(sv.VaultError) as exc:
            engine.admit(bad_hash, size_bytes=10, source="feed-a", now=T0)
        assert exc.value.code == "VAULT_BAD_HASH"
    for bad_size in (0, -5, "12"):
        with pytest.raises(sv.VaultError) as exc:
            engine.admit(digest(2), size_bytes=bad_size, source="feed-a", now=T0)
        assert exc.value.code == "VAULT_BAD_SIZE"
    for bad_days in (0, -1, 4000):
        with pytest.raises(sv.VaultError) as exc:
            engine.admit(digest(3), size_bytes=10, source="feed-a", now=T0,
                         retention_days=bad_days)
        assert exc.value.code == "VAULT_BAD_RETENTION"
    with pytest.raises(sv.VaultError) as exc:
        engine.admit(digest(4), size_bytes=10, source="", now=T0)
    assert exc.value.code == "VAULT_BAD_SOURCE"
    with pytest.raises(sv.VaultError) as exc:
        engine.admit(digest(5), size_bytes=10, source="feed-a", now=T0, priority=11)
    assert exc.value.code == "VAULT_BAD_PRIORITY"
    assert engine.samples() == []
    assert engine.stats()["denied"] == 12
    assert engine.stats()["total_bytes"] == 0


def test_duplicate_admit_does_not_consume_quota():
    engine = vault()
    first = engine.admit(digest(1), size_bytes=100, source="feed-a", now=T0)
    second = engine.admit(digest(1), size_bytes=100, source="feed-b", now=T_NEXT_DAY)
    assert second.content_hash == digest(1)
    assert second.admissions == 2
    assert second.admitted_at == first.admitted_at
    assert second.retain_until == first.retain_until
    assert len(engine.samples()) == 1
    assert engine.stats()["total_bytes"] == 100
    assert engine.stats()["admitted"] == 2
    assert engine.stats()["duplicates"] == 1


def test_lookup_unknown_hash_raises():
    engine = vault()
    with pytest.raises(sv.VaultError) as exc:
        engine.lookup(digest(9))
    assert exc.value.code == "VAULT_UNKNOWN"
    assert engine.stats()["denied"] == 1


def test_tag_and_untag_track_case_references():
    engine = seeded()
    assert engine.tag(digest(1), "case-7") == 1
    assert engine.tag(digest(1), "case-7") == 1
    assert engine.tag(digest(1), "case-8") == 2
    info = engine.lookup(digest(1))
    assert info["content_hash"] == digest(1)
    assert info["refcount"] == 2
    assert info["cases"] == ["case-7", "case-8"]
    assert engine.stats()["protected"] == 1
    assert engine.untag(digest(1), "case-7") == 1
    assert engine.untag(digest(1), "case-8") == 0
    assert engine.lookup(digest(1))["cases"] == []
    assert engine.stats()["protected"] == 0
    with pytest.raises(sv.VaultError) as exc:
        engine.untag(digest(1), "case-404")
    assert exc.value.code == "VAULT_UNKNOWN_CASE"
    with pytest.raises(sv.VaultError) as exc:
        engine.tag(digest(42), "case-1")
    assert exc.value.code == "VAULT_UNKNOWN"


def test_evict_skips_samples_with_case_references():
    engine = vault()
    for index in (1, 2, 3):
        engine.admit(digest(index), size_bytes=100, source="feed", now=T0)
    engine.tag(digest(2), "case-1")
    removed = engine.evict(needed_bytes=200, now=T0)
    assert removed == [digest(1), digest(3)]
    assert [item.content_hash for item in engine.samples()] == [digest(2)]
    assert engine.stats()["evicted"] == 2
    assert engine.stats()["total_bytes"] == 100


def test_evict_order_follows_priority_then_admission():
    engine = vault()
    engine.admit(digest(1), size_bytes=100, source="feed", now=T0, priority=1)
    engine.admit(digest(2), size_bytes=100, source="feed",
                 now="2026-11-26T01:00:00+00:00", priority=5)
    engine.admit(digest(3), size_bytes=100, source="feed",
                 now="2026-11-26T02:00:00+00:00", priority=1)
    removed = engine.evict(needed_bytes=200, now=T_NEXT_DAY)
    assert removed == [digest(1), digest(3)]
    assert [item.content_hash for item in engine.samples()] == [digest(2)]


def test_evict_is_all_or_nothing_when_shortfall_unmet():
    engine = vault()
    engine.admit(digest(1), size_bytes=100, source="feed", now=T0)
    engine.tag(digest(1), "case-1")
    with pytest.raises(sv.VaultError) as exc:
        engine.evict(needed_bytes=100, now=T0)
    assert exc.value.code == "VAULT_QUOTA_EXCEEDED"
    assert [item.content_hash for item in engine.samples()] == [digest(1)]
    assert engine.stats()["evicted"] == 0
    with pytest.raises(sv.VaultError) as exc:
        engine.evict(needed_bytes=0, now=T0)
    assert exc.value.code == "VAULT_BAD_REQUEST"


def test_admit_refuses_when_quota_exhausted():
    engine = vault(quota_bytes=250)
    engine.admit(digest(1), size_bytes=100, source="feed", now=T0)
    engine.admit(digest(2), size_bytes=100, source="feed", now=T0)
    with pytest.raises(sv.VaultError) as exc:
        engine.admit(digest(3), size_bytes=100, source="feed", now=T0)
    assert exc.value.code == "VAULT_QUOTA_EXCEEDED"
    assert len(engine.samples()) == 2
    assert engine.stats()["total_bytes"] == 200
    assert engine.stats()["denied"] == 1


def test_purge_expired_removes_only_expired_unreferenced_samples():
    engine = vault(retention_days=1)
    engine.admit(digest(1), size_bytes=100, source="feed", now=T0)
    engine.admit(digest(2), size_bytes=100, source="feed", now=T0)
    engine.tag(digest(2), "case-2")
    purged = engine.purge_expired(now="2026-11-30T00:00:00+00:00")
    assert purged == [digest(1)]
    assert [item.content_hash for item in engine.samples()] == [digest(2)]
    assert engine.stats()["purged"] == 1
    assert engine.stats()["protected"] == 1


def test_snapshot_detaches_from_live_state():
    engine = seeded()
    engine.tag(digest(1), "case-1")
    state = engine.snapshot()
    assert state == engine.snapshot()
    clone = vault()
    clone.restore(state)
    assert [item.content_hash for item in clone.samples()] == [digest(1), digest(2)]
    assert clone.lookup(digest(1))["cases"] == ["case-1"]
    assert clone.stats() == engine.stats()
    clone.admit(digest(3), size_bytes=10, source="feed", now=T0)
    assert len(engine.samples()) == 2
    assert len(clone.samples()) == 3
    assert engine.stats() != clone.stats()


def test_restore_rejects_malformed_state():
    engine = seeded()
    good = engine.snapshot()
    missing = dict(good)
    missing.pop("records")
    wrong_type = dict(good)
    wrong_type["records"] = "not-a-list"
    broken = [None, [], {}, {"version": 99}, missing, wrong_type]
    for bad in broken:
        with pytest.raises(sv.VaultError) as exc:
            engine.restore(bad)
        assert exc.value.code == "VAULT_SNAPSHOT_INVALID"
    assert [item.content_hash for item in engine.samples()] == [digest(1), digest(2)]
    assert engine.stats()["active"] == 2


def test_destroy_refuses_referenced_sample():
    engine = seeded()
    engine.tag(digest(1), "case-4")
    with pytest.raises(sv.VaultError) as exc:
        engine.destroy(digest(1), actor="ops-3", now=T0)
    assert exc.value.code == "VAULT_PROTECTED"
    assert len(engine.samples()) == 2
    assert engine.lookup(digest(1))["refcount"] == 1
    with pytest.raises(sv.VaultError) as exc:
        engine.destroy(digest(42), actor="ops-3", now=T0)
    assert exc.value.code == "VAULT_UNKNOWN"
    assert engine.stats()["destroyed"] == 0


def test_destroy_leaves_tombstone_and_blocks_lookup():
    engine = seeded()
    receipt = engine.destroy(digest(2), actor="ops-3", now=T0)
    assert receipt["content_hash"] == digest(2)
    assert receipt["status"] == "tombstone"
    assert receipt["actor"] == "ops-3"
    assert receipt["tombstones_until"] == "2026-12-03T00:00:00+00:00"
    with pytest.raises(sv.VaultError) as exc:
        engine.lookup(digest(2))
    assert exc.value.code == "VAULT_DESTROYED"
    assert [item["content_hash"] for item in engine.tombstones()] == [digest(2)]
    assert [item.content_hash for item in engine.samples()] == [digest(1)]
    assert engine.stats()["tombstoned"] == 1
    assert engine.stats()["destroyed"] == 1
    assert engine.stats()["total_bytes"] == 100


def test_capacity_report_and_stats_track_counters():
    engine = vault(quota_bytes=1000)
    engine.admit(digest(1), size_bytes=300, source="feed", now=T0)
    engine.admit(digest(2), size_bytes=200, source="feed", now=T0)
    engine.tag(digest(2), "case-1")
    report = engine.capacity_report()
    assert report["quota_bytes"] == 1000
    assert report["used_bytes"] == 500
    assert report["free_bytes"] == 500
    assert report["active"] == 2
    assert report["protected"] == 1
    assert report["evictable"] == 1
    stats = engine.stats()
    assert stats["admitted"] == 2
    assert stats["duplicates"] == 0
    assert stats["denied"] == 0
    assert stats["active"] == 2
    assert stats["total_bytes"] == 500
