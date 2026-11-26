import pytest

import ioc_feed_merger as ioc

T0 = "2026-11-26T00:00:00+00:00"


def merger(**kwargs):
    return ioc.IocFeedMerger(**kwargs)


def source(engine, name, *, weight=0.5, priority=10, kind="intel", now=T0):
    return engine.register_source(name, weight=weight, priority=priority,
                                  kind=kind, now=now)


def item(ioc_type, value, ttl=1000, confidence=None):
    payload = {"type": ioc_type, "value": value, "ttl": ttl}
    if confidence is not None:
        payload["confidence"] = confidence
    return payload


def test_register_source_validates_and_lists_sorted():
    engine = merger()
    rec = source(engine, "feed-b", weight=0.4, priority=20, kind="intel")
    assert isinstance(rec, ioc.SourceRecord)
    assert (rec.name, rec.weight, rec.priority, rec.kind) == ("feed-b", 0.4, 20, "intel")
    assert rec.added_at == T0
    source(engine, "feed-a", weight=0.6, priority=30, kind="whitelist")
    assert [row.name for row in engine.sources()] == ["feed-a", "feed-b"]
    with pytest.raises(ioc.IocError) as exc:
        source(engine, "feed-b", weight=0.5, priority=1)
    assert exc.value.code == "IOC_DUPLICATE_SOURCE"
    for kind in ("unknown", ""):
        with pytest.raises(ioc.IocError) as exc:
            engine.register_source("feed-{0}".format(kind), weight=0.5,
                                   priority=1, kind=kind, now=T0)
        assert exc.value.code == "IOC_BAD_SOURCE"
    for weight in (0, -0.1, 1.5):
        with pytest.raises(ioc.IocError) as exc:
            engine.register_source("w-{0}".format(weight), weight=weight,
                                   priority=1, kind="intel", now=T0)
        assert exc.value.code == "IOC_BAD_SOURCE"
    for priority in (-1, 101):
        with pytest.raises(ioc.IocError) as exc:
            engine.register_source("p-{0}".format(priority), weight=0.5,
                                   priority=priority, kind="intel", now=T0)
        assert exc.value.code == "IOC_BAD_SOURCE"
    assert len(engine.sources()) == 2


def test_ingest_normalizes_indicators_before_merging():
    engine = merger()
    source(engine, "feed-a")
    out = engine.ingest_feed("feed-a", [
        {"type": "domain", "value": "  Example.COM.  ", "ttl": 600},
        {"type": "ipv4", "value": "10.0.0.7", "ttl": 600},
        {"type": "url", "value": "HTTPS://Bad.Example/Path", "ttl": 600},
        {"type": "sha256", "value": "A" * 64, "ttl": 600},
    ], now=T0)
    assert out["accepted"] == 4
    assert out["rejected"] == 0
    assert out["rejected_indexes"] == []
    keys = [(row["type"], row["value"]) for row in engine.merge(now=T0)]
    assert keys == [
        ("domain", "example.com"),
        ("ipv4", "10.0.0.7"),
        ("sha256", "a" * 64),
        ("url", "https://bad.example/path"),
    ]


def test_ingest_rejects_unknown_source_and_bad_fields():
    engine = merger()
    source(engine, "feed-a")
    with pytest.raises(ioc.IocError) as exc:
        engine.ingest_feed("feed-x", [item("domain", "a.example")], now=T0)
    assert exc.value.code == "IOC_UNKNOWN_SOURCE"
    out = engine.ingest_feed("feed-a", [
        {"type": "cve", "value": "CVE-2026-1", "ttl": 600},
        {"type": "domain", "value": "   ", "ttl": 600},
        {"type": "domain", "value": "ok.example", "ttl": 0},
        {"type": "domain", "value": "ok2.example", "ttl": 600, "confidence": 1.5},
        {"type": "domain", "value": "ok3.example", "ttl": 600},
    ], now=T0)
    assert out["accepted"] == 1
    assert out["rejected"] == 4
    assert out["rejected_indexes"] == [0, 1, 2, 3]
    assert [row["value"] for row in engine.merge(now=T0)] == ["ok3.example"]


def test_merge_combines_confidence_and_keeps_longest_ttl():
    engine = merger()
    source(engine, "feed-a", weight=0.5, priority=10)
    source(engine, "feed-b", weight=0.5, priority=10)
    engine.ingest_feed("feed-a", [item("domain", "evil.example", ttl=1000)], now=T0)
    engine.ingest_feed("feed-b", [item("domain", "evil.example", ttl=5000)], now=T0)
    rows = engine.merge(now=T0)
    assert len(rows) == 1
    row = rows[0]
    assert row["type"] == "domain"
    assert row["value"] == "evil.example"
    assert row["confidence"] == pytest.approx(0.75)
    assert row["expires_at"] == "2026-11-26T01:23:20+00:00"
    assert len(row["sources"]) == 2
    assert [entry["source"] for entry in row["sources"]] == ["feed-a", "feed-b"]


def test_repeated_ingest_from_same_source_replaces_observation():
    engine = merger()
    source(engine, "feed-a", weight=0.5)
    for _ in range(3):
        engine.ingest_feed("feed-a", [item("domain", "dup.example", ttl=600)], now=T0)
    row = engine.lookup("domain", "dup.example", now=T0)
    assert len(row["sources"]) == 1
    assert row["confidence"] == pytest.approx(0.5)
    assert engine.stats()["observations"] == 1
    assert engine.stats()["accepted"] == 3


def test_whitelist_only_indicator_is_allowed():
    engine = merger()
    source(engine, "allow-list", weight=0.9, priority=5, kind="whitelist")
    engine.ingest_feed("allow-list", [item("domain", "partner.example", ttl=600)], now=T0)
    row = engine.lookup("domain", "partner.example", now=T0)
    assert row["verdict"] == "allow"
    assert [entry["kind"] for entry in row["sources"]] == ["whitelist"]
    assert engine.audit() == []
    assert engine.stats()["conflicts"] == 0


def test_intel_with_higher_priority_wins_and_is_audited():
    engine = merger()
    source(engine, "intel-a", weight=0.4, priority=50, kind="intel")
    source(engine, "allow-a", weight=0.9, priority=20, kind="whitelist")
    engine.ingest_feed("intel-a", [item("ipv4", "203.0.113.9", ttl=600)], now=T0)
    engine.ingest_feed("allow-a", [item("ipv4", "203.0.113.9", ttl=600)], now=T0)
    row = engine.lookup("ipv4", "203.0.113.9", now=T0)
    assert row["verdict"] == "block"
    entries = engine.audit()
    assert len(entries) == 1
    assert entries[0]["reason"] == "priority_conflict"
    assert entries[0]["type"] == "ipv4"
    assert entries[0]["value"] == "203.0.113.9"
    assert entries[0]["winner"] == "intel"
    assert engine.stats()["conflicts"] == 1


def test_lookup_unknown_indicator_raises():
    engine = merger()
    source(engine, "feed-a")
    with pytest.raises(ioc.IocError) as exc:
        engine.lookup("domain", "nothing.example", now=T0)
    assert exc.value.code == "IOC_UNKNOWN"


def test_merge_returns_indicators_sorted_by_type_and_value():
    engine = merger()
    source(engine, "feed-a")
    engine.ingest_feed("feed-a", [
        item("url", "https://b.example/x", ttl=600),
        item("domain", "z.example", ttl=600),
        item("domain", "a.example", ttl=600),
        item("ipv4", "198.51.100.4", ttl=600),
    ], now=T0)
    rows = engine.merge(now=T0)
    assert [(row["type"], row["value"]) for row in rows] == [
        ("domain", "a.example"),
        ("domain", "z.example"),
        ("ipv4", "198.51.100.4"),
        ("url", "https://b.example/x"),
    ]
    assert [row["verdict"] for row in rows] == ["block", "block", "block", "block"]
    assert engine.stats()["merged_indicators"] == 4


def test_expire_sweep_is_batched():
    engine = merger()
    source(engine, "feed-a")
    engine.ingest_feed("feed-a", [
        item("domain", "e{0}.example".format(index), ttl=60) for index in range(5)
    ], now=T0)
    later = "2026-11-26T01:00:00+00:00"
    assert len(engine.expire_sweep(now=later, batch_size=2)) == 2
    assert len(engine.expire_sweep(now=later, batch_size=2)) == 2
    assert len(engine.expire_sweep(now=later, batch_size=2)) == 1
    assert engine.expire_sweep(now=later, batch_size=2) == []
    assert engine.stats()["swept"] == 5
    assert engine.stats()["observations"] == 0


def test_expire_sweep_leaves_live_observations_queryable():
    engine = merger()
    source(engine, "feed-a")
    engine.ingest_feed("feed-a", [
        item("domain", "gone.example", ttl=60),
        item("domain", "live.example", ttl=100000),
    ], now=T0)
    later = "2026-11-26T01:00:00+00:00"
    removed = engine.expire_sweep(now=later)
    assert len(removed) == 1
    assert engine.lookup("domain", "live.example", now=later)["value"] == "live.example"
    with pytest.raises(ioc.IocError) as exc:
        engine.lookup("domain", "gone.example", now=later)
    assert exc.value.code == "IOC_UNKNOWN"
    assert engine.stats()["observations"] == 1


def test_effective_confidence_decays_with_remaining_ttl():
    engine = merger()
    source(engine, "feed-a", weight=0.8)
    engine.ingest_feed("feed-a", [item("domain", "slow.example", ttl=1000)], now=T0)
    assert engine.effective_confidence("domain", "slow.example", now=T0) == pytest.approx(0.8)
    half = "2026-11-26T00:08:20+00:00"
    assert engine.effective_confidence("domain", "slow.example", now=half) == pytest.approx(0.4)


def test_stats_track_sources_observations_and_sweeps():
    engine = merger()
    source(engine, "feed-a")
    source(engine, "feed-b", kind="whitelist")
    engine.ingest_feed("feed-a", [item("domain", "s1.example", ttl=60)], now=T0)
    engine.ingest_feed("feed-b", [item("domain", "s1.example", ttl=60)], now=T0)
    stats = engine.stats()
    assert stats["sources"] == 2
    assert stats["observations"] == 2
    assert stats["indicators"] == 1
    assert stats["accepted"] == 2
    assert stats["rejected"] == 0
    assert stats["swept"] == 0
    engine.expire_sweep(now="2026-11-26T02:00:00+00:00")
    assert engine.stats()["observations"] == 0
    assert engine.stats()["swept"] == 2


def test_snapshot_roundtrip_keeps_sources_and_verdicts():
    engine = merger()
    source(engine, "feed-a", weight=0.6, priority=30, kind="intel")
    source(engine, "allow-a", weight=0.4, priority=10, kind="whitelist")
    engine.ingest_feed("feed-a", [item("domain", "keep.example", ttl=5000)], now=T0)
    state = engine.snapshot()
    clone = merger()
    clone.restore(state)
    assert [row.name for row in clone.sources()] == ["allow-a", "feed-a"]
    row = clone.lookup("domain", "keep.example", now=T0)
    assert row["confidence"] == pytest.approx(0.6)
    assert row["expires_at"] == "2026-11-26T01:23:20+00:00"
    assert clone.stats() == engine.stats()
    clone.ingest_feed("feed-a", [item("domain", "extra.example", ttl=600)], now=T0)
    assert engine.stats()["observations"] == 1
    assert clone.stats()["observations"] == 2


def test_restore_rejects_malformed_snapshot():
    engine = merger()
    source(engine, "feed-a")
    good = engine.snapshot()
    missing = dict(good)
    missing.pop("sources")
    wrong_type = dict(good)
    wrong_type["observations"] = []
    broken = [None, {}, {"version": 99}, missing, wrong_type]
    for bad in broken:
        with pytest.raises(ioc.IocError) as exc:
            engine.restore(bad)
        assert exc.value.code == "IOC_SNAPSHOT_INVALID"
    assert [row.name for row in engine.sources()] == ["feed-a"]
