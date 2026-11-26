import copy
import threading

import pytest

import static_shadow_cache as sc


def cache(**kwargs):
    return sc.StaticShadowCache(**kwargs)


def three(capacity=4):
    c = cache(capacity=capacity)
    c.register("a", transform=(0.0, 0.0, 0.0), material="rock")
    c.register("b", transform=(1.0, 0.0, 0.0), material="wood")
    c.register("c", transform=(2.0, 0.0, 0.0), material="rock")
    return c


def test_register_validates_objects():
    c = cache()
    record = c.register("rock", transform=(1.0, 2.0, 3.0), material="stone",
                        lod=2)
    assert record.object_id == "rock"
    assert record.transform == (1.0, 2.0, 3.0)
    assert record.material == "stone"
    assert record.lod == 2
    with pytest.raises(sc.ShadowCacheError) as exc:
        c.register("rock")
    assert exc.value.code == "SHADOW_INVALID_INPUT"
    for kwargs in (dict(transform=(0.0, 0.0)),
                   dict(transform=(0.0, 0.0, float("nan"))),
                   dict(material="   "),
                   dict(lod=-1),
                   dict(lod=1.5)):
        with pytest.raises(sc.ShadowCacheError) as exc:
            c.register("stone-1", **kwargs)
        assert exc.value.code == "SHADOW_INVALID_INPUT"
    with pytest.raises(sc.ShadowCacheError) as exc:
        c.register("", material="rock")
    assert exc.value.code == "SHADOW_INVALID_INPUT"
    with pytest.raises(sc.ShadowCacheError) as exc:
        c.lookup("ghost")
    assert exc.value.code == "SHADOW_UNKNOWN_OBJECT"


def test_tick_advances_the_frame():
    c = three()
    assert c.stats()["frame"] == 0
    assert c.tick() == 1
    assert c.tick() == 2
    assert c.stats()["frame"] == 2
    assert c.stats()["objects"] == 3


def test_acquire_allocates_the_lowest_free_slot():
    c = three(capacity=3)
    c.tick()
    assert c.acquire_slot("a") == 0
    assert c.acquire_slot("b") == 1
    assert c.acquire_slot("c") == 2
    c.register("d", transform=(3.0, 0.0, 0.0), material="rock")
    with pytest.raises(sc.ShadowCacheError) as exc:
        c.acquire_slot("d")
    assert exc.value.code == "SHADOW_CAPACITY_EXCEEDED"
    assert c.lookup("d").slot is None
    assert c.stats()["evictions"] == 0


def test_refresh_renders_once_then_reuses():
    c = cache(capacity=2)
    c.register("rock", transform=(0.0, 1.0, 0.0), material="stone", lod=1)
    c.tick()
    assert c.acquire_slot("rock") == 0
    first = c.refresh("rock")
    assert first.object_id == "rock"
    assert first.slot == 0
    assert first.frame == 1
    assert first.generation == 1
    assert first.rendered is True
    assert first.payload == {"object": "rock", "transform": (0.0, 1.0, 0.0),
                             "material": "stone", "lod": 1, "generation": 1}
    second = c.refresh("rock")
    assert second.rendered is False
    assert second.generation == 1
    assert second.payload == first.payload
    stats = c.stats()
    assert stats["renders"] == 1
    assert stats["reuse_hits"] == 1


def test_invalidate_coalesces_within_one_frame():
    c = cache(capacity=2)
    c.register("rock", material="stone")
    c.tick()
    c.refresh("rock")
    assert c.invalidate("rock", "transform") is True
    assert c.invalidate("rock", "material") is False
    assert c.invalidate("rock", "lod") is False
    rendered = c.refresh("rock")
    assert rendered.rendered is True
    assert rendered.generation == 2
    again = c.refresh("rock")
    assert again.rendered is False
    stats = c.stats()
    assert stats["renders"] == 2
    assert stats["invalidations"] == 3


def test_invalidate_validates_object_and_reason():
    c = cache(capacity=2)
    c.register("rock", material="stone")
    c.tick()
    c.refresh("rock")
    with pytest.raises(sc.ShadowCacheError) as exc:
        c.invalidate("ghost", "transform")
    assert exc.value.code == "SHADOW_UNKNOWN_OBJECT"
    with pytest.raises(sc.ShadowCacheError) as exc:
        c.invalidate("rock", "sun")
    assert exc.value.code == "SHADOW_INVALID_INPUT"
    info = c.lookup("rock")
    assert info.dirty is False
    assert info.generation == 1
    assert c.stats()["renders"] == 1


def test_release_slot_frees_and_reuses_the_index():
    c = cache(capacity=2)
    c.register("a", material="rock")
    c.register("b", material="wood")
    c.register("c", material="rock")
    c.tick()
    assert c.acquire_slot("a") == 0
    assert c.acquire_slot("b") == 1
    assert c.release_slot("a") is True
    assert c.release_slot("a") is False
    info = c.lookup("a")
    assert info.slot is None
    assert info.dirty is True
    assert c.acquire_slot("c") == 0
    assert c.stats()["evictions"] == 0


def test_lru_eviction_skips_current_frame_use():
    c = three(capacity=2)
    c.tick()
    assert c.refresh("a").slot == 0
    assert c.refresh("b").slot == 1
    c.tick()
    c.refresh("a")
    assert c.acquire_slot("c") == 1
    assert c.lookup("b").slot is None
    assert c.lookup("a").slot == 0
    assert c.stats()["evictions"] == 1
    assert c.stats()["slotted"] == 2


def test_capacity_error_when_every_slot_is_in_use():
    c = cache(capacity=1)
    c.register("a", material="rock")
    c.register("b", material="wood")
    c.tick()
    c.refresh("a")
    with pytest.raises(sc.ShadowCacheError) as exc:
        c.acquire_slot("b")
    assert exc.value.code == "SHADOW_CAPACITY_EXCEEDED"
    assert c.lookup("b").slot is None
    assert c.stats()["evictions"] == 0


def test_resize_shrinks_by_lru_and_rejects_bad_capacity():
    c = three(capacity=3)
    c.register("d", transform=(3.0, 0.0, 0.0), material="wood")
    c.tick()
    c.refresh("a")
    c.refresh("b")
    c.refresh("c")
    c.tick()
    c.refresh("a")
    assert c.resize(1) == 2
    assert c.capacity == 1
    assert c.lookup("a").slot == 0
    assert c.lookup("b").slot is None
    assert c.lookup("c").slot is None
    assert c.stats()["evictions"] == 2
    with pytest.raises(sc.ShadowCacheError) as exc:
        c.resize(0)
    assert exc.value.code == "SHADOW_INVALID_CAPACITY"
    assert c.capacity == 1
    tight = cache(capacity=2)
    tight.register("a", material="rock")
    tight.register("b", material="wood")
    tight.tick()
    tight.refresh("a")
    tight.refresh("b")
    with pytest.raises(sc.ShadowCacheError) as exc:
        tight.resize(1)
    assert exc.value.code == "SHADOW_CAPACITY_EXCEEDED"
    assert tight.capacity == 2
    assert tight.lookup("a").slot == 0
    assert tight.lookup("b").slot == 1


def test_resize_grows_without_eviction():
    c = cache(capacity=1)
    c.register("a", material="rock")
    c.register("b", material="wood")
    c.tick()
    assert c.refresh("a").slot == 0
    assert c.resize(4) == 0
    assert c.capacity == 4
    assert c.acquire_slot("b") == 1
    assert c.stats()["evictions"] == 0
    assert c.stats()["slotted"] == 2


def test_concurrent_refresh_renders_once():
    c = cache(capacity=2)
    c.register("a", material="rock")
    c.tick()
    results = []
    failures = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(c.refresh("a"))
        except Exception as exc:  # noqa: BLE001 - reported through failures
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert len(results) == 8
    assert sum(1 for item in results if item.rendered) == 1
    assert len({item.generation for item in results}) == 1
    assert c.stats()["renders"] == 1
    assert c.lookup("a").generation == 1


def test_snapshot_roundtrip_keeps_frame_and_slots():
    c = cache(capacity=3)
    c.register("a", material="rock")
    c.register("b", material="wood")
    c.tick()
    assert c.refresh("a").slot == 0
    assert c.refresh("b").slot == 1
    c.tick()
    c.refresh("a")
    c.invalidate("b", "material")
    state = c.snapshot()
    assert set(state) == {"version", "capacity", "frame", "objects", "slots",
                          "entries", "counters", "use_seq"}
    pristine = copy.deepcopy(state)
    state["slots"].clear()
    state["counters"]["renders"] = 99
    assert c.stats()["renders"] == 2

    clone = cache(capacity=1)
    clone.restore(pristine)
    stats = clone.stats()
    assert stats["frame"] == 2
    assert stats["capacity"] == 3
    assert stats["objects"] == 2
    assert stats["slotted"] == 2
    assert stats["renders"] == 2
    assert stats["reuse_hits"] == 1
    assert clone.lookup("a").slot == 0
    assert clone.lookup("a").generation == 1
    assert clone.lookup("b").dirty is True
    assert clone.tick() == 3
    redo = clone.refresh("b")
    assert redo.rendered is True
    assert redo.generation == 2
    assert clone.stats()["renders"] == 3
    clone.register("c", material="rock")
    assert clone.acquire_slot("c") == 2
    assert clone.stats()["slotted"] == 3
    assert clone.stats()["evictions"] == 0
    clone.register("d", material="wood")
    assert clone.acquire_slot("d") == 0
    assert clone.lookup("a").slot is None
    assert clone.lookup("b").slot == 1
    assert clone.stats()["evictions"] == 1


def test_restore_rejects_malformed_snapshots():
    c = three(capacity=2)
    c.tick()
    c.refresh("a")
    valid = c.snapshot()
    bad_snapshots = [
        None,
        {},
        dict(valid, version=2),
        dict(valid, capacity=0),
        dict(valid, frame=-1),
        dict(valid, objects="none"),
        dict(valid, slots=[[9, "a"]]),
        dict(valid, entries=[]),
        dict(valid, counters=[]),
        {key: value for key, value in valid.items() if key != "entries"},
    ]
    for snapshot in bad_snapshots:
        with pytest.raises(sc.ShadowCacheError) as exc:
            c.restore(snapshot)
        assert exc.value.code == "SHADOW_SNAPSHOT_INVALID"
    assert c.stats()["frame"] == 1
    assert c.stats()["renders"] == 1
    assert c.lookup("a").slot == 0


def test_stats_counts_each_event():
    c = three(capacity=2)
    assert c.tick() == 1
    c.refresh("a")
    c.refresh("a")
    c.refresh("b")
    c.invalidate("a")
    c.refresh("a")
    assert c.tick() == 2
    c.refresh("a")
    c.acquire_slot("c")
    c.release_slot("a")
    stats = c.stats()
    assert stats["frame"] == 2
    assert stats["capacity"] == 2
    assert stats["objects"] == 3
    assert stats["slotted"] == 1
    assert stats["renders"] == 3
    assert stats["evictions"] == 1
    assert stats["invalidations"] == 1
    assert stats["reuse_hits"] == 2
