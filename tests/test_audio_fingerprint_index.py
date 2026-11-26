import copy
import threading

import pytest

import audio_fingerprint_index as afi


def index(**kwargs):
    return afi.AudioFingerprintIndex(**kwargs)


def test_index_stores_entry_and_counters():
    store = index(capacity=8)
    entry = store.index("clip-a", hashes=[7, 3, 5], meta={"source": "sfx"})
    assert entry.clip_id == "clip-a"
    assert entry.hashes == (3, 5, 7)
    assert entry.indexed_seq == 1
    assert entry.last_hit_seq == 1
    assert entry.meta == (("source", "sfx"),)
    assert store.size() == 1
    assert store.entry_of("clip-a") == entry
    assert store.entries() == (entry,)
    assert store.capacity() == 8
    assert store.stats() == {"indexed": 1, "reindexed": 0, "removed": 0,
                             "evicted": 0, "queries": 0, "duplicates": 0,
                             "reviews": 0, "resolved": 0}


def test_index_rejects_invalid_input():
    store = index()
    bad_calls = [
        dict(clip_id="", hashes=[1, 2, 3]),
        dict(clip_id="   ", hashes=[1, 2, 3]),
        dict(clip_id="clip-a", hashes=[]),
        dict(clip_id="clip-a", hashes=[1, "2"]),
        dict(clip_id="clip-a", hashes=[-3]),
    ]
    for kwargs in bad_calls:
        with pytest.raises(afi.FingerprintError) as exc:
            store.index(**kwargs)
        assert exc.value.code == "AUDIO_FP_INVALID"
    assert store.size() == 0
    assert store.stats()["indexed"] == 0


def test_repeated_hashes_collapse_to_one_fingerprint():
    store = index()
    entry = store.index("clip-a", hashes=[5, 5, 7, 5])
    assert entry.hashes == (5, 7)
    matches = store.query([5, 7, 9])
    assert len(matches) == 1
    assert matches[0].clip_id == "clip-a"
    assert matches[0].hits == 2
    assert matches[0].similarity == 1.0
    assert matches[0].verdict == "below"


def test_reindex_replaces_hashes_without_doubling_hits():
    store = index()
    first = store.index("clip-a", hashes=[1, 2, 3])
    second = store.index("clip-a", hashes=[10, 11, 12, 13, 14])
    assert second.hashes == (10, 11, 12, 13, 14)
    assert second.indexed_seq == first.indexed_seq
    assert second.last_hit_seq == 2
    assert store.size() == 1
    assert store.stats()["indexed"] == 1
    assert store.stats()["reindexed"] == 1
    matches = store.query([10, 11, 12, 13, 14])
    assert len(matches) == 1
    assert matches[0].hits == 5
    assert matches[0].verdict == "duplicate"


def test_query_exact_match_is_duplicate():
    store = index()
    store.index("clip-a", hashes=[1, 2, 3, 4, 5, 6])
    matches = store.query([1, 2, 3, 4, 5, 6])
    assert len(matches) == 1
    assert matches[0].hits == 6
    assert matches[0].similarity == 1.0
    assert matches[0].verdict == "duplicate"
    assert store.stats()["queries"] == 1
    assert store.stats()["duplicates"] == 1
    assert store.stats()["reviews"] == 0


def test_query_similarity_uses_shorter_side():
    store = index()
    store.index("clip-a", hashes=[1, 2, 3, 4, 5, 6])
    matches = store.query([1, 2, 3])
    assert len(matches) == 1
    assert matches[0].hits == 3
    assert matches[0].similarity == 1.0
    assert matches[0].verdict == "below"


def test_query_without_overlap_returns_nothing():
    store = index()
    store.index("clip-a", hashes=[1, 2, 3, 4, 5, 6])
    assert store.query([7, 8]) == ()
    assert store.stats()["queries"] == 1
    assert store.stats()["duplicates"] == 0


def test_query_results_sorted_by_hits_then_clip_id():
    store = index()
    store.index("beta", hashes=[1, 2, 20, 21])
    store.index("alpha", hashes=[1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    store.index("aaa", hashes=[1, 2, 30, 31])
    matches = store.query([1, 2, 3, 4, 5, 6, 7, 8, 9, 10])
    assert [match.clip_id for match in matches] == ["alpha", "aaa", "beta"]
    assert [match.hits for match in matches] == [10, 2, 2]
    assert [match.verdict for match in matches] == ["duplicate", "below", "below"]


def test_query_rejects_empty_or_invalid_hashes():
    store = index()
    store.index("clip-a", hashes=[1, 2, 3])
    for bad in ([], [1, "x"], [-1]):
        with pytest.raises(afi.FingerprintError) as exc:
            store.query(bad)
        assert exc.value.code == "AUDIO_FP_INVALID"
    assert store.stats()["queries"] == 0


def test_remove_is_idempotent():
    store = index()
    store.index("clip-a", hashes=[1, 2, 3])
    store.index("clip-b", hashes=[4, 5, 6])
    assert store.remove("clip-a") is True
    assert store.remove("clip-a") is False
    assert store.size() == 1
    assert store.entry_of("clip-a") is None
    assert store.stats()["removed"] == 1


def test_set_capacity_validates_and_shrinks():
    store = index(capacity=3)
    store.index("clip-a", hashes=[1, 2, 3, 4])
    store.index("clip-b", hashes=[30, 31, 32, 33])
    store.index("clip-c", hashes=[40, 41, 42, 43])
    store.query([1, 2])
    assert store.set_capacity(1) == 1
    assert store.capacity() == 1
    assert store.size() == 1
    assert store.entry_of("clip-a") is not None
    assert store.entry_of("clip-b") is None
    assert store.entry_of("clip-c") is None
    assert store.stats()["evicted"] == 2
    for bad in (0, -1, "2"):
        with pytest.raises(afi.FingerprintError) as exc:
            store.set_capacity(bad)
        assert exc.value.code == "AUDIO_FP_INVALID"


def test_evict_removes_least_recently_hit_entry():
    store = index(capacity=2)
    store.index("clip-a", hashes=[1, 2, 3, 4])
    store.index("clip-b", hashes=[30, 31, 32, 33])
    store.query([1, 2])
    assert store.evict() == "clip-b"
    assert store.size() == 1
    assert store.entry_of("clip-b") is None
    assert store.evict() is None
    assert store.stats()["evicted"] == 1


def test_index_auto_evicts_when_full():
    store = index(capacity=2)
    store.index("clip-a", hashes=[1, 2, 3, 4])
    store.index("clip-b", hashes=[30, 31, 32, 33])
    store.query([1, 2])
    store.index("clip-c", hashes=[7, 8, 9])
    assert store.size() == 2
    assert store.entry_of("clip-a") is not None
    assert store.entry_of("clip-c") is not None
    assert store.entry_of("clip-b") is None
    assert store.stats()["evicted"] == 1
    assert store.stats()["indexed"] == 3


def test_snapshot_roundtrip_and_invalid_restore():
    store = index(capacity=4)
    store.index("clip-a", hashes=[1, 2, 3, 4, 5], meta={"tag": "jingle"})
    store.index("clip-b", hashes=[4, 5, 6])
    store.query([1, 2])
    state = store.snapshot()
    pristine = copy.deepcopy(state)
    assert set(state) == {"version", "capacity", "entries", "reviews",
                          "sequence", "stats"}
    state["entries"].clear()
    state["stats"]["queries"] = 99
    assert store.size() == 2
    assert store.stats()["queries"] == 1
    clone = index(capacity=1)
    clone.restore(pristine)
    assert clone.capacity() == 4
    assert clone.size() == 2
    assert clone.entry_of("clip-a").hashes == (1, 2, 3, 4, 5)
    assert clone.entry_of("clip-a").meta == (("tag", "jingle"),)
    assert clone.query([1, 2, 3, 4, 5])[0].verdict == "duplicate"
    assert clone.stats()["queries"] == 2
    bad_states = [
        None,
        {},
        {"version": 2, "capacity": 4, "entries": {}, "reviews": [],
         "sequence": 1, "stats": {}},
        {"version": 1, "capacity": 0, "entries": {}, "reviews": [],
         "sequence": 1, "stats": {"indexed": 1}},
        {"version": 1, "capacity": 4, "entries": "nope", "reviews": [],
         "sequence": 1, "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(afi.FingerprintError) as exc:
            clone.restore(bad)
        assert exc.value.code == "AUDIO_FP_SNAPSHOT_INVALID"
    assert clone.size() == 2
    assert clone.entry_of("clip-b") is not None


def test_concurrent_index_registers_all_clips():
    store = index(capacity=64)
    errors = []
    barrier = threading.Barrier(12)

    def worker(number):
        try:
            barrier.wait(timeout=5)
            store.index(f"clip-{number:02d}",
                        hashes=[number + 1, number + 2, number + 3])
        except Exception as exc:  # pragma: no cover - reported via errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(number,))
               for number in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert store.size() == 12
    assert store.stats()["indexed"] == 12
    assert [entry.clip_id for entry in store.entries()] == [
        f"clip-{number:02d}" for number in range(12)]
