import copy
import threading

import pytest

import voice_stealing_allocator as va


def alloc(**kwargs):
    return va.VoiceStealingAllocator(**kwargs)


def test_request_allocates_slot_on_free_pool():
    pool = alloc(capacity=4)
    slot = pool.request_voice("ambient-wind", priority=3, distance=2.5, frame=10)
    assert slot.voice_id == "voice-0001"
    assert slot.source_id == "ambient-wind"
    assert slot.priority == 3
    assert slot.distance == 2.5
    assert slot.started_frame == 10
    assert slot.last_used_frame == 10
    assert slot.state == "live"
    assert pool.voice_of("ambient-wind") == slot
    assert pool.voices() == (slot,)
    assert pool.free_slots() == 3
    assert pool.stats() == {"requests": 1, "duplicates": 0, "refused": 0,
                            "steals": 0, "evictions": 0, "recovered": 0,
                            "expired": 0}


def test_duplicate_request_reuses_existing_slot():
    pool = alloc(capacity=4)
    first = pool.request_voice("machine-hum", priority=1, frame=5)
    again = pool.request_voice("machine-hum", priority=9, distance=4.0, frame=7)
    assert again.voice_id == first.voice_id
    assert again.priority == 1
    assert again.distance == 0.0
    assert again.started_frame == 5
    assert again.last_used_frame == 7
    assert len(pool.voices()) == 1
    assert pool.voice_of("machine-hum").last_used_frame == 7
    stats = pool.stats()
    assert stats["requests"] == 2
    assert stats["duplicates"] == 1
    assert stats["steals"] == 0


def test_invalid_request_is_rejected():
    pool = alloc()
    bad_calls = [
        dict(source_id="   ", priority=1, distance=0.0),
        dict(source_id="s", priority=16, distance=0.0),
        dict(source_id="s", priority=-1, distance=0.0),
        dict(source_id="s", priority="3", distance=0.0),
        dict(source_id="s", priority=1, distance=-0.5),
    ]
    for kwargs in bad_calls:
        with pytest.raises(va.VoiceError) as exc:
            pool.request_voice(**kwargs)
        assert exc.value.code == "AUDIO_VOICE_INVALID"
    assert pool.stats()["requests"] == 0
    assert pool.voices() == ()


def test_same_priority_steals_farther_voice():
    pool = alloc(capacity=1)
    near = pool.request_voice("near-voice", priority=5, distance=1.0, frame=0)
    fresh = pool.request_voice("close-voice", priority=5, distance=0.5, frame=1)
    assert fresh is not None
    assert fresh.source_id == "close-voice"
    assert fresh.started_frame == 1
    assert fresh.state == "live"
    assert pool.voice_of("near-voice") is None
    queued = pool.virtual_queue()
    assert [item.source_id for item in queued] == ["near-voice"]
    assert queued[0].reason == "stolen"
    assert queued[0].requested_frame == near.started_frame
    assert [slot.source_id for slot in pool.voices()] == ["close-voice"]
    assert pool.stats()["steals"] == 1


def test_higher_priority_steals_weakest_voice():
    pool = alloc(capacity=2)
    pool.request_voice("low-priority", priority=1, distance=9.0, frame=0)
    pool.request_voice("mid-priority", priority=5, distance=1.0, frame=0)
    fresh = pool.request_voice("boss-voice", priority=9, distance=8.0, frame=2)
    assert fresh is not None
    assert fresh.voice_id == "voice-0003"
    assert [slot.source_id for slot in pool.voices()] == ["mid-priority",
                                                          "boss-voice"]
    assert [item.source_id for item in pool.virtual_queue()] == ["low-priority"]
    assert pool.stats()["steals"] == 1
    assert pool.free_slots() == 0


def test_weaker_request_is_refused():
    pool = alloc(capacity=1)
    live = pool.request_voice("held", priority=8, distance=1.0, frame=0)
    assert pool.request_voice("equal-far", priority=8, distance=2.0, frame=1) is None
    assert pool.request_voice("weaker", priority=3, distance=0.1, frame=1) is None
    assert pool.voice_of("held") == live
    assert len(pool.virtual_queue()) == 0
    stats = pool.stats()
    assert stats["refused"] == 2
    assert stats["steals"] == 0


def test_release_fades_then_frees_slot():
    pool = alloc(capacity=2, fade_frames=2)
    slot = pool.request_voice("door-creak", priority=4, frame=3)
    pool.release(slot.voice_id)
    fading = pool.voices(state="fading")
    assert len(fading) == 1
    assert fading[0].voice_id == slot.voice_id
    assert fading[0].state == "fading"
    assert pool.free_slots() == 1
    first_tick = pool.tick()
    assert first_tick["frame"] == 4
    assert first_tick["expired"] == 0
    assert len(pool.voices(state="fading")) == 1
    second_tick = pool.tick()
    assert second_tick["frame"] == 5
    assert pool.voices() == ()
    assert pool.free_slots() == 2


def test_release_unknown_voice_is_rejected():
    pool = alloc(capacity=2)
    with pytest.raises(va.VoiceError) as exc:
        pool.release("voice-9999")
    assert exc.value.code == "AUDIO_UNKNOWN_VOICE"
    slot = pool.request_voice("pad", priority=1, frame=0)
    pool.release(slot.voice_id)
    with pytest.raises(va.VoiceError) as exc:
        pool.release(slot.voice_id)
    assert exc.value.code == "AUDIO_UNKNOWN_VOICE"
    assert pool.stats()["steals"] == 0


def test_preempt_moves_voice_to_virtual_queue():
    pool = alloc(capacity=2)
    slot = pool.request_voice("alarm", priority=6, distance=0.0, frame=12)
    entry = pool.preempt(slot.voice_id, reason="scene-cut")
    assert entry.source_id == "alarm"
    assert entry.priority == 6
    assert entry.distance == 0.0
    assert entry.requested_frame == 12
    assert entry.reason == "scene-cut"
    assert entry.entry_id == "virtual-0001"
    assert pool.voice_of("alarm") is None
    assert pool.free_slots() == 2
    assert pool.stats()["steals"] == 1
    with pytest.raises(va.VoiceError) as exc:
        pool.preempt("voice-9999")
    assert exc.value.code == "AUDIO_UNKNOWN_VOICE"


def test_virtual_queue_is_ordered_by_priority_then_distance():
    pool = alloc(capacity=1, virtual_timeout=500)
    first = pool.request_voice("one", priority=1, distance=0.0, frame=0)
    pool.preempt(first.voice_id)
    second = pool.request_voice("two", priority=3, distance=5.0, frame=1)
    pool.preempt(second.voice_id)
    third = pool.request_voice("three", priority=3, distance=1.0, frame=2)
    pool.preempt(third.voice_id)
    assert [item.source_id for item in pool.virtual_queue()] == [
        "three", "two", "one"]
    assert [item.entry_id for item in pool.virtual_queue()] == [
        "virtual-0003", "virtual-0002", "virtual-0001"]


def test_tick_recovers_up_to_free_slots():
    pool = alloc(capacity=2, virtual_timeout=500)
    pool.request_voice("bed", priority=1, frame=0)
    second = pool.request_voice("crowd", priority=4, frame=1)
    pool.preempt(second.voice_id)
    third = pool.request_voice("drum", priority=7, frame=2)
    pool.preempt(third.voice_id)
    assert [item.source_id for item in pool.virtual_queue()] == ["drum", "crowd"]
    result = pool.tick()
    assert result["frame"] == 3
    assert result["expired"] == 0
    assert len(result["recovered"]) == 1
    assert pool.voice_of("drum") is not None
    assert pool.voice_of("crowd") is None
    assert result["recovered"][0] == pool.voice_of("drum").voice_id
    assert [item.source_id for item in pool.virtual_queue()] == ["crowd"]
    assert pool.stats()["recovered"] == 1
    assert len(pool.voices()) == 2


def test_set_capacity_resizes_pool():
    pool = alloc(capacity=3)
    pool.request_voice("low", priority=1, frame=0)
    pool.request_voice("mid", priority=5, frame=0)
    pool.request_voice("top", priority=9, frame=0)
    assert pool.set_capacity(1) == 1
    assert [slot.source_id for slot in pool.voices()] == ["top"]
    assert [item.source_id for item in pool.virtual_queue()] == ["mid", "low"]
    assert pool.stats()["evictions"] == 2
    assert pool.free_slots() == 0
    assert pool.set_capacity(4) == 4
    assert pool.free_slots() == 3
    with pytest.raises(va.VoiceError) as exc:
        pool.set_capacity(0)
    assert exc.value.code == "AUDIO_VOICE_INVALID"


def test_snapshot_roundtrip_preserves_frame_and_queue():
    pool = alloc(capacity=3)
    live = pool.request_voice("live-one", priority=5, frame=4)
    queued = pool.request_voice("queued-one", priority=7, frame=6)
    pool.preempt(queued.voice_id, reason="focus")
    state = pool.snapshot()
    pristine = copy.deepcopy(state)
    assert set(state) == {"version", "capacity", "frame", "voices", "virtual",
                          "stats"}
    state["voices"].clear()
    state["stats"]["steals"] = 99
    assert pool.voice_of("live-one") == live
    assert pool.stats()["steals"] == 1
    clone = alloc(capacity=1)
    clone.restore(pristine)
    assert clone.voice_of("live-one") == live
    assert clone.virtual_queue()[0].source_id == "queued-one"
    assert clone.free_slots() == 2
    fresh = clone.request_voice("after-restore", priority=2)
    assert fresh.started_frame == 6


def test_restore_rejects_malformed_state_without_mutation():
    pool = alloc(capacity=2)
    slot = pool.request_voice("anchor", priority=3, frame=9)
    bad_states = [
        None,
        {},
        {"version": 2, "capacity": 2, "frame": 0, "voices": [],
         "virtual": [], "stats": {}},
        {"version": 1, "capacity": 2, "frame": 0, "voices": "nope",
         "virtual": [], "stats": {}},
        {"version": 1, "capacity": 0, "frame": 0, "voices": [],
         "virtual": [], "stats": {"requests": 0}},
    ]
    for bad in bad_states:
        with pytest.raises(va.VoiceError) as exc:
            pool.restore(bad)
        assert exc.value.code == "AUDIO_VOICE_SNAPSHOT_INVALID"
    assert pool.voice_of("anchor") == slot
    assert pool.stats()["requests"] == 1


def test_concurrent_requests_respect_capacity():
    pool = alloc(capacity=8)
    errors = []
    barrier = threading.Barrier(32)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            pool.request_voice(f"source-{index:02d}", priority=5,
                               distance=float(index))
        except Exception as exc:  # pragma: no cover - reported via errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(32)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    live = pool.voices()
    assert len(live) == 8
    assert len({slot.source_id for slot in live}) == 8
    stats = pool.stats()
    assert stats["requests"] == 32
    assert stats["duplicates"] == 0
    assert stats["steals"] + stats["refused"] == 24
    assert pool.free_slots() == 0
