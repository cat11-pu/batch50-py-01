import threading

import pytest

import sampler_voice_allocator as va


def allocator(**kwargs):
    return va.VoiceAllocator(**kwargs)


def test_note_on_allocates_increasing_voice_ids():
    a = allocator(polyphony=4)
    assert a.note_on(60) == 1
    assert a.note_on(64) == 2
    assert [v.note for v in a.active_voices()] == [60, 64]
    assert [v.voice_id for v in a.active_voices()] == [1, 2]
    assert a.voice_count() == 2
    assert a.stats()["note_ons"] == 2


def test_note_on_rejects_out_of_range_note():
    a = allocator()
    for bad in (-1, 128):
        with pytest.raises(va.VoiceError) as exc:
            a.note_on(bad)
        assert exc.value.code == "INVALID_NOTE"
    assert a.voice_count() == 0
    assert a.stats()["note_ons"] == 0


def test_polyphony_limit_steals_oldest_voice():
    a = allocator(polyphony=2)
    first = a.note_on(60)
    second = a.note_on(64)
    third = a.note_on(67)
    assert third > second > first
    assert a.voice_count() == 2
    assert [v.note for v in a.active_voices()] == [64, 67]
    assert [v.voice_id for v in a.active_voices()] == [second, third]
    assert a.stats()["steals"] == 1


def test_priority_overrides_age_for_steal_victim():
    a = allocator(polyphony=2)
    a.set_priority("pad", 1)
    a.set_priority("lead", 9)
    pad = a.note_on(60, sample_id="pad")
    lead = a.note_on(64, sample_id="lead")
    fresh = a.note_on(67, sample_id="lead")
    remaining = [v.voice_id for v in a.active_voices()]
    assert pad not in remaining
    assert lead in remaining
    assert fresh in remaining
    assert a.stats()["steals"] == 1


def test_set_polyphony_rejects_non_positive_value():
    a = allocator()
    for bad in (0, -3):
        with pytest.raises(va.VoiceError) as exc:
            a.set_polyphony(bad)
        assert exc.value.code == "INVALID_POLYPHONY"
    assert a.stats()["polyphony"] == 8


def test_set_polyphony_shrink_steals_excess_voices():
    a = allocator(polyphony=8)
    for note in (60, 62, 64, 65, 67, 69):
        a.note_on(note)
    assert a.set_polyphony(4) == 4
    assert a.voice_count() == 4
    assert [v.voice_id for v in a.active_voices()] == [3, 4, 5, 6]
    assert a.stats()["steals"] == 2


def test_note_off_releases_voice():
    a = allocator(polyphony=4)
    a.note_on(60)
    a.note_on(64)
    assert a.note_off(60) == 1
    assert a.voice_count() == 1
    assert [v.note for v in a.active_voices()] == [64]
    assert a.stats()["note_offs"] == 1


def test_note_off_unknown_note_returns_zero():
    a = allocator(polyphony=4)
    a.note_on(60)
    assert a.note_off(72) == 0
    assert a.voice_count() == 1
    assert a.stats()["note_offs"] == 0


def test_steal_returns_victim_and_none_when_absent():
    a = allocator(polyphony=4)
    held = a.note_on(60)
    assert a.steal(60) == held
    assert a.voice_count() == 0
    assert a.steal(60) is None
    assert a.stats()["steals"] == 1


def test_group_exclusive_keeps_single_active_voice():
    a = allocator(polyphony=4)
    a.note_on(60, group="keys")
    a.note_on(62, group="keys")
    assert len(a.group_voices("keys")) == 1
    assert [v.note for v in a.active_voices()] == [62]
    assert a.voice_count() == 1
    assert a.stats()["steals"] == 1


def test_sample_limit_rejects_extra_instance():
    a = allocator(polyphony=8)
    a.set_sample_limit("kick", 2)
    a.note_on(36, sample_id="kick")
    a.note_on(38, sample_id="kick")
    with pytest.raises(va.VoiceError) as exc:
        a.note_on(40, sample_id="kick")
    assert exc.value.code == "SAMPLE_LIMIT"
    assert a.voice_count() == 2
    assert [v.sample_id for v in a.active_voices()] == ["kick", "kick"]


def test_panic_releases_all_voices():
    a = allocator(polyphony=8)
    a.note_on(60, group="keys")
    a.note_on(64, group="keys")
    a.note_on(36)
    assert a.voice_count() == 2
    assert a.panic() == 2
    assert a.voice_count() == 0
    assert a.group_voices("keys") == []
    assert a.stats()["panics"] == 1


def test_snapshot_restore_keeps_voices_and_priority_table():
    a = allocator(polyphony=4)
    a.set_priority("pad", 3)
    a.set_sample_limit("kick", 2)
    a.note_on(60, sample_id="pad")
    a.note_on(36, sample_id="kick")
    snap = a.snapshot()
    clone = allocator()
    clone.restore(snap)
    assert clone.stats() == a.stats()
    assert [(v.voice_id, v.note, v.sample_id) for v in clone.active_voices()] == [
        (1, 60, "pad"),
        (2, 36, "kick"),
    ]
    assert clone.note_on(64, sample_id="pad") == 3
    assert clone.active_voices()[-1].priority == 3


def test_restore_rejects_malformed_state_without_touching_voices():
    a = allocator(polyphony=4)
    a.note_on(60)
    before = a.stats()
    bad_states = (None, {}, {"version": 1}, {"version": 1, "voices": "nope"})
    for bad in bad_states:
        with pytest.raises(va.VoiceError) as exc:
            a.restore(bad)
        assert exc.value.code == "SNAPSHOT_INVALID"
    assert a.stats() == before
    assert [v.note for v in a.active_voices()] == [60]


def test_concurrent_note_on_respects_polyphony():
    a = allocator(polyphony=4)
    errors = []
    barrier = threading.Barrier(16)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            a.note_on(20 + index)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert a.voice_count() == 4
    assert a.stats()["note_ons"] == 16
    assert a.stats()["steals"] == 12
