import copy
import threading

import pytest

import audio_track_selector as ats


def selector(**kwargs):
    return ats.AudioTrackSelector(**kwargs)


def test_add_track_and_available_listing():
    sel = selector()
    english = sel.add_track("tr-en", language="en", keyframes=(0, 48),
                            codec="aac", channels=2, bitrate=192000)
    japanese = sel.add_track("tr-ja", language="ja", keyframes=(0,),
                             codec="opus", channels=6)
    assert english.track_id == "tr-en"
    assert english.language == "en"
    assert english.codec == "aac"
    assert english.channels == 2
    assert english.bitrate == 192000
    assert english.keyframes == (0, 48)
    assert japanese.track_id == "tr-ja"
    assert japanese.channels == 6
    assert [track.track_id for track in sel.available()] == ["tr-en", "tr-ja"]
    assert [track.track_id for track in sel.available(language="ja")] == ["tr-ja"]
    assert sel.available(language="de") == ()
    assert sel.current() is None
    assert sel.active_tracks() == ()


def test_add_track_validation_and_duplicates():
    sel = selector()
    bad_calls = [
        dict(track_id="", language="en"),
        dict(track_id="t", language="   "),
        dict(track_id="t", language="en", keyframes=(0, 0)),
        dict(track_id="t", language="en", keyframes=(-1,)),
        dict(track_id="t", language="en", bitrate=0),
        dict(track_id="t", language="en", channels=0),
    ]
    for kwargs in bad_calls:
        with pytest.raises(ats.TrackError) as exc:
            sel.add_track(**kwargs)
        assert exc.value.code == "AUDIO_TRACK_INVALID"
    sel.add_track("tr-en", language="en")
    with pytest.raises(ats.TrackError) as exc:
        sel.add_track("tr-en", language="en", codec="opus")
    assert exc.value.code == "AUDIO_TRACK_EXISTS"


def test_device_capabilities_filter_available_tracks():
    sel = selector()
    sel.add_track("a-aac", language="en", codec="aac", channels=2)
    sel.add_track("b-aac6", language="en", codec="aac", channels=6)
    sel.add_track("c-opus", language="en", codec="opus", channels=2)
    sel.set_device(codecs=("opus",), max_channels=2)
    assert [track.track_id for track in sel.available()] == ["c-opus"]
    with pytest.raises(ats.TrackError) as exc:
        sel.set_device(codecs=())
    assert exc.value.code == "AUDIO_DEVICE_INVALID"
    with pytest.raises(ats.TrackError) as exc:
        sel.set_device(max_channels=0)
    assert exc.value.code == "AUDIO_DEVICE_INVALID"


def test_set_preference_normalizes_input():
    sel = selector()
    assert sel.set_preference([" EN ", "ja", "en", "JA"]) == ("en", "ja")
    for bad in ([], ["  "], [5]):
        with pytest.raises(ats.TrackError) as exc:
            sel.set_preference(bad)
        assert exc.value.code == "AUDIO_PREFERENCE_INVALID"


def test_preload_existing_language_becomes_ready():
    sel = selector()
    sel.add_track("tr-en", language="en", keyframes=(0, 48))
    result = sel.preload("en")
    assert result.status == "ready"
    assert result.track_id == "tr-en"
    assert result.language == "en"
    assert result.reason is None
    assert sel.stats()["preloads"] == 1
    assert sel.stats()["preload_failures"] == 0


def test_preload_missing_language_is_reported():
    sel = selector()
    result = sel.preload("de")
    assert result.status == "missing"
    assert result.track_id is None
    assert result.reason == "no_track"
    assert sel.stats()["preload_failures"] == 1
    assert sel.stats()["preloads"] == 0


def test_preload_unsupported_codec_is_reported():
    sel = selector()
    sel.add_track("tr-en", language="en", codec="aac")
    sel.set_device(codecs=("opus",))
    result = sel.preload("en")
    assert result.status == "unsupported"
    assert result.track_id is None
    assert result.reason == "device"
    assert sel.stats()["preload_failures"] == 1


def test_switch_without_preload_is_refused():
    sel = selector()
    sel.add_track("tr-en", language="en", keyframes=(0,))
    with pytest.raises(ats.TrackError) as exc:
        sel.switch_to("en", position=0)
    assert exc.value.code == "AUDIO_PRELOAD_REQUIRED"
    assert sel.stats()["switches"] == 0


def test_switch_at_keyframe_applies_track():
    sel = selector()
    sel.add_track("tr-en", language="en", keyframes=(0, 48, 96))
    sel.add_track("tr-ja", language="ja", keyframes=(0, 24))
    sel.set_preference(["ja", "en"])
    sel.preload("en")
    result = sel.switch_to("en", position=48)
    assert result.status == "applied"
    assert result.track_id == "tr-en"
    assert result.language == "en"
    assert result.position == 48
    assert result.scheduled_at is None
    assert result.reason is None
    assert sel.current().track_id == "tr-en"
    assert len(sel.active_tracks()) == 1
    assert sel.active_tracks()[0].track_id == "tr-en"
    assert sel.stats()["switches"] == 1
    assert sel.stats()["queued"] == 0


def test_switch_to_current_language_is_unchanged():
    sel = selector()
    sel.add_track("tr-en", language="en", keyframes=(0, 48))
    sel.preload("en")
    first = sel.switch_to("en", position=0)
    assert first.status == "applied"
    second = sel.switch_to("en", position=48)
    assert second.status == "unchanged"
    assert second.track_id == "tr-en"
    assert second.scheduled_at is None
    assert sel.stats()["switches"] == 1
    assert sel.stats()["queued"] == 0
    assert len(sel.active_tracks()) == 1


def test_abort_preload_clears_window():
    sel = selector()
    sel.add_track("tr-en", language="en", keyframes=(0,))
    sel.preload("en")
    assert sel.abort_preload("en") == 1
    with pytest.raises(ats.TrackError) as exc:
        sel.switch_to("en", position=0)
    assert exc.value.code == "AUDIO_PRELOAD_REQUIRED"
    assert sel.abort_preload("en") == 0
    assert sel.stats()["aborts"] == 1


def test_preload_window_evicts_oldest_track():
    sel = selector(max_preloaded=2)
    for language in ("en", "ja", "fr"):
        sel.add_track(f"tr-{language}", language=language, keyframes=(0,))
    assert sel.preload("en").status == "ready"
    assert sel.preload("ja").status == "ready"
    third = sel.preload("fr")
    assert third.status == "ready"
    assert sel.stats()["preload_evictions"] == 1
    with pytest.raises(ats.TrackError) as exc:
        sel.switch_to("en", position=0)
    assert exc.value.code == "AUDIO_PRELOAD_REQUIRED"
    assert sel.switch_to("fr", position=0).status == "applied"


def test_snapshot_roundtrip_preserves_tracks_and_preloads():
    sel = selector()
    sel.add_track("tr-en", language="en", keyframes=(0, 48))
    sel.set_preference(["en", "ja"])
    sel.preload("en")
    assert sel.switch_to("en", position=0).status == "applied"
    sel.add_track("tr-ja", language="ja", keyframes=(0,))
    sel.preload("ja")
    state = sel.snapshot()
    pristine = copy.deepcopy(state)
    assert set(state) == {"version", "tracks", "preferences", "device",
                          "current", "preloaded", "queued", "position", "stats"}
    state["tracks"].clear()
    state["stats"]["switches"] = 99
    assert sel.current().track_id == "tr-en"
    assert sel.stats()["switches"] == 1
    clone = selector()
    clone.restore(pristine)
    assert clone.current().track_id == "tr-en"
    assert [track.track_id for track in clone.available(language="ja")] == ["tr-ja"]
    assert clone.switch_to("ja", position=0).status == "applied"
    assert clone.stats()["switches"] == 2


def test_restore_rejects_malformed_state_without_mutation():
    sel = selector()
    sel.add_track("tr-en", language="en", keyframes=(0,))
    sel.preload("en")
    sel.switch_to("en", position=0)
    bad_states = [
        None,
        {},
        {"version": 2, "tracks": [], "preferences": [], "device": {},
         "current": None, "preloaded": [], "queued": None, "position": 0,
         "stats": {}},
        {"version": 1, "tracks": "nope", "preferences": [], "device": {},
         "current": None, "preloaded": {}, "queued": None, "position": 0,
         "stats": {"switches": 1}},
        {"version": 1, "tracks": [], "preferences": [], "device": {},
         "current": None, "preloaded": {}, "queued": None, "position": 0,
         "stats": {}},
    ]
    for bad in bad_states:
        with pytest.raises(ats.TrackError) as exc:
            sel.restore(bad)
        assert exc.value.code == "AUDIO_SNAPSHOT_INVALID"
    assert sel.current().track_id == "tr-en"
    assert sel.stats()["switches"] == 1


def test_concurrent_preload_and_switch_keeps_single_track():
    sel = selector(max_preloaded=64)
    errors = []
    barrier = threading.Barrier(12)

    def worker(index):
        language = f"l{index:02d}"
        try:
            barrier.wait(timeout=5)
            sel.add_track(f"tr-{language}", language=language, keyframes=(0,))
            result = sel.preload(language)
            if result.status != "ready":
                errors.append(f"preload {language}: {result.status}")
                return
            sel.switch_to(language, position=0)
        except Exception as exc:  # pragma: no cover - reported via errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    stats = sel.stats()
    assert stats["preloads"] == 12
    assert stats["preload_failures"] == 0
    assert stats["switches"] == 12
    assert len(sel.active_tracks()) == 1
    assert sel.current() is not None
    assert len(sel.available()) == 12
