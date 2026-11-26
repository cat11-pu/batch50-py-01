import threading

import pytest

import icc_transform_resolver as icc

SRGB = "srgb"
PANEL = "display-lab"


def resolver(**kwargs):
    return icc.IccTransformResolver(**kwargs)


def with_panel(**kwargs):
    instance = resolver(**kwargs)
    instance.register_profile(PANEL, device_class="display",
                              white_point=(0.3127, 0.3290), gamut="display-p3",
                              media_white=(0.9642, 1.0, 0.8249))
    return instance


def test_register_profile_stores_metadata():
    instance = resolver()
    view = instance.register_profile(PANEL, device_class="display",
                                     white_point=(0.3127, 0.3290),
                                     gamut="display-p3", version=3,
                                     media_white=(0.9642, 1.0, 0.8249))
    assert view.profile_id == PANEL
    assert view.device_class == "display"
    assert view.version == 3
    assert view.white_point == (0.3127, 0.3290)
    assert view.gamut == "display-p3"
    assert view.media_white == (0.9642, 1.0, 0.8249)
    assert view.valid is True
    assert view.diagnostics == ()
    stored = instance.profile_view(PANEL)
    assert stored == view
    assert instance.profile_view(SRGB).device_class == "colorspace"
    assert instance.profile_view(SRGB).version == 1


def test_register_profile_refuses_duplicates_and_bad_input():
    instance = with_panel()
    with pytest.raises(icc.IccError) as exc:
        instance.register_profile(PANEL, device_class="display",
                                  white_point=(0.3127, 0.3290), gamut="srgb")
    assert exc.value.code == "ICC_PROFILE_EXISTS"
    for bad in ("", "   "):
        with pytest.raises(icc.IccError) as exc:
            instance.register_profile(bad, device_class="display",
                                      white_point=(0.3, 0.3), gamut="srgb")
        assert exc.value.code == "ICC_INVALID_REQUEST"
    with pytest.raises(icc.IccError) as exc:
        instance.register_profile("odd", device_class="camera",
                                  white_point=(0.3, 0.3), gamut="srgb")
    assert exc.value.code == "ICC_INVALID_REQUEST"
    with pytest.raises(icc.IccError) as exc:
        instance.register_profile("odd", device_class="display",
                                  white_point=(0.0, 0.3), gamut="srgb")
    assert exc.value.code == "ICC_INVALID_REQUEST"
    with pytest.raises(icc.IccError) as exc:
        instance.register_profile("odd", device_class="display",
                                  white_point=(0.3, 0.3), gamut="  ")
    assert exc.value.code == "ICC_INVALID_REQUEST"
    with pytest.raises(icc.IccError) as exc:
        instance.register_profile("odd", device_class="display",
                                  white_point=(0.3, 0.3), gamut="srgb",
                                  version=0)
    assert exc.value.code == "ICC_INVALID_REQUEST"
    with pytest.raises(icc.IccError) as exc:
        instance.profile_view("nowhere")
    assert exc.value.code == "ICC_UNKNOWN_PROFILE"


def test_validate_profile_reports_bad_gamut_with_fallback():
    instance = with_panel()
    good = instance.validate_profile(PANEL)
    assert good["profile_id"] == PANEL
    assert good["valid"] is True
    assert good["diagnostics"] == ()
    assert good["fallback"] is None
    instance.register_profile("kiosk", device_class="output",
                              white_point=(0.3457, 0.3585), gamut="broken-lab")
    bad = instance.validate_profile("kiosk")
    assert bad["valid"] is False
    assert "ICC_GAMUT_UNSUPPORTED" in bad["diagnostics"]
    assert bad["fallback"] == SRGB


def test_validate_profile_requires_known_profile():
    instance = resolver()
    with pytest.raises(icc.IccError) as exc:
        instance.validate_profile("nowhere")
    assert exc.value.code == "ICC_UNKNOWN_PROFILE"


def test_link_cache_key_is_stable_and_intent_sensitive():
    instance = with_panel()
    first = instance.link_cache_key(SRGB, PANEL, intent="perceptual")
    again = instance.link_cache_key(SRGB, PANEL, intent="perceptual")
    assert isinstance(first, str)
    assert first == again
    assert first != instance.link_cache_key(SRGB, PANEL, intent="saturation")
    assert first != instance.link_cache_key(SRGB, PANEL, intent="perceptual",
                                            bpc=False)
    assert first == instance.link_cache_key(SRGB, PANEL, intent="PERCEPTUAL")
    assert len({first,
                instance.link_cache_key(SRGB, PANEL, intent="relative"),
                instance.link_cache_key(SRGB, PANEL, intent="absolute"),
                instance.link_cache_key(SRGB, PANEL, intent="saturation")}) == 4


def test_link_cache_key_refuses_unknown_intent_and_profile():
    instance = with_panel()
    with pytest.raises(icc.IccError) as exc:
        instance.link_cache_key(SRGB, PANEL, intent="vivid")
    assert exc.value.code == "ICC_INTENT_UNSUPPORTED"
    with pytest.raises(icc.IccError) as exc:
        instance.link_cache_key(SRGB, "nowhere", intent="perceptual")
    assert exc.value.code == "ICC_UNKNOWN_PROFILE"


def test_resolve_returns_compiled_handle_and_counts_miss():
    instance = with_panel()
    handle = instance.resolve_transform(SRGB, PANEL)
    assert isinstance(handle, icc.TransformHandle)
    assert handle.source_id == SRGB
    assert handle.source_version == 1
    assert handle.target_id == PANEL
    assert handle.target_version == 1
    assert handle.intent == "perceptual"
    assert handle.bpc is True
    assert handle.fallback is False
    assert handle.diagnostic is None
    assert handle.refs == 0
    assert handle.cache_key == instance.link_cache_key(SRGB, PANEL,
                                                      intent="perceptual")
    cache = instance.cache_stats()
    assert cache.entries == 1
    assert cache.misses == 1
    assert cache.hits == 0
    assert cache.compiles == 1
    assert instance.stats()["resolves"] == 1


def test_resolve_same_key_hits_the_cache():
    instance = with_panel()
    first = instance.resolve_transform(SRGB, PANEL, intent="perceptual")
    second = instance.resolve_transform(SRGB, PANEL, intent="perceptual")
    assert second.cache_key == first.cache_key
    cache = instance.cache_stats()
    assert cache.entries == 1
    assert cache.hits == 1
    assert cache.misses == 1
    assert cache.compiles == 1


def test_black_point_override_changes_cache_key():
    instance = with_panel()
    on = instance.resolve_transform(SRGB, PANEL, intent="perceptual")
    off = instance.resolve_transform(SRGB, PANEL, intent="perceptual", bpc=False)
    assert on.cache_key != off.cache_key
    assert off.bpc is False
    assert instance.cache_stats().entries == 2
    assert instance.cache_stats().compiles == 2


def test_resolve_falls_back_to_srgb_for_broken_target():
    instance = with_panel()
    instance.register_profile("kiosk", device_class="output",
                              white_point=(0.3457, 0.3585), gamut="broken-lab")
    handle = instance.resolve_transform(SRGB, "kiosk")
    assert handle.fallback is True
    assert handle.diagnostic == "ICC_GAMUT_UNSUPPORTED"
    assert handle.target_id == SRGB
    assert handle.target_version == 1
    assert instance.stats()["fallbacks"] == 1


def test_retain_and_release_handle_references():
    instance = with_panel()
    handle = instance.resolve_transform(SRGB, PANEL)
    held = instance.retain_handle(handle)
    assert held.refs == 1
    assert instance.retain_handle(held).refs == 2
    assert instance.release_handle(held).refs == 1
    assert instance.release_handle(held).refs == 0
    with pytest.raises(icc.IccError) as exc:
        instance.release_handle(held)
    assert exc.value.code == "ICC_HANDLE_STALE"
    stray = icc.TransformHandle(cache_key="bogus", source_id=SRGB,
                                source_version=1, target_id=PANEL,
                                target_version=1, intent="perceptual",
                                bpc=True, fallback=False, diagnostic=None,
                                refs=0)
    with pytest.raises(icc.IccError) as exc:
        instance.retain_handle(stray)
    assert exc.value.code == "ICC_HANDLE_STALE"


def test_invalidate_device_drops_its_cached_transforms():
    instance = with_panel()
    instance.register_profile("paper", device_class="output",
                              white_point=(0.9642, 1.0, 0.8249),
                              gamut="adobe-rgb")
    first = instance.resolve_transform(SRGB, PANEL)
    second = instance.resolve_transform(PANEL, "paper", intent="relative")
    third = instance.resolve_transform(SRGB, "paper", intent="relative")
    assert instance.cache_stats().entries == 3
    dropped = instance.invalidate_device(PANEL)
    assert isinstance(dropped, tuple)
    assert set(dropped) == {first.cache_key, second.cache_key}
    assert instance.cache_stats().entries == 1
    assert instance.stats()["invalidations"] == 1
    refetched = instance.resolve_transform(SRGB, PANEL)
    assert refetched.cache_key == first.cache_key
    assert instance.cache_stats().misses == 4
    assert instance.cache_stats().compiles == 4
    assert third.cache_key == instance.link_cache_key(SRGB, "paper",
                                                      intent="relative")
    with pytest.raises(icc.IccError) as exc:
        instance.invalidate_device("nowhere")
    assert exc.value.code == "ICC_UNKNOWN_PROFILE"


def test_cache_limit_evicts_oldest_entry():
    instance = with_panel(max_cache_entries=2)
    keys = []
    for intent in ("perceptual", "relative", "saturation"):
        keys.append(instance.resolve_transform(SRGB, PANEL,
                                               intent=intent).cache_key)
    cache = instance.cache_stats()
    assert cache.limit == 2
    assert cache.entries == 2
    assert cache.evictions == 1
    assert keys[0] not in {keys[1], keys[2]}
    again = instance.resolve_transform(SRGB, PANEL, intent="perceptual")
    assert again.cache_key == keys[0]
    assert instance.cache_stats().misses == 4


def test_snapshot_roundtrip_and_invalid_restore():
    instance = with_panel()
    instance.resolve_transform(SRGB, PANEL, intent="relative")
    snap = instance.snapshot()
    assert set(snap) >= {"profiles", "cache", "stats"}
    snap["profiles"].clear()
    assert instance.profile_view(PANEL).version == 1
    fresh = resolver()
    fresh.restore(instance.snapshot())
    assert fresh.profile_view(PANEL).gamut == "display-p3"
    hit = fresh.resolve_transform(SRGB, PANEL, intent="relative")
    assert fresh.cache_stats().hits == 1
    assert hit.diagnostic is None
    before = fresh.snapshot()
    with pytest.raises(icc.IccError) as exc:
        fresh.restore({"profiles": "not-a-mapping"})
    assert exc.value.code == "ICC_SNAPSHOT_INVALID"
    assert fresh.snapshot() == before


def test_concurrent_resolve_compiles_once():
    instance = with_panel()
    barrier = threading.Barrier(8)
    results = []
    errors = []
    lock = threading.Lock()

    def worker():
        try:
            barrier.wait(timeout=5)
            handle = instance.resolve_transform(SRGB, PANEL, intent="saturation")
            with lock:
                results.append(handle.cache_key)
        except BaseException as exc:  # noqa: BLE001 - collected for assert
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == []
    assert len(set(results)) == 1
    cache = instance.cache_stats()
    assert cache.compiles == 1
    assert cache.entries == 1
    assert cache.hits == 7
