import copy
import threading

import pytest

import text_run_shaper as ts

GLYPHS = {"a": 0.5, "b": 0.5, "c": 0.5, " ": 0.5, "\u2026": 0.5}


def shaper(**kwargs):
    return ts.TextRunShaper(**kwargs)


def main_font(target, *, version=1, glyphs=GLYPHS, fallbacks=()):
    return target.register_font("main", glyphs=glyphs, version=version,
                                fallbacks=fallbacks)


def test_register_font_reports_info_and_sorted_ids():
    shaper_ = shaper()
    assert main_font(shaper_) == 1
    assert shaper_.register_font("alt", glyphs=GLYPHS, version=2) == 2
    assert shaper_.fonts() == ("alt", "main")
    info = shaper_.font_info("main")
    assert info["font_id"] == "main"
    assert info["version"] == 1
    assert info["glyph_count"] == 5
    assert info["fallbacks"] == ()
    assert shaper_.stats()["fonts"] == 2


def test_register_font_rejects_invalid_arguments_and_version_conflicts():
    shaper_ = shaper()
    bad_calls = [
        lambda: shaper_.register_font("", glyphs=GLYPHS),
        lambda: shaper_.register_font("main", glyphs={}),
        lambda: shaper_.register_font("main", glyphs={"a": 0.0}),
        lambda: shaper_.register_font("main", glyphs=GLYPHS, version=0),
        lambda: shaper_.register_font("main", glyphs=GLYPHS,
                                      fallbacks=("ghost",)),
    ]
    for call in bad_calls:
        with pytest.raises(ts.TextShapeError) as exc:
            call()
        assert exc.value.code == "TEXT_INVALID_REQUEST"
    main_font(shaper_)
    with pytest.raises(ts.TextShapeError) as exc:
        main_font(shaper_, version=1)
    assert exc.value.code == "TEXT_FONT_VERSION_CONFLICT"
    with pytest.raises(ts.TextShapeError) as exc:
        shaper_.font_info("ghost")
    assert exc.value.code == "TEXT_UNKNOWN_FONT"
    assert shaper_.stats()["fonts"] == 1


def test_resolve_fallback_maps_covered_clusters():
    shaper_ = shaper()
    main_font(shaper_)
    out = shaper_.resolve_fallback("main", "ab")
    assert out["font_id"] == "main"
    assert out["chains"] == (("a", "main"), ("b", "main"))
    assert out["missing"] == ()
    with pytest.raises(ts.TextShapeError) as exc:
        shaper_.resolve_fallback("ghost", "ab")
    assert exc.value.code == "TEXT_UNKNOWN_FONT"


def test_shape_run_reports_advances_width_and_clusters():
    shaper_ = shaper()
    main_font(shaper_)
    out = shaper_.shape_run("ab", font_id="main")
    assert out["text"] == "ab"
    assert out["font_id"] == "main"
    assert out["size"] == 16.0
    assert out["features"] == ()
    assert out["clusters"] == ("a", "b")
    assert out["fonts"] == ("main", "main")
    assert out["advances"] == pytest.approx((8.0, 8.0))
    assert out["width"] == pytest.approx(16.0)


def test_shape_run_rejects_bad_input_and_handles_empty_text():
    shaper_ = shaper()
    main_font(shaper_)
    with pytest.raises(ts.TextShapeError) as exc:
        shaper_.shape_run("ab", font_id="ghost")
    assert exc.value.code == "TEXT_UNKNOWN_FONT"
    with pytest.raises(ts.TextShapeError) as exc:
        shaper_.shape_run("ab", font_id="main", size=0.0)
    assert exc.value.code == "TEXT_INVALID_REQUEST"
    empty = shaper_.shape_run("", font_id="main")
    assert empty["clusters"] == ()
    assert empty["advances"] == ()
    assert empty["width"] == 0.0
    tagged = shaper_.shape_run("ab", font_id="main", features=("liga",))
    assert tagged["features"] == ("liga",)
    key_a = shaper_.cache_key("ab", font_id="main", size=16.0,
                              max_width=16.0)
    key_b = shaper_.cache_key("ab", font_id="main", size=16.0,
                              max_width=24.0)
    assert key_a != key_b


def test_break_lines_wraps_at_spaces():
    shaper_ = shaper()
    main_font(shaper_)
    lines = shaper_.break_lines("aa bb", font_id="main", size=16.0,
                                max_width=16.0)
    assert [line["text"] for line in lines] == ["aa", "bb"]
    assert [line["width"] for line in lines] == pytest.approx([16.0, 16.0])
    assert [line["ellipsis"] for line in lines] == [False, False]


def test_break_lines_keeps_forced_newlines():
    shaper_ = shaper()
    main_font(shaper_)
    lines = shaper_.break_lines("a\n\nb", font_id="main", size=16.0,
                                max_width=64.0)
    assert [line["text"] for line in lines] == ["a", "", "b"]
    assert [line["width"] for line in lines] == pytest.approx([8.0, 0.0, 8.0])


def test_break_lines_splits_long_word_at_clusters():
    shaper_ = shaper()
    main_font(shaper_)
    lines = shaper_.break_lines("aaaa", font_id="main", size=16.0,
                                max_width=16.0)
    assert [line["text"] for line in lines] == ["aa", "aa"]
    assert [line["width"] for line in lines] == pytest.approx([16.0, 16.0])


def test_layout_uses_cache_and_reports_width():
    shaper_ = shaper()
    main_font(shaper_)
    first = shaper_.layout("aa", font_id="main", size=16.0, max_width=16.0)
    assert first["cached"] is False
    assert first["lines"][0]["text"] == "aa"
    assert first["width"] == pytest.approx(16.0)
    assert first["cache_key"] == shaper_.cache_key(
        "aa", font_id="main", size=16.0, max_width=16.0)
    second = shaper_.layout("aa", font_id="main", size=16.0, max_width=16.0)
    assert second["cached"] is True
    assert second["lines"] == first["lines"]
    assert shaper_.stats()["layouts"] == 1
    assert shaper_.stats()["cache_hits"] == 1


def test_layout_ellipsis_truncates_last_allowed_line():
    shaper_ = shaper()
    main_font(shaper_)
    result = shaper_.layout("aa bb cc", font_id="main", size=16.0,
                            max_width=16.0, max_lines=1)
    assert len(result["lines"]) == 1
    line = result["lines"][0]
    assert line["text"] == "a\u2026"
    assert line["width"] == pytest.approx(16.0)
    assert line["ellipsis"] is True
    assert result["width"] == pytest.approx(16.0)

    unlimited = shaper_.layout("aa bb cc", font_id="main", size=16.0,
                               max_width=16.0)
    assert [row["text"] for row in unlimited["lines"]] == ["aa", "bb", "cc"]
    assert all(row["ellipsis"] is False for row in unlimited["lines"])


def test_font_hot_replace_invalidates_layout_and_rollback_restores():
    shaper_ = shaper()
    main_font(shaper_)
    before = shaper_.layout("a", font_id="main", size=16.0, max_width=16.0)
    assert before["width"] == pytest.approx(8.0)

    bigger = {"a": 1.0, "b": 1.0, "c": 1.0, " ": 0.5, "\u2026": 0.5}
    assert main_font(shaper_, version=2, glyphs=bigger) == 2
    replaced = shaper_.layout("a", font_id="main", size=16.0, max_width=32.0)
    assert replaced["width"] == pytest.approx(16.0)
    assert replaced["cached"] is False

    assert shaper_.rollback_font("main") == 1
    assert shaper_.font_info("main")["version"] == 1
    restored = shaper_.layout("a", font_id="main", size=16.0, max_width=16.0)
    assert restored["width"] == pytest.approx(8.0)
    assert restored["cached"] is False
    assert shaper_.stats()["font_versions"] == 2


def test_invalidate_cache_and_stats_are_exact():
    shaper_ = shaper()
    main_font(shaper_)
    shaper_.register_font("alt", glyphs=GLYPHS)
    shaper_.layout("aa", font_id="main", size=16.0, max_width=16.0)
    shaper_.layout("aa", font_id="main", size=16.0, max_width=16.0)
    assert shaper_.invalidate_cache("main") == 1
    shaper_.layout("aa", font_id="main", size=16.0, max_width=16.0)
    assert shaper_.stats() == {
        "fonts": 2,
        "font_versions": 2,
        "layouts": 2,
        "cache_hits": 1,
        "cache_invalidations": 1,
    }
    with pytest.raises(ts.TextShapeError) as exc:
        shaper_.invalidate_cache("ghost")
    assert exc.value.code == "TEXT_UNKNOWN_FONT"


def test_concurrent_layout_computes_once():
    shaper_ = shaper()
    main_font(shaper_)
    errors = []
    results = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(shaper_.layout("aa bb", font_id="main", size=16.0,
                                          max_width=16.0))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 8
    assert shaper_.stats()["layouts"] == 1
    assert shaper_.stats()["cache_hits"] == 7
    assert sum(1 for result in results if result["cached"]) == 7
    assert all(result["lines"] == results[0]["lines"] for result in results)


def test_snapshot_is_detached_and_restores_fonts_and_cache():
    shaper_ = shaper()
    main_font(shaper_)
    shaper_.layout("aa", font_id="main", size=16.0, max_width=16.0)
    snap = shaper_.snapshot()
    assert set(snap) == {"schema", "fonts", "cache", "stats"}
    pristine = copy.deepcopy(snap)

    snap["fonts"].clear()
    snap["cache"].clear()
    snap["stats"]["layouts"] = 99
    assert shaper_.font_info("main")["version"] == 1
    assert shaper_.layout("aa", font_id="main", size=16.0,
                          max_width=16.0)["cached"] is True
    assert shaper_.stats()["layouts"] == 1

    clone = shaper()
    clone.restore(pristine)
    assert clone.font_info("main")["glyph_count"] == 5
    assert clone.layout("aa", font_id="main", size=16.0,
                        max_width=16.0)["cached"] is True
    assert clone.stats()["cache_hits"] == 1


def test_restore_rejects_malformed_state():
    shaper_ = shaper()
    main_font(shaper_)
    shaper_.layout("aa", font_id="main", size=16.0, max_width=16.0)
    bad_states = [
        None,
        {},
        {"schema": 1, "fonts": {}, "cache": {}},
        {"schema": 1, "fonts": [], "cache": {}, "stats": {}},
        {"schema": 1, "fonts": {}, "cache": [], "stats": {}},
        {"schema": 1, "fonts": {}, "cache": {}, "stats": []},
    ]
    for bad in bad_states:
        with pytest.raises(ts.TextShapeError) as exc:
            shaper_.restore(bad)
        assert exc.value.code == "TEXT_SNAPSHOT_INVALID"
    assert shaper_.font_info("main")["version"] == 1
    assert shaper_.layout("aa", font_id="main", size=16.0,
                          max_width=16.0)["cached"] is True
