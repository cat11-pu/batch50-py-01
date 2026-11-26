import math
import threading

import pytest

import vector_path_tessellator as vpt

PATH = "badge"


def tessellator(**kwargs):
    return vpt.PathTessellator(**kwargs)


def square(**kwargs):
    instance = tessellator(**kwargs)
    instance.begin_path(PATH)
    instance.move_to(PATH, 0.0, 0.0)
    instance.line_to(PATH, 10.0, 0.0)
    instance.line_to(PATH, 10.0, 10.0)
    instance.line_to(PATH, 0.0, 10.0)
    instance.close(PATH)
    return instance


def test_begin_path_creates_empty_path():
    instance = tessellator()
    view = instance.begin_path(PATH)
    assert view.path_id == PATH
    assert view.version == 1
    assert view.segments == ()
    assert view.closed is False
    assert view.point_count == 0
    assert view.style.fill_rule == "nonzero"
    assert view.style.stroke_width == 0.0
    assert view.style.join == "miter"
    assert view.style.dash is None
    assert instance.stats()["paths"] == 1
    with pytest.raises(vpt.TessellationError) as exc:
        instance.begin_path(PATH)
    assert exc.value.code == "PATH_EXISTS"
    for bad in ("", "   "):
        with pytest.raises(vpt.TessellationError) as exc:
            instance.begin_path(bad)
        assert exc.value.code == "PATH_INVALID_REQUEST"
    with pytest.raises(vpt.TessellationError) as exc:
        instance.path_view("nowhere")
    assert exc.value.code == "PATH_UNKNOWN"


def test_line_to_requires_an_open_subpath():
    instance = tessellator()
    instance.begin_path(PATH)
    with pytest.raises(vpt.TessellationError) as exc:
        instance.line_to(PATH, 1.0, 1.0)
    assert exc.value.code == "PATH_INVALID_REQUEST"
    instance.move_to(PATH, 0.0, 0.0)
    with pytest.raises(vpt.TessellationError) as exc:
        instance.move_to(PATH, 5.0, 5.0)
    assert exc.value.code == "PATH_INVALID_REQUEST"
    view = instance.line_to(PATH, 4.0, 0.0)
    assert [segment.kind for segment in view.segments] == ["move", "line"]
    assert view.segments[0].points == ((0.0, 0.0),)
    assert view.segments[1].points == ((0.0, 0.0), (4.0, 0.0))
    assert view.point_count == 2
    assert instance.stats()["edits"] == 3


def test_coordinates_must_be_finite_numbers():
    instance = tessellator()
    instance.begin_path(PATH)
    for bad in ("1.0", None, float("nan"), float("inf")):
        with pytest.raises(vpt.TessellationError) as exc:
            instance.move_to(PATH, bad, 0.0)
        assert exc.value.code == "PATH_INVALID_REQUEST"
    instance.move_to(PATH, 0.0, 0.0)
    with pytest.raises(vpt.TessellationError) as exc:
        instance.cubic_to(PATH, 0.0, 1.0, 2.0, "3", 4.0, 4.0)
    assert exc.value.code == "PATH_INVALID_REQUEST"


def test_close_requires_a_drawn_subpath():
    instance = tessellator()
    instance.begin_path(PATH)
    with pytest.raises(vpt.TessellationError) as exc:
        instance.close(PATH)
    assert exc.value.code == "PATH_INVALID_REQUEST"
    instance.move_to(PATH, 0.0, 0.0)
    with pytest.raises(vpt.TessellationError) as exc:
        instance.close(PATH)
    assert exc.value.code == "PATH_INVALID_REQUEST"
    instance.line_to(PATH, 5.0, 0.0)
    closed = instance.close(PATH)
    assert closed.closed is True
    assert closed.point_count == 2
    with pytest.raises(vpt.TessellationError) as exc:
        instance.close(PATH)
    assert exc.value.code == "PATH_INVALID_REQUEST"
    with pytest.raises(vpt.TessellationError) as exc:
        instance.line_to(PATH, 9.0, 9.0)
    assert exc.value.code == "PATH_INVALID_REQUEST"


def test_cubic_segment_flattens_into_many_points():
    instance = tessellator()
    instance.begin_path(PATH)
    instance.move_to(PATH, 0.0, 0.0)
    instance.cubic_to(PATH, 0.0, 100.0, 100.0, 100.0, 100.0, 0.0)
    result = instance.tessellate(PATH, tolerance=0.5)
    assert result.vertex_count == len(result.points)
    assert result.vertex_count >= 9
    assert result.points[0] == (0.0, 0.0)
    assert result.points[-1][0] == pytest.approx(100.0)
    assert result.points[-1][1] == pytest.approx(0.0, abs=1e-9)
    assert all(math.isfinite(x) and math.isfinite(y)
               for x, y in result.points)
    assert result.tolerance_used == 0.5


def test_tolerance_bounds_and_default():
    instance = square(default_tolerance=0.5)
    default = instance.tessellate(PATH)
    assert default.tolerance_used == 0.5
    assert instance.tessellate(PATH, tolerance=0.25).tolerance_used == 0.25
    for bad in (0.0, -0.5, 100.0, "0.5"):
        with pytest.raises(vpt.TessellationError) as exc:
            instance.tessellate(PATH, tolerance=bad)
        assert exc.value.code == "PATH_INVALID_TOLERANCE"


def test_closed_square_fills_with_two_triangles():
    instance = square()
    result = instance.tessellate(PATH)
    assert instance.path_view(PATH).closed is True
    assert result.vertex_count == 4
    assert result.triangle_count == 2
    assert len(result.triangles) == 2
    for triangle in result.triangles:
        assert len(triangle) == 3
        for index in triangle:
            assert 0 <= index < result.vertex_count
    assert result.stroke_quads == 0


def test_open_path_gets_no_fill_triangles():
    instance = tessellator()
    instance.begin_path(PATH)
    instance.move_to(PATH, 0.0, 0.0)
    instance.line_to(PATH, 10.0, 0.0)
    instance.line_to(PATH, 10.0, 10.0)
    instance.line_to(PATH, 0.0, 10.0)
    result = instance.tessellate(PATH)
    assert instance.path_view(PATH).closed is False
    assert result.vertex_count == 4
    assert result.triangle_count == 0
    assert result.triangles == ()


def test_degenerate_segments_are_merged():
    instance = tessellator()
    instance.begin_path(PATH)
    instance.move_to(PATH, 0.0, 0.0)
    instance.line_to(PATH, 0.0, 0.0)
    instance.line_to(PATH, 10.0, 0.0)
    instance.close(PATH)
    result = instance.tessellate(PATH)
    assert result.degenerate_segments == 1
    assert result.points == ((0.0, 0.0), (10.0, 0.0))
    assert result.vertex_count == 2
    assert result.triangle_count == 0


def test_style_validation():
    instance = square()
    with pytest.raises(vpt.TessellationError) as exc:
        instance.set_style(PATH, fill_rule="winding")
    assert exc.value.code == "PATH_INVALID_REQUEST"
    with pytest.raises(vpt.TessellationError) as exc:
        instance.set_style(PATH, join="square")
    assert exc.value.code == "PATH_INVALID_REQUEST"
    for width in (-1.0, "wide"):
        with pytest.raises(vpt.TessellationError) as exc:
            instance.set_style(PATH, stroke_width=width)
        assert exc.value.code == "PATH_INVALID_REQUEST"
    for dash in ((1.0,), (2.0, 0.0), (2.0, -1.0)):
        with pytest.raises(vpt.TessellationError) as exc:
            instance.set_style(PATH, dash=dash)
        assert exc.value.code == "PATH_INVALID_REQUEST"
    styled = instance.set_style(PATH, fill_rule="evenodd", stroke_width=1.5,
                                join="round", dash=(4.0, 2.0))
    assert styled.style.fill_rule == "evenodd"
    assert styled.style.stroke_width == 1.5
    assert styled.style.join == "round"
    assert styled.style.dash == (4.0, 2.0)


def test_style_and_tolerance_change_the_cache_key():
    instance = square()
    base = instance.cache_key(PATH)
    assert isinstance(base, str)
    assert base == instance.cache_key(PATH)
    styled = instance.set_style(PATH, stroke_width=1.0)
    assert styled.version > 1
    assert instance.cache_key(PATH) != base
    strict = instance.cache_key(PATH, tolerance=0.25)
    assert strict != instance.cache_key(PATH)
    assert strict == instance.cache_key(PATH, tolerance=0.25)
    with pytest.raises(vpt.TessellationError) as exc:
        instance.cache_key("nowhere")
    assert exc.value.code == "PATH_UNKNOWN"


def test_tessellation_result_is_cached():
    instance = square()
    first = instance.tessellate(PATH)
    second = instance.tessellate(PATH)
    assert first.cached is False
    assert second.cached is True
    assert first.cache_key == second.cache_key == instance.cache_key(PATH)
    assert first.points == second.points
    assert first.triangles == second.triangles
    usage = instance.cache_usage()
    assert usage["entries"] == 1
    assert usage["hits"] == 1
    assert usage["misses"] == 1
    assert usage["used_vertices"] == 4
    assert instance.stats()["tessellations"] == 2


def test_stroke_layout_adds_quads():
    instance = tessellator()
    instance.begin_path(PATH)
    instance.move_to(PATH, 0.0, 0.0)
    instance.line_to(PATH, 10.0, 0.0)
    instance.line_to(PATH, 10.0, 10.0)
    bare = instance.tessellate(PATH)
    assert bare.stroke_quads == 0
    instance.set_style(PATH, stroke_width=2.0, join="bevel")
    stroked = instance.tessellate(PATH)
    assert stroked.stroke_quads > 0
    assert stroked.vertex_count >= bare.vertex_count


def test_release_and_snapshot_roundtrip():
    instance = square()
    expected = instance.tessellate(PATH).points
    snap = instance.snapshot()
    assert set(snap) >= {"paths", "stats"}
    snap["paths"].clear()
    assert instance.path_view(PATH).closed is True
    released = instance.release_path(PATH)
    assert released.path_id == PATH
    with pytest.raises(vpt.TessellationError) as exc:
        instance.path_view(PATH)
    assert exc.value.code == "PATH_UNKNOWN"
    with pytest.raises(vpt.TessellationError) as exc:
        instance.tessellate(PATH)
    assert exc.value.code == "PATH_UNKNOWN"
    fresh = tessellator()
    fresh.restore(square().snapshot())
    assert fresh.tessellate(PATH).points == expected
    assert fresh.path_view(PATH).point_count == 4
    before = fresh.snapshot()
    with pytest.raises(vpt.TessellationError) as exc:
        fresh.restore({"paths": "not-a-mapping"})
    assert exc.value.code == "PATH_SNAPSHOT_INVALID"
    assert fresh.snapshot() == before


def test_concurrent_tessellation_hits_one_cache_entry():
    instance = square()
    barrier = threading.Barrier(8)
    results = []
    errors = []
    lock = threading.Lock()

    def worker():
        try:
            barrier.wait(timeout=5)
            result = instance.tessellate(PATH)
            with lock:
                results.append((result.points, result.triangles))
        except BaseException as exc:  # noqa: BLE001 - collected for assert
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == []
    assert len(set(results)) == 1
    usage = instance.cache_usage()
    assert usage["entries"] == 1
    assert usage["misses"] == 1
    assert usage["hits"] == 7
