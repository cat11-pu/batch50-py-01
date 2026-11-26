import copy
import threading

import pytest

import tangent_frame_builder as tf

POSITIONS = ((0.0, 0.0, 0.0), (1.0, 0.0, 0.0), (0.0, 1.0, 0.0))
NORMALS = ((0.0, 0.0, 1.0), (0.0, 0.0, 1.0), (0.0, 0.0, 1.0))
UVS = ((0.0, 0.0), (1.0, 0.0), (0.0, 1.0))
INDICES = (0, 1, 2)


def builder(**kwargs):
    return tf.TangentFrameBuilder(**kwargs)


def add_triangle(target, mesh_id="m1", *, positions=POSITIONS, uvs=UVS,
                 indices=INDICES, normals=NORMALS, **kwargs):
    return target.register_mesh(mesh_id, positions=positions, uvs=uvs,
                                indices=indices, normals=normals, **kwargs)


def test_register_mesh_reports_version_and_counts():
    frames = builder()
    version = add_triangle(frames)
    assert version == 1
    info = frames.mesh_info("m1")
    assert info["mesh_id"] == "m1"
    assert info["version"] == 1
    assert info["vertex_count"] == 3
    assert info["triangle_count"] == 1
    assert info["uv_channels"] == (0,)
    assert frames.stats()["meshes"] == 1
    assert frames.stats()["versions"] == 1


def test_register_mesh_rejects_invalid_arrays():
    frames = builder(max_vertices=2)
    bad_calls = [
        lambda: frames.register_mesh("", positions=POSITIONS, uvs=UVS,
                                     indices=INDICES),
        lambda: frames.register_mesh("m1", positions=(), uvs=(), indices=()),
        lambda: frames.register_mesh("m2", positions=POSITIONS,
                                     uvs=UVS[:2], indices=INDICES),
        lambda: frames.register_mesh("m3", positions=POSITIONS, uvs=UVS,
                                     indices=(0, 1)),
        lambda: frames.register_mesh("m4", positions=POSITIONS, uvs=UVS,
                                     indices=(0, 1, 9)),
        lambda: frames.register_mesh("m5", positions=POSITIONS, uvs=UVS,
                                     indices=INDICES, normals=NORMALS[:2]),
        lambda: frames.register_mesh("m6", positions=POSITIONS, uvs=UVS,
                                     indices=INDICES, material_groups=("a", "b")),
    ]
    for call in bad_calls:
        with pytest.raises(tf.TangentError) as exc:
            call()
        assert exc.value.code == "TANGENT_INVALID_REQUEST"
    with pytest.raises(tf.TangentError) as exc:
        add_triangle(frames, "m7")
    assert exc.value.code == "TANGENT_VERTEX_LIMIT"
    assert frames.stats()["meshes"] == 0


def test_build_frames_is_cached_until_mesh_version_changes():
    frames = builder()
    add_triangle(frames)
    first = frames.build_frames("m1")
    assert first["cached"] is False
    assert first["triangle_count"] == 1
    second = frames.build_frames("m1")
    assert second["cached"] is True
    assert second["tangents"] == first["tangents"]
    assert frames.stats()["builds"] == 1
    assert frames.stats()["cache_hits"] == 1

    old_key = frames.cache_key("m1", 0)
    add_triangle(frames)
    new_key = frames.cache_key("m1", 0)
    assert new_key != old_key
    assert frames.mesh_info("m1")["version"] == 2
    third = frames.build_frames("m1")
    assert third["cached"] is False
    assert frames.stats()["builds"] == 2


def test_build_frames_reconstructs_axis_aligned_tangents():
    frames = builder()
    add_triangle(frames)
    result = frames.build_frames("m1")
    assert result["mesh_id"] == "m1"
    assert result["version"] == 1
    assert result["uv_channel"] == 0
    assert result["indices"] == INDICES
    assert result["vertex_count"] == 3
    flat = [component for tangent in result["tangents"]
            for component in tangent]
    assert flat == pytest.approx([1.0, 0.0, 0.0, 1.0,
                                  1.0, 0.0, 0.0, 1.0,
                                  1.0, 0.0, 0.0, 1.0])


def test_uv_channels_have_independent_cache_entries():
    frames = builder()
    add_triangle(frames)
    first = frames.build_frames("m1", uv_channel=0)
    assert first["cached"] is False
    channel_one = ((0.0, 0.0), (0.0, 1.0), (1.0, 0.0))
    version = frames.set_uv_channel("m1", 1, channel_one)
    assert version == 2
    miss = frames.build_frames("m1", uv_channel=1)
    assert miss["cached"] is False
    hit = frames.build_frames("m1", uv_channel=1)
    assert hit["cached"] is True
    assert frames.cache_key("m1", 0) != frames.cache_key("m1", 1)
    assert frames.stats()["builds"] == 2
    assert frames.stats()["cache_hits"] == 1


def test_invalidate_drops_cached_frames():
    frames = builder()
    add_triangle(frames)
    frames.build_frames("m1")
    assert frames.invalidate("m1") == 1
    assert frames.build_frames("m1")["cached"] is False
    assert frames.stats()["invalidations"] == 1
    with pytest.raises(tf.TangentError) as exc:
        frames.invalidate("ghost")
    assert exc.value.code == "TANGENT_UNKNOWN_MESH"


def test_validate_reports_structure_without_rejecting_mesh():
    frames = builder()
    add_triangle(frames)
    frames.set_uv_channel("m1", 1, UVS)
    report = frames.validate("m1")
    assert report["valid"] is True
    assert report["vertex_count"] == 3
    assert report["triangle_count"] == 1
    assert "degenerate_uv_triangles" in report
    assert "mirrored_triangles" in report
    assert frames.mesh_info("m1")["uv_channels"] == (0, 1)


def test_set_max_vertices_caps_builds():
    frames = builder(max_vertices=4)
    add_triangle(frames)
    with pytest.raises(tf.TangentError) as exc:
        frames.set_max_vertices(0)
    assert exc.value.code == "TANGENT_INVALID_REQUEST"
    frames.set_max_vertices(2)
    with pytest.raises(tf.TangentError) as exc:
        frames.build_frames("m1")
    assert exc.value.code == "TANGENT_VERTEX_LIMIT"
    assert frames.stats()["vertex_limit_refusals"] == 1
    frames.set_max_vertices(3)
    result = frames.build_frames("m1")
    assert result["cached"] is False
    assert result["vertex_count"] == 3


def test_unknown_mesh_is_rejected_across_operations():
    frames = builder()
    calls = [
        lambda: frames.build_frames("ghost"),
        lambda: frames.cache_key("ghost"),
        lambda: frames.validate("ghost"),
        lambda: frames.set_uv_channel("ghost", 1, UVS),
        lambda: frames.invalidate("ghost"),
        lambda: frames.mesh_info("ghost"),
        lambda: frames.split_vertices("ghost"),
    ]
    for call in calls:
        with pytest.raises(tf.TangentError) as exc:
            call()
        assert exc.value.code == "TANGENT_UNKNOWN_MESH"


def test_concurrent_builds_share_one_computation():
    frames = builder()
    add_triangle(frames)
    errors = []
    results = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(frames.build_frames("m1"))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(results) == 8
    assert frames.stats()["builds"] == 1
    assert frames.stats()["cache_hits"] == 7
    assert sum(1 for result in results if result["cached"]) == 7
    assert all(result["tangents"] == results[0]["tangents"]
               for result in results)


def test_snapshot_is_detached_from_live_mesh_and_cache():
    frames = builder()
    add_triangle(frames)
    frames.build_frames("m1")
    snap = frames.snapshot()
    assert set(snap) == {"schema", "meshes", "cache", "stats"}
    pristine = copy.deepcopy(snap)

    snap["meshes"].clear()
    snap["cache"].clear()
    snap["stats"]["cache_hits"] = 99
    assert frames.mesh_info("m1")["version"] == 1
    assert frames.build_frames("m1")["cached"] is True
    assert frames.stats()["cache_hits"] == 1


def test_snapshot_restore_roundtrip_keeps_mesh_and_cache():
    frames = builder()
    add_triangle(frames)
    first = frames.build_frames("m1")
    state = frames.snapshot()

    clone = builder()
    clone.restore(copy.deepcopy(state))
    assert clone.mesh_info("m1")["vertex_count"] == 3
    cached = clone.build_frames("m1")
    assert cached["cached"] is True
    assert cached["tangents"] == first["tangents"]
    assert clone.stats()["cache_hits"] == 1


def test_restore_rejects_malformed_state():
    frames = builder()
    add_triangle(frames)
    frames.build_frames("m1")
    bad_states = [
        None,
        {},
        {"schema": 1, "meshes": {}, "cache": {}},
        {"schema": 1, "meshes": [], "cache": {}, "stats": {}},
        {"schema": 1, "meshes": {}, "cache": [], "stats": {}},
        {"schema": 1, "meshes": {}, "cache": {}, "stats": []},
    ]
    for bad in bad_states:
        with pytest.raises(tf.TangentError) as exc:
            frames.restore(bad)
        assert exc.value.code == "TANGENT_SNAPSHOT_INVALID"
    assert frames.mesh_info("m1")["version"] == 1
    assert frames.build_frames("m1")["cached"] is True


def test_stats_track_each_operation():
    frames = builder()
    add_triangle(frames, "m1")
    add_triangle(frames, "m2")
    frames.build_frames("m1")
    frames.build_frames("m1")
    frames.invalidate("m1")
    add_triangle(frames, "m1")
    frames.build_frames("m1")
    frames.set_max_vertices(1)
    with pytest.raises(tf.TangentError):
        frames.build_frames("m2")
    assert frames.stats() == {
        "meshes": 2,
        "versions": 3,
        "builds": 2,
        "cache_hits": 1,
        "invalidations": 1,
        "vertex_limit_refusals": 1,
    }


def test_cache_key_format_and_uv_channel_validation():
    frames = builder()
    add_triangle(frames)
    assert frames.cache_key("m1") == "m1:v1:uv0"
    assert frames.cache_key("m1", 0) == "m1:v1:uv0"
    with pytest.raises(tf.TangentError) as exc:
        frames.build_frames("m1", uv_channel=2)
    assert exc.value.code == "TANGENT_INVALID_REQUEST"
    with pytest.raises(tf.TangentError) as exc:
        frames.set_uv_channel("m1", 1, UVS[:2])
    assert exc.value.code == "TANGENT_INVALID_REQUEST"
    with pytest.raises(tf.TangentError) as exc:
        frames.set_uv_channel("m1", -1, UVS)
    assert exc.value.code == "TANGENT_INVALID_REQUEST"
    assert frames.mesh_info("m1")["uv_channels"] == (0,)
