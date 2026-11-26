import copy

import pytest

import mesh_decimation_planner as mp

OCTA_VERTICES = [(1, 0, 0), (0, 1, 0), (-1, 0, 0), (0, -1, 0), (0, 0, 1),
                 (0, 0, -1)]
OCTA_FACES = [(0, 1, 4), (1, 2, 4), (2, 3, 4), (3, 0, 4), (1, 0, 5),
              (2, 1, 5), (3, 2, 5), (0, 3, 5)]

TETRA_A = [(0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1)]
TETRA_A_FACES = [(0, 1, 2), (0, 1, 3), (0, 2, 3), (1, 2, 3)]
TWO_TETRA_VERTICES = TETRA_A + [(10, 0, 0), (12, 0, 0), (10, 2, 0), (10, 0, 2)]
TWO_TETRA_FACES = TETRA_A_FACES + [(4, 5, 6), (4, 5, 7), (4, 6, 7), (5, 6, 7)]

PRISM_VERTICES = [(0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, 1), (1, 0, 1),
                  (0, 1, 1)]
PRISM_FACES = [(0, 1, 2), (3, 5, 4), (0, 1, 4), (0, 4, 3), (1, 2, 5),
               (1, 5, 4), (2, 0, 3), (2, 3, 5)]

QUAD_VERTICES = [(0, 0, 0), (1, 0, 0), (1, 1, 0), (0, 1, 0)]
QUAD_FACES = [(0, 1, 2), (0, 2, 3)]


def planner():
    return mp.MeshDecimationPlanner()


def octa(target=1):
    p = planner()
    p.load("octa", OCTA_VERTICES, OCTA_FACES)
    p.set_target(target)
    return p


def edge_usage(faces):
    counts = {}
    for a, b, c in faces:
        for left, right in ((a, b), (b, c), (c, a)):
            key = (left, right) if left < right else (right, left)
            counts[key] = counts.get(key, 0) + 1
    return counts


def test_load_reports_topology_and_rejects_bad_meshes():
    p = planner()
    summary = p.load("octa", OCTA_VERTICES, OCTA_FACES)
    assert summary.mesh_id == "octa"
    assert summary.vertices == 6
    assert summary.faces == 8
    assert summary.boundary_vertices == ()
    assert summary.locked == 0
    assert p.stats()["faces"] == 8

    bad_meshes = [
        ("", OCTA_VERTICES, OCTA_FACES),
        ("octa", [(0, 0, 0), (1, 0, 0), (0, 1, 0)], OCTA_FACES),
        ("octa", [(1, 0), (0, 1, 0), (-1, 0, 0), (0, -1, 0)], OCTA_FACES),
        ("octa", [(0, 0, 0), (1, 0, 0), (0, 1, 0), (0, 0, "x")], OCTA_FACES),
        ("octa", OCTA_VERTICES, []),
        ("octa", OCTA_VERTICES, [(0, 1)]),
        ("octa", OCTA_VERTICES, [(0, 1, 9)]),
        ("octa", OCTA_VERTICES, [(0, 1, 1)]),
        ("octa", OCTA_VERTICES, [(0, 1, 2.5)]),
    ]
    for mesh_id, vertices, faces in bad_meshes:
        with pytest.raises(mp.MeshPlanError) as exc:
            p.load(mesh_id, vertices, faces)
        assert exc.value.code == "MESH_INVALID_INPUT"
    assert p.stats()["faces"] == 8


def test_operations_require_a_loaded_mesh():
    p = planner()
    calls = [
        lambda: p.plan(),
        lambda: p.set_target(4),
        lambda: p.apply_round(),
        lambda: p.report(),
        lambda: p.rollback(0),
        lambda: p.edge_cost(0, 1),
        lambda: p.lock_boundary(),
        lambda: p.snapshot(),
    ]
    for call in calls:
        with pytest.raises(mp.MeshPlanError) as exc:
            call()
        assert exc.value.code == "MESH_NO_MESH"


def test_edge_cost_is_squared_distance():
    p = planner()
    p.load("octa", OCTA_VERTICES, OCTA_FACES)
    assert p.edge_cost(0, 1) == pytest.approx(2.0)
    assert p.edge_cost(1, 0) == pytest.approx(2.0)
    assert p.edge_cost(0, 2) == pytest.approx(4.0)
    assert p.edge_cost(4, 5) == pytest.approx(4.0)
    for left, right in ((0, 0), (0, 9)):
        with pytest.raises(mp.MeshPlanError) as exc:
            p.edge_cost(left, right)
        assert exc.value.code == "MESH_INVALID_INPUT"


def test_set_target_validates_the_budget():
    p = planner()
    p.load("octa", OCTA_VERTICES, OCTA_FACES)
    with pytest.raises(mp.MeshPlanError) as exc:
        p.apply_round()
    assert exc.value.code == "MESH_NO_TARGET"
    for bad in (0, -1, 8, 9, 3.5):
        with pytest.raises(mp.MeshPlanError) as exc:
            p.set_target(bad)
        assert exc.value.code == "MESH_INVALID_TARGET"
    assert p.set_target(4) == 4
    assert p.report()["target"] == 4


def test_plan_is_ordered_by_cost_then_index():
    p = octa()
    plan = p.plan()
    assert len(plan) == 12
    assert plan == sorted(plan)
    assert plan[0] == (2.0, 0, 1)
    seen = set()
    for cost, survivor, removed in plan:
        assert survivor < removed
        assert cost == pytest.approx(p.edge_cost(survivor, removed))
        seen.add((survivor, removed))
    assert len(seen) == len(plan)
    assert p.plan() == plan


def test_apply_round_merges_into_the_survivor():
    p = octa()
    record = p.apply_round()
    assert record.round == 1
    assert record.survivor == 0
    assert record.removed == 1
    assert record.cost == pytest.approx(2.0)
    assert record.faces_before == 8
    assert record.faces_after == 6
    assert record.vertices == 5
    assert p.edge_cost(0, 2) == pytest.approx(2.5)
    report = p.report()
    assert report["faces"] == 6
    assert report["vertices"] == 5
    assert report["rounds"] == 1
    assert report["reached"] is False


def test_apply_round_stops_at_the_target():
    p = octa(target=6)
    record = p.apply_round()
    assert record.faces_after == 6
    assert p.report()["reached"] is True
    with pytest.raises(mp.MeshPlanError) as exc:
        p.apply_round()
    assert exc.value.code == "MESH_TARGET_REACHED"


def test_unreachable_target_reports_the_reachable_count():
    p = planner()
    p.load("twin", TWO_TETRA_VERTICES, TWO_TETRA_FACES)
    p.set_target(1)
    first = p.apply_round()
    assert first.faces_before == 8
    assert first.faces_after == 5
    second = p.apply_round()
    assert second.faces_after == 2
    assert p.plan() == []
    report = p.report()
    assert report["faces"] == 2
    assert report["target"] == 1
    assert report["reached"] is False
    assert report["reachable"] == 2
    with pytest.raises(mp.MeshPlanError) as exc:
        p.apply_round()
    assert exc.value.code == "MESH_NO_CANDIDATE"


def test_collapsed_faces_stay_distinct_and_complete():
    p = octa(target=1)
    records = []
    for _ in range(20):
        try:
            records.append(p.apply_round())
        except mp.MeshPlanError as exc:
            assert exc.code in {"MESH_TARGET_REACHED", "MESH_NO_CANDIDATE"}
            break
    assert len(records) >= 2
    faces = p.snapshot()["faces"]
    assert faces
    for face in faces:
        assert len(set(face)) == 3
    keys = [tuple(sorted(face)) for face in faces]
    assert len(keys) == len(set(keys))
    assert p.report()["faces"] == len(faces)


def test_decimation_never_leaves_non_manifold_edges():
    p = planner()
    p.load("prism", PRISM_VERTICES, PRISM_FACES)
    p.set_target(2)
    vertices_seen = []
    for _ in range(20):
        try:
            record = p.apply_round()
        except mp.MeshPlanError as exc:
            assert exc.code in {"MESH_TARGET_REACHED", "MESH_NO_CANDIDATE"}
            break
        vertices_seen.append(record.vertices)
        usage = edge_usage(p.snapshot()["faces"])
        assert usage
        assert max(usage.values()) <= 2
    assert vertices_seen
    assert vertices_seen == sorted(vertices_seen, reverse=True)
    assert p.report()["faces"] >= 1


def test_rollback_restores_earlier_rounds():
    p = octa(target=1)
    faces_after = []
    for _ in range(3):
        record = p.apply_round()
        faces_after.append(record.faces_after)
    assert p.report()["rounds"] == 3
    assert p.rollback(1) == faces_after[0]
    report = p.report()
    assert report["faces"] == faces_after[0]
    assert report["rounds"] == 1
    with pytest.raises(mp.MeshPlanError) as exc:
        p.rollback(5)
    assert exc.value.code == "MESH_ROLLBACK_OUT_OF_RANGE"
    assert p.rollback(0) == 8
    assert p.report()["rounds"] == 0
    assert p.report()["faces"] == 8
    again = p.apply_round()
    assert again.round == 1
    assert again.faces_after == faces_after[0]


def test_planning_is_deterministic_across_instances():
    left = octa(target=2)
    right = octa(target=2)
    assert left.plan() == right.plan()
    left.apply_round()
    right.apply_round()
    assert left.plan() == right.plan()
    assert left.report()["faces"] == right.report()["faces"]


def test_lock_boundary_protects_the_rim():
    p = planner()
    summary = p.load("quad", QUAD_VERTICES, QUAD_FACES)
    assert summary.boundary_vertices == (0, 1, 2, 3)
    assert p.lock_boundary([0, 2, 2]) == 2
    assert p.lock_boundary([1]) == 3
    assert p.stats()["locked"] == 3
    with pytest.raises(mp.MeshPlanError) as exc:
        p.lock_boundary([9])
    assert exc.value.code == "MESH_INVALID_INPUT"
    fresh = planner()
    fresh.load("quad", QUAD_VERTICES, QUAD_FACES)
    assert fresh.lock_boundary() == 4
    assert fresh.stats()["locked"] == 4


def test_snapshot_roundtrip_keeps_the_queue_state():
    p = octa(target=1)
    record = p.apply_round()
    state = p.snapshot()
    assert set(state) == {"version", "mesh_id", "vertices", "faces", "locked",
                          "boundary", "target", "history", "counters"}
    pristine = copy.deepcopy(state)
    state["faces"].clear()
    state["counters"]["applied"] = 99
    assert p.report()["faces"] == record.faces_after
    assert p.stats()["applied"] == 1

    clone = planner()
    clone.restore(pristine)
    assert clone.stats()["mesh"] == "octa"
    assert clone.stats()["applied"] == 1
    assert clone.report()["faces"] == record.faces_after
    assert clone.report()["rounds"] == 1
    assert clone.plan() == p.plan()
    assert clone.rollback(0) == 8
    assert clone.report()["faces"] == 8


def test_restore_rejects_malformed_snapshots():
    p = octa(target=1)
    p.apply_round()
    valid = p.snapshot()
    bad_snapshots = [
        None,
        {},
        dict(valid, version=2),
        dict(valid, mesh_id=""),
        dict(valid, vertices="none"),
        dict(valid, faces=[]),
        dict(valid, faces=[(0, 1)]),
        dict(valid, locked=[9]),
        dict(valid, target=0),
        dict(valid, history=[]),
        dict(valid, counters=[]),
        {key: value for key, value in valid.items() if key != "locked"},
    ]
    for snapshot in bad_snapshots:
        with pytest.raises(mp.MeshPlanError) as exc:
            p.restore(snapshot)
        assert exc.value.code == "MESH_SNAPSHOT_INVALID"
    assert p.report()["faces"] == 6
    assert p.stats()["applied"] == 1
    assert p.apply_round().faces_before == 6
