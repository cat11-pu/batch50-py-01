import copy

import pytest

import authz_matrix_prober as amp

NOW = "2026-11-26T10:00:00+00:00"
LATER = "2026-11-26T10:05:00+00:00"


def own_resource_executor(entry):
    return 200, {"resource_owner": entry.account_id, "summary": "ok"}


def build_prober(executor=own_resource_executor, **kwargs):
    prober = amp.AuthzMatrixProber(executor=executor, **kwargs)
    prober.register_endpoint("GET", "/api/orders/{id}", domain="orders.example.test",
                             resource_kind="other", write=False)
    prober.register_endpoint("POST", "/api/orders", domain="orders.example.test",
                             resource_kind="own", write=True)
    prober.register_role("viewer", "acct-viewer", write_allowed=False)
    prober.register_role("editor", "acct-editor", write_allowed=True)
    return prober


def test_matrix_expands_endpoints_times_roles_in_order():
    prober = build_prober()
    entries = prober.build_matrix()
    assert [(e.index, e.method, e.path, e.role) for e in entries] == [
        (0, "GET", "/api/orders/{id}", "viewer"),
        (1, "GET", "/api/orders/{id}", "editor"),
        (2, "POST", "/api/orders", "viewer"),
        (3, "POST", "/api/orders", "editor"),
    ]
    assert len({e.marker for e in entries}) == 4


def test_write_endpoint_expectation_follows_role_capability():
    entries = build_prober().build_matrix()
    by_key = {(e.method, e.role): e for e in entries}
    assert by_key[("POST", "viewer")].expectation == "deny"
    assert by_key[("POST", "editor")].expectation == "allow"
    assert by_key[("GET", "viewer")].expectation == "allow"
    assert by_key[("GET", "editor")].expectation == "allow"
    assert by_key[("POST", "viewer")].write is True


def test_duplicate_endpoint_registration_is_deduped():
    prober = build_prober()
    again = prober.register_endpoint("get", "/api/orders/{id}",
                                     domain="orders.example.test")
    entries = prober.build_matrix()
    assert again.method == "GET"
    assert again.path == "/api/orders/{id}"
    assert len(entries) == 4
    assert prober.report()["deduped"] == 1


def test_marker_encodes_fingerprint_prefix_and_is_unique():
    entries = build_prober().build_matrix()
    first = entries[0]
    assert len(first.fingerprint) == 16
    assert all(ch in "0123456789abcdef" for ch in first.fingerprint)
    assert first.marker == "MK-{}-0000".format(first.fingerprint[:8])
    assert entries[3].marker.endswith("-0003")
    assert len({e.marker for e in entries}) == len(entries)


def test_invalid_catalog_inputs_are_rejected():
    prober = amp.AuthzMatrixProber()
    with pytest.raises(amp.MatrixError) as exc:
        prober.build_matrix()
    assert exc.value.code == "MATRIX_INVALID_REQUEST"

    with pytest.raises(amp.MatrixError) as exc:
        prober.register_endpoint("", "/x", domain="d")
    assert exc.value.code == "MATRIX_INVALID_REQUEST"

    with pytest.raises(amp.MatrixError) as exc:
        prober.register_role("   ", "acct")
    assert exc.value.code == "MATRIX_INVALID_REQUEST"


def test_matrix_capacity_cap_is_enforced_at_build():
    prober = build_prober(max_entries=3)
    with pytest.raises(amp.MatrixError) as exc:
        prober.build_matrix()
    assert exc.value.code == "MATRIX_CAPACITY_EXCEEDED"
    assert prober.progress()["completed"] == 0


def test_run_shard_executes_only_its_partition():
    prober = build_prober()
    prober.build_matrix()
    out = prober.run_shard(0, 2)
    assert out["executed"] == 2
    assert [row.index for row in out["results"]] == [0, 2]
    assert out["status"] == "running"
    assert all(row.verdict == "granted" for row in out["results"])


def test_rerunning_a_shard_does_not_repeat_entries():
    prober = build_prober()
    prober.build_matrix()
    prober.run_shard(0, 2)
    second = prober.run_shard(0, 2)
    assert second["executed"] == 0
    assert second["results"] == []
    assert prober.report()["executed"] == 2
    assert prober.progress()["completed"] == 2


def test_pause_blocks_execution_until_resume():
    prober = build_prober()
    prober.build_matrix()
    prober.pause("change-window")
    with pytest.raises(amp.MatrixError) as exc:
        prober.run_shard(0, 1)
    assert exc.value.code == "MATRIX_PAUSED"

    state = prober.resume(now=NOW)
    assert state["status"] == "running"
    assert state["completed"] == 0
    prober.run_shard(0, 1)
    assert prober.progress()["completed"] == 4


def test_rate_budget_pauses_instead_of_raising():
    prober = build_prober(rate_per_minute=1)
    prober.build_matrix()
    first = prober.run_shard(0, 1)
    assert first["executed"] == 1
    assert first["status"] == "paused"
    assert prober.progress()["paused_reason"] == "rate_budget"
    assert prober.progress()["completed"] == 1

    state = prober.resume(now=LATER)
    assert state["status"] == "running"
    second = prober.run_shard(0, 1)
    assert second["executed"] == 3
    assert prober.progress()["completed"] == 4


def test_progress_tracks_watermark_per_shard():
    prober = build_prober()
    prober.build_matrix()
    prober.run_shard(1, 2)
    progress = prober.progress()
    assert progress["completed"] == 2
    assert progress["shards"] == {1: 2}
    assert progress["paused_reason"] is None


def test_report_counts_each_verdict():
    def executor(entry):
        if entry.role == "viewer" and entry.method == "GET":
            return 200, {"resource_owner": "acct-somebody-else", "summary": "foreign order"}
        if entry.role == "viewer":
            return 403, {"resource_owner": "", "summary": "forbidden"}
        return 200, {"resource_owner": entry.account_id, "summary": "ok"}

    prober = build_prober(executor=executor)
    prober.build_matrix()
    prober.run_shard(0, 1)
    report = prober.report()
    assert report["total"] == 4
    assert report["executed"] == 4
    assert report["verdicts"] == {"denied": 1, "granted": 2, "exceeded": 1,
                                  "review": 0, "invalid": 0}
    assert report["blocked_roles"] == []


def test_snapshot_is_detached_and_restore_roundtrips():
    prober = build_prober()
    prober.build_matrix()
    prober.run_shard(0, 2)
    state = prober.snapshot()
    assert set(state) == {"version", "endpoints", "roles", "entries",
                          "results", "deduped", "shards"}
    assert state["shards"] == {0: 2}

    pristine = copy.deepcopy(state)
    state["entries"].clear()
    state["shards"].clear()
    state["deduped"] = 99
    assert len(prober.build_matrix()) == 4
    assert prober.progress()["completed"] == 2

    clone = amp.AuthzMatrixProber(executor=own_resource_executor)
    clone.restore(pristine)
    assert clone.progress()["completed"] == 2
    assert clone.run_shard(1, 2)["executed"] == 2


def test_restore_rejects_malformed_state_and_keeps_live_data():
    prober = build_prober()
    prober.build_matrix()
    prober.run_shard(0, 1)
    bad_states = [
        None,
        {},
        {"version": 1, "endpoints": [], "roles": [], "entries": [],
         "results": [], "deduped": 0},
        {"version": 1, "endpoints": "nope", "roles": [], "entries": [],
         "results": [], "deduped": 0, "shards": {}},
    ]
    for bad in bad_states:
        with pytest.raises(amp.MatrixError) as exc:
            prober.restore(bad)
        assert exc.value.code == "MATRIX_SNAPSHOT_INVALID"
    assert prober.progress()["completed"] == 4


def test_invalid_shard_arguments_are_rejected():
    prober = build_prober()
    prober.build_matrix()
    for index, count in ((0, 0), (2, 2), (-1, 2)):
        with pytest.raises(amp.MatrixError) as exc:
            prober.run_shard(index, count)
        assert exc.value.code == "MATRIX_SHARD_INVALID"
    assert prober.progress()["completed"] == 0
