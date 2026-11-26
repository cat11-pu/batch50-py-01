import copy
import threading

import pytest

import media_rotation_normalizer as mrn


def normalizer(**kwargs):
    return mrn.MediaRotationNormalizer(**kwargs)


def test_register_neutral_asset_and_inspect():
    norm = normalizer()
    state = norm.register("clip-a", width=1920, height=1080)
    assert state.asset_id == "clip-a"
    assert state.width == 1920
    assert state.height == 1080
    assert state.rotation == 0
    assert state.flip_h is False
    assert state.flip_v is False
    assert state.sar == (1, 1)
    assert state.revision == 0
    assert state.normalized is False
    info = norm.inspect("clip-a")
    assert info["output_width"] == 1920
    assert info["output_height"] == 1080
    assert info["normalized"] is False
    assert info["revision"] == 0
    assert norm.is_normalized("clip-a") is False
    assert norm.stats() == {"registered": 1, "plans": 0, "skipped": 0,
                            "applied": 0, "rollbacks": 0, "discarded": 0}


def test_register_validation_and_duplicates():
    norm = normalizer()
    bad_calls = [
        dict(width=0, height=1080),
        dict(width=1920, height=-1),
        dict(width=1920, height=1080, rotation=45),
        dict(width=1920, height=1080, sar="1:0"),
        dict(width=1920, height=1080, sar="square"),
    ]
    for kwargs in bad_calls:
        with pytest.raises(mrn.MediaError) as exc:
            norm.register("bad", **kwargs)
        assert exc.value.code == "MEDIA_ASSET_INVALID"
    with pytest.raises(mrn.MediaError) as exc:
        norm.register("   ", width=1920, height=1080)
    assert exc.value.code == "MEDIA_ASSET_INVALID"
    norm.register("clip-a", width=1920, height=1080)
    with pytest.raises(mrn.MediaError) as exc:
        norm.register("clip-a", width=1280, height=720)
    assert exc.value.code == "MEDIA_ASSET_EXISTS"


def test_rotated_output_dimensions():
    norm = normalizer()
    norm.register("r90", width=1920, height=1080, rotation=90)
    norm.register("r180", width=1920, height=1080, rotation=180)
    norm.register("r270", width=1920, height=1080, rotation=270)
    assert (norm.inspect("r90")["output_width"],
            norm.inspect("r90")["output_height"]) == (1080, 1920)
    assert (norm.inspect("r270")["output_width"],
            norm.inspect("r270")["output_height"]) == (1080, 1920)
    assert (norm.inspect("r180")["output_width"],
            norm.inspect("r180")["output_height"]) == (1920, 1080)


def test_filter_chain_for_pure_rotations_and_flips():
    norm = normalizer()
    norm.register("r0", width=640, height=480)
    norm.register("r90", width=640, height=480, rotation=90)
    norm.register("r180", width=640, height=480, rotation=180)
    norm.register("r270", width=640, height=480, rotation=270)
    norm.register("fh", width=640, height=480, flip_h=True)
    assert norm.plan_filters("r0") == ()
    assert norm.plan_filters("r90") == ("transpose=1",)
    assert norm.plan_filters("r180") == ("rotate=180",)
    assert norm.plan_filters("r270") == ("transpose=2",)
    assert norm.plan_filters("fh") == ("hflip",)


def test_normalize_creates_pending_plan():
    norm = normalizer()
    norm.register("clip-b", width=1920, height=1080, rotation=90)
    plan = norm.normalize("clip-b")
    assert plan.plan_id == "plan-0001"
    assert plan.asset_id == "clip-b"
    assert plan.status == "planned"
    assert plan.rotation == 90
    assert plan.filters == ("transpose=1",)
    assert plan.output_width == 1080
    assert plan.output_height == 1920
    assert norm.pending_plans() == ("plan-0001",)
    assert norm.stats()["plans"] == 1
    assert norm.is_normalized("clip-b") is False


def test_normalize_reuses_pending_plan():
    norm = normalizer()
    norm.register("clip-b", width=1920, height=1080, rotation=90)
    first = norm.normalize("clip-b")
    second = norm.normalize("clip-b")
    assert second.plan_id == first.plan_id
    assert norm.pending_plans() == ("plan-0001",)
    assert norm.stats()["plans"] == 1
    assert norm.stats()["skipped"] == 0


def test_apply_marks_asset_normalized():
    norm = normalizer()
    norm.register("clip-b", width=1920, height=1080, rotation=90)
    plan = norm.normalize("clip-b")
    applied = norm.apply(plan.plan_id)
    assert applied.status == "applied"
    assert norm.is_normalized("clip-b") is True
    info = norm.inspect("clip-b")
    assert info["rotation"] == 0
    assert info["normalized"] is True
    assert info["revision"] == 1
    assert info["output_width"] == 1080
    assert info["output_height"] == 1920
    metadata = norm.metadata_of("clip-b")
    assert metadata["before"]["rotation"] == 90
    assert metadata["before"]["width"] == 1920
    assert metadata["after"]["rotation"] == 0
    assert metadata["after"]["width"] == 1080
    assert metadata["after"]["height"] == 1920
    assert metadata["normalized"] is True
    assert norm.pending_plans() == ()
    assert norm.stats()["applied"] == 1


def test_apply_unknown_or_consumed_plan_is_rejected():
    norm = normalizer()
    norm.register("clip-b", width=1920, height=1080, rotation=90)
    with pytest.raises(mrn.MediaError) as exc:
        norm.apply("plan-9999")
    assert exc.value.code == "MEDIA_UNKNOWN_PLAN"
    plan = norm.normalize("clip-b")
    norm.apply(plan.plan_id)
    with pytest.raises(mrn.MediaError) as exc:
        norm.apply(plan.plan_id)
    assert exc.value.code == "MEDIA_UNKNOWN_PLAN"


def test_normalize_after_apply_is_skipped():
    norm = normalizer()
    norm.register("clip-c", width=1280, height=720, rotation=0)
    norm.apply(norm.normalize("clip-c").plan_id)
    again = norm.normalize("clip-c")
    assert again.status == "skipped"
    assert again.filters == ()
    assert again.output_width == 1280
    assert again.output_height == 720
    assert norm.is_normalized("clip-c") is True
    assert norm.inspect("clip-c")["revision"] == 1
    assert norm.stats()["skipped"] == 1
    assert norm.pending_plans() == ()


def test_rollback_restores_previous_metadata():
    norm = normalizer()
    norm.register("clip-b", width=1920, height=1080, rotation=90)
    norm.apply(norm.normalize("clip-b").plan_id)
    restored = norm.rollback("clip-b")
    assert restored.rotation == 90
    assert restored.width == 1920
    assert restored.height == 1080
    assert restored.normalized is False
    assert restored.revision == 2
    metadata = norm.metadata_of("clip-b")
    assert metadata["after"] is None
    assert metadata["before"]["rotation"] == 90
    assert norm.is_normalized("clip-b") is False
    assert norm.stats()["rollbacks"] == 1
    with pytest.raises(mrn.MediaError) as exc:
        norm.rollback("clip-b")
    assert exc.value.code == "MEDIA_NOT_NORMALIZED"


def test_discard_plan_drops_pending_work():
    norm = normalizer()
    norm.register("clip-b", width=1920, height=1080, rotation=90)
    plan = norm.normalize("clip-b")
    assert norm.discard_plan(plan.plan_id) is True
    assert norm.pending_plans() == ()
    assert norm.stats()["discarded"] == 1
    with pytest.raises(mrn.MediaError) as exc:
        norm.apply(plan.plan_id)
    assert exc.value.code == "MEDIA_UNKNOWN_PLAN"
    assert norm.discard_plan("plan-9999") is False


def test_metadata_is_detached_and_unknown_asset_rejected():
    norm = normalizer()
    norm.register("clip-a", width=1920, height=1080)
    metadata = norm.metadata_of("clip-a")
    metadata["before"]["width"] = 5
    assert norm.inspect("clip-a")["width"] == 1920
    for call in (lambda: norm.inspect("nope"),
                 lambda: norm.plan_filters("nope"),
                 lambda: norm.normalize("nope"),
                 lambda: norm.metadata_of("nope")):
        with pytest.raises(mrn.MediaError) as exc:
            call()
        assert exc.value.code == "MEDIA_UNKNOWN_ASSET"


def test_snapshot_roundtrip_preserves_pending_and_flags():
    norm = normalizer()
    norm.register("done", width=1920, height=1080, rotation=90)
    norm.apply(norm.normalize("done").plan_id)
    norm.register("later", width=1280, height=720, rotation=270)
    pending = norm.normalize("later")
    state = norm.snapshot()
    pristine = copy.deepcopy(state)
    assert set(state) == {"version", "assets", "plans", "sequence", "stats"}
    state["assets"].clear()
    state["stats"]["applied"] = 99
    assert norm.is_normalized("done") is True
    assert norm.pending_plans() == (pending.plan_id,)
    assert norm.stats()["applied"] == 1
    clone = normalizer()
    clone.restore(pristine)
    assert clone.is_normalized("done") is True
    assert clone.pending_plans() == (pending.plan_id,)
    assert clone.inspect("done")["revision"] == 1
    assert clone.apply(pending.plan_id).status == "applied"
    assert clone.is_normalized("later") is True
    assert clone.stats() == {"registered": 2, "plans": 2, "skipped": 0,
                             "applied": 2, "rollbacks": 0, "discarded": 0}


def test_restore_rejects_malformed_state_without_mutation():
    norm = normalizer()
    norm.register("clip-a", width=1920, height=1080)
    norm.normalize("clip-a")
    bad_states = [
        None,
        {},
        {"version": 2, "assets": [], "plans": {}, "sequence": 1,
         "stats": {}},
        {"version": 1, "assets": "nope", "plans": {}, "sequence": 1,
         "stats": {}},
        {"version": 1, "assets": [], "plans": {}, "sequence": 1,
         "stats": {"plans": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(mrn.MediaError) as exc:
            norm.restore(bad)
        assert exc.value.code == "MEDIA_SNAPSHOT_INVALID"
    assert norm.pending_plans() == ("plan-0001",)
    assert norm.inspect("clip-a")["rotation"] == 0


def test_concurrent_register_normalize_apply():
    norm = normalizer()
    errors = []
    barrier = threading.Barrier(12)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            asset_id = f"clip-{index:02d}"
            norm.register(asset_id, width=1920, height=1080, rotation=90)
            plan = norm.normalize(asset_id)
            norm.apply(plan.plan_id)
        except Exception as exc:  # pragma: no cover - reported via errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,))
               for index in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    for index in range(12):
        assert norm.is_normalized(f"clip-{index:02d}") is True
    stats = norm.stats()
    assert stats["registered"] == 12
    assert stats["plans"] == 12
    assert stats["applied"] == 12
    assert norm.pending_plans() == ()
