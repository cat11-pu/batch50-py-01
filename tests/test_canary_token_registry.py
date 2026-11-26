import copy
import threading
from datetime import datetime, timedelta, timezone

import pytest

import canary_token_registry as cg

BASE = datetime(2026, 11, 26, 9, 0, 0, tzinfo=timezone.utc)


def at(seconds=0):
    return (BASE + timedelta(seconds=seconds)).isoformat()


def registry(**kwargs):
    return cg.CanaryTokenRegistry(**kwargs)


def issue(reg, token_id, *, batch_id="batch-a", purpose="aws_key",
          placement="s3://cfg/app.env", owner="soc", now=at(0)):
    return reg.issue(token_id, purpose=purpose, placement=placement,
                     batch_id=batch_id, owner=owner, now=now)


def test_issue_registers_active_token_and_counts():
    reg = registry()
    token = issue(reg, "tok-1")
    assert isinstance(token, cg.CanaryToken)
    assert (token.token_id, token.purpose, token.placement) == (
        "tok-1", "aws_key", "s3://cfg/app.env")
    assert (token.batch_id, token.owner, token.issued_at) == (
        "batch-a", "soc", at(0))
    assert token.state == "active"
    assert token.hits == 0
    assert token.last_hit_at is None
    assert token.revoked_at is None
    assert token.revoke_reason is None
    assert token.assets == ()
    assert reg.stats() == {"issued": 1, "hits": 0, "deduped": 0,
                           "escalated": 0, "revoked": 0, "frozen": 0}


def test_issue_rejects_duplicate_token():
    reg = registry()
    issue(reg, "tok-1")
    with pytest.raises(cg.CanaryError) as exc:
        issue(reg, "tok-1", purpose="dns")
    assert exc.value.code == "CANARY_DUPLICATE_TOKEN"
    assert len(reg.tokens()) == 1
    assert reg.tokens()[0].purpose == "aws_key"
    assert reg.stats()["issued"] == 1


def test_issue_rejects_invalid_fields():
    reg = registry()
    bad = [
        dict(token_id="", purpose="aws_key", placement="p", batch_id="b", owner="o"),
        dict(token_id="tok-1", purpose="", placement="p", batch_id="b", owner="o"),
        dict(token_id="tok-2", purpose="aws_key", placement="  ", batch_id="b", owner="o"),
        dict(token_id="tok-3", purpose="aws_key", placement="p", batch_id="", owner="o"),
        dict(token_id="tok-4", purpose="aws_key", placement="p", batch_id="b", owner=""),
        dict(token_id=7, purpose="aws_key", placement="p", batch_id="b", owner="o"),
    ]
    for kwargs in bad:
        with pytest.raises(cg.CanaryError) as exc:
            reg.issue(now=at(0), **kwargs)
        assert exc.value.code == "CANARY_BAD_REQUEST"
    assert reg.tokens() == []
    assert reg.stats()["issued"] == 0


def test_first_hit_freezes_assets_and_cascades_batch():
    reg = registry()
    issue(reg, "tok-1", batch_id="batch-a")
    issue(reg, "tok-2", batch_id="batch-a")
    issue(reg, "tok-3", batch_id="batch-a")
    issue(reg, "tok-4", batch_id="batch-b")
    reg.bind_asset("tok-1", "asset-1")
    reg.bind_asset("tok-2", "asset-2")
    reg.bind_asset("tok-4", "asset-4")
    out = reg.report_hit("tok-1", source="waf", now=at(10))
    assert out["token_id"] == "tok-1"
    assert out["deduped"] is False
    assert out["hits"] == 1
    assert out["cascaded"] == 2
    assert reg.status("tok-1")["state"] == "triggered"
    assert reg.status("tok-2")["state"] == "revoked"
    assert reg.status("tok-3")["state"] == "revoked"
    assert reg.status("tok-4")["state"] == "active"
    assert [row["asset_id"] for row in reg.frozen_assets()] == ["asset-1", "asset-2"]
    assert [row["token_id"] for row in reg.frozen_assets()] == ["tok-1", "tok-2"]
    assert all(row["reason"] == "canary_hit" for row in reg.frozen_assets())
    assert reg.stats() == {"issued": 4, "hits": 1, "deduped": 0,
                           "escalated": 1, "revoked": 2, "frozen": 2}


def test_repeated_hit_inside_window_is_deduped_but_counted():
    reg = registry(hit_window_seconds=300)
    issue(reg, "tok-1")
    first = reg.report_hit("tok-1", source="waf", now=at(0))
    second = reg.report_hit("tok-1", source="waf", now=at(100))
    assert first["deduped"] is False
    assert first["hits"] == 1
    assert second["deduped"] is True
    assert second["hits"] == 2
    assert second["cascaded"] == 0
    assert reg.status("tok-1")["hits"] == 2
    assert reg.status("tok-1")["last_hit_at"] == at(100)
    assert reg.stats()["deduped"] == 1
    assert reg.stats()["escalated"] == 1


def test_hit_after_window_is_not_deduped():
    reg = registry(hit_window_seconds=300)
    issue(reg, "tok-1")
    reg.report_hit("tok-1", source="waf", now=at(0))
    out = reg.report_hit("tok-1", source="waf", now=at(400))
    assert out["deduped"] is False
    assert out["hits"] == 2
    assert reg.status("tok-1")["last_hit_at"] == at(400)
    assert reg.stats()["deduped"] == 0


def test_unknown_token_is_rejected_everywhere():
    reg = registry()
    with pytest.raises(cg.CanaryError) as exc:
        reg.report_hit("nope", source="waf", now=at(0))
    assert exc.value.code == "CANARY_UNKNOWN_TOKEN"
    with pytest.raises(cg.CanaryError) as exc:
        reg.status("nope")
    assert exc.value.code == "CANARY_UNKNOWN_TOKEN"
    with pytest.raises(cg.CanaryError) as exc:
        reg.revoke("nope", reason="manual", now=at(0))
    assert exc.value.code == "CANARY_UNKNOWN_TOKEN"
    with pytest.raises(cg.CanaryError) as exc:
        reg.bind_asset("nope", "asset-1")
    assert exc.value.code == "CANARY_UNKNOWN_TOKEN"


def test_revoke_marks_token_and_freezes_its_assets():
    reg = registry()
    issue(reg, "tok-1")
    reg.bind_asset("tok-1", "asset-2")
    reg.bind_asset("tok-1", "asset-1")
    out = reg.revoke("tok-1", reason="manual", now=at(5))
    assert out["token_id"] == "tok-1"
    assert out["changed"] is True
    assert out["frozen_assets"] == 2
    token = reg.status("tok-1")
    assert token["state"] == "revoked"
    assert token["revoked_at"] == at(5)
    assert token["revoke_reason"] == "manual"
    assert token["assets"] == ("asset-1", "asset-2")
    frozen = reg.frozen_assets()
    assert [row["asset_id"] for row in frozen] == ["asset-1", "asset-2"]
    assert [row["reason"] for row in frozen] == ["manual", "manual"]
    assert reg.stats()["revoked"] == 1
    assert reg.stats()["frozen"] == 2


def test_cascade_revokes_all_active_tokens_in_batch():
    reg = registry()
    issue(reg, "tok-1", batch_id="batch-a")
    issue(reg, "tok-2", batch_id="batch-a")
    reg.bind_asset("tok-2", "asset-2")
    issue(reg, "tok-3", batch_id="batch-b")
    out = reg.cascade("batch-a", reason="leak", now=at(7))
    assert out["batch_id"] == "batch-a"
    assert out["revoked"] == 2
    assert out["already_revoked"] == 0
    assert out["frozen_assets"] == 1
    assert reg.status("tok-1")["state"] == "revoked"
    assert reg.status("tok-2")["state"] == "revoked"
    assert reg.status("tok-3")["state"] == "active"
    assert reg.frozen_assets()[0]["reason"] == "leak"
    assert reg.stats()["revoked"] == 2


def test_cascade_unknown_batch_is_rejected():
    reg = registry()
    issue(reg, "tok-1", batch_id="batch-a")
    with pytest.raises(cg.CanaryError) as exc:
        reg.cascade("batch-z", reason="leak", now=at(1))
    assert exc.value.code == "CANARY_UNKNOWN_BATCH"
    assert reg.status("tok-1")["state"] == "active"


def test_status_reports_hit_fields_and_sorted_assets():
    reg = registry()
    issue(reg, "tok-1")
    reg.bind_asset("tok-1", "asset-9")
    reg.bind_asset("tok-1", "asset-1")
    reg.report_hit("tok-1", source="waf", now=at(1))
    row = reg.status("tok-1")
    assert row["token_id"] == "tok-1"
    assert row["state"] == "triggered"
    assert row["hits"] == 1
    assert row["last_hit_at"] == at(1)
    assert row["batch_id"] == "batch-a"
    assert row["assets"] == ("asset-1", "asset-9")
    assert row["revoked_at"] is None
    assert row["revoke_reason"] is None


def test_tokens_filter_by_batch_and_sort_by_id():
    reg = registry()
    issue(reg, "tok-b", batch_id="batch-a")
    issue(reg, "tok-a", batch_id="batch-a")
    issue(reg, "tok-c", batch_id="batch-b")
    assert [row.token_id for row in reg.tokens(batch_id="batch-a")] == ["tok-a", "tok-b"]
    assert [row.token_id for row in reg.tokens()] == ["tok-a", "tok-b", "tok-c"]
    assert reg.tokens(batch_id="batch-z") == []


def test_snapshot_is_detached_and_restore_roundtrips():
    reg = registry()
    issue(reg, "tok-1", batch_id="batch-a")
    issue(reg, "tok-2", batch_id="batch-a")
    reg.bind_asset("tok-1", "asset-1")
    reg.report_hit("tok-1", source="waf", now=at(0))
    state = reg.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "tokens", "assets", "frozen", "stats"}

    state["tokens"].clear()
    state["frozen"].clear()
    state["stats"]["hits"] = 99
    assert reg.status("tok-1")["hits"] == 1
    assert reg.status("tok-2")["state"] == "revoked"

    clone = registry()
    clone.restore(pristine)
    assert clone.status("tok-1")["state"] == "triggered"
    assert clone.status("tok-2")["state"] == "revoked"
    assert clone.status("tok-1")["assets"] == ("asset-1",)
    assert [row["asset_id"] for row in clone.frozen_assets()] == ["asset-1"]
    assert clone.stats() == reg.stats()


def test_restore_rejects_malformed_state_without_touching_live():
    reg = registry()
    issue(reg, "tok-1")
    full_stats = {"issued": 1, "hits": 0, "deduped": 0,
                  "escalated": 0, "revoked": 0, "frozen": 0}
    bad_states = [
        None,
        {},
        {"version": 2, "tokens": [], "assets": {}, "frozen": [], "stats": full_stats},
        {"version": 1, "tokens": "nope", "assets": {}, "frozen": [], "stats": full_stats},
        {"version": 1, "tokens": [], "assets": [], "frozen": [], "stats": full_stats},
        {"version": 1, "tokens": [], "assets": {}, "frozen": [], "stats": {"issued": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(cg.CanaryError) as exc:
            reg.restore(bad)
        assert exc.value.code == "CANARY_SNAPSHOT_INVALID"

    assert reg.status("tok-1")["state"] == "active"
    assert reg.stats()["issued"] == 1


def test_concurrent_hits_are_serialized_and_counted():
    reg = registry(hit_window_seconds=300)
    issue(reg, "tok-1")
    errors = []
    barrier = threading.Barrier(8)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            reg.report_hit("tok-1", source=f"probe-{index}", now=at(0))
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert reg.status("tok-1")["hits"] == 8
    assert reg.stats()["deduped"] == 7
    assert reg.stats()["escalated"] == 1
