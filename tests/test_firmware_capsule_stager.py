import hashlib
import hmac
from pathlib import Path

import pytest

import firmware_capsule_stager as fw

MODEL = "router-x1"
SECRET = b"vendor-secret-1"
PAYLOAD = b"firmware-image-2026-11"


def sign(model, version, payload, secret=SECRET):
    body = f"{model}:{version}:{hashlib.sha256(payload).hexdigest()}".encode()
    return hmac.new(secret, body, hashlib.sha256).hexdigest()


def stager(tmp_path, **kwargs):
    kwargs.setdefault("model", MODEL)
    kwargs.setdefault("allowed_models", (MODEL,))
    kwargs.setdefault("trusted_keys", {"vendor-1": SECRET})
    kwargs.setdefault("chunk_size", 4)
    kwargs.setdefault("max_payload_bytes", 64)
    return fw.FirmwareCapsuleStager(tmp_path, **kwargs)


def stage(g, capsule_id="cap-1", version=2, payload=PAYLOAD, model=MODEL,
          key_id="vendor-1", signature=None):
    return g.stage(capsule_id=capsule_id, model=model, version=version,
                   payload=payload, key_id=key_id,
                   signature=signature if signature is not None else sign(model, version, payload))


def test_stage_writes_inactive_slot_and_reports(tmp_path):
    g = stager(tmp_path)
    report = stage(g)
    assert report.state == "staged"
    assert report.slot == "B"
    assert report.written == len(PAYLOAD) == report.total
    assert report.digest == hashlib.sha256(PAYLOAD).hexdigest()
    assert report.already_staged is False
    rows = g.capsules()
    assert len(rows) == 1
    assert Path(rows[0].path).read_bytes() == PAYLOAD
    assert g.status()["active"] == "A"
    assert g.stats()["staged"] == 1


def test_stage_rejects_model_outside_whitelist(tmp_path):
    g = stager(tmp_path)
    with pytest.raises(fw.FirmwareStagerError) as exc:
        stage(g, model="router-z9", signature=sign("router-z9", 2, PAYLOAD))
    assert exc.value.code == "FIRMWARE_MODEL_NOT_ALLOWED"
    assert g.stats()["rejected"] == 1
    assert g.capsules() == []


def test_stage_rejects_unknown_key_and_bad_signature(tmp_path):
    g = stager(tmp_path)
    with pytest.raises(fw.FirmwareStagerError) as exc:
        stage(g, key_id="vendor-9")
    assert exc.value.code == "FIRMWARE_KEY_UNKNOWN"
    with pytest.raises(fw.FirmwareStagerError) as exc:
        stage(g, signature="0" * 64)
    assert exc.value.code == "FIRMWARE_SIGNATURE_INVALID"
    assert g.stats()["rejected"] == 2
    assert g.capsules() == []


def test_stage_rejects_payload_over_limit(tmp_path):
    g = stager(tmp_path, max_payload_bytes=8)
    with pytest.raises(fw.FirmwareStagerError) as exc:
        stage(g, payload=b"012345678")
    assert exc.value.code == "FIRMWARE_PAYLOAD_TOO_LARGE"
    assert g.stats()["rejected"] == 1


def test_verify_recomputes_whole_slot_digest(tmp_path):
    g = stager(tmp_path)
    stage(g)
    ok = g.verify("cap-1")
    assert ok.valid is True
    assert ok.code == "FIRMWARE_VERIFIED"
    assert ok.digest == hashlib.sha256(PAYLOAD).hexdigest()
    assert ok.bytes_checked == len(PAYLOAD)
    Path(g.capsules()[0].path).write_bytes(b"X" * len(PAYLOAD))
    bad = g.verify("cap-1")
    assert bad.valid is False
    assert bad.code == "FIRMWARE_CHECKSUM_MISMATCH"
    assert g.stats()["verified"] == 1


def test_commit_switches_slot_and_raises_min_version(tmp_path):
    g = stager(tmp_path)
    stage(g)
    g.verify("cap-1")
    report = g.commit()
    assert (report.active, report.previous, report.version, report.idempotent) == ("B", "A", 2, False)
    assert g.status()["active"] == "B"
    assert g.status()["min_version"] == 2
    assert g.status()["slots"]["B"]["state"] == "active"
    assert g.stats()["committed"] == 1


def test_commit_requires_verified_capsule(tmp_path):
    g = stager(tmp_path)
    stage(g)
    with pytest.raises(fw.FirmwareStagerError) as exc:
        g.commit()
    assert exc.value.code == "FIRMWARE_NOT_VERIFIED"
    assert g.stats()["committed"] == 0
    assert g.status()["active"] == "A"
    g.verify("cap-1")
    assert g.commit().active == "B"


def test_commit_twice_is_idempotent(tmp_path):
    g = stager(tmp_path)
    stage(g)
    g.verify("cap-1")
    first = g.commit()
    second = g.commit()
    assert second.idempotent is True
    assert (second.active, second.previous, second.version) == (
        first.active, first.previous, first.version)
    assert g.status()["active"] == "B"
    assert g.stats()["committed"] == 1


def test_rollback_returns_to_previous_slot(tmp_path):
    g = stager(tmp_path)
    stage(g)
    g.verify("cap-1")
    g.commit()
    back = g.rollback()
    assert (back.active, back.previous, back.version, back.idempotent) == ("A", "B", 1, False)
    assert g.status()["active"] == "A"
    assert g.stats()["rolled_back"] == 1
    again = g.rollback()
    assert again.idempotent is True
    assert (again.active, again.version) == ("A", 1)
    assert g.stats()["rolled_back"] == 1


def test_rollback_without_target_is_refused(tmp_path):
    g = stager(tmp_path)
    with pytest.raises(fw.FirmwareStagerError) as exc:
        g.rollback()
    assert exc.value.code == "FIRMWARE_NO_ROLLBACK_TARGET"
    assert g.stats()["rolled_back"] == 0
    assert g.status()["active"] == "A"


def test_version_below_recorded_minimum_is_refused(tmp_path):
    g = stager(tmp_path)
    stage(g)
    g.verify("cap-1")
    g.commit()
    with pytest.raises(fw.FirmwareStagerError) as exc:
        stage(g, capsule_id="cap-old", version=1, payload=b"older-image")
    assert exc.value.code == "FIRMWARE_VERSION_ROLLBACK"
    assert len(g.capsules()) == 1
    assert g.stats()["staged"] == 1


def test_interrupted_write_resumes_from_checkpoint(tmp_path):
    payload = bytes(range(20))
    g = stager(tmp_path)
    opened = g.begin_stage(capsule_id="cap-1", model=MODEL, version=2,
                           payload=payload, key_id="vendor-1",
                           signature=sign(MODEL, 2, payload))
    assert (opened.state, opened.written, opened.total, opened.slot) == ("writing", 0, 20, "B")
    g.append_chunk("cap-1", payload[:5])
    partial = g.append_chunk("cap-1", payload[5:10])
    assert partial.written == 10
    resumed = stager(tmp_path)
    assert resumed.resume() == ("cap-1",)
    rows = resumed.capsules()
    assert rows[0].state == "staged"
    assert rows[0].written == 20
    assert Path(rows[0].path).read_bytes() == payload
    assert resumed.status()["slots"]["B"]["state"] == "staged"
    assert resumed.verify("cap-1").valid is True
    assert resumed.stats()["resumed"] == 1


def test_resume_is_noop_for_completed_capsule(tmp_path):
    g = stager(tmp_path)
    stage(g)
    digest = g.capsules()[0].digest
    assert g.resume() == ()
    assert g.stats()["resumed"] == 0
    rows = g.capsules()
    assert rows[0].state == "staged"
    assert rows[0].digest == digest


def test_capsules_sorted_and_slot_states_visible(tmp_path):
    g = stager(tmp_path)
    stage(g, version=2)
    g.verify("cap-1")
    g.commit()
    stage(g, capsule_id="cap-5", version=5, payload=b"firmware-image-2027-01")
    assert [(c.version, c.slot, c.state) for c in g.capsules()] == [
        (2, "B", "committed"),
        (5, "A", "staged"),
    ]
    status = g.status()
    assert status["slots"]["A"]["state"] == "staged"
    assert status["slots"]["A"]["version"] == 5
    assert status["slots"]["B"]["state"] == "active"
    assert status["capsules"] == 2


def test_status_and_stats_survive_restart(tmp_path):
    g = stager(tmp_path)
    stage(g)
    g.verify("cap-1")
    g.commit()
    expected = {"staged": 1, "verified": 1, "committed": 1,
                "rolled_back": 0, "rejected": 0, "resumed": 0}
    assert g.stats() == expected
    again = stager(tmp_path)
    status = again.status()
    assert status["active"] == "B"
    assert status["min_version"] == 2
    assert status["model"] == MODEL
    assert status["slots"]["B"]["version"] == 2
    assert again.stats() == expected
    assert [c.capsule_id for c in again.capsules()] == ["cap-1"]
