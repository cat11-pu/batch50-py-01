import threading

import pytest

import attestation_trust_policy as at

BASE = 1_800_000_000
AAGUID = "00112233445566778899aabbccddeeff"
OTHER = "ffeeddccbbaa99887766554433221100"
NEW = "0123456789abcdef0123456789abcdef"


def policy(**kwargs):
    return at.AttestationTrustPolicy(rp_id="rp.example", **kwargs)


def entry(aaguid=AAGUID, formats=("none",), anchors=(), version=1,
          vendor="Acme", model="KeyOne"):
    return {"aaguid": aaguid, "vendor": vendor, "model": model,
            "formats": list(formats), "anchors": list(anchors),
            "version": version}


def code_of(exc_info):
    return exc_info.value.code


def test_upsert_stores_normalized_metadata():
    pol = policy()
    rec = pol.upsert_metadata(entry(formats=("direct", "none"),
                                    anchors=("root-a",)))
    assert rec["aaguid"] == AAGUID
    assert rec["vendor"] == "Acme"
    assert rec["model"] == "KeyOne"
    assert rec["formats"] == ("direct", "none")
    assert rec["anchors"] == ("root-a",)
    assert rec["version"] == 1
    stored = pol.metadata_for(AAGUID)
    assert stored["model"] == "KeyOne"
    assert stored["formats"] == ("direct", "none")
    assert pol.stats()["upserts"] == 1


def test_same_version_conflict_and_identical_reupsert():
    pol = policy()
    pol.upsert_metadata(entry())
    again = pol.upsert_metadata(entry())
    assert again["version"] == 1
    assert pol.stats()["upserts"] == 1
    with pytest.raises(at.AttestationError) as conflict:
        pol.upsert_metadata(entry(vendor="Other"))
    assert code_of(conflict) == "ATTEST_CONFLICT"
    assert pol.metadata_for(AAGUID)["vendor"] == "Acme"


def test_upsert_validates_aaguid_vendor_formats_and_version():
    pol = policy()
    with pytest.raises(at.AttestationError) as bad_id:
        pol.upsert_metadata(entry(aaguid="zz"))
    assert code_of(bad_id) == "ATTEST_INVALID"
    with pytest.raises(at.AttestationError) as bad_vendor:
        pol.upsert_metadata(entry(vendor="  "))
    assert code_of(bad_vendor) == "ATTEST_INVALID"
    with pytest.raises(at.AttestationError) as bad_formats:
        pol.upsert_metadata(entry(formats=()))
    assert code_of(bad_formats) == "ATTEST_INVALID"
    with pytest.raises(at.AttestationError) as bad_version:
        pol.upsert_metadata(entry(version=0))
    assert code_of(bad_version) == "ATTEST_INVALID"
    assert pol.stats()["upserts"] == 0


def test_evaluate_accepts_known_authenticator_with_none():
    pol = policy()
    pol.upsert_metadata(entry(formats=("none",)))
    decision = pol.evaluate(AAGUID, "none")
    assert decision["status"] == "accepted"
    assert decision["aaguid"] == AAGUID
    assert decision["fmt"] == "none"
    assert decision["metadata_version"] == 1
    assert decision["cached"] is False
    assert pol.stats()["evaluations"] == 1


def test_unknown_aaguid_is_quarantined_on_first_sight():
    pol = policy()
    decision = pol.evaluate(NEW, "none")
    assert decision["status"] == "quarantined"
    assert decision["code"] == "ATTEST_UNKNOWN"
    assert pol.quarantined() == [NEW]
    assert pol.stats()["quarantined"] == 1
    with pytest.raises(at.AttestationError) as blocked:
        pol.evaluate(NEW, "none")
    assert code_of(blocked) == "ATTEST_QUARANTINED"


def test_format_unsupported_by_model_is_rejected():
    pol = policy()
    pol.upsert_metadata(entry(formats=("none",)))
    pol.set_policy(("enterprise", "direct", "indirect", "none"))
    with pytest.raises(at.AttestationError) as unsupported:
        pol.evaluate(AAGUID, "direct")
    assert code_of(unsupported) == "ATTEST_FORMAT"


def test_format_below_policy_minimum_is_rejected():
    pol = policy()
    pol.upsert_metadata(entry(formats=("none",)))
    pol.set_policy(("enterprise", "direct", "indirect", "none"),
                   minimum="direct")
    with pytest.raises(at.AttestationError) as weak:
        pol.evaluate(AAGUID, "none")
    assert code_of(weak) == "ATTEST_WEAKER"


def test_format_outside_policy_order_is_rejected():
    pol = policy()
    pol.upsert_metadata(entry(formats=("direct",), anchors=("root-a",)))
    pol.set_policy(("none", "indirect"))
    with pytest.raises(at.AttestationError) as not_allowed:
        pol.evaluate(AAGUID, "direct", trust_path_root="root-a")
    assert code_of(not_allowed) == "ATTEST_FORMAT_NOT_ALLOWED"


def test_direct_attestation_without_chain_root_is_rejected():
    pol = policy()
    pol.upsert_metadata(entry(formats=("direct",), anchors=("root-a",)))
    pol.set_policy(("direct", "none"))
    with pytest.raises(at.AttestationError) as missing:
        pol.evaluate(AAGUID, "direct")
    assert code_of(missing) == "ATTEST_ANCHOR_MISSING"
    accepted = pol.evaluate(AAGUID, "direct", trust_path_root="root-a")
    assert accepted["status"] == "accepted"


def test_manual_quarantine_blocks_known_authenticator():
    pol = policy()
    pol.upsert_metadata(entry(formats=("none",)))
    pol.upsert_metadata(entry(aaguid=OTHER, formats=("none",)))
    first = pol.quarantine(AAGUID, "批次异常")
    assert first["aaguid"] == AAGUID
    assert first["reason"] == "批次异常"
    pol.quarantine(OTHER, "型号停产")
    assert pol.quarantined() == sorted([AAGUID, OTHER])
    assert pol.stats()["quarantined"] == 2
    with pytest.raises(at.AttestationError) as blocked:
        pol.evaluate(AAGUID, "none")
    assert code_of(blocked) == "ATTEST_QUARANTINED"


def test_anchor_rotation_keeps_overlap_window():
    pol = policy(overlap_seconds=1000)
    pol.upsert_metadata(entry(formats=("direct",), anchors=("root-a",)))
    rotated = pol.rotate_anchor(AAGUID, "root-new", now=BASE)
    assert rotated["aaguid"] == AAGUID
    assert pol.active_anchors(AAGUID, now=BASE) == ("root-a", "root-new")
    assert pol.active_anchors(AAGUID, now=BASE + 999) == ("root-a", "root-new")
    assert pol.active_anchors(AAGUID, now=BASE + 1000) == ("root-new",)
    assert pol.stats()["rotations"] == 1


def test_reload_replaces_whole_set_and_rejects_broken_package():
    pol = policy()
    pol.upsert_metadata(entry(formats=("none",)))
    out = pol.reload({"version": 2, "entries": [entry(aaguid=NEW, formats=("none",))]})
    assert out["version"] == 2
    assert out["count"] == 1
    with pytest.raises(at.AttestationError) as gone:
        pol.metadata_for(AAGUID)
    assert code_of(gone) == "ATTEST_UNKNOWN"
    assert pol.metadata_for(NEW)["aaguid"] == NEW
    assert pol.stats()["reloads"] == 1
    with pytest.raises(at.AttestationError) as broken:
        pol.reload({"version": 3, "entries": "nope"})
    assert code_of(broken) == "ATTEST_INVALID"
    assert pol.metadata_for(NEW)["aaguid"] == NEW


def test_evaluate_caches_until_metadata_version_moves():
    pol = policy()
    pol.upsert_metadata(entry(formats=("none",)))
    first = pol.evaluate(AAGUID, "none")
    second = pol.evaluate(AAGUID, "none")
    assert first["cached"] is False
    assert second["cached"] is True
    assert second["status"] == "accepted"
    assert pol.stats()["cache_hits"] == 1
    pol.upsert_metadata(entry(formats=("none",), version=2))
    third = pol.evaluate(AAGUID, "none")
    assert third["cached"] is False
    assert third["metadata_version"] == 2


def test_snapshot_restore_keeps_metadata_policy_and_quarantine():
    pol = policy()
    pol.upsert_metadata(entry(formats=("direct",), anchors=("root-a",)))
    pol.set_policy(("direct", "none"))
    pol.quarantine(OTHER, "未知型号")
    clone = policy()
    clone.restore(pol.snapshot())
    assert clone.metadata_for(AAGUID)["anchors"] == ("root-a",)
    assert clone.quarantined() == [OTHER]
    assert clone.stats() == pol.stats()
    decision = clone.evaluate(AAGUID, "direct", trust_path_root="root-a")
    assert decision["status"] == "accepted"
    with pytest.raises(at.AttestationError) as broken:
        clone.restore({"version": 1, "metadata": None})
    assert code_of(broken) == "ATTEST_SNAPSHOT"
    assert clone.metadata_for(AAGUID)["aaguid"] == AAGUID


def test_concurrent_evaluation_never_sees_half_metadata():
    pol = policy()
    pol.upsert_metadata(entry(formats=("none",)))
    pol.set_policy(("none",))
    results = []
    failures = []
    guard = threading.Lock()

    def evaluator():
        try:
            decision = pol.evaluate(AAGUID, "none")
        except Exception as err:  # noqa: BLE001 - collect refusal reason
            with guard:
                failures.append(getattr(err, "code", type(err).__name__))
        else:
            with guard:
                results.append(decision)

    def reloader():
        try:
            pol.reload({"version": 2,
                        "entries": [entry(formats=("none",), version=2)]})
        except Exception as err:  # noqa: BLE001 - collect refusal reason
            with guard:
                failures.append(getattr(err, "code", type(err).__name__))

    threads = [threading.Thread(target=reloader)]
    threads += [threading.Thread(target=evaluator) for _ in range(16)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert failures == []
    assert len(results) == 16
    assert {item["status"] for item in results} == {"accepted"}
    assert {item["metadata_version"] for item in results} <= {1, 2}
    assert pol.metadata_for(AAGUID)["version"] == 2
