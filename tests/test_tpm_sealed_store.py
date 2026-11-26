import json

import pytest

import tpm_sealed_store as tpm

NOW = "2026-11-26T09:00:00+00:00"
SOON = "2026-11-26T09:00:30+00:00"
AFTER = "2026-11-26T09:01:01+00:00"
LATER = "2026-11-26T09:02:00+00:00"
DATA = "TOPSECRET-42"
H0 = "a" * 64
H7 = "b" * 64
H7B = "c" * 64


def store(**kwargs):
    return tpm.TpmSealedStore(**kwargs)


def sealed(policy=None, **kwargs):
    keeper = store(**kwargs)
    keeper.seal("app-key", DATA, pcr_indexes=[7, 0],
                expected={7: H7, 0: H0}, policy=policy, now=NOW)
    return keeper


def test_seal_records_pcr_expectation():
    keeper = store()
    record = keeper.seal("app-key", DATA, pcr_indexes=[7, 0],
                         expected={7: H7, 0: H0}, policy="boot-a", now=NOW)
    assert record.name == "app-key"
    assert record.pcr_indexes == (0, 7)
    assert record.expected == ((0, H0), (7, H7))
    assert record.policy == "boot-a"
    assert record.policy_history == ("boot-a",)
    assert record.version == 1
    assert record.reseal_count == 0
    assert record.sealed_at == NOW
    assert keeper.stats()["sealed"] == 1
    assert keeper.objects() == ["app-key"]


def test_seal_argument_validation():
    keeper = store()
    for indexes in ([], [24], [1, 1]):
        with pytest.raises(tpm.SealError) as err:
            keeper.seal("k", DATA, pcr_indexes=indexes,
                        expected={item: H0 for item in indexes}, now=NOW)
        assert err.value.code == "SEAL_BAD_PCR"
    with pytest.raises(tpm.SealError) as err:
        keeper.seal("k", DATA, pcr_indexes=[0, 7], expected={0: H0}, now=NOW)
    assert err.value.code == "SEAL_BAD_EXPECTED"
    with pytest.raises(tpm.SealError) as err:
        keeper.seal("k", DATA, pcr_indexes=[0], expected={0: "zz"}, now=NOW)
    assert err.value.code == "SEAL_BAD_EXPECTED"
    with pytest.raises(tpm.SealError) as err:
        keeper.seal("", DATA, pcr_indexes=[0], expected={0: H0}, now=NOW)
    assert err.value.code == "SEAL_BAD_NAME"
    assert keeper.stats()["denied"] == 6
    assert keeper.objects() == []


def test_unseal_matching_pcr_returns_payload():
    keeper = sealed()
    assert keeper.unseal("app-key", pcr_values={0: H0, 7: H7}, now=SOON) == DATA
    assert keeper.stats()["unsealed_ok"] == 1
    assert keeper.status("app-key")["failure_count"] == 0


def test_unseal_pcr_mismatch_reports_index_and_counts_failure():
    keeper = sealed()
    with pytest.raises(tpm.SealError) as err:
        keeper.unseal("app-key", pcr_values={0: H0, 7: H7B}, now=SOON)
    assert err.value.code == "SEAL_POLICY_FAILED"
    assert err.value.detail["index"] == 7
    assert keeper.status("app-key")["failure_count"] == 1
    assert keeper.stats()["unsealed_failed"] == 1
    assert keeper.unseal("app-key", pcr_values={0: H0, 7: H7}, now=SOON) == DATA
    assert keeper.status("app-key")["failure_count"] == 0


def test_repeated_failures_lock_the_object():
    keeper = sealed(max_failures=2)
    wrong = {0: H0, 7: H7B}
    for _ in range(2):
        with pytest.raises(tpm.SealError) as err:
            keeper.unseal("app-key", pcr_values=wrong, now=NOW)
        assert err.value.code == "SEAL_POLICY_FAILED"
    status = keeper.status("app-key")
    assert status["locked"] is True
    assert status["locked_until"] == "2026-11-26T09:01:00+00:00"
    with pytest.raises(tpm.SealError) as err:
        keeper.unseal("app-key", pcr_values={0: H0, 7: H7}, now=SOON)
    assert err.value.code == "SEAL_LOCKED"
    assert keeper.stats()["locked_events"] == 1


def test_lock_expires_and_allows_unseal_again():
    keeper = sealed(max_failures=1)
    with pytest.raises(tpm.SealError) as err:
        keeper.unseal("app-key", pcr_values={0: H0, 7: H7B}, now=NOW)
    assert err.value.code == "SEAL_POLICY_FAILED"
    with pytest.raises(tpm.SealError) as err:
        keeper.unseal("app-key", pcr_values={0: H0, 7: H7}, now=SOON)
    assert err.value.code == "SEAL_LOCKED"
    assert keeper.unseal("app-key", pcr_values={0: H0, 7: H7}, now=AFTER) == DATA
    assert keeper.stats()["unsealed_ok"] == 1


def test_object_table_is_bounded_and_evict_frees_a_slot():
    keeper = store(max_objects=1)
    keeper.seal("a", DATA, pcr_indexes=[0], expected={0: H0}, now=NOW)
    with pytest.raises(tpm.SealError) as err:
        keeper.seal("b", DATA, pcr_indexes=[0], expected={0: H0}, now=NOW)
    assert err.value.code == "SEAL_STORE_FULL"
    keeper.evict("a")
    record = keeper.seal("b", DATA, pcr_indexes=[0], expected={0: H0}, now=NOW)
    assert record.version == 1
    assert keeper.objects() == ["b"]
    assert keeper.stats()["evicted"] == 1


def test_held_object_cannot_be_evicted():
    keeper = sealed()
    assert keeper.hold("app-key") == 1
    with pytest.raises(tpm.SealError) as err:
        keeper.evict("app-key")
    assert err.value.code == "SEAL_IN_USE"
    assert keeper.release("app-key") == 0
    keeper.evict("app-key")
    assert keeper.objects() == []
    with pytest.raises(tpm.SealError) as err:
        keeper.evict("app-key")
    assert err.value.code == "SEAL_NOT_FOUND"
    with pytest.raises(tpm.SealError) as err:
        keeper.hold("app-key")
    assert err.value.code == "SEAL_NOT_FOUND"


def test_reseal_without_arguments_keeps_policy_and_payload():
    keeper = sealed(policy="boot-a")
    record = keeper.reseal("app-key", now=LATER)
    assert record.version == 2
    assert record.reseal_count == 1
    assert record.policy == "boot-a"
    assert record.pcr_indexes == (0, 7)
    assert record.sealed_at == LATER
    assert keeper.stats()["resealed"] == 1
    assert keeper.unseal("app-key", pcr_values={0: H0, 7: H7}, now=LATER) == DATA


def test_reseal_replacing_policy_keeps_history():
    keeper = sealed(policy="boot-a")
    record = keeper.reseal("app-key", policy="boot-b", now=LATER)
    assert record.policy == "boot-b"
    assert record.policy_history == ("boot-a", "boot-b")
    assert record.version == 2
    assert keeper.status("app-key")["policy"] == "boot-b"


def test_status_reports_object_metadata():
    keeper = sealed(policy="boot-a")
    status = keeper.status("app-key")
    assert status["pcr_indexes"] == (0, 7)
    assert status["version"] == 1
    assert status["policy"] == "boot-a"
    assert status["failure_count"] == 0
    assert status["locked"] is False
    assert status["locked_until"] is None
    assert status["held"] == 0
    with pytest.raises(tpm.SealError) as err:
        keeper.status("ghost")
    assert err.value.code == "SEAL_NOT_FOUND"


def test_snapshot_exposes_metadata_only():
    keeper = sealed()
    keeper.hold("app-key")
    snap = keeper.snapshot()
    blob = json.dumps(snap, ensure_ascii=False)
    assert DATA not in blob
    assert "data" not in snap["objects"][0]
    assert snap["stats"]["sealed"] == 1


def test_restored_store_keeps_lockout_state():
    keeper = sealed(max_failures=1)
    with pytest.raises(tpm.SealError) as err:
        keeper.unseal("app-key", pcr_values={0: H0, 7: H7B}, now=NOW)
    assert err.value.code == "SEAL_POLICY_FAILED"
    snap = keeper.snapshot()
    fresh = store()
    fresh.restore(snap)
    assert fresh.status("app-key")["locked"] is True
    with pytest.raises(tpm.SealError) as err:
        fresh.unseal("app-key", pcr_values={0: H0, 7: H7}, now=SOON)
    assert err.value.code == "SEAL_LOCKED"
    assert fresh.unseal("app-key", pcr_values={0: H0, 7: H7},
                        now=AFTER) == DATA


def test_invalid_snapshot_leaves_store_untouched():
    keeper = sealed()
    before = keeper.stats()
    with pytest.raises(tpm.SealError) as err:
        keeper.restore({"objects": 5})
    assert err.value.code == "SEAL_SNAPSHOT_INVALID"
    assert keeper.stats() == before
    assert keeper.objects() == ["app-key"]
    assert keeper.unseal("app-key", pcr_values={0: H0, 7: H7}, now=SOON) == DATA


def test_stats_accumulate_each_operation_family():
    keeper = store()
    keeper.seal("a", DATA, pcr_indexes=[0], expected={0: H0}, now=NOW)
    keeper.seal("b", DATA, pcr_indexes=[0], expected={0: H0}, now=NOW)
    with pytest.raises(tpm.SealError) as err:
        keeper.seal("a", DATA, pcr_indexes=[0], expected={0: H0}, now=NOW)
    assert err.value.code == "SEAL_DUPLICATE"
    assert keeper.unseal("a", pcr_values={0: H0}, now=NOW) == DATA
    with pytest.raises(tpm.SealError) as err:
        keeper.unseal("b", pcr_values={0: H7}, now=NOW)
    assert err.value.code == "SEAL_POLICY_FAILED"
    keeper.evict("b")
    assert keeper.stats() == {"sealed": 2, "duplicates": 1, "unsealed_ok": 1,
                              "unsealed_failed": 1, "resealed": 0, "evicted": 1,
                              "denied": 1, "locked_events": 0}
