import copy
import threading

import pytest

import ssh_host_ca_guard as hg

NOW = "2026-11-26T09:00:00+00:00"
LATER = "2026-11-26T09:30:00+00:00"
CA_FROM = "2026-01-01T00:00:00+00:00"
CA_TO = "2027-01-01T00:00:00+00:00"
CERT_TO = "2026-12-31T00:00:00+00:00"
EXPIRED_TO = "2026-11-26T08:00:00+00:00"
KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHostCaKey"


def cert(serial="s-001", principals=("web.example.com",), ca_name="ca-a",
         valid_to=CERT_TO):
    return hg.HostCertificate(ca_name=ca_name, serial=serial,
                              principals=tuple(principals),
                              valid_from=CA_FROM, valid_to=valid_to)


def guard(**kwargs):
    return hg.SshHostCaGuard(**kwargs)


def trusted_guard(**kwargs):
    item = guard(**kwargs)
    item.trust_ca("ca-a", KEY, CA_FROM, CA_TO, now=NOW)
    return item


def test_trust_ca_records_anchor_and_rejects_duplicates():
    item = guard()
    record = item.trust_ca("ca-a", KEY, CA_FROM, CA_TO, now=NOW)
    assert record.name == "ca-a"
    assert record.public_key == KEY
    assert record.valid_from == CA_FROM
    assert record.valid_to == CA_TO
    assert record.retired_at is None
    assert item.status()["cas"] == 1
    assert item.stats()["trusted_cas"] == 1
    with pytest.raises(hg.HostTrustError) as exc:
        item.trust_ca("ca-a", KEY, CA_FROM, CA_TO, now=NOW)
    assert exc.value.code == "HOST_CA_CONFLICT"


def test_trust_ca_rejects_invalid_windows_and_blank_keys():
    item = guard()
    cases = [
        ("ca-b", KEY, CA_TO, CA_FROM),
        ("", KEY, CA_FROM, CA_TO),
        ("ca-b", "", CA_FROM, CA_TO),
    ]
    for name, key, valid_from, valid_to in cases:
        with pytest.raises(hg.HostTrustError) as exc:
            item.trust_ca(name, key, valid_from, valid_to, now=NOW)
        assert exc.value.code == "HOST_INVALID_REQUEST"
    assert item.status()["cas"] == 0


def test_verify_host_accepts_ca_signed_certificate():
    item = trusted_guard()
    verdict = item.verify_host("web.example.com", 22, cert(), now=NOW)
    assert verdict.accepted is True
    assert verdict.reason == "ok"
    assert verdict.ca_name == "ca-a"
    assert verdict.serial == "s-001"
    assert (verdict.host, verdict.port) == ("web.example.com", 22)
    assert item.stats()["verified"] == 1


def test_verify_host_rejects_expired_certificate():
    item = trusted_guard()
    verdict = item.verify_host("web.example.com", 22, cert(valid_to=EXPIRED_TO), now=NOW)
    assert verdict.accepted is False
    assert verdict.reason == "certificate_expired"
    assert item.stats()["rejected_expired"] == 1


def test_verify_host_rejects_unknown_ca():
    item = trusted_guard()
    verdict = item.verify_host("web.example.com", 22, cert(ca_name="ca-z"), now=NOW)
    assert verdict.accepted is False
    assert verdict.reason == "unknown_ca"
    assert item.stats()["rejected_unknown_ca"] == 1


def test_verify_host_rejects_principal_mismatch():
    item = trusted_guard()
    verdict = item.verify_host("web.example.com", 22, cert(principals=("db.example.com",)), now=NOW)
    assert verdict.accepted is False
    assert verdict.reason == "principal_mismatch"
    assert item.stats()["rejected_principal"] == 1


def test_verify_host_matches_port_scoped_principal_exactly():
    item = trusted_guard()
    wrong_port = item.verify_host("db.example.com", 22, cert(principals=("db.example.com:2222",)), now=NOW)
    assert wrong_port.accepted is False
    assert wrong_port.reason == "principal_mismatch"
    right_port = item.verify_host("db.example.com", 2222, cert(principals=("db.example.com:2222",)), now=NOW)
    assert right_port.accepted is True
    assert right_port.reason == "ok"


def test_revoke_blocks_certificate_and_invalidates_cache():
    item = trusted_guard()
    assert item.verify_host("web.example.com", 22, cert(), now=NOW).accepted is True
    assert item.revoke("s-001", "ca-a", 2, now=LATER) == 2
    assert item.revocation_version() == 2
    verdict = item.verify_host("web.example.com", 22, cert(serial="s-001"), now=LATER)
    assert verdict.accepted is False
    assert verdict.reason == "revoked"
    assert item.stats()["revoked"] == 1


def test_revocation_version_must_stay_monotonic():
    item = trusted_guard()
    assert item.revoke("s-001", "ca-a", 2, now=NOW) == 2
    assert item.revoke("s-002", "ca-a", 3, now=NOW) == 3
    with pytest.raises(hg.HostTrustError) as exc:
        item.revoke("s-003", "ca-a", 2, now=NOW)
    assert exc.value.code == "HOST_REVOCATION_STALE"
    assert item.revocation_version() == 3
    assert item.status()["revocations"] == 2
    assert item.stats()["stale_revocations"] == 1


def test_migrate_known_hosts_dedupes_and_keeps_fingerprints():
    item = trusted_guard()
    batch = [
        ("web.example.com", 22, "SHA256:abc", "ssh-ed25519"),
        ("web.example.com", 22, "SHA256:abc", "ssh-ed25519"),
        ("db.example.com", 22, "SHA256:def", "ssh-rsa"),
    ]
    migrated = item.migrate_known_hosts(batch, now=NOW)
    assert [(entry.host, entry.port) for entry in migrated] == [
        ("db.example.com", 22),
        ("web.example.com", 22),
    ]
    assert all(entry.migrated_at == NOW for entry in migrated)
    assert item.status()["known_hosts"] == 2
    assert item.stats()["migrated"] == 2
    assert item.stats()["migration_skipped"] == 1

    again = item.migrate_known_hosts(batch, now=LATER)
    assert len(again) == 2
    assert item.status()["known_hosts"] == 2
    assert item.stats()["migration_skipped"] == 4

    with pytest.raises(hg.HostTrustError) as exc:
        item.migrate_known_hosts([("web.example.com", 22, "SHA256:zzz", "ssh-ed25519")], now=LATER)
    assert exc.value.code == "HOST_MIGRATION_CONFLICT"
    entries = item.known_hosts_entries()
    assert entries[1].host == "web.example.com"
    assert entries[1].fingerprint == "SHA256:abc"


def test_migrate_known_hosts_is_atomic_under_capacity():
    item = trusted_guard(max_migration_entries=2)
    batch = [
        ("a.example.com", 22, "SHA256:1", "ssh-ed25519"),
        ("b.example.com", 22, "SHA256:2", "ssh-ed25519"),
        ("c.example.com", 22, "SHA256:3", "ssh-ed25519"),
    ]
    with pytest.raises(hg.HostTrustError) as exc:
        item.migrate_known_hosts(batch, now=NOW)
    assert exc.value.code == "HOST_CAPACITY_EXCEEDED"
    assert item.status()["known_hosts"] == 0
    assert item.known_hosts_entries() == ()
    assert item.stats()["migrated"] == 0


def test_untrust_ca_invalidates_verification():
    item = trusted_guard()
    assert item.verify_host("web.example.com", 22, cert(), now=NOW).accepted is True
    assert item.untrust_ca("ca-a", now=LATER) is True
    assert item.untrust_ca("ca-a", now=LATER) is False
    verdict = item.verify_host("web.example.com", 22, cert(serial="s-002"), now=LATER)
    assert verdict.accepted is False
    assert verdict.reason == "unknown_ca"
    assert item.stats()["untrusted_cas"] == 1


def test_concurrent_verification_is_consistent():
    item = trusted_guard()
    verdicts = []
    errors = []
    barrier = threading.Barrier(8)

    def worker():
        try:
            barrier.wait(timeout=5)
            verdicts.append(item.verify_host("web.example.com", 22, cert(), now=NOW).accepted)
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert len(verdicts) == 8
    assert all(verdicts)
    assert item.status()["cas"] == 1


def test_snapshot_roundtrip_keeps_anchors_and_revocations():
    item = trusted_guard()
    item.revoke("s-001", "ca-a", 2, now=NOW)
    item.migrate_known_hosts([("web.example.com", 22, "SHA256:abc", "ssh-ed25519")], now=NOW)
    state = item.snapshot()
    assert set(state) == {"version", "anchors", "revocations", "known_hosts",
                          "cache", "counters", "stats"}
    pristine = copy.deepcopy(state)
    state["anchors"].clear()
    state["stats"]["revoked"] = 99
    assert item.status()["cas"] == 1
    assert item.stats()["revoked"] == 1

    clone = guard()
    clone.restore(pristine)
    assert clone.revocation_version() == 2
    assert clone.status()["known_hosts"] == 1
    verdict = clone.verify_host("web.example.com", 22, cert(serial="s-001"), now=NOW)
    assert verdict.accepted is False
    assert verdict.reason == "revoked"


def test_restore_rejects_malformed_state_without_touching_live_state():
    item = trusted_guard()
    bad_states = [
        None,
        {},
        {"version": 4, "anchors": {}, "revocations": {}, "known_hosts": {},
         "cache": {}, "counters": {}, "stats": {}},
        {"version": 1, "anchors": [], "revocations": {}, "known_hosts": {},
         "cache": {}, "counters": {}, "stats": {}},
        {"version": 1, "anchors": {}, "revocations": [], "known_hosts": {},
         "cache": {}, "counters": {}, "stats": {}},
        {"version": 1, "anchors": {}, "revocations": {}, "known_hosts": [],
         "cache": {}, "counters": {}, "stats": {}},
        {"version": 1, "anchors": {}, "revocations": {}, "known_hosts": {},
         "cache": {}, "counters": {}, "stats": {"trusted_cas": 1}},
    ]
    for bad in bad_states:
        with pytest.raises(hg.HostTrustError) as exc:
            item.restore(bad)
        assert exc.value.code == "HOST_SNAPSHOT_INVALID"
    assert item.status()["cas"] == 1
    assert item.verify_host("web.example.com", 22, cert(), now=NOW).accepted is True
