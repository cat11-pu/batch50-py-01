import copy
import threading
import time

import pytest

import saml_artifact_resolver as sr

NOW = "2026-11-26T09:00:00+00:00"
SOON = "2026-11-26T09:01:00+00:00"
EXPIRED_AT = "2026-11-26T09:02:00+00:00"
LATER = "2026-11-26T09:05:00+00:00"
DEADLINE = "2026-11-26T09:02:00+00:00"
SP = "https://sp.example/saml"
SP2 = "https://sp2.example/saml"


def resolver(**kwargs):
    return sr.SamlArtifactResolver(**kwargs)


def ready(**kwargs):
    b = resolver(**kwargs)
    b.register_sp(SP, tenant="t1", now=NOW)
    return b


def backend_for(ticket, *, subject=None, valid=True, attributes=None):
    def fetcher(artifact, entity_id):
        return sr.BackendAssertion(
            assertion=f"assertion-{artifact}",
            in_response_to=ticket.in_response_to,
            signature_valid=valid,
            subject=subject or ticket.subject,
            attributes={"role": "admin"} if attributes is None else attributes,
        )
    return fetcher


def test_register_sp_records_and_rejects_duplicates():
    b = resolver()
    sp = b.register_sp(SP, tenant="t1", now=NOW)
    assert sp.entity_id == SP
    assert sp.tenant == "t1"
    assert sp.registered_at == NOW
    assert b.sp_record(SP) == sp
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.register_sp(SP, tenant="t1", now=NOW)
    assert exc.value.code == "SAML_INVALID_REQUEST"
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.register_sp("  ", tenant="t1", now=NOW)
    assert exc.value.code == "SAML_INVALID_REQUEST"
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.sp_record(SP2)
    assert exc.value.code == "SAML_UNKNOWN_SP"


def test_issue_creates_pending_ticket():
    b = ready()
    ticket = b.issue(SP, subject="alice", attributes={"role": "admin"}, now=NOW)
    assert ticket.entity_id == SP
    assert ticket.tenant == "t1"
    assert ticket.idp_entity_id == "idp-1"
    assert ticket.subject == "alice"
    assert ticket.artifact.startswith("AA-")
    assert len(ticket.in_response_to) >= 8
    assert ticket.created_at == NOW
    assert ticket.expires_at == DEADLINE
    assert ticket.status == "pending"
    assert b.artifact_state(ticket.artifact) == "pending"
    assert b.stats()["issued"] == 1


def test_issue_rejects_unknown_sp_blank_subject_and_capacity():
    b = ready()
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.issue(SP2, subject="alice", now=NOW)
    assert exc.value.code == "SAML_UNKNOWN_SP"
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.issue(SP, subject="   ", now=NOW)
    assert exc.value.code == "SAML_INVALID_REQUEST"
    tight = ready(max_pending_per_tenant=1)
    tight.issue(SP, subject="alice", now=NOW)
    with pytest.raises(sr.SamlArtifactError) as exc:
        tight.issue(SP, subject="bob", now=NOW)
    assert exc.value.code == "SAML_CAPACITY_EXCEEDED"
    assert tight.stats()["issued"] == 1


def test_resolve_returns_assertion_once():
    b = ready()
    ticket = b.issue(SP, subject="alice", attributes={"role": "admin"}, now=NOW)
    b.set_backend(backend_for(ticket))
    assertion = b.resolve(ticket.artifact, SP, now=SOON)
    assert assertion.artifact == ticket.artifact
    assert assertion.entity_id == SP
    assert assertion.subject == "alice"
    assert assertion.in_response_to == ticket.in_response_to
    assert assertion.attributes == {"role": "admin"}
    assert assertion.resolved_at == SOON
    assert b.artifact_state(ticket.artifact) == "resolved"
    assert b.stats()["resolved"] == 1
    assert b.stats()["backend_calls"] == 1


def test_resolve_rejects_unknown_artifact_and_revoked_artifact():
    b = ready()
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.resolve("AA-missing", SP, now=SOON)
    assert exc.value.code == "SAML_UNKNOWN_ARTIFACT"
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.resolve("AA-missing", SP2, now=SOON)
    assert exc.value.code == "SAML_UNKNOWN_SP"

    doomed = b.issue(SP, subject="alice", now=NOW)
    survivor = b.issue(SP, subject="bob", now=NOW)
    assert b.revoke(doomed.artifact) is True
    assert b.revoke(doomed.artifact) is False
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.revoke("AA-missing")
    assert exc.value.code == "SAML_UNKNOWN_ARTIFACT"
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.resolve(doomed.artifact, SP, now=SOON)
    assert exc.value.code == "SAML_ARTIFACT_REVOKED"
    b.set_backend(backend_for(survivor))
    assert b.resolve(survivor.artifact, SP, now=SOON).subject == "bob"
    assert b.stats()["revoked"] == 1


def test_resolve_rejects_expired_artifact():
    short = ready(artifact_ttl=60)
    ticket = short.issue(SP, subject="alice", now=NOW)
    assert short.expire(now=NOW) == 0
    with pytest.raises(sr.SamlArtifactError) as exc:
        short.resolve(ticket.artifact, SP, now=LATER)
    assert exc.value.code == "SAML_ARTIFACT_EXPIRED"
    assert short.artifact_state(ticket.artifact) == "expired"
    assert short.stats()["expired"] == 1

    b = ready()
    other = b.issue(SP, subject="bob", now=NOW)
    assert b.expire(now=LATER) == 1
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.resolve(other.artifact, SP, now=LATER)
    assert exc.value.code == "SAML_ARTIFACT_EXPIRED"


def test_resolve_rejects_invalid_backend_signature():
    b = ready()
    ticket = b.issue(SP, subject="alice", now=NOW)
    b.set_backend(backend_for(ticket, valid=False))
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.resolve(ticket.artifact, SP, now=SOON)
    assert exc.value.code == "SAML_SIGNATURE_INVALID"
    assert b.artifact_state(ticket.artifact) == "rejected"
    assert b.stats()["rejected"] == 1
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.resolve(ticket.artifact, SP, now=SOON)
    assert exc.value.code == "SAML_ARTIFACT_REJECTED"


def test_backend_timeout_keeps_artifact_resolvable():
    b = ready()
    ticket = b.issue(SP, subject="alice", now=NOW)
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.resolve(ticket.artifact, SP, now=SOON)
    assert exc.value.code == "SAML_BACKEND_UNAVAILABLE"
    assert b.artifact_state(ticket.artifact) == "pending"

    def slow(artifact, entity_id):
        raise TimeoutError("artifact resolution backend timed out")

    b.set_backend(slow)
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.resolve(ticket.artifact, SP, now=SOON)
    assert exc.value.code == "SAML_BACKEND_TIMEOUT"
    assert b.artifact_state(ticket.artifact) == "pending"
    assert b.stats()["timeouts"] == 1
    assert b.stats()["resolved"] == 0

    b.set_backend(backend_for(ticket))
    assert b.resolve(ticket.artifact, SP, now=LATER).subject == "alice"
    assert b.stats()["resolved"] == 1


def test_resolve_second_time_reports_consumed():
    b = ready()
    ticket = b.issue(SP, subject="alice", now=NOW)
    b.set_backend(backend_for(ticket))
    b.resolve(ticket.artifact, SP, now=SOON)
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.resolve(ticket.artifact, SP, now=LATER)
    assert exc.value.code == "SAML_ARTIFACT_CONSUMED"
    assert b.stats()["resolved"] == 1
    assert b.stats()["backend_calls"] == 1


def test_concurrent_resolution_fetches_backend_once():
    b = ready()
    ticket = b.issue(SP, subject="alice", now=NOW)
    calls = []

    def fetcher(artifact, entity_id):
        calls.append(artifact)
        time.sleep(0.05)
        return sr.BackendAssertion(
            assertion="assertion-shared",
            in_response_to=ticket.in_response_to,
            signature_valid=True,
            subject="alice",
            attributes={"role": "admin"},
        )

    b.set_backend(fetcher)
    results = []
    failures = []
    barrier = threading.Barrier(6)

    def worker():
        try:
            barrier.wait(timeout=5)
            results.append(b.resolve(ticket.artifact, SP, now=SOON))
        except Exception as exc:  # noqa: BLE001 - reported through failures
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert failures == []
    assert len(results) == 6
    assert {row.assertion for row in results} == {"assertion-shared"}
    assert len(calls) == 1
    assert b.stats()["resolved"] == 1
    assert b.stats()["backend_calls"] == 1


def test_concurrent_resolution_shares_backend_timeout():
    b = ready()
    ticket = b.issue(SP, subject="alice", now=NOW)
    calls = []

    def fetcher(artifact, entity_id):
        calls.append(artifact)
        time.sleep(0.05)
        raise TimeoutError("artifact resolution backend timed out")

    b.set_backend(fetcher)
    failures = []
    barrier = threading.Barrier(4)

    def worker():
        try:
            barrier.wait(timeout=5)
            b.resolve(ticket.artifact, SP, now=SOON)
        except Exception as exc:  # noqa: BLE001 - reported through failures
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(failures) == 4
    assert {getattr(exc, "code", None) for exc in failures} == {"SAML_BACKEND_TIMEOUT"}
    assert len(calls) == 1
    assert b.artifact_state(ticket.artifact) == "pending"
    assert b.stats()["timeouts"] == 1


def test_pending_for_is_scoped_and_expire_frees_capacity():
    b = ready(max_pending_per_tenant=1)
    b.register_sp(SP2, tenant="t1", now=NOW)
    first = b.issue(SP, subject="alice", now=NOW)
    with pytest.raises(sr.SamlArtifactError) as exc:
        b.issue(SP, subject="bob", now=NOW)
    assert exc.value.code == "SAML_CAPACITY_EXCEEDED"
    assert b.pending_for(SP) == (first.artifact,)
    assert b.pending_for(SP2) == ()
    assert b.expire(now=LATER) == 1
    second = b.issue(SP, subject="bob", now=NOW)
    assert b.pending_for(SP) == (second.artifact,)

    multi = ready()
    left = multi.issue(SP, subject="alice", now=NOW)
    right = multi.issue(SP, subject="bob", now=NOW)
    assert multi.pending_for(SP) == tuple(sorted([left.artifact, right.artifact]))
    assert multi.pending_for(SP2) == ()


def test_snapshot_roundtrip_restores_artifacts():
    b = ready()
    pending = b.issue(SP, subject="alice", now=NOW)
    done = b.issue(SP, subject="bob", now=NOW)
    b.set_backend(backend_for(done))
    b.resolve(done.artifact, SP, now=SOON)
    state = b.snapshot()
    assert set(state) == {"version", "sps", "artifacts", "stats"}
    pristine = copy.deepcopy(state)
    state["artifacts"].clear()
    state["stats"]["issued"] = 99
    assert b.stats()["issued"] == 2
    assert b.artifact_state(pending.artifact) == "pending"

    clone = resolver()
    clone.restore(pristine)
    assert clone.stats()["issued"] == 2
    assert clone.stats()["resolved"] == 1
    assert clone.artifact_state(pending.artifact) == "pending"
    assert clone.artifact_state(done.artifact) == "resolved"
    assert clone.sp_record(SP).tenant == "t1"
    clone.set_backend(backend_for(pending))
    assert clone.resolve(pending.artifact, SP, now=SOON).subject == "alice"


def test_restore_rejects_malformed_snapshot():
    b = ready()
    ticket = b.issue(SP, subject="alice", now=NOW)
    bad_snapshots = [
        None,
        {},
        {"version": 2, "sps": [], "artifacts": [], "stats": {}},
        {"version": 1, "sps": {}, "artifacts": [], "stats": {}},
        {"version": 1, "sps": [], "artifacts": "no", "stats": {}},
        {"version": 1, "sps": [], "artifacts": [], "stats": []},
    ]
    for snapshot in bad_snapshots:
        with pytest.raises(sr.SamlArtifactError) as exc:
            b.restore(snapshot)
        assert exc.value.code == "SAML_SNAPSHOT_INVALID"
    assert b.artifact_state(ticket.artifact) == "pending"
    assert b.stats()["issued"] == 1


def test_stats_count_each_backend_outcome():
    b = ready()
    resolved = b.issue(SP, subject="alice", now=NOW)
    rejected = b.issue(SP, subject="bob", now=NOW)
    revoked = b.issue(SP, subject="carol", now=NOW)
    b.set_backend(backend_for(resolved))
    b.resolve(resolved.artifact, SP, now=SOON)
    b.set_backend(backend_for(rejected, valid=False))
    with pytest.raises(sr.SamlArtifactError):
        b.resolve(rejected.artifact, SP, now=SOON)
    b.revoke(revoked.artifact)
    assert b.stats()["issued"] == 3
    assert b.stats()["resolved"] == 1
    assert b.stats()["rejected"] == 1
    assert b.stats()["revoked"] == 1
    assert b.stats()["expired"] == 0
    assert b.stats()["timeouts"] == 0
    assert b.stats()["backend_calls"] == 2
