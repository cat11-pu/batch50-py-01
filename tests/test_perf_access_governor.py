import json

import pytest

import perf_access_governor as perf

NOW = "2026-11-26T09:00:00+00:00"
SOON = "2026-11-26T09:00:30+00:00"
AFTER = "2026-11-26T09:01:01+00:00"


def gov(**kwargs):
    return perf.PerfAccessGovernor(**kwargs)


def test_request_records_granted_metadata():
    keeper = gov()
    record = keeper.request(requester="agent-a", event_type="cycles", cgroup="web",
                            target_pid=4242, now=NOW)
    assert record.request_id == "req-1"
    assert record.requester == "agent-a"
    assert record.event_type == "cycles"
    assert record.cgroup == "web"
    assert record.target_pid == 4242
    assert record.target_cpu is None
    assert record.level == 2
    assert record.kernel is False
    assert record.privileged is False
    assert record.created_at == NOW
    assert keeper.stats()["granted"] == 1


def test_request_argument_validation():
    keeper = gov()
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.request(requester="", event_type="cycles", cgroup="web",
                       target_pid=1, now=NOW)
    assert err.value.code == "PERF_BAD_REQUEST"
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.request(requester="a", event_type="", cgroup="web",
                       target_pid=1, now=NOW)
    assert err.value.code == "PERF_BAD_REQUEST"
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.request(requester="a", event_type="cycles", cgroup="web",
                       target_pid=1, target_cpu=0, now=NOW)
    assert err.value.code == "PERF_BAD_TARGET"
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.request(requester="a", event_type="cycles", cgroup="web", now=NOW)
    assert err.value.code == "PERF_BAD_TARGET"
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.request(requester="a", event_type="cycles", cgroup="web",
                       target_pid=0, now=NOW)
    assert err.value.code == "PERF_BAD_TARGET"
    assert keeper.stats()["denied"] == 5


def test_paranoid_tier_blocks_kernel_sampling_and_everything():
    two = gov(paranoid=2)
    with pytest.raises(perf.PerfAccessError) as err:
        two.request(requester="a", event_type="cycles", cgroup="web",
                    target_pid=1, kernel=True, now=NOW)
    assert err.value.code == "PERF_PARANOID_DENIED"
    assert two.stats()["denied"] == 1
    four = gov(paranoid=4)
    with pytest.raises(perf.PerfAccessError) as err:
        four.request(requester="a", event_type="cycles", cgroup="web",
                     target_pid=1, now=NOW)
    assert err.value.code == "PERF_PARANOID_DENIED"
    assert four.stats()["granted"] == 0


def test_blacklist_beats_whitelist_and_privilege():
    keeper = gov(paranoid=0)
    assert keeper.add_blacklist("kmem") == 1
    assert keeper.add_whitelist("kmem") == 1
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.request(requester="a", event_type="kmem", cgroup="web",
                       target_pid=1, kernel=True, privileged=True, now=NOW)
    assert err.value.code == "PERF_BLACKLISTED"
    assert keeper.stats()["blacklisted"] == 1
    assert keeper.stats()["granted"] == 0


def test_whitelist_allows_cpu_wide_event_at_high_paranoid():
    keeper = gov(paranoid=3)
    assert keeper.add_whitelist("cycles") == 1
    record = keeper.request(requester="a", event_type="cycles", cgroup="web",
                            target_cpu=0, now=NOW)
    assert record.target_cpu == 0
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.request(requester="a", event_type="cpu-clock", cgroup="web",
                       target_cpu=0, now=NOW)
    assert err.value.code == "PERF_PARANOID_DENIED"


def test_per_cgroup_quota_blocks_and_close_frees_a_slot():
    keeper = gov(max_events_per_cgroup=2)
    first = keeper.request(requester="a", event_type="cycles", cgroup="web",
                           target_pid=1, now=NOW)
    keeper.request(requester="a", event_type="cycles", cgroup="web",
                   target_pid=2, now=NOW)
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.request(requester="a", event_type="cycles", cgroup="web",
                       target_pid=3, now=NOW)
    assert err.value.code == "PERF_QUOTA_EXCEEDED"
    keeper.request(requester="a", event_type="cycles", cgroup="api",
                   target_pid=4, now=NOW)
    fd = keeper.open(first.request_id, now=NOW)
    assert keeper.close(fd, now=NOW)["closed"] is True
    keeper.request(requester="a", event_type="cycles", cgroup="web",
                   target_pid=5, now=NOW)
    assert keeper.stats()["quota_denied"] == 1


def test_privilege_pool_is_bounded():
    keeper = gov(privilege_pool=2)
    keeper.request(requester="a", event_type="cycles", cgroup="web",
                   target_pid=1, privileged=True, now=NOW)
    keeper.request(requester="a", event_type="cycles", cgroup="web",
                   target_pid=2, privileged=True, now=NOW)
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.request(requester="a", event_type="cycles", cgroup="web",
                       target_pid=3, privileged=True, now=NOW)
    assert err.value.code == "PERF_PRIVILEGE_EXHAUSTED"
    assert keeper.stats()["privilege_denied"] == 1


def test_shared_target_reuses_fd_and_counts_references():
    keeper = gov()
    first = keeper.request(requester="a", event_type="cycles", cgroup="web",
                           target_pid=7, now=NOW)
    second = keeper.request(requester="b", event_type="instructions",
                            cgroup="web", target_pid=7, now=NOW)
    fd_first = keeper.open(first.request_id, now=NOW)
    fd_second = keeper.open(second.request_id, now=NOW)
    assert fd_first == fd_second == 3
    active = keeper.active()
    assert len(active) == 1
    assert active[0]["fd"] == 3
    assert active[0]["refcount"] == 2
    first_close = keeper.close(fd_first, now=NOW)
    assert first_close["closed"] is False
    assert first_close["refcount"] == 1
    assert keeper.close(fd_first, now=NOW)["closed"] is True


def test_open_and_close_reject_bad_handles():
    keeper = gov()
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.open("req-99", now=NOW)
    assert err.value.code == "PERF_NOT_FOUND"
    record = keeper.request(requester="a", event_type="cycles", cgroup="web",
                            target_pid=1, now=NOW)
    fd = keeper.open(record.request_id, now=NOW)
    keeper.close(fd, now=NOW)
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.open(record.request_id, now=NOW)
    assert err.value.code == "PERF_REQUEST_CLOSED"
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.close(99, now=NOW)
    assert err.value.code == "PERF_BAD_FD"


def test_revoke_closes_matching_collections_immediately():
    keeper = gov()
    first = keeper.request(requester="agent-a", event_type="cycles",
                           cgroup="web", target_pid=1, now=NOW)
    second = keeper.request(requester="agent-a", event_type="cycles",
                            cgroup="web", target_pid=2, now=NOW)
    third = keeper.request(requester="agent-b", event_type="cycles",
                           cgroup="api", target_pid=3, now=NOW)
    fd_first = keeper.open(first.request_id, now=NOW)
    fd_second = keeper.open(second.request_id, now=NOW)
    fd_third = keeper.open(third.request_id, now=NOW)
    assert len({fd_first, fd_second, fd_third}) == 3
    assert keeper.revoke(requester="agent-a", now=NOW) == 2
    for fd in (fd_first, fd_second):
        with pytest.raises(perf.PerfAccessError) as err:
            keeper.close(fd, now=NOW)
        assert err.value.code == "PERF_BAD_FD"
    assert keeper.close(fd_third, now=NOW)["closed"] is True
    assert keeper.stats()["revoked"] == 2


def test_privilege_expiry_is_reported_and_frees_the_pool():
    keeper = gov(privilege_pool=1, privilege_ttl=60)
    record = keeper.request(requester="a", event_type="cycles", cgroup="web",
                            target_pid=1, kernel=True, privileged=True, now=NOW)
    assert record.expires_at == "2026-11-26T09:01:00+00:00"
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.request(requester="a", event_type="cycles", cgroup="web",
                       target_pid=2, privileged=True, now=SOON)
    assert err.value.code == "PERF_PRIVILEGE_EXHAUSTED"
    out = keeper.review(now=AFTER)
    assert out["privilege_expired"] == 1
    keeper.request(requester="a", event_type="cycles", cgroup="web",
                   target_pid=2, privileged=True, now=AFTER)
    assert keeper.stats()["granted"] == 2


def test_audit_records_metadata_without_kernel_addresses():
    keeper = gov()
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.request(requester="agent-a", event_type="cycles", cgroup="web",
                       target_pid=1, kernel=True, now=NOW)
    assert err.value.code == "PERF_PARANOID_DENIED"
    entries = keeper.audit(now=NOW)
    assert [item["action"] for item in entries] == ["denied"]
    assert entries[0]["requester"] == "agent-a"
    assert entries[0]["event_type"] == "cycles"
    blob = json.dumps(entries, ensure_ascii=False)
    assert "0x" not in blob
    assert "addr" not in blob


def test_paranoid_can_be_raised_but_not_out_of_range():
    keeper = gov()
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.set_paranoid(5)
    assert err.value.code == "PERF_BAD_PARANOID"
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.set_paranoid(-1)
    assert err.value.code == "PERF_BAD_PARANOID"
    keeper.set_paranoid(3)
    assert keeper.status()["paranoid"] == 3
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.request(requester="a", event_type="cpu-clock", cgroup="web",
                       target_cpu=0, now=NOW)
    assert err.value.code == "PERF_PARANOID_DENIED"


def test_snapshot_restores_active_collections():
    keeper = gov()
    record = keeper.request(requester="a", event_type="cycles", cgroup="web",
                            target_pid=7, now=NOW)
    fd = keeper.open(record.request_id, now=NOW)
    snap = keeper.snapshot()
    keeper.close(fd, now=NOW)
    fresh = gov()
    fresh.restore(snap)
    active = fresh.active()
    assert len(active) == 1
    assert active[0]["fd"] == fd
    assert active[0]["refcount"] == 1
    assert fresh.status()["paranoid"] == 2
    assert fresh.close(fd, now=AFTER)["closed"] is True
    assert fresh.stats()["granted"] == 1


def test_invalid_snapshot_keeps_the_active_set():
    keeper = gov()
    record = keeper.request(requester="a", event_type="cycles", cgroup="web",
                            target_pid=7, now=NOW)
    fd = keeper.open(record.request_id, now=NOW)
    before = keeper.stats()
    with pytest.raises(perf.PerfAccessError) as err:
        keeper.restore({"collections": "not-a-list"})
    assert err.value.code == "PERF_SNAPSHOT_INVALID"
    assert keeper.stats() == before
    assert keeper.active()[0]["fd"] == fd
    assert keeper.close(fd, now=NOW)["closed"] is True
    stats = keeper.stats()
    assert stats["granted"] == 1
    assert stats["opened"] == 1
    assert stats["closed"] == 1
    assert stats["denied"] == 0
