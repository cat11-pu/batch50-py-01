import pytest

import memfd_exec_guard as mg

T0 = "2026-11-26T10:00:00+00:00"
T1 = "2026-11-26T10:02:00+00:00"
T2 = "2026-11-26T10:05:00+00:00"

FULL = frozenset({mg.SEAL_SEAL, mg.SEAL_SHRINK, mg.SEAL_GROW, mg.SEAL_WRITE})


def guard(**kwargs):
    return mg.MemfdExecGuard(**kwargs)


def created(g, *, pid=4100, fd=7, inode=9001, name="payload",
            seals=None, now=T0):
    if seals is None:
        seals = FULL
    return g.on_memfd_create(pid=pid, fd=fd, inode=inode, name=name,
                             seals=seals, now=now)


def test_memfd_create_records_normalized_seal_set():
    g = guard()
    rec = created(g, seals=[mg.SEAL_SEAL, mg.SEAL_WRITE, mg.SEAL_SHRINK, mg.SEAL_GROW])
    assert isinstance(rec, mg.MemfdRecord)
    assert (rec.inode, rec.name, rec.pid, rec.fd) == (9001, "payload", 4100, 7)
    assert rec.seals == FULL
    assert rec.state == "tracked"
    assert rec.updated_at == T0
    assert g.seals_for(9001) == FULL
    assert [row.inode for row in g.records()] == [9001]
    assert g.stats()["tracked"] == 1


def test_create_rejects_unknown_seal_names():
    g = guard()
    with pytest.raises(mg.MemfdError) as exc:
        created(g, seals={"F_SEAL_SEAL", "F_SEAL_NOPE"})
    assert exc.value.code == "MEMFD_BAD_SEAL"
    assert g.records() == []
    assert g.stats()["tracked"] == 0


def test_exec_without_seal_seal_is_denied():
    g = guard()
    created(g, seals=[mg.SEAL_SHRINK, mg.SEAL_GROW, mg.SEAL_WRITE])
    out = g.on_exec(pid=4100, path="memfd:payload", now=T1)
    assert (out.decision, out.code) == ("deny", "MEMFD_UNSEALED")
    assert (out.inode, out.source, out.pid) == (9001, "memfd", 4100)
    assert out.path == "memfd:payload"


def test_exec_with_write_mapping_is_denied():
    g = guard()
    created(g, inode=9001, name="writable", seals=[mg.SEAL_SEAL, mg.SEAL_SHRINK, mg.SEAL_GROW])
    out = g.on_exec(pid=4100, path="memfd:writable", now=T1)
    assert (out.decision, out.code, out.inode) == ("deny", "MEMFD_WRITABLE", 9001)

    created(g, pid=4200, fd=3, inode=9002, name="future-write",
            seals=[mg.SEAL_SEAL, mg.SEAL_SHRINK, mg.SEAL_GROW, mg.SEAL_FUTURE_WRITE])
    sealed_by_future_write = g.on_exec(pid=4200, path="memfd:future-write", now=T1)
    assert sealed_by_future_write.code == "MEMFD_NOT_ALLOWED"


def test_sealed_memfd_still_requires_allowance():
    g = guard()
    created(g)
    out = g.on_exec(pid=4100, path="memfd:payload", now=T1)
    assert (out.decision, out.code) == ("deny", "MEMFD_NOT_ALLOWED")
    assert g.stats()["denied"] == 1


def test_allow_then_exec_is_permitted():
    g = guard()
    created(g)
    granted = g.allow(9001, now=T0)
    assert granted.state == "allowed"
    out = g.on_exec(pid=4100, path="memfd:payload", now=T1)
    assert (out.decision, out.code, out.inode) == ("allow", "MEMFD_ALLOWED", 9001)
    assert g.stats()["allowed"] == 1


def test_allow_rejects_unknown_inode():
    g = guard()
    with pytest.raises(mg.MemfdError) as exc:
        g.allow(123456, now=T0)
    assert exc.value.code == "MEMFD_UNKNOWN"
    assert g.stats()["allowed"] == 0


def test_allow_rejects_unsealed_inode():
    g = guard()
    created(g, seals=[mg.SEAL_SHRINK, mg.SEAL_GROW, mg.SEAL_WRITE])
    with pytest.raises(mg.MemfdError) as exc:
        g.allow(9001, now=T0)
    assert exc.value.code == "MEMFD_UNSEALED"
    assert g.records()[0].state == "tracked"
    assert g.on_exec(pid=4100, path="memfd:payload", now=T1).code == "MEMFD_UNSEALED"


def test_quarantine_blocks_exec_and_further_allow():
    g = guard()
    created(g)
    parked = g.quarantine(9001, reason="内存挖矿", now=T0)
    assert (parked.state, parked.inode) == ("quarantined", 9001)
    out = g.on_exec(pid=4100, path="memfd:payload", now=T1)
    assert (out.decision, out.code) == ("deny", "MEMFD_QUARANTINED")
    with pytest.raises(mg.MemfdError) as exc:
        g.allow(9001, now=T1)
    assert exc.value.code == "MEMFD_QUARANTINED"
    assert g.stats()["quarantined"] == 1


def test_latest_seal_state_wins_for_same_inode():
    g = guard()
    created(g)
    created(g, now=T1, seals=[mg.SEAL_SHRINK, mg.SEAL_GROW, mg.SEAL_WRITE])
    assert g.seals_for(9001) == frozenset({mg.SEAL_SHRINK, mg.SEAL_GROW, mg.SEAL_WRITE})
    assert len(g.records()) == 1
    out = g.on_exec(pid=4100, path="memfd:payload", now=T1)
    assert (out.decision, out.code) == ("deny", "MEMFD_UNSEALED")


def test_regular_file_exec_is_permitted_and_not_tracked():
    g = guard()
    out = g.on_exec(pid=4100, path="/usr/bin/bash", now=T0)
    assert (out.decision, out.code, out.inode, out.source) == ("allow", "EXEC_FILE", None, "file")
    assert g.records() == []
    assert g.report() == []
    assert g.stats()["allowed"] == 1


def test_repeated_identical_denials_are_deduplicated_in_report():
    g = guard()
    created(g, seals=[mg.SEAL_SHRINK, mg.SEAL_WRITE])
    first = g.on_exec(pid=4100, path="memfd:payload", now=T0)
    second = g.on_exec(pid=4100, path="memfd:payload", now=T1)
    assert first.code == second.code == "MEMFD_UNSEALED"
    events = g.report()
    assert len(events) == 1
    event = events[0]
    assert (event["kind"], event["code"]) == ("exec_denied", "MEMFD_UNSEALED")
    assert (event["inode"], event["pid"], event["path"]) == (9001, 4100, "memfd:payload")
    assert event["count"] == 2
    assert (event["first_at"], event["last_at"]) == (T0, T1)
    assert g.stats()["denied"] == 2
    assert g.stats()["events"] == 1


def test_quarantine_is_inherited_by_child_process():
    g = guard()
    created(g, pid=500, fd=4, inode=9002, name="tool")
    g.allow(9002, now=T0)
    assert g.on_exec(pid=500, path="memfd:tool", now=T0).code == "MEMFD_ALLOWED"
    g.quarantine_process(500, reason="横向移动", now=T1)
    g.on_clone(parent_pid=500, child_pid=901)
    child = g.on_exec(pid=901, path="memfd:tool", now=T1)
    assert (child.decision, child.code) == ("deny", "MEMFD_INHERITED_BLOCK")
    parent = g.on_exec(pid=500, path="memfd:tool", now=T1)
    assert (parent.decision, parent.code) == ("deny", "MEMFD_PROC_QUARANTINED")


def test_snapshot_restore_roundtrip_preserves_allowance_and_events():
    g = guard()
    created(g, pid=4100, fd=7, inode=9001, name="payload")
    g.allow(9001, now=T0)
    created(g, pid=4300, fd=5, inode=9003, name="dropper",
            seals=[mg.SEAL_SHRINK, mg.SEAL_WRITE])
    g.on_exec(pid=4300, path="memfd:dropper", now=T0)
    g.on_exec(pid=4300, path="memfd:dropper", now=T1)
    g.quarantine_process(4300, reason="投递器", now=T1)
    g.on_clone(parent_pid=4300, child_pid=4301)

    state = g.snapshot()
    clone = guard()
    clone.restore(state)

    assert clone.seals_for(9001) == FULL
    events = clone.report()
    assert len(events) == 1
    assert events[0]["count"] == 2
    assert clone.stats() == g.stats()
    assert clone.on_exec(pid=4100, path="memfd:payload", now=T2).code == "MEMFD_ALLOWED"
    assert clone.on_exec(pid=4301, path="memfd:payload", now=T2).code == "MEMFD_INHERITED_BLOCK"

    state["allowed"] = {}
    state["memfds"] = {}
    assert g.seals_for(9001) == FULL


def test_restore_rejects_malformed_snapshot():
    g = guard()
    created(g)
    g.allow(9001, now=T0)
    good = g.snapshot()
    broken = [None, {}, {"version": 7, "memfds": {}, "allowed": {}, "quarantined_inodes": {},
                         "quarantined_pids": {}, "children": {}, "events": [],
                         "counters": {}, "stats": {}}]
    partial = dict(good)
    partial.pop("events")
    broken.append(partial)
    wrong_type = dict(good)
    wrong_type["allowed"] = ["9001"]
    broken.append(wrong_type)
    for bad in broken:
        with pytest.raises(mg.MemfdError) as exc:
            g.restore(bad)
        assert exc.value.code == "MEMFD_SNAPSHOT_INVALID"
    assert g.on_exec(pid=4100, path="memfd:payload", now=T2).code == "MEMFD_ALLOWED"
    assert g.records()[0].state == "allowed"
