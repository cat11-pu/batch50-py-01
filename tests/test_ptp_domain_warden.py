import copy

import ptp_domain_warden as pw

ID_A = "00:00:00:00:00:00:0a"
ID_B = "00:00:00:00:00:00:0b"
ID_C = "00:00:00:00:00:00:0c"


def announce(identity, **overrides):
    data = {
        "domain": 0,
        "clock_identity": identity,
        "priority1": 128,
        "clock_class": 6,
        "clock_accuracy": 0x22,
        "variance": 1000,
        "priority2": 128,
        "steps_removed": 1,
        "source_port": "1",
    }
    data.update(overrides)
    return data


def warden(**kwargs):
    params = dict(domain=0, announce_timeout=3.0, max_foreign=16)
    params.update(kwargs)
    return pw.PtpDomainWarden(**params)


def test_first_announce_elects_master():
    instance = warden()
    assert instance.on_announce(announce(ID_A), now=100.0) is True
    master = instance.elected()
    assert master.clock_identity == ID_A
    assert master.sequence == 1
    assert instance.state() == "master"
    assert instance.time_trusted(now=100.1) is True


def test_lower_priority1_wins():
    instance = warden()
    instance.on_announce(announce(ID_A, priority1=128), now=100.0)
    instance.on_announce(announce(ID_B, priority1=32), now=100.1)
    master = instance.elected()
    assert master.clock_identity == ID_B
    assert master.sequence == 2


def test_lower_clock_class_breaks_priority1_tie():
    instance = warden()
    instance.on_announce(announce(ID_A, clock_class=6), now=100.0)
    instance.on_announce(announce(ID_B, clock_class=2), now=100.1)
    assert instance.elected().clock_identity == ID_B


def test_lower_clock_accuracy_breaks_clock_class_tie():
    instance = warden()
    instance.on_announce(announce(ID_A, clock_accuracy=0x22), now=100.0)
    instance.on_announce(announce(ID_B, clock_accuracy=0x21), now=100.1)
    assert instance.elected().clock_identity == ID_B


def test_lower_variance_breaks_accuracy_tie():
    instance = warden()
    instance.on_announce(announce(ID_A, variance=1000), now=100.0)
    instance.on_announce(announce(ID_B, variance=500), now=100.1)
    assert instance.elected().clock_identity == ID_B


def test_lower_priority2_breaks_variance_tie():
    instance = warden()
    instance.on_announce(announce(ID_A, priority2=128), now=100.0)
    instance.on_announce(announce(ID_B, priority2=64), now=100.1)
    assert instance.elected().clock_identity == ID_B


def test_lower_clock_identity_breaks_full_tie():
    instance = warden()
    instance.on_announce(announce(ID_B), now=100.0)
    instance.on_announce(announce(ID_A), now=100.1)
    assert instance.elected().clock_identity == ID_A
    assert instance.elected().sequence == 2


def test_lower_steps_removed_breaks_identity_tie():
    instance = warden()
    instance.on_announce(announce(ID_A, steps_removed=2), now=100.0)
    instance.on_announce(announce(ID_B, steps_removed=1), now=100.1)
    assert instance.elected().clock_identity == ID_B


def test_duplicate_announce_does_not_change_election():
    instance = warden()
    instance.on_announce(announce(ID_A), now=100.0)
    assert instance.on_announce(announce(ID_A), now=100.1) is True
    master = instance.elected()
    assert master.sequence == 1
    assert instance.stats()["duplicates"] == 1


def test_worse_announce_is_stored_without_changing_master():
    instance = warden()
    instance.on_announce(announce(ID_A, priority1=10), now=100.0)
    assert instance.on_announce(announce(ID_B, priority1=20), now=100.1) is True
    assert instance.elected().clock_identity == ID_A
    assert len(instance.foreign_records()) == 2


def test_sync_is_only_accepted_from_current_master():
    instance = warden()
    instance.on_announce(announce(ID_A), now=100.0)
    good = {"domain": 0, "clock_identity": ID_A, "source_port": "1"}
    bad = {"domain": 0, "clock_identity": ID_B, "source_port": "1"}
    assert instance.on_sync(good, now=100.2) is True
    assert instance.on_sync(bad, now=100.3) is False
    assert instance.stats()["sync_rejected"] == 1


def test_tick_after_announce_timeout_degrades_to_listening():
    instance = warden(announce_timeout=3.0)
    instance.on_announce(announce(ID_A), now=100.0)
    events = instance.tick(104.0)
    assert "announce_timeout" in events
    assert instance.elected() is None
    assert instance.state() == "listening"
    assert instance.stats()["timeouts"] == 1


def test_tick_reelects_next_candidate_after_master_times_out():
    instance = warden(announce_timeout=3.0)
    instance.on_announce(announce(ID_A, priority1=10), now=100.0)
    instance.on_announce(announce(ID_B, priority1=20), now=102.0)
    assert instance.elected().clock_identity == ID_A
    events = instance.tick(104.0)
    master = instance.elected()
    assert master.clock_identity == ID_B
    assert master.sequence == 2
    assert "master_changed" in events


def test_snapshot_restore_does_not_restore_old_master():
    instance = warden()
    instance.on_announce(announce(ID_A), now=100.0)
    instance.on_sync(
        {"domain": 0, "clock_identity": ID_A, "source_port": "1"},
        now=100.5,
    )
    state = instance.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {
        "version", "domain", "candidates", "master", "sequence", "counters",
    }
    state["candidates"].clear()
    assert instance.elected() is not None

    clone = warden()
    clone.restore(pristine)
    assert clone.elected() is None
    assert clone.state() == "listening"
    assert clone.foreign_records() == ()
    clone.on_announce(announce(ID_B), now=200.0)
    assert clone.elected().sequence == 2


def test_foreign_table_capacity_evicts_worst_candidate():
    instance = warden(max_foreign=2)
    instance.on_announce(announce(ID_A, priority1=10), now=100.0)
    instance.on_announce(announce(ID_B, priority1=20), now=100.1)
    instance.on_announce(announce(ID_C, priority1=30), now=100.2)
    assert instance.elected().clock_identity == ID_A
    assert len(instance.foreign_records()) == 2
    assert instance.stats()["evicted"] == 1
