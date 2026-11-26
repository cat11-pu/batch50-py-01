import threading

import pytest

import zone_transfer_governor as zg

ZONE = "example.net."
DIGEST = "5f" * 32
RECORDS = (
    "example.net. 300 IN SOA ns1.example.net. hostmaster.example.net. 6 3600 600 86400 300",
    "example.net. 300 IN A 10.0.0.1",
    "www.example.net. 300 IN A 10.0.0.2",
)
NOW = 5000
LATER = 5100


def gov(**kwargs):
    return zg.ZoneTransferGovernor(**kwargs)


def ready(**kwargs):
    g = gov(**kwargs)
    g.register_key(ZONE, "tsig-a")
    g.register_key(ZONE, "tsig-b")
    g.load_zone(ZONE, serial=6, digest=DIGEST, records=RECORDS,
                history=(4, 5, 6), now=NOW)
    g.authorize(ZONE, secondary="sec-a", source="10.0.0.5", key_name="tsig-a", now=NOW)
    g.authorize(ZONE, secondary="sec-b", source="10.0.0.6", key_name="tsig-a", now=NOW)
    return g


def begin(g, secondary="sec-a", **kwargs):
    kwargs.setdefault("source", "10.0.0.5" if secondary == "sec-a" else "10.0.0.6")
    kwargs.setdefault("key_name", "tsig-a")
    kwargs.setdefault("now", NOW)
    return g.begin_transfer(ZONE, secondary=secondary, **kwargs)


def test_load_zone_exposes_serial_digest_and_records():
    g = gov()
    state = g.load_zone(ZONE, serial=6, digest=DIGEST, records=RECORDS,
                        history=(4, 5, 6), now=NOW)
    assert state.zone == ZONE
    assert state.serial == 6
    assert state.digest == DIGEST
    assert state.records == RECORDS
    assert state.history == (4, 5, 6)
    assert state.loaded_at == NOW
    status = g.zone_status(ZONE)
    assert status["serial"] == 6
    assert status["records"] == len(RECORDS)
    assert status["watermarks"] == ()
    assert status["active"] == ()
    assert g.stats()["zones_loaded"] == 1
    for bad in (dict(serial=-1), dict(serial=2 ** 32), dict(records=())):
        kwargs = dict(serial=6, digest=DIGEST, records=RECORDS)
        kwargs.update(bad)
        with pytest.raises(zg.TransferDenied) as exc:
            g.load_zone(ZONE, now=NOW, **kwargs)
        assert exc.value.code == "INVALID_REQUEST"


def test_begin_requires_matching_authorization():
    g = gov()
    g.register_key(ZONE, "tsig-a")
    g.load_zone(ZONE, serial=6, digest=DIGEST, records=RECORDS, now=NOW)
    with pytest.raises(zg.TransferDenied) as exc:
        begin(g, mode="axfr")
    assert exc.value.code == "NOT_AUTHORIZED"
    g.authorize(ZONE, secondary="sec-a", source="10.0.0.5", key_name="tsig-a", now=NOW)
    with pytest.raises(zg.TransferDenied) as exc:
        begin(g, secondary="sec-b", mode="axfr")
    assert exc.value.code == "NOT_AUTHORIZED"
    assert g.stats()["transfers_started"] == 0


def test_equal_serial_answers_with_single_soa_and_completes():
    g = ready()
    plan = begin(g, mode="auto", since=6)
    assert plan.mode == "nochange"
    assert plan.messages == 1
    assert plan.since == 6
    assert plan.serial == 6
    assert plan.digest == DIGEST
    g.record_progress(ZONE, "sec-a", messages=1, bytes_=128, last_soa=6, now=NOW)
    receipt = g.complete(ZONE, "sec-a", digest=DIGEST, now=NOW)
    assert receipt.state == "completed"
    assert receipt.mode == "nochange"
    assert receipt.serial == 6
    assert g.zone_status(ZONE)["watermarks"] == (("sec-a", 6),)


def test_explicit_axfr_counts_records_plus_two_soa_messages():
    g = ready()
    plan = begin(g, mode="axfr")
    assert plan.mode == "axfr"
    assert plan.since is None
    assert plan.messages == len(RECORDS) + 2
    g.record_progress(ZONE, "sec-a", messages=2, bytes_=256, now=NOW)
    receipt = g.complete(ZONE, "sec-a", digest=DIGEST, now=LATER)
    assert receipt.mode == "axfr"
    assert receipt.serial == 6
    assert receipt.digest == DIGEST
    assert receipt.state == "completed"


def test_incremental_transfer_uses_journal_between_serials():
    g = ready()
    plan = begin(g, mode="auto", since=5)
    assert plan.mode == "ixfr"
    assert plan.since == 5
    assert plan.messages == 4
    assert plan.serial == 6


def test_stale_secondary_serial_is_refused():
    g = ready()
    with pytest.raises(zg.TransferDenied) as exc:
        begin(g, mode="auto", since=7)
    assert exc.value.code == "SERIAL_REGRESSION"
    assert g.zone_status(ZONE)["active"] == ()
    assert g.stats()["denied"] == 1


def test_secondaries_are_isolated_and_duplicate_transfer_is_refused():
    g = ready()
    begin(g, secondary="sec-a", mode="axfr")
    begin(g, secondary="sec-b", mode="axfr")
    assert g.zone_status(ZONE)["active"] == ("sec-a", "sec-b")
    g.record_progress(ZONE, "sec-a", messages=2, bytes_=200, now=NOW)
    report_b = g.record_progress(ZONE, "sec-b", messages=0, bytes_=0, now=NOW)
    assert report_b.messages == 0
    assert report_b.bytes_sent == 0
    with pytest.raises(zg.TransferDenied) as exc:
        begin(g, secondary="sec-a", mode="axfr")
    assert exc.value.code == "TRANSFER_IN_PROGRESS"
    assert g.stats()["transfers_started"] == 2


def test_progress_accounting_tracks_remaining_budget():
    g = ready(max_messages=10, max_bytes=1000)
    with pytest.raises(zg.TransferDenied) as exc:
        g.record_progress(ZONE, "sec-b", messages=1, now=NOW)
    assert exc.value.code == "TRANSFER_NOT_ACTIVE"
    begin(g, mode="axfr")
    report = g.record_progress(ZONE, "sec-a", messages=2, bytes_=100, last_soa=6, now=NOW)
    assert report.mode == "axfr"
    assert report.messages == 2
    assert report.bytes_sent == 100
    assert report.remaining_messages == 8
    assert report.remaining_bytes == 900
    assert report.last_soa == 6
    with pytest.raises(zg.TransferDenied) as exc:
        g.record_progress(ZONE, "sec-a", messages=-1, now=NOW)
    assert exc.value.code == "INVALID_REQUEST"
    assert g.stats()["messages_sent"] == 2
    assert g.stats()["bytes_sent"] == 100


def test_message_budget_aborts_transfer_and_keeps_state_clean():
    g = ready(max_messages=4)
    begin(g, mode="axfr")
    g.record_progress(ZONE, "sec-a", messages=3, bytes_=300, last_soa=6, now=NOW)
    with pytest.raises(zg.TransferDenied) as exc:
        g.record_progress(ZONE, "sec-a", messages=2, bytes_=200, now=NOW)
    assert exc.value.code == "BUDGET_EXCEEDED"
    assert g.zone_status(ZONE)["active"] == ()
    assert g.stats()["budget_aborted"] == 1
    with pytest.raises(zg.TransferDenied) as exc:
        g.abort(ZONE, "sec-a", now=NOW)
    assert exc.value.code == "TRANSFER_NOT_ACTIVE"


def test_completion_updates_only_the_transferring_secondary_watermark():
    g = ready()
    begin(g, secondary="sec-a", mode="axfr")
    begin(g, secondary="sec-b", mode="axfr")
    g.record_progress(ZONE, "sec-a", messages=1, bytes_=64, now=NOW)
    g.complete(ZONE, "sec-a", digest=DIGEST, now=NOW)
    status = g.zone_status(ZONE)
    assert status["watermarks"] == (("sec-a", 6),)
    assert status["active"] == ("sec-b",)
    g.record_progress(ZONE, "sec-b", messages=1, bytes_=64, now=NOW)
    g.complete(ZONE, "sec-b", digest=DIGEST, now=NOW)
    assert g.zone_status(ZONE)["watermarks"] == (("sec-a", 6), ("sec-b", 6))
    assert g.stats()["transfers_completed"] == 2


def test_digest_mismatch_keeps_transfer_open_for_retry():
    g = ready()
    begin(g, mode="axfr")
    with pytest.raises(zg.TransferDenied) as exc:
        g.complete(ZONE, "sec-a", digest="00" * 32, now=NOW)
    assert exc.value.code == "DIGEST_MISMATCH"
    assert g.zone_status(ZONE)["active"] == ("sec-a",)
    assert g.zone_status(ZONE)["watermarks"] == ()
    g.complete(ZONE, "sec-a", digest=DIGEST, now=NOW)
    assert g.zone_status(ZONE)["watermarks"] == (("sec-a", 6),)
    with pytest.raises(zg.TransferDenied) as exc:
        g.complete(ZONE, "sec-a", digest=DIGEST, now=NOW)
    assert exc.value.code == "TRANSFER_NOT_ACTIVE"


def test_abort_records_last_soa_and_resume_continues_incrementally():
    g = ready()
    begin(g, mode="auto", since=4)
    g.record_progress(ZONE, "sec-a", messages=1, bytes_=500, last_soa=5, now=NOW)
    aborted = g.abort(ZONE, "sec-a", reason="pull failed", now=NOW)
    assert aborted["state"] == "aborted"
    assert aborted["last_soa"] == 5
    assert aborted["messages"] == 1
    assert aborted["bytes_sent"] == 500
    assert g.zone_status(ZONE)["active"] == ()
    plan = g.resume(ZONE, "sec-a", source="10.0.0.5", key_name="tsig-a", now=LATER)
    assert plan.mode == "ixfr"
    assert plan.since == 5
    assert plan.messages == 4
    with pytest.raises(zg.TransferDenied) as exc:
        g.resume(ZONE, "sec-a", source="10.0.0.5", key_name="tsig-a", now=LATER)
    assert exc.value.code == "TRANSFER_IN_PROGRESS"


def test_authorization_expires_and_binds_source_and_key():
    g = gov(auth_ttl=300)
    g.register_key(ZONE, "tsig-a")
    g.register_key(ZONE, "tsig-b")
    g.load_zone(ZONE, serial=6, digest=DIGEST, records=RECORDS, now=0)
    grant = g.authorize(ZONE, secondary="sec-a", source="10.0.0.5", key_name="tsig-a", now=0)
    assert grant.expires_at == 300
    assert grant.state == "active"
    with pytest.raises(zg.TransferDenied) as exc:
        begin(g, mode="axfr", now=301)
    assert exc.value.code == "NOT_AUTHORIZED"
    g.authorize(ZONE, secondary="sec-a", source="10.0.0.5", key_name="tsig-a", now=301)
    assert begin(g, mode="axfr", now=301).mode == "axfr"
    g.authorize(ZONE, secondary="sec-b", source="10.0.0.6", key_name="tsig-a", now=301)
    with pytest.raises(zg.TransferDenied) as exc:
        begin(g, secondary="sec-b", mode="axfr", now=301, source="10.0.0.99")
    assert exc.value.code == "AUTH_MISMATCH"
    with pytest.raises(zg.TransferDenied) as exc:
        begin(g, secondary="sec-b", mode="axfr", now=301, key_name="tsig-b")
    assert exc.value.code == "AUTH_MISMATCH"


def test_concurrent_begin_for_same_secondary_admits_exactly_one():
    g = ready()
    outcomes = []
    barrier = threading.Barrier(4)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            begin(g, mode="axfr")
            outcomes.append("started")
        except zg.TransferDenied as exc:
            outcomes.append(exc.code)
        except Exception as exc:  # pragma: no cover - surfaced through outcomes
            outcomes.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["TRANSFER_IN_PROGRESS"] * 3 + ["started"]
    assert g.stats()["transfers_started"] == 1


def test_snapshot_is_detached_and_restore_roundtrips():
    g = ready()
    begin(g, secondary="sec-a", mode="auto", since=5)
    g.record_progress(ZONE, "sec-a", messages=2, bytes_=200, last_soa=5, now=NOW)
    state = g.snapshot()
    assert set(state) == {"version", "zones", "keys", "auths", "active",
                          "aborted", "watermarks", "counters"}
    pristine = g.snapshot()
    state["zones"].clear()
    state["active"].clear()
    state["counters"]["transfers_started"] = 0
    assert g.zone_status(ZONE)["active"] == ("sec-a",)
    assert g.stats()["transfers_started"] == 1

    clone = gov()
    clone.restore(pristine)
    assert clone.zone_status(ZONE)["serial"] == 6
    assert clone.zone_status(ZONE)["active"] == ("sec-a",)
    assert clone.stats()["transfers_started"] == 1
    report = clone.record_progress(ZONE, "sec-a", messages=1, bytes_=10, now=LATER)
    assert report.messages == 3
    for bad in (None, {}, {"version": 2, "zones": [], "keys": {}, "auths": {},
                           "active": [], "aborted": {}, "watermarks": {},
                           "counters": {}}):
        with pytest.raises(zg.TransferDenied) as exc:
            clone.restore(bad)
        assert exc.value.code == "SNAPSHOT_INVALID"
    assert clone.zone_status(ZONE)["active"] == ("sec-a",)
