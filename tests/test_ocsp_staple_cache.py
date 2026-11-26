import threading

import pytest

import ocsp_staple_cache as oc

FP = "a" * 64
FP2 = "b" * 64
ISSUER = "intermediate-ca-one"
BODY = b"\x30\x82ocsp-response-body-bytes"


def cache(**kwargs):
    return oc.OcspStapleCache(**kwargs)


def registered(**kwargs):
    c = cache(**kwargs)
    c.register("shop.example", fingerprint=FP, issuer=ISSUER, serial=42, now=0)
    return c


def test_register_records_certificate_and_rejects_duplicate_site():
    c = cache()
    record = c.register("shop.example", fingerprint=FP, issuer=ISSUER, serial=42,
                        must_staple=True, now=0)
    assert record.site == "shop.example"
    assert record.fingerprint == FP
    assert record.issuer == ISSUER
    assert record.serial == 42
    assert record.must_staple is True
    assert record.registered_at == 0
    with pytest.raises(oc.StapleError) as exc:
        c.register("shop.example", fingerprint=FP2, issuer=ISSUER, serial=1, now=0)
    assert exc.value.code == "STAPLE_SITE_EXISTS"
    assert c.stats()["registrations"] == 1


def test_cache_miss_returns_unavailable_view_without_must_staple():
    c = registered()
    with pytest.raises(oc.StapleError) as exc:
        c.get_staple("ghost.example", now=0)
    assert exc.value.code == "STAPLE_UNKNOWN_SITE"
    view = c.get_staple("shop.example", now=0)
    assert view.available is False
    assert view.body is None
    assert view.state == "empty"
    assert view.this_update is None
    assert view.next_update is None
    assert view.issuer == ISSUER
    assert c.stats()["cache_misses"] == 1
    assert c.stats()["cache_hits"] == 0


def test_must_staple_site_fails_handshake_without_response():
    c = cache()
    c.register("secure.example", fingerprint=FP, issuer=ISSUER, serial=7,
               must_staple=True, now=0)
    with pytest.raises(oc.StapleError) as exc:
        c.get_staple("secure.example", now=0)
    assert exc.value.code == "MUST_STAPLE_UNAVAILABLE"
    c.refresh("secure.example", body=BODY, this_update=0, next_update=90, now=0)
    view = c.get_staple("secure.example", now=10)
    assert view.available is True
    assert view.body == BODY
    assert view.state == "good"


def test_refresh_caches_verbatim_bytes_and_reports_state():
    c = registered()
    result = c.refresh("shop.example", body=BODY, this_update=0, next_update=90, now=0)
    assert result.site == "shop.example"
    assert result.fingerprint == FP
    assert result.issuer == ISSUER
    assert result.state == "good"
    assert result.body_size == len(BODY)
    assert result.this_update == 0
    assert result.next_update == 90
    view = c.get_staple("shop.example", now=30)
    assert view.available is True
    assert view.body == BODY
    assert view.this_update == 0
    assert view.next_update == 90
    assert c.status("shop.example")["available"] is True
    assert c.status("shop.example")["body_size"] == len(BODY)
    assert c.stats()["refreshes"] == 1
    assert c.stats()["cache_hits"] == 1


def test_refresh_with_foreign_serial_is_rejected():
    c = registered()
    with pytest.raises(oc.StapleError) as exc:
        c.refresh("shop.example", body=BODY, this_update=0, next_update=90,
                  serial=43, now=0)
    assert exc.value.code == "STAPLE_SERIAL_MISMATCH"
    assert c.get_staple("shop.example", now=0).available is False
    assert c.stats()["refresh_failures"] == 1


def test_refresh_with_foreign_issuer_is_rejected():
    c = registered()
    with pytest.raises(oc.StapleError) as exc:
        c.refresh("shop.example", body=BODY, this_update=0, next_update=90,
                  issuer="other-ca", now=0)
    assert exc.value.code == "STAPLE_ISSUER_MISMATCH"
    assert c.status("shop.example")["body_size"] == 0


def test_refresh_validates_signature_and_validity_window():
    c = registered()
    with pytest.raises(oc.StapleError) as exc:
        c.refresh("shop.example", body=BODY, this_update=0, next_update=90,
                  signature_ok=False, now=0)
    assert exc.value.code == "STAPLE_BAD_SIGNATURE"
    with pytest.raises(oc.StapleError) as exc:
        c.refresh("shop.example", body=BODY, this_update=100, next_update=100, now=0)
    assert exc.value.code == "STAPLE_WINDOW_INVALID"
    assert c.stats()["refresh_failures"] == 2


def test_staple_stops_being_served_after_next_update():
    c = registered()
    c.refresh("shop.example", body=BODY, this_update=0, next_update=100, now=0)
    assert c.get_staple("shop.example", now=100).available is True
    expired = c.get_staple("shop.example", now=101)
    assert expired.available is False
    assert expired.state == "expired"
    assert expired.body is None
    assert c.stats()["cache_hits"] == 1


def test_refresh_lease_serializes_inflight_work():
    c = registered()
    lease = c.acquire_refresh("shop.example", now=5)
    assert lease.site == "shop.example"
    assert lease.fingerprint == FP
    assert lease.issuer == ISSUER
    assert lease.acquired_at == 5
    assert lease.expires_at == 15
    with pytest.raises(oc.StapleError) as exc:
        c.acquire_refresh("shop.example", now=6)
    assert exc.value.code == "REFRESH_IN_PROGRESS"
    with pytest.raises(oc.StapleError) as exc:
        c.refresh("shop.example", body=BODY, this_update=0, next_update=90, now=6)
    assert exc.value.code == "REFRESH_IN_PROGRESS"
    c.refresh("shop.example", body=BODY, this_update=0, next_update=90,
              lease=lease, now=6)
    assert c.release_refresh("shop.example", now=7) is True
    assert c.release_refresh("shop.example", now=7) is False
    c.refresh("shop.example", body=BODY, this_update=0, next_update=90, now=8)


def test_concurrent_lease_acquisition_admits_single_holder():
    c = registered()
    outcomes = []
    barrier = threading.Barrier(4)

    def worker(index):
        try:
            barrier.wait(timeout=5)
            c.acquire_refresh("shop.example", now=1)
            outcomes.append("held")
        except oc.StapleError as exc:
            outcomes.append(exc.code)
        except Exception as exc:  # pragma: no cover - surfaced through outcomes
            outcomes.append(repr(exc))

    threads = [threading.Thread(target=worker, args=(index,)) for index in range(4)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert sorted(outcomes) == ["REFRESH_IN_PROGRESS"] * 3 + ["held"]
    assert c.status("shop.example")["in_flight"] is True


def test_sweep_reports_refresh_due_then_expires_entries():
    c = registered(refresh_ratio=0.75)
    c.refresh("shop.example", body=BODY, this_update=0, next_update=100, now=0)
    assert c.sweep(now=70).due == 0
    assert c.sweep(now=80).due == 1
    report = c.sweep(now=101)
    assert report.expired == 1
    assert report.evicted == 0
    assert c.status()["cached"] == 0
    assert c.stats()["sweeps"] == 3


def test_response_and_fingerprint_capacities_are_enforced():
    c = registered(max_bytes=64)
    with pytest.raises(oc.StapleError) as exc:
        c.refresh("shop.example", body=b"x" * 100, this_update=0, next_update=90, now=0)
    assert exc.value.code == "STAPLE_CAPACITY_EXCEEDED"
    assert c.status("shop.example")["body_size"] == 0

    tiny = cache(max_fingerprints=1)
    tiny.register("a.example", fingerprint=FP, issuer=ISSUER, serial=1, now=0)
    with pytest.raises(oc.StapleError) as exc:
        tiny.register("b.example", fingerprint=FP2, issuer=ISSUER, serial=2, now=0)
    assert exc.value.code == "STAPLE_FINGERPRINT_LIMIT"


def test_invalidate_counts_every_site_using_the_fingerprint():
    c = cache()
    c.register("a.example", fingerprint=FP, issuer=ISSUER, serial=42, now=0)
    c.register("b.example", fingerprint=FP, issuer=ISSUER, serial=42, now=0)
    c.refresh("a.example", body=BODY, this_update=0, next_update=90, now=0)
    c.refresh("b.example", body=BODY, this_update=0, next_update=90, now=0)
    assert c.invalidate(FP, now=10) == 2
    assert c.invalidate("c" * 64, now=10) == 0
    assert c.stats()["invalidated"] == 2


def test_mark_revoked_matches_issuer_and_serial_together():
    c = cache()
    c.register("a.example", fingerprint=FP, issuer="ca-1", serial=7, now=0)
    c.register("b.example", fingerprint=FP2, issuer="ca-1", serial=8, now=0)
    c.register("c.example", fingerprint="d" * 64, issuer="ca-2", serial=7, now=0)
    assert c.mark_revoked("ca-1", 7, now=5) == 1
    assert c.mark_revoked("ca-1", 99, now=5) == 0
    assert c.stats()["revoked"] == 1
    assert c.status()["revoked"] == 1
    assert c.status()["sites"] == 3


def test_snapshot_is_detached_and_restore_roundtrips():
    c = registered()
    c.refresh("shop.example", body=BODY, this_update=0, next_update=100, now=0)
    state = c.snapshot()
    assert set(state) == {"version", "sites", "cache", "leases", "counters"}
    pristine = c.snapshot()
    state["sites"].clear()
    state["cache"].clear()
    state["counters"]["refreshes"] = 0
    assert c.status("shop.example")["available"] is True
    assert c.stats()["refreshes"] == 1

    clone = cache()
    clone.restore(pristine)
    view = clone.get_staple("shop.example", now=10)
    assert view.available is True
    assert view.body == BODY
    assert clone.stats()["refreshes"] == 1
    for bad in (None, {}, {"version": 2, "sites": [], "cache": [], "leases": [],
                           "counters": {}}):
        with pytest.raises(oc.StapleError) as exc:
            clone.restore(bad)
        assert exc.value.code == "STAPLE_SNAPSHOT_INVALID"
    assert clone.get_staple("shop.example", now=10).available is True
