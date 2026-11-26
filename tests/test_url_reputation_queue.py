import threading

import pytest

import url_reputation_queue as uq


def queue(**kwargs):
    return uq.UrlReputationQueue(**kwargs)


def submit_and_expand(app, url, *, chain=(), now=1000):
    ticket = app.submit(url, chain=list(chain), now=now)
    return app.expand(ticket["job_id"], now=now)


def test_submit_normalizes_scheme_host_port_and_path():
    app = queue()
    ticket = app.submit("HTTPS://Example.COM:443/a/../b?x=1#frag", now=1000)
    assert ticket["url"] == "https://example.com/b?x=1"
    assert ticket["state"] == uq.JOB_QUEUED
    assert ticket["job_id"] == "JOB-0001"
    assert app.pending() == ("JOB-0001",)

    root = app.submit("http://Example.com", now=1001)
    assert root["url"] == "http://example.com/"
    kept = app.submit("https://example.com:8443/p", now=1002)
    assert kept["url"] == "https://example.com:8443/p"


def test_submit_rejects_bad_urls_and_bad_chain_entries():
    app = queue()
    for url in ("ftp://example.com/a", "http:///path", "",
                "https://user:pw@example.com/"):
        with pytest.raises(uq.UrlQueueError) as exc:
            app.submit(url, now=1000)
        assert exc.value.code == "URL_BAD_URL"

    for chain in (["http://ok.example/x", "%%%"], ["http://ok.example/x", 5]):
        with pytest.raises(uq.UrlQueueError) as exc:
            app.submit("http://ok.example/start", chain=chain, now=1000)
        assert exc.value.code == "URL_BAD_CHAIN"
    assert app.pending() == ()
    assert app.stats()["submitted"] == 0


def test_equivalent_urls_share_one_pending_job():
    app = queue()
    first = app.submit("http://Example.com/a", now=1000)
    second = app.submit("HTTP://example.COM:80/a", now=1001)
    assert second["job_id"] == first["job_id"]
    assert second["url"] == "http://example.com/a"
    assert app.pending() == (first["job_id"],)
    assert app.stats()["submitted"] == 2


def test_expand_without_redirects_resolves_the_url_itself():
    app = queue()
    result = submit_and_expand(app, "http://a.example.com/x")
    assert result["outcome"] == uq.OUTCOME_RESOLVED
    assert result["hops"] == 0
    assert result["chain"] == ("http://a.example.com/x",)
    assert result["final_url"] == "http://a.example.com/x"
    assert result["verdict"] == uq.VERDICT_BENIGN
    assert result["reason"] == "default_policy"
    assert app.expand_result("JOB-0001") == result
    assert app.verdict("JOB-0001")["verdict"] == uq.VERDICT_BENIGN


def test_expand_follows_in_scope_redirects_and_caches_the_verdict():
    app = queue(allowed_domains=("example.com",), default_ttl=600)
    result = submit_and_expand(
        app, "http://a.example.com/start",
        chain=["https://b.example.com/login", "https://c.example.com/end"])
    assert result["outcome"] == uq.OUTCOME_RESOLVED
    assert result["hops"] == 2
    assert result["chain"] == ("http://a.example.com/start",
                               "https://b.example.com/login",
                               "https://c.example.com/end")
    assert result["final_url"] == "https://c.example.com/end"
    cached = app.cache_lookup("https://c.example.com/end", now=1000)
    assert cached["verdict"] == uq.VERDICT_BENIGN
    assert cached["expires_at"] == 1600


def test_domain_policy_sets_verdict_and_ttl():
    app = queue(default_ttl=600)
    policy = app.register_domain_policy("evil.example", ttl=30,
                                        verdict=uq.VERDICT_MALICIOUS)
    assert policy == {"domain": "evil.example", "ttl": 30,
                      "verdict": uq.VERDICT_MALICIOUS}
    result = submit_and_expand(app, "https://evil.example/dropper")
    assert result["verdict"] == uq.VERDICT_MALICIOUS
    assert result["reason"] == "domain_policy"
    cached = app.cache_lookup("https://evil.example/dropper", now=1000)
    assert cached["verdict"] == uq.VERDICT_MALICIOUS
    assert cached["expires_at"] == 1030


def test_redirect_loop_is_undetermined_and_not_cached():
    app = queue(allowed_domains=("example.com",))
    result = submit_and_expand(
        app, "http://a.example.com/x",
        chain=["https://b.example.com/y", "https://a.example.com/x"])
    assert result["outcome"] == uq.OUTCOME_LOOP
    assert result["verdict"] == uq.VERDICT_UNDETERMINED
    assert result["reason"] == "redirect_loop"
    assert result["hops"] == 2
    assert result["final_url"] is None
    assert app.cache_lookup("http://a.example.com/x", now=1000) is None
    assert app.stats()["undetermined"] == 1


def test_hop_limit_stops_before_following_one_more_redirect():
    app = queue(hop_limit=2, allowed_domains=("example.com",))
    result = submit_and_expand(
        app, "http://a.example.com/1",
        chain=["https://b.example.com/2", "https://c.example.com/3",
               "https://d.example.com/4"])
    assert result["outcome"] == uq.OUTCOME_HOP_LIMIT
    assert result["hops"] == 2
    assert result["verdict"] == uq.VERDICT_UNDETERMINED
    assert result["reason"] == "hop_limit"
    assert len(result["chain"]) == 3
    assert result["final_url"] is None


def test_expand_is_idempotent_for_an_expanded_job():
    app = queue()
    first = submit_and_expand(app, "http://a.example.com/x")
    second = app.expand("JOB-0001", now=5000)
    assert second == first
    assert app.stats()["expansions"] == 1
    assert [row["state"] for row in app.jobs()] == [uq.JOB_EXPANDED]


def test_fresh_cache_answers_submit_without_queueing():
    app = queue()
    submit_and_expand(app, "http://a.example.com/x")
    ticket = app.submit("http://a.example.com/x", now=1100)
    assert ticket["state"] == "cached"
    assert ticket["job_id"] is None
    assert ticket["verdict"]["verdict"] == uq.VERDICT_BENIGN
    assert app.pending() == ()
    assert app.stats()["cache_hits"] == 1


def test_domain_ttl_controls_which_cache_entries_expire():
    app = queue(default_ttl=600)
    app.register_domain_policy("short.example", ttl=30)
    app.register_domain_policy("long.example", ttl=300)
    submit_and_expand(app, "https://short.example/a")
    submit_and_expand(app, "https://long.example/b")
    assert app.expire(now=1029) == 0
    assert app.expire(now=1031) == 1
    assert app.expire(now=1032) == 0
    assert app.cache_lookup("https://long.example/b", now=1031)["verdict"] == \
        uq.VERDICT_BENIGN


def test_pending_capacity_releases_a_slot_after_expansion():
    app = queue(max_pending=2)
    app.submit("http://one.example/a", now=1000)
    app.submit("http://two.example/b", now=1001)
    with pytest.raises(uq.UrlQueueError) as exc:
        app.submit("http://three.example/c", now=1002)
    assert exc.value.code == "URL_QUEUE_FULL"

    app.expand("JOB-0001", now=1003)
    ticket = app.submit("http://three.example/c", now=1004)
    assert ticket["job_id"] == "JOB-0003"
    assert app.pending() == ("JOB-0002", "JOB-0003")


def test_concurrent_submits_of_same_url_share_one_job():
    app = queue()
    errors = []
    ids = []
    barrier = threading.Barrier(12)

    def worker():
        try:
            barrier.wait(timeout=10)
            ids.append(app.submit("HTTP://Example.com/x", now=1000)["job_id"])
        except Exception as exc:  # pragma: no cover - reported through errors
            errors.append(repr(exc))

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    assert set(ids) == {"JOB-0001"}
    assert app.pending() == ("JOB-0001",)


def test_snapshot_is_detached_and_restore_roundtrips():
    app = queue()
    app.register_domain_policy("evil.example", verdict=uq.VERDICT_MALICIOUS)
    submit_and_expand(app, "https://evil.example/a", now=1000)
    app.submit("http://pending.example/b", now=1001)

    state = app.snapshot()
    assert set(state) == {"format", "policies", "jobs", "cache", "counters"}
    state["jobs"].clear()
    state["cache"].clear()
    assert app.verdict("JOB-0001")["verdict"] == uq.VERDICT_MALICIOUS
    assert app.pending() == ("JOB-0002",)

    clone = queue()
    clone.restore(app.snapshot())
    assert clone.verdict("JOB-0001")["reason"] == "domain_policy"
    assert clone.pending() == ("JOB-0002",)
    assert clone.cache_lookup("https://evil.example/a", now=1005)["verdict"] == \
        uq.VERDICT_MALICIOUS
    assert clone.stats() == {"policies": 1, "submitted": 2, "expansions": 1,
                             "cache_hits": 0, "expired": 0, "undetermined": 0}


def test_restore_rejects_malformed_state_and_pending_result_is_refused():
    app = queue()
    app.submit("http://a.example.com/x", now=1000)
    good = app.snapshot()
    bad_states = [
        None,
        {},
        dict(good, format="other"),
        dict(good, jobs=[]),
        dict(good, policies="nope"),
        dict(good, counters={}),
    ]
    for bad in bad_states:
        with pytest.raises(uq.UrlQueueError) as exc:
            app.restore(bad)
        assert exc.value.code == "URL_SNAPSHOT_INVALID"

    assert app.pending() == ("JOB-0001",)
    with pytest.raises(uq.UrlQueueError) as exc:
        app.expand_result("JOB-0001")
    assert exc.value.code == "URL_JOB_PENDING"
    with pytest.raises(uq.UrlQueueError) as exc:
        app.expand("JOB-9999", now=1000)
    assert exc.value.code == "URL_JOB_UNKNOWN"
