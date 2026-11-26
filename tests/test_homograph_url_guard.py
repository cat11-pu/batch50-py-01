import pytest

import homograph_url_guard as hg

NOW = 1_700_000_000


def make_guard(**kwargs):
    kwargs.setdefault("brands", {"paypal": ["paypal.com"]})
    return hg.HomographUrlGuard(**kwargs)


def test_normalize_host_strips_userinfo_port_and_trailing_dot():
    guard = make_guard()
    assert guard.normalize_host("HTTPS://user:pw@Example.COM.:8443/Path") == "example.com"


def test_normalize_host_treats_backslash_as_separator():
    guard = make_guard()
    assert guard.normalize_host("https://evil.test\\@bank.test/x") == "evil.test"


def test_registrable_domain_uses_public_suffix_table():
    guard = make_guard()
    assert guard.registrable_domain("a.b.example.co.uk") == "example.co.uk"
    assert guard.registrable_domain("shop.example.com.cn") == "example.com.cn"
    assert guard.registrable_domain("Example.COM") == "example.com"


def test_official_brand_domain_is_low_risk():
    guard = make_guard()
    verdict = guard.analyze("https://paypal.com/account", now=NOW)
    assert verdict.risk == "low"
    assert verdict.brand == "paypal"
    assert verdict.similarity == 1.0
    assert verdict.registrable_domain == "paypal.com"


def test_mixed_script_homoglyph_is_high_risk():
    guard = make_guard(brands={"apple": ["apple.com"]})
    verdict = guard.analyze("https://аpple.com/", now=NOW)
    assert verdict.risk == "high"
    assert "Latin" in verdict.scripts
    assert "Cyrillic" in verdict.scripts
    assert verdict.ascii_host.startswith("xn--")
    assert verdict.unicode_host == "аpple.com"


def test_ascii_lookalike_scores_against_brand():
    guard = make_guard()
    verdict = guard.analyze("https://paypa1.com/login", now=NOW)
    assert verdict.risk == "high"
    assert verdict.brand == "paypal"
    assert verdict.similarity >= 0.9


def test_unrelated_host_has_no_brand_candidate():
    guard = make_guard()
    verdict = guard.analyze("https://news.example.org/", now=NOW)
    assert verdict.risk == "low"
    assert verdict.brand is None
    assert verdict.similarity == 0.0
    assert guard.stats()["analyzed"] == 1


def test_allowlist_matches_registrable_domain_and_expires():
    guard = make_guard()
    assert guard.analyze("https://paypa1.com/", now=NOW).risk == "high"
    guard.allowlist("paypa1.com", ttl=3600, now=NOW)
    assert guard.is_allowlisted("login.paypa1.com", now=NOW) is True
    assert guard.analyze("https://paypa1.com/", now=NOW).risk == "low"
    assert guard.is_allowlisted("login.paypa1.com", now=NOW + 4000) is False
    assert guard.analyze("https://paypa1.com/", now=NOW + 4000).risk == "high"


def test_community_feedback_raises_risk():
    guard = make_guard()
    for offset in range(3):
        guard.feedback("https://bad.example.net/login", label="phishing", now=NOW + offset)
    verdict = guard.analyze("https://bad.example.net/login", now=NOW + 10)
    assert verdict.risk == "high"


def test_invalid_feedback_label_is_rejected():
    guard = make_guard()
    with pytest.raises(hg.UrlGuardError) as err:
        guard.feedback("https://bad.example.net/login", label="unknown", now=NOW)
    assert err.value.code == "FEEDBACK_INVALID"


def test_redirect_chain_takes_worst_hop():
    guard = make_guard()
    verdict = guard.analyze("https://short.example/abc",
                            redirects=["https://paypa1.com/login"], now=NOW)
    assert verdict.risk == "high"
    assert len(verdict.redirect_chain) == 2
    assert verdict.redirect_chain[0] == "https://short.example/abc"


def test_redirect_limit_is_enforced():
    guard = make_guard(max_redirects=1)
    with pytest.raises(hg.UrlGuardError) as err:
        guard.analyze("https://short.example/abc",
                      redirects=["https://hop1.example/", "https://paypa1.com/"], now=NOW)
    assert err.value.code == "REDIRECT_LIMIT"


def test_sweep_skips_invalid_urls_and_counts_them():
    guard = make_guard()
    verdicts = guard.sweep(["https://news.example.org/", "not a url",
                            "https://paypa1.com/"], now=NOW)
    assert [item.risk for item in verdicts] == ["low", "high"]
    assert guard.stats()["invalid"] == 1


def test_brand_table_version_invalidates_host_cache():
    guard = make_guard()
    first = guard.analyze("https://paypa1.com/", now=NOW)
    assert first.cached is False
    assert guard.analyze("https://paypa1.com/", now=NOW + 1).cached is True
    assert guard.stats()["cached"] == 1
    guard.add_brand("other", domains=("other.test",))
    assert guard.analyze("https://paypa1.com/", now=NOW + 2).cached is False


def test_snapshot_restore_keeps_brands_allowlist_and_feedback():
    guard = make_guard()
    guard.allowlist("partner.test", ttl=3600, now=NOW)
    guard.feedback("https://bad.example.net/x", label="phishing", now=NOW)
    snap = guard.snapshot()
    clone = make_guard()
    clone.restore(snap)
    assert clone.is_allowlisted("partner.test", now=NOW) is True
    assert clone.analyze("https://paypa1.com/", now=NOW).risk == "high"
    with pytest.raises(hg.UrlGuardError) as err:
        clone.restore("broken")
    assert err.value.code == "SNAPSHOT_INVALID"
    assert clone.is_allowlisted("partner.test", now=NOW) is True
