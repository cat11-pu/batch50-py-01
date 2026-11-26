import pytest

import bucket_exposure_scanner as bs

NOW = 3_000_000

PRIVATE_ACL = {"public_read": False, "public_write": False}
PUBLIC_ACL = {"public_read": True, "public_write": True}
READ_ACL = {"public_read": True, "public_write": False}
ALLOW_ALL = {"statements": [{"id": "all", "effect": "Allow", "principal": "*", "action": "s3:*"}]}
ALLOW_READ = {"statements": [{"id": "read", "effect": "Allow", "principal": "*",
                             "action": "s3:GetObject"}]}
EMPTY_POLICY = {"statements": []}


class FakeProber:
    def __init__(self):
        self.responses = {}
        self.calls = []

    def set(self, bucket, action, value):
        self.responses[(bucket, action)] = value

    def __call__(self, bucket, region, action):
        self.calls.append((bucket, region, action))
        value = self.responses.get((bucket, action))
        if value is None:
            return {"status": 403, "keys": (), "body": ""}
        if isinstance(value, Exception):
            raise value
        return dict(value)


def make_scanner(**kwargs):
    prober = FakeProber()
    kwargs.setdefault("probe_per_minute", 30)
    kwargs.setdefault("cooldown_seconds", 60)
    kwargs.setdefault("rescan_interval", 600)
    scanner = bs.BucketExposureScanner(prober=prober, **kwargs)
    return scanner, prober


def test_register_assigns_and_bumps_policy_version():
    scanner, _ = make_scanner()
    scanner.register("logs-bucket", region="r1", account="acct",
                     acl=PRIVATE_ACL, policy=EMPTY_POLICY)
    scanner.register("logs-bucket", region="r1", account="acct",
                     acl=PRIVATE_ACL, policy=ALLOW_READ)
    assert scanner.stats()["buckets"] == 1


def test_invalid_bucket_name_is_rejected():
    scanner, _ = make_scanner()
    for name in ("My_Bucket", "ab"):
        with pytest.raises(bs.ExposureError) as err:
            scanner.register(name, region="r1", account="acct",
                             acl=PRIVATE_ACL, policy=EMPTY_POLICY)
        assert err.value.code == "INVALID_BUCKET"


def test_bucket_capacity_is_enforced():
    scanner, _ = make_scanner(max_buckets=1)
    scanner.register("first-bucket", region="r1", account="acct",
                     acl=PRIVATE_ACL, policy=EMPTY_POLICY)
    with pytest.raises(bs.ExposureError) as err:
        scanner.register("second-bucket", region="r1", account="acct",
                         acl=PRIVATE_ACL, policy=EMPTY_POLICY)
    assert err.value.code == "CAPACITY_EXCEEDED"


def test_acl_and_policy_both_allow_public_read_write():
    scanner, _ = make_scanner()
    scanner.register("open-bucket", region="r1", account="acct",
                     acl=PUBLIC_ACL, policy=ALLOW_ALL)
    verdict = scanner.evaluate_acl("open-bucket", region="r1")
    assert verdict.read_allowed is True
    assert verdict.write_allowed is True
    assert verdict.public_read is True
    assert verdict.public_write is True
    assert verdict.explicit_denies == ()


def test_public_read_and_write_are_judged_separately():
    scanner, _ = make_scanner()
    scanner.register("read-bucket", region="r1", account="acct",
                     acl=READ_ACL, policy=ALLOW_READ)
    verdict = scanner.evaluate_acl("read-bucket", region="r1")
    assert verdict.read_allowed is True
    assert verdict.write_allowed is False
    assert verdict.public_write is False


def test_evaluate_acl_uses_overrides_and_rejects_unknown_bucket():
    scanner, _ = make_scanner()
    with pytest.raises(bs.ExposureError) as err:
        scanner.evaluate_acl("missing-bucket", region="r1")
    assert err.value.code == "BUCKET_UNKNOWN"
    scanner.register("known-bucket", region="r1", account="acct",
                     acl=PRIVATE_ACL, policy=EMPTY_POLICY)
    verdict = scanner.evaluate_acl("known-bucket", region="r1",
                                   acl=PUBLIC_ACL, policy=ALLOW_ALL)
    assert verdict.read_allowed is True
    assert verdict.write_allowed is True


def test_denied_head_probe_is_clean():
    scanner, prober = make_scanner()
    scanner.register("denied-bucket", region="r1", account="acct",
                     acl=PRIVATE_ACL, policy=EMPTY_POLICY)
    prober.set("denied-bucket", "HEAD", {"status": 403})
    result = scanner.probe_anonymous("denied-bucket", region="r1", now=NOW)
    assert result.state == "clean"
    assert result.evidence != ()
    assert scanner.stats()["probes"] == 1


def test_missing_bucket_is_recorded_separately():
    scanner, prober = make_scanner()
    scanner.register("gone-bucket", region="r1", account="acct",
                     acl=PRIVATE_ACL, policy=EMPTY_POLICY)
    prober.set("gone-bucket", "HEAD", {"status": 404})
    result = scanner.probe_anonymous("gone-bucket", region="r1", now=NOW)
    assert result.state == "missing"
    assert scanner.stats()["not_found"] == 1


def test_network_error_is_probe_failure():
    scanner, prober = make_scanner()
    scanner.register("flaky-bucket", region="r1", account="acct",
                     acl=PRIVATE_ACL, policy=EMPTY_POLICY)
    prober.set("flaky-bucket", "HEAD", OSError("connection reset"))
    with pytest.raises(bs.ExposureError) as err:
        scanner.probe_anonymous("flaky-bucket", region="r1", now=NOW)
    assert err.value.code == "PROBE_FAILED"
    assert scanner.stats()["failures"] == 1


def test_server_error_enters_cooldown_not_exposure():
    scanner, prober = make_scanner()
    scanner.register("busy-bucket", region="r1", account="acct",
                     acl=PRIVATE_ACL, policy=EMPTY_POLICY)
    prober.set("busy-bucket", "HEAD", {"status": 503})
    result = scanner.probe_anonymous("busy-bucket", region="r1", now=NOW)
    assert result.state == "cooldown"
    assert scanner.stats()["cooldowns"] == 1
    with pytest.raises(bs.ExposureError) as err:
        scanner.probe_anonymous("busy-bucket", region="r1", now=NOW + 1)
    assert err.value.code == "COOLDOWN_ACTIVE"
    again = scanner.probe_anonymous("busy-bucket", region="r1", now=NOW + 61)
    assert again.state == "cooldown"


def test_confirm_requires_reproducible_anonymous_read():
    scanner, prober = make_scanner()
    scanner.register("public-bucket", region="r1", account="acct",
                     acl=READ_ACL, policy=ALLOW_READ)
    prober.set("public-bucket", "HEAD", {"status": 200})
    prober.set("public-bucket", "GET", {"status": 200, "keys": ("public/readme.txt",)})
    first = scanner.probe_anonymous("public-bucket", region="r1", now=NOW)
    assert first.state == "candidate"
    assert first.evidence != ()
    with pytest.raises(bs.ExposureError) as err:
        scanner.confirm("public-bucket", region="r1", now=NOW + 1)
    assert err.value.code == "NOT_REPRODUCIBLE"
    scanner.probe_anonymous("public-bucket", region="r1", now=NOW + 5)
    assert scanner.confirm("public-bucket", region="r1", now=NOW + 6) == "confirmed"
    conclusion = scanner.conclusions(state="confirmed")[0]
    assert conclusion.read_public is True


def test_probe_rate_budget_is_enforced():
    scanner, _ = make_scanner(probe_per_minute=1)
    for name in ("one-bucket", "two-bucket"):
        scanner.register(name, region="r1", account="acct",
                         acl=PRIVATE_ACL, policy=EMPTY_POLICY)
    scanner.probe_anonymous("one-bucket", region="r1", now=NOW)
    with pytest.raises(bs.ExposureError) as err:
        scanner.probe_anonymous("two-bucket", region="r1", now=NOW)
    assert err.value.code == "PROBE_RATE_LIMITED"


def test_rescan_flips_confirmed_bucket_to_fixed():
    scanner, prober = make_scanner()
    scanner.register("fixed-bucket", region="r1", account="acct",
                     acl=READ_ACL, policy=ALLOW_READ)
    prober.set("fixed-bucket", "HEAD", {"status": 200})
    prober.set("fixed-bucket", "GET", {"status": 200, "keys": ("a.txt",)})
    scanner.probe_anonymous("fixed-bucket", region="r1", now=NOW)
    scanner.probe_anonymous("fixed-bucket", region="r1", now=NOW + 5)
    scanner.confirm("fixed-bucket", region="r1", now=NOW + 6)
    prober.set("fixed-bucket", "HEAD", {"status": 403})
    prober.set("fixed-bucket", "GET", {"status": 403})
    conclusion = scanner.rescan("fixed-bucket", region="r1", now=NOW + 600)
    assert conclusion.state == "fixed"
    assert conclusion.cached is False


def test_rescan_uses_cache_until_policy_changes():
    scanner, prober = make_scanner()
    scanner.register("cached-bucket", region="r1", account="acct",
                     acl=READ_ACL, policy=ALLOW_READ)
    prober.set("cached-bucket", "HEAD", {"status": 200})
    prober.set("cached-bucket", "GET", {"status": 200, "keys": ("a.txt",)})
    scanner.probe_anonymous("cached-bucket", region="r1", now=NOW)
    calls = len(prober.calls)
    cached = scanner.rescan("cached-bucket", region="r1", now=NOW + 60)
    assert cached.cached is True
    assert len(prober.calls) == calls
    scanner.register("cached-bucket", region="r1", account="acct",
                     acl=READ_ACL, policy=EMPTY_POLICY)
    fresh = scanner.rescan("cached-bucket", region="r1", now=NOW + 120)
    assert fresh.cached is False
    assert len(prober.calls) > calls


def test_snapshot_restore_keeps_ledger_and_stats():
    scanner, prober = make_scanner()
    scanner.register("snap-bucket", region="r1", account="acct",
                     acl=READ_ACL, policy=ALLOW_READ)
    prober.set("snap-bucket", "HEAD", {"status": 200})
    prober.set("snap-bucket", "GET", {"status": 200, "keys": ("a.txt",)})
    scanner.probe_anonymous("snap-bucket", region="r1", now=NOW)
    snap = scanner.snapshot()
    clone, _ = make_scanner()
    clone.restore(snap)
    assert clone.stats() == scanner.stats()
    assert [(item.bucket, item.region, item.state) for item in clone.conclusions()] == [
        ("snap-bucket", "r1", "candidate")]
    with pytest.raises(bs.ExposureError) as err:
        clone.restore("broken")
    assert err.value.code == "SNAPSHOT_INVALID"
    assert len(clone.conclusions()) == 1
