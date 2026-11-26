import pytest

import graphql_abuse_guard as gg

LIST_QUERY = "query { user { id posts(first: 10) { id title } } }"
SIMPLE_QUERY = "query { user { id name } }"
FRAGMENT_QUERY = "query { viewer { ...F } } fragment F on User { id name }"
CYCLE_QUERY = ("query { a { ...A } } fragment A on T { b { ...B } } "
               "fragment B on T { c { ...A } }")
INTROSPECTION_QUERY = "query { __schema { types { name } } }"


def permissive(**kwargs):
    kwargs.setdefault("strict_persisted", False)
    return gg.GraphqlAbuseGuard(**kwargs)


def test_simple_query_admitted_with_cost_and_remaining():
    guard = permissive()
    out = guard.admit(SIMPLE_QUERY, client="c1", now=0.0)
    assert out.cost == 3
    assert out.depth == 2
    assert out.client == "c1"
    assert out.fingerprint
    assert out.remaining == 9


def test_list_field_multiplies_subtree_cost():
    guard = permissive()
    out = guard.admit(LIST_QUERY, client="c1", now=0.0)
    assert out.cost == 23
    assert out.depth == 3


def test_depth_limit_rejects_deep_query():
    guard = permissive(depth_limit=2)
    with pytest.raises(gg.GraphqlGuardError) as err:
        guard.admit(LIST_QUERY, client="c1", now=0.0)
    assert err.value.code == "DEPTH_EXCEEDED"


def test_cyclic_fragment_is_rejected():
    guard = permissive()
    with pytest.raises(gg.GraphqlGuardError) as err:
        guard.admit(CYCLE_QUERY, client="c1", now=0.0)
    assert err.value.code == "CYCLE_DETECTED"


def test_fragment_expansion_is_counted_in_cost():
    guard = permissive()
    out = guard.admit(FRAGMENT_QUERY, client="c1", now=0.0)
    assert out.cost == 3
    assert out.depth == 2


def test_cost_budget_rejects_expensive_query():
    guard = permissive(cost_budget=10)
    with pytest.raises(gg.GraphqlGuardError) as err:
        guard.admit(LIST_QUERY, client="c1", now=0.0)
    assert err.value.code == "COST_EXCEEDED"
    assert err.value.detail is not None


def test_strict_mode_requires_persisted_query():
    guard = gg.GraphqlAbuseGuard()
    with pytest.raises(gg.GraphqlGuardError) as err:
        guard.admit(SIMPLE_QUERY, client="c1", now=0.0)
    assert err.value.code == "PERSISTED_REQUIRED"
    fingerprint = guard.register_persisted(query=SIMPLE_QUERY)
    assert fingerprint in guard.persisted()
    out = guard.admit(SIMPLE_QUERY, client="c1", now=0.0)
    assert out.cost == 3


def test_revoked_persisted_query_is_blocked_again():
    guard = gg.GraphqlAbuseGuard()
    fingerprint = guard.register_persisted(query=SIMPLE_QUERY)
    assert guard.revoke(fingerprint) is True
    assert guard.revoke(fingerprint) is False
    assert guard.persisted() == ()
    with pytest.raises(gg.GraphqlGuardError) as err:
        guard.admit(SIMPLE_QUERY, client="c1", now=0.0)
    assert err.value.code == "PERSISTED_REQUIRED"


def test_fingerprint_ignores_layout_but_keeps_argument_values():
    guard = permissive()
    base = guard.fingerprint("query { a b }")
    assert base == guard.fingerprint("query{a   b}")
    assert base == guard.fingerprint("query { b a }")
    assert guard.fingerprint("query { user { x y } }") == guard.fingerprint("query { user { y x } }")
    assert guard.fingerprint("query { user(id: 5) { id } }") != guard.fingerprint(
        "query { user(id: 6) { id } }")


def test_introspection_is_denied_until_policy_enables_it():
    guard = permissive()
    with pytest.raises(gg.GraphqlGuardError) as err:
        guard.admit(INTROSPECTION_QUERY, client="c1", now=0.0)
    assert err.value.code == "INTROSPECTION_DENIED"
    guard.policy(allow_introspection=True)
    out = guard.admit(INTROSPECTION_QUERY, client="c1", now=0.0)
    assert out.cost >= 1


def test_token_bucket_limits_burst():
    guard = permissive(burst=2)
    guard.admit("query { a }", client="c1", now=0.0)
    guard.admit("query { a }", client="c1", now=0.0)
    with pytest.raises(gg.GraphqlGuardError) as err:
        guard.admit("query { a }", client="c1", now=0.0)
    assert err.value.code == "RATE_LIMITED"


def test_charge_overdraft_is_atomic():
    guard = permissive(burst=5)
    guard.charge("c1", 3, now=0.0)
    with pytest.raises(gg.GraphqlGuardError) as err:
        guard.charge("c1", 4, now=0.0)
    assert err.value.code == "QUOTA_EXHAUSTED"
    assert guard.status("c1")["tokens"] == 2


def test_concurrency_cap_and_complete():
    guard = permissive(max_concurrent=1)
    guard.admit("query { a }", client="c1", now=0.0)
    with pytest.raises(gg.GraphqlGuardError) as err:
        guard.admit("query { b }", client="c1", now=0.0)
    assert err.value.code == "CONCURRENCY_LIMITED"
    guard.complete("c1")
    out = guard.admit("query { c }", client="c1", now=0.0)
    assert out.cost == 1


def test_batch_charges_total_cost_and_checks_budget():
    guard = permissive(cost_per_token=1)
    results = guard.admit_batch([SIMPLE_QUERY, "query { viewer { id } }"],
                                client="c1", now=0.0)
    assert [item.cost for item in results] == [3, 2]
    assert guard.stats()["tokens_spent"] == 5
    small = permissive(cost_budget=10)
    with pytest.raises(gg.GraphqlGuardError) as err:
        small.admit_batch([LIST_QUERY, LIST_QUERY], client="c1", now=0.0)
    assert err.value.code == "BATCH_COST_EXCEEDED"


def test_snapshot_restore_keeps_whitelist_and_stats():
    guard = gg.GraphqlAbuseGuard()
    fingerprint = guard.register_persisted(query=SIMPLE_QUERY)
    guard.admit(SIMPLE_QUERY, client="c1", now=0.0)
    snap = guard.snapshot()
    clone = gg.GraphqlAbuseGuard()
    clone.restore(snap)
    assert clone.persisted() == (fingerprint,)
    assert clone.stats()["admitted"] == 1
    with pytest.raises(gg.GraphqlGuardError) as err:
        clone.restore("broken")
    assert err.value.code == "SNAPSHOT_INVALID"
    assert clone.persisted() == (fingerprint,)
