import pytest

import polkit_rule_engine as pk

ACTION = "org.example.backup.run"
NOW = "2026-11-26T09:00:00+00:00"
LATER = "2026-11-26T09:01:00+00:00"
EXPIRED = "2026-11-26T09:05:01+00:00"


def engine(**kwargs):
    return pk.PolkitRuleEngine(**kwargs)


def rule(result, *, source="admin", action=ACTION, subject="alice",
         subject_kind="user"):
    return pk.Rule(source=source, action=action, subject=subject,
                   subject_kind=subject_kind, result=result)


def loaded(result="yes", **kwargs):
    eng = engine(**kwargs)
    eng.register_action(ACTION, description="nightly backup")
    eng.load_rules([rule(result)], now=NOW)
    return eng


def test_unknown_action_rejected():
    eng = engine()
    with pytest.raises(pk.PolicyError) as exc:
        eng.evaluate("alice", ACTION, now=NOW)
    assert exc.value.code == "POLICY_UNKNOWN_ACTION"


def test_admin_rule_overrides_vendor_default():
    eng = engine()
    eng.register_action(ACTION)
    eng.load_rules([rule("no", source="vendor"), rule("yes", source="admin")], now=NOW)
    decision = eng.evaluate("alice", ACTION, now=NOW)
    assert decision.result == "yes"
    assert decision.source == "admin"


def test_first_matching_rule_wins_within_same_layer():
    eng = engine()
    eng.register_action(ACTION)
    eng.load_rules([rule("no"), rule("yes")], now=NOW)
    assert eng.evaluate("alice", ACTION, now=NOW).result == "no"


def test_group_rule_matches_member():
    eng = engine()
    eng.register_action(ACTION)
    eng.load_rules([rule("yes", subject="staff", subject_kind="group")], now=NOW)
    decision = eng.evaluate("bob", ACTION, groups=("staff", "wheel"), now=NOW)
    assert decision.result == "yes"
    assert decision.source == "admin"


def test_no_matching_rule_denies():
    eng = engine()
    eng.register_action(ACTION)
    eng.load_rules([rule("yes", subject="someoneelse")], now=NOW)
    decision = eng.evaluate("nobody", ACTION, now=NOW)
    assert decision.result == "no"
    assert decision.source is None


def test_yes_rule_authorizes_directly():
    eng = loaded("yes")
    auth = eng.authorize("alice", ACTION, now=NOW)
    assert auth.granted is True
    assert auth.source == "admin"
    assert auth.expires_at == "2026-11-26T09:10:00+00:00"


def test_no_rule_denies_authorize():
    eng = loaded("no")
    with pytest.raises(pk.PolicyError) as exc:
        eng.authorize("alice", ACTION, now=NOW)
    assert exc.value.code == "POLICY_DENIED"
    assert eng.stats()["denied"] == 1


def test_auth_rule_requires_challenge():
    eng = loaded("auth_self")
    with pytest.raises(pk.PolicyError) as exc:
        eng.authorize("alice", ACTION, now=NOW)
    assert exc.value.code == "POLICY_AUTH_REQUIRED"


def test_challenge_completion_grants_authorization():
    eng = loaded("auth_self")
    challenge = eng.challenge("alice", ACTION, now=NOW)
    assert challenge.user == "alice"
    assert challenge.action == ACTION
    assert challenge.attempts == 0
    assert challenge.rule_version == 1
    assert challenge.expires_at == "2026-11-26T09:05:00+00:00"
    auth = eng.complete(challenge.challenge_id, proof_ok=True, now=LATER)
    assert auth.granted is True
    assert auth.source == "admin"
    again = eng.authorize("alice", ACTION, now=LATER)
    assert again.granted is True


def test_repeat_completion_is_idempotent():
    eng = loaded("auth_self")
    challenge = eng.challenge("alice", ACTION, now=NOW)
    first = eng.complete(challenge.challenge_id, proof_ok=True, now=LATER)
    second = eng.complete(challenge.challenge_id, proof_ok=True, now=LATER)
    assert second == first
    assert eng.stats()["completed"] == 1


def test_expired_challenge_rejected():
    eng = loaded("auth_self")
    challenge = eng.challenge("alice", ACTION, now=NOW)
    with pytest.raises(pk.PolicyError) as exc:
        eng.complete(challenge.challenge_id, proof_ok=True, now=EXPIRED)
    assert exc.value.code == "POLICY_CHALLENGE_EXPIRED"


def test_failed_attempts_enter_cooldown():
    eng = loaded("auth_self")
    challenge = eng.challenge("alice", ACTION, now=NOW)
    for _ in range(2):
        with pytest.raises(pk.PolicyError) as bad:
            eng.complete(challenge.challenge_id, proof_ok=False, now=LATER)
        assert bad.value.code == "POLICY_BAD_CREDENTIALS"
    with pytest.raises(pk.PolicyError) as cold:
        eng.complete(challenge.challenge_id, proof_ok=False, now=LATER)
    assert cold.value.code == "POLICY_COOLDOWN"
    with pytest.raises(pk.PolicyError) as blocked:
        eng.challenge("alice", ACTION, now=LATER)
    assert blocked.value.code == "POLICY_COOLDOWN"


def test_revoke_drops_active_authorization():
    eng = loaded("auth_self")
    challenge = eng.challenge("alice", ACTION, now=NOW)
    eng.complete(challenge.challenge_id, proof_ok=True, now=LATER)
    assert eng.authorize("alice", ACTION, now=LATER).granted is True
    assert eng.revoke("alice", ACTION) == 1
    with pytest.raises(pk.PolicyError) as exc:
        eng.authorize("alice", ACTION, now=LATER)
    assert exc.value.code == "POLICY_AUTH_REQUIRED"
    assert eng.stats()["revoked"] == 1


def test_rule_reload_bumps_version_and_drops_cache():
    eng = engine()
    eng.register_action(ACTION)
    assert eng.load_rules([rule("yes")], now=NOW) == 1
    first = eng.evaluate("alice", ACTION, now=NOW)
    assert first.result == "yes"
    assert first.cached is False
    assert eng.evaluate("alice", ACTION, now=NOW).cached is True
    assert eng.load_rules([rule("no")], now=LATER) == 2
    fresh = eng.evaluate("alice", ACTION, now=LATER)
    assert fresh.result == "no"
    assert fresh.cached is False


def test_snapshot_roundtrip_and_invalid_state():
    eng = loaded("auth_self")
    challenge = eng.challenge("alice", ACTION, now=NOW)
    state = eng.snapshot()
    clone = engine()
    clone.restore(state)
    assert clone.stats()["rules_version"] == 1
    assert [c.challenge_id for c in clone.active_challenges()] == [challenge.challenge_id]
    with pytest.raises(pk.PolicyError) as exc:
        clone.restore({"bogus": True})
    assert exc.value.code == "POLICY_SNAPSHOT_INVALID"
    assert clone.stats()["rules_version"] == 1
