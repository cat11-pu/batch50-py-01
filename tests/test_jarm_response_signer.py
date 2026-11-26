import base64
import copy
import json
import threading
from datetime import datetime

import pytest

import jarm_response_signer as js

NOW = "2026-11-26T09:00:00+00:00"
SOON = "2026-11-26T09:01:00+00:00"
LATER = "2026-11-26T09:06:00+00:00"
ISS = "https://idp.example"
K1_SECRET = "k1-secret-material"
K2_SECRET = "k2-secret-material"


def signer(**kwargs):
    return js.JarmResponseSigner(**kwargs)


def ready(**kwargs):
    s = signer(**kwargs)
    s.register_client("rp-1", tenant="t1", algorithms=["RS256"], kid="k1",
                      secret=K1_SECRET, now=NOW)
    return s


def epoch(ts):
    return int(datetime.fromisoformat(ts).timestamp())


def decode(segment):
    padded = segment + "=" * (-len(segment) % 4)
    return json.loads(base64.urlsafe_b64decode(padded))


def encode(payload):
    raw = json.dumps(payload, separators=(",", ":")).encode("utf-8")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def test_register_client_normalizes_algorithms():
    s = signer()
    keys = s.register_client("rp-1", tenant="t1",
                             algorithms=["hs512", "HS256", "HS512"],
                             kid="k1", secret=K1_SECRET, now=NOW)
    assert keys.client_id == "rp-1"
    assert keys.tenant == "t1"
    assert keys.algorithms == ("HS512", "HS256")
    assert keys.version == 1
    assert keys.active_kid == "k1"
    assert keys.kids == ("k1",)
    assert s.client_keys("rp-1") == keys
    with pytest.raises(js.JarmError) as exc:
        s.register_client("rp-1", tenant="t1", algorithms=["HS256"], kid="k2",
                          secret="dup-secret", now=NOW)
    assert exc.value.code == "JARM_INVALID_REQUEST"
    with pytest.raises(js.JarmError) as exc:
        s.register_client("rp-2", tenant="t1", algorithms=["md5"], kid="k9",
                          secret="x", now=NOW)
    assert exc.value.code == "JARM_INVALID_REQUEST"
    with pytest.raises(js.JarmError) as exc:
        s.client_keys("rp-9")
    assert exc.value.code == "JARM_UNKNOWN_CLIENT"


def test_register_client_rejects_blank_fields():
    s = signer()
    bad = [
        dict(client_id="", tenant="t1", kid="k1"),
        dict(client_id="rp-1", tenant=" ", kid="k1"),
        dict(client_id="rp-1", tenant="t1", kid=""),
        dict(client_id="rp-1", tenant="t1", kid="k1", algorithms=[]),
        dict(client_id="rp-1", tenant="t1", kid="k1", secret=""),
    ]
    for kwargs in bad:
        kwargs.setdefault("algorithms", ["HS256"])
        kwargs.setdefault("secret", K1_SECRET)
        with pytest.raises(js.JarmError) as exc:
            s.register_client(now=NOW, **kwargs)
        assert exc.value.code == "JARM_INVALID_REQUEST"
    assert s.stats()["clients"] == 0


def test_rotate_client_key_bumps_version_and_keeps_previous_kid():
    s = ready()
    keys = s.rotate_client_key("rp-1", kid="k2", secret=K2_SECRET, now=SOON)
    assert keys.version == 2
    assert keys.active_kid == "k2"
    assert keys.kids == ("k1", "k2")
    with pytest.raises(js.JarmError) as exc:
        s.rotate_client_key("rp-1", kid="k2", secret="dup-secret", now=SOON)
    assert exc.value.code == "JARM_INVALID_REQUEST"
    with pytest.raises(js.JarmError) as exc:
        s.rotate_client_key("rp-9", kid="k3", secret="x", now=SOON)
    assert exc.value.code == "JARM_UNKNOWN_CLIENT"


def test_sign_emits_three_part_token_with_expected_claims():
    s = ready()
    signed = s.sign("rp-1", state="st-1", iss=ISS, aud="rp-1", now=NOW)
    assert signed.client_id == "rp-1"
    assert signed.state == "st-1"
    assert signed.kid == "k1"
    assert signed.alg == "RS256"
    parts = signed.token.split(".")
    assert len(parts) == 3
    assert all(parts)
    header = decode(parts[0])
    payload = decode(parts[1])
    assert header == {"alg": "RS256", "kid": "k1", "typ": "JARM"}
    assert payload["iss"] == ISS
    assert payload["aud"] == "rp-1"
    assert payload["state"] == "st-1"
    assert payload["iat"] == epoch(NOW)
    assert payload["exp"] == epoch(NOW) + 300
    assert signed.header == header
    assert signed.payload == payload
    assert s.stats()["signed"] == 1
    with pytest.raises(js.JarmError) as exc:
        s.sign("rp-1", state="st-1", iss=ISS, aud="rp-1", now=SOON)
    assert exc.value.code == "JARM_STATE_DUPLICATE"
    assert s.state_status("st-1") == "open"
    assert s.stats()["signed"] == 1


def test_sign_merges_claims_and_rejects_reserved_override():
    s = ready()
    signed = s.sign("rp-1", state="st-1", iss=ISS, aud="rp-1",
                    claims={"scope": "openid", "auth_time": 90}, now=NOW)
    payload = decode(signed.token.split(".")[1])
    assert payload["scope"] == "openid"
    assert payload["auth_time"] == 90
    with pytest.raises(js.JarmError) as exc:
        s.sign("rp-1", state="st-2", iss=ISS, aud="rp-1",
               claims={"exp": 1}, now=NOW)
    assert exc.value.code == "JARM_INVALID_REQUEST"
    assert s.state_status("st-2") == "unknown"
    assert s.stats()["signed"] == 1
    with pytest.raises(js.JarmError) as exc:
        s.sign("rp-1", state="", iss=ISS, aud="rp-1", now=NOW)
    assert exc.value.code == "JARM_INVALID_REQUEST"
    with pytest.raises(js.JarmError) as exc:
        s.sign("rp-9", state="st-3", iss=ISS, aud="rp-1", now=NOW)
    assert exc.value.code == "JARM_UNKNOWN_CLIENT"


def test_verify_accepts_freshly_signed_token():
    s = ready()
    signed = s.sign("rp-1", state="st-1", iss=ISS, aud="rp-1",
                    claims={"scope": "openid"}, now=NOW)
    verified = s.verify("rp-1", signed.token, expected_aud="rp-1",
                        expected_iss=ISS, now=SOON)
    assert verified.client_id == "rp-1"
    assert verified.state == "st-1"
    assert verified.kid == "k1"
    assert verified.alg == "RS256"
    assert verified.claims["scope"] == "openid"
    assert verified.claims["aud"] == "rp-1"
    assert s.stats()["verified"] == 1


def test_verify_rejects_tampered_payload():
    s = ready()
    signed = s.sign("rp-1", state="st-1", iss=ISS, aud="rp-1", now=NOW)
    head, payload, signature = signed.token.split(".")
    claims = decode(payload)
    claims["aud"] = "attacker"
    forged = ".".join([head, encode(claims), signature])
    with pytest.raises(js.JarmError) as exc:
        s.verify("rp-1", forged, expected_aud="rp-1", now=SOON)
    assert exc.value.code == "JARM_SIGNATURE_INVALID"
    with pytest.raises(js.JarmError) as exc:
        s.verify("rp-1", "not-a-token", now=SOON)
    assert exc.value.code == "JARM_RESPONSE_MALFORMED"


def test_verify_rejects_expired_response():
    s = ready()
    signed = s.sign("rp-1", state="st-1", iss=ISS, aud="rp-1", ttl=30, now=NOW)
    with pytest.raises(js.JarmError) as exc:
        s.verify("rp-1", signed.token, expected_aud="rp-1", now=LATER)
    assert exc.value.code == "JARM_RESPONSE_EXPIRED"


def test_verify_rejects_audience_and_issuer_mismatch():
    s = ready()
    signed = s.sign("rp-1", state="st-1", iss=ISS, aud="rp-1", now=NOW)
    with pytest.raises(js.JarmError) as exc:
        s.verify("rp-1", signed.token, expected_aud="rp-2", now=SOON)
    assert exc.value.code == "JARM_AUDIENCE_MISMATCH"
    with pytest.raises(js.JarmError) as exc:
        s.verify("rp-1", signed.token, expected_iss="https://other.example", now=SOON)
    assert exc.value.code == "JARM_ISSUER_MISMATCH"


def test_token_signed_before_rotation_verifies_until_kid_revoked():
    s = ready()
    old = s.sign("rp-1", state="st-old", iss=ISS, aud="rp-1", now=NOW)
    keys = s.rotate_client_key("rp-1", kid="k2", secret=K2_SECRET, now=SOON)
    assert keys.version == 2
    assert keys.active_kid == "k2"
    assert keys.kids == ("k1", "k2")
    fresh = s.sign("rp-1", state="st-new", iss=ISS, aud="rp-1", now=SOON)
    assert fresh.kid == "k2"
    verified = s.verify("rp-1", old.token, expected_aud="rp-1", now=SOON)
    assert verified.kid == "k1"
    with pytest.raises(js.JarmError) as exc:
        s.revoke_key("rp-1", "k2")
    assert exc.value.code == "JARM_INVALID_REQUEST"
    assert s.revoke_key("rp-1", "k1") is True
    assert s.revoke_key("rp-1", "k1") is False
    assert "k1" not in s.client_keys("rp-1").kids
    with pytest.raises(js.JarmError) as exc:
        s.verify("rp-1", old.token, expected_aud="rp-1", now=SOON)
    assert exc.value.code == "JARM_UNKNOWN_KEY"


def test_redeem_state_marks_state_redeemed():
    s = ready()
    s.register_client("rp-2", tenant="t2", algorithms=["HS256"], kid="k8",
                      secret="rp2-secret", now=NOW)
    s.sign("rp-1", state="st-1", iss=ISS, aud="rp-1", now=NOW)
    assert s.state_status("st-1") == "open"
    assert s.redeem_state("rp-1", "st-1", now=SOON) == "redeemed"
    assert s.state_status("st-1") == "redeemed"
    assert s.stats()["redeemed"] == 1
    with pytest.raises(js.JarmError) as exc:
        s.redeem_state("rp-1", "st-404", now=SOON)
    assert exc.value.code == "JARM_UNKNOWN_STATE"
    with pytest.raises(js.JarmError) as exc:
        s.redeem_state("rp-2", "st-1", now=SOON)
    assert exc.value.code == "JARM_UNKNOWN_STATE"


def test_compensate_reissues_open_state_with_same_key():
    s = ready()
    signed = s.sign("rp-1", state="st-1", iss=ISS, aud="rp-1", ttl=120, now=NOW)
    again = s.compensate("rp-1", state="st-1", now=SOON)
    assert again.state == "st-1"
    assert again.kid == signed.kid == "k1"
    assert again.alg == signed.alg
    assert decode(again.token.split(".")[1])["iat"] == epoch(SOON)
    verified = s.verify("rp-1", again.token, expected_aud="rp-1", now=SOON)
    assert verified.state == "st-1"
    assert s.stats()["compensated"] == 1
    with pytest.raises(js.JarmError) as exc:
        s.compensate("rp-1", state="st-404", now=SOON)
    assert exc.value.code == "JARM_UNKNOWN_STATE"


def test_concurrent_redeem_has_single_winner():
    s = ready()
    s.sign("rp-1", state="st-1", iss=ISS, aud="rp-1", now=NOW)
    wins = []
    failures = []
    barrier = threading.Barrier(12)

    def worker():
        try:
            barrier.wait(timeout=5)
            wins.append(s.redeem_state("rp-1", "st-1", now=SOON))
        except Exception as exc:  # noqa: BLE001 - reported through failures
            failures.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(wins) + len(failures) == 12
    assert wins == ["redeemed"]
    assert s.stats()["redeemed"] == 1


def test_sweep_expired_marks_open_states_and_blocks_compensation():
    s = ready()
    s.sign("rp-1", state="st-1", iss=ISS, aud="rp-1", ttl=30, now=NOW)
    s.sign("rp-1", state="st-2", iss=ISS, aud="rp-1", ttl=600, now=NOW)
    assert s.sweep_expired(now=NOW) == 0
    assert s.sweep_expired(now=SOON) == 1
    assert s.state_status("st-1") == "expired"
    assert s.state_status("st-2") == "open"
    assert s.sweep_expired(now=SOON) == 0
    with pytest.raises(js.JarmError) as exc:
        s.compensate("rp-1", state="st-1", now=SOON)
    assert exc.value.code == "JARM_STATE_EXPIRED"
    assert s.stats()["swept"] == 1


def test_snapshot_roundtrip_and_malformed_rejection():
    s = ready()
    signed = s.sign("rp-1", state="st-1", iss=ISS, aud="rp-1", now=NOW)
    s.sign("rp-1", state="st-2", iss=ISS, aud="rp-1", now=NOW)
    s.redeem_state("rp-1", "st-1", now=SOON)
    state = s.snapshot()
    assert set(state) == {"version", "clients", "states", "stats"}
    pristine = copy.deepcopy(state)
    state["stats"]["signed"] = 99
    state["states"].clear()
    assert s.stats()["signed"] == 2
    assert s.state_status("st-1") == "redeemed"

    clone = signer()
    clone.restore(pristine)
    assert clone.stats()["signed"] == 2
    assert clone.state_status("st-1") == "redeemed"
    assert clone.state_status("st-2") == "open"
    assert clone.client_keys("rp-1").active_kid == "k1"
    restored = clone.verify("rp-1", signed.token, expected_aud="rp-1", now=SOON)
    assert restored.state == "st-1"

    bad_snapshots = [
        None,
        {},
        {"version": 9, "clients": [], "states": [], "stats": {}},
        {"version": 1, "clients": {}, "states": [], "stats": {}},
        {"version": 1, "clients": [], "states": "no", "stats": {}},
    ]
    for snapshot in bad_snapshots:
        with pytest.raises(js.JarmError) as exc:
            clone.restore(snapshot)
        assert exc.value.code == "JARM_SNAPSHOT_INVALID"
    assert clone.state_status("st-1") == "redeemed"
