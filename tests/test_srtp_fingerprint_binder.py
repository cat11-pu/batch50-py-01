import copy
import hashlib

import pytest

import srtp_fingerprint_binder as sf

CERT_A = b"certificate-alpha"
CERT_B = b"certificate-bravo"


def fingerprint(algorithm, cert_der):
    digest = hashlib.new(algorithm, cert_der).hexdigest().upper()
    return ":".join(digest[index:index + 2] for index in range(0, len(digest), 2))


def section(mid="audio", media="audio", port=49170,
            protocol="UDP/TLS/RTP/SAVPF",
            algorithm="sha-256", value=None, setup="actpass"):
    lines = [
        f"m={media} {port} {protocol} 111",
        f"a=mid:{mid}",
    ]
    if algorithm is not None:
        lines.append(f"a=fingerprint:{algorithm} {value}")
    if setup is not None:
        lines.append(f"a=setup:{setup}")
    return lines


def sdp(*sections):
    lines = ["v=0", "o=- 1 1 IN IP4 127.0.0.1", "s=-", "t=0 0"]
    for item in sections:
        lines.extend(item)
    return "\r\n".join(lines) + "\r\n"


def test_parse_sdp_extracts_media_attributes():
    binder = sf.SrtpFingerprintBinder()
    parsed = binder.parse_sdp(sdp(section(algorithm="SHA-256", value="AB:CD:EF")))
    assert len(parsed) == 1
    item = parsed[0]
    assert (item.mid, item.media, item.port, item.protocol) == (
        "audio", "audio", 49170, "UDP/TLS/RTP/SAVPF",
    )
    assert item.fingerprint_algorithm == "sha-256"
    assert item.fingerprint_value == "AB:CD:EF"
    assert item.setup == "actpass"


def test_parse_sdp_rejects_section_without_mid():
    binder = sf.SrtpFingerprintBinder()
    text = sdp([
        "m=audio 49170 UDP/TLS/RTP/SAVPF 111",
        "a=fingerprint:sha-256 AB:CD",
    ])
    with pytest.raises(sf.SrtpError) as exc:
        binder.parse_sdp(text)
    assert exc.value.code == "SRTP_INVALID_SDP"


def test_bind_offer_creates_one_binding_per_media_section():
    binder = sf.SrtpFingerprintBinder()
    audio_fp = fingerprint("sha-256", CERT_A)
    video_fp = fingerprint("sha-256", CERT_B)
    result = binder.bind_offer(sdp(
        section(value=audio_fp),
        section(mid="video", media="video", port=49172, value=video_fp),
    ))
    assert sorted(result) == ["audio", "video"]
    assert result["audio"].context_id < result["video"].context_id
    assert result["audio"].algorithm == "sha-256"
    assert result["audio"].fingerprint == audio_fp
    assert result["audio"].verified is False


def test_bind_offer_requires_fingerprint_attribute():
    binder = sf.SrtpFingerprintBinder()
    with pytest.raises(sf.SrtpError) as exc:
        binder.bind_offer(sdp(
            section(algorithm=None, value=None),
            section(mid="video", media="video", algorithm=None, value=None),
        ))
    assert exc.value.code == "SRTP_FINGERPRINT_MISSING"


def test_bind_offer_rejects_algorithm_outside_allowlist():
    binder = sf.SrtpFingerprintBinder(allowed_algorithms=("sha-384", "sha-512"))
    offer = sdp(section(value=fingerprint("sha-256", CERT_A)))
    with pytest.raises(sf.SrtpError) as exc:
        binder.bind_offer(offer)
    assert exc.value.code == "SRTP_ALGORITHM_NOT_ALLOWED"


def test_bind_offer_rejects_fingerprint_with_wrong_length():
    binder = sf.SrtpFingerprintBinder()
    with pytest.raises(sf.SrtpError) as exc:
        binder.bind_offer(sdp(section(value="AB:CD:EF:01")))
    assert exc.value.code == "SRTP_FINGERPRINT_INVALID"


def test_accept_answer_requires_matching_media_set():
    binder = sf.SrtpFingerprintBinder()
    audio_fp = fingerprint("sha-256", CERT_A)
    video_fp = fingerprint("sha-256", CERT_B)
    binder.bind_offer(sdp(
        section(value=audio_fp),
        section(mid="video", media="video", port=49172, value=video_fp),
    ))
    with pytest.raises(sf.SrtpError) as exc:
        binder.accept_answer(sdp(section(value=audio_fp, setup="active")))
    assert exc.value.code == "SRTP_SDP_MISMATCH"


def test_accept_answer_records_local_role():
    binder = sf.SrtpFingerprintBinder()
    offer_fp = fingerprint("sha-256", CERT_A)
    answer_fp = fingerprint("sha-256", CERT_B)
    binder.bind_offer(sdp(section(value=offer_fp)))
    result = binder.accept_answer(sdp(section(value=answer_fp, setup="active")))
    assert list(result) == ["audio"]
    assert result["audio"].role == "active"


def test_verify_peer_accepts_matching_certificate():
    binder = sf.SrtpFingerprintBinder()
    offer_fp = fingerprint("sha-256", CERT_A)
    binder.bind_offer(sdp(section(value=offer_fp)))
    assert binder.verify_peer("audio", CERT_A) is True
    assert binder.bindings()[0].verified is True
    assert binder.stats()["verified"] == 1


def test_verify_peer_rejects_mismatched_certificate():
    binder = sf.SrtpFingerprintBinder()
    binder.bind_offer(sdp(section(value=fingerprint("sha-256", CERT_A))))
    with pytest.raises(sf.SrtpError) as exc:
        binder.verify_peer("audio", CERT_B)
    assert exc.value.code == "SRTP_FINGERPRINT_MISMATCH"
    assert binder.stats()["rejected"] == 1


def test_rejected_segment_refuses_key_material():
    binder = sf.SrtpFingerprintBinder()
    binder.bind_offer(sdp(section(value=fingerprint("sha-256", CERT_A))))
    with pytest.raises(sf.SrtpError):
        binder.verify_peer("audio", CERT_B)
    with pytest.raises(sf.SrtpError) as exc:
        binder.key_material("audio")
    assert exc.value.code == "SRTP_SEGMENT_REJECTED"


def test_renegotiate_adds_new_media_section():
    binder = sf.SrtpFingerprintBinder()
    audio_fp = fingerprint("sha-256", CERT_A)
    video_fp = fingerprint("sha-256", CERT_B)
    binder.bind_offer(sdp(section(value=audio_fp)))
    result = binder.renegotiate(sdp(
        section(value=audio_fp),
        section(mid="video", media="video", port=49172, value=video_fp),
    ))
    assert result["added"] == ("video",)
    assert result["removed"] == ()
    assert [item.mid for item in binder.bindings()] == ["audio", "video"]


def test_renegotiate_removes_dropped_media_section():
    binder = sf.SrtpFingerprintBinder()
    audio_fp = fingerprint("sha-256", CERT_A)
    video_fp = fingerprint("sha-256", CERT_B)
    binder.bind_offer(sdp(
        section(value=audio_fp),
        section(mid="video", media="video", port=49172, value=video_fp),
    ))
    result = binder.renegotiate(sdp(section(value=audio_fp)))
    assert result["removed"] == ("video",)
    assert [item.mid for item in binder.bindings()] == ["audio"]


def test_binding_capacity_is_enforced():
    binder = sf.SrtpFingerprintBinder(max_bindings=1)
    audio_fp = fingerprint("sha-256", CERT_A)
    video_fp = fingerprint("sha-256", CERT_B)
    with pytest.raises(sf.SrtpError) as exc:
        binder.bind_offer(sdp(
            section(value=audio_fp),
            section(mid="video", media="video", port=49172, value=video_fp),
        ))
    assert exc.value.code == "SRTP_BINDING_CAPACITY"
    assert binder.bindings() == ()


def test_snapshot_is_detached_and_restore_roundtrips():
    binder = sf.SrtpFingerprintBinder()
    binder.bind_offer(sdp(section(value=fingerprint("sha-256", CERT_A))))
    assert binder.verify_peer("audio", CERT_A) is True
    state = binder.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {"version", "bindings", "counters"}

    state["bindings"].clear()
    state["counters"]["verified"] = 99
    assert len(binder.bindings()) == 1
    assert binder.stats()["verified"] == 1

    clone = sf.SrtpFingerprintBinder()
    clone.restore(pristine)
    assert len(clone.bindings()) == 1
    assert clone.stats()["verified"] == 1
    assert clone.verify_peer("audio", CERT_A) is True
