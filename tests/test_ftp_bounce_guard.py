import copy

import pytest

import ftp_bounce_guard as fb

PEER = "203.0.113.9"


def guard(**kwargs):
    params = dict(
        control_peer=PEER,
        pasv_port_range=(40000, 40005),
        max_line=512,
    )
    params.update(kwargs)
    return fb.FtpBounceGuard(**params)


def authed(**kwargs):
    session = guard(**kwargs)
    assert session.authenticate("ftpuser", "s3cret") is True
    return session


def test_feed_buffers_partial_command_until_newline():
    session = authed()
    assert session.feed(b"NO") == []
    out = session.feed(b"OP\r\n")
    assert [reply.code for reply in out] == [200]
    assert session.stats()["commands"] == 1


def test_overlong_command_is_rejected_and_counted():
    session = authed()
    out = session.feed(b"X" * 600 + b"\r\n")
    assert [reply.code for reply in out] == [500]
    assert session.stats()["line_too_long"] == 1


def test_data_command_before_login_is_refused():
    session = guard()
    reply = session.on_command("PASV")
    assert reply.code == 530
    assert session.pending_data() is None


def test_user_and_pass_commands_authenticate_session():
    session = guard()
    assert session.on_command("USER ftpuser").code == 331
    assert session.on_command("PASS s3cret").code == 230
    assert session.on_command("PASV").code == 227


def test_wrong_password_leaves_session_unauthenticated():
    session = guard()
    session.on_command("USER ftpuser")
    assert session.on_command("PASS wrong").code == 530
    assert session.on_command("PORT 203,0,113,9,0,20").code == 530
    assert session.authenticate("ftpuser", "s3cret") is True


def test_port_to_foreign_host_is_refused_and_channel_stays_usable():
    session = authed()
    reply = session.on_command("PORT 198,51,100,7,10,20")
    assert reply.code == 501
    assert session.pending_data() is None
    assert session.on_command("NOOP").code == 200
    assert session.stats()["rejected"] == 1


def test_port_to_control_peer_is_accepted():
    session = authed()
    reply = session.on_command("PORT 203,0,113,9,0,20")
    assert reply.code == 200
    target = session.pending_data()
    assert (target.ip, target.port, target.mode) == (PEER, 20, "active")


def test_eprt_ipv4_to_control_peer_is_accepted():
    session = authed()
    assert session.on_command("EPRT |1|203.0.113.9|20|").code == 200
    assert session.pending_data().ip == PEER


def test_second_data_command_while_pending_is_refused():
    session = authed()
    session.on_command("PORT 203,0,113,9,0,20")
    reply = session.on_command("PASV")
    assert reply.code == 503
    assert session.stats()["pending_rejected"] == 1


def test_authorize_data_rejects_unexpected_peer():
    session = authed()
    session.on_command("PORT 203,0,113,9,0,20")
    with pytest.raises(fb.FtpGuardError) as exc:
        session.authorize_data("198.51.100.7", 20)
    assert exc.value.code == "FTP_DATA_PEER_MISMATCH"
    target = session.authorize_data(PEER, 20)
    assert target.port == 20


def test_epsv_allocates_port_inside_configured_range():
    session = authed()
    reply = session.on_command("EPSV")
    assert reply.code == 229
    target = session.pending_data()
    assert target.mode == "passive"
    assert 40000 <= target.port <= 40005


def test_rewrite_pasv_maps_private_advertised_address():
    session = authed()
    ip, port = session.rewrite_pasv("192.168.10.20", 40003)
    assert (ip, port) == (PEER, 40003)
    assert session.stats()["rewritten"] == 1


def test_rewrite_pasv_keeps_public_address_and_enforces_port_range():
    session = authed()
    assert session.rewrite_pasv("198.51.100.20", 40003) == ("198.51.100.20", 40003)
    with pytest.raises(fb.FtpGuardError) as exc:
        session.rewrite_pasv("198.51.100.20", 39999)
    assert exc.value.code == "FTP_PASV_PORT_RANGE"


def test_snapshot_is_detached_and_restore_roundtrips():
    session = authed()
    session.on_command("EPRT |1|203.0.113.9|20|")
    state = session.snapshot()
    pristine = copy.deepcopy(state)
    assert set(pristine) == {
        "version", "authenticated", "user", "buffer", "pending",
        "counters", "closed",
    }
    state["pending"] = None
    state["counters"]["commands"] = 99
    assert session.pending_data() is not None
    assert session.stats()["commands"] == 1

    clone = guard()
    clone.restore(pristine)
    assert clone.pending_data().ip == PEER
    assert clone.on_command("NOOP").code == 200


def test_close_drops_pending_and_refuses_further_commands():
    session = authed()
    session.on_command("PASV")
    session.close()
    assert session.pending_data() is None
    assert session.on_command("NOOP").code == 421
    assert session.authenticate("ftpuser", "s3cret") is False
