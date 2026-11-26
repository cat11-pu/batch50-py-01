import hashlib
from pathlib import Path

import pytest

import tty_injection_guard as tig


def guard(record_dir, **kwargs):
    return tig.TtyInjectionGuard(record_dir, **kwargs)


def test_ioctl_blocks_sti_and_tioclinux(tmp_path):
    g = guard(tmp_path)
    sti = g.on_ioctl("pts/1", 0x5412)
    tioclinux = g.on_ioctl("pts/1", 0x541C)
    termios = g.on_ioctl("pts/1", 0x5401)
    assert (sti.allowed, sti.code, sti.request) == (False, "IOCTL_BLOCKED_TIOCSTI", 0x5412)
    assert (tioclinux.allowed, tioclinux.code) == (False, "IOCTL_BLOCKED_TIOCLINUX")
    assert (termios.allowed, termios.code) == (True, "IOCTL_ALLOWED")
    assert g.stats()["ioctl_calls"] == 3
    assert g.stats()["ioctl_blocked"] == 2


def test_ioctl_keeps_counters_for_allowed_requests(tmp_path):
    g = guard(tmp_path)
    for request in (0x5401, 0x5402, 0x5403):
        verdict = g.on_ioctl("pts/2", request)
        assert verdict.allowed is True
        assert verdict.code == "IOCTL_ALLOWED"
    assert g.stats()["ioctl_calls"] == 3
    assert g.stats()["ioctl_blocked"] == 0
    assert g.stats()["chunks_filtered"] == 0


def test_filter_drops_whole_osc52_sequence(tmp_path):
    g = guard(tmp_path)
    raw = "x" + "\x1b]52;c;cGF5bG9hZA==" + "\x07" + "y"
    verdict = g.filter_output("pts/1", raw)
    assert verdict.emitted == "xy"
    assert verdict.pending == ""
    assert verdict.blocked == ("osc52",)
    assert g.stats()["sequences_blocked"] == 1
    assert g.stats()["bytes_blocked"] == len("\x1b]52;c;cGF5bG9hZA==\x07")


def test_filter_blocks_private_cursor_mode(tmp_path):
    g = guard(tmp_path)
    verdict = g.filter_output("pts/1", "\x1b[?25lforged prompt")
    assert verdict.emitted == "forged prompt"
    assert verdict.blocked == ("csi?25",)
    keep = g.filter_output("pts/1", "\x1b[?1049h")
    assert keep.emitted == "\x1b[?1049h"
    assert keep.blocked == ()


def test_filter_carries_partial_escape_across_chunks(tmp_path):
    g = guard(tmp_path)
    first = g.filter_output("pts/1", "red\x1b[31")
    assert first.emitted == "red"
    assert first.pending == "\x1b[31"
    second = g.filter_output("pts/1", "mred\x1b[0m")
    assert second.emitted == "\x1b[31mred\x1b[0m"
    assert second.pending == ""
    assert g.stats()["chunks_filtered"] == 2
    assert g.stats()["sequences_blocked"] == 0


def test_filter_passes_plain_text(tmp_path):
    g = guard(tmp_path)
    verdict = g.filter_output("pts/1", "plain text\n")
    assert (verdict.emitted, verdict.pending, verdict.blocked) == ("plain text\n", "", ())
    assert g.stats()["chunks_filtered"] == 1
    assert g.stats()["bytes_blocked"] == 0


def test_record_writes_segment_file(tmp_path):
    g = guard(tmp_path)
    g.open_session("pts/3", "s1")
    opened = g.record("pts/3", b"hello")
    g.record("pts/3", "world")
    assert (opened.tty, opened.session, opened.seq) == ("pts/3", "s1", 1)
    assert opened.status == "open"
    assert opened.bytes_written == 5
    rows = g.segments("pts/3")
    assert len(rows) == 1
    assert rows[0].bytes_written == 10
    assert Path(rows[0].path).read_bytes() == b"helloworld"
    assert g.stats()["segments_opened"] == 1


def test_flush_seals_segment_with_digest(tmp_path):
    g = guard(tmp_path)
    g.open_session("pts/3", "s1")
    g.record("pts/3", b"hello")
    sealed = g.flush("pts/3")
    assert sealed.status == "complete"
    assert sealed.bytes_written == 5
    assert sealed.sha256 == hashlib.sha256(b"hello").hexdigest()
    assert g.flush("pts/3") is None
    assert g.segments("pts/3")[0].status == "complete"
    assert g.stats()["segments_closed"] == 1


def test_record_after_flush_starts_next_segment(tmp_path):
    g = guard(tmp_path)
    g.open_session("pts/3", "s1")
    g.record("pts/3", b"one")
    g.flush("pts/3")
    second = g.record("pts/3", b"two")
    assert second.seq == 2
    assert second.status == "open"
    assert second.bytes_written == 3
    assert [row.seq for row in g.segments("pts/3")] == [1, 2]
    assert [row.status for row in g.segments("pts/3")] == ["complete", "open"]


def test_record_rejects_chunk_over_segment_limit(tmp_path):
    g = guard(tmp_path, max_segment_bytes=8)
    g.open_session("pts/3", "s1")
    g.record("pts/3", b"12345")
    with pytest.raises(tig.TtyGuardError) as exc:
        g.record("pts/3", b"6789")
    assert exc.value.code == "TTY_SEGMENT_TOO_LARGE"
    rows = g.segments("pts/3")
    assert rows[0].bytes_written == 5
    assert Path(rows[0].path).read_bytes() == b"12345"
    assert g.record("pts/3", b"678").bytes_written == 8


def test_close_releases_owner_and_blocks_further_record(tmp_path):
    g = guard(tmp_path)
    g.open_session("pts/3", "s1")
    g.record("pts/3", b"x")
    closed = g.close("pts/3")
    assert closed.status == "complete"
    assert g.status("pts/3")["owner"] is None
    with pytest.raises(tig.TtyGuardError) as exc:
        g.record("pts/3", b"y")
    assert exc.value.code == "TTY_SESSION_CLOSED"
    assert g.close("pts/3") is None
    assert len(g.segments("pts/3")) == 1


def test_update_rules_hot_swap_is_atomic(tmp_path):
    g = guard(tmp_path)
    g.update_rules(blocked_osc=(8,), blocked_private_modes=())
    passthrough = g.filter_output("pts/1", "\x1b]52;c;ZGF0YQ==\x07ok")
    assert passthrough.emitted == "\x1b]52;c;ZGF0YQ==\x07ok"
    assert passthrough.blocked == ()
    blocked = g.filter_output("pts/1", "\x1b]8;;http://bad\x07click")
    assert blocked.emitted == "click"
    assert blocked.blocked == ("osc8",)
    with pytest.raises(tig.TtyGuardError) as exc:
        g.update_rules(blocked_osc=("52",))
    assert exc.value.code == "TTY_RULE_INVALID"
    still_blocked = g.filter_output("pts/1", "\x1b]8;;http://bad\x07again")
    assert still_blocked.emitted == "again"
    assert still_blocked.blocked == ("osc8",)
    cursor = g.filter_output("pts/1", "\x1b[?25lvisible")
    assert cursor.emitted == "\x1b[?25lvisible"
    assert cursor.blocked == ()


def test_recover_seals_unfinished_segment(tmp_path):
    first = guard(tmp_path)
    first.open_session("pts/9", "s9")
    first.record("pts/9", b"partial")
    second = guard(tmp_path)
    assert second.recover() == 1
    rows = second.segments("pts/9")
    assert len(rows) == 1
    assert rows[0].status == "incomplete"
    assert rows[0].bytes_written == 7
    assert rows[0].sha256 == hashlib.sha256(b"partial").hexdigest()
    assert second.stats()["recovered"] == 1
    assert second.recover() == 0
    assert second.segments("pts/9")[0].status == "incomplete"


def test_filter_rejects_non_text_chunk(tmp_path):
    g = guard(tmp_path)
    with pytest.raises(tig.TtyGuardError) as exc:
        g.filter_output("pts/1", b"bytes")
    assert exc.value.code == "TTY_INVALID_CHUNK"
    assert g.stats()["chunks_filtered"] == 0
    assert g.stats()["bytes_blocked"] == 0


def test_stats_track_lifecycle(tmp_path):
    g = guard(tmp_path)
    g.on_ioctl("pts/1", 0x5412)
    g.filter_output("pts/1", "a\x1b]52;c;x\x07b")
    g.open_session("pts/1", "s1")
    g.record("pts/1", b"abc")
    g.flush("pts/1")
    assert g.stats() == {
        "ioctl_calls": 1,
        "ioctl_blocked": 1,
        "chunks_filtered": 1,
        "sequences_blocked": 1,
        "bytes_blocked": 9,
        "segments_opened": 1,
        "segments_closed": 1,
        "segments_incomplete": 0,
        "recovered": 0,
    }
