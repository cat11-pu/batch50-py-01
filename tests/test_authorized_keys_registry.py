import pytest

import authorized_keys_registry as ak

T0 = "2026-11-26T11:00:00+00:00"
T1 = "2026-11-26T11:30:00+00:00"

BODY1 = "ZWQyNTUxOS10ZXN0LWtleS1tYXRlcmlhbC0wMDAx"
BODY2 = "ZWQyNTUxOS10ZXN0LWtleS1tYXRlcmlhbC0wMDAy"
BODY3 = "ZWQyNTUxOS10ZXN0LWtleS1tYXRlcmlhbC0wMDAz"

LINE_A = 'from="10.0.0.0/8",no-pty ssh-ed25519 {body} ops@alpha'.format(body=BODY1)
LINE_B = 'ssh-ed25519 {body} ops@beta'.format(body=BODY2)
LINE_C = 'ssh-ed25519 {body} ops@gamma'.format(body=BODY3)
LINE_CMD = ('command="/usr/bin/rsync --server --daemon .",no-pty '
            'ssh-ed25519 {body} backup@ops'.format(body=BODY1))


def registry(**kwargs):
    return ak.AuthorizedKeysRegistry(**kwargs)


def test_parse_line_returns_structured_entry():
    reg = registry()
    entry = reg.parse_line(LINE_A)
    assert isinstance(entry, ak.KeyEntry)
    assert entry.key_type == "ssh-ed25519"
    assert entry.comment == "ops@alpha"
    assert entry.options == {"from": "10.0.0.0/8", "no-pty": True}
    assert entry.account == ""
    assert entry.line == LINE_A
    assert entry.fingerprint.startswith("SHA256:")
    other = reg.parse_line(LINE_B)
    assert other.fingerprint != entry.fingerprint
    assert other.options == {}


def test_parse_line_rejects_unknown_key_type():
    reg = registry()
    bad_lines = [
        "ssh-dss AAAAB3NzaC1kc3MAAACBAP ops@x",
        "ssh-ed25519 !!!not-base64!!! ops@x",
        "no-key-type-here",
    ]
    for line in bad_lines:
        with pytest.raises(ak.KeysError) as exc:
            reg.parse_line(line)
        assert exc.value.code == "KEYS_LINE_INVALID"
    assert reg.entries() == []


def test_upsert_is_deduplicated_by_fingerprint():
    reg = registry()
    first = reg.upsert("ops", LINE_B, now=T0)
    assert (first.account, first.revision) == ("ops", 1)
    assert first.comment == "ops@beta"
    second = reg.upsert("ops", "ssh-ed25519 {body} rotated@beta".format(body=BODY2), now=T1)
    assert second.revision == 2
    assert second.comment == "rotated@beta"
    assert second.fingerprint == first.fingerprint
    assert second.added_at == T0
    assert len(reg.entries()) == 1
    counts = reg.stats()
    assert (counts["entries"], counts["upserted"], counts["updated"]) == (1, 1, 1)


def test_cross_account_fingerprint_is_refused_under_reject_policy():
    reg = registry()
    reg.upsert("ops", LINE_B, now=T0)
    with pytest.raises(ak.KeysError) as exc:
        reg.upsert("svc", LINE_B, now=T1)
    assert exc.value.code == "KEYS_FINGERPRINT_CONFLICT"
    assert reg.entries() == []
    assert reg.quarantined() == []
    assert reg.render() == ""


def test_isolate_policy_quarantines_both_accounts():
    reg = registry(dedup_policy="isolate")
    reg.upsert("ops", LINE_B, now=T0)
    with pytest.raises(ak.KeysError) as exc:
        reg.upsert("svc", LINE_B, now=T1)
    assert exc.value.code == "KEYS_FINGERPRINT_CONFLICT"
    fingerprint = reg.parse_line(LINE_B).fingerprint
    assert reg.entries() == []
    assert reg.quarantined() == [fingerprint]
    assert reg.stats()["quarantined"] == 1


def test_revoked_fingerprint_cannot_be_revived():
    reg = registry()
    entry = reg.upsert("ops", LINE_B, now=T0)
    assert reg.revoke(entry.fingerprint, now=T1) is True
    assert reg.entries() == []
    assert reg.render() == ""
    with pytest.raises(ak.KeysError) as exc:
        reg.upsert("ops", "ssh-ed25519 {body} same-key-new-comment".format(body=BODY2),
                   now=T1)
    assert exc.value.code == "KEYS_REVOKED"
    assert reg.stats()["revoked"] == 1


def test_revoke_unknown_fingerprint_is_noop():
    reg = registry()
    assert reg.revoke("SHA256:not-registered", now=T0) is False
    assert reg.revoke("SHA256:not-registered", now=T1) is False
    assert reg.stats()["revoked"] == 0
    assert reg.audit_log() == []


def test_render_orders_accounts_and_fingerprints():
    reg = registry()
    reg.upsert("zeta", LINE_B, now=T0)
    reg.upsert("alpha", LINE_A, now=T0)
    assert reg.render() == LINE_A + "\n" + LINE_B + "\n"
    assert [row.account for row in reg.entries()] == ["alpha", "zeta"]

    grouped = registry()
    grouped.upsert("ops", "ssh-ed25519 {body} zulu@x".format(body=BODY3), now=T0)
    grouped.upsert("ops", "ssh-ed25519 {body} alpha@x".format(body=BODY1), now=T0)
    rows = grouped.entries("ops")
    assert [row.fingerprint for row in rows] == sorted(row.fingerprint for row in rows)
    assert grouped.render() == "".join(row.line + "\n" for row in rows)


def test_render_preserves_option_quoting():
    reg = registry()
    reg.upsert("ops", LINE_CMD, now=T0)
    assert reg.render() == LINE_CMD + "\n"
    entry = reg.entries("ops")[0]
    assert entry.options["command"] == "/usr/bin/rsync --server --daemon ."
    assert entry.options["no-pty"] is True


def test_apply_writes_render_atomically_and_is_idempotent(tmp_path):
    target = tmp_path / "authorized_keys"
    reg = registry()
    reg.upsert("ops", LINE_A, now=T0)
    out = reg.apply(target)
    assert out["path"] == str(target)
    assert out["written"] == 1
    assert target.read_text(encoding="utf-8") == reg.render()
    reg.apply(target)
    assert target.read_text(encoding="utf-8") == LINE_A + "\n"
    assert reg.stats()["applied"] == 2


def test_apply_failure_leaves_target_untouched(tmp_path):
    target = tmp_path / "keys_dir"
    target.mkdir()
    reg = registry()
    reg.upsert("ops", LINE_A, now=T0)
    with pytest.raises(ak.KeysError) as exc:
        reg.apply(target)
    assert exc.value.code == "KEYS_APPLY_FAILED"
    assert target.is_dir()
    assert reg.stats()["applied"] == 0


def test_diff_reports_added_removed_and_unchanged(tmp_path):
    target = tmp_path / "authorized_keys"
    target.write_text(LINE_A + "\n" + LINE_C + "\n", encoding="utf-8")
    reg = registry()
    reg.upsert("alpha", LINE_A, now=T0)
    reg.upsert("ops", LINE_B, now=T0)
    delta = reg.diff(target)
    assert delta["added"] == [reg.parse_line(LINE_B).fingerprint]
    assert delta["removed"] == [reg.parse_line(LINE_C).fingerprint]
    assert delta["unchanged"] == 1


def test_load_reads_valid_lines_from_target_file(tmp_path):
    target = tmp_path / "authorized_keys"
    target.write_text(LINE_A + "\n" + LINE_B + "\n", encoding="utf-8")
    reg = registry()
    loaded = reg.load(target, account="ops", now=T0)
    assert loaded == 2
    assert len(reg.entries("ops")) == 2
    assert sorted(reg.render().splitlines()) == sorted([LINE_A, LINE_B])
    assert reg.stats()["entries"] == 2


def test_snapshot_roundtrip_keeps_revocations_and_counters():
    reg = registry()
    doomed = reg.upsert("ops", LINE_B, now=T0)
    reg.upsert("alpha", LINE_A, now=T0)
    reg.revoke(doomed.fingerprint, now=T1)
    reg.upsert("alpha", "ssh-ed25519 {body} third@x".format(body=BODY3), now=T1)
    state = reg.snapshot()

    clone = registry()
    clone.restore(state)
    assert [row.fingerprint for row in clone.entries()] == [
        row.fingerprint for row in reg.entries()]
    assert clone.render() == reg.render()
    assert clone.stats() == reg.stats()
    with pytest.raises(ak.KeysError) as exc:
        clone.upsert("ops", "ssh-ed25519 {body} again@x".format(body=BODY2), now=T1)
    assert exc.value.code == "KEYS_REVOKED"

    state["entries"] = {}
    assert reg.stats()["entries"] == 2


def test_restore_rejects_malformed_snapshot():
    reg = registry()
    reg.upsert("ops", LINE_A, now=T0)
    good = reg.snapshot()
    broken = [None, {},
              {"version": 9, "entries": {}, "revoked": {}, "quarantined": [],
               "comments": [], "audit": [], "counters": {}, "stats": {}}]
    partial = dict(good)
    partial.pop("revoked")
    broken.append(partial)
    wrong_type = dict(good)
    wrong_type["entries"] = ["nope"]
    broken.append(wrong_type)
    for bad in broken:
        with pytest.raises(ak.KeysError) as exc:
            reg.restore(bad)
        assert exc.value.code == "KEYS_SNAPSHOT_INVALID"
    assert reg.render() == LINE_A + "\n"
    assert reg.stats()["entries"] == 1
