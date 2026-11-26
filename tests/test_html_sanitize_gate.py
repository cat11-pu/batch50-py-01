import copy

import pytest

import html_sanitize_gate as sg


def gate(**kwargs):
    return sg.HtmlSanitizeGate(**kwargs)


def out(gate_obj, html, **kwargs):
    return gate_obj.sanitize(html, **kwargs).html


def test_allowed_tags_and_attributes_are_normalized():
    obj = gate()
    assert out(obj, '<P CLASS="lead">Hi</P>') == '<p class="lead">Hi</p>'
    assert out(obj, '<A TITLE="t" HREF="https://x.test/a?b=1&amp;c=2">go</A>') == (
        '<a href="https://x.test/a?b=1&amp;c=2" title="t">go</a>')
    assert out(obj, "<p>a &amp; b</p>") == "<p>a &amp; b</p>"


def test_disallowed_tag_is_unwrapped_keeping_content():
    obj = gate()
    assert out(obj, "<div>a<b>b</b></div>") == "a<b>b</b>"
    assert out(obj, "<p><table><tr><td>t</td></tr></table></p>") == "<p>t</p>"


def test_script_and_style_payloads_are_removed_with_content():
    obj = gate()
    assert out(obj, "<p>ok</p><script>alert(1)</script><style>p{color:red}</style>") == (
        "<p>ok</p>")
    assert out(obj, "<b>x</b><script>document.write('<p>no</p>')</script>") == "<b>x</b>"


def test_unsafe_url_scheme_is_dropped_case_insensitively():
    obj = gate()
    assert out(obj, '<a href=" javascript:alert(1)">x</a>') == "<a>x</a>"
    assert out(obj, '<a href="JaVaScRiPt:alert(1)" title="t">x</a>') == '<a title="t">x</a>'
    assert out(obj, '<a href="/local/path">x</a>') == '<a href="/local/path">x</a>'
    assert out(obj, '<a href="mailto:soc@example.test">x</a>') == (
        '<a href="mailto:soc@example.test">x</a>')


def test_entity_encoded_url_scheme_is_rejected():
    obj = gate()
    assert out(obj, '<a href="&#106;avascript:alert(1)">x</a>') == "<a>x</a>"
    assert out(obj, '<a href="&#x6a;avascript&#58;alert(1)">x</a>') == "<a>x</a>"


def test_comments_and_processing_instructions_are_dropped():
    obj = gate()
    assert out(obj, "a<!-- hi -->b<p><!--c-->t</p>") == "ab<p>t</p>"
    assert out(obj, "<p>x<!--[if IE]>y<![endif]--></p>") == "<p>x</p>"


def test_unclosed_and_misnested_tags_are_repaired():
    obj = gate()
    assert out(obj, "<p>a<p>b") == "<p>a</p><p>b</p>"
    assert out(obj, "<ul><li>one<li>two</ul>") == "<ul><li>one</li><li>two</li></ul>"
    assert out(obj, "<b><i>t</b></i>") == "<b><i>t</i></b>"


def test_duplicate_attributes_keep_first_and_are_counted():
    obj = gate()
    result = obj.sanitize(
        '<a href="https://a.test" href="https://b.test" title="t">x</a>')
    assert result.html == '<a href="https://a.test" title="t">x</a>'
    assert result.duplicate_attributes == 1


def test_sanitize_is_bytewise_idempotent():
    obj = gate()
    first = obj.sanitize('<div onclick="x"><b>t</b><i>u</i></div>').html
    second = obj.sanitize(first).html
    assert first == "<b>t</b><i>u</i>"
    assert second == first


def test_nesting_depth_limit_drops_extra_tags_but_keeps_text():
    obj = gate(max_depth=2)
    assert out(obj, "<p>a<span>b<span>c</span></span></p>") == "<p>a<span>bc</span></p>"


def test_output_length_limit_raises():
    obj = gate(max_length=10)
    with pytest.raises(sg.SanitizeError) as exc:
        obj.sanitize("<p>abcdefghij</p>")
    assert exc.value.code == "SANITIZE_TOO_LARGE"
    assert obj.stats()["oversized"] == 1


def test_policy_reload_bumps_version_and_applies():
    obj = gate()
    assert obj.status()["version"] == 1
    policy = obj.reload_policy(allowed_tags=("b",), allowed_attributes={},
                               allowed_protocols=("https",))
    assert policy.version == 2
    status = obj.status()
    assert status["version"] == 2
    assert status["allowed_tags"] == ("b",)
    result = obj.sanitize("<i>x</i><b>y</b>")
    assert result.html == "x<b>y</b>"
    assert result.policy_version == 2


def test_validate_policy_rejects_script_and_unknown_protocol():
    obj = gate()
    with pytest.raises(sg.SanitizeError) as exc:
        obj.validate_policy(allowed_tags=("b", "script"), allowed_attributes={},
                            allowed_protocols=("https",))
    assert exc.value.code == "SANITIZE_POLICY_INVALID"

    with pytest.raises(sg.SanitizeError) as exc:
        obj.validate_policy(allowed_tags=("a",), allowed_attributes={"a": ("href",)},
                            allowed_protocols=("javascript",))
    assert exc.value.code == "SANITIZE_POLICY_INVALID"
    assert obj.status()["version"] == 1


def test_explain_reports_reasons_without_touching_stats():
    obj = gate()
    html = '<script>x</script><p onclick="y" class="k">t</p>'
    assert obj.explain(html) == ["tag_not_allowed", "attribute_not_allowed"]
    assert obj.stats()["sanitized"] == 0

    result = obj.sanitize(html)
    assert result.html == '<p class="k">t</p>'
    assert result.dropped_tags == ("script",)
    assert result.dropped_attributes == ("onclick",)
    assert obj.stats() == {"sanitized": 1, "dropped_tags": 1, "dropped_attributes": 1,
                           "duplicates": 0, "oversized": 0}


def test_snapshot_roundtrips_and_rejects_malformed_state():
    obj = gate()
    obj.sanitize("<p>x</p>")
    obj.reload_policy(allowed_tags=("p", "b"), allowed_attributes={},
                      allowed_protocols=("https",))
    state = obj.snapshot()
    assert set(state) == {"version", "policy", "stats", "reloads"}
    assert state["version"] == 2

    pristine = copy.deepcopy(state)
    state["policy"]["allowed_tags"] = ()
    state["stats"]["sanitized"] = 99
    assert obj.status()["allowed_tags"] == ("p", "b")
    assert obj.stats()["sanitized"] == 1

    clone = gate()
    clone.restore(pristine)
    assert clone.status()["version"] == 2
    assert clone.stats()["sanitized"] == 1
    assert clone.status()["allowed_tags"] == ("p", "b")

    for bad in (None, {}, {"version": 1, "policy": {}, "stats": {}},
                {"version": 1, "policy": "nope", "stats": {}, "reloads": 0}):
        with pytest.raises(sg.SanitizeError) as exc:
            clone.restore(bad)
        assert exc.value.code == "SANITIZE_SNAPSHOT_INVALID"
    assert clone.status()["version"] == 2
