"""Rich text HTML sanitizing gate.

The gate rewrites untrusted HTML against a versioned allow-list.  Parsing,
canonical serialization, structural repair and reparse verification are all
handled locally with the standard library.
"""

from __future__ import annotations

import copy
import re
import threading
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from html import unescape
from html.parser import HTMLParser


class SanitizeError(ValueError):
    """Raised when sanitizing or a policy operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SanitizePolicy:
    version: int
    allowed_tags: tuple
    allowed_attributes: dict
    allowed_protocols: tuple


@dataclass(frozen=True)
class SanitizeResult:
    policy_version: int
    html: str
    dropped_tags: tuple
    dropped_attributes: tuple
    duplicate_attributes: int


_HARD_ALLOWED_PROTOCOLS = frozenset({"http", "https", "mailto"})
_URL_ATTRIBUTES = frozenset({"href", "src"})
_RAW_CONTENT_TAGS = frozenset({"script", "style"})
_IMPLICIT_CLOSE_TAGS = frozenset({"p", "li"})
_STATS_KEYS = ("sanitized", "dropped_tags", "dropped_attributes",
               "duplicates", "oversized")

_SCHEME_RE = re.compile(r"^([a-z][a-z0-9+.-]*):")
_ASCII_WHITESPACE_CONTROL_RE = re.compile(r"[\x00-\x20\x7f]")
_CONDITIONAL_OPEN_RE = re.compile(r"^\[if\b[^\]]*\]$", re.IGNORECASE | re.DOTALL)

_DEFAULT_ALLOWED_TAGS = (
    "a", "abbr", "b", "blockquote", "br", "code", "em", "i", "li", "ol",
    "p", "pre", "span", "strong", "u", "ul",
)
_DEFAULT_ALLOWED_ATTRIBUTES = {
    "*": ("class", "title"),
    "a": ("href",),
}
_DEFAULT_ALLOWED_PROTOCOLS = ("http", "https", "mailto")


def _is_real_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _policy_name(value: object) -> str:
    if not isinstance(value, str):
        raise SanitizeError("SANITIZE_POLICY_INVALID", "policy names must be strings")
    return unescape(value).strip().lower()


def _name_sequence(value: object, label: str) -> tuple:
    if isinstance(value, (str, bytes)) or not isinstance(value, Iterable):
        raise SanitizeError(
            "SANITIZE_POLICY_INVALID",
            f"{label} must be an iterable of strings",
        )

    names = []
    for item in value:
        name = _policy_name(item)
        if not name:
            raise SanitizeError(
                "SANITIZE_POLICY_INVALID",
                f"{label} contains an empty name",
            )
        names.append(name)
    return tuple(names)


def _build_policy(*, allowed_tags, allowed_attributes, allowed_protocols,
                  version: int) -> SanitizePolicy:
    tags = _name_sequence(allowed_tags, "allowed_tags")
    protocols = _name_sequence(allowed_protocols, "allowed_protocols")

    if not isinstance(allowed_attributes, Mapping):
        raise SanitizeError(
            "SANITIZE_POLICY_INVALID",
            "allowed_attributes must be a mapping",
        )

    attributes = {}
    for raw_tag, raw_names in allowed_attributes.items():
        tag = _policy_name(raw_tag)
        attributes[tag] = _name_sequence(
            raw_names, f"allowed_attributes[{tag!r}]"
        )

    for protocol in protocols:
        if protocol not in _HARD_ALLOWED_PROTOCOLS:
            raise SanitizeError(
                "SANITIZE_POLICY_INVALID",
                f"protocol {protocol!r} is not allowed",
            )

    if "script" in tags or "style" in tags:
        raise SanitizeError(
            "SANITIZE_POLICY_INVALID",
            "script and style tags cannot be allowed",
        )

    return SanitizePolicy(
        version=version,
        allowed_tags=tags,
        allowed_attributes=attributes,
        allowed_protocols=protocols,
    )


def _public_policy(policy: SanitizePolicy) -> SanitizePolicy:
    return SanitizePolicy(
        version=policy.version,
        allowed_tags=tuple(policy.allowed_tags),
        allowed_attributes={
            tag: tuple(names)
            for tag, names in policy.allowed_attributes.items()
        },
        allowed_protocols=tuple(policy.allowed_protocols),
    )


def _escape_text(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
    )


def _escape_attribute(value: str) -> str:
    return _escape_text(value).replace('"', "&quot;")


def _canonical_attribute_name(name: object) -> str:
    if name is None:
        return ""
    return unescape(str(name)).lower()


def _url_allowed(value: str, protocols: frozenset) -> bool:
    compact = _ASCII_WHITESPACE_CONTROL_RE.sub("", value.strip()).lower()
    match = _SCHEME_RE.match(compact)
    if match is None:
        return True
    return match.group(1) in protocols


class _SanitizeParser(HTMLParser):
    """Parse one fragment and emit its canonical sanitized representation."""

    def __init__(self, policy: SanitizePolicy, max_depth: int) -> None:
        super().__init__(convert_charrefs=True)
        self._policy = policy
        self._max_depth = max_depth
        self._allowed_tags = frozenset(policy.allowed_tags)
        self._allowed_protocols = frozenset(policy.allowed_protocols)

        self.parts: list[str] = []
        self.stack: list[list[object]] = []
        self.dropped_tags: list[str] = []
        self.dropped_attributes: list[str] = []
        self.reasons: list[str] = []
        self.duplicate_attributes = 0

        self._raw_stack: list[str] = []
        self._conditional_depth = 0

    def handle_comment(self, data: str) -> None:
        self.reasons.append("comment")

    def parse_bogus_comment(self, i: int, report: bool = True):
        raw = self.rawdata
        closing = raw.find(">", i + 2)
        is_open = False
        is_close = False
        if closing != -1:
            marker = raw[i + 2:closing].strip()
            is_open = bool(_CONDITIONAL_OPEN_RE.match(marker))
            is_close = marker.lower().startswith("[endif]")

        result = super().parse_bogus_comment(i, report)
        if report and result >= 0:
            if is_open:
                self._conditional_depth += 1
            elif is_close and self._conditional_depth:
                self._conditional_depth -= 1
        return result

    def handle_pi(self, data: str) -> None:
        if self._conditional_depth == 0:
            self.reasons.append("comment")

    def handle_decl(self, decl: str) -> None:
        return

    def unknown_decl(self, data: str) -> None:
        return

    def handle_data(self, data: str) -> None:
        if self._conditional_depth or self._raw_stack:
            return
        self.parts.append(_escape_text(data))

    def handle_startendtag(self, tag: str, attrs) -> None:
        self.handle_starttag(tag, attrs)
        canonical = unescape(str(tag)).strip().lower()
        if canonical not in _RAW_CONTENT_TAGS:
            self.handle_endtag(tag)

    def handle_starttag(self, tag: str, attrs) -> None:
        if self._conditional_depth:
            return

        canonical_tag = unescape(str(tag)).strip().lower()

        if self._raw_stack:
            return

        if canonical_tag not in self._allowed_tags:
            self.dropped_tags.append(canonical_tag)
            self.reasons.append("tag_not_allowed")
            self._process_attributes(canonical_tag, attrs)
            if canonical_tag in _RAW_CONTENT_TAGS:
                self._raw_stack.append(canonical_tag)
            return

        if canonical_tag in _IMPLICIT_CLOSE_TAGS:
            self._close_implicit_same(canonical_tag)

        depth_exceeded = len(self.stack) >= self._max_depth
        if depth_exceeded:
            self.reasons.append("depth_exceeded")

        rendered_attributes = self._process_attributes(canonical_tag, attrs)

        if depth_exceeded:
            if canonical_tag != "br":
                self.stack.append([canonical_tag, False])
            return

        attributes_html = "".join(
            f' {name}="{_escape_attribute(value)}"'
            for name, value in sorted(rendered_attributes, key=lambda item: item[0])
        )

        if canonical_tag == "br":
            self.parts.append(f"<br{attributes_html}/>")
            return

        self.stack.append([canonical_tag, True])
        self.parts.append(f"<{canonical_tag}{attributes_html}>")

    def handle_endtag(self, tag: str) -> None:
        canonical_tag = unescape(str(tag)).strip().lower()

        if canonical_tag in _RAW_CONTENT_TAGS and self._raw_stack:
            for index in range(len(self._raw_stack) - 1, -1, -1):
                if self._raw_stack[index] == canonical_tag:
                    del self._raw_stack[index:]
                    break
            return

        if self._conditional_depth:
            return

        self._close_through(canonical_tag)

    def finish(self) -> str:
        while self.stack:
            tag, rendered = self.stack.pop()
            if rendered:
                self.parts.append(f"</{tag}>")
        return "".join(self.parts)

    def _close_implicit_same(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            current = self.stack[index][0]
            if tag == "li" and current in {"ul", "ol"}:
                return
            if current == tag:
                self._close_to_index(index)
                return

    def _close_through(self, tag: str) -> None:
        for index in range(len(self.stack) - 1, -1, -1):
            if self.stack[index][0] == tag:
                self._close_to_index(index)
                return

    def _close_to_index(self, index: int) -> None:
        while len(self.stack) > index:
            closing_tag, rendered = self.stack.pop()
            if rendered:
                self.parts.append(f"</{closing_tag}>")

    def _attribute_allowed(self, tag: str, name: str) -> bool:
        attributes = self._policy.allowed_attributes
        if name in attributes.get(tag, ()):
            return True
        return name in attributes.get("*", ())

    def _process_attributes(self, tag: str, raw_attributes) -> list[tuple[str, str]]:
        seen = set()
        rendered = []

        for raw_name, raw_value in raw_attributes or ():
            name = _canonical_attribute_name(raw_name)
            if name in seen:
                self.duplicate_attributes += 1
                self.reasons.append("duplicate_attribute")
                continue
            seen.add(name)

            value = "" if raw_value is None else str(raw_value)

            if not self._attribute_allowed(tag, name):
                self.dropped_attributes.append(name)
                self.reasons.append("attribute_not_allowed")
                continue

            if name in _URL_ATTRIBUTES and not _url_allowed(
                value, self._allowed_protocols
            ):
                self.dropped_attributes.append(name)
                self.reasons.append("protocol_not_allowed")
                continue

            if name in _URL_ATTRIBUTES:
                value = value.strip()

            rendered.append((name, value))

        return rendered


def _render_once(html: str, policy: SanitizePolicy,
                 max_depth: int) -> tuple[_SanitizeParser, str]:
    parser = _SanitizeParser(policy, max_depth)
    parser.feed(html)
    parser.close()
    return parser, parser.finish()


def _render_verified(html: str, policy: SanitizePolicy,
                     max_depth: int) -> tuple[_SanitizeParser, str]:
    parser, candidate = _render_once(html, policy, max_depth)

    for _ in range(3):
        verifier, reparsed = _render_once(candidate, policy, max_depth)
        if reparsed == candidate:
            return parser, candidate
        candidate = reparsed

    _, reparsed = _render_once(candidate, policy, max_depth)
    if reparsed != candidate:
        candidate = _escape_text(candidate)

    return parser, candidate


def _empty_stats() -> dict:
    return {key: 0 for key in _STATS_KEYS}


class HtmlSanitizeGate:
    """Rewrite untrusted rich text against a versioned allow-list policy."""

    def __init__(self, *, max_length: int = 4096, max_depth: int = 12) -> None:
        if not _is_real_int(max_length) or max_length < 0:
            raise SanitizeError("SANITIZE_LIMIT_INVALID", "invalid max_length")
        if not _is_real_int(max_depth) or max_depth < 0:
            raise SanitizeError("SANITIZE_LIMIT_INVALID", "invalid max_depth")

        self._lock = threading.RLock()
        self._max_length = max_length
        self._max_depth = max_depth
        self._version = 1
        self._reloads = 0
        self._stats = _empty_stats()
        self._policy = _build_policy(
            allowed_tags=_DEFAULT_ALLOWED_TAGS,
            allowed_attributes=_DEFAULT_ALLOWED_ATTRIBUTES,
            allowed_protocols=_DEFAULT_ALLOWED_PROTOCOLS,
            version=1,
        )

    @property
    def max_length(self) -> int:
        with self._lock:
            return self._max_length

    @max_length.setter
    def max_length(self, value) -> None:
        self.set_limits(max_length=value)

    @property
    def max_depth(self) -> int:
        with self._lock:
            return self._max_depth

    @max_depth.setter
    def max_depth(self, value) -> None:
        self.set_limits(max_depth=value)

    def sanitize(self, html: str, *, tenant: str = "default") -> SanitizeResult:
        if not isinstance(html, str):
            raise SanitizeError("SANITIZE_INVALID_INPUT", "html must be a string")

        with self._lock:
            policy = self._policy
            max_length = self._max_length
            max_depth = self._max_depth

        parser, output = _render_verified(html, policy, max_depth)
        output_length = len(output)
        oversized = output_length > max_length

        with self._lock:
            if oversized:
                self._stats["oversized"] += 1
            else:
                self._stats["sanitized"] += 1
                self._stats["dropped_tags"] += len(parser.dropped_tags)
                self._stats["dropped_attributes"] += len(parser.dropped_attributes)
                self._stats["duplicates"] += parser.duplicate_attributes

        if oversized:
            raise SanitizeError(
                "SANITIZE_TOO_LARGE",
                {"length": output_length, "max_length": max_length},
            )

        return SanitizeResult(
            policy_version=policy.version,
            html=output,
            dropped_tags=tuple(parser.dropped_tags),
            dropped_attributes=tuple(parser.dropped_attributes),
            duplicate_attributes=parser.duplicate_attributes,
        )

    def validate_policy(self, *, allowed_tags, allowed_attributes,
                        allowed_protocols) -> SanitizePolicy:
        candidate = _build_policy(
            allowed_tags=allowed_tags,
            allowed_attributes=allowed_attributes,
            allowed_protocols=allowed_protocols,
            version=0,
        )
        with self._lock:
            version = self._version
        return SanitizePolicy(
            version=version,
            allowed_tags=candidate.allowed_tags,
            allowed_attributes=dict(candidate.allowed_attributes),
            allowed_protocols=candidate.allowed_protocols,
        )

    def reload_policy(self, *, allowed_tags, allowed_attributes,
                      allowed_protocols) -> SanitizePolicy:
        candidate = _build_policy(
            allowed_tags=allowed_tags,
            allowed_attributes=allowed_attributes,
            allowed_protocols=allowed_protocols,
            version=0,
        )

        with self._lock:
            version = self._version + 1
            policy = SanitizePolicy(
                version=version,
                allowed_tags=candidate.allowed_tags,
                allowed_attributes=dict(candidate.allowed_attributes),
                allowed_protocols=candidate.allowed_protocols,
            )
            self._version = version
            self._policy = policy
            self._reloads += 1
            return _public_policy(policy)

    def explain(self, html: str, *, tenant: str = "default") -> list:
        if not isinstance(html, str):
            raise SanitizeError("SANITIZE_INVALID_INPUT", "html must be a string")

        with self._lock:
            policy = self._policy
            max_depth = self._max_depth

        parser, _ = _render_verified(html, policy, max_depth)
        return list(parser.reasons)

    def status(self) -> dict:
        with self._lock:
            policy = self._policy
            return {
                "version": self._version,
                "allowed_tags": tuple(policy.allowed_tags),
                "allowed_attributes": {
                    tag: tuple(names)
                    for tag, names in policy.allowed_attributes.items()
                },
                "allowed_protocols": tuple(policy.allowed_protocols),
                "max_length": self._max_length,
                "max_depth": self._max_depth,
            }

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def reset_stats(self) -> None:
        with self._lock:
            self._stats = _empty_stats()

    def set_limits(self, *, max_length=None, max_depth=None) -> None:
        with self._lock:
            if max_length is not None:
                if not _is_real_int(max_length) or max_length < 0:
                    raise SanitizeError(
                        "SANITIZE_LIMIT_INVALID", "invalid max_length"
                    )
                self._max_length = max_length

            if max_depth is not None:
                if not _is_real_int(max_depth) or max_depth < 0:
                    raise SanitizeError(
                        "SANITIZE_LIMIT_INVALID", "invalid max_depth"
                    )
                self._max_depth = max_depth

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": self._version,
                "policy": {
                    "allowed_tags": tuple(self._policy.allowed_tags),
                    "allowed_attributes": {
                        tag: tuple(names)
                        for tag, names in self._policy.allowed_attributes.items()
                    },
                    "allowed_protocols": tuple(self._policy.allowed_protocols),
                },
                "stats": dict(self._stats),
                "reloads": self._reloads,
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        if not isinstance(state, Mapping):
            raise SanitizeError("SANITIZE_SNAPSHOT_INVALID", "state must be a mapping")

        for key in ("version", "policy", "stats", "reloads"):
            if key not in state:
                raise SanitizeError(
                    "SANITIZE_SNAPSHOT_INVALID", f"missing {key}"
                )

        version = state["version"]
        reloads = state["reloads"]
        policy_state = state["policy"]
        stats_state = state["stats"]

        if not _is_real_int(version) or version < 1:
            raise SanitizeError("SANITIZE_SNAPSHOT_INVALID", "invalid version")
        if not _is_real_int(reloads) or reloads < 0:
            raise SanitizeError("SANITIZE_SNAPSHOT_INVALID", "invalid reloads")
        if not isinstance(policy_state, Mapping):
            raise SanitizeError("SANITIZE_SNAPSHOT_INVALID", "policy must be a mapping")
        if not isinstance(stats_state, Mapping):
            raise SanitizeError("SANITIZE_SNAPSHOT_INVALID", "stats must be a mapping")

        for key in ("allowed_tags", "allowed_attributes", "allowed_protocols"):
            if key not in policy_state:
                raise SanitizeError(
                    "SANITIZE_SNAPSHOT_INVALID", f"policy missing {key}"
                )

        for key in _STATS_KEYS:
            if key not in stats_state:
                raise SanitizeError(
                    "SANITIZE_SNAPSHOT_INVALID", f"stats missing {key}"
                )
            if not _is_real_int(stats_state[key]) or stats_state[key] < 0:
                raise SanitizeError(
                    "SANITIZE_SNAPSHOT_INVALID", f"invalid stats.{key}"
                )

        try:
            policy = _build_policy(
                allowed_tags=policy_state["allowed_tags"],
                allowed_attributes=policy_state["allowed_attributes"],
                allowed_protocols=policy_state["allowed_protocols"],
                version=version,
            )
        except SanitizeError as exc:
            raise SanitizeError(
                "SANITIZE_SNAPSHOT_INVALID", "invalid policy in snapshot"
            ) from exc

        stats = {key: int(stats_state[key]) for key in _STATS_KEYS}

        with self._lock:
            self._version = version
            self._policy = policy
            self._stats = stats
            self._reloads = reloads
