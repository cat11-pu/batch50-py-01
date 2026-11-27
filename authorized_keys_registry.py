"""authorized_keys governance: parsing, dedup, revocation and atomic writes."""

from __future__ import annotations

import base64
import copy
import hashlib
import os
import re
import tempfile
import threading
from dataclasses import dataclass, fields, replace
from datetime import datetime, timezone
from pathlib import Path


class KeysError(ValueError):
    """Raised when a registry operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


KEY_TYPES = ("ssh-ed25519", "ssh-rsa", "ecdsa-sha2-nistp256")

VALUE_OPTIONS = ("from", "command", "expiry-time", "principals", "environment")
FLAG_OPTIONS = ("no-pty", "no-port-forwarding", "no-agent-forwarding",
                "no-X11-forwarding", "restrict")

DEDUP_POLICIES = ("reject", "isolate")
STATS_KEYS = (
    "entries",
    "upserted",
    "updated",
    "revoked",
    "quarantined",
    "applied",
    "rejected",
)

_MUTUALLY_EXCLUSIVE_OPTIONS = (
    frozenset(("pty", "no-pty")),
    frozenset(("port-forwarding", "no-port-forwarding")),
    frozenset(("agent-forwarding", "no-agent-forwarding")),
    frozenset(("x11-forwarding", "no-x11-forwarding")),
    frozenset(("user-rc", "no-user-rc")),
)

_BASE64_RE = re.compile(r"[A-Za-z0-9+/]+={0,2}\Z")


@dataclass(frozen=True)
class KeyEntry:
    account: str
    fingerprint: str
    key_type: str
    comment: str
    options: dict
    line: str
    revision: int
    added_at: str


def _utc_now(value=None) -> datetime:
    if value is None:
        return datetime.now(timezone.utc)
    if isinstance(value, datetime):
        moment = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            moment = datetime.fromisoformat(text)
        except ValueError as exc:
            raise KeysError("KEYS_TIME_INVALID", value) from exc
    else:
        raise KeysError("KEYS_TIME_INVALID", value)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _iso_utc(value=None) -> str:
    return _utc_now(value).isoformat()


def parse_expiry_time(value: str) -> datetime:
    """Parse an OpenSSH expiry-time value, always using UTC by policy."""
    if not isinstance(value, str):
        raise ValueError("expiry-time must be a string")
    text = value.strip()
    if text.endswith(("Z", "z")):
        text = text[:-1]
    if len(text) == 8:
        fmt = "%Y%m%d"
    elif len(text) == 12:
        fmt = "%Y%m%d%H%M"
    elif len(text) == 14:
        fmt = "%Y%m%d%H%M%S"
    else:
        raise ValueError(f"unsupported expiry-time: {value!r}")
    return datetime.strptime(text, fmt).replace(tzinfo=timezone.utc)


def _fingerprint(body: str) -> str:
    if not isinstance(body, str) or not _BASE64_RE.fullmatch(body):
        raise KeysError("KEYS_LINE_INVALID", "invalid base64 key body")
    padding = "=" * ((-len(body)) % 4)
    try:
        raw_key = base64.b64decode(body + padding, validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise KeysError("KEYS_LINE_INVALID", "invalid base64 key body") from exc
    if not raw_key:
        raise KeysError("KEYS_LINE_INVALID", "empty key body")
    digest = hashlib.sha256(raw_key).digest()
    encoded = base64.b64encode(digest).decode("ascii").rstrip("=")
    return f"SHA256:{encoded}"


def _unquote_option_value(raw_value: str) -> str:
    if len(raw_value) < 2 or raw_value[0] != '"' or raw_value[-1] != '"':
        raise KeysError("KEYS_LINE_INVALID", "option value must be quoted")

    result: list[str] = []
    index = 1
    while index < len(raw_value) - 1:
        char = raw_value[index]
        if char == "\\" and index + 1 < len(raw_value) - 1:
            nxt = raw_value[index + 1]
            if nxt in ('"', "\\"):
                result.append(nxt)
            else:
                result.extend((char, nxt))
            index += 2
            continue
        if char == '"':
            raise KeysError("KEYS_LINE_INVALID", "unterminated option quote")
        result.append(char)
        index += 1
    return "".join(result)


def _split_option_tokens(options_raw: str) -> list[str]:
    tokens: list[str] = []
    start = 0
    quoted = False
    escaped = False
    for index, char in enumerate(options_raw):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quoted:
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            continue
        if char == "," and not quoted:
            tokens.append(options_raw[start:index])
            start = index + 1
    if quoted:
        raise KeysError("KEYS_LINE_INVALID", "unterminated option quote")
    tokens.append(options_raw[start:])
    return tokens


def _parse_options(options_raw: str) -> dict:
    options: dict[str, object] = {}
    normalized_names: dict[str, str] = {}
    for token in _split_option_tokens(options_raw):
        if not token.strip():
            raise KeysError("KEYS_LINE_INVALID", "empty option")
        if "=" in token:
            raw_name, raw_value = token.split("=", 1)
            name = raw_name.strip()
            if not name:
                raise KeysError("KEYS_LINE_INVALID", "empty option name")
            lookup = name.lower()
            if lookup in normalized_names:
                raise KeysError("KEYS_LINE_INVALID", f"duplicate option: {name}")
            value = _unquote_option_value(raw_value.strip())
            options[name] = value
            normalized_names[lookup] = name
            if lookup == "expiry-time":
                try:
                    parse_expiry_time(value)
                except ValueError as exc:
                    raise KeysError("KEYS_LINE_INVALID", str(exc)) from exc
        else:
            name = token.strip()
            if not name:
                raise KeysError("KEYS_LINE_INVALID", "empty option name")
            lookup = name.lower()
            if lookup in normalized_names:
                raise KeysError("KEYS_LINE_INVALID", f"duplicate option: {name}")
            options[name] = True
            normalized_names[lookup] = name

    present = set(normalized_names)
    for exclusive_group in _MUTUALLY_EXCLUSIVE_OPTIONS:
        if exclusive_group.issubset(present):
            names = "/".join(sorted(exclusive_group))
            raise KeysError("KEYS_LINE_INVALID", f"mutually exclusive options: {names}")
    return options


def parse_authorized_key_line(line: object, *, account: str = "") -> KeyEntry:
    if not isinstance(line, str):
        raise KeysError("KEYS_LINE_INVALID", "line must be a string")
    if "\n" in line.rstrip("\r\n") or "\r" in line.rstrip("\r\n"):
        raise KeysError("KEYS_LINE_INVALID", "a key line must not contain line breaks")

    raw_line = line.rstrip("\r\n")
    if not raw_line.strip() or raw_line.lstrip().startswith("#"):
        raise KeysError("KEYS_LINE_INVALID", "not an authorized key line")

    quoted = False
    escaped = False
    boundary = -1
    for index, char in enumerate(raw_line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quoted:
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            continue
        if char.isspace() and not quoted:
            boundary = index
            break
    if quoted or boundary < 0:
        raise KeysError("KEYS_LINE_INVALID", "missing key type or body")

    prefix = raw_line[:boundary]
    if prefix in KEY_TYPES:
        key_type = prefix
        options: dict[str, object] = {}
        body_and_comment = raw_line[boundary:].lstrip().split(None, 1)
        if not body_and_comment:
            raise KeysError("KEYS_LINE_INVALID", "missing key body")
        body = body_and_comment[0]
        comment = body_and_comment[1].strip() if len(body_and_comment) == 2 else ""
    else:
        options = _parse_options(prefix)
        type_body_comment = raw_line[boundary:].lstrip().split(None, 2)
        if len(type_body_comment) < 2:
            raise KeysError("KEYS_LINE_INVALID", "missing key type or body")
        key_type, body = type_body_comment[0], type_body_comment[1]
        comment = type_body_comment[2].strip() if len(type_body_comment) == 3 else ""

        if key_type not in KEY_TYPES:
            raise KeysError("KEYS_LINE_INVALID", f"unsupported key type: {key_type}")

    if key_type not in KEY_TYPES:
        raise KeysError("KEYS_LINE_INVALID", f"unsupported key type: {key_type}")

    fingerprint = _fingerprint(body)
    return KeyEntry(
        account=account or "",
        fingerprint=fingerprint,
        key_type=key_type,
        comment=comment,
        options=options,
        line=raw_line,
        revision=0,
        added_at="",
    )


def canonicalize_expiry_time(line: str) -> str:
    """Force a naive expiry-time option to UTC without reformatting other text."""
    quoted = False
    escaped = False
    boundary = -1
    for index, char in enumerate(line):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quoted:
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            continue
        if char.isspace() and not quoted:
            boundary = index
            break
    if boundary < 0 or line[:boundary] in KEY_TYPES:
        return line

    prefix = line[:boundary]
    try:
        tokens = _split_option_tokens(prefix)
    except KeysError:
        return line

    changed = False
    for index, token in enumerate(tokens):
        if "=" not in token:
            continue
        name, raw_value = token.split("=", 1)
        if name.strip().lower() != "expiry-time":
            continue
        match = re.fullmatch(r'(\s*")(.*)("\s*)', raw_value, re.DOTALL)
        if not match:
            continue
        opening, value, closing = match.groups()
        value = value.strip()
        if value.endswith(("Z", "z")):
            value = value[:-1]
        tokens[index] = f"{name}={opening}{value}Z{closing}"
        changed = True

    if not changed:
        return line
    return ",".join(tokens) + line[boundary:]


class AuthorizedKeysRegistry:
    """Maintain per-account authorized keys with fingerprint dedup and atomic writes."""

    def __init__(self, *, dedup_policy: str = "reject") -> None:
        if dedup_policy not in DEDUP_POLICIES:
            raise KeysError("KEYS_DEDUP_POLICY_INVALID", dedup_policy)
        self.dedup_policy = dedup_policy
        self._lock = threading.RLock()
        self._entries: dict[tuple[str, str], KeyEntry] = {}
        self._revoked: dict[str, str] = {}
        self._quarantined: list[str] = []
        self._comments: list[str] = []
        self._audit: list[dict] = []
        self._counters: dict[str, int] = {
            "upserted": 0,
            "updated": 0,
            "applied": 0,
            "rejected": 0,
        }

    def parse_line(self, line: str, *, account: str = "") -> KeyEntry:
        return parse_authorized_key_line(line, account=account)

    def upsert(self, account: str, line: str, *, now=None) -> KeyEntry:
        try:
            parsed = self.parse_line(line, account=account)
        except KeysError as exc:
            with self._lock:
                self._counters["rejected"] += 1
                self._audit_locked(
                    "upsert_rejected",
                    account=account,
                    code=exc.code,
                    detail=exc.detail,
                    line=line if isinstance(line, str) else None,
                    now=now,
                )
            raise

        with self._lock:
            timestamp = _iso_utc(now)
            fingerprint = parsed.fingerprint

            if fingerprint in self._revoked:
                self._reject_upsert_locked(
                    account, line, fingerprint, "KEYS_REVOKED", now
                )
                raise KeysError("KEYS_REVOKED", fingerprint)

            if fingerprint in self._quarantined:
                detail = {"fingerprint": fingerprint, "reason": "quarantined"}
                self._reject_upsert_locked(
                    account, line, fingerprint, "KEYS_FINGERPRINT_CONFLICT", now, detail
                )
                raise KeysError("KEYS_FINGERPRINT_CONFLICT", detail)

            matching_keys = [key for key in self._entries if key[1] == fingerprint]
            other_accounts = [key for key in matching_keys if key[0] != account]
            if other_accounts:
                accounts = sorted({key[0] for key in matching_keys})
                for key in matching_keys:
                    del self._entries[key]

                detail = {"fingerprint": fingerprint, "accounts": accounts}
                self._counters["rejected"] += 1
                self._audit_locked(
                    "fingerprint_conflict",
                    account=account,
                    fingerprint=fingerprint,
                    accounts=accounts,
                    policy=self.dedup_policy,
                    now=now,
                )

                if self.dedup_policy == "isolate":
                    if fingerprint not in self._quarantined:
                        self._quarantined.append(fingerprint)
                    self._audit_locked(
                        "fingerprint_quarantined",
                        fingerprint=fingerprint,
                        accounts=accounts,
                        now=now,
                    )

                raise KeysError("KEYS_FINGERPRINT_CONFLICT", detail)

            key = (account, fingerprint)
            previous = self._entries.get(key)
            if previous is None:
                entry = KeyEntry(
                    account=account,
                    fingerprint=fingerprint,
                    key_type=parsed.key_type,
                    comment=parsed.comment,
                    options=dict(parsed.options),
                    line=parsed.line,
                    revision=1,
                    added_at=timestamp,
                )
                self._entries[key] = entry
                self._counters["upserted"] += 1
                action = "upserted"
            else:
                entry = KeyEntry(
                    account=account,
                    fingerprint=fingerprint,
                    key_type=parsed.key_type,
                    comment=parsed.comment,
                    options=dict(parsed.options),
                    line=parsed.line,
                    revision=previous.revision + 1,
                    added_at=previous.added_at,
                )
                self._entries[key] = entry
                self._counters["updated"] += 1
                action = "updated"

            expiry_value = entry.options.get("expiry-time")
            expires_at: str | None = None
            if isinstance(expiry_value, str):
                try:
                    expires_at = parse_expiry_time(expiry_value).isoformat()
                except ValueError:
                    expires_at = None
            self._audit_locked(
                action,
                account=account,
                fingerprint=fingerprint,
                revision=entry.revision,
                comment=entry.comment,
                source=entry.options.get("from"),
                expiry_time=entry.options.get("expiry-time"),
                expires_at_utc=expires_at,
                now=now,
            )
            return self._public_entry(entry)

    def revoke(self, fingerprint: str, *, now=None) -> bool:
        with self._lock:
            if not isinstance(fingerprint, str):
                return False
            if fingerprint in self._revoked:
                return False

            matching_keys = [
                key for key, entry in self._entries.items()
                if entry.fingerprint == fingerprint
            ]
            known_quarantined = fingerprint in self._quarantined
            if not matching_keys and not known_quarantined:
                return False

            for key in matching_keys:
                del self._entries[key]
            self._revoked[fingerprint] = _iso_utc(now)
            self._audit_locked(
                "revoked",
                fingerprint=fingerprint,
                removed_accounts=sorted({key[0] for key in matching_keys}),
                from_quarantine=known_quarantined,
                now=now,
            )
            return True

    def render(self) -> str:
        with self._lock:
            lines: list[str] = []
            for comment_line in self._comments:
                if not comment_line.strip() or comment_line.lstrip().startswith("#"):
                    lines.append(comment_line)
            entries = sorted(
                self._entries.values(),
                key=lambda entry: (entry.account, entry.fingerprint),
            )
            lines.extend(canonicalize_expiry_time(entry.line) for entry in entries)
            if not lines:
                return ""
            return "\n".join(lines) + "\n"

    def apply(self, path) -> dict:
        raw_path = os.fspath(path)
        target = Path(raw_path)
        returned_path = raw_path if isinstance(raw_path, str) else os.fsdecode(raw_path)
        with self._lock:
            self._absorb_target_comments_locked(target)
            content = self.render()
            self._validate_rendered_content(content)

            temporary_name: str | None = None
            try:
                file_descriptor, temporary_name = tempfile.mkstemp(
                    prefix=".authorized_keys.",
                    suffix=".tmp",
                    dir=target.parent,
                )
                try:
                    with os.fdopen(file_descriptor, "w", encoding="utf-8", newline="") as handle:
                        handle.write(content)
                        handle.flush()
                        os.fsync(handle.fileno())
                    os.chmod(temporary_name, 0o600)
                    os.replace(temporary_name, target)
                    temporary_name = None
                finally:
                    if temporary_name is not None and os.path.exists(temporary_name):
                        os.unlink(temporary_name)
            except KeysError:
                raise
            except Exception as exc:
                raise KeysError(
                    "KEYS_APPLY_FAILED",
                    {"path": str(target), "error": repr(exc)},
                ) from exc

            self._counters["applied"] += 1
            written = content.count("\n")
            self._audit_locked("applied", path=returned_path, written=written)
            return {"path": returned_path, "written": written}

    def diff(self, path) -> dict:
        target = Path(os.fspath(path))
        target_fingerprints: set[str] = set()
        try:
            if target.exists():
                text = target.read_text(encoding="utf-8")
            else:
                text = ""
        except OSError as exc:
            raise KeysError("KEYS_DIFF_FAILED", str(target)) from exc

        for raw_line in text.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            try:
                parsed = self.parse_line(raw_line)
            except KeysError:
                continue
            target_fingerprints.add(parsed.fingerprint)

        with self._lock:
            current_fingerprints = {
                entry.fingerprint for entry in self._entries.values()
            }
        return {
            "added": sorted(current_fingerprints - target_fingerprints),
            "removed": sorted(target_fingerprints - current_fingerprints),
            "unchanged": len(current_fingerprints & target_fingerprints),
        }

    def load(self, path, *, account: str, now=None) -> int:
        source = Path(os.fspath(path))
        try:
            text = source.read_text(encoding="utf-8")
        except OSError as exc:
            raise KeysError("KEYS_LOAD_FAILED", str(source)) from exc

        loaded = 0
        for line_number, raw_line in enumerate(text.splitlines(), start=1):
            stripped = raw_line.strip()
            if not stripped:
                continue
            if stripped.startswith("#"):
                with self._lock:
                    self._comments.append(raw_line)
                continue
            try:
                self.upsert(account, raw_line, now=now)
            except KeysError as exc:
                if exc.code == "KEYS_LINE_INVALID" and not isinstance(
                    exc.detail, dict
                ):
                    exc.detail = {"line_number": line_number, "line": raw_line}
                raise
            loaded += 1
        return loaded

    def entries(self, account=None) -> list[KeyEntry]:
        with self._lock:
            rows = list(self._entries.values())
            if account is not None:
                rows = [row for row in rows if row.account == account]
            rows.sort(key=lambda row: (row.account, row.fingerprint))
            return [self._public_entry(row) for row in rows]

    def quarantined(self) -> list[str]:
        with self._lock:
            return list(self._quarantined)

    def audit_log(self) -> list[dict]:
        with self._lock:
            return copy.deepcopy(self._audit)

    def snapshot(self) -> dict:
        with self._lock:
            entries = {
                f"{account}\x1f{fingerprint}": {
                    field.name: getattr(entry, field.name)
                    for field in fields(KeyEntry)
                }
                for (account, fingerprint), entry in self._entries.items()
            }
            return {
                "version": 1,
                "entries": copy.deepcopy(entries),
                "revoked": dict(self._revoked),
                "quarantined": list(self._quarantined),
                "comments": list(self._comments),
                "audit": copy.deepcopy(self._audit),
                "counters": copy.deepcopy(self._counters),
                "stats": self.stats(),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._build_restored_state_locked(state)
            except KeysError as exc:
                if exc.code == "KEYS_SNAPSHOT_INVALID":
                    raise
                raise KeysError("KEYS_SNAPSHOT_INVALID", exc.detail) from exc
            except Exception as exc:
                raise KeysError("KEYS_SNAPSHOT_INVALID", repr(exc)) from exc

            self._entries = restored["entries"]
            self._revoked = restored["revoked"]
            self._quarantined = restored["quarantined"]
            self._comments = restored["comments"]
            self._audit = restored["audit"]
            self._counters = restored["counters"]

    def stats(self) -> dict:
        with self._lock:
            return {
                "entries": len(self._entries),
                "upserted": self._counters["upserted"],
                "updated": self._counters["updated"],
                "revoked": len(self._revoked),
                "quarantined": len(self._quarantined),
                "applied": self._counters["applied"],
                "rejected": self._counters["rejected"],
            }

    def is_expired(self, fingerprint: str, *, now=None) -> bool:
        """Return whether a known entry's UTC expiry-time is in the past."""
        with self._lock:
            entry = next(
                (row for row in self._entries.values() if row.fingerprint == fingerprint),
                None,
            )
            if entry is None:
                return False
            value = entry.options.get("expiry-time")
            if not isinstance(value, str):
                return False
            try:
                expires_at = parse_expiry_time(value)
            except ValueError:
                return False
            return _utc_now(now) >= expires_at

    def _reject_upsert_locked(
        self, account, line, fingerprint, code, now, detail=None
    ) -> None:
        self._counters["rejected"] += 1
        self._audit_locked(
            "upsert_rejected",
            account=account,
            fingerprint=fingerprint,
            code=code,
            detail=fingerprint if detail is None else detail,
            line=line if isinstance(line, str) else None,
            now=now,
        )

    def _audit_locked(self, action: str, *, now=None, **payload) -> None:
        event = {"at": _iso_utc(now), "action": action}
        event.update(payload)
        self._audit.append(event)

    @staticmethod
    def _public_entry(entry: KeyEntry) -> KeyEntry:
        return replace(entry, options=copy.deepcopy(entry.options))

    @staticmethod
    def _validate_rendered_content(content: str) -> None:
        for raw_line in content.splitlines():
            stripped = raw_line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            parse_authorized_key_line(raw_line)

    def _absorb_target_comments_locked(self, target: Path) -> None:
        try:
            text = target.read_text(encoding="utf-8")
        except OSError:
            return
        known = set(self._comments)
        for raw_line in text.splitlines():
            if raw_line.strip().startswith("#") and raw_line not in known:
                self._comments.append(raw_line)
                known.add(raw_line)

    def _build_restored_state_locked(self, state) -> dict:
        required = {
            "version",
            "entries",
            "revoked",
            "quarantined",
            "comments",
            "audit",
            "counters",
            "stats",
        }
        if not isinstance(state, dict) or not required.issubset(state):
            raise KeysError("KEYS_SNAPSHOT_INVALID", "missing snapshot fields")
        if state["version"] != 1:
            raise KeysError("KEYS_SNAPSHOT_INVALID", "unsupported snapshot version")
        if not isinstance(state["entries"], dict):
            raise KeysError("KEYS_SNAPSHOT_INVALID", "entries must be a dict")
        if not isinstance(state["revoked"], dict):
            raise KeysError("KEYS_SNAPSHOT_INVALID", "revoked must be a dict")
        if not isinstance(state["quarantined"], list):
            raise KeysError("KEYS_SNAPSHOT_INVALID", "quarantined must be a list")
        if not isinstance(state["comments"], list):
            raise KeysError("KEYS_SNAPSHOT_INVALID", "comments must be a list")
        if not isinstance(state["audit"], list):
            raise KeysError("KEYS_SNAPSHOT_INVALID", "audit must be a list")
        if not isinstance(state["counters"], dict):
            raise KeysError("KEYS_SNAPSHOT_INVALID", "counters must be a dict")
        if not isinstance(state["stats"], dict):
            raise KeysError("KEYS_SNAPSHOT_INVALID", "stats must be a dict")

        restored_entries: dict[tuple[str, str], KeyEntry] = {}
        fingerprint_accounts: dict[str, str] = {}
        entry_fields = {field.name for field in fields(KeyEntry)}

        for storage_key, data in state["entries"].items():
            if not isinstance(storage_key, str) or "\x1f" not in storage_key:
                raise KeysError("KEYS_SNAPSHOT_INVALID", "invalid entry key")
            account_from_key, fingerprint_from_key = storage_key.split("\x1f", 1)
            if not isinstance(data, dict) or not entry_fields.issubset(data):
                raise KeysError("KEYS_SNAPSHOT_INVALID", "invalid entry record")

            account = data["account"]
            fingerprint = data["fingerprint"]
            if account != account_from_key or fingerprint != fingerprint_from_key:
                raise KeysError("KEYS_SNAPSHOT_INVALID", "entry key mismatch")
            if not isinstance(account, str) or not isinstance(fingerprint, str):
                raise KeysError("KEYS_SNAPSHOT_INVALID", "invalid entry identity")
            if fingerprint in fingerprint_accounts:
                raise KeysError("KEYS_SNAPSHOT_INVALID", "duplicate fingerprint")
            fingerprint_accounts[fingerprint] = account

            for name in ("key_type", "comment", "line", "added_at"):
                if not isinstance(data[name], str):
                    raise KeysError("KEYS_SNAPSHOT_INVALID", f"invalid {name}")
            if not isinstance(data["options"], dict):
                raise KeysError("KEYS_SNAPSHOT_INVALID", "options must be a dict")
            revision = data["revision"]
            if isinstance(revision, bool) or not isinstance(revision, int) or revision < 1:
                raise KeysError("KEYS_SNAPSHOT_INVALID", "invalid revision")

            parsed = parse_authorized_key_line(data["line"], account=account)
            if parsed.fingerprint != fingerprint or parsed.key_type != data["key_type"]:
                raise KeysError("KEYS_SNAPSHOT_INVALID", "entry does not match line")
            if parsed.options != data["options"] or parsed.comment != data["comment"]:
                raise KeysError("KEYS_SNAPSHOT_INVALID", "entry metadata does not match line")

            restored_entries[(account, fingerprint)] = KeyEntry(
                account=account,
                fingerprint=fingerprint,
                key_type=data["key_type"],
                comment=data["comment"],
                options=copy.deepcopy(data["options"]),
                line=data["line"],
                revision=revision,
                added_at=data["added_at"],
            )

        for fingerprint, revoked_at in state["revoked"].items():
            if not isinstance(fingerprint, str) or not isinstance(revoked_at, str):
                raise KeysError("KEYS_SNAPSHOT_INVALID", "invalid revocation record")
        for fingerprint in state["quarantined"]:
            if not isinstance(fingerprint, str):
                raise KeysError("KEYS_SNAPSHOT_INVALID", "invalid quarantine record")
        for comment in state["comments"]:
            if not isinstance(comment, str):
                raise KeysError("KEYS_SNAPSHOT_INVALID", "invalid comment record")
        for event in state["audit"]:
            if not isinstance(event, dict):
                raise KeysError("KEYS_SNAPSHOT_INVALID", "invalid audit record")

        counters = copy.deepcopy(state["counters"])
        for name in ("upserted", "updated", "applied", "rejected"):
            value = counters.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise KeysError("KEYS_SNAPSHOT_INVALID", f"invalid counter: {name}")

        stats = state["stats"]
        for name in STATS_KEYS:
            value = stats.get(name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise KeysError("KEYS_SNAPSHOT_INVALID", f"invalid stat: {name}")
        expected_stats = {
            "entries": len(restored_entries),
            "upserted": counters["upserted"],
            "updated": counters["updated"],
            "revoked": len(state["revoked"]),
            "quarantined": len(state["quarantined"]),
            "applied": counters["applied"],
            "rejected": counters["rejected"],
        }
        if any(stats[name] != value for name, value in expected_stats.items()):
            raise KeysError("KEYS_SNAPSHOT_INVALID", "inconsistent stats")

        return {
            "entries": restored_entries,
            "revoked": copy.deepcopy(state["revoked"]),
            "quarantined": copy.deepcopy(state["quarantined"]),
            "comments": copy.deepcopy(state["comments"]),
            "audit": copy.deepcopy(state["audit"]),
            "counters": counters,
        }
