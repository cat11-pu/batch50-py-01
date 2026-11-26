"""Pseudo-terminal guard: ioctl admission, escape filtering and recording."""

from __future__ import annotations

import errno
import hashlib
import json
import os
import re
import threading
from dataclasses import dataclass, replace
from pathlib import Path
from urllib.parse import quote

try:
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None


TIOCSTI = 0x5412
TIOCLINUX = 0x541C

IOCTL_ALLOWED = "IOCTL_ALLOWED"
IOCTL_BLOCKED_TIOCSTI = "IOCTL_BLOCKED_TIOCSTI"
IOCTL_BLOCKED_TIOCLINUX = "IOCTL_BLOCKED_TIOCLINUX"

ERR_INVALID_CHUNK = "TTY_INVALID_CHUNK"
ERR_INVALID_ARGUMENT = "TTY_INVALID_ARGUMENT"
ERR_SESSION_REQUIRED = "TTY_SESSION_REQUIRED"
ERR_SESSION_CLOSED = "TTY_SESSION_CLOSED"
ERR_ALREADY_RECORDING = "TTY_ALREADY_RECORDING"
ERR_SEGMENT_TOO_LARGE = "TTY_SEGMENT_TOO_LARGE"
ERR_RULE_INVALID = "TTY_RULE_INVALID"

SEGMENT_OPEN = "open"
SEGMENT_COMPLETE = "complete"
SEGMENT_INCOMPLETE = "incomplete"

_META_KIND = "tty_injection_guard_segment_v1"
_PRIVATE_MODE_RE = re.compile(r"^\?\d+(?:;\d+)*$")


class TtyGuardError(ValueError):
    """Raised when a tty operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class IoctlVerdict:
    """Outcome of one ioctl request seen on a tty."""

    allowed: bool
    code: str
    request: int


@dataclass(frozen=True)
class OutputVerdict:
    """Outcome of filtering one output chunk."""

    emitted: str
    pending: str
    blocked: tuple


@dataclass(frozen=True)
class SegmentInfo:
    """Metadata of one recording segment."""

    tty: str
    session: str
    seq: int
    path: str
    status: str
    bytes_written: int
    sha256: object


class _TtyState:
    __slots__ = (
        "pending",
        "owner",
        "closed",
        "seq",
        "current",
        "fh",
        "lock_fh",
        "hasher",
        "data_path",
        "meta_path",
    )

    def __init__(self) -> None:
        self.pending = ""
        self.owner = None
        self.closed = False
        self.seq = 0
        self.current = None
        self.fh = None
        self.lock_fh = None
        self.hasher = None
        self.data_path = None
        self.meta_path = None


def _validate_osc_rules(value) -> tuple:
    try:
        raw_rules = tuple(value)
    except TypeError as exc:
        raise TtyGuardError(ERR_RULE_INVALID, "blocked_osc must be iterable") from exc

    rules = []
    for code in raw_rules:
        if isinstance(code, bool) or not isinstance(code, int) or code < 0:
            raise TtyGuardError(ERR_RULE_INVALID, f"invalid OSC rule: {code!r}")
        rules.append(code)
    return tuple(rules)


def _validate_private_mode_rules(value) -> tuple:
    try:
        raw_rules = tuple(value)
    except TypeError as exc:
        raise TtyGuardError(
            ERR_RULE_INVALID, "blocked_private_modes must be iterable"
        ) from exc

    rules = []
    for mode in raw_rules:
        if not isinstance(mode, str) or _PRIVATE_MODE_RE.fullmatch(mode) is None:
            raise TtyGuardError(
                ERR_RULE_INVALID, f"invalid private mode rule: {mode!r}"
            )
        rules.append(mode)
    return tuple(rules)


def _private_mode_label(params: str, blocked_modes: tuple):
    if not params.startswith("?"):
        return None

    tokens = set(params[1:].split(";")) if len(params) > 1 else set()
    for mode in blocked_modes:
        if params == mode:
            return f"csi{mode}"
        wanted = mode[1:] if mode.startswith("?") else mode
        if wanted and wanted in tokens:
            return f"csi{mode}"
    return None


def _parse_output(text: str, blocked_osc: tuple, blocked_modes: tuple):
    emitted_parts = []
    blocked = []
    bytes_blocked = 0
    pending = ""
    osc_codes = frozenset(blocked_osc)
    length = len(text)
    index = 0

    while index < length:
        esc = text.find("\x1b", index)
        if esc < 0:
            emitted_parts.append(text[index:])
            break

        if esc > index:
            emitted_parts.append(text[index:esc])

        start = esc
        pos = esc + 1
        if pos >= length:
            pending = text[start:]
            break

        introducer = text[pos]

        if introducer == "[":
            final = pos + 1
            while final < length and not ("@" <= text[final] <= "~"):
                final += 1
            if final >= length:
                pending = text[start:]
                break

            sequence = text[start : final + 1]
            params = text[pos + 1 : final]
            label = _private_mode_label(params, blocked_modes)
            if label is None:
                emitted_parts.append(sequence)
            else:
                blocked.append(label)
                bytes_blocked += len(sequence)
            index = final + 1
            continue

        if introducer == "]":
            cursor = pos + 1
            terminator_end = -1
            while cursor < length:
                char = text[cursor]
                if char == "\x07":
                    terminator_end = cursor
                    break
                if char == "\x1b" and cursor + 1 < length and text[cursor + 1] == "\\":
                    terminator_end = cursor + 1
                    break
                cursor += 1

            if terminator_end < 0:
                pending = text[start:]
                break

            sequence = text[start : terminator_end + 1]
            digit_end = pos + 1
            while digit_end < terminator_end and text[digit_end] in "0123456789":
                digit_end += 1
            digits = text[pos + 1 : digit_end]
            code = int(digits) if digits else None

            if code is not None and code in osc_codes:
                blocked.append(f"osc{code}")
                bytes_blocked += len(sequence)
            else:
                emitted_parts.append(sequence)
            index = terminator_end + 1
            continue

        if introducer in ("P", "X", "^", "_"):
            cursor = pos + 1
            terminator_end = -1
            while cursor < length:
                if (
                    text[cursor] == "\x1b"
                    and cursor + 1 < length
                    and text[cursor + 1] == "\\"
                ):
                    terminator_end = cursor + 1
                    break
                cursor += 1
            if terminator_end < 0:
                pending = text[start:]
                break
            sequence = text[start : terminator_end + 1]
            emitted_parts.append(sequence)
            index = terminator_end + 1
            continue

        cursor = pos
        while cursor < length and " " <= text[cursor] <= "/":
            cursor += 1
        if cursor >= length:
            pending = text[start:]
            break

        if "0" <= text[cursor] <= "~":
            emitted_parts.append(text[start : cursor + 1])
            index = cursor + 1
        else:
            emitted_parts.append(text[start:cursor])
            index = cursor

    return "".join(emitted_parts), pending, tuple(blocked), bytes_blocked


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(str(path), os.O_RDONLY)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


class TtyInjectionGuard:
    """Guard ioctl calls, sanitize terminal output and record sessions."""

    def __init__(
        self,
        record_dir,
        *,
        max_segment_bytes: int = 1048576,
        blocked_osc=(52,),
        blocked_private_modes=("?25",),
    ) -> None:
        self.record_dir = str(record_dir)
        try:
            self.max_segment_bytes = int(max_segment_bytes)
        except (TypeError, ValueError) as exc:
            raise TtyGuardError(
                ERR_INVALID_ARGUMENT, "max_segment_bytes must be an integer"
            ) from exc
        if self.max_segment_bytes < 0:
            raise TtyGuardError(
                ERR_INVALID_ARGUMENT, "max_segment_bytes must be non-negative"
            )

        self._blocked_osc = _validate_osc_rules(blocked_osc)
        self._blocked_private_modes = _validate_private_mode_rules(
            blocked_private_modes
        )
        self._lock = threading.RLock()
        self._stats = {
            "ioctl_calls": 0,
            "ioctl_blocked": 0,
            "chunks_filtered": 0,
            "sequences_blocked": 0,
            "bytes_blocked": 0,
            "segments_opened": 0,
            "segments_closed": 0,
            "segments_incomplete": 0,
            "recovered": 0,
        }
        self._states = {}
        self._segments = {}
        self._orders = {}

        Path(self.record_dir).mkdir(parents=True, exist_ok=True)
        with self._lock:
            self._load_existing_locked()

    def on_ioctl(self, tty_id: str, request: int, arg=None) -> IoctlVerdict:
        with self._lock:
            self._stats["ioctl_calls"] += 1
            if request == TIOCSTI:
                self._stats["ioctl_blocked"] += 1
                code = IOCTL_BLOCKED_TIOCSTI
                allowed = False
            elif request == TIOCLINUX:
                self._stats["ioctl_blocked"] += 1
                code = IOCTL_BLOCKED_TIOCLINUX
                allowed = False
            else:
                code = IOCTL_ALLOWED
                allowed = True
            return IoctlVerdict(allowed=allowed, code=code, request=request)

    def open_session(self, tty_id: str, session_id: str) -> None:
        self._validate_tty_id(tty_id)
        if not isinstance(session_id, str) or not session_id:
            raise TtyGuardError(
                ERR_INVALID_ARGUMENT, "session_id must be a non-empty string"
            )

        with self._lock:
            self._load_existing_locked()
            state = self._get_state_locked(tty_id)
            if state.owner is not None:
                raise TtyGuardError(
                    ERR_ALREADY_RECORDING,
                    {"tty": tty_id, "owner": state.owner, "requested": session_id},
                )

            tty_dir = self._tty_dir_locked(tty_id)
            tty_dir.mkdir(parents=True, exist_ok=True)
            lock_fh = self._acquire_session_file_lock_locked(tty_dir, tty_id, session_id)

            state.owner = session_id
            state.closed = False
            state.seq = max(
                (
                    segment.seq
                    for segment in self._segments.get(tty_id, [])
                    if segment.session == session_id
                ),
                default=0,
            )
            state.current = None
            state.fh = None
            state.lock_fh = lock_fh
            state.hasher = None
            state.data_path = None
            state.meta_path = None

    def filter_output(self, tty_id: str, chunk: str) -> OutputVerdict:
        if not isinstance(chunk, str):
            raise TtyGuardError(ERR_INVALID_CHUNK, "chunk must be a string")

        with self._lock:
            state = self._get_state_locked(tty_id)
            combined = state.pending + chunk
            emitted, pending, blocked, blocked_bytes = _parse_output(
                combined,
                self._blocked_osc,
                self._blocked_private_modes,
            )
            state.pending = pending

            self._stats["chunks_filtered"] += 1
            self._stats["sequences_blocked"] += len(blocked)
            self._stats["bytes_blocked"] += blocked_bytes
            return OutputVerdict(
                emitted=emitted,
                pending=pending,
                blocked=blocked,
            )

    def record(self, tty_id: str, data) -> SegmentInfo:
        if isinstance(data, str):
            payload = data.encode("utf-8")
        elif isinstance(data, (bytes, bytearray, memoryview)):
            payload = bytes(data)
        else:
            raise TtyGuardError(
                ERR_INVALID_ARGUMENT, "record data must be str, bytes or byte-like"
            )

        with self._lock:
            state = self._get_existing_state_locked(tty_id)
            if state is None or state.owner is None:
                if state is not None and state.closed:
                    code = ERR_SESSION_CLOSED
                else:
                    code = ERR_SESSION_REQUIRED
                raise TtyGuardError(code, {"tty": tty_id})

            current_size = (
                state.current.bytes_written if state.current is not None else 0
            )
            if current_size + len(payload) > self.max_segment_bytes:
                raise TtyGuardError(
                    ERR_SEGMENT_TOO_LARGE,
                    {
                        "tty": tty_id,
                        "session": state.owner,
                        "current_bytes": current_size,
                        "chunk_bytes": len(payload),
                        "max_segment_bytes": self.max_segment_bytes,
                    },
                )

            self._ensure_segment_locked(tty_id, state)
            assert state.fh is not None and state.hasher is not None

            state.fh.write(payload)
            state.fh.flush()
            try:
                os.fsync(state.fh.fileno())
            except OSError:
                pass
            state.hasher.update(payload)

            written = state.current.bytes_written + len(payload)
            info = replace(state.current, bytes_written=written)
            state.current = info
            self._upsert_segment_locked(tty_id, info)
            self._write_meta_locked(tty_id, info)
            return info

    def flush(self, tty_id: str):
        with self._lock:
            state = self._get_existing_state_locked(tty_id)
            if state is None or state.current is None:
                return None
            return self._seal_current_locked(tty_id, state, SEGMENT_COMPLETE)

    def close(self, tty_id: str):
        with self._lock:
            state = self._get_existing_state_locked(tty_id)
            if state is None:
                state = self._get_state_locked(tty_id)
                state.closed = True
                return None

            if state.owner is None:
                return None

            sealed = None
            try:
                if state.current is not None:
                    sealed = self._seal_current_locked(
                        tty_id, state, SEGMENT_COMPLETE
                    )
                if state.fh is not None:
                    try:
                        state.fh.close()
                    except OSError:
                        pass
            finally:
                state.fh = None
                lock_fh = state.lock_fh
                state.lock_fh = None
                if lock_fh is not None and fcntl is not None:
                    try:
                        fcntl.flock(lock_fh.fileno(), fcntl.LOCK_UN)
                    except OSError:
                        pass
                    try:
                        lock_fh.close()
                    except OSError:
                        pass
                state.hasher = None
                state.data_path = None
                state.meta_path = None
                state.current = None
                state.seq = 0
                state.owner = None
                state.closed = True
            return sealed

    def update_rules(
        self,
        *,
        blocked_osc=None,
        blocked_private_modes=None,
    ) -> None:
        with self._lock:
            next_osc = self._blocked_osc
            next_modes = self._blocked_private_modes
            if blocked_osc is not None:
                next_osc = _validate_osc_rules(blocked_osc)
            if blocked_private_modes is not None:
                next_modes = _validate_private_mode_rules(blocked_private_modes)
            self._blocked_osc = next_osc
            self._blocked_private_modes = next_modes

    def recover(self) -> int:
        recovered = 0
        with self._lock:
            self._load_existing_locked()
            for tty_id in list(self._segments.keys()):
                state = self._states.get(tty_id)
                if state is not None and state.current is not None:
                    self._seal_current_locked(tty_id, state, SEGMENT_INCOMPLETE)

                rows = self._segments.get(tty_id, [])
                for index, info in enumerate(list(rows)):
                    if info.status != SEGMENT_OPEN:
                        continue

                    path = Path(info.path)
                    if path.exists():
                        digest = _sha256_file(path)
                        size = path.stat().st_size
                    else:
                        digest = hashlib.sha256(b"").hexdigest()
                        size = info.bytes_written

                    sealed = replace(
                        info,
                        status=SEGMENT_INCOMPLETE,
                        bytes_written=size,
                        sha256=digest,
                    )
                    rows[index] = sealed
                    self._write_meta_locked(tty_id, sealed)
                    self._stats["segments_closed"] += 1
                    self._stats["segments_incomplete"] += 1
                    self._stats["recovered"] += 1
                    recovered += 1

                self._sort_segments_locked(tty_id)
        return recovered

    def segments(self, tty_id: str) -> list:
        with self._lock:
            return list(self._segments.get(tty_id, ()))

    def status(self, tty_id: str) -> dict:
        with self._lock:
            state = self._get_existing_state_locked(tty_id)
            pending = state.pending if state is not None else ""
            owner = state.owner if state is not None else None

            open_segment = None
            if state is not None and state.current is not None:
                open_segment = state.current.seq
            else:
                for info in reversed(self._segments.get(tty_id, [])):
                    if info.status == SEGMENT_OPEN:
                        open_segment = info.seq
                        break

            return {
                "owner": owner,
                "session": owner,
                "pending": pending,
                "open_segment": open_segment,
                "segments": self.segments(tty_id),
            }

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _validate_tty_id(self, tty_id: str) -> None:
        if not isinstance(tty_id, str) or not tty_id or "\x00" in tty_id:
            raise TtyGuardError(ERR_INVALID_ARGUMENT, "invalid tty_id")
        parts = [
            part
            for part in tty_id.replace("\\", "/").split("/")
            if part not in ("", ".")
        ]
        if not parts or any(part == ".." for part in parts):
            raise TtyGuardError(ERR_INVALID_ARGUMENT, "unsafe tty_id")

    def _tty_dir_locked(self, tty_id: str) -> Path:
        self._validate_tty_id(tty_id)
        parts = [
            part
            for part in tty_id.replace("\\", "/").split("/")
            if part not in ("", ".")
        ]
        return Path(self.record_dir).joinpath(*parts)

    def _acquire_session_file_lock_locked(
        self,
        tty_dir: Path,
        tty_id: str,
        session_id: str,
    ):
        if fcntl is None:
            return None

        lock_path = tty_dir / ".session.lock"
        handle = lock_path.open("a+b")
        try:
            fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            handle.close()
            if exc.errno not in (errno.EACCES, errno.EAGAIN):
                return None
            owner = None
            try:
                owner = lock_path.read_text(encoding="utf-8").strip() or None
            except OSError:
                owner = None
            raise TtyGuardError(
                ERR_ALREADY_RECORDING,
                {
                    "tty": tty_id,
                    "owner": owner,
                    "requested": session_id,
                },
            ) from exc

        try:
            handle.seek(0)
            handle.truncate()
            handle.write(session_id.encode("utf-8"))
            handle.flush()
        except OSError:
            pass
        return handle

    def _get_existing_state_locked(self, tty_id: str):
        return self._states.get(tty_id)

    def _get_state_locked(self, tty_id: str) -> _TtyState:
        state = self._states.get(tty_id)
        if state is None:
            self._validate_tty_id(tty_id)
            state = _TtyState()
            self._states[tty_id] = state
        return state

    def _ensure_segment_locked(self, tty_id: str, state: _TtyState) -> None:
        if state.current is not None:
            return

        tty_dir = self._tty_dir_locked(tty_id)
        tty_dir.mkdir(parents=True, exist_ok=True)
        safe_session = quote(state.owner or "", safe="")

        while True:
            state.seq += 1
            stem = f"{safe_session}-{state.seq}"
            data_path = tty_dir / f"{stem}.log"
            meta_path = tty_dir / f"{stem}.json"
            try:
                handle = data_path.open("xb")
                break
            except FileExistsError:
                continue

        state.fh = handle
        state.hasher = hashlib.sha256()
        state.data_path = data_path
        state.meta_path = meta_path

        info = SegmentInfo(
            tty=tty_id,
            session=state.owner or "",
            seq=state.seq,
            path=str(data_path),
            status=SEGMENT_OPEN,
            bytes_written=0,
            sha256=None,
        )
        state.current = info
        self._upsert_segment_locked(tty_id, info)
        self._stats["segments_opened"] += 1
        self._write_meta_locked(tty_id, info)
        _fsync_directory(tty_dir)

    def _seal_current_locked(
        self,
        tty_id: str,
        state: _TtyState,
        status: str,
    ) -> SegmentInfo:
        info = state.current

        if state.fh is not None:
            state.fh.flush()
            try:
                os.fsync(state.fh.fileno())
            except OSError:
                pass
            state.fh.close()

        digest = (
            state.hasher.hexdigest()
            if state.hasher is not None
            else _sha256_file(Path(info.path))
        )
        sealed = replace(info, status=status, sha256=digest)
        self._upsert_segment_locked(tty_id, sealed)
        self._write_meta_locked(tty_id, sealed)

        state.current = None
        state.fh = None
        state.hasher = None
        state.data_path = None
        state.meta_path = None

        self._stats["segments_closed"] += 1
        if status == SEGMENT_INCOMPLETE:
            self._stats["segments_incomplete"] += 1
        return sealed

    def _upsert_segment_locked(
        self,
        tty_id: str,
        info: SegmentInfo,
        order: int | None = None,
    ) -> None:
        rows = self._segments.setdefault(tty_id, [])
        for index, existing in enumerate(rows):
            same_path = existing.path == info.path
            same_identity = (
                existing.session == info.session and existing.seq == info.seq
            )
            if same_path or same_identity:
                rows[index] = info
                break
        else:
            rows.append(info)

        orders = self._orders.setdefault(tty_id, {})
        if order is None:
            order = orders.get(info.path)
        if order is None:
            order = max(orders.values(), default=len(rows)) + 1
        orders[info.path] = order
        self._sort_segments_locked(tty_id)

    def _sort_segments_locked(self, tty_id: str) -> None:
        orders = self._orders.get(tty_id, {})
        rows = self._segments.get(tty_id, [])
        rows.sort(
            key=lambda info: (
                orders.get(info.path, 10**12),
                info.session,
                info.seq,
                info.path,
            )
        )

    def _write_meta_locked(self, tty_id: str, info: SegmentInfo) -> None:
        data_path = Path(info.path)
        meta_path = data_path.with_suffix(".json")
        orders = self._orders.setdefault(tty_id, {})
        order = orders.get(info.path)
        if order is None:
            order = max(orders.values(), default=0) + 1
            orders[info.path] = order

        payload = {
            "kind": _META_KIND,
            "order": order,
            "tty": info.tty,
            "session": info.session,
            "seq": info.seq,
            "data_file": data_path.name,
            "status": info.status,
            "bytes_written": info.bytes_written,
            "sha256": info.sha256,
        }
        meta_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = meta_path.with_name(f".{meta_path.name}.tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.flush()
            try:
                os.fsync(handle.fileno())
            except OSError:
                pass
        os.replace(temporary, meta_path)
        _fsync_directory(meta_path.parent)

    def _load_existing_locked(self) -> None:
        root = Path(self.record_dir)
        if not root.exists():
            return

        for meta_path in root.rglob("*.json"):
            if not meta_path.is_file() or meta_path.name.startswith("."):
                continue
            try:
                payload = json.loads(meta_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(payload, dict) or payload.get("kind") != _META_KIND:
                continue

            try:
                tty_id = str(payload["tty"])
                session_id = str(payload["session"])
                seq = int(payload["seq"])
                data_name = str(payload["data_file"])
            except (KeyError, TypeError, ValueError):
                continue

            data_path = meta_path.parent / Path(data_name).name
            if not data_path.is_file():
                continue

            status = payload.get("status", SEGMENT_OPEN)
            if status not in (SEGMENT_OPEN, SEGMENT_COMPLETE, SEGMENT_INCOMPLETE):
                status = SEGMENT_OPEN

            try:
                size = data_path.stat().st_size
            except OSError:
                size = int(payload.get("bytes_written", 0) or 0)

            sha256 = None
            if status != SEGMENT_OPEN:
                try:
                    sha256 = _sha256_file(data_path)
                except OSError:
                    sha256 = payload.get("sha256")

            info = SegmentInfo(
                tty=tty_id,
                session=session_id,
                seq=seq,
                path=str(data_path),
                status=status,
                bytes_written=size,
                sha256=sha256,
            )
            try:
                order = int(payload.get("order", 0))
            except (TypeError, ValueError):
                order = None
            self._upsert_segment_locked(tty_id, info, order=order)
