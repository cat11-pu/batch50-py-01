"""FTP control channel bounce protection for active and passive transfers."""

from __future__ import annotations

import copy
import ipaddress
import threading
from dataclasses import dataclass


class FtpGuardError(ValueError):
    """Raised when a data connection request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Reply:
    code: int
    text: str


@dataclass(frozen=True)
class DataTarget:
    ip: str
    port: int
    mode: str
    mapped: bool


_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(cidr)
    for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
                 "127.0.0.0/8", "169.254.0.0/16")
)

_SNAPSHOT_VERSION = 1

_COUNTER_KEYS = (
    "commands", "rejected", "line_too_long", "pending_rejected",
    "rewritten", "data_authorized",
)


def _is_private_ip(ip: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in _PRIVATE_NETWORKS)


class FtpBounceGuard:
    """Track one FTP control session and police data connection targets."""

    def __init__(self, *, control_peer: str, pasv_port_range=(40000, 40100),
                 active_peer_port: int = 20, max_line: int = 512,
                 users=None, pasv_advertised_ip: str = "192.168.10.20") -> None:
        self.control_peer = control_peer
        self.pasv_port_range = tuple(pasv_port_range)
        self.active_peer_port = active_peer_port
        self.max_line = max_line
        self.users = dict(users or {"ftpuser": "s3cret"})
        self.pasv_advertised_ip = pasv_advertised_ip
        self._lock = threading.RLock()
        self._authenticated = False
        self._user = None
        self._buffer = ""
        self._overflow = False
        self._pending = None
        self._closed = False
        self._pasv_next = 0
        self._counters = {key: 0 for key in _COUNTER_KEYS}

    def authenticate(self, user: str, password: str) -> bool:
        with self._lock:
            if self._closed:
                return False
            if self.users.get(user) == password:
                self._authenticated = True
                self._user = user
                return True
            return False

    def feed(self, chunk) -> list[Reply]:
        if isinstance(chunk, (bytes, bytearray)):
            text = bytes(chunk).decode("utf-8", "replace")
        else:
            text = str(chunk)
        replies = []
        with self._lock:
            self._buffer += text
            while True:
                idx = self._buffer.find("\n")
                if self._overflow:
                    if idx == -1:
                        self._buffer = ""
                        break
                    self._buffer = self._buffer[idx + 1:]
                    self._overflow = False
                    replies.append(self._line_too_long_reply())
                    continue
                if idx == -1:
                    if len(self._buffer) > self.max_line:
                        self._overflow = True
                        self._buffer = ""
                    break
                line = self._buffer[:idx]
                self._buffer = self._buffer[idx + 1:]
                if line.endswith("\r"):
                    line = line[:-1]
                if len(line) > self.max_line:
                    replies.append(self._line_too_long_reply())
                else:
                    replies.append(self.on_command(line))
        return replies

    def _line_too_long_reply(self) -> Reply:
        self._counters["line_too_long"] += 1
        self._counters["rejected"] += 1
        return Reply(500, "Command line too long")

    def on_command(self, line: str) -> Reply:
        with self._lock:
            self._counters["commands"] += 1
            if self._closed:
                return Reply(421, "Service not available, closing control connection")
            parts = line.strip().split(None, 1)
            verb = parts[0].upper() if parts else ""
            arg = parts[1] if len(parts) > 1 else ""
            if verb in ("USER", "PASS", "QUIT"):
                return self._handle_auth_command(verb, arg)
            if not self._authenticated:
                self._counters["rejected"] += 1
                return Reply(530, "Please login with USER and PASS")
            if verb == "NOOP":
                return Reply(200, "NOOP ok")
            if verb == "PORT":
                return self._handle_port(arg)
            if verb == "EPRT":
                return self._handle_eprt(arg)
            if verb == "PASV":
                return self._handle_pasv(extended=False)
            if verb == "EPSV":
                return self._handle_pasv(extended=True)
            self._counters["rejected"] += 1
            return Reply(502, "Command not implemented")

    def _handle_auth_command(self, verb: str, arg: str) -> Reply:
        if verb == "USER":
            self._user = arg.strip() or None
            return Reply(331, "Password required")
        if verb == "PASS":
            if self._user is not None and self.users.get(self._user) == arg.strip():
                self._authenticated = True
                return Reply(230, "Login successful")
            self._authenticated = False
            self._counters["rejected"] += 1
            return Reply(530, "Login incorrect")
        return Reply(221, "Goodbye")

    def _reject_format(self, detail: str) -> Reply:
        self._counters["rejected"] += 1
        return Reply(501, detail)

    def _pending_conflict(self) -> Reply:
        self._counters["pending_rejected"] += 1
        return Reply(503, "Data connection already pending")

    def _register_active_target(self, ip: str, port: int) -> Reply:
        if ip != self.control_peer or port != self.active_peer_port:
            return self._reject_format("Data connection target not allowed")
        if self._pending is not None:
            return self._pending_conflict()
        self._pending = DataTarget(ip=ip, port=port, mode="active", mapped=False)
        return Reply(200, "PORT command successful")

    def _handle_port(self, arg: str) -> Reply:
        fields = arg.strip().split(",")
        if len(fields) != 6:
            return self._reject_format("Invalid PORT syntax")
        try:
            nums = [int(field) for field in fields]
        except ValueError:
            return self._reject_format("Invalid PORT syntax")
        if any(num < 0 or num > 255 for num in nums):
            return self._reject_format("Invalid PORT syntax")
        ip = ".".join(str(num) for num in nums[:4])
        port = nums[4] * 256 + nums[5]
        return self._register_active_target(ip, port)

    def _handle_eprt(self, arg: str) -> Reply:
        arg = arg.strip()
        if len(arg) < 2:
            return self._reject_format("Invalid EPRT syntax")
        delim = arg[0]
        parts = arg.split(delim)
        if len(parts) != 5 or parts[0] != "" or parts[4] != "":
            return self._reject_format("Invalid EPRT syntax")
        proto, ip, port_text = parts[1], parts[2], parts[3]
        if proto not in ("1", "2"):
            return self._reject_format("Unsupported EPRT protocol")
        try:
            port = int(port_text)
        except ValueError:
            return self._reject_format("Invalid EPRT syntax")
        if not 0 <= port <= 65535:
            return self._reject_format("Invalid EPRT syntax")
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return self._reject_format("Invalid EPRT syntax")
        return self._register_active_target(ip, port)

    def _allocate_pasv_port(self) -> int:
        lo, hi = self.pasv_port_range
        if hi < lo:
            raise FtpGuardError("FTP_PASV_PORT_RANGE",
                                {"range": self.pasv_port_range})
        port = lo + (self._pasv_next % (hi - lo + 1))
        self._pasv_next += 1
        if not lo <= port <= hi:
            raise FtpGuardError("FTP_PASV_PORT_RANGE",
                                {"port": port, "range": self.pasv_port_range})
        return port

    def _handle_pasv(self, extended: bool) -> Reply:
        if self._pending is not None:
            return self._pending_conflict()
        port = self._allocate_pasv_port()
        ip, port = self.rewrite_pasv(self.pasv_advertised_ip, port)
        mapped = ip != self.pasv_advertised_ip
        self._pending = DataTarget(ip=ip, port=port, mode="passive", mapped=mapped)
        if extended:
            return Reply(229, "Entering Extended Passive Mode (|||%d|)" % port)
        quads = ip.split(".")
        text = "Entering Passive Mode (%s,%d,%d)" % (
            ",".join(quads), port // 256, port % 256)
        return Reply(227, text)

    def authorize_data(self, peer_ip: str, peer_port: int) -> DataTarget:
        with self._lock:
            if self._pending is None:
                raise FtpGuardError("FTP_NO_PENDING_DATA")
            target = self._pending
            mismatch = peer_ip != target.ip or (
                target.mode == "active" and peer_port != target.port)
            if mismatch:
                raise FtpGuardError(
                    "FTP_DATA_PEER_MISMATCH",
                    {"expected": (target.ip, target.port),
                     "got": (peer_ip, peer_port)})
            self._pending = None
            self._counters["data_authorized"] += 1
            return target

    def rewrite_pasv(self, advertised_ip: str, port: int) -> tuple[str, int]:
        with self._lock:
            lo, hi = self.pasv_port_range
            if not lo <= port <= hi:
                raise FtpGuardError(
                    "FTP_PASV_PORT_RANGE",
                    {"port": port, "range": self.pasv_port_range})
            if _is_private_ip(advertised_ip) and not _is_private_ip(self.control_peer):
                self._counters["rewritten"] += 1
                return self.control_peer, port
            return advertised_ip, port

    def pending_data(self) -> DataTarget | None:
        with self._lock:
            return self._pending

    def release_data(self) -> bool:
        with self._lock:
            had = self._pending is not None
            self._pending = None
            return had

    def snapshot(self) -> dict:
        with self._lock:
            pending = None
            if self._pending is not None:
                pending = {"ip": self._pending.ip, "port": self._pending.port,
                           "mode": self._pending.mode, "mapped": self._pending.mapped}
            return copy.deepcopy({
                "version": _SNAPSHOT_VERSION,
                "authenticated": self._authenticated,
                "user": self._user,
                "buffer": self._buffer,
                "pending": pending,
                "counters": dict(self._counters),
                "closed": self._closed,
            })

    def restore(self, state: dict) -> None:
        with self._lock:
            self._authenticated = bool(state.get("authenticated", False))
            self._user = state.get("user")
            self._buffer = str(state.get("buffer", ""))
            self._overflow = False
            pending = state.get("pending")
            if pending:
                self._pending = DataTarget(
                    ip=pending["ip"], port=int(pending["port"]),
                    mode=pending["mode"], mapped=bool(pending["mapped"]))
            else:
                self._pending = None
            counters = {key: 0 for key in _COUNTER_KEYS}
            counters.update(state.get("counters") or {})
            self._counters = counters
            self._closed = bool(state.get("closed", False))

    def stats(self) -> dict:
        with self._lock:
            return dict(self._counters)

    def close(self) -> None:
        with self._lock:
            self._closed = True
            self._authenticated = False
            self._user = None
            self._pending = None
            self._buffer = ""
            self._overflow = False
