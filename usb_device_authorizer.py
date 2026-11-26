"""USB device authorization: interface rules, fingerprints and temporary grants."""

from __future__ import annotations

import threading
from dataclasses import dataclass


ERR_INVALID_REQUEST = "USB_INVALID_REQUEST"
ERR_RULE_DUPLICATE = "USB_RULE_DUPLICATE"
ERR_RULE_UNKNOWN = "USB_RULE_UNKNOWN"
ERR_DEVICE_UNKNOWN = "USB_DEVICE_UNKNOWN"
ERR_NOT_AUTHORIZED = "USB_NOT_AUTHORIZED"
ERR_HANDLE_DUPLICATE = "USB_HANDLE_DUPLICATE"
ERR_SNAPSHOT_INVALID = "USB_SNAPSHOT_INVALID"


class UsbError(ValueError):
    """Raised when a USB authorization step is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Rule:
    rule_id: str
    vid: int
    pid: object
    serial: object
    interfaces: tuple
    decision: str
    ttl: object


@dataclass(frozen=True)
class DeviceRecord:
    fingerprint: str
    vid: int
    pid: int
    serial: object
    interfaces: tuple
    port_path: str
    state: str
    expires_at: object
    matched_rule: object
    prompt: bool


@dataclass(frozen=True)
class ExpireReport:
    revoked: int
    handles_closed: int


class UsbDeviceAuthorizer:
    """Decide whether a hot-plugged USB device is authorized to attach."""

    def __init__(self, *, temp_window: int = 300, rules=None) -> None:
        self.temp_window = int(temp_window)
        self._initial_rules = tuple(rules or ())
        self._lock = threading.RLock()

    def add_rule(self, rule_id: str, *, vid: int, pid=None, serial=None,
                 interfaces=(), decision: str = "allow", ttl=None) -> Rule:
        raise NotImplementedError

    def remove_rule(self, rule_id: str) -> bool:
        raise NotImplementedError

    def on_insert(self, *, vid: int, pid: int, interfaces, port_path: str,
                  serial=None, now=None) -> DeviceRecord:
        raise NotImplementedError

    def evaluate(self, fingerprint: str) -> str:
        raise NotImplementedError

    def authorize(self, fingerprint: str, *, ttl=None, now=None) -> DeviceRecord:
        raise NotImplementedError

    def revoke(self, fingerprint: str, *, now=None) -> int:
        raise NotImplementedError

    def expire(self, *, now=None) -> ExpireReport:
        raise NotImplementedError

    def attach(self, fingerprint: str, handle_id: str) -> int:
        raise NotImplementedError

    def detach(self, handle_id: str) -> int:
        raise NotImplementedError

    def handles(self, fingerprint: str) -> int:
        raise NotImplementedError

    def devices(self) -> list:
        raise NotImplementedError

    def status(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
