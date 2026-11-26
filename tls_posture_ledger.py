"""TLS posture ledger: per-round endpoint records, downgrade regressions, waivers and history."""

from __future__ import annotations


class LedgerError(ValueError):
    """Raised when a ledger operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


PROTOCOLS = ("TLSv1.0", "TLSv1.1", "TLSv1.2", "TLSv1.3")

STATE_OPEN = "open"
STATE_WAIVED = "waived"
STATE_RESOLVED = "resolved"

KIND_DOWNGRADE = "protocol_downgrade"
KIND_SUITE_REMOVED = "suite_removed"
KIND_ISSUER_CHANGED = "cert_issuer_changed"
KIND_CERT_EXPIRING = "cert_expiring"


class TlsPostureLedger:
    """Keep the newest scan rounds and turn posture changes into tracked regressions."""

    def __init__(self, *, history_rounds: int = 3,
                 cert_warning_days: int = 30) -> None:
        self.history_rounds = history_rounds
        self.cert_warning_days = cert_warning_days

    def record_scan(self, round_no: int, *, endpoints, now: int) -> dict:
        raise NotImplementedError

    def diff_round(self, round_no: int) -> dict:
        raise NotImplementedError

    def regress(self, round_no: int) -> tuple:
        raise NotImplementedError

    def waive(self, regression_id: str, *, until: int, reason: str,
              now: int) -> dict:
        raise NotImplementedError

    def resolve(self, regression_id: str, *, now: int) -> dict:
        raise NotImplementedError

    def regressions(self, *, state: str | None = None) -> tuple:
        raise NotImplementedError

    def history(self, *, endpoint: str | None = None) -> tuple:
        raise NotImplementedError

    def endpoint_state(self, endpoint: str) -> dict:
        raise NotImplementedError

    def summary(self, round_no: int) -> dict:
        raise NotImplementedError

    def sweep(self, *, now: int) -> dict:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError
