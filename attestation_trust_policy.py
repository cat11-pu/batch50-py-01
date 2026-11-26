"""WebAuthn attestation trust policy: AAGUID metadata, trust anchors, quarantine."""

from __future__ import annotations

import threading


class AttestationError(ValueError):
    """Refused attestation operation carrying a stable machine-readable code."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class AttestationTrustPolicy:
    """Decide which attestation formats and authenticator models a relying party accepts."""

    def __init__(self, *, rp_id: str, overlap_seconds: int = 86400,
                 minimum: str = "none", clock=None) -> None:
        self.rp_id = rp_id
        self.overlap_seconds = overlap_seconds
        self.minimum = minimum
        self._clock = clock
        self._lock = threading.RLock()

    def upsert_metadata(self, entry: dict) -> dict:
        raise NotImplementedError

    def metadata_for(self, aaguid: str) -> dict:
        raise NotImplementedError

    def set_policy(self, order, minimum: str | None = None) -> dict:
        raise NotImplementedError

    def evaluate(self, aaguid: str, fmt: str, *,
                 trust_path_root: str | None = None,
                 now: int | None = None) -> dict:
        raise NotImplementedError

    def quarantine(self, aaguid: str, reason: str, *,
                   now: int | None = None) -> dict:
        raise NotImplementedError

    def quarantined(self) -> list[str]:
        raise NotImplementedError

    def reload(self, package: dict) -> dict:
        raise NotImplementedError

    def rotate_anchor(self, aaguid: str, new_root: str, *,
                      now: int | None = None) -> dict:
        raise NotImplementedError

    def active_anchors(self, aaguid: str, *,
                       now: int | None = None) -> tuple:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
