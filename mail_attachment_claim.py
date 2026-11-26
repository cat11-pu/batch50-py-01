"""In-game mail attachments: capacity-checked claiming, expiry returns, idempotency.

Each mail carries an ordered list of attachments.  Claiming one attachment or the
whole mail reserves bag slots, marks the attachment as taken and hands the item to
the player.  When a mail expires, only the attachments that were never claimed are
returned to the sender; already claimed items are never returned twice.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "MailError",
    "AttachmentView",
    "MailView",
    "ClaimResult",
    "ReturnRecord",
    "ExpiryResult",
    "BagView",
    "MailAttachmentClaim",
]


class MailError(ValueError):
    """Raised when a mail or bag operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AttachmentView:
    """One attachment slot of an in-game mail."""

    attachment_id: int
    item_id: str
    count: int
    slots: int
    claimed: bool


@dataclass(frozen=True)
class MailView:
    """Immutable view of one mail."""

    mail_id: str
    sender: str
    recipient: str
    status: str
    attachments: tuple[AttachmentView, ...]
    expires_at: int | None
    claimed_count: int
    unclaimed_count: int


@dataclass(frozen=True)
class ClaimResult:
    """Outcome of one claim call."""

    mail_id: str
    player: str
    claimed: tuple[AttachmentView, ...]
    slots_used: int
    status: str


@dataclass(frozen=True)
class ReturnRecord:
    """One attachment returned to the sender when a mail expires."""

    return_id: str
    mail_id: str
    sender: str
    item_id: str
    count: int
    slots: int
    returned_at: int


@dataclass(frozen=True)
class ExpiryResult:
    """Outcome of expiring one mail."""

    mail_id: str
    returned: tuple[ReturnRecord, ...]
    status: str


@dataclass(frozen=True)
class BagView:
    """Immutable view of one player's bag."""

    player: str
    used_slots: int
    free_slots: int
    items: tuple[tuple[str, int], ...]


class MailAttachmentClaim:
    """Deliver mail attachments into player bags with expiry returns."""

    def __init__(self, *, bag_slots: int = 40, max_attachments: int = 5,
                 default_ttl_ms: int | None = None, bag_writer=None) -> None:
        self.bag_slots = bag_slots
        self.max_attachments = max_attachments
        self.default_ttl_ms = default_ttl_ms
        self.bag_writer = bag_writer
        self._lock = threading.RLock()

    def send_mail(self, mail_id: str, *, sender: str, recipient: str,
                  attachments, sent_at: int,
                  expires_at: int | None = None) -> MailView:
        raise NotImplementedError

    def claim_attachment(self, mail_id: str, *, player: str, attachment_id: int,
                         now: int) -> ClaimResult:
        raise NotImplementedError

    def claim_all(self, mail_id: str, *, player: str, now: int) -> ClaimResult:
        raise NotImplementedError

    def expire_mail(self, mail_id: str, *, now: int) -> ExpiryResult:
        raise NotImplementedError

    def expire_due(self, *, now: int) -> tuple[ExpiryResult, ...]:
        raise NotImplementedError

    def mail_view(self, mail_id: str) -> MailView:
        raise NotImplementedError

    def inbox(self, player: str) -> tuple[MailView, ...]:
        raise NotImplementedError

    def bag_of(self, player: str) -> BagView:
        raise NotImplementedError

    def returns_for(self, sender: str) -> tuple[ReturnRecord, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
