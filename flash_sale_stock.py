"""Flash sale stock ledger.

Tracks one limited-time sale: global remaining stock, per-account purchase
quota, order reservations with a hold deadline and the actual deduction that
happens on commit.  Reservations can be released manually or expire, and the
whole ledger survives a snapshot round trip.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "FlashSaleError",
    "Reservation",
    "FlashSaleStock",
]


class FlashSaleError(ValueError):
    """Raised when a flash sale operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Reservation:
    """One order reservation against the sale stock."""

    order_id: str
    account: str
    qty: int
    status: str
    created_at: int
    expires_at: int


class FlashSaleStock:
    """Reserve, commit, release and expire orders for one flash sale."""

    def __init__(self, *, total_stock: int, per_account_limit: int,
                 hold_ttl: int) -> None:
        self.total_stock = total_stock
        self.per_account_limit = per_account_limit
        self.hold_ttl = hold_ttl
        self._lock = threading.RLock()

    def open_session(self, session_id: str, *,
                     now: int | None = None) -> dict:
        """Open the sale session with the configured stock and quota."""
        raise NotImplementedError

    def close_session(self, *, now: int | None = None) -> dict:
        """Close the sale session for new reservations."""
        raise NotImplementedError

    def reserve(self, order_id: str, account: str, qty: int, *,
                now: int | None = None) -> Reservation:
        """Hold stock and quota for an order until the hold deadline."""
        raise NotImplementedError

    def commit(self, order_id: str, *,
               now: int | None = None) -> Reservation:
        """Turn a held reservation into an actual deduction."""
        raise NotImplementedError

    def release(self, order_id: str, *,
                now: int | None = None) -> Reservation:
        """Cancel a held reservation and give stock and quota back."""
        raise NotImplementedError

    def expire_reservations(self, *, now: int | None = None) -> int:
        """Release every held reservation whose hold deadline has passed."""
        raise NotImplementedError

    def stock_of(self) -> int:
        """Return the stock that is neither held nor committed."""
        raise NotImplementedError

    def quota_of(self, account: str) -> int:
        """Return the quota an account can still reserve."""
        raise NotImplementedError

    def order_of(self, order_id: str) -> Reservation:
        """Return one reservation by order id."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a deep copy of the session, orders and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Replace ledger state with a snapshot, validating its structure."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative counters for reservations and refusals."""
        raise NotImplementedError
