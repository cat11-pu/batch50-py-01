"""Flash sale stock ledger.

Tracks one limited-time sale: global remaining stock, per-account purchase
quota, order reservations with a hold deadline and the actual deduction that
happens on commit.  Reservations can be released manually or expire, and the
whole ledger survives a snapshot round trip.
"""

from __future__ import annotations

import copy
import threading
import time
from dataclasses import dataclass, replace

__all__ = [
    "FlashSaleError",
    "Reservation",
    "FlashSaleStock",
]


_COUNTER_KEYS = (
    "sessions",
    "reservations",
    "committed_orders",
    "released_orders",
    "expired_orders",
    "duplicate_orders",
    "quota_refusals",
    "stock_refusals",
)

_ORDER_STATUSES = frozenset({"held", "committed", "released", "expired"})


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


def _is_positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _is_nonnegative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


class FlashSaleStock:
    """Reserve, commit, release and expire orders for one flash sale."""

    def __init__(self, *, total_stock: int, per_account_limit: int,
                 hold_ttl: int) -> None:
        self.total_stock = total_stock
        self.per_account_limit = per_account_limit
        self.hold_ttl = hold_ttl
        self._lock = threading.RLock()
        self._session: dict | None = None
        self._orders: dict[str, Reservation] = {}
        self._stock = 0
        self._quota_used: dict[str, int] = {}
        self._counters = {key: 0 for key in _COUNTER_KEYS}

    @staticmethod
    def _clock(now: int | None) -> int:
        return int(time.time()) if now is None else now

    def _validate_config(self) -> None:
        if (
            not _is_positive_int(self.total_stock)
            or not _is_positive_int(self.per_account_limit)
            or not _is_positive_int(self.hold_ttl)
        ):
            raise FlashSaleError(
                "FLASH_INVALID_CONFIG",
                {
                    "total_stock": self.total_stock,
                    "per_account_limit": self.per_account_limit,
                    "hold_ttl": self.hold_ttl,
                },
            )

    def _session_record_locked(self) -> dict:
        if self._session is None:
            raise FlashSaleError("FLASH_SESSION_CLOSED", "no active sale")
        return {
            "session_id": self._session["session_id"],
            "total_stock": self.total_stock,
            "per_account_limit": self.per_account_limit,
            "hold_ttl": self.hold_ttl,
            "status": self._session["status"],
            "closed_at": self._session["closed_at"],
        }

    def _expire_one_locked(self, reservation: Reservation) -> Reservation:
        expired = replace(reservation, status="expired")
        self._orders[reservation.order_id] = expired
        self._stock += reservation.qty

        remaining = self._quota_used.get(reservation.account, 0)
        remaining -= reservation.qty
        if remaining < 0:
            raise RuntimeError("quota ledger became negative")
        if remaining:
            self._quota_used[reservation.account] = remaining
        else:
            self._quota_used.pop(reservation.account, None)

        self._counters["expired_orders"] += 1
        return expired

    def open_session(self, session_id: str, *,
                     now: int | None = None) -> dict:
        """Open the sale session with the configured stock and quota."""
        opened_at = self._clock(now)
        with self._lock:
            if self._session is not None:
                raise FlashSaleError(
                    "FLASH_SESSION_ACTIVE", self._session["session_id"]
                )
            if not isinstance(session_id, str) or not session_id:
                raise FlashSaleError("FLASH_INVALID_REQUEST", "session_id")
            self._validate_config()

            self._session = {
                "session_id": session_id,
                "status": "open",
                "opened_at": opened_at,
                "closed_at": None,
            }
            self._orders = {}
            self._stock = self.total_stock
            self._quota_used = {}
            self._counters = {key: 0 for key in _COUNTER_KEYS}
            self._counters["sessions"] = 1
            return self._session_record_locked()

    def close_session(self, *, now: int | None = None) -> dict:
        """Close the sale session for new reservations."""
        closed_at = self._clock(now)
        with self._lock:
            if self._session is None or self._session["status"] != "open":
                raise FlashSaleError("FLASH_SESSION_CLOSED", "already closed")
            self._session["status"] = "closed"
            self._session["closed_at"] = closed_at
            return self._session_record_locked()

    def reserve(self, order_id: str, account: str, qty: int, *,
                now: int | None = None) -> Reservation:
        """Hold stock and quota for an order until the hold deadline."""
        if not isinstance(order_id, str) or not order_id:
            raise FlashSaleError("FLASH_INVALID_REQUEST", "order_id")
        if not isinstance(account, str) or not account:
            raise FlashSaleError("FLASH_INVALID_REQUEST", "account")
        if not _is_positive_int(qty):
            raise FlashSaleError("FLASH_INVALID_REQUEST", "qty")

        created_at = self._clock(now)
        with self._lock:
            if order_id in self._orders:
                self._counters["duplicate_orders"] += 1
                raise FlashSaleError("FLASH_DUPLICATE_ORDER", order_id)

            if self._session is None or self._session["status"] != "open":
                raise FlashSaleError("FLASH_SESSION_CLOSED", "sale is closed")

            if qty > self._stock:
                self._counters["stock_refusals"] += 1
                raise FlashSaleError(
                    "FLASH_INSUFFICIENT_STOCK",
                    {"requested": qty, "available": self._stock},
                )

            used = self._quota_used.get(account, 0)
            if used + qty > self.per_account_limit:
                self._counters["quota_refusals"] += 1
                raise FlashSaleError(
                    "FLASH_QUOTA_EXCEEDED",
                    {
                        "requested": qty,
                        "available": self.per_account_limit - used,
                    },
                )

            reservation = Reservation(
                order_id=order_id,
                account=account,
                qty=qty,
                status="held",
                created_at=created_at,
                expires_at=created_at + self.hold_ttl,
            )
            self._orders[order_id] = reservation
            self._stock -= qty
            self._quota_used[account] = used + qty
            self._counters["reservations"] += 1
            return reservation

    def commit(self, order_id: str, *,
               now: int | None = None) -> Reservation:
        """Turn a held reservation into an actual deduction."""
        committed_at = self._clock(now)
        with self._lock:
            reservation = self._orders.get(order_id)
            if reservation is None:
                raise FlashSaleError("FLASH_UNKNOWN_ORDER", order_id)
            if reservation.status == "committed":
                raise FlashSaleError("FLASH_ALREADY_COMMITTED", order_id)
            if reservation.status != "held":
                raise FlashSaleError("FLASH_NOT_HELD", order_id)
            if committed_at >= reservation.expires_at:
                self._expire_one_locked(reservation)
                raise FlashSaleError("FLASH_NOT_HELD", order_id)

            committed = replace(reservation, status="committed")
            self._orders[order_id] = committed
            self._counters["committed_orders"] += 1
            return committed

    def release(self, order_id: str, *,
                now: int | None = None) -> Reservation:
        """Cancel a held reservation and give stock and quota back."""
        released_at = self._clock(now)
        with self._lock:
            reservation = self._orders.get(order_id)
            if reservation is None:
                raise FlashSaleError("FLASH_UNKNOWN_ORDER", order_id)
            if reservation.status != "held":
                raise FlashSaleError("FLASH_NOT_HELD", order_id)
            if released_at >= reservation.expires_at:
                self._expire_one_locked(reservation)
                raise FlashSaleError("FLASH_NOT_HELD", order_id)

            released = replace(reservation, status="released")
            self._orders[order_id] = released
            self._stock += reservation.qty

            remaining = self._quota_used.get(reservation.account, 0)
            remaining -= reservation.qty
            if remaining < 0:
                raise RuntimeError("quota ledger became negative")
            if remaining:
                self._quota_used[reservation.account] = remaining
            else:
                self._quota_used.pop(reservation.account, None)

            self._counters["released_orders"] += 1
            return released

    def expire_reservations(self, *, now: int | None = None) -> int:
        """Release every held reservation whose hold deadline has passed."""
        expired_at = self._clock(now)
        with self._lock:
            due = [
                reservation
                for reservation in self._orders.values()
                if (
                    reservation.status == "held"
                    and expired_at >= reservation.expires_at
                )
            ]
            for reservation in due:
                self._expire_one_locked(reservation)
            return len(due)

    def stock_of(self) -> int:
        """Return the stock that is neither held nor committed."""
        with self._lock:
            return self._stock

    def quota_of(self, account: str) -> int:
        """Return the quota an account can still reserve."""
        with self._lock:
            if self._session is None:
                return 0
            return self.per_account_limit - self._quota_used.get(account, 0)

    def order_of(self, order_id: str) -> Reservation:
        """Return one reservation by order id."""
        with self._lock:
            reservation = self._orders.get(order_id)
            if reservation is None:
                raise FlashSaleError("FLASH_UNKNOWN_ORDER", order_id)
            return reservation

    def snapshot(self) -> dict:
        """Return a deep copy of the session, orders and counters."""
        with self._lock:
            session = None
            if self._session is not None:
                session = {
                    "session_id": self._session["session_id"],
                    "opened_at": self._session["opened_at"],
                    "total_stock": self.total_stock,
                    "per_account_limit": self.per_account_limit,
                    "hold_ttl": self.hold_ttl,
                    "status": self._session["status"],
                    "closed_at": self._session["closed_at"],
                }

            orders = {
                order_id: {
                    "order_id": reservation.order_id,
                    "account": reservation.account,
                    "qty": reservation.qty,
                    "status": reservation.status,
                    "created_at": reservation.created_at,
                    "expires_at": reservation.expires_at,
                }
                for order_id, reservation in self._orders.items()
            }

            held_by_account: dict[str, int] = {}
            committed_by_account: dict[str, int] = {}
            held_total = 0
            committed_total = 0
            for reservation in self._orders.values():
                if reservation.status == "held":
                    held_total += reservation.qty
                    held_by_account[reservation.account] = (
                        held_by_account.get(reservation.account, 0)
                        + reservation.qty
                    )
                elif reservation.status == "committed":
                    committed_total += reservation.qty
                    committed_by_account[reservation.account] = (
                        committed_by_account.get(reservation.account, 0)
                        + reservation.qty
                    )

            accounts = {
                reservation.account for reservation in self._orders.values()
            }
            quotas = {}
            for account in accounts:
                held = held_by_account.get(account, 0)
                committed = committed_by_account.get(account, 0)
                quotas[account] = {
                    "held": held,
                    "committed": committed,
                    "available": self.per_account_limit - held - committed,
                }

            return copy.deepcopy(
                {
                    "version": 1,
                    "config": {
                        "total_stock": self.total_stock,
                        "per_account_limit": self.per_account_limit,
                        "hold_ttl": self.hold_ttl,
                    },
                    "session": session,
                    "orders": orders,
                    "stock": {
                        "total": self.total_stock,
                        "available": self._stock,
                        "held": held_total,
                        "committed": committed_total,
                    },
                    "quotas": quotas,
                    "counters": dict(self._counters),
                }
            )

    @staticmethod
    def _snapshot_invalid(detail: object) -> None:
        raise FlashSaleError("FLASH_SNAPSHOT_INVALID", detail)

    @classmethod
    def _decode_snapshot(cls, state: object) -> tuple:
        if not isinstance(state, dict):
            cls._snapshot_invalid("snapshot must be a mapping")
        if state.get("version") != 1:
            cls._snapshot_invalid("unsupported snapshot version")

        config = state.get("config")
        if not isinstance(config, dict):
            cls._snapshot_invalid("config")
        total_stock = config.get("total_stock")
        per_account_limit = config.get("per_account_limit")
        hold_ttl = config.get("hold_ttl")
        if (
            not _is_positive_int(total_stock)
            or not _is_positive_int(per_account_limit)
            or not _is_positive_int(hold_ttl)
        ):
            cls._snapshot_invalid("invalid config")

        raw_session = state.get("session")
        session = None
        if raw_session is not None:
            if not isinstance(raw_session, dict):
                cls._snapshot_invalid("session")
            session_id = raw_session.get("session_id")
            opened_at = raw_session.get("opened_at")
            status = raw_session.get("status")
            closed_at = raw_session.get("closed_at")
            if not isinstance(session_id, str) or not session_id:
                cls._snapshot_invalid("session_id")
            if (
                not isinstance(opened_at, int)
                or isinstance(opened_at, bool)
                or status not in {"open", "closed"}
            ):
                cls._snapshot_invalid("session status")
            if status == "open":
                if closed_at is not None:
                    cls._snapshot_invalid("open session closed_at")
            elif not isinstance(closed_at, int) or isinstance(closed_at, bool):
                cls._snapshot_invalid("closed session closed_at")
            for key, value in (
                ("total_stock", total_stock),
                ("per_account_limit", per_account_limit),
                ("hold_ttl", hold_ttl),
            ):
                if raw_session.get(key) != value:
                    cls._snapshot_invalid(f"session {key}")
            session = {
                "session_id": session_id,
                "opened_at": opened_at,
                "status": status,
                "closed_at": closed_at,
            }

        raw_orders = state.get("orders")
        if not isinstance(raw_orders, dict):
            cls._snapshot_invalid("orders")
        orders: dict[str, Reservation] = {}
        held_by_account: dict[str, int] = {}
        committed_by_account: dict[str, int] = {}
        held_total = 0
        committed_total = 0
        committed_count = 0
        released_count = 0
        expired_count = 0
        for order_id, raw_order in raw_orders.items():
            if not isinstance(order_id, str) or not order_id:
                cls._snapshot_invalid("order key")
            if not isinstance(raw_order, dict):
                cls._snapshot_invalid(f"order {order_id}")
            account = raw_order.get("account")
            qty = raw_order.get("qty")
            status = raw_order.get("status")
            created_at = raw_order.get("created_at")
            expires_at = raw_order.get("expires_at")
            if raw_order.get("order_id") != order_id:
                cls._snapshot_invalid(f"order id {order_id}")
            if not isinstance(account, str) or not account:
                cls._snapshot_invalid(f"account {order_id}")
            if not _is_positive_int(qty):
                cls._snapshot_invalid(f"qty {order_id}")
            if status not in _ORDER_STATUSES:
                cls._snapshot_invalid(f"status {order_id}")
            if (
                not isinstance(created_at, int)
                or isinstance(created_at, bool)
                or not isinstance(expires_at, int)
                or isinstance(expires_at, bool)
                or expires_at != created_at + hold_ttl
            ):
                cls._snapshot_invalid(f"times {order_id}")

            reservation = Reservation(
                order_id=order_id,
                account=account,
                qty=qty,
                status=status,
                created_at=created_at,
                expires_at=expires_at,
            )
            orders[order_id] = reservation
            if status == "held":
                held_total += qty
                held_by_account[account] = (
                    held_by_account.get(account, 0) + qty
                )
            elif status == "committed":
                committed_total += qty
                committed_by_account[account] = (
                    committed_by_account.get(account, 0) + qty
                )
                committed_count += 1
            elif status == "released":
                released_count += 1
            else:
                expired_count += 1

        raw_stock = state.get("stock")
        if not isinstance(raw_stock, dict):
            cls._snapshot_invalid("stock")
        if raw_stock.get("total") != total_stock:
            cls._snapshot_invalid("stock total")
        if (
            raw_stock.get("held") != held_total
            or raw_stock.get("committed") != committed_total
        ):
            cls._snapshot_invalid("stock quantities")
        available_stock = raw_stock.get("available")
        if not _is_nonnegative_int(available_stock):
            cls._snapshot_invalid("stock available")
        if session is None:
            if available_stock != 0:
                cls._snapshot_invalid("stock available before open")
        elif available_stock != total_stock - held_total - committed_total:
            cls._snapshot_invalid("stock available")

        raw_quotas = state.get("quotas")
        if not isinstance(raw_quotas, dict):
            cls._snapshot_invalid("quotas")
        expected_accounts = {
            reservation.account for reservation in orders.values()
        }
        quota_used: dict[str, int] = {}
        for account in expected_accounts:
            raw_quota = raw_quotas.get(account)
            held = held_by_account.get(account, 0)
            committed = committed_by_account.get(account, 0)
            used = held + committed
            available = per_account_limit - used
            if available < 0:
                cls._snapshot_invalid(f"quota overflow {account}")
            if not isinstance(raw_quota, dict):
                cls._snapshot_invalid(f"quota {account}")
            if (
                raw_quota.get("held") != held
                or raw_quota.get("committed") != committed
                or raw_quota.get("available") != available
            ):
                cls._snapshot_invalid(f"quota values {account}")
            quota_used[account] = used
        for account, raw_quota in raw_quotas.items():
            if not isinstance(account, str) or not isinstance(raw_quota, dict):
                cls._snapshot_invalid("quota entry")
            if account not in expected_accounts:
                if (
                    raw_quota.get("held") != 0
                    or raw_quota.get("committed") != 0
                    or raw_quota.get("available") != per_account_limit
                ):
                    cls._snapshot_invalid(f"unexpected quota {account}")

        raw_counters = state.get("counters")
        if not isinstance(raw_counters, dict):
            cls._snapshot_invalid("counters")
        counters = {}
        for key in _COUNTER_KEYS:
            value = raw_counters.get(key)
            if not _is_nonnegative_int(value):
                cls._snapshot_invalid(f"counter {key}")
            counters[key] = value
        if counters["sessions"] != (1 if session is not None else 0):
            cls._snapshot_invalid("sessions counter")
        if session is None and orders:
            cls._snapshot_invalid("orders without a session")
        if counters["reservations"] != len(orders):
            cls._snapshot_invalid("reservations counter")
        if counters["committed_orders"] != committed_count:
            cls._snapshot_invalid("committed counter")
        if counters["released_orders"] != released_count:
            cls._snapshot_invalid("released counter")
        if counters["expired_orders"] != expired_count:
            cls._snapshot_invalid("expired counter")

        return (
            total_stock,
            per_account_limit,
            hold_ttl,
            session,
            orders,
            available_stock,
            quota_used,
            counters,
        )

    def restore(self, state: dict) -> None:
        """Replace ledger state with a snapshot, validating its structure."""
        try:
            detached_state = copy.deepcopy(state)
        except Exception as exc:
            raise FlashSaleError("FLASH_SNAPSHOT_INVALID", "not copyable") from exc

        with self._lock:
            (
                total_stock,
                per_account_limit,
                hold_ttl,
                session,
                orders,
                available_stock,
                quota_used,
                counters,
            ) = self._decode_snapshot(detached_state)

            self.total_stock = total_stock
            self.per_account_limit = per_account_limit
            self.hold_ttl = hold_ttl
            self._session = session
            self._orders = orders
            self._stock = available_stock
            self._quota_used = quota_used
            self._counters = counters

    def stats(self) -> dict:
        """Return cumulative counters for reservations and refusals."""
        with self._lock:
            return dict(self._counters)
