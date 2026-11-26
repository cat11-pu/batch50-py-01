"""Block-device IO budget partitioning: hierarchy, weighted sharing, loans and reclaim."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Callable


class IoBudgetError(ValueError):
    """Raised when a budget operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class GrantRecord:
    grant_id: str
    device: str
    borrower: str
    amount: int
    lenders: dict[str, int] = field(default_factory=dict)
    expires_at: str = ""
    grace: bool = False


@dataclass
class _Limit:
    limit: int
    weight: int


@dataclass
class _Usage:
    used: int = 0
    windows: dict[int, int] = field(default_factory=dict)
    last_account_bucket: int | None = None


@dataclass
class _Device:
    capacity: int
    window_seconds: int
    windows: int
    limits: dict[str, _Limit] = field(default_factory=dict)
    usage: dict[str, _Usage] = field(default_factory=dict)
    shares: dict[str, int] = field(default_factory=dict)
    grants: dict[str, GrantRecord] = field(default_factory=dict)


@dataclass
class _Group:
    parent: str | None
    weight: int


class IoBudgetPartitioner:
    """Track per-device limits, weights, loans and usage windows for a cgroup tree."""

    _SNAPSHOT_VERSION = 1

    def __init__(self, *, clock: Callable[[], object] | None = None) -> None:
        self._clock = clock
        self._lock = threading.RLock()
        self._devices: dict[str, _Device] = {}
        self._groups: dict[str, _Group] = {}
        self._next_grant_id = 1
        self._stats = {
            "borrows": 0,
            "borrow_denied": 0,
            "accounts": 0,
            "reclaimed_grants": 0,
            "denied": 0,
        }

    # ------------------------------------------------------------------
    # Validation and small helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _is_name(value: object) -> bool:
        return isinstance(value, str) and bool(value)

    def _reject(self, code: str, detail: object = None, *, denied: bool = True):
        if denied:
            self._stats["denied"] += 1
        raise IoBudgetError(code, detail)

    def _device(self, name: str) -> _Device:
        device = self._devices.get(name)
        if device is None:
            self._reject("IO_BUDGET_UNKNOWN", {"device": name})
        return device

    def _group(self, name: str) -> _Group:
        group = self._groups.get(name)
        if group is None:
            self._reject("IO_BUDGET_UNKNOWN", {"group": name})
        return group

    def _resolve_now(self, now: object = None) -> datetime:
        raw = now
        if raw is None:
            raw = self._clock() if self._clock is not None else datetime.now(timezone.utc)
        try:
            if isinstance(raw, datetime):
                value = raw
            elif isinstance(raw, (int, float)) and not isinstance(raw, bool):
                value = datetime.fromtimestamp(raw, tz=timezone.utc)
            elif isinstance(raw, str) and raw:
                value = datetime.fromisoformat(raw.replace("Z", "+00:00"))
            else:
                raise ValueError("unsupported timestamp")
        except (TypeError, ValueError, OverflowError) as exc:
            self._reject("IO_BUDGET_BAD_TIME", {"now": raw, "error": str(exc)})
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc)

    @staticmethod
    def _parse_expiry(value: str) -> datetime:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    @staticmethod
    def _bucket(moment: datetime, window_seconds: int) -> int:
        return int(moment.timestamp()) // window_seconds * window_seconds

    @staticmethod
    def _weighted_allocate(
        total: int,
        weights: dict[str, int],
        caps: dict[str, int],
    ) -> dict[str, int]:
        """Split an integer total by weight, respecting caps and deterministic ties."""

        allocations = {name: 0 for name in weights}
        if total <= 0:
            return allocations

        active = {
            name
            for name in weights
            if weights.get(name, 0) > 0 and caps.get(name, 0) > 0
        }
        remaining = total

        while remaining > 0 and active:
            total_weight = sum(weights[name] for name in active)
            if total_weight <= 0:
                break

            proposals = {
                name: remaining * weights[name] // total_weight for name in active
            }
            if sum(proposals.values()) == 0:
                order = sorted(active, key=lambda name: (-weights[name], name))
                for name in order:
                    if remaining <= 0:
                        break
                    room = caps[name] - allocations[name]
                    take = min(1, room, remaining)
                    allocations[name] += take
                    remaining -= take
                    if allocations[name] >= caps[name]:
                        active.discard(name)
                continue

            was_capped = False
            for name in list(active):
                room = caps[name] - allocations[name]
                take = min(proposals[name], room)
                allocations[name] += take
                remaining -= take
                if take < proposals[name]:
                    was_capped = True
                if allocations[name] >= caps[name]:
                    active.discard(name)

            if remaining <= 0:
                break
            if was_capped:
                continue

            # Floors leave less than one byte per active group.  The task
            # specifies weight-descending, then name order for those bytes.
            order = sorted(active, key=lambda name: (-weights[name], name))
            while remaining > 0:
                progressed = False
                for name in order:
                    if name not in active:
                        continue
                    room = caps[name] - allocations[name]
                    if room <= 0:
                        active.discard(name)
                        continue
                    allocations[name] += 1
                    remaining -= 1
                    progressed = True
                    if allocations[name] >= caps[name]:
                        active.discard(name)
                    if remaining <= 0:
                        break
                if not progressed:
                    break
            break

        return allocations

    def _borrowed_in(self, device: _Device, group: str) -> int:
        return sum(
            grant.amount
            for grant in device.grants.values()
            if grant.borrower == group
        )

    @staticmethod
    def _grant_sort_key(grant: GrantRecord) -> tuple[int, int | str]:
        if grant.grant_id.startswith("grant-") and grant.grant_id[6:].isdigit():
            return (0, int(grant.grant_id[6:]))
        return (1, grant.grant_id)

    def _borrowed_out(self, device: _Device, group: str) -> int:
        return sum(
            grant.lenders.get(group, 0)
            for grant in device.grants.values()
        )

    def _window_used(self, device: _Device, group: str) -> int:
        usage = device.usage.get(group)
        if usage is None or not usage.windows:
            return 0
        latest = max(usage.windows)
        cutoff = latest - (device.windows - 1) * device.window_seconds
        return sum(
            amount
            for bucket, amount in usage.windows.items()
            if bucket >= cutoff
        )

    def _prune_windows(self, device: _Device, usage: _Usage) -> None:
        if not usage.windows:
            return
        latest = max(usage.windows)
        cutoff = latest - (device.windows - 1) * device.window_seconds
        usage.windows = {
            bucket: amount
            for bucket, amount in usage.windows.items()
            if bucket >= cutoff
        }

    def _advance_windows(self, device: _Device, now: datetime) -> None:
        current = self._bucket(now, device.window_seconds)
        for usage in device.usage.values():
            if not usage.windows:
                continue
            latest = max(max(usage.windows), current)
            cutoff = latest - (device.windows - 1) * device.window_seconds
            usage.windows = {
                bucket: amount
                for bucket, amount in usage.windows.items()
                if bucket >= cutoff
            }

    @staticmethod
    def _effective_weights(
        device: _Device,
        now: datetime | None = None,
    ) -> dict[str, int]:
        weights = {
            group: limit.weight for group, limit in device.limits.items()
        }
        if now is None:
            return weights

        current = IoBudgetPartitioner._bucket(now, device.window_seconds)
        for group, weight in list(weights.items()):
            usage = device.usage.get(group)
            if usage is None or usage.last_account_bucket is None:
                continue
            if usage.last_account_bucket < current - 3 * device.window_seconds:
                weights[group] = weight * 2
        return weights

    def _recalculate_shares(
        self,
        device: _Device,
        *,
        now: datetime | None = None,
    ) -> set[str]:
        weights = self._effective_weights(device, now)
        caps = {group: limit.limit for group, limit in device.limits.items()}
        device.shares = self._weighted_allocate(device.capacity, weights, caps)

        if now is None:
            return set()
        current = self._bucket(now, device.window_seconds)
        return {
            group
            for group in device.limits
            if weights[group] > device.limits[group].weight
            and device.usage.get(group) is not None
            and device.usage[group].last_account_bucket is not None
            and device.usage[group].last_account_bucket
            < current - 3 * device.window_seconds
        }

    # ------------------------------------------------------------------
    # Devices and groups
    # ------------------------------------------------------------------

    def add_device(
        self,
        name: str,
        *,
        capacity: int,
        window_seconds: int = 10,
        windows: int = 3,
    ) -> None:
        with self._lock:
            if not self._is_name(name):
                self._reject("IO_BUDGET_BAD_DEVICE", {"name": name})
            if name in self._devices:
                self._reject("IO_BUDGET_EXISTS", {"device": name})
            if not self._is_int(capacity) or capacity <= 0:
                self._reject("IO_BUDGET_BAD_CAPACITY", {"capacity": capacity})
            if not self._is_int(window_seconds) or window_seconds <= 0:
                self._reject(
                    "IO_BUDGET_BAD_WINDOW", {"window_seconds": window_seconds}
                )
            if not self._is_int(windows) or windows <= 0:
                self._reject("IO_BUDGET_BAD_WINDOW", {"windows": windows})
            self._devices[name] = _Device(capacity, window_seconds, windows)

    def remove_device(self, name: str) -> dict:
        with self._lock:
            device = self._device(name)
            returned = sum(grant.amount for grant in device.grants.values())
            recalled = len(device.grants)
            if recalled:
                self._stats["reclaimed_grants"] += recalled
            del self._devices[name]
            return {
                "device": name,
                "recalled": recalled,
                "returned": returned,
            }

    def add_group(
        self,
        name: str,
        *,
        parent: str | None = None,
        weight: int = 100,
    ) -> None:
        with self._lock:
            if not self._is_name(name):
                self._reject("IO_BUDGET_BAD_GROUP", {"name": name})
            if name in self._groups:
                self._reject("IO_BUDGET_EXISTS", {"group": name})
            if not self._is_int(weight) or not 1 <= weight <= 1000:
                self._reject("IO_BUDGET_BAD_WEIGHT", {"weight": weight})
            if parent is not None:
                if not self._is_name(parent):
                    self._reject("IO_BUDGET_BAD_GROUP", {"parent": parent})
                if parent not in self._groups:
                    self._reject(
                        "IO_BUDGET_UNKNOWN", {"group": parent, "as": "parent"}
                    )
            self._groups[name] = _Group(parent=parent, weight=weight)

    def remove_group(self, name: str) -> None:
        with self._lock:
            self._group(name)
            if any(group.parent == name for group in self._groups.values()):
                self._reject("IO_BUDGET_HAS_CHILDREN", {"group": name})

            for device in self._devices.values():
                for grant in device.grants.values():
                    if grant.borrower == name or name in grant.lenders:
                        self._reject(
                            "IO_BUDGET_UNSETTLED", {"group": name}
                        )

            del self._groups[name]
            for device in self._devices.values():
                device.limits.pop(name, None)
                device.usage.pop(name, None)
                device.shares.pop(name, None)
                self._recalculate_shares(device)

    # ------------------------------------------------------------------
    # Limits and shares
    # ------------------------------------------------------------------

    def _validate_hierarchy(
        self,
        device: _Device,
        group: str,
        proposed_limit: int,
    ) -> None:
        proposed = {
            name: limit.limit for name, limit in device.limits.items()
        }
        proposed[group] = proposed_limit

        child_sum = sum(
            proposed[child]
            for child in proposed
            if self._groups[child].parent == group
        )
        if child_sum > proposed_limit:
            self._reject(
                "IO_BUDGET_HIERARCHY",
                {
                    "group": group,
                    "limit": proposed_limit,
                    "children": child_sum,
                },
            )

        parent = self._groups[group].parent
        if parent is not None and parent in proposed:
            sibling_sum = sum(
                proposed[name]
                for name in proposed
                if self._groups[name].parent == parent
            )
            if sibling_sum > proposed[parent]:
                self._reject(
                    "IO_BUDGET_HIERARCHY",
                    {
                        "group": group,
                        "limit": proposed_limit,
                        "parent": parent,
                        "parent_limit": proposed[parent],
                        "children": sibling_sum,
                    },
                )

    def set_limit(
        self,
        device_name: str,
        group_name: str,
        *,
        limit: int,
        weight: int | None = None,
    ) -> dict:
        with self._lock:
            device = self._device(device_name)
            group = self._group(group_name)
            if not self._is_int(limit) or limit <= 0:
                self._reject("IO_BUDGET_BAD_LIMIT", {"limit": limit})
            if weight is not None and (
                not self._is_int(weight) or not 1 <= weight <= 1000
            ):
                self._reject("IO_BUDGET_BAD_WEIGHT", {"weight": weight})

            self._validate_hierarchy(device, group_name, limit)

            previous = device.limits.get(group_name)
            new_weight = (
                weight
                if weight is not None
                else (previous.weight if previous is not None else group.weight)
            )
            shrink = previous is not None and limit < previous.limit

            recalled = 0
            returned = 0
            if shrink:
                borrowed_out = self._borrowed_out(device, group_name)
                used = device.usage.get(group_name, _Usage()).used
                if limit < used + borrowed_out:
                    for grant_id, grant in list(device.grants.items()):
                        portion = grant.lenders.get(group_name, 0)
                        if portion <= 0:
                            continue
                        recalled += 1
                        returned += portion
                        if portion == grant.amount:
                            del device.grants[grant_id]
                            self._stats["reclaimed_grants"] += 1
                        else:
                            lenders = dict(grant.lenders)
                            del lenders[group_name]
                            device.grants[grant_id] = GrantRecord(
                                grant_id=grant.grant_id,
                                device=grant.device,
                                borrower=grant.borrower,
                                amount=grant.amount - portion,
                                lenders=lenders,
                                expires_at=grant.expires_at,
                                grace=grant.grace,
                            )

            clamped = False
            used = device.usage.get(group_name, _Usage()).used
            if limit < used:
                limit = used
                clamped = True

            device.limits[group_name] = _Limit(limit=limit, weight=new_weight)
            self._recalculate_shares(device)
            return {
                "limit": limit,
                "weight": new_weight,
                "share": device.shares.get(group_name, 0),
                "recalled": recalled,
                "returned": returned,
                "clamped": clamped,
            }

    # ------------------------------------------------------------------
    # Accounting
    # ------------------------------------------------------------------

    def account(
        self,
        device_name: str,
        group_name: str,
        *,
        bytes_done: int,
        now: object = None,
    ) -> dict:
        with self._lock:
            device = self._device(device_name)
            self._group(group_name)
            if not self._is_int(bytes_done) or bytes_done <= 0:
                self._reject(
                    "IO_BUDGET_BAD_ACCOUNT", {"bytes_done": bytes_done}
                )

            moment = self._resolve_now(now)
            self._advance_windows(device, moment)
            self._settle_expirations(device, moment, decay=False)
            bucket = self._bucket(moment, device.window_seconds)
            usage = device.usage.setdefault(group_name, _Usage())
            usage.used += bytes_done
            usage.windows[bucket] = usage.windows.get(bucket, 0) + bytes_done
            if (
                usage.last_account_bucket is None
                or bucket > usage.last_account_bucket
            ):
                usage.last_account_bucket = bucket
            self._prune_windows(device, usage)
            self._stats["accounts"] += 1

            limit = device.limits.get(group_name)
            effective = (
                limit.limit + self._borrowed_in(device, group_name)
                if limit is not None
                else 0
            )
            return {
                "used": usage.used,
                "window_used": self._window_used(device, group_name),
                "over": max(0, usage.used - effective),
            }

    # ------------------------------------------------------------------
    # Borrowing, expiry and reclaim
    # ------------------------------------------------------------------

    def borrow(
        self,
        device_name: str,
        group_name: str,
        *,
        amount: int,
        ttl: int = 30,
        now: object = None,
    ) -> dict:
        with self._lock:
            device = self._device(device_name)
            self._group(group_name)
            if not self._is_int(amount) or amount <= 0:
                self._reject("IO_BUDGET_BAD_BORROW", {"amount": amount})
            if not self._is_int(ttl) or ttl <= 0:
                self._reject("IO_BUDGET_BAD_BORROW", {"ttl": ttl})
            if group_name not in device.limits:
                self._reject("IO_BUDGET_NO_LIMIT", {"group": group_name})

            moment = self._resolve_now(now)
            self._advance_windows(device, moment)
            self._settle_expirations(device, moment, decay=False)

            weights: dict[str, int] = {}
            caps: dict[str, int] = {}
            for name, limit in device.limits.items():
                if name == group_name:
                    continue
                spare = max(
                    0,
                    limit.limit
                    - device.usage.get(name, _Usage()).used
                    - self._borrowed_out(device, name),
                )
                if spare > 0:
                    weights[name] = limit.weight
                    caps[name] = spare

            if sum(caps.values()) < amount:
                self._stats["borrow_denied"] += 1
                self._reject(
                    "IO_BUDGET_INSUFFICIENT",
                    {"amount": amount, "available": sum(caps.values())},
                    denied=False,
                )

            allocated = self._weighted_allocate(amount, weights, caps)
            lenders = {
                name: value for name, value in allocated.items() if value > 0
            }
            grant_id = f"grant-{self._next_grant_id}"
            self._next_grant_id += 1
            expires_at = (moment + timedelta(seconds=ttl)).isoformat()
            record = GrantRecord(
                grant_id=grant_id,
                device=device_name,
                borrower=group_name,
                amount=amount,
                lenders=lenders,
                expires_at=expires_at,
            )
            device.grants[grant_id] = record
            self._stats["borrows"] += 1
            return {
                "borrower": group_name,
                "amount": amount,
                "lenders": dict(lenders),
                "expires_at": expires_at,
            }

    def _return_grant_portion(
        self,
        device: _Device,
        grant: GrantRecord,
        amount: int,
    ) -> tuple[GrantRecord | None, int]:
        amount = min(grant.amount, amount)
        if amount <= 0:
            return grant, 0
        if amount == grant.amount:
            del device.grants[grant.grant_id]
            self._stats["reclaimed_grants"] += 1
            return None, amount

        returned = self._weighted_allocate(
            amount,
            dict(grant.lenders),
            dict(grant.lenders),
        )
        new_lenders = {
            lender: grant.lenders[lender] - returned[lender]
            for lender in grant.lenders
            if grant.lenders[lender] - returned[lender] > 0
        }
        replacement = GrantRecord(
            grant_id=grant.grant_id,
            device=grant.device,
            borrower=grant.borrower,
            amount=grant.amount - amount,
            lenders=new_lenders,
            expires_at=grant.expires_at,
            grace=grant.grace,
        )
        device.grants[grant.grant_id] = replacement
        return replacement, amount

    def _settle_expirations(
        self,
        device: _Device,
        now: datetime,
        *,
        decay: bool,
    ) -> dict:
        expired: list[str] = []
        returned = 0

        due_by_borrower: dict[str, list[GrantRecord]] = {}
        for grant in device.grants.values():
            if grant.grace:
                continue
            try:
                expires = self._parse_expiry(grant.expires_at)
            except (TypeError, ValueError):
                continue
            if expires <= now:
                due_by_borrower.setdefault(grant.borrower, []).append(grant)

        for borrower, grants in due_by_borrower.items():
            limit = device.limits.get(borrower)
            base_limit = limit.limit if limit is not None else 0
            used = device.usage.get(borrower, _Usage()).used
            total_borrowed = self._borrowed_in(device, borrower)
            available_unused = max(0, base_limit + total_borrowed - used)

            for grant in sorted(grants, key=self._grant_sort_key):
                if grant.grant_id not in device.grants:
                    continue
                current = device.grants[grant.grant_id]
                give_back = min(current.amount, available_unused)
                available_unused -= give_back
                expired.append(current.grant_id)
                if give_back >= current.amount:
                    _, gave = self._return_grant_portion(
                        device, current, give_back
                    )
                    returned += gave
                else:
                    if give_back > 0:
                        replacement, gave = self._return_grant_portion(
                            device, current, give_back
                        )
                        returned += gave
                    else:
                        replacement = current
                    if replacement is not None:
                        device.grants[replacement.grant_id] = GrantRecord(
                            grant_id=replacement.grant_id,
                            device=replacement.device,
                            borrower=replacement.borrower,
                            amount=replacement.amount,
                            lenders=replacement.lenders,
                            expires_at=replacement.expires_at,
                            grace=True,
                        )

        if decay:
            by_borrower: dict[str, list[GrantRecord]] = {}
            for grant in device.grants.values():
                if grant.grace:
                    by_borrower.setdefault(grant.borrower, []).append(grant)

            for borrower, grants in by_borrower.items():
                limit = device.limits.get(borrower)
                base_limit = limit.limit if limit is not None else 0
                used = device.usage.get(borrower, _Usage()).used
                over = max(0, used - base_limit)
                grace_total = sum(grant.amount for grant in grants)
                debt_to_reduce = min(grace_total, over)
                if debt_to_reduce <= 0:
                    continue
                step = max(1, debt_to_reduce // 4)
                step = min(step, debt_to_reduce)

                for grant in sorted(grants, key=self._grant_sort_key):
                    if step <= 0:
                        break
                    current = device.grants.get(grant.grant_id)
                    if current is None:
                        continue
                    give_back = min(current.amount, step)
                    _, gave = self._return_grant_portion(
                        device, current, give_back
                    )
                    step -= gave
                    returned += gave

        return {"expired": expired, "returned": returned}

    def reclaim(self, device_name: str, *, now: object = None) -> dict:
        with self._lock:
            device = self._device(device_name)
            moment = self._resolve_now(now)
            self._advance_windows(device, moment)
            result = self._settle_expirations(device, moment, decay=True)
            return {
                "expired": result["expired"],
                "returned": result["returned"],
            }

    def rebalance(self, device_name: str, *, now: object = None) -> dict:
        with self._lock:
            device = self._device(device_name)
            moment = self._resolve_now(now)
            self._advance_windows(device, moment)
            result = self._settle_expirations(device, moment, decay=True)
            starved = self._recalculate_shares(device, now=moment)
            return {
                "shares": dict(device.shares),
                "starved": sorted(starved),
                "expired": result["expired"],
                "returned": result["returned"],
            }

    # ------------------------------------------------------------------
    # Read-only views
    # ------------------------------------------------------------------

    def status(self, device_name: str, group_name: str) -> dict:
        with self._lock:
            device = self._device(device_name)
            self._group(group_name)
            limit = device.limits.get(group_name)
            if limit is None:
                self._reject(
                    "IO_BUDGET_NO_LIMIT",
                    {"group": group_name},
                    denied=False,
                )

            borrowed_in = self._borrowed_in(device, group_name)
            borrowed_out = self._borrowed_out(device, group_name)
            used = device.usage.get(group_name, _Usage()).used
            effective = limit.limit + borrowed_in
            return {
                "limit": limit.limit,
                "weight": limit.weight,
                "share": device.shares.get(group_name, 0),
                "used": used,
                "effective_limit": effective,
                "available": max(0, effective - used - borrowed_out),
                "borrowed_in": borrowed_in,
                "borrowed_out": borrowed_out,
                "over": max(0, used - effective),
                "window_used": self._window_used(device, group_name),
            }

    def grants(self, device_name: str) -> list:
        with self._lock:
            device = self._device(device_name)
            result = []
            for grant in device.grants.values():
                result.append(
                    {
                        "grant_id": grant.grant_id,
                        "borrower": grant.borrower,
                        "amount": grant.amount,
                        "lenders": dict(grant.lenders),
                        "expires_at": grant.expires_at,
                    }
                )
            return result

    def stats(self) -> dict:
        with self._lock:
            return {
                "devices": len(self._devices),
                "groups": len(self._groups),
                "grants": sum(
                    len(device.grants) for device in self._devices.values()
                ),
                "borrows": self._stats["borrows"],
                "borrow_denied": self._stats["borrow_denied"],
                "accounts": self._stats["accounts"],
                "reclaimed_grants": self._stats["reclaimed_grants"],
                "denied": self._stats["denied"],
            }

    # ------------------------------------------------------------------
    # Persistent snapshots
    # ------------------------------------------------------------------

    def snapshot(self) -> dict:
        with self._lock:
            devices = {}
            for name, device in self._devices.items():
                devices[name] = {
                    "capacity": device.capacity,
                    "window_seconds": device.window_seconds,
                    "windows": device.windows,
                    "limits": {
                        group: {"limit": limit.limit, "weight": limit.weight}
                        for group, limit in device.limits.items()
                    },
                    "usage": {
                        group: {
                            "used": usage.used,
                            "windows": [
                                [bucket, amount]
                                for bucket, amount in sorted(
                                    usage.windows.items()
                                )
                            ],
                            "last_account_bucket": usage.last_account_bucket,
                        }
                        for group, usage in device.usage.items()
                    },
                    "shares": dict(device.shares),
                }

            groups = {
                name: {"parent": group.parent, "weight": group.weight}
                for name, group in self._groups.items()
            }
            grants = []
            for device in self._devices.values():
                for grant in device.grants.values():
                    grants.append(
                        {
                            "grant_id": grant.grant_id,
                            "device": grant.device,
                            "borrower": grant.borrower,
                            "amount": grant.amount,
                            "lenders": dict(grant.lenders),
                            "expires_at": grant.expires_at,
                            "grace": grant.grace,
                        }
                    )
            state = {
                "version": self._SNAPSHOT_VERSION,
                "devices": devices,
                "groups": groups,
                "grants": grants,
                "next_grant_id": self._next_grant_id,
                "stats": dict(self._stats),
            }
            return copy.deepcopy(state)

    @staticmethod
    def _validate_snapshot_group_tree(groups: dict[str, _Group]) -> None:
        for name, group in groups.items():
            seen = {name}
            parent = group.parent
            while parent is not None:
                if parent in seen or parent not in groups:
                    raise ValueError("invalid group tree")
                seen.add(parent)
                parent = groups[parent].parent

    def _state_from_snapshot(self, state: object):
        if not isinstance(state, dict):
            raise ValueError("snapshot must be a mapping")
        if state.get("version") != self._SNAPSHOT_VERSION:
            raise ValueError("unsupported snapshot version")
        raw_devices = state.get("devices")
        raw_groups = state.get("groups")
        raw_grants = state.get("grants")
        if not isinstance(raw_devices, dict):
            raise ValueError("devices must be a mapping")
        if not isinstance(raw_groups, dict):
            raise ValueError("groups must be a mapping")
        if not isinstance(raw_grants, list):
            raise ValueError("grants must be a list")

        groups: dict[str, _Group] = {}
        for name, raw in raw_groups.items():
            if not self._is_name(name) or not isinstance(raw, dict):
                raise ValueError("invalid group")
            parent = raw.get("parent")
            weight = raw.get("weight")
            if parent is not None and not self._is_name(parent):
                raise ValueError("invalid group parent")
            if not self._is_int(weight) or not 1 <= weight <= 1000:
                raise ValueError("invalid group weight")
            groups[name] = _Group(parent=parent, weight=weight)
        self._validate_snapshot_group_tree(groups)

        devices: dict[str, _Device] = {}
        for name, raw in raw_devices.items():
            if not self._is_name(name) or not isinstance(raw, dict):
                raise ValueError("invalid device")
            capacity = raw.get("capacity")
            window_seconds = raw.get("window_seconds")
            windows = raw.get("windows")
            if not self._is_int(capacity) or capacity <= 0:
                raise ValueError("invalid device capacity")
            if not self._is_int(window_seconds) or window_seconds <= 0:
                raise ValueError("invalid device window")
            if not self._is_int(windows) or windows <= 0:
                raise ValueError("invalid device windows")
            device = _Device(capacity, window_seconds, windows)

            raw_limits = raw.get("limits", {})
            raw_usage = raw.get("usage", {})
            raw_shares = raw.get("shares")
            if not isinstance(raw_limits, dict) or not isinstance(raw_usage, dict):
                raise ValueError("invalid device tables")

            for group, item in raw_limits.items():
                if group not in groups or not isinstance(item, dict):
                    raise ValueError("invalid limit group")
                limit = item.get("limit")
                weight = item.get("weight")
                if not self._is_int(limit) or limit <= 0:
                    raise ValueError("invalid limit")
                if not self._is_int(weight) or not 1 <= weight <= 1000:
                    raise ValueError("invalid limit weight")
                device.limits[group] = _Limit(limit=limit, weight=weight)

            for group, item in raw_usage.items():
                if group not in groups or not isinstance(item, dict):
                    raise ValueError("invalid usage group")
                used = item.get("used", 0)
                raw_windows = item.get("windows", [])
                last_bucket = item.get("last_account_bucket")
                if not self._is_int(used) or used < 0:
                    raise ValueError("invalid usage")
                if not isinstance(raw_windows, list):
                    raise ValueError("invalid usage windows")
                parsed_windows: dict[int, int] = {}
                for pair in raw_windows:
                    if (
                        not isinstance(pair, (list, tuple))
                        or len(pair) != 2
                        or not self._is_int(pair[0])
                        or not self._is_int(pair[1])
                        or pair[1] <= 0
                    ):
                        raise ValueError("invalid usage window")
                    parsed_windows[pair[0]] = (
                        parsed_windows.get(pair[0], 0) + pair[1]
                    )
                if last_bucket is not None and (
                    not self._is_int(last_bucket) or last_bucket < 0
                ):
                    raise ValueError("invalid last account bucket")
                device.usage[group] = _Usage(
                    used=used,
                    windows=parsed_windows,
                    last_account_bucket=last_bucket,
                )

            if raw_shares is not None:
                if not isinstance(raw_shares, dict):
                    raise ValueError("invalid shares")
                parsed_shares: dict[str, int] = {}
                for group, share in raw_shares.items():
                    if (
                        group not in device.limits
                        or not self._is_int(share)
                        or share < 0
                        or share > device.limits[group].limit
                    ):
                        raise ValueError("invalid share")
                    parsed_shares[group] = share
                if set(parsed_shares) != set(device.limits):
                    raise ValueError("incomplete shares")
                if sum(parsed_shares.values()) > capacity:
                    raise ValueError("shares exceed capacity")
                device.shares = parsed_shares
            devices[name] = device

        for device in devices.values():
            for group in device.limits:
                parent = groups[group].parent
                if parent is not None and parent in device.limits:
                    child_sum = sum(
                        other.limit
                        for child, other in device.limits.items()
                        if groups[child].parent == parent
                    )
                    if child_sum > device.limits[parent].limit:
                        raise ValueError("snapshot violates hierarchy")

        grants: dict[str, dict[str, GrantRecord]] = {
            name: {} for name in devices
        }
        seen_ids: set[str] = set()
        max_grant_number = 0
        for raw in raw_grants:
            if not isinstance(raw, dict):
                raise ValueError("invalid grant")
            grant_id = raw.get("grant_id")
            device_name = raw.get("device")
            borrower = raw.get("borrower")
            amount = raw.get("amount")
            lenders = raw.get("lenders")
            expires_at = raw.get("expires_at")
            grace = raw.get("grace", False)
            if (
                not self._is_name(grant_id)
                or grant_id in seen_ids
                or device_name not in devices
                or borrower not in groups
                or not self._is_int(amount)
                or amount <= 0
                or not isinstance(lenders, dict)
                or not lenders
                or not isinstance(expires_at, str)
                or not isinstance(grace, bool)
            ):
                raise ValueError("invalid grant fields")
            if borrower not in devices[device_name].limits:
                raise ValueError("grant borrower has no limit")
            parsed_lenders: dict[str, int] = {}
            for lender, portion in lenders.items():
                if (
                    lender == borrower
                    or lender not in devices[device_name].limits
                    or not self._is_int(portion)
                    or portion <= 0
                ):
                    raise ValueError("invalid grant lender")
                parsed_lenders[lender] = portion
            if sum(parsed_lenders.values()) != amount:
                raise ValueError("grant amount does not match lenders")
            try:
                self._parse_expiry(expires_at)
            except (TypeError, ValueError):
                raise ValueError("invalid grant expiry") from None
            if grant_id.startswith("grant-") and grant_id[6:].isdigit():
                max_grant_number = max(max_grant_number, int(grant_id[6:]))
            seen_ids.add(grant_id)
            grants[device_name][grant_id] = GrantRecord(
                grant_id=grant_id,
                device=device_name,
                borrower=borrower,
                amount=amount,
                lenders=parsed_lenders,
                expires_at=expires_at,
                grace=grace,
            )

        for device_name, device in devices.items():
            device.grants = grants[device_name]
            if not device.shares:
                self._recalculate_shares(device)

        next_grant_id = state.get("next_grant_id", max_grant_number + 1)
        if not self._is_int(next_grant_id) or next_grant_id <= max_grant_number:
            raise ValueError("invalid next grant id")

        raw_stats = state.get("stats", {})
        if not isinstance(raw_stats, dict):
            raise ValueError("invalid stats")
        stats = {}
        for name in (
            "borrows",
            "borrow_denied",
            "accounts",
            "reclaimed_grants",
            "denied",
        ):
            value = raw_stats.get(name, 0)
            if not self._is_int(value) or value < 0:
                raise ValueError("invalid stats counter")
            stats[name] = value

        return devices, groups, next_grant_id, stats

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                devices, groups, next_grant_id, stats = self._state_from_snapshot(
                    state
                )
            except (TypeError, ValueError, KeyError, AttributeError) as exc:
                self._reject(
                    "IO_BUDGET_SNAPSHOT_INVALID",
                    {"error": str(exc)},
                )

            self._devices = devices
            self._groups = groups
            self._next_grant_id = next_grant_id
            self._stats = stats
