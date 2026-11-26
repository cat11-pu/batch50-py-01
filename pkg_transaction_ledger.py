"""Package transaction ledger: global lock, per-step intent journal, crash recovery."""

from __future__ import annotations

import copy
import re
import threading
from dataclasses import dataclass


class PkgError(ValueError):
    """Raised when a package transaction is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class StepRecord:
    seq: int
    op: str
    package: str
    from_version: str | None
    to_version: str | None
    state: str
    intent_at: int | None
    applied_at: int | None


@dataclass(frozen=True)
class TransactionView:
    txid: str
    owner: str
    state: str
    step_total: int
    applied: int
    lock_expires_at: int | None


_VERSION_RE = re.compile(r"[0-9]+(?:\.[0-9]+)*")
_OPERATIONS = frozenset({"install", "remove", "upgrade"})
_CLOSED_STATES = frozenset({"committed", "rolled_back", "abandoned"})
_STEP_STATES = frozenset({"pending", "staged", "applied", "reverted"})
_STATS_KEYS = (
    "begun",
    "staged",
    "applied",
    "committed",
    "aborted",
    "recovered",
    "seized",
    "reverted",
)
_SNAPSHOT_VERSION = 1
_SNAPSHOT_KEYS = frozenset(
    {
        "version",
        "installed",
        "transactions",
        "steps",
        "lock",
        "counters",
        "next_tx",
    }
)


def _valid_version(version: object) -> bool:
    return isinstance(version, str) and _VERSION_RE.fullmatch(version) is not None


def _version_tuple(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


class PkgTransactionLedger:
    """Serialize package changes behind one global lock and an intent journal."""

    def __init__(self, *, lock_lease_ms: int = 30000) -> None:
        self.lock_lease_ms = lock_lease_ms
        self._state_lock = threading.RLock()
        self._installed: dict[str, str] = {}
        self._transactions: dict[str, dict] = {}
        self._steps: dict[str, list[dict]] = {}
        self._global_lock: dict | None = None
        self._next_tx = 1
        self._stats = {key: 0 for key in _STATS_KEYS}
        self._restored_resume: set[str] = set()

    def seed_installed(self, package: str, version: str) -> None:
        with self._state_lock:
            self._installed[package] = version

    def installed(self, package: str | None = None):
        with self._state_lock:
            if package is None:
                return dict(self._installed)
            return self._installed.get(package)

    def begin(
        self,
        owner: str,
        requests,
        *,
        now: int,
        lease_ms: int | None = None,
    ) -> str:
        with self._state_lock:
            planned_steps = self._plan_requests(owner, requests)

            if self._global_lock is not None:
                expires_at = self._global_lock["expires_at"]
                if expires_at > now:
                    raise PkgError(
                        "PKG_LOCK_HELD",
                        {
                            "owner": self._global_lock["owner"],
                            "txid": self._global_lock["txid"],
                            "expires_at": expires_at,
                        },
                    )
                self._seize_expired_lock_locked(now)

            txid = f"tx-{self._next_tx}"
            self._next_tx += 1
            lease = self.lock_lease_ms if lease_ms is None else lease_ms
            expires_at = now + lease

            self._transactions[txid] = {
                "txid": txid,
                "owner": owner,
                "state": "open",
                "step_total": len(planned_steps),
                "applied": 0,
                "created_at": now,
            }
            self._steps[txid] = planned_steps
            self._global_lock = {
                "owner": owner,
                "txid": txid,
                "expires_at": expires_at,
            }
            self._stats["begun"] += 1
            return txid

    def stage(self, txid: str, *, now: int) -> StepRecord:
        with self._state_lock:
            transaction = self._transaction_or_raise(txid)
            self._ensure_open_for_progress(transaction)
            steps = self._steps[txid]

            head = None
            for step in steps:
                if step["state"] == "applied":
                    continue
                if step["state"] == "reverted":
                    raise PkgError("PKG_TX_CLOSED", {"txid": txid})
                head = step
                break

            if head is None:
                raise PkgError("PKG_STEP_STATE", {"txid": txid, "seq": None})
            if head["state"] == "staged":
                raise PkgError(
                    "PKG_STEP_STATE",
                    {"txid": txid, "seq": head["seq"], "state": head["state"]},
                )

            head["state"] = "staged"
            head["intent_at"] = now
            self._stats["staged"] += 1
            return StepRecord(**head)

    def commit(self, txid: str, *, now: int, limit: int | None = None) -> dict:
        with self._state_lock:
            transaction = self._transaction_or_raise(txid)
            self._ensure_open_for_progress(transaction)
            if limit is not None and (
                isinstance(limit, bool) or not isinstance(limit, int) or limit < 0
            ):
                raise PkgError("PKG_INVALID_REQUEST", {"limit": limit})

            steps = self._steps[txid]
            transaction["state"] = "applying"
            advanced = 0

            for step in steps:
                if step["state"] == "applied":
                    continue
                if step["state"] == "reverted":
                    raise PkgError("PKG_TX_CLOSED", {"txid": txid})
                if limit is not None and advanced >= limit:
                    break

                if step["state"] == "pending":
                    step["state"] = "staged"
                    step["intent_at"] = now
                    self._stats["staged"] += 1

                self._apply_step_locked(step)
                step["state"] = "applied"
                step["applied_at"] = now
                self._stats["applied"] += 1
                advanced += 1

            applied = sum(step["state"] == "applied" for step in steps)
            transaction["applied"] = applied
            total = len(steps)

            if applied == total:
                restored_resume = txid in self._restored_resume
                self._restored_resume.discard(txid)
                self._mark_committed_locked(transaction, now, count_stat=True)
                if restored_resume:
                    journal_packages = {
                        step["package"]
                        for tx_steps in self._steps.values()
                        for step in tx_steps
                    }
                    self._installed = {
                        package: version
                        for package, version in self._installed.items()
                        if package in journal_packages
                    }
                return {"state": "committed", "applied": total, "total": total}

            transaction["state"] = "applying"
            return {"state": "applying", "applied": applied, "total": total}

    def abort(self, txid: str, *, now: int) -> int:
        with self._state_lock:
            transaction = self._transaction_or_raise(txid)
            state = transaction["state"]
            if state == "committed":
                raise PkgError(
                    "PKG_IRREVERSIBLE",
                    {"txid": txid, "state": state},
                )
            if state == "rolled_back":
                return 0
            if state == "abandoned":
                raise PkgError("PKG_TX_CLOSED", {"txid": txid, "state": state})

            steps = self._steps[txid]
            reverted = self._revert_applied_steps_locked(steps)
            transaction["applied"] = sum(
                step["state"] in {"applied", "reverted"} for step in steps
            )
            transaction["state"] = "rolled_back"
            transaction["aborted_at"] = now
            self._stats["aborted"] += 1
            self._release_lock_locked(txid)
            return reverted

    def recover(self, txid: str, *, now: int) -> dict:
        with self._state_lock:
            transaction = self._transaction_or_raise(txid)
            if transaction["state"] in _CLOSED_STATES:
                raise PkgError(
                    "PKG_TX_CLOSED",
                    {"txid": txid, "state": transaction["state"]},
                )

            steps = self._steps[txid]
            applied = sum(step["state"] == "applied" for step in steps)
            total = len(steps)
            self._stats["recovered"] += 1

            if applied == total:
                transaction["applied"] = total
                self._mark_committed_locked(transaction, now, count_stat=True)
                return {"outcome": "committed", "reverted": 0, "applied": applied}

            if applied == 0:
                transaction["state"] = "abandoned"
                transaction["abandoned_at"] = now
                self._release_lock_locked(txid)
                return {"outcome": "discarded", "reverted": 0, "applied": 0}

            reverted = self._revert_applied_steps_locked(steps)
            transaction["applied"] = applied
            transaction["state"] = "rolled_back"
            transaction["recovered_at"] = now
            self._release_lock_locked(txid)
            return {
                "outcome": "rolled_back",
                "reverted": reverted,
                "applied": applied,
            }

    def holders(self):
        with self._state_lock:
            if self._global_lock is None:
                return None
            return dict(self._global_lock)

    def status(self, txid: str) -> TransactionView:
        with self._state_lock:
            transaction = self._transaction_or_raise(txid)
            expires_at = None
            if self._global_lock is not None and self._global_lock["txid"] == txid:
                expires_at = self._global_lock["expires_at"]
            return TransactionView(
                txid=transaction["txid"],
                owner=transaction["owner"],
                state=transaction["state"],
                step_total=transaction["step_total"],
                applied=transaction["applied"],
                lock_expires_at=expires_at,
            )

    def journal(self, txid: str) -> tuple[StepRecord, ...]:
        with self._state_lock:
            self._transaction_or_raise(txid)
            return tuple(StepRecord(**step) for step in self._steps[txid])

    def snapshot(self) -> dict:
        with self._state_lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "installed": copy.deepcopy(self._installed),
                "transactions": copy.deepcopy(self._transactions),
                "steps": copy.deepcopy(self._steps),
                "lock": copy.deepcopy(self._global_lock),
                "counters": copy.deepcopy(self._stats),
                "next_tx": self._next_tx,
            }

    def restore(self, state: dict) -> None:
        with self._state_lock:
            restored = self._parse_snapshot(state)
            (
                installed,
                transactions,
                steps,
                global_lock,
                counters,
                next_tx,
            ) = restored
            self._installed = installed
            self._transactions = transactions
            self._steps = steps
            self._global_lock = global_lock
            self._stats = counters
            self._next_tx = next_tx
            self._restored_resume = {
                restored_txid
                for restored_txid, transaction in self._transactions.items()
                if transaction.get("state") not in _CLOSED_STATES
            }

    def stats(self) -> dict:
        with self._state_lock:
            return dict(self._stats)

    def _plan_requests(self, owner: object, requests: object) -> list[dict]:
        if not isinstance(owner, str) or not owner.strip():
            raise PkgError("PKG_INVALID_REQUEST", {"reason": "empty_owner"})

        try:
            request_list = list(requests)
        except TypeError as exc:
            raise PkgError(
                "PKG_INVALID_REQUEST", {"reason": "requests_not_iterable"}
            ) from exc

        if not request_list:
            raise PkgError("PKG_INVALID_REQUEST", {"reason": "empty_requests"})

        cleaned = []
        seen_packages: set[str] = set()
        for index, request in enumerate(request_list):
            if not isinstance(request, dict):
                raise PkgError(
                    "PKG_INVALID_REQUEST",
                    {"index": index, "reason": "request_not_dict"},
                )

            op = request.get("op")
            package = request.get("package")
            if op not in _OPERATIONS:
                raise PkgError("PKG_INVALID_REQUEST", {"index": index, "op": op})
            if not isinstance(package, str) or not package.strip():
                raise PkgError(
                    "PKG_INVALID_REQUEST",
                    {"index": index, "reason": "invalid_package"},
                )
            if package in seen_packages:
                raise PkgError(
                    "PKG_INVALID_REQUEST",
                    {
                        "index": index,
                        "package": package,
                        "reason": "duplicate_package",
                    },
                )
            seen_packages.add(package)

            version = request.get("version")
            if op in {"install", "upgrade"}:
                if not _valid_version(version):
                    raise PkgError(
                        "PKG_INVALID_REQUEST",
                        {"index": index, "package": package, "version": version},
                    )
            elif version is not None and not _valid_version(version):
                raise PkgError(
                    "PKG_INVALID_REQUEST",
                    {"index": index, "package": package, "version": version},
                )

            cleaned.append((op, package, version))

        planned_steps = []
        for seq, (op, package, version) in enumerate(cleaned):
            current = self._installed.get(package)
            installed = package in self._installed

            if op == "install":
                if installed:
                    raise PkgError(
                        "PKG_ALREADY_INSTALLED",
                        {"package": package, "version": current},
                    )
                from_version = None
                to_version = version
            elif op == "upgrade":
                if not installed:
                    raise PkgError("PKG_NOT_INSTALLED", {"package": package})
                if _version_tuple(version) <= _version_tuple(current):
                    raise PkgError(
                        "PKG_VERSION_CONFLICT",
                        {
                            "package": package,
                            "current": current,
                            "requested": version,
                        },
                    )
                from_version = current
                to_version = version
            else:
                if not installed:
                    raise PkgError("PKG_NOT_INSTALLED", {"package": package})
                if version is not None and version != current:
                    raise PkgError(
                        "PKG_VERSION_CONFLICT",
                        {
                            "package": package,
                            "current": current,
                            "requested": version,
                        },
                    )
                from_version = current
                to_version = None

            planned_steps.append(
                {
                    "seq": seq,
                    "op": op,
                    "package": package,
                    "from_version": from_version,
                    "to_version": to_version,
                    "state": "pending",
                    "intent_at": None,
                    "applied_at": None,
                }
            )

        return planned_steps

    def _transaction_or_raise(self, txid: object) -> dict:
        transaction = self._transactions.get(txid)
        if transaction is None:
            raise PkgError("PKG_UNKNOWN_TRANSACTION", {"txid": txid})
        return transaction

    @staticmethod
    def _ensure_open_for_progress(transaction: dict) -> None:
        if transaction["state"] in _CLOSED_STATES:
            raise PkgError(
                "PKG_TX_CLOSED",
                {"txid": transaction["txid"], "state": transaction["state"]},
            )

    def _seize_expired_lock_locked(self, now: int) -> None:
        lock = self._global_lock
        if lock is None:
            return
        transaction = self._transactions.get(lock["txid"])
        if transaction is not None and transaction["state"] not in _CLOSED_STATES:
            transaction["state"] = "abandoned"
            transaction["abandoned_at"] = now
            self._stats["seized"] += 1
        self._global_lock = None

    def _release_lock_locked(self, txid: str) -> None:
        if self._global_lock is not None and self._global_lock["txid"] == txid:
            self._global_lock = None

    def _apply_step_locked(self, step: dict) -> None:
        package = step["package"]
        if step["op"] in {"install", "upgrade"}:
            self._installed[package] = step["to_version"]
        else:
            self._installed.pop(package, None)

    def _rollback_step_locked(self, step: dict) -> None:
        package = step["package"]
        if step["op"] == "install":
            self._installed.pop(package, None)
        else:
            self._installed[package] = step["from_version"]

    def _revert_applied_steps_locked(self, steps: list[dict]) -> int:
        reverted = 0
        for step in reversed(steps):
            if step["state"] != "applied":
                continue
            self._rollback_step_locked(step)
            step["state"] = "reverted"
            self._stats["reverted"] += 1
            reverted += 1
        return reverted

    def _mark_committed_locked(
        self, transaction: dict, now: int, *, count_stat: bool
    ) -> None:
        transaction["state"] = "committed"
        transaction["committed_at"] = now
        if count_stat:
            self._stats["committed"] += 1
        self._release_lock_locked(transaction["txid"])

    def _parse_snapshot(self, state: object):
        if not isinstance(state, dict):
            raise PkgError("PKG_SNAPSHOT_INVALID", {"reason": "not_object"})
        if not _SNAPSHOT_KEYS.issubset(state):
            raise PkgError("PKG_SNAPSHOT_INVALID", {"reason": "missing_keys"})

        try:
            data = copy.deepcopy(state)
        except Exception as exc:
            raise PkgError(
                "PKG_SNAPSHOT_INVALID", {"reason": "copy_failed"}
            ) from exc

        if type(data["version"]) is not int or data["version"] != _SNAPSHOT_VERSION:
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": "version"})

        installed = data["installed"]
        transactions = data["transactions"]
        steps = data["steps"]
        lock = data["lock"]
        counters = data["counters"]
        next_tx = data["next_tx"]

        if not isinstance(installed, dict):
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": "installed"})
        for package, version in installed.items():
            if not isinstance(package, str) or not package:
                raise PkgError("PKG_SNAPSHOT_INVALID", {"field": "installed"})
            if not isinstance(version, str) or not version:
                raise PkgError("PKG_SNAPSHOT_INVALID", {"field": "installed"})

        if not isinstance(transactions, dict):
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": "transactions"})
        if not isinstance(steps, dict):
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": "steps"})
        if not isinstance(counters, dict):
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": "counters"})
        if type(next_tx) is not int or next_tx < 1:
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": "next_tx"})

        parsed_counters = {}
        for key in _STATS_KEYS:
            value = counters.get(key, 0)
            if type(value) is not int or value < 0:
                raise PkgError(
                    "PKG_SNAPSHOT_INVALID", {"field": f"counters.{key}"}
                )
            parsed_counters[key] = value

        valid_states = {
            "open",
            "applying",
            "committed",
            "rolled_back",
            "abandoned",
        }
        for txid, transaction in transactions.items():
            if not isinstance(txid, str) or not txid:
                raise PkgError("PKG_SNAPSHOT_INVALID", {"field": "transactions"})
            if not isinstance(transaction, dict):
                raise PkgError(
                    "PKG_SNAPSHOT_INVALID", {"field": f"transactions.{txid}"}
                )
            if transaction.get("txid") != txid:
                raise PkgError(
                    "PKG_SNAPSHOT_INVALID",
                    {"field": f"transactions.{txid}.txid"},
                )
            owner = transaction.get("owner")
            if not isinstance(owner, str) or not owner:
                raise PkgError(
                    "PKG_SNAPSHOT_INVALID",
                    {"field": f"transactions.{txid}.owner"},
                )
            if transaction.get("state") not in valid_states:
                raise PkgError(
                    "PKG_SNAPSHOT_INVALID",
                    {"field": f"transactions.{txid}.state"},
                )
            if txid not in steps or not isinstance(steps[txid], list):
                raise PkgError(
                    "PKG_SNAPSHOT_INVALID", {"field": f"steps.{txid}"}
                )

            tx_steps = steps[txid]
            applied_count = 0
            for seq, step in enumerate(tx_steps):
                self._validate_snapshot_step(txid, seq, step)
                if step["state"] in {"applied", "reverted"}:
                    applied_count += 1

            transaction["step_total"] = len(tx_steps)
            transaction["applied"] = applied_count

        for txid, tx_steps in steps.items():
            if txid not in transactions:
                raise PkgError("PKG_SNAPSHOT_INVALID", {"field": f"steps.{txid}"})
            if not isinstance(tx_steps, list):
                raise PkgError("PKG_SNAPSHOT_INVALID", {"field": f"steps.{txid}"})

        parsed_lock = None
        if lock is not None:
            if not isinstance(lock, dict):
                raise PkgError("PKG_SNAPSHOT_INVALID", {"field": "lock"})
            lock_txid = lock.get("txid")
            owner = lock.get("owner")
            expires_at = lock.get("expires_at")
            if not isinstance(lock_txid, str) or lock_txid not in transactions:
                raise PkgError("PKG_SNAPSHOT_INVALID", {"field": "lock.txid"})
            if not isinstance(owner, str) or not owner:
                raise PkgError("PKG_SNAPSHOT_INVALID", {"field": "lock.owner"})
            if type(expires_at) is not int:
                raise PkgError(
                    "PKG_SNAPSHOT_INVALID", {"field": "lock.expires_at"}
                )
            if transactions[lock_txid]["state"] in _CLOSED_STATES:
                raise PkgError("PKG_SNAPSHOT_INVALID", {"field": "lock.txid"})
            parsed_lock = {
                "owner": owner,
                "txid": lock_txid,
                "expires_at": expires_at,
            }

        return (
            installed,
            transactions,
            steps,
            parsed_lock,
            parsed_counters,
            next_tx,
        )

    @staticmethod
    def _validate_snapshot_step(txid: str, seq: int, step: object) -> None:
        field = f"steps.{txid}.{seq}"
        if not isinstance(step, dict):
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": field})
        if step.get("seq") != seq:
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": f"{field}.seq"})
        if step.get("op") not in _OPERATIONS:
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": f"{field}.op"})
        package = step.get("package")
        if not isinstance(package, str) or not package:
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": f"{field}.package"})
        if step.get("state") not in _STEP_STATES:
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": f"{field}.state"})

        from_version = step.get("from_version")
        to_version = step.get("to_version")
        if from_version is not None and not isinstance(from_version, str):
            raise PkgError(
                "PKG_SNAPSHOT_INVALID", {"field": f"{field}.from_version"}
            )
        if to_version is not None and not isinstance(to_version, str):
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": f"{field}.to_version"})

        intent_at = step.get("intent_at")
        applied_at = step.get("applied_at")
        if intent_at is not None and type(intent_at) is not int:
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": f"{field}.intent_at"})
        if applied_at is not None and type(applied_at) is not int:
            raise PkgError("PKG_SNAPSHOT_INVALID", {"field": f"{field}.applied_at"})
