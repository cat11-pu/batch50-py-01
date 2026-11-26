"""Confirmed-commit guard: rollback timer, one-shot persist-id and datastore locks."""

from __future__ import annotations

import copy
import threading
import time
import uuid
from dataclasses import dataclass


class NetconfError(ValueError):
    """Raised when a confirmed-commit operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CommitTicket:
    commit_id: int
    datastore: str
    session_id: str
    version: int
    expires_at: int
    persist_id: object


_STAT_KEYS = ("commits", "confirms", "rollbacks", "expired", "adopted", "lock_denied")
_SCALAR_TYPES = (str, int, float, bool, type(None))


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _non_negative_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value >= 0


def _valid_candidate(candidate: object) -> bool:
    if not isinstance(candidate, dict):
        return False
    for key, value in candidate.items():
        if not isinstance(key, str):
            return False
        if not isinstance(value, _SCALAR_TYPES):
            return False
    return True


class ConfirmedCommitGuard:
    """Serialise unconfirmed commits per datastore and own their rollback timers."""

    def __init__(self, *, default_timeout: int = 60) -> None:
        self.default_timeout = default_timeout
        self._lock = threading.RLock()
        self._stores: dict = {}
        self._pendings: dict = {}
        self._locks: dict = {}
        self._next_commit_id = 1
        self._stats = {key: 0 for key in _STAT_KEYS}

    def commit(self, session_id: str, candidate: dict, *,
               datastore: str = "running", timeout=None,
               persist_id=None, now=None) -> CommitTicket:
        if not _valid_candidate(candidate):
            raise NetconfError("NETCONF_INVALID_CANDIDATE", "candidate must be a dict of string keys and scalar values")

        effective_timeout = self._timeout_value(timeout)
        current_now = time.time() if now is None else now
        time_base = "wall" if now is None else "logical"

        with self._lock:
            self._expire_for_call_locked(current_now if now is not None else None, datastore)

            owner = self._locks.get(datastore)
            if owner is not None and owner != session_id:
                self._stats["lock_denied"] += 1
                raise NetconfError("NETCONF_LOCK_HELD", {
                    "datastore": datastore,
                    "owner": owner,
                })

            if datastore in self._pendings:
                raise NetconfError("NETCONF_COMMIT_IN_PROGRESS", {
                    "datastore": datastore,
                    "commit_id": self._pendings[datastore]["commit_id"],
                })

            store = self._store_locked(datastore)
            base_config = copy.deepcopy(store["config"])
            version = store["version"] + 1
            store["config"] = copy.deepcopy(candidate)
            store["version"] = version

            commit_id = self._next_commit_id
            self._next_commit_id += 1
            expires_at = current_now + effective_timeout
            pending = {
                "commit_id": commit_id,
                "datastore": datastore,
                "session_id": session_id,
                "version": version,
                "expires_at": expires_at,
                "persist_id": copy.deepcopy(persist_id),
                "base_config": base_config,
                "base_version": version - 1,
                "time_base": time_base,
            }
            self._pendings[datastore] = pending
            self._stats["commits"] += 1
            return self._ticket(pending)

    def confirm(self, session_id: str, *, datastore: str = "running",
                commit_id=None, persist_id=None, now=None) -> int:
        with self._lock:
            self._expire_for_call_locked(now, datastore)
            pending = self._resolve_pending_for_confirm_locked(
                session_id,
                datastore,
                commit_id,
                persist_id,
            )

            del self._pendings[datastore]
            self._stats["confirms"] += 1
            return self._stores[datastore]["version"]

    def rollback(self, session_id=None, *, datastore: str = "running",
                 commit_id=None, now=None) -> int:
        with self._lock:
            self._expire_for_call_locked(now, datastore)
            pending = self._pendings.get(datastore)

            if commit_id is not None:
                if pending is None or pending["commit_id"] != commit_id:
                    raise NetconfError("NETCONF_UNKNOWN_COMMIT", {
                        "datastore": datastore,
                        "commit_id": commit_id,
                    })
            elif pending is None:
                raise NetconfError("NETCONF_UNKNOWN_COMMIT", {"datastore": datastore})

            return self._rollback_pending_locked(datastore, pending, expired=False)

    def persist(self, session_id: str, *, datastore: str = "running",
                persist_id=None) -> str:
        with self._lock:
            pending = self._pendings.get(datastore)
            if pending is None:
                raise NetconfError("NETCONF_UNKNOWN_COMMIT", {"datastore": datastore})
            if session_id != pending["session_id"]:
                raise NetconfError("NETCONF_WRONG_SESSION", {
                    "datastore": datastore,
                    "owner": pending["session_id"],
                })

            if persist_id is None:
                if pending["persist_id"] is None:
                    pending["persist_id"] = uuid.uuid4().hex
            else:
                pending["persist_id"] = copy.deepcopy(persist_id)
            return pending["persist_id"]

    def adopt(self, session_id: str, persist_id: str, *,
              datastore: str = "running") -> CommitTicket:
        with self._lock:
            pending = self._pendings.get(datastore)
            if (pending is None or persist_id is None
                    or pending.get("persist_id") != persist_id):
                raise NetconfError("NETCONF_UNKNOWN_PERSIST", {
                    "datastore": datastore,
                    "persist_id": persist_id,
                })

            pending["session_id"] = session_id
            self._stats["adopted"] += 1
            return self._ticket(pending)

    def lock_datastore(self, session_id: str, datastore: str = "running") -> None:
        with self._lock:
            owner = self._locks.get(datastore)
            if owner is not None and owner != session_id:
                self._stats["lock_denied"] += 1
                raise NetconfError("NETCONF_LOCK_HELD", {
                    "datastore": datastore,
                    "owner": owner,
                })
            self._locks[datastore] = session_id
            self._store_locked(datastore)

    def unlock_datastore(self, session_id: str, datastore: str = "running") -> None:
        with self._lock:
            owner = self._locks.get(datastore)
            if owner is None or owner != session_id:
                raise NetconfError("NETCONF_NOT_OWNER", {
                    "datastore": datastore,
                    "owner": owner,
                })
            del self._locks[datastore]

    def close_session(self, session_id: str, *, now=None) -> int:
        rolled_back = 0
        with self._lock:
            if now is not None:
                self._expire_due_locked(now)

            for datastore, pending in list(self._pendings.items()):
                if pending["session_id"] == session_id and pending["persist_id"] is None:
                    self._rollback_pending_locked(datastore, pending, expired=False)
                    rolled_back += 1

            for datastore, owner in list(self._locks.items()):
                if owner == session_id:
                    del self._locks[datastore]

        return rolled_back

    def expire(self, now) -> int:
        current_now = time.time() if now is None else now
        with self._lock:
            return self._expire_due_locked(current_now)

    def pending_for(self, datastore: str = "running"):
        with self._lock:
            pending = self._pendings.get(datastore)
            if pending is None:
                return None
            return self._ticket(pending)

    def version_for(self, datastore: str = "running") -> int:
        with self._lock:
            store = self._stores.get(datastore)
            return 0 if store is None else store["version"]

    def config_for(self, datastore: str = "running") -> dict:
        with self._lock:
            store = self._stores.get(datastore)
            if store is None:
                return {}
            return copy.deepcopy(store["config"])

    def snapshot(self) -> dict:
        with self._lock:
            stores = copy.deepcopy(self._stores)
            for datastore, store in stores.items():
                store["lock_owner"] = self._locks.get(datastore)
                store["next_commit_id"] = self._next_commit_id
            for datastore, owner in self._locks.items():
                if datastore not in stores:
                    stores[datastore] = {
                        "config": {},
                        "version": 0,
                        "lock_owner": owner,
                        "next_commit_id": self._next_commit_id,
                    }

            return {
                "version": 1,
                "stores": stores,
                "pendings": copy.deepcopy(self._pendings),
                "stats": self.stats(),
            }

    def restore(self, state: dict) -> None:
        try:
            new_state = self._build_restored_state(state)
        except NetconfError:
            raise
        except Exception as exc:
            raise NetconfError("NETCONF_SNAPSHOT_INVALID", "invalid snapshot structure") from exc

        with self._lock:
            self._stores = new_state["stores"]
            self._locks = new_state["locks"]
            self._pendings = new_state["pendings"]
            self._next_commit_id = new_state["next_commit_id"]
            self._stats = new_state["stats"]

    def stats(self) -> dict:
        with self._lock:
            return {key: self._stats[key] for key in _STAT_KEYS}

    def _timeout_value(self, timeout) -> int:
        value = self.default_timeout if timeout is None else timeout
        if not _positive_int(value):
            raise NetconfError("NETCONF_INVALID_REQUEST", "timeout must be a positive integer")
        return value

    def _store_locked(self, datastore: str) -> dict:
        store = self._stores.get(datastore)
        if store is None:
            store = {"config": {}, "version": 0}
            self._stores[datastore] = store
        return store

    def _ticket(self, pending: dict) -> CommitTicket:
        return CommitTicket(
            commit_id=pending["commit_id"],
            datastore=pending["datastore"],
            session_id=pending["session_id"],
            version=pending["version"],
            expires_at=pending["expires_at"],
            persist_id=copy.deepcopy(pending["persist_id"]),
        )

    def _expire_for_call_locked(self, now, datastore: str) -> int:
        if now is not None:
            return self._expire_due_locked(now, datastore)

        pending = self._pendings.get(datastore)
        if pending is not None and pending.get("time_base") == "wall":
            return self._expire_due_locked(time.time(), datastore)
        return 0

    def _expire_due_locked(self, now, datastore: str | None = None) -> int:
        if datastore is not None:
            datastores = [datastore]
        else:
            datastores = list(self._pendings)

        count = 0
        for name in datastores:
            pending = self._pendings.get(name)
            if pending is not None and now >= pending["expires_at"]:
                self._rollback_pending_locked(name, pending, expired=True)
                count += 1
        return count

    def _rollback_pending_locked(self, datastore: str, pending: dict, *, expired: bool) -> int:
        store = self._store_locked(datastore)
        store["config"] = copy.deepcopy(pending["base_config"])
        store["version"] = pending["version"] + 1
        del self._pendings[datastore]

        self._stats["rollbacks"] += 1
        if expired:
            self._stats["expired"] += 1
        return store["version"]

    def _resolve_pending_for_confirm_locked(self, session_id, datastore,
                                            commit_id, persist_id):
        current = self._pendings.get(datastore)

        if commit_id is not None:
            if current is None or current["commit_id"] != commit_id:
                raise NetconfError("NETCONF_UNKNOWN_COMMIT", {
                    "datastore": datastore,
                    "commit_id": commit_id,
                })
            self._assert_confirm_credentials(session_id, current, persist_id)
            return current

        if persist_id is not None:
            if current is None:
                raise NetconfError("NETCONF_UNKNOWN_PERSIST", {
                    "datastore": datastore,
                    "persist_id": persist_id,
                })
            expected_persist_id = current["persist_id"]
            if expected_persist_id is not None and persist_id != expected_persist_id:
                raise NetconfError("NETCONF_PERSIST_MISMATCH", {
                    "datastore": datastore,
                })
            if expected_persist_id is None and session_id != current["session_id"]:
                raise NetconfError("NETCONF_WRONG_SESSION", {
                    "datastore": datastore,
                    "owner": current["session_id"],
                })
            return current

        if current is None:
            raise NetconfError("NETCONF_UNKNOWN_COMMIT", {"datastore": datastore})

        self._assert_confirm_credentials(session_id, current, None)
        return current

    @staticmethod
    def _assert_confirm_credentials(session_id, pending: dict, supplied_persist_id) -> None:
        expected_persist_id = pending["persist_id"]
        if expected_persist_id is None:
            if session_id != pending["session_id"]:
                raise NetconfError("NETCONF_WRONG_SESSION", {
                    "datastore": pending["datastore"],
                    "owner": pending["session_id"],
                })
            return

        if supplied_persist_id is not None:
            if supplied_persist_id != expected_persist_id:
                raise NetconfError("NETCONF_PERSIST_MISMATCH", {
                    "datastore": pending["datastore"],
                })
            return

        if session_id == pending["session_id"]:
            return

        raise NetconfError("NETCONF_PERSIST_MISMATCH", {
            "datastore": pending["datastore"],
        })

    def _build_restored_state(self, state: object) -> dict:
        if not isinstance(state, dict):
            raise NetconfError("NETCONF_SNAPSHOT_INVALID", "snapshot must be a dict")

        required = ("version", "stores", "pendings", "stats")
        if any(key not in state for key in required):
            raise NetconfError("NETCONF_SNAPSHOT_INVALID", "snapshot is missing required top-level keys")

        snapshot = copy.deepcopy(state)
        version_info = snapshot["version"]
        if isinstance(version_info, bool) or not isinstance(version_info, int) or version_info != 1:
            raise NetconfError("NETCONF_SNAPSHOT_INVALID", "unsupported snapshot version")

        explicit_next_commit_id = snapshot.get("next_commit_id")

        stores_raw = snapshot["stores"]
        pendings_raw = snapshot["pendings"]
        stats_raw = snapshot["stats"]
        if not isinstance(stores_raw, dict) or not isinstance(pendings_raw, dict):
            raise NetconfError("NETCONF_SNAPSHOT_INVALID", "stores and pendings must be dicts")
        if not isinstance(stats_raw, dict):
            raise NetconfError("NETCONF_SNAPSHOT_INVALID", "stats must be a dict")

        stores = {}
        locks = {}
        store_commit_sequences = []
        for datastore, store_state in stores_raw.items():
            if not isinstance(datastore, str) or not isinstance(store_state, dict):
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "store entry is invalid")
            if "config" not in store_state or "version" not in store_state:
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "store entry is incomplete")
            config = store_state["config"]
            version = store_state["version"]
            if not _valid_candidate(config) or not _non_negative_int(version):
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "store config or version is invalid")

            owner = store_state.get("lock_owner")
            if owner is not None and not isinstance(owner, str):
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "lock owner is invalid")
            store_next_commit_id = store_state.get("next_commit_id", 1)
            if not _positive_int(store_next_commit_id):
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "store commit sequence is invalid")

            stores[datastore] = {"config": copy.deepcopy(config), "version": version}
            if owner is not None:
                locks[datastore] = owner
            store_commit_sequences.append(store_next_commit_id)

        pendings = {}
        commit_ids = set()
        for datastore, pending in pendings_raw.items():
            if not isinstance(datastore, str) or not isinstance(pending, dict):
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "pending entry is invalid")

            required_pending = (
                "commit_id", "datastore", "session_id", "version",
                "expires_at", "persist_id", "base_config",
            )
            if any(key not in pending for key in required_pending):
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "pending entry is incomplete")

            commit_id = pending["commit_id"]
            pending_ds = pending["datastore"]
            session_id = pending["session_id"]
            version = pending["version"]
            expires_at = pending["expires_at"]
            base_config = pending["base_config"]

            if not _positive_int(commit_id) or commit_id in commit_ids:
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "pending commit_id is invalid")
            if pending_ds != datastore or not isinstance(session_id, str):
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "pending identity is invalid")
            if not _positive_int(version) or not isinstance(expires_at, (int, float)) or isinstance(expires_at, bool):
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "pending version or expiry is invalid")
            if not _valid_candidate(base_config):
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "pending base_config is invalid")
            if datastore not in stores or stores[datastore]["version"] != version:
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "pending version does not match store")

            time_base = pending.get("time_base", "logical")
            if time_base not in ("logical", "wall"):
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "pending time base is invalid")

            base_version = pending.get("base_version", version - 1)
            if not _non_negative_int(base_version) or base_version != version - 1:
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", "pending base_version is invalid")

            commit_ids.add(commit_id)
            pendings[datastore] = {
                "commit_id": commit_id,
                "datastore": datastore,
                "session_id": session_id,
                "version": version,
                "expires_at": expires_at,
                "persist_id": copy.deepcopy(pending["persist_id"]),
                "base_config": copy.deepcopy(base_config),
                "base_version": base_version,
                "time_base": time_base,
            }

        next_commit_id = 1
        if _positive_int(explicit_next_commit_id):
            next_commit_id = explicit_next_commit_id
        for sequence in store_commit_sequences:
            next_commit_id = max(next_commit_id, sequence)
        for commit_id in commit_ids:
            next_commit_id = max(next_commit_id, commit_id + 1)

        stats = {}
        for key in _STAT_KEYS:
            value = stats_raw.get(key, 0)
            if not _non_negative_int(value):
                raise NetconfError("NETCONF_SNAPSHOT_INVALID", f"stat {key} is invalid")
            stats[key] = value

        return {
            "stores": stores,
            "locks": locks,
            "pendings": pendings,
            "next_commit_id": next_commit_id,
            "stats": stats,
        }
