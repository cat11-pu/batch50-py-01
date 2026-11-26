"""Anonymous identity upgrade: resource migration, conflict merge and rollback."""

from __future__ import annotations

import copy
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


class AnonymousBindError(ValueError):
    """Raised when an anonymous identity operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class AnonSession:
    anon_id: str
    device_id: str
    state: str
    created_at: str
    resource_count: int


@dataclass(frozen=True)
class BindResult:
    bind_id: str
    anon_id: str
    account_id: str
    status: str
    migrated: int
    added: int
    conflicts: int
    overwritten: int
    bound_at: str


class AnonymousIdentityBinder:
    """Carry an anonymous session's resources into a real account."""

    _VERSION = 1
    _KINDS = frozenset({"cart", "draft", "preference", "upload"})
    _STAT_KEYS = (
        "anonymous_created",
        "resources_attached",
        "bound",
        "rolled_back",
        "conflicts",
    )

    def __init__(self, *, conflict_policy: str = "account_wins",
                 max_resources_per_anon: int = 64) -> None:
        self.conflict_policy = conflict_policy
        self.max_resources_per_anon = max_resources_per_anon
        self._lock = threading.RLock()
        self._anonymous: dict[str, dict[str, Any]] = {}
        self._accounts: dict[str, dict[str, Any]] = {}
        self._binds: list[dict[str, Any]] = []
        self._stats: dict[str, int] = {key: 0 for key in self._STAT_KEYS}

    def create_anon(self, *, device_id: str,
                    now: str | None = None) -> AnonSession:
        if not isinstance(device_id, str) or not device_id.strip():
            raise AnonymousBindError("ANON_INVALID_REQUEST", "device_id")

        with self._lock:
            created_at = self._timestamp(now)
            anon_id = self._new_anon_id_locked()
            self._anonymous[anon_id] = {
                "anon_id": anon_id,
                "device_id": device_id,
                "state": "active",
                "created_at": created_at,
                "account_id": None,
                "bound_at": None,
                "resources": {},
            }
            self._stats["anonymous_created"] += 1
            return self._session_locked(anon_id)

    def attach_resource(self, anon_id: str, *, kind: str, key: str,
                        value: str, now: str | None = None) -> dict:
        with self._lock:
            anon = self._get_anonymous_locked(anon_id)
            if kind not in self._KINDS:
                raise AnonymousBindError("ANON_BAD_KIND", kind)
            if self._is_blank(key) or self._is_blank(value):
                raise AnonymousBindError("ANON_INVALID_REQUEST",
                                         "key and value are required")

            resource_key = (kind, key)
            resources = anon["resources"]
            existing = resources.get(resource_key)
            if existing is None:
                if len(resources) >= self.max_resources_per_anon:
                    raise AnonymousBindError(
                        "ANON_RESOURCE_LIMIT",
                        self.max_resources_per_anon,
                    )
                revision = 1
            else:
                revision = int(existing["revision"]) + 1

            resource = {
                "kind": kind,
                "key": key,
                "value": value,
                "revision": revision,
            }
            resources[resource_key] = resource
            self._stats["resources_attached"] += 1
            return copy.deepcopy(resource)

    def detach_resource(self, anon_id: str, *, kind: str, key: str) -> bool:
        with self._lock:
            anon = self._get_anonymous_locked(anon_id)
            if kind not in self._KINDS:
                raise AnonymousBindError("ANON_BAD_KIND", kind)
            if self._is_blank(key):
                raise AnonymousBindError("ANON_INVALID_REQUEST", "key")
            return anon["resources"].pop((kind, key), None) is not None

    def merge_state(self, anon_id: str, *, account_id: str,
                    now: str | None = None) -> dict:
        with self._lock:
            anon = self._get_anonymous_locked(anon_id)
            account_id = self._valid_account_id(account_id)
            return self._plan_locked(anon, account_id)

    def bind_to_account(self, anon_id: str, *, account_id: str,
                        now: str | None = None) -> BindResult:
        with self._lock:
            bound_at = self._timestamp(now)
            anon = self._get_anonymous_locked(anon_id)
            account_id = self._valid_account_id(account_id)
            if anon["state"] == "bound":
                raise AnonymousBindError("ANON_ALREADY_BOUND", {
                    "anon_id": anon_id,
                    "account_id": anon.get("account_id"),
                })

            account = self._accounts.get(account_id)
            if account is not None and account.get("frozen"):
                raise AnonymousBindError("ANON_ACCOUNT_FROZEN", account_id)

            plan = self._plan_locked(anon, account_id)
            bind_id = self._new_bind_id_locked()
            moved_resources = copy.deepcopy(list(anon["resources"].values()))
            existing_account_resources = self._account_resources_locked(account_id)
            added_keys = [
                [resource["kind"], resource["key"]]
                for resource in moved_resources
                if (resource["kind"], resource["key"])
                not in existing_account_resources
            ]
            overwritten_resources = []

            if account is None:
                account = {"frozen": False, "resources": {}}
                self._accounts[account_id] = account

            account_resources = account["resources"]
            for resource in moved_resources:
                resource_key = (resource["kind"], resource["key"])
                if resource_key in account_resources:
                    if self.conflict_policy != "account_wins":
                        overwritten_resources.append(
                            copy.deepcopy(account_resources[resource_key])
                        )
                        replacement = copy.deepcopy(resource)
                        replacement["revision"] = (
                            int(account_resources[resource_key]["revision"]) + 1
                        )
                        account_resources[resource_key] = replacement
                    continue
                account_resources[resource_key] = copy.deepcopy(resource)

            bind_record = {
                "bind_id": bind_id,
                "anon_id": anon_id,
                "account_id": account_id,
                "status": "bound",
                "migrated": plan["migrated"],
                "added": plan["added"],
                "conflicts": plan["conflicts"],
                "overwritten": plan["overwritten"],
                "bound_at": bound_at,
                "resources": moved_resources,
                "added_keys": added_keys,
                "overwritten_resources": overwritten_resources,
            }
            self._binds.append(bind_record)

            anon["state"] = "bound"
            anon["account_id"] = account_id
            anon["bound_at"] = bound_at
            anon["resources"].clear()

            self._stats["bound"] += 1
            self._stats["conflicts"] += plan["conflicts"]

            return BindResult(
                bind_id=bind_id,
                anon_id=anon_id,
                account_id=account_id,
                status="bound",
                migrated=plan["migrated"],
                added=plan["added"],
                conflicts=plan["conflicts"],
                overwritten=plan["overwritten"],
                bound_at=bound_at,
            )

    def rollback(self, account_id: str, *, now: str | None = None) -> dict:
        with self._lock:
            bind_index = None
            for index in range(len(self._binds) - 1, -1, -1):
                if self._binds[index]["account_id"] == account_id:
                    bind_index = index
                    break
            if bind_index is None:
                raise AnonymousBindError("ANON_ROLLBACK_UNAVAILABLE", account_id)

            bind = self._binds.pop(bind_index)
            account = self._accounts.get(account_id)
            if account is not None:
                for kind, key in bind["added_keys"]:
                    account["resources"].pop((kind, key), None)
                for resource in bind.get("overwritten_resources", []):
                    resource_key = (resource["kind"], resource["key"])
                    account["resources"][resource_key] = copy.deepcopy(resource)

            anon = self._anonymous[bind["anon_id"]]
            restored_resources = {
                (resource["kind"], resource["key"]): copy.deepcopy(resource)
                for resource in bind["resources"]
            }
            for resource_key, resource in anon["resources"].items():
                restored_resources[resource_key] = copy.deepcopy(resource)
            anon["state"] = "active"
            anon["account_id"] = None
            anon["bound_at"] = None
            anon["resources"] = restored_resources

            self._stats["rolled_back"] += 1
            return {
                "bind_id": bind["bind_id"],
                "anon_id": bind["anon_id"],
                "restored": len(bind["resources"]),
            }

    def freeze_account(self, account_id: str) -> None:
        if self._is_blank(account_id):
            raise AnonymousBindError("ANON_INVALID_REQUEST", "account_id")
        with self._lock:
            account = self._accounts.get(account_id)
            if account is None:
                account = {"frozen": True, "resources": {}}
                self._accounts[account_id] = account
            else:
                account["frozen"] = True

    def status(self, anon_id: str) -> dict:
        with self._lock:
            anon = self._get_anonymous_locked(anon_id)
            return {
                "anon_id": anon["anon_id"],
                "device_id": anon["device_id"],
                "state": anon["state"],
                "account_id": anon["account_id"],
                "resource_count": len(anon["resources"]),
            }

    def anon_resources(self, anon_id: str) -> list[dict]:
        with self._lock:
            anon = self._get_anonymous_locked(anon_id)
            return self._sorted_resources_locked(anon["resources"])

    def account_resources(self, account_id: str) -> list[dict]:
        with self._lock:
            return self._sorted_resources_locked(
                self._account_resources_locked(account_id)
            )

    def list_anonymous(self) -> list[str]:
        with self._lock:
            return list(self._anonymous)

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "version": self._VERSION,
                "anonymous": {
                    anon_id: {
                        "anon_id": anon["anon_id"],
                        "device_id": anon["device_id"],
                        "state": anon["state"],
                        "created_at": anon["created_at"],
                        "account_id": anon["account_id"],
                        "bound_at": anon.get("bound_at"),
                        "resources": self._sorted_resources_locked(
                            anon["resources"]
                        ),
                    }
                    for anon_id, anon in self._anonymous.items()
                },
                "accounts": {
                    account_id: {
                        "frozen": bool(account.get("frozen", False)),
                        "resources": self._sorted_resources_locked(
                            account["resources"]
                        ),
                    }
                    for account_id, account in self._accounts.items()
                },
                "binds": copy.deepcopy(self._binds),
                "stats": copy.deepcopy(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        try:
            normalized = self._normalize_snapshot(state)
        except AnonymousBindError:
            raise
        except Exception as exc:
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", str(exc)) from exc

        with self._lock:
            self._anonymous = normalized["anonymous"]
            self._accounts = normalized["accounts"]
            self._binds = normalized["binds"]
            self._stats = normalized["stats"]

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

    @staticmethod
    def _timestamp(now: str | None) -> str:
        if now is not None:
            return now
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _is_blank(value: object) -> bool:
        return not isinstance(value, str) or not value.strip()

    def _valid_account_id(self, account_id: str) -> str:
        if self._is_blank(account_id):
            raise AnonymousBindError("ANON_INVALID_REQUEST", "account_id")
        return account_id

    def _new_anon_id_locked(self) -> str:
        while True:
            anon_id = f"anon_{uuid.uuid4().hex[:12]}"
            if anon_id not in self._anonymous:
                return anon_id

    def _new_bind_id_locked(self) -> str:
        existing = {bind["bind_id"] for bind in self._binds}
        while True:
            bind_id = f"bind_{uuid.uuid4().hex[:12]}"
            if bind_id not in existing:
                return bind_id

    def _get_anonymous_locked(self, anon_id: str) -> dict[str, Any]:
        try:
            anon = self._anonymous.get(anon_id)
        except TypeError:
            anon = None
        if anon is None:
            raise AnonymousBindError("ANON_UNKNOWN", anon_id)
        return anon

    def _account_resources_locked(self, account_id: str) -> dict[tuple[str, str], dict]:
        account = self._accounts.get(account_id)
        if account is None:
            return {}
        return account["resources"]

    @staticmethod
    def _resource_sort_key(resource_key: tuple[str, str]) -> str:
        return f"{resource_key[0]}:{resource_key[1]}"

    def _sorted_resources_locked(
        self, resources: dict[tuple[str, str], dict[str, Any]]
    ) -> list[dict[str, Any]]:
        ordered_keys = sorted(resources, key=self._resource_sort_key)
        return [copy.deepcopy(resources[key]) for key in ordered_keys]

    def _session_locked(self, anon_id: str) -> AnonSession:
        anon = self._anonymous[anon_id]
        return AnonSession(
            anon_id=anon["anon_id"],
            device_id=anon["device_id"],
            state=anon["state"],
            created_at=anon["created_at"],
            resource_count=len(anon["resources"]),
        )

    def _plan_locked(self, anon: dict[str, Any], account_id: str) -> dict[str, Any]:
        anon_keys = set(anon["resources"])
        account_keys = set(self._account_resources_locked(account_id))
        all_keys = sorted(
            anon_keys | account_keys,
            key=self._resource_sort_key,
        )
        return {
            "migrated": len(anon_keys),
            "added": len(anon_keys - account_keys),
            "conflicts": len(anon_keys & account_keys),
            "overwritten": (
                len(anon_keys & account_keys)
                if self.conflict_policy != "account_wins"
                else 0
            ),
            "keys": [self._resource_sort_key(key) for key in all_keys],
        }

    def _normalize_snapshot(self, state: object) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "state must be object")
        if set(state) != {"version", "anonymous", "accounts", "binds", "stats"}:
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "top-level keys")
        version = state["version"]
        if (
            not isinstance(version, int)
            or isinstance(version, bool)
            or version != self._VERSION
        ):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "version")
        if not isinstance(state["anonymous"], dict):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "anonymous")
        if not isinstance(state["accounts"], dict):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "accounts")
        if not isinstance(state["binds"], list):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "binds")
        if not isinstance(state["stats"], dict):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "stats")

        anonymous: dict[str, dict[str, Any]] = {}
        for anon_id, raw_anon in state["anonymous"].items():
            if not isinstance(anon_id, str) or not isinstance(raw_anon, dict):
                raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "anonymous entry")
            anonymous[anon_id] = self._normalize_anonymous(raw_anon)

        accounts: dict[str, dict[str, Any]] = {}
        for account_id, raw_account in state["accounts"].items():
            if not isinstance(account_id, str) or not isinstance(raw_account, dict):
                raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "account entry")
            resources = self._normalize_resource_list(
                raw_account.get("resources", [])
            )
            frozen = raw_account.get("frozen", False)
            if not isinstance(frozen, bool):
                raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "account frozen")
            accounts[account_id] = {
                "frozen": frozen,
                "resources": resources,
            }

        binds: list[dict[str, Any]] = []
        for raw_bind in state["binds"]:
            binds.append(self._normalize_bind(raw_bind, anonymous))

        stats = self._normalize_stats(state["stats"])
        return {
            "anonymous": anonymous,
            "accounts": accounts,
            "binds": binds,
            "stats": stats,
        }

    def _normalize_anonymous(self, raw: dict[str, Any]) -> dict[str, Any]:
        required = {
            "anon_id",
            "device_id",
            "state",
            "created_at",
            "account_id",
            "bound_at",
            "resources",
        }
        if not required.issubset(raw):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "anonymous fields")
        if raw["state"] not in {"active", "bound"}:
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "anonymous state")
        if not isinstance(raw["anon_id"], str) or not isinstance(raw["device_id"], str):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "anonymous identity")
        if not isinstance(raw["created_at"], str):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "created_at")
        if raw["state"] == "bound":
            if not isinstance(raw["account_id"], str):
                raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "bound account")
        elif raw["account_id"] is not None:
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "active account")

        return {
            "anon_id": raw["anon_id"],
            "device_id": raw["device_id"],
            "state": raw["state"],
            "created_at": raw["created_at"],
            "account_id": raw["account_id"],
            "bound_at": raw.get("bound_at"),
            "resources": self._normalize_resource_list(raw["resources"]),
        }

    def _normalize_resource_list(self, raw: object) -> dict[tuple[str, str], dict]:
        if not isinstance(raw, list):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "resources")
        resources: dict[tuple[str, str], dict[str, Any]] = {}
        for raw_resource in raw:
            if not isinstance(raw_resource, dict):
                raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "resource")
            kind = raw_resource.get("kind")
            key = raw_resource.get("key")
            value = raw_resource.get("value")
            revision = raw_resource.get("revision")
            if kind not in self._KINDS or self._is_blank(key) or self._is_blank(value):
                raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "resource fields")
            if not isinstance(revision, int) or isinstance(revision, bool) or revision < 1:
                raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "revision")
            resource_key = (kind, key)
            if resource_key in resources:
                raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "duplicate resource")
            resources[resource_key] = {
                "kind": kind,
                "key": key,
                "value": value,
                "revision": revision,
            }
        return resources

    def _normalize_bind(
        self, raw: object, anonymous: dict[str, dict[str, Any]]
    ) -> dict[str, Any]:
        if not isinstance(raw, dict):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "bind")
        integer_fields = (
            "migrated",
            "added",
            "conflicts",
            "overwritten",
        )
        for field in integer_fields:
            value = raw.get(field)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise AnonymousBindError("ANON_SNAPSHOT_INVALID", f"bind.{field}")
        if not isinstance(raw.get("bind_id"), str):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "bind_id")
        if not isinstance(raw.get("anon_id"), str) or raw["anon_id"] not in anonymous:
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "bind anon")
        if not isinstance(raw.get("account_id"), str):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "bind account")
        if raw.get("status") != "bound":
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "bind status")
        if not isinstance(raw.get("bound_at"), str):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "bound_at")

        resources = self._normalize_resource_list(raw.get("resources", []))
        added_keys_raw = raw.get("added_keys", [])
        if not isinstance(added_keys_raw, list):
            raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "added_keys")
        added_keys: list[list[str]] = []
        for raw_key in added_keys_raw:
            if (
                not isinstance(raw_key, list)
                or len(raw_key) != 2
                or raw_key[0] not in self._KINDS
                or self._is_blank(raw_key[1])
            ):
                raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "added key")
            kind, key = raw_key
            if (kind, key) not in resources:
                raise AnonymousBindError("ANON_SNAPSHOT_INVALID", "added key resource")
            added_keys.append([kind, key])

        overwritten = self._normalize_resource_list(
            raw.get("overwritten_resources", [])
        )
        return {
            "bind_id": raw["bind_id"],
            "anon_id": raw["anon_id"],
            "account_id": raw["account_id"],
            "status": "bound",
            "migrated": raw["migrated"],
            "added": raw["added"],
            "conflicts": raw["conflicts"],
            "overwritten": raw["overwritten"],
            "bound_at": raw["bound_at"],
            "resources": [copy.deepcopy(resource) for resource in resources.values()],
            "added_keys": added_keys,
            "overwritten_resources": [
                copy.deepcopy(resource) for resource in overwritten.values()
            ],
        }

    def _normalize_stats(self, raw: dict[str, Any]) -> dict[str, int]:
        stats: dict[str, int] = {}
        for key in self._STAT_KEYS:
            value = raw.get(key)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise AnonymousBindError("ANON_SNAPSHOT_INVALID", f"stats.{key}")
            stats[key] = value
        return stats
