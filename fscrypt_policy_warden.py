"""Directory encryption policy governance: inheritance, key slots, locking and rotation."""

from __future__ import annotations

import copy
import posixpath
import threading
from dataclasses import dataclass

MODES = ("aes128-cts", "aes256-cts", "aes256-xts")
MODE_RANK = {name: rank for rank, name in enumerate(MODES, start=1)}


class FscryptError(ValueError):
    """Raised when an encryption policy operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PolicyRecord:
    path: str
    policy_id: str
    mode: str
    key_desc: str
    key_state: str = "locked"
    rotation_state: str = "idle"
    rotation_pending: int = 0
    rotation_total: int = 0


class FscryptPolicyWarden:
    """Own per-directory policies, the volume keyring and rotation progress."""

    def __init__(self, *, volume: str = "v1", max_policies: int = 16,
                 key_slots: int = 6, clock=None) -> None:
        self.volume = volume
        self.max_policies = max_policies
        self.key_slots = key_slots
        self._clock = clock
        self._lock = threading.RLock()
        self._state = self._new_state()

    @staticmethod
    def _new_state() -> dict:
        return {
            "version": 1,
            "dirs": {},
            "policies": {},
            "keys": [],
            "policy_seq": 0,
            "stats": {
                "rotations_done": 0,
                "rotations_partial": 0,
                "denied": 0,
            },
        }

    def _deny(self, code: str, detail: object = None):
        self._state["stats"]["denied"] += 1
        raise FscryptError(code, detail)

    @staticmethod
    def _canonical_path(path: object) -> str:
        if not isinstance(path, str):
            raise FscryptError("FSCRYPT_INVALID_PATH", path)
        if not path.startswith("/") or "\x00" in path:
            raise FscryptError("FSCRYPT_INVALID_PATH", path)
        if path != "/":
            components = path.split("/")[1:]
            if not components or any(
                part in ("", ".", "..") for part in components
            ):
                raise FscryptError("FSCRYPT_INVALID_PATH", path)
        return path

    def _valid_path(self, path: object) -> str:
        try:
            return self._canonical_path(path)
        except FscryptError:
            self._state["stats"]["denied"] += 1
            raise

    def _valid_name(self, name: object) -> str:
        if (
            not isinstance(name, str)
            or not name
            or "/" in name
            or "\x00" in name
            or name in (".", "..")
        ):
            self._deny("FSCRYPT_NOT_FOUND", name)
        return name

    def _require_dir(self, path: str) -> dict:
        directory = self._state["dirs"].get(path)
        if directory is None:
            self._deny("FSCRYPT_NO_DIR", path)
        return directory

    def _require_policy(self, path: str) -> dict:
        policy = self._state["policies"].get(path)
        if policy is None:
            self._deny("FSCRYPT_NO_POLICY", path)
        return policy

    @staticmethod
    def _is_under(path: str, root: str) -> bool:
        if root == "/":
            return path.startswith("/")
        return path == root or path.startswith(root + "/")

    def _is_nonempty(self, path: str, directory: dict) -> bool:
        return bool(directory["files"])

    def _ancestor_policy(self, path: str, extra: dict | None = None) -> dict | None:
        parent = posixpath.dirname(path)
        while True:
            if extra is not None and parent in extra:
                return extra[parent]
            policy = self._state["policies"].get(parent)
            if policy is not None:
                return policy
            if parent == "/":
                return None
            parent = posixpath.dirname(parent)

    def _peek_policy_id(self) -> str:
        return f"pol-{self._state['policy_seq'] + 1}"

    @staticmethod
    def _make_policy(path: str, policy_id: str, mode: str,
                     key_desc: str) -> dict:
        return {
            "path": path,
            "policy_id": policy_id,
            "mode": mode,
            "key_desc": key_desc,
            "key_state": "locked",
            "rotation_state": "idle",
            "rotation_pending": 0,
            "rotation_total": 0,
            "rotation": None,
        }

    def _record(self, path: str) -> PolicyRecord:
        policy = self._state["policies"][path]
        return PolicyRecord(
            path=policy["path"],
            policy_id=policy["policy_id"],
            mode=policy["mode"],
            key_desc=policy["key_desc"],
            key_state=policy["key_state"],
            rotation_state=policy["rotation_state"],
            rotation_pending=policy["rotation_pending"],
            rotation_total=policy["rotation_total"],
        )

    def _has_key(self, policy_id: str, key_desc: str) -> bool:
        return any(
            key[0] == policy_id and key[1] == key_desc
            for key in self._state["keys"]
        )

    def _key_in_use(self, policy_id: str, key_desc: str) -> bool:
        for policy in self._state["policies"].values():
            if policy["policy_id"] != policy_id:
                continue
            if policy["key_desc"] == key_desc:
                return True
            rotation = policy.get("rotation")
            if rotation and key_desc in (
                rotation["old_key_desc"],
                rotation["new_key_desc"],
            ):
                return True
            directory = self._state["dirs"].get(policy["path"])
            if directory is not None:
                for file_record in directory["files"].values():
                    if file_record.get("key_desc") == key_desc:
                        return True
        return False

    def _rotation_view(self, policy: dict) -> dict:
        rotation = policy.get("rotation") or {}
        return {
            "old_key_desc": rotation.get("old_key_desc", policy["key_desc"]),
            "new_key_desc": rotation.get("new_key_desc", policy["key_desc"]),
            "total": policy["rotation_total"],
            "pending": policy["rotation_pending"],
            "state": policy["rotation_state"],
        }

    def mkdir(self, path: str) -> None:
        with self._lock:
            path = self._valid_path(path)
            if path == "/" or path in self._state["dirs"]:
                self._deny("FSCRYPT_EXISTS", path)
            parent = posixpath.dirname(path)
            if parent != "/" and parent not in self._state["dirs"]:
                self._deny("FSCRYPT_NO_DIR", path)
            self._state["dirs"][path] = {"files": {}}

    def register_file(self, path: str, name: str, size: int = 4096) -> int:
        with self._lock:
            path = self._valid_path(path)
            directory = self._require_dir(path)
            name = self._valid_name(name)
            policy = self._state["policies"].get(path)
            key_desc = policy["key_desc"] if policy is not None else None
            file_record = directory["files"].get(name)
            if file_record is None:
                directory["files"][name] = {
                    "data": "",
                    "size": size,
                    "key_desc": key_desc,
                }
            else:
                file_record["size"] = size
            return int(size)

    def set_policy(self, path: str, *, mode: str, key_desc: str,
                   policy_id: str | None = None,
                   recursive: bool = False) -> PolicyRecord:
        with self._lock:
            path = self._valid_path(path)
            directory = self._require_dir(path)
            if not isinstance(mode, str) or mode not in MODE_RANK:
                self._deny("FSCRYPT_UNSUPPORTED_MODE", mode)

            existing = self._state["policies"].get(path)
            if (
                existing is None
                and self._is_nonempty(path, directory)
                and not recursive
            ):
                self._deny("FSCRYPT_DIR_NOT_EMPTY", path)

            ancestor = self._ancestor_policy(path)
            generated_id = False
            if ancestor is not None:
                if policy_id is not None and policy_id != ancestor["policy_id"]:
                    self._deny("FSCRYPT_POLICY_MISMATCH", policy_id)
                if key_desc != ancestor["key_desc"]:
                    self._deny("FSCRYPT_KEY_MISMATCH", key_desc)
                if MODE_RANK[mode] < MODE_RANK[ancestor["mode"]]:
                    self._deny("FSCRYPT_MODE_WIDEN", mode)
                effective_id = ancestor["policy_id"]
            elif policy_id is not None:
                effective_id = policy_id
            else:
                effective_id = self._peek_policy_id()
                generated_id = True

            planned: dict[str, dict] = {}
            new_policy_count = 0
            if existing is None:
                planned[path] = self._make_policy(
                    path, effective_id, mode, key_desc
                )
                new_policy_count += 1

            if recursive:
                descendants = sorted(
                    candidate
                    for candidate in self._state["dirs"]
                    if candidate != path and self._is_under(candidate, path)
                )
                for child in descendants:
                    if child in self._state["policies"]:
                        continue
                    child_ancestor = self._ancestor_policy(child, planned)
                    if child_ancestor is None:
                        child_policy = self._make_policy(
                            child,
                            effective_id,
                            mode,
                            key_desc,
                        )
                    else:
                        child_policy = self._make_policy(
                            child,
                            child_ancestor["policy_id"],
                            child_ancestor["mode"],
                            child_ancestor["key_desc"],
                        )
                    planned[child] = child_policy
                    new_policy_count += 1

            if (
                len(self._state["policies"]) + new_policy_count
                > self.max_policies
            ):
                self._deny("FSCRYPT_POLICY_LIMIT", self.max_policies)

            if existing is not None:
                existing["policy_id"] = effective_id
                existing["mode"] = mode
                existing["key_desc"] = key_desc

            for policy_path, policy in planned.items():
                self._state["policies"][policy_path] = policy
                policy_directory = self._state["dirs"][policy_path]
                for file_record in policy_directory["files"].values():
                    if file_record.get("key_desc") is None:
                        file_record["key_desc"] = policy["key_desc"]

            if generated_id:
                self._state["policy_seq"] += 1

            return self._record(path)

    def unlock(self, path: str, key_desc: str) -> int:
        with self._lock:
            path = self._valid_path(path)
            self._require_dir(path)
            policy = self._require_policy(path)
            policy_id = policy["policy_id"]
            if not isinstance(key_desc, str) or not self._has_key(
                policy_id, key_desc
            ):
                self._deny("FSCRYPT_KEY_UNAVAILABLE", (policy_id, key_desc))

            affected = [
                policy_path
                for policy_path in sorted(self._state["policies"])
                if self._is_under(policy_path, path)
            ]
            for policy_path in affected:
                self._state["policies"][policy_path]["key_state"] = "unlocked"
            return len(affected)

    def lock(self, path: str) -> int:
        with self._lock:
            path = self._valid_path(path)
            self._require_dir(path)
            self._require_policy(path)
            affected = [
                policy_path
                for policy_path in sorted(self._state["policies"])
                if self._is_under(policy_path, path)
            ]
            for policy_path in affected:
                self._state["policies"][policy_path]["key_state"] = "locked"
            return len(affected)

    def read_file(self, path: str, name: str) -> str:
        with self._lock:
            path = self._valid_path(path)
            directory = self._require_dir(path)
            name = self._valid_name(name)
            policy = self._require_policy(path)
            if policy["key_state"] != "unlocked":
                self._deny("FSCRYPT_LOCKED", path)
            file_record = directory["files"].get(name)
            if file_record is None:
                self._deny("FSCRYPT_NOT_FOUND", name)
            return file_record["data"]

    def write_file(self, path: str, name: str, data: str = "") -> str:
        with self._lock:
            path = self._valid_path(path)
            directory = self._require_dir(path)
            name = self._valid_name(name)
            policy = self._require_policy(path)
            if policy["key_state"] != "unlocked":
                self._deny("FSCRYPT_LOCKED", path)

            rotation = policy.get("rotation")
            if policy["rotation_state"] == "partial" and rotation is not None:
                key_desc = rotation["new_key_desc"]
            else:
                key_desc = policy["key_desc"]

            directory["files"][name] = {
                "data": data,
                "size": len(data.encode("utf-8")) if isinstance(data, str) else 0,
                "key_desc": key_desc,
            }
            return key_desc

    def file_key(self, path: str, name: str) -> str:
        with self._lock:
            path = self._valid_path(path)
            directory = self._require_dir(path)
            name = self._valid_name(name)
            policy = self._require_policy(path)
            file_record = directory["files"].get(name)
            if file_record is None:
                self._deny("FSCRYPT_NOT_FOUND", name)
            key_desc = file_record.get("key_desc")
            return key_desc if key_desc is not None else policy["key_desc"]

    def rotate(self, path: str, new_key_desc: str, *,
               interrupt_after: int | None = None) -> dict:
        with self._lock:
            path = self._valid_path(path)
            directory = self._require_dir(path)
            policy = self._require_policy(path)
            if policy["key_state"] != "unlocked":
                self._deny("FSCRYPT_LOCKED", path)
            if policy["rotation_state"] == "partial":
                self._deny("FSCRYPT_ROTATION_BUSY", path)
            if new_key_desc == policy["key_desc"]:
                self._deny("FSCRYPT_BAD_ROTATION", new_key_desc)
            if interrupt_after is not None and (
                not isinstance(interrupt_after, int)
                or isinstance(interrupt_after, bool)
                or interrupt_after < 0
            ):
                self._deny("FSCRYPT_BAD_ROTATION", interrupt_after)

            policy_id = policy["policy_id"]
            if not self._has_key(policy_id, new_key_desc):
                if len(self._state["keys"]) >= self.key_slots:
                    self._deny(
                        "FSCRYPT_KEY_SLOT_EXHAUSTED",
                        {"policy_id": policy_id, "key_desc": new_key_desc},
                    )
                self._state["keys"].append([policy_id, new_key_desc])

            names = sorted(directory["files"])
            policy["rotation"] = {
                "old_key_desc": policy["key_desc"],
                "new_key_desc": new_key_desc,
                "file_order": names,
                "state": "partial",
            }
            policy["rotation_total"] = len(names)
            policy["rotation_pending"] = len(names)
            policy["rotation_state"] = "partial"

            return self._advance_rotation(
                path, policy, interrupt_after, initial=True
            )

    def resume_rotation(self, path: str) -> dict:
        with self._lock:
            path = self._valid_path(path)
            self._require_dir(path)
            policy = self._require_policy(path)
            if policy["rotation_state"] == "done":
                return self._rotation_view(policy)
            if policy["rotation_state"] != "partial" or policy["rotation"] is None:
                return self._rotation_view(policy)
            if policy["key_state"] != "unlocked":
                self._deny("FSCRYPT_LOCKED", path)
            return self._advance_rotation(path, policy, None, initial=False)

    def _advance_rotation(
        self,
        path: str,
        policy: dict,
        limit: int | None,
        *,
        initial: bool,
    ) -> dict:
        rotation = policy["rotation"]
        directory = self._state["dirs"][path]
        new_key_desc = rotation["new_key_desc"]
        processed = 0

        for name in rotation["file_order"]:
            file_record = directory["files"].get(name)
            if file_record is None:
                continue
            if file_record.get("key_desc") == new_key_desc:
                continue
            if limit is not None and processed >= limit:
                break
            file_record["key_desc"] = new_key_desc
            processed += 1

        pending = 0
        for name in rotation["file_order"]:
            file_record = directory["files"].get(name)
            if (
                file_record is None
                or file_record.get("key_desc") != new_key_desc
            ):
                pending += 1

        policy["rotation_pending"] = pending
        if pending == 0:
            old_key_desc = rotation["old_key_desc"]
            policy["key_desc"] = new_key_desc
            policy["rotation_state"] = "done"
            policy["rotation_pending"] = 0
            rotation["state"] = "done"
            policy_id = policy["policy_id"]
            self._state["keys"] = [
                key
                for key in self._state["keys"]
                if not (
                    key[0] == policy_id and key[1] == old_key_desc
                )
            ]
            self._state["stats"]["rotations_done"] += 1
        else:
            policy["rotation_state"] = "partial"
            rotation["state"] = "partial"
            if initial:
                self._state["stats"]["rotations_partial"] += 1

        return self._rotation_view(policy)

    def add_key(self, key_desc: str, *, policy_id: str) -> int:
        with self._lock:
            if self._has_key(policy_id, key_desc):
                self._deny("FSCRYPT_KEY_EXISTS", (policy_id, key_desc))
            if len(self._state["keys"]) >= self.key_slots:
                self._deny("FSCRYPT_KEY_SLOT_EXHAUSTED", self.key_slots)
            self._state["keys"].append([policy_id, key_desc])
            return len(self._state["keys"])

    def drop_key(self, key_desc: str, *, policy_id: str) -> int:
        with self._lock:
            for index, key in enumerate(self._state["keys"]):
                if key[0] == policy_id and key[1] == key_desc:
                    if self._key_in_use(policy_id, key_desc):
                        self._deny(
                            "FSCRYPT_KEY_IN_USE",
                            {"policy_id": policy_id, "key_desc": key_desc},
                        )
                    self._state["keys"].pop(index)
                    break
            return len(self._state["keys"])

    def keys(self) -> tuple:
        with self._lock:
            return tuple(sorted(
                (key[0], key[1]) for key in self._state["keys"]
            ))

    def policies(self) -> list:
        with self._lock:
            return [
                self._record(path)
                for path in sorted(self._state["policies"])
            ]

    def status(self, path: str) -> dict:
        with self._lock:
            path = self._valid_path(path)
            directory = self._require_dir(path)
            policy = self._require_policy(path)
            return {
                "path": path,
                "policy_id": policy["policy_id"],
                "mode": policy["mode"],
                "key_desc": policy["key_desc"],
                "key_state": policy["key_state"],
                "rotation_state": policy["rotation_state"],
                "rotation_pending": policy["rotation_pending"],
                "rotation_total": policy["rotation_total"],
                "files": len(directory["files"]),
            }

    def rename(self, old: str, new: str) -> PolicyRecord:
        with self._lock:
            old = self._valid_path(old)
            new = self._valid_path(new)
            if old not in self._state["dirs"]:
                self._deny("FSCRYPT_NO_DIR", old)
            if new in self._state["dirs"]:
                self._deny("FSCRYPT_EXISTS", new)
            new_parent = posixpath.dirname(new)
            if new_parent != "/" and new_parent not in self._state["dirs"]:
                self._deny("FSCRYPT_NO_DIR", new_parent)
            if new_parent != "/":
                parent_record = self._state["dirs"][new_parent]
                new_name = new.rsplit("/", 1)[-1]
                if new_name in parent_record["files"]:
                    self._deny("FSCRYPT_EXISTS", new)
            if new == old or self._is_under(new, old):
                self._deny("FSCRYPT_INVALID_PATH", {"old": old, "new": new})

            old_prefix = "" if old == "/" else old
            moved = [
                path
                for path in list(self._state["dirs"])
                if path == old or (
                    old != "/" and path.startswith(old_prefix + "/")
                ) or (old == "/" and path != old)
            ]
            for old_path in moved:
                if old == "/":
                    suffix = old_path
                    new_path = new.rstrip("/") + suffix
                else:
                    suffix = old_path[len(old):]
                    new_path = new + suffix
                directory = self._state["dirs"].pop(old_path)
                self._state["dirs"][new_path] = directory

                policy = self._state["policies"].pop(old_path, None)
                if policy is not None:
                    policy["path"] = new_path
                    self._state["policies"][new_path] = policy

            if new in self._state["policies"]:
                return self._record(new)
            return None

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                candidate = copy.deepcopy(state)
                clean = self._validate_snapshot(candidate)
            except Exception as exc:
                raise FscryptError(
                    "FSCRYPT_SNAPSHOT_INVALID", "snapshot structure is invalid"
                ) from exc
            self._state = clean

    def _validate_snapshot(self, state: object) -> dict:
        if not isinstance(state, dict):
            raise ValueError("snapshot must be a dict")
        required = {
            "version", "dirs", "policies", "keys", "policy_seq", "stats"
        }
        if not required.issubset(state):
            raise ValueError("snapshot is missing required keys")

        dirs = self._validate_snapshot_dirs(state["dirs"])
        policies = self._validate_snapshot_policies(
            state["policies"], dirs
        )
        keys = self._validate_snapshot_keys(state["keys"])

        policy_seq = state["policy_seq"]
        if (
            not isinstance(policy_seq, int)
            or isinstance(policy_seq, bool)
            or policy_seq < 0
        ):
            raise ValueError("invalid policy sequence")

        stats_state = state["stats"]
        if not isinstance(stats_state, dict):
            raise ValueError("invalid stats")
        stats = {
            "rotations_done": stats_state["rotations_done"],
            "rotations_partial": stats_state["rotations_partial"],
            "denied": stats_state["denied"],
        }
        for name, value in stats.items():
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise ValueError(f"invalid stat {name}")

        return {
            "version": 1,
            "dirs": dirs,
            "policies": policies,
            "keys": keys,
            "policy_seq": policy_seq,
            "stats": stats,
        }

    def _validate_snapshot_dirs(self, raw_dirs: object) -> dict:
        if not isinstance(raw_dirs, dict):
            raise ValueError("dirs must be a dict")
        dirs = {}
        for path, directory in raw_dirs.items():
            path = self._canonical_path(path)
            if not isinstance(directory, dict):
                raise ValueError("directory must be a dict")
            raw_files = directory.get("files")
            if not isinstance(raw_files, dict):
                raise ValueError("files must be a dict")
            files = {}
            for name, file_record in raw_files.items():
                if not isinstance(name, str) or not name:
                    raise ValueError("file name must be nonempty")
                if not isinstance(file_record, dict):
                    raise ValueError("file record must be a dict")
                key_desc = file_record.get("key_desc")
                if key_desc is not None and not isinstance(key_desc, str):
                    raise ValueError("file key must be a string")
                files[name] = {
                    "data": file_record.get("data", ""),
                    "size": file_record.get("size", 0),
                    "key_desc": key_desc,
                }
            dirs[path] = {"files": files}
        return dirs

    def _validate_snapshot_policies(self, raw_policies: object,
                                    dirs: dict) -> dict:
        if not isinstance(raw_policies, dict):
            raise ValueError("policies must be a dict")
        policies = {}
        for path, policy in raw_policies.items():
            path = self._canonical_path(path)
            if path not in dirs or not isinstance(policy, dict):
                raise ValueError("policy references missing directory")
            policy_path = self._canonical_path(policy.get("path", path))
            if policy_path != path:
                raise ValueError("policy path mismatch")
            policy_id = policy.get("policy_id")
            mode = policy.get("mode")
            key_desc = policy.get("key_desc")
            key_state = policy.get("key_state")
            rotation_state = policy.get("rotation_state", "idle")
            if not isinstance(policy_id, str) or not policy_id:
                raise ValueError("invalid policy id")
            if mode not in MODE_RANK:
                raise ValueError("invalid mode")
            if not isinstance(key_desc, str) or not key_desc:
                raise ValueError("invalid key descriptor")
            if key_state not in ("locked", "unlocked"):
                raise ValueError("invalid key state")
            if rotation_state not in ("idle", "partial", "done"):
                raise ValueError("invalid rotation state")

            rotation = policy.get("rotation")
            rotation_total = policy.get("rotation_total", 0)
            rotation_pending = policy.get("rotation_pending", 0)
            if (
                not isinstance(rotation_total, int)
                or isinstance(rotation_total, bool)
                or rotation_total < 0
                or not isinstance(rotation_pending, int)
                or isinstance(rotation_pending, bool)
                or not 0 <= rotation_pending <= rotation_total
            ):
                raise ValueError("invalid rotation progress")
            if rotation is not None:
                rotation = self._validate_snapshot_rotation(
                    rotation, dirs[path], rotation_state
                )

            policies[path] = {
                "path": path,
                "policy_id": policy_id,
                "mode": mode,
                "key_desc": key_desc,
                "key_state": key_state,
                "rotation_state": rotation_state,
                "rotation_pending": rotation_pending,
                "rotation_total": rotation_total,
                "rotation": rotation,
            }
        return policies

    def _validate_snapshot_rotation(self, rotation: object, directory: dict,
                                    rotation_state: str) -> dict:
        if not isinstance(rotation, dict):
            raise ValueError("rotation must be a dict")
        old_key_desc = rotation.get("old_key_desc")
        new_key_desc = rotation.get("new_key_desc")
        file_order = rotation.get("file_order")
        if not isinstance(old_key_desc, str) or not old_key_desc:
            raise ValueError("invalid old rotation key")
        if not isinstance(new_key_desc, str) or not new_key_desc:
            raise ValueError("invalid new rotation key")
        if not isinstance(file_order, list) or not all(
            isinstance(name, str) for name in file_order
        ):
            raise ValueError("invalid rotation file order")
        if any(name not in directory["files"] for name in file_order):
            raise ValueError("rotation references missing file")
        state = rotation.get("state", rotation_state)
        if state not in ("partial", "done"):
            raise ValueError("invalid rotation record state")
        return {
            "old_key_desc": old_key_desc,
            "new_key_desc": new_key_desc,
            "file_order": list(file_order),
            "state": state,
        }

    @staticmethod
    def _validate_snapshot_keys(raw_keys: object) -> list:
        if not isinstance(raw_keys, (list, tuple)):
            raise ValueError("keys must be a list")
        keys = []
        for key in raw_keys:
            if not isinstance(key, (list, tuple)) or len(key) != 2:
                raise ValueError("key slot must be a pair")
            policy_id, key_desc = key
            if not isinstance(policy_id, str) or not isinstance(key_desc, str):
                raise ValueError("key pair must contain strings")
            normalized = [policy_id, key_desc]
            if normalized not in keys:
                keys.append(normalized)
        return keys

    def stats(self) -> dict:
        with self._lock:
            files = sum(
                len(directory["files"])
                for directory in self._state["dirs"].values()
            )
            unlocked = sum(
                policy["key_state"] == "unlocked"
                for policy in self._state["policies"].values()
            )
            counters = self._state["stats"]
            return {
                "policies": len(self._state["policies"]),
                "dirs": len(self._state["dirs"]),
                "files": files,
                "unlocked": unlocked,
                "rotations_done": counters["rotations_done"],
                "rotations_partial": counters["rotations_partial"],
                "denied": counters["denied"],
            }
