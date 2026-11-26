"""Repository trust arbitration: per-source keyrings, pins and downgrade control."""

from __future__ import annotations

import copy
import hashlib
import hmac
import re
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from functools import cmp_to_key
from itertools import zip_longest


ERR_INVALID_REQUEST = "REPO_INVALID_REQUEST"
ERR_KEY_CONFLICT = "REPO_KEY_CONFLICT"
ERR_KEY_UNKNOWN = "REPO_KEY_UNKNOWN"
ERR_KEY_ALREADY_BOUND = "REPO_KEY_ALREADY_BOUND"
ERR_KEY_NOT_BOUND = "REPO_KEY_NOT_BOUND"
ERR_SOURCE_DUPLICATE = "REPO_SOURCE_DUPLICATE"
ERR_SOURCE_UNKNOWN = "REPO_SOURCE_UNKNOWN"
ERR_COMPONENT_UNKNOWN = "REPO_COMPONENT_UNKNOWN"
ERR_RELEASE_SCOPE_MISMATCH = "REPO_RELEASE_SCOPE_MISMATCH"
ERR_RELEASE_SIGNATURE_INVALID = "REPO_RELEASE_SIGNATURE_INVALID"
ERR_RELEASE_EXPIRED = "REPO_RELEASE_EXPIRED"
ERR_NO_CANDIDATE = "REPO_NO_CANDIDATE"
ERR_DOWNGRADE_REFUSED = "REPO_DOWNGRADE_REFUSED"
ERR_PACKAGE_DUPLICATE = "REPO_PACKAGE_DUPLICATE"
ERR_SNAPSHOT_INVALID = "REPO_SNAPSHOT_INVALID"

STATE_UNVERIFIED = "unverified"
STATE_USABLE = "usable"
STATE_EXPIRED = "expired"
_SOURCE_STATES = (STATE_UNVERIFIED, STATE_USABLE, STATE_EXPIRED)

_SNAPSHOT_SCHEMA = "repo_trust_arbiter_state"
_SNAPSHOT_VERSION = 1
_STATS_KEYS = (
    "keys_added",
    "sources_added",
    "sources_removed",
    "packages_indexed",
    "verified",
    "resolved",
    "downgrades_refused",
)
_VERSION_NUMBER_RE = re.compile(r"\d+")


class RepoError(ValueError):
    """Raised when a repository operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class SourceInfo:
    source_id: str
    origin: str
    suite: str
    components: tuple
    priority: int
    keys: tuple
    state: str
    valid_until: object
    packages: int = 0

    def __getitem__(self, key: str) -> object:
        try:
            return getattr(self, key)
        except AttributeError as exc:
            raise KeyError(key) from exc

    def get(self, key: str, default: object = None) -> object:
        return getattr(self, key, default)


@dataclass(frozen=True)
class Candidate:
    name: str
    version: str
    source_id: str
    priority: int
    suite: str


@dataclass(frozen=True)
class ResolveResult:
    name: str
    version: str
    source_id: str
    priority: int
    action: str


def _parse_time(value: object) -> datetime:
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, str):
        text = value.strip()
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise RepoError(ERR_INVALID_REQUEST, {"value": value}) from exc
    else:
        raise RepoError(ERR_INVALID_REQUEST, {"value": value})

    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _coerce_now(now: object | None) -> datetime:
    if now is None:
        return datetime.now(timezone.utc)
    return _parse_time(now)


def _version_parts(version: object) -> tuple[int, ...]:
    return tuple(int(part) for part in _VERSION_NUMBER_RE.findall(str(version)))


def compare_versions(left: object, right: object) -> int:
    """Compare dot/numeric versions by integer value of each numeric field."""

    left_parts = _version_parts(left)
    right_parts = _version_parts(right)
    for left_value, right_value in zip_longest(
        left_parts, right_parts, fillvalue=0
    ):
        if left_value == right_value:
            continue
        return -1 if left_value < right_value else 1
    return 0


def _string_tuple(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    try:
        result = tuple(value)
    except TypeError as exc:
        raise RepoError(ERR_INVALID_REQUEST, {"value": value}) from exc
    if not all(isinstance(item, str) for item in result):
        raise RepoError(ERR_INVALID_REQUEST, {"value": value})
    return result


def _priority(value: object) -> int:
    if not isinstance(value, int) or isinstance(value, bool):
        raise RepoError(ERR_INVALID_REQUEST, {"priority": value})
    return value


class RepoTrustArbiter:
    """Decide whether a package version from some source may be installed."""

    def __init__(self, *, installed_versions=None, arch: str = "amd64") -> None:
        self.installed_versions = dict(installed_versions or {})
        self.arch = arch
        self._lock = threading.RLock()
        self._keys: dict[str, str] = {}
        self._key_owner: dict[str, str] = {}
        self._sources: dict[str, dict] = {}
        self._pins: dict[str, dict[str, dict]] = {}
        self._stats: dict[str, int] = {key: 0 for key in _STATS_KEYS}

    def add_key(self, key_id: str, material: str) -> None:
        with self._lock:
            if not isinstance(key_id, str) or not key_id:
                raise RepoError(ERR_INVALID_REQUEST, {"key_id": key_id})
            if not isinstance(material, str):
                raise RepoError(ERR_INVALID_REQUEST, {"key_id": key_id})
            if key_id in self._keys:
                raise RepoError(ERR_KEY_CONFLICT, {"key_id": key_id})
            self._keys[key_id] = material
            self._stats["keys_added"] += 1

    def revoke_key(self, key_id: str) -> bool:
        with self._lock:
            if key_id not in self._keys:
                return False

            del self._keys[key_id]
            source_id = self._key_owner.pop(key_id, None)
            source = self._sources.get(source_id) if source_id else None
            if source is not None:
                source["keys"] = tuple(
                    key for key in source["keys"] if key != key_id
                )
                release = source.get("release")
                if isinstance(release, dict) and release.get("key_id") == key_id:
                    source["state"] = STATE_UNVERIFIED
                    source["valid_until"] = None
                    source["release"] = None
            return True

    def add_source(self, source_id: str, *, origin: str, suite: str,
                   components=(), priority: int = 100, keys=()) -> SourceInfo:
        with self._lock:
            if not isinstance(source_id, str) or not source_id:
                raise RepoError(ERR_INVALID_REQUEST, {"source_id": source_id})
            if source_id in self._sources:
                raise RepoError(
                    ERR_SOURCE_DUPLICATE, {"source_id": source_id}
                )

            if not isinstance(origin, str) or not origin:
                raise RepoError(ERR_INVALID_REQUEST, {"origin": origin})
            if not isinstance(suite, str) or not suite:
                raise RepoError(ERR_INVALID_REQUEST, {"suite": suite})

            component_tuple = _string_tuple(components)
            key_tuple = tuple(dict.fromkeys(_string_tuple(keys)))
            priority_value = _priority(priority)

            for key_id in key_tuple:
                if key_id not in self._keys:
                    raise RepoError(ERR_KEY_UNKNOWN, {"key_id": key_id})

            for key_id in key_tuple:
                owner = self._key_owner.get(key_id)
                if owner is not None:
                    raise RepoError(
                        ERR_KEY_ALREADY_BOUND,
                        {"key_id": key_id, "source_id": owner},
                    )

            source = {
                "source_id": source_id,
                "origin": origin,
                "suite": suite,
                "components": component_tuple,
                "priority": priority_value,
                "keys": key_tuple,
                "state": STATE_UNVERIFIED,
                "valid_until": None,
                "release": None,
                "packages": {},
            }
            self._sources[source_id] = source
            for key_id in key_tuple:
                self._key_owner[key_id] = source_id
            self._stats["sources_added"] += 1
            return self._source_info_locked(source)

    def remove_source(self, source_id: str) -> bool:
        with self._lock:
            source = self._sources.pop(source_id, None)
            if source is None:
                return False

            for key_id in source["keys"]:
                self._key_owner.pop(key_id, None)

            for package_name in list(self._pins):
                rules = self._pins[package_name]
                rules.pop(source_id, None)
                if not rules:
                    self._pins.pop(package_name, None)

            self._stats["sources_removed"] += 1
            return True

    def publish_package(self, source_id: str, *, name: str, version: str,
                        component: str, origin=None, suite=None,
                        arch: str = "amd64", digest: str = "") -> None:
        with self._lock:
            source = self._sources.get(source_id)
            if source is None:
                raise RepoError(ERR_SOURCE_UNKNOWN, {"source_id": source_id})
            if not isinstance(name, str) or not name:
                raise RepoError(ERR_INVALID_REQUEST, {"name": name})
            if not isinstance(version, str) or not version:
                raise RepoError(ERR_INVALID_REQUEST, {"version": version})
            if not isinstance(component, str):
                raise RepoError(ERR_INVALID_REQUEST, {"component": component})
            if component not in source["components"]:
                raise RepoError(
                    ERR_COMPONENT_UNKNOWN,
                    {"source_id": source_id, "component": component},
                )

            package_key = (name, version)
            if package_key in source["packages"]:
                raise RepoError(
                    ERR_PACKAGE_DUPLICATE,
                    {"source_id": source_id, "name": name, "version": version},
                )

            record_origin = source["origin"] if origin is None else origin
            record_suite = source["suite"] if suite is None else suite
            if not isinstance(record_origin, str):
                raise RepoError(ERR_INVALID_REQUEST, {"origin": origin})
            if not isinstance(record_suite, str):
                raise RepoError(ERR_INVALID_REQUEST, {"suite": suite})

            source["packages"][package_key] = {
                "name": name,
                "version": version,
                "component": component,
                "origin": record_origin,
                "suite": record_suite,
                "arch": arch,
                "digest": digest,
            }
            self._stats["packages_indexed"] += 1

    def verify_release(self, source_id: str, *, suite: str, origin: str,
                       valid_until: str, now: str, key_id: str,
                       signature: str) -> dict:
        with self._lock:
            source = self._sources.get(source_id)
            if source is None:
                raise RepoError(ERR_SOURCE_UNKNOWN, {"source_id": source_id})
            if key_id not in source["keys"]:
                raise RepoError(
                    ERR_KEY_NOT_BOUND,
                    {"source_id": source_id, "key_id": key_id},
                )

            material = self._keys.get(key_id)
            if not isinstance(material, str):
                raise RepoError(
                    ERR_KEY_UNKNOWN,
                    {"source_id": source_id, "key_id": key_id},
                )

            digest_body = (
                f"{origin}:{suite}:{valid_until}:{material}".encode("utf-8")
            )
            expected_signature = hashlib.sha256(digest_body).hexdigest()
            if not isinstance(signature, str) or not hmac.compare_digest(
                expected_signature, signature
            ):
                raise RepoError(
                    ERR_RELEASE_SIGNATURE_INVALID,
                    {"source_id": source_id, "key_id": key_id},
                )

            if origin != source["origin"] or suite != source["suite"]:
                raise RepoError(
                    ERR_RELEASE_SCOPE_MISMATCH,
                    {
                        "source_id": source_id,
                        "expected_origin": source["origin"],
                        "expected_suite": source["suite"],
                        "origin": origin,
                        "suite": suite,
                    },
                )

            now_time = _parse_time(now)
            valid_until_time = _parse_time(valid_until)
            report = {
                "source_id": source_id,
                "suite": suite,
                "origin": origin,
                "valid_until": valid_until,
                "key_id": key_id,
            }

            if valid_until_time <= now_time:
                source["state"] = STATE_EXPIRED
                source["valid_until"] = valid_until
                source["release"] = {
                    "suite": suite,
                    "origin": origin,
                    "valid_until": valid_until,
                    "key_id": key_id,
                    "signature": signature,
                }
                expired_report = dict(report, state=STATE_EXPIRED)
                raise RepoError(ERR_RELEASE_EXPIRED, expired_report)

            source["state"] = STATE_USABLE
            source["valid_until"] = valid_until
            source["release"] = {
                "suite": suite,
                "origin": origin,
                "valid_until": valid_until,
                "key_id": key_id,
                "signature": signature,
            }
            self._stats["verified"] += 1
            return dict(report, state=STATE_USABLE)

    def pin(self, package: str, *, source_id: str, priority: int,
            reason: str = "") -> None:
        with self._lock:
            if source_id not in self._sources:
                raise RepoError(ERR_SOURCE_UNKNOWN, {"source_id": source_id})
            if not isinstance(package, str) or not package:
                raise RepoError(ERR_INVALID_REQUEST, {"package": package})
            priority_value = _priority(priority)
            if not isinstance(reason, str):
                raise RepoError(ERR_INVALID_REQUEST, {"reason": reason})
            self._pins.setdefault(package, {})[source_id] = {
                "priority": priority_value,
                "reason": reason,
            }

    def unpin(self, package: str, *, source_id: str) -> bool:
        with self._lock:
            rules = self._pins.get(package)
            if not isinstance(rules, dict) or source_id not in rules:
                return False
            del rules[source_id]
            if not rules:
                self._pins.pop(package, None)
            return True

    def mark_installed(self, name: str, version: str) -> None:
        with self._lock:
            self.installed_versions[name] = version

    def candidates(self, name: str, *, now=None) -> list:
        with self._lock:
            return self._candidates_locked(name, now)

    def resolve(self, name: str, *, now=None, allow_downgrade: bool = False) -> ResolveResult:
        with self._lock:
            candidates = self._candidates_locked(name, now)
            if not candidates:
                raise RepoError(ERR_NO_CANDIDATE, {"name": name})

            selected = candidates[0]
            installed_version = self.installed_versions.get(name)
            if installed_version is None:
                action = "install"
            else:
                version_order = compare_versions(
                    selected.version, installed_version
                )
                if version_order < 0:
                    if not allow_downgrade:
                        self._stats["downgrades_refused"] += 1
                        raise RepoError(
                            ERR_DOWNGRADE_REFUSED,
                            {
                                "name": name,
                                "candidate": selected.version,
                                "installed": installed_version,
                                "source_id": selected.source_id,
                            },
                        )
                    action = "downgrade"
                elif version_order == 0:
                    action = "keep"
                else:
                    action = "install"

            self._stats["resolved"] += 1
            return ResolveResult(
                name=selected.name,
                version=selected.version,
                source_id=selected.source_id,
                priority=selected.priority,
                action=action,
            )

    def status(self, source_id=None) -> object:
        with self._lock:
            if source_id is None:
                return {
                    current_id: self._status_locked(source)
                    for current_id, source in self._sources.items()
                }
            source = self._sources.get(source_id)
            if source is None:
                return None
            return self._status_locked(source)

    def audit(self, *, now=None) -> dict:
        with self._lock:
            now_time = _coerce_now(now)
            usable = unverified = expired = 0
            package_count = 0
            for source in self._sources.values():
                state = self._effective_state_locked(source, now_time)
                if state == STATE_USABLE:
                    usable += 1
                elif state == STATE_EXPIRED:
                    expired += 1
                else:
                    unverified += 1
                package_count += len(source["packages"])

            pin_count = sum(len(rules) for rules in self._pins.values())
            return {
                "sources_total": len(self._sources),
                "usable": usable,
                "unverified": unverified,
                "expired": expired,
                "packages": package_count,
                "keys": len(self._keys),
                "pins": pin_count,
            }

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "schema": _SNAPSHOT_SCHEMA,
                "version": _SNAPSHOT_VERSION,
                "arch": self.arch,
                "installed_versions": self.installed_versions,
                "keys": self._keys,
                "key_owner": self._key_owner,
                "sources": self._sources,
                "pins": self._pins,
                "stats": self._stats,
            }
            return copy.deepcopy(state)

    def restore(self, state) -> None:
        with self._lock:
            try:
                valid_state = _coerce_snapshot_state(state)
            except Exception as exc:
                raise RepoError(ERR_SNAPSHOT_INVALID) from exc

            self.arch = valid_state["arch"]
            self.installed_versions = valid_state["installed_versions"]
            self._keys = valid_state["keys"]
            self._key_owner = valid_state["key_owner"]
            self._sources = valid_state["sources"]
            self._pins = valid_state["pins"]
            self._stats = valid_state["stats"]

    def stats(self) -> dict:
        with self._lock:
            return {key: self._stats[key] for key in _STATS_KEYS}

    def _source_info_locked(self, source: dict) -> SourceInfo:
        status = self._status_locked(source)
        return SourceInfo(
            source_id=status["source_id"],
            origin=status["origin"],
            suite=status["suite"],
            components=status["components"],
            priority=status["priority"],
            keys=status["keys"],
            state=status["state"],
            valid_until=status["valid_until"],
            packages=status["packages"],
        )

    def _status_locked(self, source: dict) -> dict:
        return {
            "source_id": source["source_id"],
            "origin": source["origin"],
            "suite": source["suite"],
            "components": tuple(source["components"]),
            "priority": source["priority"],
            "keys": tuple(source["keys"]),
            "state": source["state"],
            "valid_until": source["valid_until"],
            "packages": len(source["packages"]),
        }

    def _effective_state_locked(self, source: dict, now_time: datetime) -> str:
        state = source["state"]
        if state == STATE_USABLE and source.get("valid_until") is not None:
            try:
                if _parse_time(source["valid_until"]) <= now_time:
                    return STATE_EXPIRED
            except RepoError:
                return STATE_EXPIRED
        return state

    def _candidates_locked(self, name: str, now: object | None) -> list:
        now_time = _coerce_now(now)
        rows = []
        for source_id, source in self._sources.items():
            state = self._effective_state_locked(source, now_time)
            if state != STATE_USABLE:
                continue

            pin_rules = self._pins.get(name, {})
            for package in source["packages"].values():
                if package["name"] != name:
                    continue
                if package.get("arch") not in (self.arch, "all"):
                    continue
                if package.get("origin") != source["origin"]:
                    continue
                if package.get("suite") != source["suite"]:
                    continue

                pin = pin_rules.get(source_id)
                priority = (
                    pin["priority"] if isinstance(pin, dict) else source["priority"]
                )
                rows.append(
                    Candidate(
                        name=package["name"],
                        version=package["version"],
                        source_id=source_id,
                        priority=priority,
                        suite=package["suite"],
                    )
                )

        rows.sort(key=cmp_to_key(_compare_candidate_rows))
        return rows


def _compare_candidate_rows(left: Candidate, right: Candidate) -> int:
    if left.priority != right.priority:
        return -1 if left.priority > right.priority else 1

    version_order = compare_versions(left.version, right.version)
    if version_order != 0:
        return -version_order

    if left.source_id != right.source_id:
        return -1 if left.source_id < right.source_id else 1
    return 0


def _coerce_snapshot_state(state: object) -> dict:
    data = copy.deepcopy(state)
    if not isinstance(data, dict):
        raise ValueError("snapshot must be a dictionary")
    if data.get("schema") != _SNAPSHOT_SCHEMA:
        raise ValueError("unsupported snapshot schema")
    if data.get("version") != _SNAPSHOT_VERSION:
        raise ValueError("unsupported snapshot version")

    arch = data.get("arch")
    if not isinstance(arch, str) or not arch:
        raise ValueError("invalid architecture")

    installed_raw = data.get("installed_versions")
    if not isinstance(installed_raw, dict):
        raise ValueError("invalid installed versions")
    installed_versions = {}
    for name, version in installed_raw.items():
        if not isinstance(name, str) or not isinstance(version, str):
            raise ValueError("invalid installed version entry")
        installed_versions[name] = version

    keys_raw = data.get("keys")
    if not isinstance(keys_raw, dict):
        raise ValueError("invalid keys")
    keys = {}
    for key_id, material in keys_raw.items():
        if not isinstance(key_id, str) or not isinstance(material, str):
            raise ValueError("invalid key entry")
        keys[key_id] = material

    sources_raw = data.get("sources")
    if not isinstance(sources_raw, dict):
        raise ValueError("invalid sources")
    sources = {}
    expected_owner = {}

    for source_id, source_raw in sources_raw.items():
        if not isinstance(source_id, str) or not isinstance(source_raw, dict):
            raise ValueError("invalid source entry")
        if source_raw.get("source_id") != source_id:
            raise ValueError("source id mismatch")

        origin = source_raw.get("origin")
        suite = source_raw.get("suite")
        if not isinstance(origin, str) or not origin:
            raise ValueError("invalid source origin")
        if not isinstance(suite, str) or not suite:
            raise ValueError("invalid source suite")

        components = _string_tuple(source_raw.get("components", ()))
        key_ids = tuple(dict.fromkeys(_string_tuple(source_raw.get("keys", ()))))
        priority = _priority(source_raw.get("priority"))
        state_name = source_raw.get("state")
        if state_name not in _SOURCE_STATES:
            raise ValueError("invalid source state")

        valid_until = source_raw.get("valid_until")
        if valid_until is not None:
            if not isinstance(valid_until, str):
                raise ValueError("invalid valid_until")
            _parse_time(valid_until)

        release = source_raw.get("release")
        if release is not None and not isinstance(release, dict):
            raise ValueError("invalid release")

        packages_raw = source_raw.get("packages", {})
        if not isinstance(packages_raw, dict):
            raise ValueError("invalid packages")
        packages = {}
        for package_key, package_raw in packages_raw.items():
            if not isinstance(package_key, (tuple, list)) or len(package_key) != 2:
                raise ValueError("invalid package key")
            name, version = package_key
            if not isinstance(name, str) or not isinstance(version, str):
                raise ValueError("invalid package key")
            if not isinstance(package_raw, dict):
                raise ValueError("invalid package record")
            if package_raw.get("name") != name:
                raise ValueError("package name mismatch")
            if package_raw.get("version") != version:
                raise ValueError("package version mismatch")

            component = package_raw.get("component")
            package_origin = package_raw.get("origin")
            package_suite = package_raw.get("suite")
            package_arch = package_raw.get("arch")
            digest = package_raw.get("digest", "")
            if not all(
                isinstance(value, str)
                for value in (component, package_origin, package_suite,
                              package_arch, digest)
            ):
                raise ValueError("invalid package field")

            packages[(name, version)] = {
                "name": name,
                "version": version,
                "component": component,
                "origin": package_origin,
                "suite": package_suite,
                "arch": package_arch,
                "digest": digest,
            }

        for key_id in key_ids:
            if key_id not in keys:
                raise ValueError("source references unknown key")
            if key_id in expected_owner:
                raise ValueError("key bound to multiple sources")
            expected_owner[key_id] = source_id

        sources[source_id] = {
            "source_id": source_id,
            "origin": origin,
            "suite": suite,
            "components": components,
            "priority": priority,
            "keys": key_ids,
            "state": state_name,
            "valid_until": valid_until,
            "release": copy.deepcopy(release),
            "packages": packages,
        }

    key_owner_raw = data.get("key_owner")
    if not isinstance(key_owner_raw, dict):
        raise ValueError("invalid key owner")
    key_owner = {}
    for key_id, source_id in key_owner_raw.items():
        if not isinstance(key_id, str) or not isinstance(source_id, str):
            raise ValueError("invalid key owner entry")
        key_owner[key_id] = source_id
    if key_owner != expected_owner:
        raise ValueError("key owner index is inconsistent")

    pins_raw = data.get("pins")
    if not isinstance(pins_raw, dict):
        raise ValueError("invalid pins")
    pins = {}
    for package_name, rules_raw in pins_raw.items():
        if not isinstance(package_name, str) or not isinstance(rules_raw, dict):
            raise ValueError("invalid pin group")
        rules = {}
        for source_id, pin_raw in rules_raw.items():
            if source_id not in sources:
                raise ValueError("pin references unknown source")
            if not isinstance(pin_raw, dict):
                raise ValueError("invalid pin")
            priority = _priority(pin_raw.get("priority"))
            reason = pin_raw.get("reason", "")
            if not isinstance(reason, str):
                raise ValueError("invalid pin reason")
            rules[source_id] = {"priority": priority, "reason": reason}
        pins[package_name] = rules

    stats_raw = data.get("stats")
    if not isinstance(stats_raw, dict):
        raise ValueError("invalid stats")
    stats = {}
    for key in _STATS_KEYS:
        value = stats_raw.get(key)
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError("invalid statistic")
        stats[key] = value

    return {
        "arch": arch,
        "installed_versions": installed_versions,
        "keys": keys,
        "key_owner": key_owner,
        "sources": sources,
        "pins": pins,
        "stats": stats,
    }
