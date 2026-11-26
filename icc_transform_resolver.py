"""ICC profile registry and colour transform cache."""

from __future__ import annotations

import ast
import copy
import math
import threading
from collections import OrderedDict
from collections.abc import Mapping
from dataclasses import dataclass, fields, replace
from typing import Any

__all__ = [
    "IccError",
    "ProfileView",
    "TransformHandle",
    "CacheStats",
    "IccTransformResolver",
]

INTENTS = ("perceptual", "relative", "saturation", "absolute")
DEVICE_CLASSES = ("input", "display", "output", "colorspace")
SUPPORTED_GAMUTS = ("srgb", "display-p3", "rec2020", "adobe-rgb", "prophoto")

ICC_PROFILE_EXISTS = "ICC_PROFILE_EXISTS"
ICC_INVALID_REQUEST = "ICC_INVALID_REQUEST"
ICC_UNKNOWN_PROFILE = "ICC_UNKNOWN_PROFILE"
ICC_INTENT_UNSUPPORTED = "ICC_INTENT_UNSUPPORTED"
ICC_HANDLE_STALE = "ICC_HANDLE_STALE"
ICC_SNAPSHOT_INVALID = "ICC_SNAPSHOT_INVALID"
ICC_GAMUT_UNSUPPORTED = "ICC_GAMUT_UNSUPPORTED"
ICC_ABSOLUTE_MEDIA_WHITE_MISSING = "ICC_ABSOLUTE_MEDIA_WHITE_MISSING"

FALLBACK_PROFILE_ID = "srgb"
_KEY_PREFIX = "icc-transform-v1:"


class IccError(ValueError):
    """Raised when a profile or transform operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ProfileView:
    """Immutable snapshot of one registered profile."""

    profile_id: str
    device_class: str
    version: int
    white_point: tuple[float, ...]
    gamut: str
    media_white: tuple[float, ...] | None
    valid: bool
    diagnostics: tuple[str, ...]


@dataclass(frozen=True)
class TransformHandle:
    """One compiled colour transform handed to a caller."""

    cache_key: str
    source_id: str
    source_version: int
    target_id: str
    target_version: int
    intent: str
    bpc: bool
    fallback: bool
    diagnostic: str | None
    refs: int


@dataclass(frozen=True)
class CacheStats:
    """Counters for the transform cache."""

    entries: int
    limit: int
    hits: int
    misses: int
    compiles: int
    evictions: int
    invalidations: int
    refusals: int


@dataclass
class _HandleLease:
    key: str
    refs: int = 0


class IccTransformResolver:
    """Register device profiles and resolve cached colour transforms."""

    def __init__(self, *, max_cache_entries: int = 64,
                 black_point_compensation: bool = True,
                 fallback_profile: str = "srgb") -> None:
        if (not isinstance(max_cache_entries, int)
                or isinstance(max_cache_entries, bool)
                or max_cache_entries <= 0):
            raise IccError(
                ICC_INVALID_REQUEST,
                "max_cache_entries must be a positive integer",
            )

        self.max_cache_entries = max_cache_entries
        self._limit = max_cache_entries
        self.black_point_compensation = black_point_compensation
        self.fallback_profile = fallback_profile
        self._lock = threading.RLock()
        self._profiles: dict[str, ProfileView] = {}
        self._profile_versions: dict[str, dict[int, ProfileView]] = {}
        self._cache: OrderedDict[str, TransformHandle] = OrderedDict()
        self._leases: dict[str, _HandleLease] = {}
        self._stats = self._initial_stats()
        self._install_builtin_profiles()

    @staticmethod
    def _initial_stats() -> dict[str, int]:
        return {
            "registrations": 0,
            "resolves": 0,
            "fallbacks": 0,
            "hits": 0,
            "misses": 0,
            "compiles": 0,
            "evictions": 0,
            "invalidations": 0,
            "refusals": 0,
        }

    def _install_builtin_profiles(self) -> None:
        srgb = ProfileView(
            profile_id=FALLBACK_PROFILE_ID,
            device_class="colorspace",
            version=1,
            white_point=(0.3127, 0.3290),
            gamut="srgb",
            media_white=(0.9642, 1.0, 0.8249),
            valid=True,
            diagnostics=(),
        )
        self._profiles[FALLBACK_PROFILE_ID] = srgb
        self._profile_versions[FALLBACK_PROFILE_ID] = {1: srgb}

    def _refuse_locked(self, code: str, detail: object = None) -> None:
        self._stats["refusals"] += 1
        raise IccError(code, detail)

    @staticmethod
    def _valid_white_point(
        white_point: tuple[float, ...] | list[float],
    ) -> tuple[float, ...] | None:
        if not isinstance(white_point, (tuple, list)):
            return None
        if len(white_point) not in (2, 3):
            return None

        values: list[float] = []
        inclusive_upper = len(white_point) == 3
        for component in white_point:
            if isinstance(component, bool) or not isinstance(
                component, (int, float)
            ):
                return None
            value = float(component)
            upper_ok = value <= 1.0 if inclusive_upper else value < 1.0
            if not math.isfinite(value) or not 0.0 < value or not upper_ok:
                return None
            values.append(value)
        return tuple(values)

    @staticmethod
    def _freeze_sequence(value: object) -> object:
        if isinstance(value, list):
            return tuple(
                IccTransformResolver._freeze_sequence(item)
                for item in value
            )
        if isinstance(value, dict):
            return {
                key: IccTransformResolver._freeze_sequence(item)
                for key, item in value.items()
            }
        return value

    def _profile_locked(self, profile_id: str) -> ProfileView:
        if not isinstance(profile_id, str):
            self._refuse_locked(
                ICC_UNKNOWN_PROFILE, {"profile_id": profile_id}
            )
        normalized_id = profile_id.strip()
        profile = self._profiles.get(normalized_id)
        if profile is None:
            self._refuse_locked(
                ICC_UNKNOWN_PROFILE, {"profile_id": profile_id}
            )
        return profile

    def _fallback_profile_locked(self) -> ProfileView:
        candidate_id = self.fallback_profile
        if isinstance(candidate_id, str):
            candidate = self._profiles.get(candidate_id.strip())
            if candidate is not None and candidate.valid:
                return candidate
        return self._profiles[FALLBACK_PROFILE_ID]

    def _normalize_intent_locked(self, intent: str) -> str:
        if not isinstance(intent, str):
            self._refuse_locked(
                ICC_INTENT_UNSUPPORTED, {"intent": intent}
            )
        normalized = intent.strip().lower()
        if normalized not in INTENTS:
            self._refuse_locked(
                ICC_INTENT_UNSUPPORTED, {"intent": intent}
            )
        return normalized

    def _normalize_bpc(self, bpc: bool | None) -> bool:
        value = self.black_point_compensation if bpc is None else bpc
        return bool(value)

    @staticmethod
    def _cache_key(
        source: ProfileView,
        target: ProfileView,
        intent: str,
        bpc: bool,
    ) -> str:
        payload = (
            source.profile_id,
            source.version,
            target.profile_id,
            target.version,
            intent,
            bpc,
        )
        return _KEY_PREFIX + repr(payload)

    @staticmethod
    def _involved_devices(
        key: str, handle: TransformHandle
    ) -> tuple[str, str]:
        if key.startswith(_KEY_PREFIX):
            try:
                payload = ast.literal_eval(key[len(_KEY_PREFIX):])
                if len(payload) >= 4:
                    return str(payload[0]), str(payload[2])
            except (SyntaxError, ValueError):
                pass
        return handle.source_id, handle.target_id

    @staticmethod
    def _media_white_missing(profile: ProfileView) -> bool:
        media_white = profile.media_white
        if media_white is None:
            return True
        if isinstance(media_white, (str, bytes)):
            return False
        try:
            return len(media_white) == 0
        except TypeError:
            return False

    def _lease_for_handle(
        self, handle: TransformHandle
    ) -> _HandleLease | None:
        return self._leases.get(handle.cache_key)

    def register_profile(self, profile_id: str, *, device_class: str,
                         white_point: tuple[float, ...], gamut: str,
                         version: int = 1,
                         media_white: tuple[float, ...] | None = None) -> ProfileView:
        """Register or replace a profile under its device identity."""
        with self._lock:
            if not isinstance(profile_id, str):
                self._refuse_locked(
                    ICC_INVALID_REQUEST, {"field": "profile_id"}
                )
            device_id = profile_id.strip()
            if not device_id:
                self._refuse_locked(
                    ICC_INVALID_REQUEST, {"field": "profile_id"}
                )

            if (not isinstance(device_class, str)
                    or device_class not in DEVICE_CLASSES):
                self._refuse_locked(
                    ICC_INVALID_REQUEST, {"field": "device_class"}
                )

            valid_white_point = self._valid_white_point(white_point)
            if valid_white_point is None:
                self._refuse_locked(
                    ICC_INVALID_REQUEST, {"field": "white_point"}
                )

            if not isinstance(gamut, str) or not gamut.strip():
                self._refuse_locked(ICC_INVALID_REQUEST, {"field": "gamut"})
            gamut_label = gamut.strip()

            if (isinstance(version, bool)
                    or not isinstance(version, int)
                    or version < 1):
                self._refuse_locked(
                    ICC_INVALID_REQUEST, {"field": "version"}
                )

            versions = self._profile_versions.setdefault(device_id, {})
            if version in versions:
                self._refuse_locked(
                    ICC_PROFILE_EXISTS,
                    {"profile_id": device_id, "version": version},
                )

            diagnostics: tuple[str, ...] = ()
            if gamut_label not in SUPPORTED_GAMUTS:
                diagnostics = (ICC_GAMUT_UNSUPPORTED,)

            profile = ProfileView(
                profile_id=device_id,
                device_class=device_class,
                version=version,
                white_point=valid_white_point,
                gamut=gamut_label,
                media_white=self._freeze_sequence(media_white),
                valid=not diagnostics,
                diagnostics=diagnostics,
            )
            versions[version] = profile
            self._profiles[device_id] = profile
            self._stats["registrations"] += 1
            return profile

    def profile_view(self, profile_id: str) -> ProfileView:
        """Return the current registration of a profile."""
        with self._lock:
            return self._profile_locked(profile_id)

    def validate_profile(self, profile_id: str) -> dict:
        """Check a profile and report diagnostics plus the fallback target."""
        with self._lock:
            profile = self._profile_locked(profile_id)
            fallback = None
            if profile.diagnostics:
                fallback = self._fallback_profile_locked().profile_id
            return {
                "profile_id": profile.profile_id,
                "valid": profile.valid,
                "diagnostics": tuple(profile.diagnostics),
                "fallback": fallback,
            }

    def link_cache_key(self, source_id: str, target_id: str, *,
                       intent: str = "perceptual", bpc: bool | None = None) -> str:
        """Return the stable cache key for a transform request."""
        with self._lock:
            normalized_intent = self._normalize_intent_locked(intent)
            bpc_value = self._normalize_bpc(bpc)
            source = self._profile_locked(source_id)
            target = self._profile_locked(target_id)
            return self._cache_key(
                source, target, normalized_intent, bpc_value
            )

    def resolve_transform(self, source_id: str, target_id: str, *,
                          intent: str = "perceptual",
                          bpc: bool | None = None) -> TransformHandle:
        """Compile or reuse the transform for a profile pair and intent."""
        with self._lock:
            normalized_intent = self._normalize_intent_locked(intent)
            bpc_value = self._normalize_bpc(bpc)
            requested_source = self._profile_locked(source_id)
            requested_target = self._profile_locked(target_id)
            key = self._cache_key(
                requested_source,
                requested_target,
                normalized_intent,
                bpc_value,
            )

            self._stats["resolves"] += 1
            existing = self._cache.get(key)
            if existing is not None:
                self._cache.move_to_end(key)
                self._stats["hits"] += 1
                return existing

            self._stats["misses"] += 1
            self._stats["compiles"] += 1

            compiled_source = requested_source
            compiled_target = requested_target
            fallback = False
            diagnostic: str | None = None

            profile_diagnostics = (
                requested_target.diagnostics
                or requested_source.diagnostics
            )
            if profile_diagnostics:
                fallback = True
                diagnostic = profile_diagnostics[0]
                fallback_profile = self._fallback_profile_locked()
                compiled_source = fallback_profile
                compiled_target = fallback_profile
                self._stats["fallbacks"] += 1
            elif (normalized_intent == "absolute"
                  and self._media_white_missing(requested_target)):
                diagnostic = ICC_ABSOLUTE_MEDIA_WHITE_MISSING

            handle = TransformHandle(
                cache_key=key,
                source_id=compiled_source.profile_id,
                source_version=compiled_source.version,
                target_id=compiled_target.profile_id,
                target_version=compiled_target.version,
                intent=normalized_intent,
                bpc=bpc_value,
                fallback=fallback,
                diagnostic=diagnostic,
                refs=0,
            )

            lease = self._leases.get(key)
            if lease is None:
                lease = _HandleLease(key=key)
                self._leases[key] = lease
            self._cache[key] = handle
            self._evict_lru_locked()
            return handle

    def retain_handle(self, handle: TransformHandle) -> TransformHandle:
        """Mark a transform as referenced by an in-flight render frame."""
        with self._lock:
            if not isinstance(handle, TransformHandle):
                self._refuse_locked(ICC_HANDLE_STALE, {"handle": handle})
            lease = self._lease_for_handle(handle)
            if lease is None:
                self._refuse_locked(
                    ICC_HANDLE_STALE,
                    {"cache_key": getattr(handle, "cache_key", None)},
                )

            lease.refs += 1
            return replace(handle, refs=lease.refs)

    def release_handle(self, handle: TransformHandle) -> TransformHandle:
        """Drop one in-flight reference from a transform handle."""
        with self._lock:
            if not isinstance(handle, TransformHandle):
                self._refuse_locked(ICC_HANDLE_STALE, {"handle": handle})
            lease = self._lease_for_handle(handle)
            if lease is None or lease.refs <= 0:
                self._refuse_locked(
                    ICC_HANDLE_STALE,
                    {"cache_key": getattr(handle, "cache_key", None)},
                )

            lease.refs -= 1
            released = replace(handle, refs=lease.refs)
            return released

    def invalidate_device(self, device_id: str) -> tuple[str, ...]:
        """Drop every cached transform that involves one device."""
        with self._lock:
            profile = self._profile_locked(device_id)
            resolved_id = profile.profile_id
            dropped: list[str] = []

            for key in list(self._cache):
                handle = self._cache[key]
                source_id, target_id = self._involved_devices(key, handle)
                if source_id == resolved_id or target_id == resolved_id:
                    dropped.append(key)
                    del self._cache[key]

            self._stats["invalidations"] += 1
            return tuple(sorted(dropped))

    def cache_stats(self) -> CacheStats:
        """Return cache entry counts and hit/miss/eviction counters."""
        with self._lock:
            return CacheStats(
                entries=len(self._cache),
                limit=self._limit,
                hits=self._stats["hits"],
                misses=self._stats["misses"],
                compiles=self._stats["compiles"],
                evictions=self._stats["evictions"],
                invalidations=self._stats["invalidations"],
                refusals=self._stats["refusals"],
            )

    def snapshot(self) -> dict:
        """Return a deep copy of profiles, cache and counters."""
        with self._lock:
            return {
                "profiles": copy.deepcopy(self._profiles),
                "profile_versions": copy.deepcopy(self._profile_versions),
                "cache": copy.deepcopy(self._cache),
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        """Replace resolver state with a snapshot, validating its structure."""
        try:
            new_profiles, new_versions = self._decode_profiles_state(state)
            new_cache = self._decode_cache_state(state)
            new_stats = self._decode_stats_state(state)
        except IccError:
            raise
        except Exception as exc:
            raise IccError(
                ICC_SNAPSHOT_INVALID,
                str(exc) or exc.__class__.__name__,
            ) from exc

        with self._lock:
            self._profiles = new_profiles
            self._profile_versions = new_versions
            self._cache = new_cache
            self._stats = new_stats
            self._leases = {}
            for key, handle in self._cache.items():
                lease = _HandleLease(key=key, refs=max(0, handle.refs))
                self._leases[key] = lease

    def stats(self) -> dict:
        """Return cumulative counters for registrations, resolves and fallbacks."""
        with self._lock:
            return copy.deepcopy(self._stats)

    def _evict_lru_locked(self) -> None:
        while len(self._cache) > self._limit:
            for key in list(self._cache):
                lease = self._leases.get(key)
                if lease is None or lease.refs == 0:
                    del self._cache[key]
                    self._stats["evictions"] += 1
                    break
            else:
                break

    @staticmethod
    def _mapping(value: object, name: str) -> Mapping:
        if not isinstance(value, Mapping):
            raise ValueError(f"{name} must be a mapping")
        return value

    @classmethod
    def _coerce_profile(cls, value: object) -> ProfileView:
        if isinstance(value, ProfileView):
            return copy.deepcopy(value)
        data = cls._mapping(value, "profile")
        allowed = {item.name for item in fields(ProfileView)}
        kwargs: dict[str, Any] = {
            key: copy.deepcopy(item)
            for key, item in data.items()
            if key in allowed
        }
        for field_name in ("white_point", "media_white", "diagnostics"):
            if field_name in kwargs and isinstance(
                kwargs[field_name], list
            ):
                kwargs[field_name] = tuple(kwargs[field_name])
        return ProfileView(**kwargs)

    @classmethod
    def _coerce_handle(cls, value: object) -> TransformHandle:
        if isinstance(value, TransformHandle):
            return copy.deepcopy(value)
        data = cls._mapping(value, "handle")
        allowed = {item.name for item in fields(TransformHandle)}
        kwargs: dict[str, Any] = {
            key: copy.deepcopy(item)
            for key, item in data.items()
            if key in allowed
        }
        return TransformHandle(**kwargs)

    def _decode_profiles_state(
        self, state: object
    ) -> tuple[dict[str, ProfileView], dict[str, dict[int, ProfileView]]]:
        root = self._mapping(state, "state")
        profiles_data = self._mapping(root["profiles"], "profiles")

        profiles: dict[str, ProfileView] = {}
        for profile_id, value in profiles_data.items():
            profile = self._coerce_profile(value)
            key = (
                profile_id
                if isinstance(profile_id, str)
                else profile.profile_id
            )
            profiles[key] = profile

        if FALLBACK_PROFILE_ID not in profiles:
            profiles[FALLBACK_PROFILE_ID] = copy.deepcopy(
                self._profiles[FALLBACK_PROFILE_ID]
            )

        versions: dict[str, dict[int, ProfileView]] = {}
        raw_versions = root.get("profile_versions")
        if raw_versions is not None:
            versions_data = self._mapping(
                raw_versions, "profile_versions"
            )
            for profile_id, by_version in versions_data.items():
                if not isinstance(profile_id, str):
                    raise ValueError("profile version key must be a string")
                version_map_data = self._mapping(
                    by_version, f"profile_versions.{profile_id}"
                )
                version_map: dict[int, ProfileView] = {}
                for version, profile_data in version_map_data.items():
                    version_map[int(version)] = self._coerce_profile(
                        profile_data
                    )
                versions[profile_id] = version_map

        for profile_id, profile in profiles.items():
            versions.setdefault(profile_id, {})
            versions[profile_id].setdefault(profile.version, profile)

        return profiles, versions

    def _decode_cache_state(
        self, state: object
    ) -> OrderedDict[str, TransformHandle]:
        root = self._mapping(state, "state")
        cache_data = self._mapping(root["cache"], "cache")
        cache: OrderedDict[str, TransformHandle] = OrderedDict()

        for key, value in cache_data.items():
            if not isinstance(key, str):
                raise ValueError("cache keys must be strings")
            cache[key] = self._coerce_handle(value)

        return cache

    def _decode_stats_state(self, state: object) -> dict[str, Any]:
        root = self._mapping(state, "state")
        stats_data = self._mapping(root["stats"], "stats")
        stats = self._initial_stats()

        for key in stats:
            if key not in stats_data:
                continue
            value = stats_data[key]
            if (isinstance(value, bool)
                    or not isinstance(value, int)
                    or value < 0):
                raise ValueError(
                    f"stats.{key} must be a non-negative integer"
                )
            stats[key] = value

        for key, value in stats_data.items():
            if key not in stats:
                stats[key] = copy.deepcopy(value)

        return stats
