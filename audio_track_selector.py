"""Player audio track selection with preload window and language fallback.

Tracks are registered per language; the selector preloads a target track and
only swaps the audible track once the switch lands on a keyframe of the target
track.  Missing languages degrade along the preference, system and default
language chain.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "TrackError",
    "TrackInfo",
    "PreloadResult",
    "SwitchResult",
    "AudioTrackSelector",
]


class TrackError(ValueError):
    """Raised when a track selection operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TrackInfo:
    """One registered audio track."""

    track_id: str
    language: str
    codec: str
    channels: int
    bitrate: int
    keyframes: tuple[int, ...]


@dataclass(frozen=True)
class PreloadResult:
    """Outcome of one preload attempt."""

    status: str
    track_id: str | None
    language: str
    reason: str | None


@dataclass(frozen=True)
class SwitchResult:
    """Outcome of one switch request."""

    status: str
    track_id: str | None
    language: str | None
    position: int
    scheduled_at: int | None
    reason: str | None


@dataclass(frozen=True)
class _QueuedSwitch:
    track_id: str
    language: str
    position: int
    scheduled_at: int | None


_SNAPSHOT_VERSION = 1
_STAT_KEYS = (
    "switches",
    "queued",
    "preloads",
    "preload_failures",
    "preload_evictions",
    "aborts",
    "fallbacks",
)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _text(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    value = value.strip()
    return value or None


def _language(value: object) -> str:
    text = _text(value)
    return text.lower() if text is not None else ""


def _validate_keyframes(value: object) -> tuple[int, ...]:
    if isinstance(value, (str, bytes)):
        raise TrackError("AUDIO_TRACK_INVALID", "keyframes must be a sequence")
    try:
        raw = tuple(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise TrackError("AUDIO_TRACK_INVALID", "keyframes must be a sequence") from exc

    previous: int | None = None
    for item in raw:
        if not _is_int(item) or item < 0:
            raise TrackError(
                "AUDIO_TRACK_INVALID", "keyframes must be non-negative integers"
            )
        if previous is not None and item <= previous:
            raise TrackError(
                "AUDIO_TRACK_INVALID", "keyframes must be strictly increasing"
            )
        previous = item
    return raw


def _validate_codecs(value: object) -> tuple[str, ...]:
    if value is None or isinstance(value, (str, bytes)):
        raise TrackError("AUDIO_DEVICE_INVALID", "codecs must be a non-empty sequence")
    try:
        raw = list(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise TrackError(
            "AUDIO_DEVICE_INVALID", "codecs must be a non-empty sequence"
        ) from exc
    if not raw:
        raise TrackError("AUDIO_DEVICE_INVALID", "codecs must not be empty")

    result: list[str] = []
    for item in raw:
        text = _text(item)
        if text is None:
            raise TrackError(
                "AUDIO_DEVICE_INVALID", "codecs must contain non-empty strings"
            )
        codec = text.lower()
        if codec not in result:
            result.append(codec)
    return tuple(result)


class AudioTrackSelector:
    """Resolve languages to tracks, preload them and switch at keyframes."""

    def __init__(self, *, system_language: str = "zh",
                 default_language: str = "und", max_preloaded: int = 2,
                 device_codecs: tuple[str, ...] = ("aac", "opus"),
                 max_channels: int = 8) -> None:
        if not _is_int(max_preloaded) or max_preloaded <= 0:
            raise TrackError(
                "AUDIO_TRACK_INVALID", "max_preloaded must be a positive integer"
            )
        if not _is_int(max_channels) or max_channels <= 0:
            raise TrackError(
                "AUDIO_DEVICE_INVALID", "max_channels must be a positive integer"
            )

        self.system_language = _language(system_language)
        self.default_language = _language(default_language)
        self.max_preloaded = max_preloaded
        self.device_codecs = _validate_codecs(device_codecs)
        self.max_channels = max_channels

        self._lock = threading.RLock()
        self._tracks: dict[str, TrackInfo] = {}
        self._preferences: tuple[str, ...] = ()
        self._device_codecs: tuple[str, ...] = self.device_codecs
        self._max_channels: int = self.max_channels
        self._current_id: str | None = None
        self._preloaded: dict[str, TrackInfo] = {}
        self._queued: list[_QueuedSwitch] = []
        self._position = 0
        self._stats: dict[str, int] = {key: 0 for key in _STAT_KEYS}

    # ------------------------------------------------------------------
    # Registration and device capabilities
    # ------------------------------------------------------------------
    def add_track(self, track_id: str, *, language: str,
                  keyframes: tuple[int, ...] = (0,), codec: str = "aac",
                  channels: int = 2, bitrate: int = 128000) -> TrackInfo:
        """Register one track of *language* with its keyframe positions."""
        with self._lock:
            tid = _text(track_id)
            if tid is None:
                raise TrackError("AUDIO_TRACK_INVALID", "track_id must not be empty")
            lang = _language(language)
            if not lang:
                raise TrackError("AUDIO_TRACK_INVALID", "language must not be empty")
            codec_name = _text(codec)
            if codec_name is None:
                raise TrackError("AUDIO_TRACK_INVALID", "codec must not be empty")
            if not _is_int(channels) or channels <= 0:
                raise TrackError(
                    "AUDIO_TRACK_INVALID", "channels must be a positive integer"
                )
            if not _is_int(bitrate) or bitrate <= 0:
                raise TrackError(
                    "AUDIO_TRACK_INVALID", "bitrate must be a positive integer"
                )
            points = _validate_keyframes(keyframes)

            if tid in self._tracks:
                raise TrackError("AUDIO_TRACK_EXISTS", tid)

            track = TrackInfo(
                track_id=tid,
                language=lang,
                codec=codec_name.lower(),
                channels=channels,
                bitrate=bitrate,
                keyframes=points,
            )
            self._tracks[tid] = track
            return track

    def set_device(self, *, codecs: tuple[str, ...] | None = None,
                   max_channels: int | None = None) -> dict:
        """Declare the decoder capabilities of the current device."""
        with self._lock:
            new_codecs = self._device_codecs
            new_channels = self._max_channels
            if codecs is not None:
                new_codecs = _validate_codecs(codecs)
            if max_channels is not None:
                if not _is_int(max_channels) or max_channels <= 0:
                    raise TrackError(
                        "AUDIO_DEVICE_INVALID",
                        "max_channels must be a positive integer",
                    )
                new_channels = max_channels

            self._device_codecs = new_codecs
            self._max_channels = new_channels
            return {
                "codecs": list(self._device_codecs),
                "max_channels": self._max_channels,
            }

    def set_preference(self, languages) -> tuple[str, ...]:
        """Store the ordered language preference list."""
        with self._lock:
            if languages is None or isinstance(languages, (str, bytes)):
                raise TrackError(
                    "AUDIO_PREFERENCE_INVALID", "languages must be a sequence"
                )
            try:
                raw = list(languages)
            except TypeError as exc:
                raise TrackError(
                    "AUDIO_PREFERENCE_INVALID", "languages must be a sequence"
                ) from exc
            if not raw:
                raise TrackError(
                    "AUDIO_PREFERENCE_INVALID", "preference list must not be empty"
                )

            result: list[str] = []
            for item in raw:
                lang = _language(item)
                if not lang:
                    raise TrackError(
                        "AUDIO_PREFERENCE_INVALID",
                        "preferences must be non-empty strings",
                    )
                if lang not in result:
                    result.append(lang)
            self._preferences = tuple(result)
            return self._preferences

    def _is_playable(self, track: TrackInfo) -> bool:
        return (
            track.codec in self._device_codecs
            and track.channels <= self._max_channels
        )

    def _playable_tracks(self, language: str | None = None) -> list[TrackInfo]:
        result = [
            track
            for track in self._tracks.values()
            if self._is_playable(track)
            and (language is None or track.language == language)
        ]
        result.sort(key=lambda track: (track.language, track.track_id))
        return result

    def available(self, *, language: str | None = None) -> tuple[TrackInfo, ...]:
        """Return the tracks the current device can decode."""
        with self._lock:
            lang = None if language is None else _language(language)
            return tuple(self._playable_tracks(lang))

    # ------------------------------------------------------------------
    # Preloading
    # ------------------------------------------------------------------
    def _first_preloaded(self, language: str) -> TrackInfo | None:
        for track in self._preloaded.values():
            if track.language == language and self._is_playable(track):
                return track
        return None

    def preload(self, language: str) -> PreloadResult:
        """Load the best track of *language* into the preload window."""
        with self._lock:
            lang = _language(language)
            all_tracks = [
                track for track in self._tracks.values()
                if track.language == lang
            ]
            if not all_tracks:
                self._stats["preload_failures"] += 1
                return PreloadResult("missing", None, lang, "no_track")

            playable = self._playable_tracks(lang)
            if not playable:
                self._stats["preload_failures"] += 1
                return PreloadResult("unsupported", None, lang, "device")

            target = self._first_preloaded(lang)
            if target is None or target not in playable:
                target = playable[0]

            if target.track_id not in self._preloaded:
                while len(self._preloaded) >= self.max_preloaded:
                    _, evicted = next(iter(self._preloaded.items()))
                    del self._preloaded[evicted.track_id]
                    self._stats["preload_evictions"] += 1
                self._preloaded[target.track_id] = target

            self._stats["preloads"] += 1
            return PreloadResult("ready", target.track_id, target.language, None)

    def abort_preload(self, language: str | None = None) -> int:
        """Drop preloaded tracks; return how many were dropped."""
        with self._lock:
            if language is None:
                removed = len(self._preloaded)
                self._preloaded.clear()
            else:
                lang = _language(language)
                removed_ids = [
                    track_id
                    for track_id, track in self._preloaded.items()
                    if track.language == lang
                ]
                for track_id in removed_ids:
                    del self._preloaded[track_id]
                removed = len(removed_ids)

            if removed:
                self._stats["aborts"] += 1
            return removed

    # ------------------------------------------------------------------
    # Switching
    # ------------------------------------------------------------------
    def _unchanged(self, track: TrackInfo, position: int) -> SwitchResult:
        return SwitchResult(
            "unchanged", track.track_id, track.language, position, None, None
        )

    def _apply(self, track: TrackInfo, position: int) -> SwitchResult:
        self._current_id = track.track_id
        self._preloaded.pop(track.track_id, None)
        self._stats["switches"] += 1
        self._position = position
        return SwitchResult(
            "applied", track.track_id, track.language, position, None, None
        )

    def _schedule_or_apply(self, track: TrackInfo, position: int) -> SwitchResult:
        current = (
            self._tracks.get(self._current_id)
            if self._current_id is not None
            else None
        )
        if current is not None and current.track_id == track.track_id:
            return self._unchanged(current, position)

        if position in track.keyframes:
            self._queued = [
                entry
                for entry in self._queued
                if entry.track_id != track.track_id
            ]
            return self._apply(track, position)

        next_keyframe = next(
            (point for point in track.keyframes if point > position), None
        )
        for index, entry in enumerate(self._queued):
            if entry.track_id == track.track_id:
                self._queued[index] = _QueuedSwitch(
                    track.track_id, track.language, position, next_keyframe
                )
                break
        else:
            self._queued.append(
                _QueuedSwitch(
                    track.track_id, track.language, position, next_keyframe
                )
            )
        return SwitchResult(
            "queued",
            track.track_id,
            track.language,
            position,
            next_keyframe,
            None,
        )

    def switch_to(self, language: str, *, position: int = 0) -> SwitchResult:
        """Switch to *language* at *position*, queueing until a keyframe."""
        if not _is_int(position) or position < 0:
            raise TrackError(
                "AUDIO_TRACK_INVALID", "position must be a non-negative integer"
            )

        with self._lock:
            requested = _language(language)
            self._position = position
            current = (
                self._tracks.get(self._current_id)
                if self._current_id is not None
                else None
            )

            target = self._first_preloaded(requested)
            if target is not None:
                if current is not None and current.track_id == target.track_id:
                    return self._unchanged(current, position)
                return self._schedule_or_apply(target, position)

            if current is not None and current.language == requested:
                return self._unchanged(current, position)

            if self._playable_tracks(requested):
                raise TrackError(
                    "AUDIO_PRELOAD_REQUIRED",
                    {"language": requested, "position": position},
                )

            fallback_target: TrackInfo | None = None
            fallback_current: TrackInfo | None = None
            fallback_has_playable = False

            for lang in self.fallback_chain():
                if lang == requested:
                    continue
                target = self._first_preloaded(lang)
                if target is not None:
                    fallback_target = target
                    break
                if current is not None and current.language == lang:
                    fallback_current = current
                    break
                if self._playable_tracks(lang):
                    fallback_has_playable = True

            if fallback_target is not None:
                self._stats["fallbacks"] += 1
                if (
                    current is not None
                    and current.track_id == fallback_target.track_id
                ):
                    return self._unchanged(current, position)
                return self._schedule_or_apply(fallback_target, position)

            if fallback_current is not None:
                self._stats["fallbacks"] += 1
                return self._unchanged(fallback_current, position)

            if fallback_has_playable:
                raise TrackError(
                    "AUDIO_PRELOAD_REQUIRED",
                    {"language": requested, "position": position},
                )

            # No requested or fallback language can be decoded.  Stay silent;
            # subtitle handling lives outside this audio-only selector.
            self._current_id = None
            return SwitchResult(
                "missing", None, requested or None, position, None, "no_track"
            )

    def advance_to(self, position: int) -> tuple[SwitchResult, ...]:
        """Advance the playback clock and apply due queued switches."""
        if not _is_int(position) or position < 0:
            raise TrackError(
                "AUDIO_TRACK_INVALID", "position must be a non-negative integer"
            )

        with self._lock:
            self._position = position
            due: list[tuple[int, int, _QueuedSwitch]] = []
            remaining: list[_QueuedSwitch] = []
            for index, entry in enumerate(self._queued):
                if entry.scheduled_at is not None and entry.scheduled_at <= position:
                    due.append((entry.scheduled_at, index, entry))
                else:
                    remaining.append(entry)
            self._queued = remaining
            due.sort(key=lambda item: (item[0], item[1]))

            results: list[SwitchResult] = []
            for scheduled_at, _, entry in due:
                track = self._tracks.get(entry.track_id)
                if track is None:
                    continue
                if self._current_id == track.track_id:
                    results.append(self._unchanged(track, scheduled_at))
                    continue

                self._preloaded.pop(track.track_id, None)
                self._current_id = track.track_id
                self._stats["switches"] += 1
                results.append(
                    SwitchResult(
                        "applied",
                        track.track_id,
                        track.language,
                        scheduled_at,
                        None,
                        None,
                    )
                )

            self._position = position
            return tuple(results)

    def abort_switch(self) -> bool:
        """Cancel a queued switch; return whether one was cancelled."""
        with self._lock:
            if not self._queued:
                return False
            self._queued.pop(0)
            self._stats["aborts"] += 1
            return True

    # ------------------------------------------------------------------
    # Inspection
    # ------------------------------------------------------------------
    def current(self) -> TrackInfo | None:
        """Return the audible track, if any."""
        with self._lock:
            if self._current_id is None:
                return None
            return self._tracks.get(self._current_id)

    def active_tracks(self) -> tuple[TrackInfo, ...]:
        """Return the tracks currently producing sound."""
        with self._lock:
            track = self.current()
            return () if track is None else (track,)

    def fallback_chain(self) -> tuple[str, ...]:
        """Return the language try order used when a track is missing."""
        with self._lock:
            result: list[str] = []
            for value in (
                *self._preferences,
                self.system_language,
                self.default_language,
            ):
                lang = _language(value)
                if lang and lang not in result:
                    result.append(lang)
            return tuple(result)

    # ------------------------------------------------------------------
    # Snapshot / restore
    # ------------------------------------------------------------------
    def _stats_view(self) -> dict[str, int]:
        result = dict(self._stats)
        for key in _STAT_KEYS:
            result.setdefault(key, 0)
        result["queued"] = len(self._queued)
        return result

    def stats(self) -> dict:
        """Return the preload, switch and abort counters."""
        with self._lock:
            return self._stats_view()

    def snapshot(self) -> dict:
        """Return a detached snapshot of the selector state."""
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "tracks": [
                    {
                        "track_id": track.track_id,
                        "language": track.language,
                        "codec": track.codec,
                        "channels": track.channels,
                        "bitrate": track.bitrate,
                        "keyframes": list(track.keyframes),
                    }
                    for track in self._tracks.values()
                ],
                "preferences": list(self._preferences),
                "device": {
                    "codecs": list(self._device_codecs),
                    "max_channels": self._max_channels,
                },
                "current": self._current_id,
                "preloaded": list(self._preloaded),
                "queued": [
                    {
                        "track_id": entry.track_id,
                        "language": entry.language,
                        "position": entry.position,
                        "scheduled_at": entry.scheduled_at,
                    }
                    for entry in self._queued
                ],
                "position": self._position,
                "stats": self._stats_view(),
            }

    @staticmethod
    def _snapshot_error(detail: object = None) -> TrackError:
        return TrackError("AUDIO_SNAPSHOT_INVALID", detail)

    def _parse_snapshot(self, state: object):
        if not isinstance(state, dict):
            raise self._snapshot_error("snapshot must be a mapping")
        required = {
            "version",
            "tracks",
            "preferences",
            "device",
            "current",
            "preloaded",
            "queued",
            "position",
            "stats",
        }
        if not required.issubset(state):
            raise self._snapshot_error("snapshot is missing required fields")

        version = state["version"]
        if not _is_int(version) or version != _SNAPSHOT_VERSION:
            raise self._snapshot_error("unsupported snapshot version")

        tracks_raw = state["tracks"]
        if not isinstance(tracks_raw, (list, tuple)):
            raise self._snapshot_error("tracks must be a sequence")
        tracks: dict[str, TrackInfo] = {}
        for raw in tracks_raw:
            if not isinstance(raw, dict):
                raise self._snapshot_error("track entries must be mappings")
            try:
                track_id = raw["track_id"]
                language = raw["language"]
                codec = raw["codec"]
                channels = raw["channels"]
                bitrate = raw["bitrate"]
                keyframes = raw["keyframes"]
            except (KeyError, TypeError) as exc:
                raise self._snapshot_error("track entry is incomplete") from exc

            tid = _text(track_id)
            lang = _language(language)
            codec_name = _text(codec)
            if (
                tid is None
                or not lang
                or codec_name is None
                or not _is_int(channels)
                or channels <= 0
                or not _is_int(bitrate)
                or bitrate <= 0
            ):
                raise self._snapshot_error("track entry is invalid")
            if tid in tracks:
                raise self._snapshot_error("duplicate track id")
            try:
                points = _validate_keyframes(keyframes)
            except TrackError as exc:
                raise self._snapshot_error(exc.detail) from exc

            tracks[tid] = TrackInfo(
                tid, lang, codec_name.lower(), channels, bitrate, points
            )

        preferences_raw = state["preferences"]
        if not isinstance(preferences_raw, (list, tuple)):
            raise self._snapshot_error("preferences must be a sequence")
        preferences: list[str] = []
        for item in preferences_raw:
            lang = _language(item)
            if not lang:
                raise self._snapshot_error("preferences contain an invalid language")
            if lang not in preferences:
                preferences.append(lang)

        device_raw = state["device"]
        if not isinstance(device_raw, dict):
            raise self._snapshot_error("device must be a mapping")
        if "codecs" not in device_raw or "max_channels" not in device_raw:
            raise self._snapshot_error("device entry is incomplete")
        try:
            codecs = _validate_codecs(device_raw["codecs"])
        except TrackError as exc:
            raise self._snapshot_error(exc.detail) from exc
        max_channels = device_raw["max_channels"]
        if not _is_int(max_channels) or max_channels <= 0:
            raise self._snapshot_error("max_channels must be a positive integer")

        current = state["current"]
        if current is not None:
            if not isinstance(current, str) or current not in tracks:
                raise self._snapshot_error("current track is unknown")

        preloaded_raw = state["preloaded"]
        if not isinstance(preloaded_raw, (list, tuple)):
            raise self._snapshot_error("preloaded must be a sequence")
        preloaded: dict[str, TrackInfo] = {}
        for track_id in preloaded_raw:
            if not isinstance(track_id, str) or track_id not in tracks:
                raise self._snapshot_error("preloaded track is unknown")
            if track_id in preloaded:
                raise self._snapshot_error("duplicate preloaded track")
            preloaded[track_id] = tracks[track_id]

        queued_raw = state["queued"]
        if not isinstance(queued_raw, (list, tuple)):
            raise self._snapshot_error("queued must be a sequence")
        queued: list[_QueuedSwitch] = []
        for raw in queued_raw:
            if not isinstance(raw, dict):
                raise self._snapshot_error("queued entries must be mappings")
            try:
                track_id = raw["track_id"]
                language = raw["language"]
                queued_position = raw["position"]
                scheduled_at = raw["scheduled_at"]
            except (KeyError, TypeError) as exc:
                raise self._snapshot_error("queued entry is incomplete") from exc
            lang = _language(language)
            if (
                not isinstance(track_id, str)
                or track_id not in tracks
                or not lang
                or not _is_int(queued_position)
                or queued_position < 0
                or (
                    scheduled_at is not None
                    and (not _is_int(scheduled_at) or scheduled_at < 0)
                )
            ):
                raise self._snapshot_error("queued entry is invalid")
            queued.append(
                _QueuedSwitch(track_id, lang, queued_position, scheduled_at)
            )

        position = state["position"]
        if not _is_int(position) or position < 0:
            raise self._snapshot_error(
                "position must be a non-negative integer"
            )

        stats_raw = state["stats"]
        if not isinstance(stats_raw, dict):
            raise self._snapshot_error("stats must be a mapping")
        if not set(_STAT_KEYS).issubset(stats_raw):
            raise self._snapshot_error("stats are incomplete")
        for value in stats_raw.values():
            if not _is_int(value) or value < 0:
                raise self._snapshot_error("stats must be non-negative integers")
        stats = dict(stats_raw)

        return (
            tracks,
            tuple(preferences),
            codecs,
            max_channels,
            current,
            preloaded,
            queued,
            position,
            stats,
        )

    def restore(self, state: dict) -> None:
        """Replace the selector state with a previously taken snapshot."""
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except TrackError:
                raise
            except Exception as exc:  # keep the public error contract
                raise self._snapshot_error(str(exc)) from exc

            (
                tracks,
                preferences,
                codecs,
                max_channels,
                current,
                preloaded,
                queued,
                position,
                stats,
            ) = parsed

            self._tracks = tracks
            self._preferences = preferences
            self._device_codecs = codecs
            self._max_channels = max_channels
            self._current_id = current
            self._preloaded = preloaded
            self._queued = queued
            self._position = position
            self._stats = stats
