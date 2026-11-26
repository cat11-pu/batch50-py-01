"""Error-bounded keyframe reduction for skeletal animation curves.

Each clip holds position, rotation and scale tracks.  A track is planned with
its raw keys, reduced while staying inside a per-clip error bound, quantized to
the tolerance grid and only then committed as the new version.  Loop clips have
to close their seam, and staged work never replaces the current version until
it is committed.
"""

from __future__ import annotations

import copy
import itertools
import math
import threading
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass
from functools import wraps

__all__ = [
    "CurveError",
    "ClipView",
    "TrackPlan",
    "TrackReport",
    "LoopReport",
    "AnimationCurveCompressor",
]

KINDS = ("position", "rotation", "scale")
ARITY = {"position": 3, "rotation": 4, "scale": 3}
MAX_KEYS_PER_TRACK = 4096

_EPS = 1e-12
_BOUND_EPS = 1e-9


class CurveError(ValueError):
    """Raised when a curve operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ClipView:
    """Immutable summary of one animation clip."""

    clip_id: str
    track_count: int
    key_budget: int
    error_bound: float
    looping: bool
    version: int
    committed_tracks: int
    staged_tracks: int


@dataclass(frozen=True)
class TrackPlan:
    """One planned track with its raw keys."""

    track: str
    kind: str
    keys: tuple[tuple[int, tuple[float, ...]], ...]
    key_budget: int
    error_bound: float


@dataclass(frozen=True)
class TrackReport:
    """Outcome of compressing one track."""

    track: str
    kind: str
    input_count: int
    output_count: int
    dropped_keys: int
    max_deviation: float
    tolerance: float
    within_bound: bool
    status: str
    keys: tuple[tuple[int, tuple[float, ...]], ...]


@dataclass(frozen=True)
class LoopReport:
    """Seam check for a looping track."""

    track: str
    closure_error: float
    within_bound: bool
    seam_frame: int


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(float(value)))


def _dot(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    return sum(x * y for x, y in zip(a, b))


def _quat_norm(q: tuple[float, ...]) -> float:
    return math.sqrt(_dot(q, q))


def _normalize_quat(q: tuple[float, ...]) -> tuple[float, ...]:
    norm = _quat_norm(q)
    if norm <= _EPS:
        raise CurveError("CURVE_INVALID_REQUEST", "zero-length quaternion")
    return tuple(component / norm for component in q)


def _align_quat(q: tuple[float, ...],
                reference: tuple[float, ...]) -> tuple[float, ...]:
    if _dot(q, reference) < 0.0:
        return tuple(-component for component in q)
    return q


def _quat_angle(a: tuple[float, ...], b: tuple[float, ...]) -> float:
    qa = _normalize_quat(a)
    qb = _normalize_quat(b)
    cosine = min(1.0, max(-1.0, abs(_dot(qa, qb))))
    return 2.0 * math.acos(cosine)


def _slerp(a: tuple[float, ...], b: tuple[float, ...],
           t: float) -> tuple[float, ...]:
    qa = _normalize_quat(a)
    qb = _normalize_quat(b)
    cosine = _dot(qa, qb)
    if cosine < 0.0:
        qb = tuple(-component for component in qb)
        cosine = -cosine
    cosine = min(1.0, max(-1.0, cosine))
    if cosine > 0.9995:
        mixed = tuple(x + (y - x) * t for x, y in zip(qa, qb))
        return _normalize_quat(mixed)
    theta = math.acos(cosine)
    sine = math.sin(theta)
    if abs(sine) <= _EPS:
        return qa
    wa = math.sin((1.0 - t) * theta) / sine
    wb = math.sin(t * theta) / sine
    return tuple(wa * x + wb * y for x, y in zip(qa, qb))


def _quat_angular_velocity(a: tuple[float, ...], b: tuple[float, ...],
                           duration: float) -> tuple[float, float, float]:
    qa = _normalize_quat(a)
    qb = _align_quat(_normalize_quat(b), qa)
    w = qa[0] * qb[0] + qa[1] * qb[1] + qa[2] * qb[2] + qa[3] * qb[3]
    x = -qa[0] * qb[1] + qa[1] * qb[0] - qa[2] * qb[3] + qa[3] * qb[2]
    y = -qa[0] * qb[2] + qa[1] * qb[3] + qa[2] * qb[0] - qa[3] * qb[1]
    z = -qa[0] * qb[3] - qa[1] * qb[2] + qa[2] * qb[1] + qa[3] * qb[0]
    vector_norm = math.sqrt(x * x + y * y + z * z)
    if vector_norm <= _EPS:
        return (0.0, 0.0, 0.0)
    angle = 2.0 * math.atan2(vector_norm, min(1.0, max(-1.0, w)))
    scale = angle / (vector_norm * duration)
    return (x * scale, y * scale, z * scale)


def _grid_value(value: float, tolerance: float) -> float:
    quantized = round(value / tolerance) * tolerance
    if abs(quantized) <= _EPS * max(1.0, tolerance):
        return 0.0
    return quantized


def _quantize_rotation(value: tuple[float, ...],
                       tolerance: float) -> tuple[float, ...]:
    source = _normalize_quat(value)
    choices = []
    for component in source:
        lower = math.floor(component / tolerance) * tolerance
        upper = math.ceil(component / tolerance) * tolerance
        if abs(lower - upper) <= _EPS * max(1.0, tolerance):
            choices.append((lower,))
        else:
            choices.append((lower, upper))

    best = None
    best_error = math.inf
    for combination in itertools.product(*choices):
        norm = math.sqrt(sum(component * component for component in combination))
        if norm <= _EPS:
            continue
        normalized = tuple(component / norm for component in combination)
        error = _quat_angle(source, normalized)
        if error < best_error:
            best_error = error
            best = normalized
    if best is not None and best_error <= tolerance:
        return best
    if best is not None:
        # A normalized quaternion generally cannot stay on a coarse component
        # grid.  Prefer the exact orientation over a grid point that would
        # violate the requested angular bound.
        return source

    index = max(range(4), key=lambda item: abs(source[item]))
    fallback = [0.0, 0.0, 0.0, 0.0]
    fallback[index] = math.copysign(tolerance, source[index])
    return _normalize_quat(tuple(fallback))


def _quantize_value(kind: str, value: tuple[float, ...],
                    tolerance: float) -> tuple[float, ...]:
    if kind == "rotation":
        return _quantize_rotation(value, tolerance)
    return tuple(_grid_value(component, tolerance) for component in value)


def _interpolate(kind: str, a: tuple[float, ...], b: tuple[float, ...],
                 t: float) -> tuple[float, ...]:
    if kind == "rotation":
        return _slerp(a, b, t)
    return tuple(x + (y - x) * t for x, y in zip(a, b))


def _deviation(kind: str, original: tuple[float, ...],
               reconstructed: tuple[float, ...]) -> float:
    if kind == "rotation":
        return _quat_angle(original, reconstructed)
    return max(abs(x - y) for x, y in zip(original, reconstructed))


def _closure_error(kind: str, first: tuple[float, ...],
                   last: tuple[float, ...]) -> float:
    if kind == "rotation":
        return _quat_angle(first, last)
    return max(abs(x - y) for x, y in zip(first, last))


def _parse_keys(kind: str, raw_keys: object) -> tuple[tuple[int, tuple[float, ...]], ...]:
    if isinstance(raw_keys, (str, bytes)) or not isinstance(raw_keys, Iterable):
        raise CurveError("CURVE_INVALID_REQUEST", "keys must be an iterable")
    try:
        items = list(raw_keys)
    except TypeError as exc:
        raise CurveError("CURVE_INVALID_REQUEST", "keys must be an iterable") from exc
    if len(items) < 2:
        raise CurveError("CURVE_INVALID_REQUEST", "at least two keys are required")
    if len(items) > MAX_KEYS_PER_TRACK:
        raise CurveError("CURVE_INVALID_REQUEST", "too many keys")

    parsed = []
    previous_frame = None
    for item in items:
        if not isinstance(item, (tuple, list)) or len(item) != 2:
            raise CurveError("CURVE_INVALID_REQUEST", "invalid key shape")
        frame, raw_value = item
        if not _is_int(frame):
            raise CurveError("CURVE_INVALID_REQUEST", "frames must be integers")
        if previous_frame is not None and frame <= previous_frame:
            raise CurveError("CURVE_FRAME_ORDER", "frames must be strictly increasing")
        if not isinstance(raw_value, (tuple, list)):
            raise CurveError("CURVE_INVALID_REQUEST", "key values must be sequences")
        if len(raw_value) != ARITY[kind]:
            raise CurveError("CURVE_INVALID_REQUEST", "wrong value arity")
        value = []
        for component in raw_value:
            if not _is_number(component):
                raise CurveError("CURVE_INVALID_REQUEST", "key components must be finite numbers")
            value.append(float(component))
        if kind == "rotation" and _quat_norm(tuple(value)) <= _EPS:
            raise CurveError("CURVE_INVALID_REQUEST", "zero-length quaternion")
        parsed.append((frame, tuple(value)))
        previous_frame = frame
    return tuple(parsed)


def _counts_refusal(method):
    @wraps(method)
    def wrapper(self, *args, **kwargs):
        try:
            return method(self, *args, **kwargs)
        except CurveError:
            with self._lock:
                self._stats["refusals"] += 1
            raise

    return wrapper


class AnimationCurveCompressor:
    """Reduce animation tracks inside an error bound and commit per version."""

    def __init__(self, *, max_tracks_per_clip: int = 64, key_budget: int = 256,
                 error_bound: float = 0.001, max_clips: int = 32) -> None:
        if not _is_int(max_tracks_per_clip) or max_tracks_per_clip <= 0:
            raise CurveError("CURVE_INVALID_REQUEST", "max_tracks_per_clip must be positive")
        if not _is_int(key_budget) or not 0 < key_budget <= MAX_KEYS_PER_TRACK:
            raise CurveError("CURVE_INVALID_REQUEST", "key_budget out of range")
        if not _is_number(error_bound) or float(error_bound) <= 0.0:
            raise CurveError("CURVE_INVALID_REQUEST", "error_bound must be positive")
        if not _is_int(max_clips) or max_clips <= 0:
            raise CurveError("CURVE_INVALID_REQUEST", "max_clips must be positive")
        self.max_tracks_per_clip = max_tracks_per_clip
        self.key_budget = key_budget
        self.error_bound = float(error_bound)
        self.max_clips = max_clips
        self._lock = threading.RLock()
        self._clips: dict[str, dict] = {}
        self._stats = {
            "plans": 0,
            "compressions": 0,
            "commits": 0,
            "rollbacks": 0,
            "dropped_keys": 0,
            "refusals": 0,
        }

    # ------------------------------------------------------------------
    # Registration and views
    # ------------------------------------------------------------------
    @staticmethod
    def _name(value: object, label: str) -> str:
        if not isinstance(value, str):
            raise CurveError("CURVE_INVALID_REQUEST", f"{label} must be a string")
        normalized = value.strip()
        if not normalized:
            raise CurveError("CURVE_INVALID_REQUEST", f"{label} must not be empty")
        return normalized

    def _clip(self, clip_id: object) -> tuple[str, dict]:
        normalized = self._name(clip_id, "clip_id")
        clip = self._clips.get(normalized)
        if clip is None:
            raise CurveError("CURVE_UNKNOWN_CLIP", normalized)
        return normalized, clip

    @staticmethod
    def _view(clip_id: str, clip: dict) -> ClipView:
        return ClipView(
            clip_id=clip_id,
            track_count=clip["track_count"],
            key_budget=clip["key_budget"],
            error_bound=clip["error_bound"],
            looping=clip["looping"],
            version=clip["version"],
            committed_tracks=len(clip["tracks"]),
            staged_tracks=len(clip["staged"]),
        )

    @_counts_refusal
    def register_clip(self, clip_id: str, *, track_count: int,
                      key_budget: int | None = None,
                      error_bound: float | None = None,
                      looping: bool = False) -> ClipView:
        """Register a clip with its track budget and error bound."""
        with self._lock:
            normalized = self._name(clip_id, "clip_id")
            if normalized in self._clips:
                raise CurveError("CURVE_CLIP_EXISTS", normalized)
            if not _is_int(track_count) or not 0 < track_count <= self.max_tracks_per_clip:
                raise CurveError("CURVE_INVALID_REQUEST", "track_count out of range")
            budget = self.key_budget if key_budget is None else key_budget
            if not _is_int(budget) or not 0 < budget <= MAX_KEYS_PER_TRACK:
                raise CurveError("CURVE_INVALID_REQUEST", "key_budget out of range")
            bound = self.error_bound if error_bound is None else error_bound
            if not _is_number(bound) or float(bound) <= 0.0:
                raise CurveError("CURVE_INVALID_REQUEST", "error_bound out of range")
            if not isinstance(looping, bool):
                raise CurveError("CURVE_INVALID_REQUEST", "looping must be boolean")
            if len(self._clips) >= self.max_clips:
                raise CurveError("CURVE_INVALID_REQUEST", "maximum clip count reached")
            clip = {
                "track_count": track_count,
                "key_budget": budget,
                "error_bound": float(bound),
                "looping": looping,
                "version": 1,
                "tracks": {},
                "plans": {},
                "staged": {},
            }
            self._clips[normalized] = clip
            return self._view(normalized, clip)

    @_counts_refusal
    def clip_view(self, clip_id: str) -> ClipView:
        """Return the current clip summary."""
        with self._lock:
            normalized, clip = self._clip(clip_id)
            return self._view(normalized, clip)

    # ------------------------------------------------------------------
    # Planning
    # ------------------------------------------------------------------
    @_counts_refusal
    def plan_tracks(self, clip_id: str, tracks) -> tuple[TrackPlan, ...]:
        """Load raw tracks for the current version, sorted by track name."""
        with self._lock:
            _, clip = self._clip(clip_id)
            if isinstance(tracks, (str, bytes)) or not isinstance(tracks, Iterable):
                raise CurveError("CURVE_INVALID_REQUEST", "tracks must be an iterable")
            try:
                entries = list(tracks)
            except TypeError as exc:
                raise CurveError("CURVE_INVALID_REQUEST", "tracks must be an iterable") from exc

            parsed_entries = []
            names = set()
            for entry in entries:
                if not isinstance(entry, (tuple, list)) or len(entry) != 3:
                    raise CurveError("CURVE_INVALID_REQUEST", "invalid track entry")
                raw_name, kind, raw_keys = entry
                name = self._name(raw_name, "track")
                if kind not in KINDS:
                    raise CurveError("CURVE_UNKNOWN_KIND", kind)
                if name in names:
                    raise CurveError("CURVE_INVALID_REQUEST", "duplicate track name")
                names.add(name)
                keys = _parse_keys(kind, raw_keys)
                parsed_entries.append((name, kind, keys))

            all_names = set(clip["tracks"]) | names
            if len(all_names) > clip["track_count"]:
                raise CurveError("CURVE_TRACK_BUDGET", len(all_names))

            for name, kind, _ in parsed_entries:
                existing = clip["tracks"].get(name)
                if existing is not None and existing["revision"] >= 1:
                    if existing["kind"] != kind:
                        raise CurveError("CURVE_INVALID_REQUEST", "committed track kind changed")

            plans = {}
            for name, kind, keys in parsed_entries:
                existing = clip["tracks"].get(name)
                if existing is not None and existing["revision"] >= 1:
                    source_kind = existing["kind"]
                    source_keys = existing["keys"]
                else:
                    source_kind = kind
                    source_keys = keys
                    clip["tracks"][name] = {
                        "kind": kind,
                        "keys": keys,
                        "revision": 0,
                    }

                old_plan = clip["plans"].get(name)
                if (old_plan is None or old_plan["kind"] != source_kind
                        or old_plan["keys"] != source_keys):
                    clip["staged"].pop(name, None)

                plan = {
                    "kind": source_kind,
                    "keys": source_keys,
                    "key_budget": clip["key_budget"],
                    "error_bound": clip["error_bound"],
                }
                clip["plans"][name] = plan
                plans[name] = plan

            self._stats["plans"] += 1
            return tuple(
                TrackPlan(
                    track=name,
                    kind=plans[name]["kind"],
                    keys=plans[name]["keys"],
                    key_budget=plans[name]["key_budget"],
                    error_bound=plans[name]["error_bound"],
                )
                for name in sorted(plans)
            )

    # ------------------------------------------------------------------
    # Reduction
    # ------------------------------------------------------------------
    @staticmethod
    def _corner_indices(kind: str,
                        keys: tuple[tuple[int, tuple[float, ...]], ...]) -> set[int]:
        corners: set[int] = set()
        if len(keys) < 3:
            return corners
        if kind == "rotation":
            values = []
            previous = None
            for _, raw in keys:
                value = _normalize_quat(raw)
                if previous is not None:
                    value = _align_quat(value, previous)
                values.append(value)
                previous = value
        else:
            values = [value for _, value in keys]

        for index in range(1, len(values) - 1):
            before = values[index - 1]
            current = values[index]
            after = values[index + 1]
            corner = False
            if kind != "rotation":
                for component in range(len(current)):
                    incoming = current[component] - before[component]
                    outgoing = after[component] - current[component]
                    if incoming * outgoing < -_EPS:
                        corner = True
                        break
                incoming = tuple(current[i] - before[i] for i in range(len(current)))
                outgoing = tuple(after[i] - current[i] for i in range(len(current)))
                if (not corner
                        and _dot(incoming, incoming) > _EPS
                        and _dot(outgoing, outgoing) > _EPS
                        and _dot(incoming, outgoing) < _EPS):
                    corner = True
            else:
                incoming = _quat_angular_velocity(before, current, 1.0)
                outgoing = _quat_angular_velocity(current, after, 1.0)
                if (_dot(incoming, incoming) > _EPS
                        and _dot(outgoing, outgoing) > _EPS
                        and _dot(incoming, outgoing) < _EPS):
                    corner = True
            if corner:
                corners.add(index)
        return corners

    @staticmethod
    def _interval_error(kind: str,
                        keys: tuple[tuple[int, tuple[float, ...]], ...],
                        values: list[tuple[float, ...]], start: int, end: int,
                        duration: float | None = None,
                        original_start: int | None = None,
                        original_end: int | None = None) -> tuple[float, int]:
        start_frame = keys[start][0]
        if duration is None:
            end_frame = keys[end][0]
        else:
            end_frame = start_frame + duration
        if original_start is None:
            original_start = start
        if original_end is None:
            original_end = end

        span = end_frame - start_frame
        worst = 0.0
        worst_index = original_start
        for index in range(original_start, original_end + 1):
            frame, original = keys[index]
            t = (frame - start_frame) / span if span else 0.0
            reconstructed = _interpolate(kind, values[start], values[end], t)
            error = _deviation(kind, original, reconstructed)
            if error > worst:
                worst = error
                worst_index = index
        return worst, worst_index

    @classmethod
    def _measure(cls, kind: str,
                 keys: tuple[tuple[int, tuple[float, ...]], ...],
                 values: list[tuple[float, ...]], selected: list[int],
                 looping: bool) -> tuple[float, int, float]:
        worst = 0.0
        worst_index = selected[0]
        for position in range(len(selected) - 1):
            error, index = cls._interval_error(
                kind, keys, values, selected[position], selected[position + 1]
            )
            if error > worst:
                worst = error
                worst_index = index

        closure = 0.0
        if looping and selected[-1] != len(keys) - 1:
            period = keys[-1][0] - keys[0][0]
            duration = keys[0][0] + period - keys[selected[-1]][0]
            error, index = cls._interval_error(
                kind,
                keys,
                values,
                selected[-1],
                selected[0],
                duration=duration,
                original_start=selected[-1],
                original_end=len(keys) - 1,
            )
            if error > worst:
                worst = error
                worst_index = index

        if looping:
            closure = _closure_error(
                kind, values[selected[0]], values[selected[-1]]
            )
        return worst, worst_index, closure

    @staticmethod
    def _seam_tangent_error(
        kind: str,
        keys: tuple[tuple[int, tuple[float, ...]], ...],
        values: list[tuple[float, ...]],
        selected: list[int],
    ) -> float:
        if len(selected) < 3:
            return 0.0
        first, second = selected[0], selected[1]
        penultimate, last = selected[-2], selected[-1]
        incoming_frames = keys[last][0] - keys[penultimate][0]
        outgoing_frames = keys[second][0] - keys[first][0]
        if incoming_frames <= 0 or outgoing_frames <= 0:
            return 0.0
        if kind == "rotation":
            incoming = _quat_angular_velocity(
                values[penultimate], values[last], incoming_frames
            )
            outgoing = _quat_angular_velocity(
                values[first], values[second], outgoing_frames
            )
            return max(abs(x - y) for x, y in zip(incoming, outgoing))
        incoming = tuple(
            (values[last][i] - values[penultimate][i]) / incoming_frames
            for i in range(len(values[first]))
        )
        outgoing = tuple(
            (values[second][i] - values[first][i]) / outgoing_frames
            for i in range(len(values[first]))
        )
        return max(abs(x - y) for x, y in zip(incoming, outgoing))

    @classmethod
    def _reduce(cls, kind: str,
                keys: tuple[tuple[int, tuple[float, ...]], ...],
                tolerance: float, looping: bool) -> tuple[list[int], list[tuple[float, ...]]]:
        values = [_quantize_value(kind, raw, tolerance) for _, raw in keys]
        count = len(keys)
        selected = list(range(count))
        if count <= 2:
            return selected, values

        forced = cls._corner_indices(kind, keys)
        raw_tangent = 0.0
        if looping:
            raw_tangent = cls._seam_tangent_error(kind, keys, values, selected)
        tangent_limit = max(tolerance, raw_tangent) + _BOUND_EPS
        closure_limit = tolerance + _BOUND_EPS

        changed = True
        while changed:
            changed = False
            position = 1
            while position < len(selected):
                index = selected[position]
                if index in forced:
                    position += 1
                    continue
                if not looping and position == len(selected) - 1:
                    position += 1
                    continue

                previous = selected[position - 1]
                if position + 1 < len(selected):
                    following = selected[position + 1]
                    error, _ = cls._interval_error(
                        kind, keys, values, previous, following
                    )
                    tangent_ok = True
                    if looping:
                        candidate = selected[:position] + selected[position + 1:]
                        tangent_ok = cls._seam_tangent_error(
                            kind, keys, values, candidate
                        ) <= tangent_limit
                    if error <= tolerance + _BOUND_EPS and tangent_ok:
                        del selected[position]
                        changed = True
                        continue
                    position += 1
                    continue

                # The final selected key may only be dropped for a loop.
                candidate = selected[:-1]
                if len(candidate) < 2:
                    position += 1
                    continue
                period = keys[-1][0] - keys[0][0]
                duration = keys[0][0] + period - keys[previous][0]
                error, _ = cls._interval_error(
                    kind,
                    keys,
                    values,
                    previous,
                    selected[0],
                    duration=duration,
                    original_start=previous,
                    original_end=len(keys) - 1,
                )
                closure = _closure_error(
                    kind, values[selected[0]], values[previous]
                )
                tangent_ok = cls._seam_tangent_error(
                    kind, keys, values, candidate
                ) <= tangent_limit
                if (error <= tolerance + _BOUND_EPS
                        and closure <= closure_limit and tangent_ok):
                    del selected[-1]
                    changed = True
                    continue
                position += 1
        return selected, values

    @classmethod
    def _compress(cls, kind: str,
                  keys: tuple[tuple[int, tuple[float, ...]], ...],
                  tolerance: float, looping: bool) -> tuple[list[int], list[tuple[float, ...]], float]:
        selected, values = cls._reduce(kind, keys, tolerance, looping)
        maximum, worst_index, _ = cls._measure(kind, keys, values, selected, looping)

        # Repair rare quantization edge cases by putting the offending original
        # key back.  A quantized key itself cannot be repaired this way.
        selected_set = set(selected)
        while maximum > tolerance + _BOUND_EPS and worst_index not in selected_set:
            selected.append(worst_index)
            selected.sort()
            selected_set.add(worst_index)
            maximum, worst_index, _ = cls._measure(
                kind, keys, values, selected, looping
            )
        return selected, values, maximum

    @_counts_refusal
    def compress_track(self, clip_id: str, track: str,
                       *, tolerance: float | None = None) -> TrackReport:
        """Reduce one planned track and stage the result."""
        with self._lock:
            _, clip = self._clip(clip_id)
            name = self._name(track, "track")
            plan = clip["plans"].get(name)
            if plan is None:
                raise CurveError("CURVE_UNKNOWN_TRACK", name)
            if tolerance is None:
                value = clip["error_bound"]
            else:
                if not _is_number(tolerance) or float(tolerance) <= 0.0:
                    raise CurveError("CURVE_INVALID_REQUEST", "tolerance must be positive")
                value = float(tolerance)
            if value > clip["error_bound"]:
                raise CurveError("CURVE_TOLERANCE_TOO_LOOSE", value)

            keys = plan["keys"]
            selected, values, maximum = self._compress(
                plan["kind"], keys, value, clip["looping"]
            )
            output_keys = tuple(
                (keys[index][0], values[index]) for index in selected
            )
            dropped = len(keys) - len(output_keys)
            status = "compressed" if dropped else "kept"
            report = TrackReport(
                track=name,
                kind=plan["kind"],
                input_count=len(keys),
                output_count=len(output_keys),
                dropped_keys=dropped,
                max_deviation=maximum,
                tolerance=value,
                within_bound=maximum <= value + _BOUND_EPS,
                status=status,
                keys=output_keys,
            )
            clip["staged"][name] = report
            self._stats["compressions"] += 1
            self._stats["dropped_keys"] += dropped
            return report

    # ------------------------------------------------------------------
    # Loops and committed views
    # ------------------------------------------------------------------
    @_counts_refusal
    def validate_loop(self, clip_id: str, track: str) -> LoopReport:
        """Check that a looping track closes its seam inside the error bound."""
        with self._lock:
            _, clip = self._clip(clip_id)
            name = self._name(track, "track")
            if not clip["looping"]:
                raise CurveError("CURVE_NOT_LOOPING", name)

            staged = clip["staged"].get(name)
            if staged is not None:
                kind = staged.kind
                keys = staged.keys
            elif name in clip["plans"]:
                kind = clip["plans"][name]["kind"]
                keys = clip["plans"][name]["keys"]
            elif name in clip["tracks"]:
                kind = clip["tracks"][name]["kind"]
                keys = clip["tracks"][name]["keys"]
            else:
                raise CurveError("CURVE_UNKNOWN_TRACK", name)

            closure = _closure_error(kind, keys[0][1], keys[-1][1])
            return LoopReport(
                track=name,
                closure_error=closure,
                within_bound=closure <= clip["error_bound"] + _BOUND_EPS,
                seam_frame=keys[-1][0],
            )

    @_counts_refusal
    def track_keys(self, clip_id: str, track: str) -> tuple[tuple[int, tuple[float, ...]], ...]:
        """Return the keys of the current committed version of a track."""
        with self._lock:
            _, clip = self._clip(clip_id)
            name = self._name(track, "track")
            committed = clip["tracks"].get(name)
            if committed is None:
                raise CurveError("CURVE_UNKNOWN_TRACK", name)
            return tuple((frame, tuple(value)) for frame, value in committed["keys"])

    @_counts_refusal
    def report(self, clip_id: str) -> tuple[TrackReport, ...]:
        """Return staged reports sorted by track name."""
        with self._lock:
            _, clip = self._clip(clip_id)
            return tuple(clip["staged"][name] for name in sorted(clip["staged"]))

    # ------------------------------------------------------------------
    # Version management
    # ------------------------------------------------------------------
    @_counts_refusal
    def commit(self, clip_id: str) -> ClipView:
        """Promote every staged track to the next clip version."""
        with self._lock:
            normalized, clip = self._clip(clip_id)
            missing = [name for name in clip["plans"] if name not in clip["staged"]]
            if not clip["plans"] or missing:
                raise CurveError("CURVE_INCOMPLETE_PLAN", sorted(missing))

            new_version = clip["version"] + 1
            for name, plan in clip["plans"].items():
                report = clip["staged"][name]
                clip["tracks"][name] = {
                    "kind": report.kind,
                    "keys": report.keys,
                    "revision": new_version,
                }
            clip["version"] = new_version
            clip["staged"].clear()
            clip["plans"].clear()
            self._stats["commits"] += 1
            return self._view(normalized, clip)

    @_counts_refusal
    def rollback(self, clip_id: str) -> ClipView:
        """Discard staged results, keeping the committed version untouched."""
        with self._lock:
            normalized, clip = self._clip(clip_id)
            clip["staged"].clear()
            self._stats["rollbacks"] += 1
            return self._view(normalized, clip)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def snapshot(self) -> dict:
        """Return a deep copy of clips and counters suitable for ``restore``."""
        with self._lock:
            clips = copy.deepcopy(self._clips)
            for clip in clips.values():
                for name, staged in list(clip["staged"].items()):
                    if isinstance(staged, TrackReport):
                        clip["staged"][name] = asdict(staged)
            return {
                "clips": clips,
                "stats": copy.deepcopy(self.stats()),
            }

    @staticmethod
    def _snapshot_name(value: object) -> str:
        if not isinstance(value, str) or not value.strip():
            raise CurveError("CURVE_SNAPSHOT_INVALID", "bad name")
        return value.strip()

    def restore(self, state: dict) -> None:
        """Replace compressor state with a snapshot, validating its structure."""
        with self._lock:
            try:
                if not isinstance(state, Mapping):
                    raise CurveError("CURVE_SNAPSHOT_INVALID", "state must be a mapping")
                if "clips" not in state or "stats" not in state:
                    raise CurveError("CURVE_SNAPSHOT_INVALID", "missing clips or stats")
                raw_clips = state["clips"]
                raw_stats = state["stats"]
                if not isinstance(raw_clips, Mapping) or not isinstance(raw_stats, Mapping):
                    raise CurveError("CURVE_SNAPSHOT_INVALID", "bad clips or stats")

                clips: dict[str, dict] = {}
                for raw_clip_id, raw_clip in raw_clips.items():
                    clip_id = self._snapshot_name(raw_clip_id)
                    if clip_id in clips:
                        raise CurveError("CURVE_SNAPSHOT_INVALID", "duplicate clip")
                    if not isinstance(raw_clip, Mapping):
                        raise CurveError("CURVE_SNAPSHOT_INVALID", "bad clip")

                    required = {
                        "track_count", "key_budget", "error_bound", "looping",
                        "version", "tracks", "plans", "staged",
                    }
                    if not required.issubset(raw_clip):
                        raise CurveError("CURVE_SNAPSHOT_INVALID", "missing clip fields")
                    track_count = raw_clip["track_count"]
                    key_budget = raw_clip["key_budget"]
                    error_bound = raw_clip["error_bound"]
                    looping = raw_clip["looping"]
                    version = raw_clip["version"]
                    if (not _is_int(track_count)
                            or not 0 < track_count <= self.max_tracks_per_clip):
                        raise CurveError("CURVE_SNAPSHOT_INVALID", "bad track_count")
                    if (not _is_int(key_budget)
                            or not 0 < key_budget <= MAX_KEYS_PER_TRACK):
                        raise CurveError("CURVE_SNAPSHOT_INVALID", "bad key_budget")
                    if not _is_number(error_bound) or float(error_bound) <= 0.0:
                        raise CurveError("CURVE_SNAPSHOT_INVALID", "bad error_bound")
                    if not isinstance(looping, bool):
                        raise CurveError("CURVE_SNAPSHOT_INVALID", "bad looping")
                    if not _is_int(version) or version < 1:
                        raise CurveError("CURVE_SNAPSHOT_INVALID", "bad version")
                    if (not isinstance(raw_clip["tracks"], Mapping)
                            or not isinstance(raw_clip["plans"], Mapping)
                            or not isinstance(raw_clip["staged"], Mapping)):
                        raise CurveError("CURVE_SNAPSHOT_INVALID", "bad clip maps")

                    tracks: dict[str, dict] = {}
                    for raw_name, raw_track in raw_clip["tracks"].items():
                        name = self._snapshot_name(raw_name)
                        if name in tracks or not isinstance(raw_track, Mapping):
                            raise CurveError("CURVE_SNAPSHOT_INVALID", "bad track")
                        kind = raw_track.get("kind")
                        if kind not in KINDS:
                            raise CurveError("CURVE_SNAPSHOT_INVALID", "bad track kind")
                        keys = _parse_keys(kind, raw_track.get("keys"))
                        revision = raw_track.get("revision", 0)
                        if (not _is_int(revision)
                                or revision < 0 or revision > version):
                            raise CurveError("CURVE_SNAPSHOT_INVALID", "bad revision")
                        tracks[name] = {
                            "kind": kind,
                            "keys": keys,
                            "revision": revision,
                        }

                    plans: dict[str, dict] = {}
                    for raw_name, raw_plan in raw_clip["plans"].items():
                        name = self._snapshot_name(raw_name)
                        if (name in plans or name not in tracks
                                or not isinstance(raw_plan, Mapping)):
                            raise CurveError("CURVE_SNAPSHOT_INVALID", "bad plan")
                        kind = raw_plan.get("kind")
                        if kind not in KINDS or kind != tracks[name]["kind"]:
                            raise CurveError("CURVE_SNAPSHOT_INVALID", "bad plan kind")
                        keys = _parse_keys(kind, raw_plan.get("keys"))
                        plan_budget = raw_plan.get("key_budget")
                        plan_bound = raw_plan.get("error_bound")
                        if not _is_int(plan_budget) or plan_budget <= 0:
                            raise CurveError("CURVE_SNAPSHOT_INVALID", "bad plan budget")
                        if not _is_number(plan_bound) or float(plan_bound) <= 0.0:
                            raise CurveError("CURVE_SNAPSHOT_INVALID", "bad plan bound")
                        plans[name] = {
                            "kind": kind,
                            "keys": keys,
                            "key_budget": plan_budget,
                            "error_bound": float(plan_bound),
                        }

                    staged: dict[str, TrackReport] = {}
                    for raw_name, raw_report in raw_clip["staged"].items():
                        name = self._snapshot_name(raw_name)
                        if isinstance(raw_report, TrackReport):
                            raw_report = {
                                "track": raw_report.track,
                                "kind": raw_report.kind,
                                "input_count": raw_report.input_count,
                                "output_count": raw_report.output_count,
                                "dropped_keys": raw_report.dropped_keys,
                                "max_deviation": raw_report.max_deviation,
                                "tolerance": raw_report.tolerance,
                                "within_bound": raw_report.within_bound,
                                "status": raw_report.status,
                                "keys": raw_report.keys,
                            }
                        if (name in staged or name not in plans
                                or not isinstance(raw_report, Mapping)):
                            raise CurveError("CURVE_SNAPSHOT_INVALID", "bad staged result")
                        kind = raw_report.get("kind")
                        if kind not in KINDS or kind != plans[name]["kind"]:
                            raise CurveError("CURVE_SNAPSHOT_INVALID", "bad report kind")
                        keys = _parse_keys(kind, raw_report.get("keys"))
                        input_count = raw_report.get("input_count")
                        output_count = raw_report.get("output_count")
                        dropped = raw_report.get("dropped_keys")
                        maximum = raw_report.get("max_deviation")
                        tolerance = raw_report.get("tolerance")
                        within = raw_report.get("within_bound")
                        status = raw_report.get("status")
                        if (not _is_int(input_count) or input_count < 2
                                or not _is_int(output_count) or output_count < 2
                                or output_count != len(keys)
                                or not _is_int(dropped)
                                or dropped != input_count - output_count
                                or not _is_number(maximum) or float(maximum) < 0.0
                                or not _is_number(tolerance) or float(tolerance) <= 0.0
                                or not isinstance(within, bool)
                                or status not in ("kept", "compressed")
                                or (status == "kept") != (dropped == 0)):
                            raise CurveError("CURVE_SNAPSHOT_INVALID", "bad report")
                        if raw_report.get("track", name) != name:
                            raise CurveError("CURVE_SNAPSHOT_INVALID", "bad report track")
                        staged[name] = TrackReport(
                            track=name,
                            kind=kind,
                            input_count=input_count,
                            output_count=output_count,
                            dropped_keys=dropped,
                            max_deviation=float(maximum),
                            tolerance=float(tolerance),
                            within_bound=within,
                            status=status,
                            keys=keys,
                        )

                    if (len(tracks) > track_count or len(plans) > len(tracks)
                            or len(staged) > len(plans)):
                        raise CurveError("CURVE_SNAPSHOT_INVALID", "inconsistent counts")
                    clips[clip_id] = {
                        "track_count": track_count,
                        "key_budget": key_budget,
                        "error_bound": float(error_bound),
                        "looping": looping,
                        "version": version,
                        "tracks": tracks,
                        "plans": plans,
                        "staged": staged,
                    }

                if len(clips) > self.max_clips:
                    raise CurveError("CURVE_SNAPSHOT_INVALID", "too many clips")
                stats = {}
                for key in ("plans", "compressions", "commits", "rollbacks",
                            "dropped_keys", "refusals"):
                    value = raw_stats.get(key)
                    if not _is_int(value) or value < 0:
                        raise CurveError("CURVE_SNAPSHOT_INVALID", "bad stats")
                    stats[key] = value
                if "clips" in raw_stats:
                    clip_stat = raw_stats["clips"]
                    if not _is_int(clip_stat) or clip_stat != len(clips):
                        raise CurveError("CURVE_SNAPSHOT_INVALID", "bad clip stat")
            except CurveError as exc:
                if exc.code == "CURVE_SNAPSHOT_INVALID":
                    raise
                raise CurveError("CURVE_SNAPSHOT_INVALID", exc.detail) from None
            except Exception as exc:  # noqa: BLE001 - all malformed states are invalid
                raise CurveError("CURVE_SNAPSHOT_INVALID", str(exc)) from None

            self._clips = clips
            self._stats = stats

    @_counts_refusal
    def stats(self) -> dict:
        """Return cumulative counters for plans, compressions and commits."""
        with self._lock:
            counters = {"clips": len(self._clips)}
            counters.update(self._stats)
            return counters
