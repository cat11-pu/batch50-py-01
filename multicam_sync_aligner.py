"""Multicamera audio fingerprint alignment and drift reporting."""

from __future__ import annotations

import copy
import math
import threading
from collections import OrderedDict
from dataclasses import dataclass


class SyncError(ValueError):
    """Raised when an alignment request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TrackInfo:
    """Public description of one ingested camera track."""

    track_id: str
    sample_rate: int
    windows: int
    locked: bool


@dataclass(frozen=True)
class OffsetEstimate:
    """Estimated offset of one track against a reference track."""

    track_id: str
    offset_ms: int
    confidence: float
    ambiguous: bool


@dataclass(frozen=True)
class DriftSegment:
    """One segment of the piecewise-linear drift report."""

    start_ms: int
    end_ms: int
    drift_ppm: int


_CONFIDENCE_LIMIT = 0.75
_HIGH_CORRELATION = 0.90
_ALIAS_SCORE_TOLERANCE = 0.015


class MulticamSyncAligner:
    """Align camera tracks onto one timeline and report long-term drift."""

    def __init__(self, *, window_ms: int = 10, max_lag_ms: int = 500,
                 segment_ms: int = 1000, max_tracks: int = 16) -> None:
        self.window_ms = window_ms
        self.max_lag_ms = max_lag_ms
        self.segment_ms = segment_ms
        self.max_tracks = max_tracks
        self._lock = threading.RLock()
        self._reset_state_locked()

    def _reset_state_locked(self) -> None:
        self._tracks = OrderedDict()
        self._ingests = 0
        self._estimate_count = 0
        self._commits = 0
        self._version = None
        self._default_reference_id = None
        self._alignment = None
        self._committed_alignment = None
        self._offset_cache = {}

    def ingest_track(self, track_id, samples, sample_rate=48000):
        rate = self._validated_sample_rate(sample_rate)
        window_size = self._window_size(rate)
        fingerprints = self._rms_fingerprints(samples, window_size)
        if not fingerprints:
            raise SyncError(
                "EMPTY_TRACK",
                "at least one complete fingerprint window is required",
            )

        with self._lock:
            if track_id in self._tracks:
                raise SyncError("DUPLICATE_TRACK", track_id)
            if len(self._tracks) >= self.max_tracks:
                raise SyncError("TRACK_CAPACITY", self.max_tracks)

            index = self._ingests
            self._tracks[track_id] = {
                "track_id": track_id,
                "index": index,
                "sample_rate": rate,
                "window_size": window_size,
                "fingerprints": fingerprints,
                "locked": False,
                "needs_review": False,
            }
            self._ingests += 1
            if self._default_reference_id is None:
                self._default_reference_id = track_id
            return index

    @staticmethod
    def _validated_sample_rate(sample_rate):
        if isinstance(sample_rate, bool) or not isinstance(
                sample_rate, (int, float)):
            raise SyncError("INVALID_SAMPLE_RATE", sample_rate)
        rate = float(sample_rate)
        if not math.isfinite(rate) or rate <= 0:
            raise SyncError("INVALID_SAMPLE_RATE", sample_rate)
        if rate.is_integer():
            return int(rate)
        return sample_rate

    def _window_size(self, sample_rate) -> int:
        try:
            window_size = int(round(
                float(sample_rate) * float(self.window_ms) / 1000.0
            ))
        except (TypeError, ValueError, OverflowError) as exc:
            raise SyncError("INVALID_WINDOW", self.window_ms) from exc
        if window_size <= 0:
            raise SyncError("INVALID_WINDOW", self.window_ms)
        return window_size

    @staticmethod
    def _rms_fingerprints(samples, window_size: int):
        fingerprints = []
        sum_squares = 0.0
        filled = 0
        for sample in samples:
            value = float(sample)
            sum_squares += value * value
            filled += 1
            if filled == window_size:
                fingerprints.append(math.sqrt(sum_squares / window_size))
                sum_squares = 0.0
                filled = 0
        return fingerprints

    def estimate_offset(self, track_id, reference_id):
        with self._lock:
            return self._estimate_offset_locked(
                track_id, reference_id, count=True
            )

    def _estimate_offset_locked(self, track_id, reference_id, *, count: bool):
        track = self._tracks.get(track_id)
        if track is None:
            raise SyncError("UNKNOWN_TRACK", track_id)
        reference = self._tracks.get(reference_id)
        if reference is None:
            raise SyncError("UNKNOWN_REFERENCE", reference_id)

        if track_id == reference_id:
            estimate = OffsetEstimate(track_id, 0, 1.0, False)
        else:
            lag, confidence, ambiguous = self._find_offset(
                track["fingerprints"], reference["fingerprints"]
            )
            estimate = OffsetEstimate(
                track_id,
                int(round(lag * float(self.window_ms))),
                confidence,
                ambiguous,
            )

        self._offset_cache[(track_id, reference_id)] = estimate
        track["needs_review"] = estimate.ambiguous
        if count:
            self._estimate_count += 1
        return estimate

    def _lag_radius_windows(self) -> int:
        try:
            radius = int(float(self.max_lag_ms) // float(self.window_ms))
        except (TypeError, ValueError, ZeroDivisionError) as exc:
            raise SyncError("INVALID_LAG", self.max_lag_ms) from exc
        return max(0, radius)

    def _find_offset(self, track_fp, reference_fp):
        radius = self._lag_radius_windows()
        scores = []
        for lag in range(-radius, radius + 1):
            score, overlap = self._correlation_at_lag(
                track_fp, reference_fp, lag
            )
            scores.append((lag, score, overlap))

        min_overlap = min(
            12,
            max(3, min(len(track_fp), len(reference_fp)) // 4),
        )
        reliable_scores = [
            item for item in scores if item[2] >= min_overlap
        ]
        peak_scores = reliable_scores or scores
        best_lag, best_score, best_overlap = self._select_peak(peak_scores)
        corrected_lag, unresolved_alias = self._resolve_periodic_alias(
            peak_scores, best_lag, best_score
        )
        corrected_lag, corrected_score, corrected_overlap = next(
            item for item in scores if item[0] == corrected_lag
        )

        close_secondary = self._has_close_secondary(
            scores, corrected_lag, corrected_score
        )
        confidence = max(0.0, min(1.0, float(corrected_score)))
        ambiguous = (
            confidence < _CONFIDENCE_LIMIT
            or unresolved_alias
            or corrected_overlap < 3
            or (
                corrected_score < _HIGH_CORRELATION
                and close_secondary
            )
        )
        if unresolved_alias:
            confidence = min(confidence, 0.4)
        return corrected_lag, confidence, ambiguous

    @staticmethod
    def _correlation_at_lag(x, y, lag):
        start_y = max(0, -lag)
        end_y = min(len(y), len(x) - lag)
        count = end_y - start_y
        if count <= 0:
            return 0.0, 0
        if count == 1:
            x_value = x[start_y + lag]
            y_value = y[start_y]
            if x_value == y_value and x_value != 0.0:
                return 1.0, 1
            return 0.0, 1

        sum_x = sum_y = 0.0
        sum_xx = sum_yy = sum_xy = 0.0
        for y_index in range(start_y, end_y):
            x_value = x[y_index + lag]
            y_value = y[y_index]
            sum_x += x_value
            sum_y += y_value
            sum_xx += x_value * x_value
            sum_yy += y_value * y_value
            sum_xy += x_value * y_value

        mean_x = sum_x / count
        mean_y = sum_y / count
        var_x = sum_xx - sum_x * mean_x
        var_y = sum_yy - sum_y * mean_y
        covariance = sum_xy - sum_x * mean_y
        if var_x <= 1e-14 or var_y <= 1e-14:
            return 0.0, count
        denominator = math.sqrt(max(0.0, var_x * var_y))
        if denominator <= 1e-14:
            return 0.0, count
        score = covariance / denominator
        score = max(0.0, min(1.0, score))
        return score, count

    @staticmethod
    def _select_peak(scores):
        return max(
            scores,
            key=lambda item: (
                item[1],
                item[2],
                -abs(item[0]),
                -item[0],
            ),
        )

    @classmethod
    def _resolve_periodic_alias(cls, scores, best_lag, best_score):
        if best_score < _HIGH_CORRELATION:
            return best_lag, False

        tied = [
            (lag, score, overlap)
            for lag, score, overlap in scores
            if score >= best_score - 1e-9
            and score >= _HIGH_CORRELATION
            and overlap >= 2
        ]
        if len(tied) >= 2:
            selected = cls._select_peak(tied)
            preferred = selected[0]
            opposite = -preferred
            unresolved = (
                preferred != 0
                and any(
                    lag == opposite
                    and lag != preferred
                    and abs(score - selected[1]) <= 1e-9
                    and overlap == selected[2]
                    for lag, score, overlap in tied
                )
            )
            return preferred, unresolved

        secondary = cls._secondary_peak(scores, best_lag, min_separation=2)
        if secondary is None:
            return best_lag, False
        secondary_lag, secondary_score = secondary
        if secondary_score < best_score - _ALIAS_SCORE_TOLERANCE:
            return best_lag, False

        period = abs(best_lag - secondary_lag)
        if period <= 1:
            return best_lag, False
        checked_lag = best_lag
        toward_zero = -1 if checked_lag > 0 else 1
        candidate_lag = checked_lag + toward_zero * period
        candidate = next(
            (item for item in scores if item[0] == candidate_lag),
            None,
        )
        if candidate is not None:
            candidate_score, candidate_overlap = candidate[1], candidate[2]
            best_item = next(item for item in scores if item[0] == best_lag)
            if (candidate_score >= best_score - 1e-9
                    and candidate_overlap >= best_item[2]):
                checked_lag = candidate_lag

        strong = [
            (lag, score, overlap)
            for lag, score, overlap in scores
            if score >= best_score - _ALIAS_SCORE_TOLERANCE
            and score >= _HIGH_CORRELATION
        ]
        aliases = [lag for lag, _, _ in strong]
        unresolved = (
            -checked_lag in aliases
            and abs(checked_lag) > 0
            and any(
                lag == -checked_lag
                and score >= best_score - 1e-9
                for lag, score, _ in strong
            )
        )
        return checked_lag, unresolved

    @staticmethod
    def _secondary_peak(scores, best_lag, *, min_separation: int):
        candidates = [
            (lag, score)
            for lag, score, _ in scores
            if abs(lag - best_lag) >= min_separation
        ]
        if not candidates:
            return None
        return max(candidates, key=lambda item: (item[1], -abs(item[0])))

    @classmethod
    def _has_close_secondary(cls, scores, best_lag, best_score) -> bool:
        secondary = cls._secondary_peak(scores, best_lag, min_separation=2)
        if secondary is None:
            return False
        _, secondary_score = secondary
        return secondary_score >= best_score - _ALIAS_SCORE_TOLERANCE

    def align(self, reference_id):
        with self._lock:
            if reference_id not in self._tracks:
                raise SyncError("UNKNOWN_REFERENCE", reference_id)

            if self._committed_alignment is not None:
                committed_ref = self._committed_alignment["reference_id"]
                frozen = dict(self._committed_alignment["offsets"])
                if reference_id == committed_ref:
                    offsets = self._extend_alignment_locked(
                        frozen, reference_id
                    )
                    for track_id, offset in offsets.items():
                        self._committed_alignment["offsets"].setdefault(
                            track_id, offset
                        )
                    self._alignment = {
                        "reference_id": reference_id,
                        "offsets": dict(offsets),
                        "frozen": True,
                    }
                    return dict(offsets)

                transformed = self._transform_offsets(
                    frozen, committed_ref, reference_id
                )
                offsets = self._extend_alignment_locked(
                    transformed, reference_id
                )
                return dict(offsets)

            base = self._alignment
            offsets = {}
            if base is not None:
                if base.get("reference_id") == reference_id:
                    offsets.update(base["offsets"])
                else:
                    offsets.update(self._transform_offsets(
                        base["offsets"],
                        base.get("reference_id"),
                        reference_id,
                    ))

            offsets[reference_id] = 0
            for track_id in self._tracks:
                if track_id == reference_id:
                    continue
                track = self._tracks[track_id]
                cached = offsets.get(track_id)
                if track["locked"] and cached is not None:
                    continue
                if track["locked"] and base is not None:
                    old_offset = base["offsets"].get(track_id)
                    if old_offset is not None:
                        offsets[track_id] = old_offset
                        continue
                estimate = self._estimate_offset_locked(
                    track_id, reference_id, count=True
                )
                offsets[track_id] = estimate.offset_ms

            offsets = {
                track_id: int(offsets.get(track_id, 0))
                for track_id in self._tracks
            }
            self._default_reference_id = reference_id
            self._alignment = {
                "reference_id": reference_id,
                "offsets": dict(offsets),
                "frozen": False,
            }
            if self._commits > 0 and self._committed_alignment is None:
                self._committed_alignment = {
                    "version": self._version,
                    "reference_id": reference_id,
                    "offsets": dict(offsets),
                }
            return dict(offsets)

    def _extend_alignment_locked(self, offsets, reference_id):
        result = dict(offsets)
        result[reference_id] = 0
        for track_id in self._tracks:
            if track_id == reference_id or track_id in result:
                continue
            estimate = self._estimate_offset_locked(
                track_id, reference_id, count=True
            )
            result[track_id] = estimate.offset_ms
        return {
            track_id: int(result.get(track_id, 0))
            for track_id in self._tracks
        }

    @staticmethod
    def _transform_offsets(offsets, old_reference, new_reference):
        if new_reference not in offsets:
            return dict(offsets)
        origin = offsets[new_reference]
        return {
            track_id: int(offset - origin)
            for track_id, offset in offsets.items()
        }

    def drift_report(self, track_id, reference_id=None):
        with self._lock:
            track = self._tracks.get(track_id)
            if track is None:
                raise SyncError("UNKNOWN_TRACK", track_id)

            resolved_reference = reference_id
            if resolved_reference is None:
                resolved_reference = self._preferred_reference_locked(track_id)
            reference = self._tracks.get(resolved_reference)
            if reference is None:
                raise SyncError("UNKNOWN_REFERENCE", reference_id)

            if track_id == resolved_reference:
                return self._zero_drift_segments(track)

            return self._build_drift_report_locked(track, reference)

    def _preferred_reference_locked(self, track_id):
        if (self._alignment is not None
                and self._alignment.get("reference_id") in self._tracks):
            return self._alignment["reference_id"]
        if (self._committed_alignment is not None
                and self._committed_alignment.get("reference_id")
                in self._tracks):
            return self._committed_alignment["reference_id"]
        for candidate_id, candidate in self._tracks.items():
            if candidate_id != track_id and candidate.get("locked"):
                return candidate_id
        for candidate_id, candidate in self._tracks.items():
            if candidate_id != track_id and not candidate.get("needs_review"):
                return candidate_id
        if self._default_reference_id in self._tracks:
            return self._default_reference_id
        for candidate_id in self._tracks:
            if candidate_id != track_id:
                return candidate_id
        return track_id

    def _segment_windows(self) -> int:
        segment_windows = int(round(
            float(self.segment_ms) / float(self.window_ms)
        ))
        return max(1, segment_windows)

    def _zero_drift_segments(self, track):
        total_ms = len(track["fingerprints"]) * int(self.window_ms)
        segment_ms = int(self.segment_ms)
        segments = []
        start_ms = 0
        while start_ms < total_ms:
            end_ms = min(total_ms, start_ms + segment_ms)
            segments.append(DriftSegment(start_ms, end_ms, 0))
            start_ms = end_ms
        if not segments:
            segments.append(DriftSegment(0, 0, 0))
        return segments

    def _build_drift_report_locked(self, track, reference):
        track_fp = track["fingerprints"]
        reference_fp = reference["fingerprints"]
        track_windows = len(track_fp)
        window_ms = float(self.window_ms)
        segment_ms_value = float(self.segment_ms)
        total_ms = track_windows * window_ms
        segment_count = max(
            1,
            int(math.ceil(total_ms / segment_ms_value - 1e-9)),
        )
        boundary_ms = [0]
        boundary_windows = [0]
        for index in range(1, segment_count + 1):
            if index == segment_count:
                end_ms = total_ms
            else:
                end_ms = min(total_ms, index * segment_ms_value)
            boundary_ms.append(int(round(end_ms)))
            boundary_windows.append(
                min(track_windows, int(round(end_ms / window_ms)))
            )

        initial_lag, _, _ = self._find_offset(track_fp, reference_fp)
        anchor_lags = self._estimate_anchor_lags(
            track_fp,
            reference_fp,
            boundary_windows,
            initial_lag,
        )

        segments = []
        for index in range(segment_count):
            start_ms = boundary_ms[index]
            end_ms = boundary_ms[index + 1]
            start_lag = anchor_lags[index]
            end_lag = anchor_lags[index + 1]
            elapsed_ms = max(1, end_ms - start_ms)
            drift_ppm = int(round(
                (end_lag - start_lag) * window_ms / elapsed_ms * 1_000_000
            ))
            segments.append(DriftSegment(start_ms, end_ms, drift_ppm))
        return segments

    def _estimate_anchor_lags(self, track_fp, reference_fp,
                              boundary_windows, initial_lag):
        track_windows = len(track_fp)
        segment_windows = self._segment_windows()
        analysis_windows = max(16, min(segment_windows, 32))
        lags = []
        previous = initial_lag
        last_anchor = len(boundary_windows) - 1
        for anchor_index, position in enumerate(boundary_windows):
            if anchor_index == 0:
                range_start = 0
                range_end = min(track_windows, analysis_windows)
            elif anchor_index == last_anchor:
                range_end = track_windows
                range_start = max(0, track_windows - analysis_windows)
            else:
                half = analysis_windows // 2
                range_start = max(0, position - half)
                range_end = min(track_windows, position + half)

            lag = self._estimate_range_lag(
                track_fp,
                reference_fp,
                range_start,
                range_end,
                previous,
                self._anchor_search_radius(anchor_index, segment_windows),
            )
            lags.append(lag)
            previous = lag

        return lags

    def _anchor_search_radius(self, anchor_index, segment_windows):
        if anchor_index == 0:
            return max(self._lag_radius_windows(), 4)
        return max(2, min(8, max(2, segment_windows // 10)))

    def _estimate_range_lag(self, track_fp, reference_fp, range_start,
                            range_end, expected_lag, search_radius):
        best_key = None
        best_lag = expected_lag
        range_length = max(0, range_end - range_start)
        min_overlap = min(8, max(4, range_length // 2))
        for lag in range(
            expected_lag - search_radius,
            expected_lag + search_radius + 1,
        ):
            score, overlap = self._correlation_range_at_lag(
                track_fp,
                reference_fp,
                lag,
                range_start,
                range_end,
            )
            if overlap < min_overlap:
                continue
            key = (
                score,
                overlap,
                -abs(lag - expected_lag),
                -abs(lag),
                -lag,
            )
            if best_key is None or key > best_key:
                best_key = key
                best_lag = lag
        return best_lag

    @staticmethod
    def _correlation_range_at_lag(x, y, lag, range_start, range_end):
        start_y = max(0, range_start - lag, -lag)
        end_y = min(
            len(y),
            range_end - lag,
            len(x) - lag,
        )
        count = end_y - start_y
        if count <= 1:
            return 0.0, max(0, count)

        sum_x = sum_y = 0.0
        sum_xx = sum_yy = sum_xy = 0.0
        for y_index in range(start_y, end_y):
            x_index = y_index + lag
            x_value = x[x_index]
            y_value = y[y_index]
            sum_x += x_value
            sum_y += y_value
            sum_xx += x_value * x_value
            sum_yy += y_value * y_value
            sum_xy += x_value * y_value

        mean_x = sum_x / count
        mean_y = sum_y / count
        var_x = sum_xx - sum_x * mean_x
        var_y = sum_yy - sum_y * mean_y
        covariance = sum_xy - sum_x * mean_y
        if var_x <= 1e-14 or var_y <= 1e-14:
            return 0.0, count
        denominator = math.sqrt(max(0.0, var_x * var_y))
        if denominator <= 1e-14:
            return 0.0, count
        score = covariance / denominator
        return max(0.0, min(1.0, score)), count

    def commit(self, project_version):
        with self._lock:
            self._version = project_version
            self._commits += 1
            if self._alignment is not None:
                self._committed_alignment = {
                    "version": project_version,
                    "reference_id": self._alignment["reference_id"],
                    "offsets": dict(self._alignment["offsets"]),
                }
            return project_version

    def lock_track(self, track_id):
        with self._lock:
            track = self._tracks.get(track_id)
            if track is None:
                raise SyncError("UNKNOWN_TRACK", track_id)
            track["locked"] = True

    def track_info(self, track_id):
        with self._lock:
            track = self._tracks.get(track_id)
            if track is None:
                raise SyncError("UNKNOWN_TRACK", track_id)
            return TrackInfo(
                track_id=track["track_id"],
                sample_rate=track["sample_rate"],
                windows=len(track["fingerprints"]),
                locked=bool(track["locked"]),
            )

    def fingerprint_count(self, track_id):
        with self._lock:
            track = self._tracks.get(track_id)
            if track is None:
                raise SyncError("UNKNOWN_TRACK", track_id)
            return len(track["fingerprints"])

    def set_max_tracks(self, n):
        if isinstance(n, bool) or not isinstance(n, int):
            try:
                integer_n = int(n)
            except (TypeError, ValueError, OverflowError) as exc:
                raise SyncError("INVALID_MAX_TRACKS", n) from exc
            if integer_n != n:
                raise SyncError("INVALID_MAX_TRACKS", n)
            n = integer_n
        if n < 0:
            raise SyncError("INVALID_MAX_TRACKS", n)
        with self._lock:
            self.max_tracks = n

    def track_stats(self):
        with self._lock:
            return {
                "tracks": len(self._tracks),
                "ingests": self._ingests,
                "estimates": self._estimate_count,
                "commits": self._commits,
                "version": self._version,
            }

    def snapshot(self):
        with self._lock:
            state = {
                "schema": "multicam-sync-aligner-state",
                "version": 1,
                "schema_version": 1,
                "project_version": copy.deepcopy(self._version),
                "window_ms": self.window_ms,
                "max_lag_ms": self.max_lag_ms,
                "segment_ms": self.segment_ms,
                "max_tracks": self.max_tracks,
                "ingests": self._ingests,
                "estimates": self._estimate_count,
                "estimate_count": self._estimate_count,
                "commits": self._commits,
                "default_reference_id": self._default_reference_id,
                "reference_id": self._default_reference_id,
                "tracks": [
                    copy.deepcopy(track) for track in self._tracks.values()
                ],
                "locks": {
                    track_id: bool(track["locked"])
                    for track_id, track in self._tracks.items()
                },
                "offsets": copy.deepcopy(
                    self._alignment["offsets"]
                    if self._alignment is not None else None
                ),
                "alignment": copy.deepcopy(self._alignment),
                "committed_alignment": copy.deepcopy(
                    self._committed_alignment
                ),
                "offset_cache": [
                    {
                        "track_id": track_id,
                        "reference_id": reference_id,
                        "offset_ms": estimate.offset_ms,
                        "confidence": estimate.confidence,
                        "ambiguous": estimate.ambiguous,
                    }
                    for (track_id, reference_id), estimate
                    in self._offset_cache.items()
                ],
                "stats": self.track_stats(),
            }
            return copy.deepcopy(state)

    def restore(self, state):
        if not isinstance(state, dict):
            raise SyncError("SNAPSHOT_INVALID", "snapshot must be a dict")
        with self._lock:
            try:
                candidate = copy.deepcopy(state)
                restored = self._parse_snapshot(candidate)
            except SyncError:
                raise
            except Exception as exc:
                raise SyncError("SNAPSHOT_INVALID", state) from exc

            (
                config,
                tracks,
                ingests,
                estimate_count,
                commits,
                version,
                default_reference_id,
                alignment,
                committed_alignment,
                offset_cache,
            ) = restored
            (
                self.window_ms,
                self.max_lag_ms,
                self.segment_ms,
                self.max_tracks,
            ) = config
            self._tracks = tracks
            self._ingests = ingests
            self._estimate_count = estimate_count
            self._commits = commits
            self._version = version
            self._default_reference_id = default_reference_id
            self._alignment = alignment
            self._committed_alignment = committed_alignment
            self._offset_cache = offset_cache

    def _parse_snapshot(self, state):
        if "schema_version" in state and state["schema_version"] != 1:
            raise SyncError("SNAPSHOT_INVALID", "unsupported snapshot version")
        schema_version = state.get("schema_version", 1)
        if isinstance(schema_version, bool) or not isinstance(
                schema_version, int) or schema_version < 1:
            raise SyncError("SNAPSHOT_INVALID", "invalid snapshot version")

        tracks_value = state.get("tracks")
        if isinstance(tracks_value, dict):
            track_entries = []
            for track_key, track_state in tracks_value.items():
                if not isinstance(track_state, dict):
                    raise SyncError("SNAPSHOT_INVALID", "track must be a dict")
                track_state = dict(track_state)
                track_state.setdefault("track_id", track_key)
                track_entries.append(track_state)
        elif isinstance(tracks_value, list):
            track_entries = tracks_value
        else:
            raise SyncError("SNAPSHOT_INVALID", "tracks must be a list")

        tracks = OrderedDict()
        for track_state in track_entries:
            track = self._parse_track_snapshot(track_state)
            track_id = track["track_id"]
            if track_id in tracks:
                raise SyncError("SNAPSHOT_INVALID", "duplicate snapshot track")
            tracks[track_id] = track

        max_tracks = self._parse_nonnegative_int(
            state.get("max_tracks", self.max_tracks), "max_tracks"
        )
        ingests = self._parse_nonnegative_int(
            state.get("ingests", len(tracks)), "ingests"
        )
        estimate_count = self._parse_nonnegative_int(
            state.get(
                "estimate_count",
                state.get("estimates", 0),
            ),
            "estimate_count",
        )
        commits = self._parse_nonnegative_int(
            state.get("commits", 0), "commits"
        )
        version = state.get("project_version", state.get("commit_version"))
        if version is None and state.get("version") != 1:
            version = state.get("version")
        if version is None and isinstance(state.get("stats"), dict):
            version = state["stats"].get("version")
        if commits == 0:
            version = None

        config = (
            state.get("window_ms", self.window_ms),
            state.get("max_lag_ms", self.max_lag_ms),
            state.get("segment_ms", self.segment_ms),
            max_tracks,
        )
        for value in config[:3]:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                raise SyncError("SNAPSHOT_INVALID", "invalid timing config")
            if not math.isfinite(float(value)) or value <= 0:
                raise SyncError("SNAPSHOT_INVALID", "invalid timing config")

        default_reference_id = state.get(
            "default_reference_id",
            state.get("reference_id", state.get("reference")),
        )
        if (default_reference_id is not None
                and default_reference_id not in tracks):
            raise SyncError("SNAPSHOT_INVALID", "default reference unknown")

        alignment = self._parse_alignment_snapshot(
            state.get("alignment"), tracks
        )
        if (alignment is None and tracks
                and isinstance(state.get("offsets"), dict)):
            reference_id = default_reference_id or next(iter(tracks), None)
            simple_offsets = {track_id: 0 for track_id in tracks}
            simple_offsets.update(state["offsets"])
            alignment = self._parse_alignment_snapshot(
                {
                    "reference_id": reference_id,
                    "offsets": simple_offsets,
                },
                tracks,
            )
        committed_alignment = self._parse_committed_snapshot(
            state.get("committed_alignment"), tracks
        )
        locks_value = state.get("locks")
        if locks_value is not None:
            self._apply_snapshot_locks(locks_value, tracks)
        if committed_alignment is None and commits > 0:
            if default_reference_id is None and tracks:
                default_reference_id = next(iter(tracks))
            if alignment is not None:
                committed_alignment = {
                    "version": version,
                    "reference_id": alignment["reference_id"],
                    "offsets": dict(alignment["offsets"]),
                }
            else:
                committed_alignment = {
                    "version": version,
                    "reference_id": default_reference_id,
                    "offsets": {track_id: 0 for track_id in tracks},
                }

        offset_cache = self._parse_offset_cache(
            state.get("offset_cache", []), tracks
        )

        stats = state.get("stats")
        if stats is not None:
            if not isinstance(stats, dict):
                raise SyncError("SNAPSHOT_INVALID", "stats must be a dict")
            expected_stats = {
                "tracks": len(tracks),
                "ingests": ingests,
                "estimates": estimate_count,
                "commits": commits,
                "version": version,
            }
            for key, expected in expected_stats.items():
                if key not in stats or stats[key] != expected:
                    raise SyncError(
                        "SNAPSHOT_INVALID", f"stats mismatch: {key}"
                    )

        return (
            config,
            tracks,
            ingests,
            estimate_count,
            commits,
            version,
            default_reference_id,
            alignment,
            committed_alignment,
            offset_cache,
        )

    @staticmethod
    def _apply_snapshot_locks(locks_value, tracks):
        if isinstance(locks_value, dict):
            for track_id, locked in locks_value.items():
                if track_id not in tracks or not isinstance(locked, bool):
                    raise SyncError("SNAPSHOT_INVALID", "invalid lock marker")
                tracks[track_id]["locked"] = locked
        elif isinstance(locks_value, list):
            for track_id in locks_value:
                if track_id not in tracks:
                    raise SyncError("SNAPSHOT_INVALID", "unknown locked track")
                tracks[track_id]["locked"] = True
        else:
            raise SyncError("SNAPSHOT_INVALID", "locks must be a mapping or list")

    def _parse_track_snapshot(self, value):
        if not isinstance(value, dict):
            raise SyncError("SNAPSHOT_INVALID", "track must be a dict")
        track_id = value.get("track_id")
        if track_id is None:
            raise SyncError("SNAPSHOT_INVALID", "track_id required")
        sample_rate = self._validated_snapshot_rate(value.get("sample_rate"))
        fingerprints_value = value.get("fingerprints")
        if not isinstance(fingerprints_value, list) or not fingerprints_value:
            raise SyncError("SNAPSHOT_INVALID", "fingerprints required")
        fingerprints = []
        for fingerprint in fingerprints_value:
            if isinstance(fingerprint, bool) or not isinstance(
                    fingerprint, (int, float)):
                raise SyncError("SNAPSHOT_INVALID", "invalid fingerprint")
            number = float(fingerprint)
            if not math.isfinite(number) or number < 0:
                raise SyncError("SNAPSHOT_INVALID", "invalid fingerprint")
            fingerprints.append(number)
        index = self._parse_nonnegative_int(
            value.get("index", 0), "index"
        )
        locked = bool(value.get("locked", False))
        needs_review = bool(value.get("needs_review", False))
        return {
            "track_id": track_id,
            "index": index,
            "sample_rate": sample_rate,
            "window_size": self._window_size(sample_rate),
            "fingerprints": fingerprints,
            "locked": locked,
            "needs_review": needs_review,
        }

    @staticmethod
    def _validated_snapshot_rate(value):
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            raise SyncError("SNAPSHOT_INVALID", "sample_rate required")
        rate = float(value)
        if not math.isfinite(rate) or rate <= 0:
            raise SyncError("SNAPSHOT_INVALID", "invalid sample_rate")
        if rate.is_integer():
            return int(rate)
        return value

    @staticmethod
    def _parse_nonnegative_int(value, name):
        if isinstance(value, bool):
            raise SyncError("SNAPSHOT_INVALID", name)
        if not isinstance(value, int):
            try:
                converted = int(value)
            except (TypeError, ValueError) as exc:
                raise SyncError("SNAPSHOT_INVALID", name) from exc
            if converted != value:
                raise SyncError("SNAPSHOT_INVALID", name)
            value = converted
        if value < 0:
            raise SyncError("SNAPSHOT_INVALID", name)
        return value

    def _parse_alignment_snapshot(self, value, tracks):
        if value is None:
            return None
        if not isinstance(value, dict):
            raise SyncError("SNAPSHOT_INVALID", "alignment must be a dict")
        reference_id = value.get("reference_id")
        if reference_id not in tracks:
            raise SyncError("SNAPSHOT_INVALID", "alignment reference unknown")
        offsets_value = value.get("offsets", {})
        if not isinstance(offsets_value, dict):
            raise SyncError("SNAPSHOT_INVALID", "offsets must be a dict")
        offsets = {}
        for track_id in tracks:
            if track_id not in offsets_value:
                raise SyncError("SNAPSHOT_INVALID", "alignment offset missing")
            offset = offsets_value[track_id]
            if isinstance(offset, bool) or not isinstance(offset, int):
                raise SyncError("SNAPSHOT_INVALID", "offset must be int")
            offsets[track_id] = offset
        extra_offsets = set(offsets_value) - set(tracks)
        if extra_offsets:
            raise SyncError("SNAPSHOT_INVALID", "alignment offset unknown")
        return {
            "reference_id": reference_id,
            "offsets": offsets,
            "frozen": bool(value.get("frozen", False)),
        }

    def _parse_committed_snapshot(self, value, tracks):
        if value is None:
            return None
        if not isinstance(value, dict):
            raise SyncError("SNAPSHOT_INVALID", "committed alignment invalid")
        parsed = self._parse_alignment_snapshot(value, tracks)
        parsed["version"] = value.get("version")
        return parsed

    def _parse_offset_cache(self, value, tracks):
        if not isinstance(value, list):
            raise SyncError("SNAPSHOT_INVALID", "offset_cache must be a list")
        cache = {}
        for item in value:
            if not isinstance(item, dict):
                raise SyncError("SNAPSHOT_INVALID", "estimate must be dict")
            track_id = item.get("track_id")
            reference_id = item.get("reference_id")
            if track_id not in tracks or reference_id not in tracks:
                raise SyncError(
                    "SNAPSHOT_INVALID", "estimate references unknown track"
                )
            offset_ms = item.get("offset_ms", 0)
            if isinstance(offset_ms, bool) or not isinstance(offset_ms, int):
                raise SyncError("SNAPSHOT_INVALID", "offset_ms must be int")
            confidence_value = item.get("confidence", 0.0)
            if isinstance(confidence_value, bool) or not isinstance(
                    confidence_value, (int, float)):
                raise SyncError("SNAPSHOT_INVALID", "confidence must be number")
            confidence = float(confidence_value)
            if not math.isfinite(confidence):
                raise SyncError("SNAPSHOT_INVALID", "confidence not finite")
            ambiguous = bool(item.get("ambiguous", False))
            estimate = OffsetEstimate(
                track_id, offset_ms, confidence, ambiguous
            )
            cache[(track_id, reference_id)] = estimate
        return cache
