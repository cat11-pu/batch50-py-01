"""Overdub latency measurement and sample-accurate take alignment.

The aligner owns a small number of recording tracks, measures the round-trip
latency of the monitoring chain, aligns newly recorded takes by a whole number
of samples and commits a take over a punch range while the previously
committed version is replaced in one step.
"""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass
from statistics import median

__all__ = [
    "OverdubError",
    "TrackSpec",
    "Take",
    "PunchRange",
    "CommitResult",
    "OverdubAligner",
]


class OverdubError(ValueError):
    """Raised when the aligner refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class TrackSpec:
    """One recording track and its current latency state."""

    track_id: str
    sample_rate: int
    latency_samples: int
    drift_samples: int
    max_latency: int


@dataclass(frozen=True)
class Take:
    """One recorded take placed on a track timeline."""

    take_id: str
    track_id: str
    start_sample: int
    length: int
    aligned_start: int
    punch_start: int
    punch_end: int
    status: str


@dataclass(frozen=True)
class PunchRange:
    """Punch in and punch out points of one take including its fades."""

    take_id: str
    start_sample: int
    end_sample: int
    fade_in: int
    fade_out: int


@dataclass(frozen=True)
class CommitResult:
    """Outcome of a committed take and the resulting span table."""

    track_id: str
    take_id: str
    replaced: bool
    start_sample: int
    end_sample: int
    spans: tuple[tuple[int, int], ...]


class OverdubAligner:
    """Align overdubbed takes to the backing track by measured latency."""

    def __init__(self, *, max_latency: int = 48000, drift_limit: int = 500,
                 max_tracks: int = 16) -> None:
        self.max_latency = max_latency
        self.drift_limit = drift_limit
        self.max_tracks = max_tracks
        self._lock = threading.RLock()
        self._tracks: dict[str, dict] = {}
        self._takes: dict[str, dict] = {}
        self._spans: dict[str, list[tuple[int, int]]] = {}
        self._stats = {
            "tracks": 0,
            "takes": 0,
            "committed": 0,
            "replaced": 0,
            "calibrations": 0,
        }

    def add_track(self, track_id: str, sample_rate: int, *,
                  max_latency: int | None = None) -> TrackSpec:
        """Register a recording track with a zero initial latency."""
        with self._lock:
            self._require_id(track_id, "track_id")
            if not self._is_int(sample_rate) or sample_rate <= 0:
                self._reject("INVALID_REQUEST", {
                    "track_id": track_id,
                    "sample_rate": sample_rate,
                })
            if track_id in self._tracks:
                self._reject("DUPLICATE_TRACK", {"track_id": track_id})

            track_max_latency = (
                self.max_latency if max_latency is None else max_latency
            )
            if not self._is_int(track_max_latency) or track_max_latency < 0:
                self._reject("INVALID_REQUEST", {
                    "track_id": track_id,
                    "max_latency": track_max_latency,
                })
            if len(self._tracks) >= self.max_tracks:
                self._reject("TRACK_LIMIT", {
                    "track_id": track_id,
                    "max_tracks": self.max_tracks,
                })

            track = {
                "track_id": track_id,
                "sample_rate": sample_rate,
                "max_latency": track_max_latency,
                "latency_samples": 0,
                "drift_samples": 0,
                "latency_revision": 0,
            }
            self._tracks[track_id] = track
            self._spans[track_id] = []
            self._stats["tracks"] += 1
            return self._track_spec(track)

    def calibrate(self, track_id: str,
                  measurements: list[int]) -> int:
        """Measure round-trip latency from samples and store the median."""
        with self._lock:
            track = self._get_track(track_id)
            if not isinstance(measurements, (list, tuple)):
                self._reject("INVALID_REQUEST", {
                    "track_id": track_id,
                    "reason": "measurements_required",
                })
            if len(measurements) == 0:
                self._reject("INVALID_REQUEST", {
                    "track_id": track_id,
                    "reason": "at_least_one_measurement",
                })

            values = []
            for index, value in enumerate(measurements):
                if not self._is_int(value) or value < 0:
                    self._reject("INVALID_REQUEST", {
                        "track_id": track_id,
                        "index": index,
                        "measurement": value,
                    })
                values.append(value)

            spread = max(values) - min(values)
            drift = self._half(spread)
            if spread > 2 * self.drift_limit:
                self._reject("DRIFT_EXCEEDED", {
                    "track_id": track_id,
                    "drift_samples": drift,
                    "drift_limit": self.drift_limit,
                })

            latency = median(values)
            if isinstance(latency, float) and latency.is_integer():
                latency = int(latency)
            if latency > track["max_latency"]:
                self._reject("LATENCY_TOO_LARGE", {
                    "track_id": track_id,
                    "latency_samples": latency,
                    "max_latency": track["max_latency"],
                })

            track["latency_samples"] = latency
            track["drift_samples"] = drift
            track["latency_revision"] += 1
            self._sync_uncommitted_alignment(track_id)
            self._stats["calibrations"] += 1
            return latency

    def set_latency(self, track_id: str, latency_samples: int) -> int:
        """Set the latency of a track explicitly within its hard limit."""
        with self._lock:
            track = self._get_track(track_id)
            if not self._is_int(latency_samples):
                self._reject("INVALID_REQUEST", {
                    "track_id": track_id,
                    "latency_samples": latency_samples,
                })
            if latency_samples < 0:
                self._reject("INVALID_REQUEST", {
                    "track_id": track_id,
                    "latency_samples": latency_samples,
                })
            if latency_samples > track["max_latency"]:
                self._reject("LATENCY_TOO_LARGE", {
                    "track_id": track_id,
                    "latency_samples": latency_samples,
                    "max_latency": track["max_latency"],
                })

            track["latency_samples"] = latency_samples
            track["latency_revision"] += 1
            self._sync_uncommitted_alignment(track_id)
            return latency_samples

    def place_take(self, track_id: str, take_id: str, start_sample: int,
                   length: int) -> Take:
        """Place a newly recorded take on the track timeline."""
        with self._lock:
            self._get_track(track_id)
            self._require_id(take_id, "take_id")
            if not self._is_int(start_sample) or start_sample < 0:
                self._reject("INVALID_REQUEST", {
                    "take_id": take_id,
                    "start_sample": start_sample,
                })
            if not self._is_int(length) or length <= 0:
                self._reject("INVALID_REQUEST", {
                    "take_id": take_id,
                    "length": length,
                })
            if take_id in self._takes:
                self._reject("DUPLICATE_TAKE", {"take_id": take_id})

            take = {
                "take_id": take_id,
                "track_id": track_id,
                "start_sample": start_sample,
                "length": length,
                "aligned_start": start_sample,
                "aligned": False,
                "aligned_revision": None,
                "punch_start": start_sample,
                "punch_end": start_sample + length,
                "fade_in": 0,
                "fade_out": 0,
                "status": "placed",
            }
            self._takes[take_id] = take
            self._stats["takes"] += 1
            return self._take_obj(take)

    def punch_range(self, take_id: str, start_sample: int,
                    end_sample: int) -> PunchRange:
        """Define the punch range and fades of one placed take."""
        with self._lock:
            take = self._get_take(take_id)
            if take["status"] in {"committed", "replaced", "discarded"}:
                self._reject("COMMIT_CONFLICT", {
                    "take_id": take_id,
                    "status": take["status"],
                })
            if not self._is_int(start_sample) or not self._is_int(end_sample):
                self._reject("INVALID_REQUEST", {
                    "take_id": take_id,
                    "start_sample": start_sample,
                    "end_sample": end_sample,
                })
            if start_sample >= end_sample:
                self._reject("INVALID_REQUEST", {
                    "take_id": take_id,
                    "start_sample": start_sample,
                    "end_sample": end_sample,
                    "reason": "punch_must_be_ordered",
                })

            take_start = take["start_sample"]
            take_end = take_start + take["length"]
            if start_sample < take_start or end_sample > take_end:
                self._reject("INVALID_REQUEST", {
                    "take_id": take_id,
                    "start_sample": start_sample,
                    "end_sample": end_sample,
                    "take_start": take_start,
                    "take_end": take_end,
                    "reason": "punch_outside_take",
                })

            fade_in, fade_out = self._fade_lengths(take, start_sample, end_sample)
            take["punch_start"] = start_sample
            take["punch_end"] = end_sample
            take["fade_in"] = fade_in
            take["fade_out"] = fade_out
            return PunchRange(
                take_id=take_id,
                start_sample=start_sample,
                end_sample=end_sample,
                fade_in=fade_in,
                fade_out=fade_out,
            )

    def align_take(self, take_id: str) -> int:
        """Return the aligned start of a take in whole samples."""
        with self._lock:
            take = self._get_take(take_id)
            if take["status"] == "discarded":
                self._reject("COMMIT_CONFLICT", {
                    "take_id": take_id,
                    "status": take["status"],
                })

            if take["status"] in {"committed", "replaced"}:
                return take["aligned_start"]

            track = self._tracks[take["track_id"]]
            aligned_start = take["start_sample"] - track["latency_samples"]
            take["aligned_start"] = aligned_start
            take["aligned"] = True
            take["aligned_revision"] = track["latency_revision"]
            if take["status"] == "placed":
                take["status"] = "aligned"
            return aligned_start

    def take_of(self, take_id: str) -> Take:
        """Return one take record by id."""
        with self._lock:
            return self._take_obj(self._get_take(take_id))

    def commit(self, take_id: str) -> CommitResult:
        """Commit an aligned take over its punch range."""
        with self._lock:
            take = self._get_take(take_id)
            if take["status"] in {"committed", "replaced", "discarded"}:
                self._reject("COMMIT_CONFLICT", {
                    "take_id": take_id,
                    "status": take["status"],
                })
            if not take["aligned"]:
                self._reject("TAKE_NOT_ALIGNED", {"take_id": take_id})

            track_id = take["track_id"]
            track = self._get_track(track_id)
            punch_start = take["punch_start"]
            punch_end = take["punch_end"]
            old_spans = list(self._spans[track_id])
            replaced = any(
                self._overlaps(punch_start, punch_end, start, end)
                for start, end in old_spans
            )

            replaced_take_ids = [
                old_id
                for old_id, old_take in self._takes.items()
                if old_take["track_id"] == track_id
                and old_take["status"] == "committed"
                and self._overlaps(
                    punch_start,
                    punch_end,
                    old_take["punch_start"],
                    old_take["punch_end"],
                )
            ]

            new_spans = self._replace_spans(
                old_spans, punch_start, punch_end
            )

            for old_id in replaced_take_ids:
                self._takes[old_id]["status"] = "replaced"
                self._stats["replaced"] += 1
            take["status"] = "committed"
            self._spans[track_id] = new_spans
            self._stats["committed"] += 1

            return CommitResult(
                track_id=track_id,
                take_id=take_id,
                replaced=replaced,
                start_sample=punch_start,
                end_sample=punch_end,
                spans=tuple(new_spans),
            )

    def discard_take(self, take_id: str) -> bool:
        """Drop an uncommitted take from its track."""
        with self._lock:
            take = self._takes.get(take_id)
            if take is None:
                return False
            if take["status"] in {"committed", "replaced"}:
                self._reject("COMMIT_CONFLICT", {
                    "take_id": take_id,
                    "status": take["status"],
                })
            del self._takes[take_id]
            return True

    def committed_spans(self, track_id: str) -> tuple[tuple[int, int], ...]:
        """Return the merged committed spans of a track in ascending order."""
        with self._lock:
            self._get_track(track_id)
            return tuple((start, end) for start, end in self._spans[track_id])

    def drift_estimate(self, track_id: str) -> int:
        """Return the drift estimate of the last calibration of a track."""
        with self._lock:
            track = self._get_track(track_id)
            return track["drift_samples"]

    def stats(self) -> dict:
        """Return cumulative aligner counters."""
        with self._lock:
            return dict(self._stats)

    def snapshot(self) -> dict:
        """Return a deep copy of tracks, takes, latency and span tables."""
        with self._lock:
            state = {
                "version": 1,
                "config": {
                    "max_latency": self.max_latency,
                    "drift_limit": self.drift_limit,
                    "max_tracks": self.max_tracks,
                },
                "tracks": self._tracks,
                "takes": self._takes,
                "spans": self._spans,
                "stats": self._stats,
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        """Replace aligner state from a snapshot, validating its structure."""
        with self._lock:
            restored = self._parse_snapshot(state)
            config = restored["config"]
            self.max_latency = config["max_latency"]
            self.drift_limit = config["drift_limit"]
            self.max_tracks = config["max_tracks"]
            self._tracks = restored["tracks"]
            self._takes = restored["takes"]
            self._spans = restored["spans"]
            self._stats = restored["stats"]

    @staticmethod
    def _reject(code: str, detail: object = None) -> None:
        raise OverdubError(f"OVERDUB_{code}", detail)

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @classmethod
    def _require_id(cls, value: object, name: str) -> None:
        if not isinstance(value, str):
            OverdubAligner._reject("INVALID_REQUEST", {
                "field": name,
                "value": value,
            })

    def _get_track(self, track_id: str) -> dict:
        self._require_id(track_id, "track_id")
        track = self._tracks.get(track_id)
        if track is None:
            self._reject("INVALID_REQUEST", {"track_id": track_id})
        return track

    def _get_take(self, take_id: str) -> dict:
        self._require_id(take_id, "take_id")
        take = self._takes.get(take_id)
        if take is None:
            self._reject("INVALID_REQUEST", {"take_id": take_id})
        return take

    def _track_spec(self, track: dict) -> TrackSpec:
        return TrackSpec(
            track_id=track["track_id"],
            sample_rate=track["sample_rate"],
            latency_samples=track["latency_samples"],
            drift_samples=track["drift_samples"],
            max_latency=track["max_latency"],
        )

    def _take_obj(self, take: dict) -> Take:
        return Take(
            take_id=take["take_id"],
            track_id=take["track_id"],
            start_sample=take["start_sample"],
            length=take["length"],
            aligned_start=take["aligned_start"],
            punch_start=take["punch_start"],
            punch_end=take["punch_end"],
            status=take["status"],
        )

    @staticmethod
    def _half(spread: int):
        half = spread / 2
        return int(half) if isinstance(half, float) and half.is_integer() else half

    def _sync_uncommitted_alignment(self, track_id: str) -> None:
        latency = self._tracks[track_id]["latency_samples"]
        for take in self._takes.values():
            if take["track_id"] != track_id:
                continue
            if take["status"] not in {"placed", "aligned"}:
                continue
            if take["aligned"]:
                take["aligned_start"] = take["start_sample"] - latency
                take["aligned_revision"] = self._tracks[track_id][
                    "latency_revision"
                ]

    @staticmethod
    def _overlaps(start_a: int, end_a: int, start_b: int, end_b: int) -> bool:
        return start_a < end_b and start_b < end_a

    def _fade_lengths(self, take: dict, punch_start: int,
                      punch_end: int) -> tuple[int, int]:
        punch_length = punch_end - punch_start
        track_spans = self._spans.get(take["track_id"], [])

        def seam_fade(position: int) -> int:
            candidates = [
                max(0, position - take["start_sample"]),
                max(0, take["start_sample"] + take["length"] - position),
            ]
            for span_start, span_end in track_spans:
                if span_start <= position <= span_end:
                    candidates.extend((
                        max(0, position - span_start),
                        max(0, span_end - position),
                    ))
            return max(0, min(candidates))

        fade_in = min(seam_fade(punch_start), punch_length)
        fade_out = min(seam_fade(punch_end), punch_length)
        half_length = punch_length // 2
        fade_in = min(fade_in, half_length)
        fade_out = min(fade_out, half_length)
        if fade_in + fade_out > punch_length:
            fade_out = max(0, punch_length - fade_in)
        return fade_in, fade_out

    @classmethod
    def _replace_spans(cls, spans: list[tuple[int, int]], start: int,
                       end: int) -> tuple[tuple[int, int], ...]:
        pieces: list[tuple[int, int]] = []
        for span_start, span_end in spans:
            if end <= span_start or start >= span_end:
                pieces.append((span_start, span_end))
                continue
            left_end = min(span_end, start)
            if span_start < left_end:
                pieces.append((span_start, left_end))
            right_start = max(span_start, end)
            if right_start < span_end:
                pieces.append((right_start, span_end))
        pieces.append((start, end))
        return cls._merge_spans(pieces)

    @staticmethod
    def _merge_spans(spans: list[tuple[int, int]]) -> tuple[tuple[int, int], ...]:
        if not spans:
            return ()
        ordered = sorted(spans)
        merged = [list(ordered[0])]
        for start, end in ordered[1:]:
            current_end = merged[-1][1]
            if start <= current_end:
                merged[-1][1] = max(current_end, end)
            else:
                merged.append([start, end])
        return tuple((start, end) for start, end in merged)

    def _parse_snapshot(self, state: object) -> dict:
        if not isinstance(state, dict):
            self._reject("SNAPSHOT_INVALID", {"reason": "state_not_dict"})
        if state.get("version") != 1:
            self._reject("SNAPSHOT_INVALID", {"reason": "bad_version"})

        config = state.get("config")
        tracks_state = state.get("tracks")
        takes_state = state.get("takes")
        spans_state = state.get("spans")
        stats_state = state.get("stats")
        if not all(isinstance(item, dict) for item in (
            config, tracks_state, takes_state, stats_state
        )):
            self._reject("SNAPSHOT_INVALID", {"reason": "missing_sections"})
        if not isinstance(spans_state, dict):
            self._reject("SNAPSHOT_INVALID", {"reason": "spans_not_dict"})

        for key in ("max_latency", "drift_limit", "max_tracks"):
            if not self._is_int(config.get(key)) or config[key] < 0:
                self._reject("SNAPSHOT_INVALID", {"config_key": key})

        tracks: dict[str, dict] = {}
        for track_id, track in tracks_state.items():
            if not isinstance(track_id, str) or not isinstance(track, dict):
                self._reject("SNAPSHOT_INVALID", {"track_id": track_id})
            if track.get("track_id", track_id) != track_id:
                self._reject("SNAPSHOT_INVALID", {"track_id": track_id})
            sample_rate = track.get("sample_rate")
            max_latency = track.get("max_latency")
            latency = track.get("latency_samples")
            drift = track.get("drift_samples", 0)
            revision = track.get("latency_revision", 0)
            if not self._is_int(sample_rate) or sample_rate <= 0:
                self._reject("SNAPSHOT_INVALID", {"track_id": track_id})
            if not self._is_int(max_latency) or max_latency < 0:
                self._reject("SNAPSHOT_INVALID", {"track_id": track_id})
            if not self._is_number(latency) or latency < 0 or latency > max_latency:
                self._reject("SNAPSHOT_INVALID", {"track_id": track_id})
            if not self._is_number(drift) or drift < 0:
                self._reject("SNAPSHOT_INVALID", {"track_id": track_id})
            if not self._is_int(revision) or revision < 0:
                self._reject("SNAPSHOT_INVALID", {"track_id": track_id})
            tracks[track_id] = {
                "track_id": track_id,
                "sample_rate": sample_rate,
                "max_latency": max_latency,
                "latency_samples": latency,
                "drift_samples": drift,
                "latency_revision": revision,
            }

        spans: dict[str, list[tuple[int, int]]] = {}
        for track_id, raw_spans in spans_state.items():
            if track_id not in tracks or not isinstance(raw_spans, (list, tuple)):
                self._reject("SNAPSHOT_INVALID", {"track_id": track_id})
            parsed_spans = []
            for item in raw_spans:
                if not isinstance(item, (list, tuple)) or len(item) != 2:
                    self._reject("SNAPSHOT_INVALID", {"span": item})
                start, end = item
                if not self._is_int(start) or not self._is_int(end) or start >= end:
                    self._reject("SNAPSHOT_INVALID", {"span": item})
                parsed_spans.append((start, end))
            spans[track_id] = list(self._merge_spans(parsed_spans))
        for track_id in tracks:
            spans.setdefault(track_id, [])

        valid_statuses = {"placed", "aligned", "committed", "replaced", "discarded"}
        takes: dict[str, dict] = {}
        for take_id, take in takes_state.items():
            if not isinstance(take_id, str) or not isinstance(take, dict):
                self._reject("SNAPSHOT_INVALID", {"take_id": take_id})
            track_id = take.get("track_id")
            if take.get("take_id", take_id) != take_id or track_id not in tracks:
                self._reject("SNAPSHOT_INVALID", {"take_id": take_id})

            start = take.get("start_sample")
            length = take.get("length")
            aligned_start = take.get("aligned_start")
            punch_start = take.get("punch_start")
            punch_end = take.get("punch_end")
            fade_in = take.get("fade_in", 0)
            fade_out = take.get("fade_out", 0)
            status = take.get("status")
            aligned = take.get("aligned", status in {"aligned", "committed", "replaced"})
            revision = take.get("aligned_revision")

            if not self._is_int(start) or start < 0:
                self._reject("SNAPSHOT_INVALID", {"take_id": take_id})
            if not self._is_int(length) or length <= 0:
                self._reject("SNAPSHOT_INVALID", {"take_id": take_id})
            if not self._is_number(aligned_start):
                self._reject("SNAPSHOT_INVALID", {"take_id": take_id})
            if not self._is_int(punch_start) or not self._is_int(punch_end):
                self._reject("SNAPSHOT_INVALID", {"take_id": take_id})
            if punch_start >= punch_end or punch_start < start:
                self._reject("SNAPSHOT_INVALID", {"take_id": take_id})
            if punch_end > start + length:
                self._reject("SNAPSHOT_INVALID", {"take_id": take_id})
            if not self._is_int(fade_in) or fade_in < 0:
                self._reject("SNAPSHOT_INVALID", {"take_id": take_id})
            if not self._is_int(fade_out) or fade_out < 0:
                self._reject("SNAPSHOT_INVALID", {"take_id": take_id})
            if fade_in + fade_out > punch_end - punch_start:
                self._reject("SNAPSHOT_INVALID", {"take_id": take_id})
            if status not in valid_statuses or not isinstance(aligned, bool):
                self._reject("SNAPSHOT_INVALID", {"take_id": take_id})
            if revision is not None and (not self._is_int(revision) or revision < 0):
                self._reject("SNAPSHOT_INVALID", {"take_id": take_id})

            takes[take_id] = {
                "take_id": take_id,
                "track_id": track_id,
                "start_sample": start,
                "length": length,
                "aligned_start": aligned_start,
                "aligned": aligned,
                "aligned_revision": revision,
                "punch_start": punch_start,
                "punch_end": punch_end,
                "fade_in": fade_in,
                "fade_out": fade_out,
                "status": status,
            }

        expected_stats = set(self._stats)
        if set(stats_state) != expected_stats:
            self._reject("SNAPSHOT_INVALID", {"stats": stats_state})
        stats = {}
        for key in expected_stats:
            value = stats_state.get(key)
            if not self._is_int(value) or value < 0:
                self._reject("SNAPSHOT_INVALID", {"stat": key})
            stats[key] = value

        if len(tracks) > config["max_tracks"]:
            self._reject("SNAPSHOT_INVALID", {"reason": "track_limit_exceeded"})

        return {
            "config": config,
            "tracks": tracks,
            "takes": takes,
            "spans": spans,
            "stats": stats,
        }

    @staticmethod
    def _is_number(value: object) -> bool:
        return (
            isinstance(value, (int, float))
            and not isinstance(value, bool)
            and value == value
            and value not in (float("inf"), float("-inf"))
        )
