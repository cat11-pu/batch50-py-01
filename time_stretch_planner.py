"""Time-stretch planning for pitch-preserving audio clip rendering.

The planner registers audio clips, derives analysis and synthesis frame
hops from a stretch ratio, walks the clip frame by frame while searching an
alignment offset inside a bounded window, records every overlap-add seam and
keeps enough state to resume after a restart.
"""

from __future__ import annotations

import math
import numbers
import threading
from dataclasses import dataclass

__all__ = [
    "TimeStretchError",
    "ClipSpec",
    "FramePlan",
    "StretchFrame",
    "TimeStretchPlanner",
]


class TimeStretchError(ValueError):
    """Raised when the planner refuses an operation."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class ClipSpec:
    """Registered audio clip with its stretch parameters."""

    clip_id: str
    sample_rate: int
    channels: int
    source_samples: int
    target_ratio: float
    search_window: int
    overlap: int


@dataclass(frozen=True)
class FramePlan:
    """Hop arithmetic derived from one clip and one stretch ratio."""

    clip_id: str
    ratio: float
    analysis_hop: int
    synthesis_hop: int
    frame_count: int
    output_samples: int
    search_window: int
    overlap: int


@dataclass(frozen=True)
class StretchFrame:
    """One rendered frame after alignment search and overlap-add."""

    clip_id: str
    index: int
    source_offset: int
    output_offset: int
    offset: int
    seam: bool


@dataclass
class _RenderProgress:
    next_index: int = 0
    rendered: int = 0
    seams: int = 0
    cancelled: bool = False


class TimeStretchPlanner:
    """Plan and render frame-aligned time stretching for audio clips."""

    def __init__(self, *, frame_size: int = 1024, max_search_window: int = 512,
                 max_overlap: int = 256, max_clips: int = 64) -> None:
        if not self._is_int(frame_size) or frame_size <= 0:
            self._fail("INVALID_REQUEST", "frame_size must be a positive integer")
        for name, value in (("max_search_window", max_search_window),
                            ("max_overlap", max_overlap),
                            ("max_clips", max_clips)):
            if not self._is_int(value) or value < 0:
                self._fail("INVALID_REQUEST",
                           f"{name} must be a non-negative integer")

        self.frame_size = frame_size
        self.max_search_window = max_search_window
        self.max_overlap = max_overlap
        self.max_clips = max_clips
        self._lock = threading.RLock()
        self._clips: dict[str, ClipSpec] = {}
        self._plans: dict[str, FramePlan] = {}
        self._progress: dict[str, _RenderProgress] = {}
        self._planned_count = 0
        self._frame_count = 0
        self._seam_count = 0
        self._cancelled_count = 0

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _fail(code: str, detail: object = None) -> None:
        raise TimeStretchError(f"TIME_STRETCH_{code}", detail)

    @classmethod
    def _validate_ratio(cls, value: object) -> float:
        if (isinstance(value, bool)
                or not isinstance(value, numbers.Real)):
            cls._fail("INVALID_RATIO", "target_ratio must be a real number")
        try:
            ratio = float(value)
        except (TypeError, ValueError, OverflowError):
            cls._fail("INVALID_RATIO", "target_ratio is not representable")
        if not math.isfinite(ratio) or ratio < 0.25 or ratio > 4.0:
            cls._fail("INVALID_RATIO",
                      "target_ratio must be between 0.25 and 4.0")
        return ratio

    @classmethod
    def _validate_clip_id(cls, clip_id: object) -> str:
        if not isinstance(clip_id, str) or not clip_id:
            cls._fail("INVALID_REQUEST", "clip_id must be a non-empty string")
        return clip_id

    def _require_clip(self, clip_id: str) -> ClipSpec:
        try:
            return self._clips[clip_id]
        except (KeyError, TypeError):
            self._fail("INVALID_REQUEST", f"unknown clip: {clip_id!r}")

    def _build_plan(self, spec: ClipSpec, ratio: float) -> FramePlan:
        analysis_hop = self.frame_size - spec.overlap
        synthesis_hop = max(1, int(round(analysis_hop * ratio)))
        frame_count = (
            spec.source_samples + analysis_hop - 1
        ) // analysis_hop
        output_samples = max(1, int(round(spec.source_samples * ratio)))
        return FramePlan(
            clip_id=spec.clip_id,
            ratio=ratio,
            analysis_hop=analysis_hop,
            synthesis_hop=synthesis_hop,
            frame_count=frame_count,
            output_samples=output_samples,
            search_window=spec.search_window,
            overlap=spec.overlap,
        )

    def _emit_frame(
        self, spec: ClipSpec, plan: FramePlan, progress: _RenderProgress
    ) -> StretchFrame:
        index = progress.next_index
        source_offset = index * plan.analysis_hop
        output_offset = index * plan.synthesis_hop
        seam = index > 0
        frame = StretchFrame(
            clip_id=spec.clip_id,
            index=index,
            source_offset=source_offset,
            output_offset=output_offset,
            offset=0,
            seam=seam,
        )

        progress.next_index += 1
        if progress.next_index >= plan.frame_count:
            progress.rendered = plan.output_samples
        else:
            progress.rendered = min(
                plan.output_samples,
                progress.next_index * plan.synthesis_hop,
            )
        if seam:
            progress.seams += 1
            self._seam_count += 1
        self._frame_count += 1
        return frame

    def register_clip(self, clip_id: str, sample_rate: int, channels: int,
                      source_samples: int, *, target_ratio: float = 1.0,
                      search_window: int | None = None,
                      overlap: int | None = None) -> ClipSpec:
        """Register a clip with its sample rate, channel count and ratio."""
        with self._lock:
            clip_id = self._validate_clip_id(clip_id)
            if clip_id in self._clips:
                self._fail("DUPLICATE_CLIP", f"clip already registered: {clip_id}")

            for name, value in (("sample_rate", sample_rate),
                                ("channels", channels),
                                ("source_samples", source_samples)):
                if not self._is_int(value) or value <= 0:
                    self._fail("INVALID_REQUEST",
                               f"{name} must be a positive integer")
            ratio = self._validate_ratio(target_ratio)

            if search_window is None:
                search_window = self.max_search_window
            if not self._is_int(search_window) or search_window < 0:
                self._fail("INVALID_REQUEST",
                           "search_window must be a non-negative integer")
            if search_window > self.max_search_window:
                self._fail("WINDOW_TOO_LARGE",
                           f"search_window exceeds {self.max_search_window}")

            if overlap is None:
                overlap = min(self.max_overlap, self.frame_size - 1)
            if not self._is_int(overlap) or overlap < 0:
                self._fail("INVALID_REQUEST",
                           "overlap must be a non-negative integer")
            if overlap > self.max_overlap:
                self._fail("OVERLAP_TOO_LARGE",
                           f"overlap exceeds {self.max_overlap}")
            if overlap >= self.frame_size:
                self._fail("INVALID_REQUEST",
                           "overlap must be smaller than frame_size")

            if len(self._clips) >= self.max_clips:
                self._fail("CLIP_LIMIT",
                           f"clip limit {self.max_clips} reached")

            spec = ClipSpec(
                clip_id=clip_id,
                sample_rate=sample_rate,
                channels=channels,
                source_samples=source_samples,
                target_ratio=ratio,
                search_window=search_window,
                overlap=overlap,
            )
            self._clips[clip_id] = spec
            self._progress[clip_id] = _RenderProgress()
            return spec

    def plan_stretch(self, clip_id: str,
                     target_ratio: float | None = None) -> FramePlan:
        """Derive analysis hop, synthesis hop and frame count for a clip."""
        with self._lock:
            spec = self._require_clip(clip_id)
            progress = self._progress[clip_id]
            if progress.cancelled:
                self._fail("CLIP_CANCELLED", f"clip is cancelled: {clip_id}")
            if target_ratio is None:
                ratio = spec.target_ratio
            else:
                ratio = self._validate_ratio(target_ratio)

            plan = self._build_plan(spec, ratio)
            if self._plans.get(clip_id) != plan:
                self._progress[clip_id] = _RenderProgress()
            self._plans[clip_id] = plan
            self._planned_count += 1
            return plan

    def next_frame(self, clip_id: str) -> StretchFrame:
        """Render and return the next frame of a planned clip."""
        with self._lock:
            spec = self._require_clip(clip_id)
            progress = self._progress[clip_id]
            if progress.cancelled:
                self._fail("CLIP_CANCELLED", f"clip is cancelled: {clip_id}")
            plan = self._plans.get(clip_id)
            if plan is None or progress.next_index >= plan.frame_count:
                self._fail("NO_FRAME", f"no pending frames for clip: {clip_id}")
            return self._emit_frame(spec, plan, progress)

    def drain(self, clip_id: str, limit: int) -> tuple[StretchFrame, ...]:
        """Return at most *limit* pending frames for a clip."""
        with self._lock:
            spec = self._require_clip(clip_id)
            if not self._is_int(limit) or limit <= 0:
                self._fail("INVALID_REQUEST", "limit must be a positive integer")
            progress = self._progress[clip_id]
            if progress.cancelled:
                self._fail("CLIP_CANCELLED", f"clip is cancelled: {clip_id}")
            plan = self._plans.get(clip_id)
            if plan is None:
                self._fail("NO_FRAME", f"clip has not been planned: {clip_id}")
            remaining = plan.frame_count - progress.next_index
            if remaining <= 0:
                self._fail("NO_FRAME", f"no pending frames for clip: {clip_id}")

            count = min(limit, remaining)
            return tuple(
                self._emit_frame(spec, plan, progress) for _ in range(count)
            )

    def pending(self, clip_id: str) -> int:
        """Return how many frames of a planned clip are still unrendered."""
        with self._lock:
            self._require_clip(clip_id)
            progress = self._progress[clip_id]
            if progress.cancelled:
                return 0
            plan = self._plans.get(clip_id)
            if plan is None:
                return 0
            return max(0, plan.frame_count - progress.next_index)

    def rendered_samples(self, clip_id: str) -> int:
        """Return how many output samples were already produced."""
        with self._lock:
            self._require_clip(clip_id)
            return self._progress[clip_id].rendered

    def seam_count(self, clip_id: str) -> int:
        """Return how many overlap-add seams were recorded for a clip."""
        with self._lock:
            self._require_clip(clip_id)
            return self._progress[clip_id].seams

    def cancel(self, clip_id: str) -> int:
        """Cancel a clip and return the samples produced so far."""
        with self._lock:
            self._require_clip(clip_id)
            progress = self._progress[clip_id]
            if not progress.cancelled:
                progress.cancelled = True
                self._cancelled_count += 1
            return progress.rendered

    def clip_of(self, clip_id: str) -> ClipSpec:
        """Return the registered specification of one clip."""
        with self._lock:
            return self._require_clip(clip_id)

    def stats(self) -> dict:
        """Return cumulative planner counters."""
        with self._lock:
            return {
                "clips": len(self._clips),
                "planned": self._planned_count,
                "frames": self._frame_count,
                "seams": self._seam_count,
                "cancelled": self._cancelled_count,
            }

    def snapshot(self) -> dict:
        """Return a deep copy of clips, plans and rendering progress."""
        with self._lock:
            clips = {
                clip_id: {
                    "clip_id": spec.clip_id,
                    "sample_rate": spec.sample_rate,
                    "channels": spec.channels,
                    "source_samples": spec.source_samples,
                    "target_ratio": spec.target_ratio,
                    "search_window": spec.search_window,
                    "overlap": spec.overlap,
                }
                for clip_id, spec in self._clips.items()
            }
            plans = {
                clip_id: {
                    "clip_id": plan.clip_id,
                    "ratio": plan.ratio,
                    "analysis_hop": plan.analysis_hop,
                    "synthesis_hop": plan.synthesis_hop,
                    "frame_count": plan.frame_count,
                    "output_samples": plan.output_samples,
                    "search_window": plan.search_window,
                    "overlap": plan.overlap,
                }
                for clip_id, plan in self._plans.items()
            }
            progress = {
                clip_id: {
                    "next_index": item.next_index,
                    "rendered_samples": item.rendered,
                    "seams": item.seams,
                    "cancelled": item.cancelled,
                }
                for clip_id, item in self._progress.items()
            }
            return {
                "version": 1,
                "clips": clips,
                "plans": plans,
                "progress": progress,
                "stats": self.stats(),
            }

    def restore(self, state: dict) -> None:
        """Replace planner state from a snapshot, validating its structure."""
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except TimeStretchError:
                raise
            except Exception as exc:
                raise TimeStretchError(
                    "TIME_STRETCH_SNAPSHOT_INVALID", str(exc)
                ) from exc

            clips, plans, progress, stats = parsed
            self._clips = clips
            self._plans = plans
            self._progress = progress
            self._planned_count = stats["planned"]
            self._frame_count = stats["frames"]
            self._seam_count = stats["seams"]
            self._cancelled_count = stats["cancelled"]

    def _parse_snapshot(
        self, state: object
    ) -> tuple[
        dict[str, ClipSpec],
        dict[str, FramePlan],
        dict[str, _RenderProgress],
        dict[str, int],
    ]:
        if not isinstance(state, dict):
            self._fail("SNAPSHOT_INVALID", "snapshot must be a mapping")

        version = state.get("version", 1)
        if not self._is_int(version) or version != 1:
            self._fail("SNAPSHOT_INVALID", "unsupported snapshot version")

        raw_clips = state.get("clips")
        raw_plans = state.get("plans")
        raw_progress = state.get("progress")
        raw_stats = state.get("stats")
        if not isinstance(raw_clips, dict) or not isinstance(raw_plans, dict):
            self._fail("SNAPSHOT_INVALID", "clips and plans must be mappings")
        if not isinstance(raw_progress, dict) or not isinstance(raw_stats, dict):
            self._fail("SNAPSHOT_INVALID",
                       "progress and stats must be mappings")
        if len(raw_clips) > self.max_clips:
            self._fail("SNAPSHOT_INVALID", "snapshot exceeds clip limit")

        clips: dict[str, ClipSpec] = {}
        for clip_id, raw in raw_clips.items():
            try:
                self._validate_clip_id(clip_id)
            except TimeStretchError as exc:
                self._fail("SNAPSHOT_INVALID", exc.detail)
            if not isinstance(raw, dict):
                self._fail("SNAPSHOT_INVALID",
                           f"invalid clip record: {clip_id!r}")

            required = ("clip_id", "sample_rate", "channels",
                        "source_samples", "target_ratio", "search_window",
                        "overlap")
            if any(name not in raw for name in required):
                self._fail("SNAPSHOT_INVALID",
                           f"incomplete clip record: {clip_id!r}")
            if raw["clip_id"] != clip_id:
                self._fail("SNAPSHOT_INVALID",
                           f"clip id mismatch: {clip_id!r}")

            for name in ("sample_rate", "channels", "source_samples"):
                if not self._is_int(raw[name]) or raw[name] <= 0:
                    self._fail("SNAPSHOT_INVALID",
                               f"invalid {name}: {clip_id!r}")
            try:
                ratio = self._validate_ratio(raw["target_ratio"])
            except TimeStretchError as exc:
                self._fail("SNAPSHOT_INVALID", exc.detail)

            for name in ("search_window", "overlap"):
                if not self._is_int(raw[name]) or raw[name] < 0:
                    self._fail("SNAPSHOT_INVALID",
                               f"invalid {name}: {clip_id!r}")
            if raw["search_window"] > self.max_search_window:
                self._fail("SNAPSHOT_INVALID", "search window exceeds limit")
            if raw["overlap"] > self.max_overlap:
                self._fail("SNAPSHOT_INVALID", "overlap exceeds limit")
            if raw["overlap"] >= self.frame_size:
                self._fail("SNAPSHOT_INVALID", "overlap exceeds frame size")

            clips[clip_id] = ClipSpec(
                clip_id=clip_id,
                sample_rate=raw["sample_rate"],
                channels=raw["channels"],
                source_samples=raw["source_samples"],
                target_ratio=ratio,
                search_window=raw["search_window"],
                overlap=raw["overlap"],
            )

        plans: dict[str, FramePlan] = {}
        for clip_id, raw in raw_plans.items():
            if clip_id not in clips or not isinstance(raw, dict):
                self._fail("SNAPSHOT_INVALID",
                           f"invalid plan record: {clip_id!r}")
            required = ("clip_id", "ratio", "analysis_hop", "synthesis_hop",
                        "frame_count", "output_samples", "search_window",
                        "overlap")
            if any(name not in raw for name in required):
                self._fail("SNAPSHOT_INVALID",
                           f"incomplete plan record: {clip_id!r}")
            if raw["clip_id"] != clip_id:
                self._fail("SNAPSHOT_INVALID",
                           f"plan id mismatch: {clip_id!r}")
            try:
                ratio = self._validate_ratio(raw["ratio"])
            except TimeStretchError as exc:
                self._fail("SNAPSHOT_INVALID", exc.detail)

            for name in ("analysis_hop", "synthesis_hop", "frame_count",
                         "output_samples", "search_window", "overlap"):
                if not self._is_int(raw[name]) or raw[name] < 0:
                    self._fail("SNAPSHOT_INVALID",
                               f"invalid {name}: {clip_id!r}")

            spec = clips[clip_id]
            expected = self._build_plan(spec, ratio)
            plan = FramePlan(
                clip_id=clip_id,
                ratio=ratio,
                analysis_hop=raw["analysis_hop"],
                synthesis_hop=raw["synthesis_hop"],
                frame_count=raw["frame_count"],
                output_samples=raw["output_samples"],
                search_window=raw["search_window"],
                overlap=raw["overlap"],
            )
            if plan != expected:
                self._fail("SNAPSHOT_INVALID",
                           f"inconsistent plan record: {clip_id!r}")
            plans[clip_id] = plan

        if set(raw_progress) != set(clips):
            self._fail("SNAPSHOT_INVALID",
                       "progress records do not match clips")

        progress: dict[str, _RenderProgress] = {}
        for clip_id, raw in raw_progress.items():
            if not isinstance(raw, dict):
                self._fail("SNAPSHOT_INVALID",
                           f"invalid progress record: {clip_id!r}")
            required = ("next_index", "rendered_samples", "seams",
                        "cancelled")
            if any(name not in raw for name in required):
                self._fail("SNAPSHOT_INVALID",
                           f"incomplete progress record: {clip_id!r}")

            for name in ("next_index", "rendered_samples", "seams"):
                if not self._is_int(raw[name]) or raw[name] < 0:
                    self._fail("SNAPSHOT_INVALID",
                               f"invalid {name}: {clip_id!r}")
            if not isinstance(raw["cancelled"], bool):
                self._fail("SNAPSHOT_INVALID",
                           f"invalid cancelled flag: {clip_id!r}")

            plan = plans.get(clip_id)
            if plan is None:
                if raw["next_index"] != 0 or raw["rendered_samples"] != 0 \
                        or raw["seams"] != 0:
                    self._fail("SNAPSHOT_INVALID",
                               f"progress without plan: {clip_id!r}")
            else:
                if raw["next_index"] > plan.frame_count:
                    self._fail("SNAPSHOT_INVALID",
                               f"cursor beyond frame count: {clip_id!r}")
                if raw["rendered_samples"] > plan.output_samples:
                    self._fail("SNAPSHOT_INVALID",
                               f"rendered beyond output: {clip_id!r}")
                expected_rendered = (
                    plan.output_samples
                    if raw["next_index"] >= plan.frame_count
                    else min(
                        plan.output_samples,
                        raw["next_index"] * plan.synthesis_hop,
                    )
                )
                if raw["rendered_samples"] != expected_rendered:
                    self._fail("SNAPSHOT_INVALID",
                               f"inconsistent rendered count: {clip_id!r}")
                expected_seams = max(0, raw["next_index"] - 1)
                if raw["seams"] != expected_seams:
                    self._fail("SNAPSHOT_INVALID",
                               f"inconsistent seam count: {clip_id!r}")

            progress[clip_id] = _RenderProgress(
                next_index=raw["next_index"],
                rendered=raw["rendered_samples"],
                seams=raw["seams"],
                cancelled=raw["cancelled"],
            )

        required_stats = ("clips", "planned", "frames", "seams", "cancelled")
        if any(name not in raw_stats for name in required_stats):
            self._fail("SNAPSHOT_INVALID", "incomplete stats")
        for name in required_stats:
            if not self._is_int(raw_stats[name]) or raw_stats[name] < 0:
                self._fail("SNAPSHOT_INVALID", f"invalid stat: {name}")

        stats = {name: raw_stats[name] for name in required_stats}
        if stats["clips"] != len(clips):
            self._fail("SNAPSHOT_INVALID", "clip count mismatch")
        if stats["planned"] < len(plans):
            self._fail("SNAPSHOT_INVALID", "planned count is too small")
        if stats["frames"] < sum(item.next_index for item in progress.values()):
            self._fail("SNAPSHOT_INVALID", "frame count is too small")
        if stats["seams"] < sum(item.seams for item in progress.values()):
            self._fail("SNAPSHOT_INVALID", "seam count is too small")
        cancelled = sum(1 for item in progress.values() if item.cancelled)
        if stats["cancelled"] != cancelled:
            self._fail("SNAPSHOT_INVALID", "cancelled count mismatch")

        return clips, plans, progress, stats
