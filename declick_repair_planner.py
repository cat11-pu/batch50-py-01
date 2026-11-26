"""Block-streamed click and clipping repair planner for restoration work."""

from __future__ import annotations

import math
import threading
from dataclasses import asdict, dataclass
from typing import Any, Iterable

CLIP_LEVEL = 0.98
SNAPSHOT_VERSION = 1


class DeclickError(ValueError):
    """Raised when a planner request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Click:
    """A detected click or clipping plateau, in global sample indices."""

    start: int
    end: int
    kind: str
    peak: float


@dataclass(frozen=True)
class RepairSpan:
    """A planned repair range and the reconstruction mode for it."""

    start: int
    end: int
    mode: str


def _is_number(value: Any) -> bool:
    return (
        isinstance(value, (int, float))
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


def _validate_threshold(value: Any) -> float:
    if not _is_number(value) or not 0.0 < float(value) <= 1.0:
        raise DeclickError("INVALID_CONFIG", {"field": "threshold", "value": value})
    return float(value)


def _validate_sample_rate(value: Any) -> Any:
    if not _is_number(value) or float(value) <= 0.0:
        raise DeclickError("INVALID_CONFIG", {"field": "sample_rate", "value": value})
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    rate = float(value)
    return int(rate) if rate.is_integer() else rate


def _validate_positive_int(value: Any, field: str) -> int:
    valid = (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value > 0
    ) or (
        _is_number(value)
        and float(value).is_integer()
        and int(value) > 0
    )
    if not valid:
        raise DeclickError("INVALID_CONFIG", {"field": field, "value": value})
    return int(value)


def _validate_merge_gap(value: Any) -> int:
    valid = (
        isinstance(value, int)
        and not isinstance(value, bool)
        and value >= 0
    ) or (
        _is_number(value)
        and float(value).is_integer()
        and int(value) >= 0
    )
    if not valid:
        raise DeclickError("INVALID_CONFIG", {"field": "merge_gap", "value": value})
    return int(value)


def _validate_residual_limit(value: Any) -> float:
    if not _is_number(value) or float(value) < 0.0:
        raise DeclickError(
            "INVALID_CONFIG", {"field": "residual_limit", "value": value}
        )
    return float(value)


def _as_index(value: Any, field: str) -> int:
    if isinstance(value, bool):
        raise DeclickError("INVALID_SPAN", {"field": field, "value": value})
    if isinstance(value, int):
        return value
    if _is_number(value) and float(value).is_integer():
        return int(value)
    raise DeclickError("INVALID_SPAN", {"field": field, "value": value})


def _normalize_click(click: Any) -> tuple[int, int, str]:
    if isinstance(click, Click):
        return click.start, click.end, click.kind
    if isinstance(click, dict):
        try:
            start = _as_index(click["start"], "start")
            end = _as_index(click["end"], "end")
            kind = click["kind"]
        except (KeyError, TypeError) as exc:
            raise DeclickError("INVALID_CLICK", {"click": click}) from exc
    elif isinstance(click, (tuple, list)) and len(click) >= 3:
        start = _as_index(click[0], "start")
        end = _as_index(click[1], "end")
        kind = click[2]
    else:
        raise DeclickError("INVALID_CLICK", {"click": click})

    if start < 0 or end < start or not isinstance(kind, str):
        raise DeclickError("INVALID_CLICK", {"click": click})
    return start, end, kind


def _normalize_span(span: Any) -> tuple[int, int, str]:
    if isinstance(span, RepairSpan):
        return span.start, span.end, span.mode
    if isinstance(span, dict):
        try:
            start = _as_index(span["start"], "start")
            end = _as_index(span["end"], "end")
            mode = span["mode"]
        except (KeyError, TypeError) as exc:
            raise DeclickError("INVALID_SPAN", {"span": span}) from exc
    elif isinstance(span, (tuple, list)) and len(span) >= 3:
        start = _as_index(span[0], "start")
        end = _as_index(span[1], "end")
        mode = span[2]
    else:
        raise DeclickError("INVALID_SPAN", {"span": span})

    if start < 0 or end < start or mode not in {"linear", "envelope", "smooth"}:
        raise DeclickError("INVALID_SPAN", {"span": span})
    return start, end, mode


def _line_reference(start: int, end: int, count: int) -> tuple[int, int] | None:
    """Return two ordered reference indices for the bridge line."""
    if start > 0 and end + 1 < count:
        return start - 1, end + 1
    if start == 0 and end + 1 < count:
        right = end + 1
        return (right + 1, right) if right + 1 < count else (right, right)
    if end + 1 >= count and start > 0:
        left = start - 1
        return (left - 1, left) if left - 1 >= 0 else (left, left)
    return None


def _line_values(start: int, end: int, samples: list[float]) -> list[float]:
    length = end - start + 1
    reference = _line_reference(start, end, len(samples))
    if reference is None:
        return [0.0] * length

    index_a, index_b = reference
    value_a = samples[index_a]
    value_b = samples[index_b]
    denominator = index_b - index_a
    values: list[float] = []
    for index in range(start, end + 1):
        if denominator == 0:
            value = value_a
        else:
            ratio = (index - index_a) / denominator
            value = value_a + (value_b - value_a) * ratio
        values.append(float(value))
    return values


def _side_slopes(
    start: int, end: int, samples: list[float]
) -> tuple[float, float]:
    count = len(samples)

    if start > 0 and start < count:
        left_slope = samples[start] - samples[start - 1]
    else:
        left_slope = 0.0

    if end + 1 < count and end >= 0:
        right_slope = samples[end + 1] - samples[end]
    else:
        right_slope = 0.0

    return float(left_slope), float(right_slope)


def _envelope_values(start: int, end: int, samples: list[float]) -> list[float]:
    """Reconstruct a clipped plateau with a slope-matched Hermite envelope."""
    length = end - start + 1
    if start > 0 and end + 1 < len(samples):
        left_index = start - 1
        right_index = end + 1
        left_value = samples[left_index]
        right_value = samples[right_index]
        left_slope, right_slope = _side_slopes(start, end, samples)
        distance = right_index - left_index

        values: list[float] = []
        for index in range(start, end + 1):
            t = (index - left_index) / distance
            t2 = t * t
            t3 = t2 * t
            h00 = 2.0 * t3 - 3.0 * t2 + 1.0
            h10 = t3 - 2.0 * t2 + t
            h01 = -2.0 * t3 + 3.0 * t2
            h11 = t3 - t2
            value = (
                h00 * left_value
                + h10 * distance * left_slope
                + h01 * right_value
                + h11 * distance * right_slope
            )
            values.append(max(-1.0, min(1.0, float(value))))
        return values

    base = _line_values(start, end, samples)
    left_slope, right_slope = _side_slopes(start, end, samples)
    amplitude = 0.5 * (left_slope - right_slope)
    values = []
    for offset, value in enumerate(base):
        u = (offset + 1) / (length + 1)
        arch = 4.0 * amplitude * u * (1.0 - u)
        values.append(max(-1.0, min(1.0, float(value + arch))))
    return values


def _cumulative_residual(start: int, end: int, samples: list[float]) -> float:
    line = _line_values(start, end, samples)
    deviations = [
        abs(samples[index] - line[index - start])
        for index in range(start, end + 1)
    ]
    residual = math.fsum(deviations)
    return 0.0 if residual == 0.0 else float(residual)


class DeclickRepairPlanner:
    """Plan repairs over a stream of audio blocks and account for residual error."""

    def __init__(
        self,
        *,
        threshold: float = 0.5,
        sample_rate: int = 48000,
        max_repair_len: int = 64,
        max_points_per_block: int = 8,
        merge_gap: int = 2,
        residual_limit: float = 0.25,
    ) -> None:
        self._lock = threading.RLock()
        self.threshold = _validate_threshold(threshold)
        self.sample_rate = _validate_sample_rate(sample_rate)
        self.max_repair_len = _validate_positive_int(
            max_repair_len, "max_repair_len"
        )
        self.max_points_per_block = _validate_positive_int(
            max_points_per_block, "max_points_per_block"
        )
        self.merge_gap = _validate_merge_gap(merge_gap)
        self.residual_limit = _validate_residual_limit(residual_limit)

        self._source_samples: list[float] = []
        self._samples: list[float] = []
        self._block_lengths: list[int] = []
        self._clicks: list[Click] = []
        self._planned_spans: list[RepairSpan] = []
        self._applied_spans: list[tuple[int, int, str]] = []
        self._repaired_positions: set[int] = set()
        self._residuals: list[dict[str, Any]] = []
        self._counts = {"clicks": 0, "clips": 0, "spans": 0, "applied": 0}

    def feed_block(self, block: Iterable[float]) -> int:
        with self._lock:
            try:
                incoming = list(block)
            except TypeError as exc:
                raise DeclickError(
                    "INVALID_SAMPLE", {"reason": "block is not iterable"}
                ) from exc

            values: list[float] = []
            for offset, sample in enumerate(incoming):
                if not _is_number(sample):
                    raise DeclickError(
                        "INVALID_SAMPLE", {"index": offset, "value": sample}
                    )
                values.append(float(sample))

            block_index = len(self._block_lengths)
            self._source_samples.extend(values)
            self._samples.extend(values)
            self._block_lengths.append(len(values))
            return block_index

    def detect_clicks(self) -> list[Click]:
        with self._lock:
            samples = self._source_samples
            runs: list[tuple[int, int]] = []
            index = 0
            count = len(samples)

            while index < count:
                if abs(samples[index]) <= self.threshold:
                    index += 1
                    continue
                start = index
                while index < count and abs(samples[index]) > self.threshold:
                    index += 1
                runs.append((start, index - 1))

            raw_clicks: list[Click] = []
            for start, end in runs:
                peak = max(abs(samples[i]) for i in range(start, end + 1))
                if peak >= CLIP_LEVEL:
                    kind = "clip"
                elif end - start + 1 <= 2 and peak < CLIP_LEVEL:
                    kind = "click"
                else:
                    continue
                raw_clicks.append(Click(start, end, kind, float(peak)))

            clicks: list[Click] = []
            for click in raw_clicks:
                if clicks and clicks[-1].kind == click.kind:
                    gap = click.start - clicks[-1].end - 1
                    if gap <= self.merge_gap:
                        previous = clicks[-1]
                        clicks[-1] = Click(
                            previous.start,
                            click.end,
                            previous.kind,
                            max(previous.peak, click.peak),
                        )
                        continue
                clicks.append(click)

            click_count = sum(click.kind == "click" for click in clicks)
            clip_count = sum(click.kind == "clip" for click in clicks)

            self._clicks = clicks
            self._counts["clicks"] = click_count
            self._counts["clips"] = clip_count
            return list(clicks)

    def _block_overlap_counts(
        self, spans: list[tuple[int, int, str]]
    ) -> list[int]:
        counts = [0] * len(self._block_lengths)
        block_start = 0
        block_ranges: list[tuple[int, int]] = []
        for length in self._block_lengths:
            block_ranges.append((block_start, block_start + length - 1))
            block_start += length

        for span_start, span_end, _ in spans:
            for block_index, (range_start, range_end) in enumerate(block_ranges):
                if range_end < range_start:
                    continue
                overlap_start = max(span_start, range_start)
                overlap_end = min(span_end, range_end)
                if overlap_start <= overlap_end:
                    counts[block_index] += overlap_end - overlap_start + 1
        return counts

    def _validate_plan(self, spans: list[tuple[int, int, str]]) -> None:
        sample_count = len(self._source_samples)
        for start, end, _ in spans:
            if end >= sample_count:
                raise DeclickError(
                    "INVALID_SPAN",
                    {"start": start, "end": end, "samples": sample_count},
                )
            length = end - start + 1
            if length > self.max_repair_len:
                raise DeclickError(
                    "REPAIR_TOO_LONG",
                    {
                        "start": start,
                        "end": end,
                        "length": length,
                        "limit": self.max_repair_len,
                    },
                )

        points_by_block = self._block_overlap_counts(spans)
        for block_index, points in enumerate(points_by_block):
            if points > self.max_points_per_block:
                raise DeclickError(
                    "POINT_BUDGET_EXCEEDED",
                    {
                        "block": block_index,
                        "points": points,
                        "limit": self.max_points_per_block,
                    },
                )

    def plan_repair(
        self,
        clicks: Iterable[Click | dict[str, Any] | tuple[Any, ...]] | None,
    ) -> list[RepairSpan]:
        with self._lock:
            if clicks is None:
                raw_clicks = list(self._clicks)
            else:
                raw_clicks = list(clicks)

            planned: list[tuple[int, int, str]] = []
            for click in raw_clicks:
                start, end, kind = _normalize_click(click)
                if end >= len(self._source_samples):
                    raise DeclickError(
                        "INVALID_CLICK",
                        {
                            "start": start,
                            "end": end,
                            "samples": len(self._source_samples),
                        },
                    )
                if kind == "click":
                    mode = "linear"
                elif kind == "clip":
                    mode = "envelope"
                else:
                    continue
                planned.append((start, end, mode))

            planned.sort(key=lambda item: (item[0], item[1]))
            self._validate_plan(planned)

            spans = [
                RepairSpan(start, end, mode) for start, end, mode in planned
            ]
            self._planned_spans = spans
            self._counts["spans"] = len(spans)
            return list(spans)

    def apply_repair(
        self,
        spans: Iterable[RepairSpan | dict[str, Any] | tuple[Any, ...]],
    ) -> int:
        with self._lock:
            raw_spans = list(spans)
            normalized = [_normalize_span(span) for span in raw_spans]
            sample_count = len(self._samples)
            for start, end, _ in normalized:
                if end >= sample_count:
                    raise DeclickError(
                        "INVALID_SPAN",
                        {"start": start, "end": end, "samples": sample_count},
                    )

            normalized.sort(key=lambda item: (item[0], item[1]))
            self._validate_plan(normalized)

            replaced = 0
            for start, end, mode in normalized:
                fresh_positions = [
                    index
                    for index in range(start, end + 1)
                    if index not in self._repaired_positions
                ]
                if not fresh_positions:
                    continue

                if mode == "envelope":
                    values = _envelope_values(start, end, self._samples)
                else:
                    values = _line_values(start, end, self._samples)

                for index in fresh_positions:
                    offset = index - start
                    self._samples[index] = values[offset]
                    self._repaired_positions.add(index)
                    replaced += 1

                self._applied_spans.append((start, end, mode))
                residual = _cumulative_residual(start, end, self._samples)
                self._residuals.append(
                    {"start": start, "end": end, "residual": residual}
                )

            self._counts["applied"] += replaced
            return replaced

    def verify_residual(self) -> dict[str, Any]:
        with self._lock:
            spans: list[dict[str, Any]] = []
            for record in self._residuals:
                start = int(record["start"])
                end = int(record["end"])
                residual = _cumulative_residual(start, end, self._samples)
                record["residual"] = residual
                spans.append(
                    {"start": start, "end": end, "residual": residual}
                )

            ok = all(
                _is_number(item["residual"])
                and float(item["residual"]) <= self.residual_limit
                for item in spans
            )
            return {"spans": spans, "ok": ok}

    def set_threshold(self, value: float) -> None:
        with self._lock:
            self.threshold = _validate_threshold(value)

    def set_sample_rate(self, rate: int) -> None:
        with self._lock:
            self.sample_rate = _validate_sample_rate(rate)

    def set_limits(
        self,
        *,
        max_repair_len: int | None = None,
        max_points_per_block: int | None = None,
    ) -> None:
        with self._lock:
            if max_repair_len is not None:
                self.max_repair_len = _validate_positive_int(
                    max_repair_len, "max_repair_len"
                )
            if max_points_per_block is not None:
                self.max_points_per_block = _validate_positive_int(
                    max_points_per_block, "max_points_per_block"
                )

    def committed_blocks(self) -> int:
        with self._lock:
            if not self._applied_spans:
                return 0
            last_end = max(end for _, end, _ in self._applied_spans)
            committed = 0
            block_start = 0
            for length in self._block_lengths:
                block_end_exclusive = block_start + length
                if block_end_exclusive <= last_end + 2:
                    committed += 1
                    block_start = block_end_exclusive
                else:
                    break
            return committed

    def repair_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "blocks": len(self._block_lengths),
                "samples": len(self._source_samples),
                "clicks": self._counts["clicks"],
                "clips": self._counts["clips"],
                "spans": self._counts["spans"],
                "applied": self._counts["applied"],
                "sample_rate": self.sample_rate,
                "threshold": self.threshold,
                "max_repair_len": self.max_repair_len,
            }

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            verification = self.verify_residual()
            return {
                "version": SNAPSHOT_VERSION,
                "config": {
                    "threshold": self.threshold,
                    "sample_rate": self.sample_rate,
                    "max_repair_len": self.max_repair_len,
                    "max_points_per_block": self.max_points_per_block,
                    "merge_gap": self.merge_gap,
                    "residual_limit": self.residual_limit,
                },
                "block_lengths": list(self._block_lengths),
                "source_samples": list(self._source_samples),
                "samples": list(self._samples),
                "clicks": [asdict(click) for click in self._clicks],
                "planned_spans": [asdict(span) for span in self._planned_spans],
                "applied_spans": [
                    {"start": start, "end": end, "mode": mode}
                    for start, end, mode in self._applied_spans
                ],
                "repaired_positions": sorted(self._repaired_positions),
                "residuals": [dict(item) for item in verification["spans"]],
                "counts": dict(self._counts),
            }

    @staticmethod
    def _decode_snapshot(state: Any) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise DeclickError(
                "SNAPSHOT_INVALID", {"reason": "state is not object"}
            )

        required = {
            "version",
            "config",
            "block_lengths",
            "source_samples",
            "samples",
            "clicks",
            "planned_spans",
            "applied_spans",
            "repaired_positions",
            "residuals",
            "counts",
        }
        missing = required.difference(state)
        if missing or state.get("version") != SNAPSHOT_VERSION:
            raise DeclickError("SNAPSHOT_INVALID", {"missing": sorted(missing)})

        config = state["config"]
        counts = state["counts"]
        if not isinstance(config, dict) or not isinstance(counts, dict):
            raise DeclickError("SNAPSHOT_INVALID", {"reason": "bad sections"})

        try:
            threshold = _validate_threshold(config["threshold"])
            sample_rate = _validate_sample_rate(config["sample_rate"])
            max_repair_len = _validate_positive_int(
                config["max_repair_len"], "max_repair_len"
            )
            max_points_per_block = _validate_positive_int(
                config["max_points_per_block"], "max_points_per_block"
            )
            merge_gap = _validate_merge_gap(config["merge_gap"])
            residual_limit = _validate_residual_limit(
                config["residual_limit"]
            )
        except (KeyError, DeclickError, TypeError) as exc:
            raise DeclickError(
                "SNAPSHOT_INVALID", {"reason": "bad config"}
            ) from exc

        block_lengths_raw = state["block_lengths"]
        source_raw = state["source_samples"]
        samples_raw = state["samples"]
        if not isinstance(block_lengths_raw, (list, tuple)):
            raise DeclickError("SNAPSHOT_INVALID", {"field": "block_lengths"})
        if not isinstance(source_raw, (list, tuple)) or not isinstance(
            samples_raw, (list, tuple)
        ):
            raise DeclickError("SNAPSHOT_INVALID", {"field": "samples"})

        block_lengths: list[int] = []
        for length in block_lengths_raw:
            if (
                isinstance(length, bool)
                or not isinstance(length, int)
                or length < 0
            ):
                raise DeclickError(
                    "SNAPSHOT_INVALID", {"field": "block_lengths"}
                )
            block_lengths.append(length)

        if not all(_is_number(sample) for sample in source_raw):
            raise DeclickError(
                "SNAPSHOT_INVALID", {"field": "source_samples"}
            )
        if not all(_is_number(sample) for sample in samples_raw):
            raise DeclickError("SNAPSHOT_INVALID", {"field": "samples"})

        source_samples = [float(sample) for sample in source_raw]
        samples = [float(sample) for sample in samples_raw]
        if len(source_samples) != len(samples):
            raise DeclickError(
                "SNAPSHOT_INVALID", {"reason": "sample length mismatch"}
            )
        if sum(block_lengths) != len(source_samples):
            raise DeclickError(
                "SNAPSHOT_INVALID", {"reason": "block length mismatch"}
            )

        def decode_named(items_raw: Any, kind: str) -> list[dict[str, Any]]:
            if not isinstance(items_raw, (list, tuple)):
                raise DeclickError("SNAPSHOT_INVALID", {"field": kind})
            decoded: list[dict[str, Any]] = []
            for item in items_raw:
                if not isinstance(item, dict):
                    raise DeclickError("SNAPSHOT_INVALID", {"field": kind})
                try:
                    start = _as_index(item["start"], "start")
                    end = _as_index(item["end"], "end")
                except (KeyError, DeclickError, TypeError) as exc:
                    raise DeclickError(
                        "SNAPSHOT_INVALID", {"field": kind}
                    ) from exc
                if start < 0 or end < start or end >= len(source_samples):
                    raise DeclickError(
                        "SNAPSHOT_INVALID", {"field": kind}
                    )
                if kind == "clicks":
                    if not isinstance(item.get("kind"), str) or not _is_number(
                        item.get("peak")
                    ):
                        raise DeclickError(
                            "SNAPSHOT_INVALID", {"field": kind}
                        )
                    decoded.append(
                        {
                            "start": start,
                            "end": end,
                            "kind": item["kind"],
                            "peak": float(item["peak"]),
                        }
                    )
                else:
                    mode = item.get("mode")
                    if mode not in {"linear", "envelope", "smooth"}:
                        raise DeclickError(
                            "SNAPSHOT_INVALID", {"field": kind}
                        )
                    decoded.append({"start": start, "end": end, "mode": mode})
            return decoded

        try:
            clicks_raw = decode_named(state["clicks"], "clicks")
            planned_raw = decode_named(
                state["planned_spans"], "planned_spans"
            )
            applied_raw = decode_named(
                state["applied_spans"], "applied_spans"
            )
        except (KeyError, TypeError) as exc:
            raise DeclickError(
                "SNAPSHOT_INVALID", {"reason": "bad ranges"}
            ) from exc

        positions_raw = state["repaired_positions"]
        if not isinstance(positions_raw, (list, tuple, set)):
            raise DeclickError(
                "SNAPSHOT_INVALID", {"field": "repaired_positions"}
            )
        repaired_positions: set[int] = set()
        for position in positions_raw:
            index = _as_index(position, "position")
            if (
                index < 0
                or index >= len(samples)
                or index in repaired_positions
            ):
                raise DeclickError(
                    "SNAPSHOT_INVALID", {"field": "repaired_positions"}
                )
            repaired_positions.add(index)

        for span in applied_raw:
            for index in range(span["start"], span["end"] + 1):
                if index not in repaired_positions:
                    raise DeclickError(
                        "SNAPSHOT_INVALID", {"field": "applied_spans"}
                    )

        residuals_raw = state["residuals"]
        if not isinstance(residuals_raw, (list, tuple)) or len(
            residuals_raw
        ) != len(applied_raw):
            raise DeclickError(
                "SNAPSHOT_INVALID", {"field": "residuals"}
            )
        residuals: list[dict[str, Any]] = []
        for record, span in zip(residuals_raw, applied_raw):
            if not isinstance(record, dict):
                raise DeclickError(
                    "SNAPSHOT_INVALID", {"field": "residuals"}
                )
            try:
                start = _as_index(record["start"], "start")
                end = _as_index(record["end"], "end")
                residual = record["residual"]
            except (KeyError, DeclickError, TypeError) as exc:
                raise DeclickError(
                    "SNAPSHOT_INVALID", {"field": "residuals"}
                ) from exc
            if (
                start != span["start"]
                or end != span["end"]
                or not _is_number(residual)
                or float(residual) < 0.0
            ):
                raise DeclickError(
                    "SNAPSHOT_INVALID", {"field": "residuals"}
                )
            residuals.append(
                {"start": start, "end": end, "residual": float(residual)}
            )

        expected_count_keys = {"clicks", "clips", "spans", "applied"}
        if not isinstance(counts, dict) or set(counts) != expected_count_keys:
            raise DeclickError("SNAPSHOT_INVALID", {"field": "counts"})
        for key in expected_count_keys:
            value = counts[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise DeclickError("SNAPSHOT_INVALID", {"field": "counts"})
        if counts["applied"] != len(repaired_positions):
            raise DeclickError(
                "SNAPSHOT_INVALID", {"field": "counts.applied"}
            )
        if counts["spans"] != len(planned_raw):
            raise DeclickError("SNAPSHOT_INVALID", {"field": "counts.spans"})
        if counts["clicks"] != sum(
            item["kind"] == "click" for item in clicks_raw
        ):
            raise DeclickError("SNAPSHOT_INVALID", {"field": "counts.clicks"})
        if counts["clips"] != sum(
            item["kind"] == "clip" for item in clicks_raw
        ):
            raise DeclickError("SNAPSHOT_INVALID", {"field": "counts.clips"})

        return {
            "threshold": threshold,
            "sample_rate": sample_rate,
            "max_repair_len": max_repair_len,
            "max_points_per_block": max_points_per_block,
            "merge_gap": merge_gap,
            "residual_limit": residual_limit,
            "block_lengths": block_lengths,
            "source_samples": source_samples,
            "samples": samples,
            "clicks": [Click(**item) for item in clicks_raw],
            "planned_spans": [RepairSpan(**item) for item in planned_raw],
            "applied_spans": [
                (item["start"], item["end"], item["mode"])
                for item in applied_raw
            ],
            "repaired_positions": repaired_positions,
            "residuals": residuals,
            "counts": dict(counts),
        }

    def restore(self, state: Any) -> None:
        with self._lock:
            try:
                decoded = self._decode_snapshot(state)
            except DeclickError as exc:
                if exc.code == "SNAPSHOT_INVALID":
                    raise
                raise DeclickError(
                    "SNAPSHOT_INVALID", {"cause": exc.code}
                ) from exc
            except Exception as exc:
                raise DeclickError(
                    "SNAPSHOT_INVALID", {"reason": "invalid state"}
                ) from exc
            self.threshold = decoded["threshold"]
            self.sample_rate = decoded["sample_rate"]
            self.max_repair_len = decoded["max_repair_len"]
            self.max_points_per_block = decoded["max_points_per_block"]
            self.merge_gap = decoded["merge_gap"]
            self.residual_limit = decoded["residual_limit"]
            self._block_lengths = decoded["block_lengths"]
            self._source_samples = decoded["source_samples"]
            self._samples = decoded["samples"]
            self._clicks = decoded["clicks"]
            self._planned_spans = decoded["planned_spans"]
            self._applied_spans = decoded["applied_spans"]
            self._repaired_positions = decoded["repaired_positions"]
            self._residuals = decoded["residuals"]
            self._counts = decoded["counts"]
