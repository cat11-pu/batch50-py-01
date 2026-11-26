"""Text run shaper: font fallback, grapheme clusters, line layout and cache."""

from __future__ import annotations

import copy
import hashlib
import json
import math
import numbers
import operator
import threading
import unicodedata
from collections import OrderedDict
from collections.abc import Mapping

__all__ = [
    "TextShapeError",
    "TextRunShaper",
    "ELLIPSIS",
]

ELLIPSIS = "…"
SNAPSHOT_SCHEMA = 1
_MISSING_ADVANCE_EM = 0.5
_FLOAT_EPS = 1e-9


class TextShapeError(ValueError):
    """Raised when a shaping, layout or snapshot request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _invalid_request(detail: object = None) -> TextShapeError:
    return TextShapeError("TEXT_INVALID_REQUEST", detail)


def _unknown_font(font_id: object = None) -> TextShapeError:
    return TextShapeError("TEXT_UNKNOWN_FONT", font_id)


def _snapshot_invalid(detail: object = None) -> TextShapeError:
    return TextShapeError("TEXT_SNAPSHOT_INVALID", detail)


def _limit_exceeded(detail: object = None) -> TextShapeError:
    return TextShapeError("TEXT_RUN_LIMIT_EXCEEDED", detail)


def _positive_float(value: object, name: str) -> float:
    if (
        isinstance(value, bool)
        or not isinstance(value, numbers.Real)
        or not math.isfinite(float(value))
        or float(value) <= 0.0
    ):
        raise _invalid_request(f"{name} must be a positive finite number")
    return float(value)


def _non_negative_int(value: object, name: str) -> int:
    if isinstance(value, bool):
        raise _invalid_request(f"{name} must be a non-negative integer")
    try:
        result = operator.index(value)  # type: ignore[arg-type]
    except TypeError as exc:
        raise _invalid_request(f"{name} must be a non-negative integer") from exc
    if result < 0:
        raise _invalid_request(f"{name} must be a non-negative integer")
    return result


def _valid_font_id(font_id: object) -> bool:
    return isinstance(font_id, str) and bool(font_id)


def _normalize_features(features: object) -> tuple[str, ...]:
    if isinstance(features, str):
        items = (features,)
    elif isinstance(features, (bytes, bytearray)):
        raise _invalid_request("features must be a sequence of feature tags")
    elif not isinstance(features, (tuple, list)):
        try:
            items = tuple(features)  # type: ignore[arg-type]
        except TypeError as exc:
            raise _invalid_request("features must be a sequence") from exc
    else:
        items = tuple(features)
    for feature in items:
        if not isinstance(feature, str) or not feature:
            raise _invalid_request("features must contain non-empty strings")
    return tuple(items)


def _is_variation_selector(code_point: int) -> bool:
    return 0xFE00 <= code_point <= 0xFE0F or 0xE0100 <= code_point <= 0xE01EF


def _is_regional_indicator(code_point: int) -> bool:
    return 0x1F1E6 <= code_point <= 0x1F1FF


def _is_skin_tone_modifier(code_point: int) -> bool:
    return 0x1F3FB <= code_point <= 0x1F3FF


def grapheme_clusters(text: str) -> tuple[str, ...]:
    """Split text without separating marks, variation selectors or ZWJ joins."""
    clusters: list[str] = []
    index = 0
    length = len(text)

    while index < length:
        start = index
        index += 1

        if start + 1 < length:
            first = ord(text[start])
            second = ord(text[start + 1])
            if _is_regional_indicator(first) and _is_regional_indicator(second):
                index = start + 2

        while index < length:
            code_point = ord(text[index])
            category = unicodedata.category(text[index])

            if category[0] == "M" or _is_variation_selector(code_point):
                index += 1
            elif _is_skin_tone_modifier(code_point):
                index += 1
            elif code_point == 0x200D:
                index += 1
                if index < length:
                    index += 1
            else:
                break

        clusters.append(text[start:index])

    return tuple(clusters)


class _Cluster:
    __slots__ = ("text", "font_id", "advance")

    def __init__(self, text: str, font_id: str | None, advance: float) -> None:
        self.text = text
        self.font_id = font_id
        self.advance = advance


class TextRunShaper:
    """Shape text through registered fonts and lay it out into lines."""

    def __init__(
        self, *, max_runs: int = 64, max_cache_entries: int = 128
    ) -> None:
        self.max_runs = _non_negative_int(max_runs, "max_runs")
        self.max_cache_entries = _non_negative_int(
            max_cache_entries, "max_cache_entries"
        )
        self._lock = threading.RLock()
        self._fonts: dict[str, dict] = {}
        self._history: dict[str, list[dict]] = {}
        self._cache: OrderedDict[str, dict] = OrderedDict()
        self._font_versions = 0
        self._layouts = 0
        self._cache_hits = 0
        self._cache_invalidations = 0

    def register_font(
        self, font_id: str, *, glyphs, version: int = 1, fallbacks=()
    ) -> int:
        if not _valid_font_id(font_id):
            raise _invalid_request("font_id must be a non-empty string")
        clean_glyphs = self._validate_glyphs(glyphs)
        version_value = _non_negative_int(version, "version")
        if version_value <= 0:
            raise _invalid_request("version must be a positive integer")
        fallback_ids = self._validate_fallback_argument(fallbacks)

        with self._lock:
            for fallback_id in fallback_ids:
                if fallback_id not in self._fonts:
                    raise _invalid_request(
                        f"fallback font is not registered: {fallback_id!r}"
                    )

            existing = self._fonts.get(font_id)
            if existing is not None and version_value == existing["version"]:
                raise TextShapeError(
                    "TEXT_FONT_VERSION_CONFLICT",
                    {"font_id": font_id, "version": version_value},
                )
            if existing is not None:
                known_versions = {
                    item["version"] for item in self._history.get(font_id, [])
                }
                known_versions.add(existing["version"])
                if version_value in known_versions:
                    raise TextShapeError(
                        "TEXT_FONT_VERSION_CONFLICT",
                        {"font_id": font_id, "version": version_value},
                    )
                self._history.setdefault(font_id, []).append(
                    copy.deepcopy(existing)
                )

            self._fonts[font_id] = {
                "font_id": font_id,
                "version": version_value,
                "glyphs": clean_glyphs,
                "fallbacks": fallback_ids,
            }
            self._history.setdefault(font_id, [])
            self._font_versions += 1
            self._invalidate_font_locked(font_id, count_stat=True)
            return version_value

    @staticmethod
    def _validate_glyphs(glyphs: object) -> dict[str, float]:
        if not isinstance(glyphs, Mapping) or len(glyphs) == 0:
            raise _invalid_request("glyphs must be a non-empty mapping")

        clean: dict[str, float] = {}
        for raw_key, raw_advance in glyphs.items():
            if isinstance(raw_key, int) and not isinstance(raw_key, bool):
                try:
                    key = chr(raw_key)
                except (ValueError, OverflowError) as exc:
                    raise _invalid_request("glyph key is not a code point") from exc
            elif isinstance(raw_key, str) and raw_key:
                key = raw_key
            else:
                raise _invalid_request(
                    "glyph keys must be characters or code points"
                )

            advance = _positive_float(raw_advance, "glyph advance")
            clean[key] = advance
        return clean

    @staticmethod
    def _validate_fallback_argument(fallbacks: object) -> tuple[str, ...]:
        if isinstance(fallbacks, (str, bytes, bytearray)):
            raise _invalid_request("fallbacks must be a sequence of font ids")
        if not isinstance(fallbacks, (tuple, list)):
            try:
                items = tuple(fallbacks)
            except TypeError as exc:
                raise _invalid_request(
                    "fallbacks must be a sequence of font ids"
                ) from exc
        else:
            items = tuple(fallbacks)

        result: list[str] = []
        for fallback_id in items:
            if not _valid_font_id(fallback_id):
                raise _invalid_request(
                    "fallback font ids must be non-empty strings"
                )
            result.append(fallback_id)
        return tuple(result)

    def rollback_font(self, font_id: str) -> int:
        with self._lock:
            self._require_font_locked(font_id)
            history = self._history.setdefault(font_id, [])
            if history:
                previous = history.pop()
                self._fonts[font_id] = copy.deepcopy(previous)
            version = self._fonts[font_id]["version"]
            self._invalidate_font_locked(font_id, count_stat=True)
            return version

    def font_info(self, font_id: str) -> dict:
        with self._lock:
            font = self._require_font_locked(font_id)
            return {
                "font_id": font["font_id"],
                "version": font["version"],
                "glyph_count": len(font["glyphs"]),
                "fallbacks": tuple(font["fallbacks"]),
            }

    def _require_font_locked(self, font_id: object) -> dict:
        if not _valid_font_id(font_id):
            raise _invalid_request("font_id must be a non-empty string")
        font = self._fonts.get(font_id)
        if font is None:
            raise _unknown_font(font_id)
        return font

    def _font_chain_locked(self, font_id: str) -> tuple[str, ...]:
        chain: list[str] = []
        seen: set[str] = set()
        pending = [font_id]

        while pending:
            current_id = pending.pop(0)
            if current_id in seen:
                continue
            current = self._fonts.get(current_id)
            if current is None:
                continue
            seen.add(current_id)
            chain.append(current_id)
            pending.extend(current["fallbacks"])

        return tuple(chain)

    @staticmethod
    def _font_covers_cluster(font: dict, cluster: str) -> bool:
        glyphs = font["glyphs"]
        return all(char in glyphs for char in cluster)

    def _select_cluster_locked(
        self, font_id: str, cluster: str
    ) -> tuple[str | None, float]:
        for candidate_id in self._font_chain_locked(font_id):
            candidate = self._fonts[candidate_id]
            if self._font_covers_cluster(candidate, cluster):
                advance = sum(
                    float(candidate["glyphs"][char]) for char in cluster
                )
                return candidate_id, advance
        for placeholder in ("\ufffd", "□"):
            for candidate_id in self._font_chain_locked(font_id):
                candidate = self._fonts[candidate_id]
                if placeholder in candidate["glyphs"]:
                    return None, float(candidate["glyphs"][placeholder])
        return None, _MISSING_ADVANCE_EM

    def resolve_fallback(self, font_id: str, text: str) -> dict:
        if not isinstance(text, str):
            raise _invalid_request("text must be a string")
        with self._lock:
            self._require_font_locked(font_id)
            chains: list[tuple[str, str | None]] = []
            missing: list[str] = []
            for cluster in grapheme_clusters(text):
                selected, _ = self._select_cluster_locked(font_id, cluster)
                chains.append((cluster, selected))
                if selected is None:
                    missing.append(cluster)
            return {
                "font_id": font_id,
                "chains": tuple(chains),
                "missing": tuple(missing),
            }

    def _shape_records_locked(
        self, text: str, font_id: str, size: float
    ) -> list[_Cluster]:
        records: list[_Cluster] = []
        run_count = 0
        previous_font: object = object()

        for cluster in grapheme_clusters(text):
            selected_font, advance_em = self._select_cluster_locked(
                font_id, cluster
            )
            if selected_font != previous_font:
                run_count += 1
                previous_font = selected_font
            records.append(_Cluster(cluster, selected_font, advance_em * size))

        if run_count > self.max_runs:
            raise _limit_exceeded(
                {"runs": run_count, "max_runs": self.max_runs}
            )
        return records

    def shape_run(
        self,
        text: str,
        *,
        font_id: str,
        size: float = 16.0,
        features=(),
    ) -> dict:
        if not isinstance(text, str):
            raise _invalid_request("text must be a string")
        size_value = _positive_float(size, "size")
        feature_tuple = _normalize_features(features)

        with self._lock:
            self._require_font_locked(font_id)
            records = self._shape_records_locked(text, font_id, size_value)
            return {
                "text": text,
                "font_id": font_id,
                "size": size_value,
                "features": feature_tuple,
                "clusters": tuple(item.text for item in records),
                "fonts": tuple(item.font_id for item in records),
                "advances": tuple(item.advance for item in records),
                "width": sum((item.advance for item in records), 0.0),
            }

    @staticmethod
    def _trim_trailing_space_records(
        records: list[_Cluster],
    ) -> list[_Cluster]:
        end = len(records)
        while end > 0 and records[end - 1].text == " ":
            end -= 1
        return records[:end]

    @staticmethod
    def _records_width(records: list[_Cluster]) -> float:
        return sum((record.advance for record in records), 0.0)

    def _wrap_paragraph_locked(
        self, records: list[_Cluster], max_width: float
    ) -> list[list[_Cluster]]:
        if not records:
            return [[]]

        lines: list[list[_Cluster]] = []
        current: list[_Cluster] = []
        width = 0.0
        index = 0

        while index < len(records):
            record = records[index]
            fits = width + record.advance <= max_width + _FLOAT_EPS

            if not current or fits:
                current.append(record)
                width += record.advance
                index += 1
                continue

            if record.text == " ":
                lines.append(self._trim_trailing_space_records(current))
                current = []
                width = 0.0
                index += 1
                continue

            space_index = None
            for candidate_index in range(len(current) - 1, -1, -1):
                if current[candidate_index].text == " ":
                    space_index = candidate_index
                    break

            if space_index is not None:
                head = self._trim_trailing_space_records(
                    current[:space_index]
                )
                if head:
                    lines.append(head)

                pending = current[space_index + 1 :] + [record]
                current = []
                width = 0.0
                for pending_record in pending:
                    if (
                        not current
                        or width + pending_record.advance
                        <= max_width + _FLOAT_EPS
                    ):
                        current.append(pending_record)
                        width += pending_record.advance
                    else:
                        lines.append(current)
                        current = [pending_record]
                        width = pending_record.advance
                index += 1
            else:
                lines.append(current)
                current = []
                width = 0.0

        if current or not lines:
            lines.append(current)
        return lines

    def _ellipsis_width_locked(self, font_id: str, size: float) -> float:
        font = self._require_font_locked(font_id)
        advance = font["glyphs"].get(ELLIPSIS)
        if advance is None:
            selected, fallback_advance = self._select_cluster_locked(
                font_id, ELLIPSIS
            )
            if selected is None:
                advance = _MISSING_ADVANCE_EM
            else:
                advance = fallback_advance
        return float(advance) * size

    @staticmethod
    def _line_dict(
        records: list[_Cluster],
        *,
        ellipsis: bool = False,
        append_ellipsis: bool = False,
        ellipsis_width: float = 0.0,
    ) -> dict:
        records = TextRunShaper._trim_trailing_space_records(records)
        text = "".join(record.text for record in records)
        width = TextRunShaper._records_width(records)
        if append_ellipsis:
            text += ELLIPSIS
            width += ellipsis_width
        return {"text": text, "width": width, "ellipsis": ellipsis}

    def break_lines(
        self,
        text: str,
        *,
        font_id: str,
        size: float = 16.0,
        max_width,
        max_lines: int = 0,
    ) -> tuple[dict, ...]:
        if not isinstance(text, str):
            raise _invalid_request("text must be a string")
        size_value = _positive_float(size, "size")
        width_value = _positive_float(max_width, "max_width")
        line_limit = _non_negative_int(max_lines, "max_lines")

        with self._lock:
            self._require_font_locked(font_id)
            paragraphs = (
                text.replace("\r\n", "\n")
                .replace("\r", "\n")
                .split("\n")
            )
            wrapped: list[tuple[list[_Cluster], int]] = []

            for paragraph_index, paragraph in enumerate(paragraphs):
                records = self._shape_records_locked(
                    paragraph, font_id, size_value
                )
                for line_records in self._wrap_paragraph_locked(
                    records, width_value
                ):
                    wrapped.append((line_records, paragraph_index))

            has_clipped_content = any(
                any(record.text != " " for record in records)
                for records, _ in wrapped[line_limit:]
            )
            if (
                line_limit > 0
                and len(wrapped) > line_limit
                and has_clipped_content
            ):
                target_records, paragraph_index = wrapped[line_limit - 1]
                ellipsis_width = self._ellipsis_width_locked(
                    font_id, size_value
                )
                available_width = width_value - ellipsis_width
                truncated: list[_Cluster] = []
                truncated_width = 0.0
                for record in target_records:
                    if (
                        truncated_width + record.advance
                        <= available_width + _FLOAT_EPS
                    ):
                        truncated.append(record)
                        truncated_width += record.advance
                    else:
                        break

                lines = [
                    self._line_dict(records)
                    for records, _ in wrapped[: line_limit - 1]
                ]
                lines.append(
                    self._line_dict(
                        truncated,
                        ellipsis=True,
                        append_ellipsis=True,
                        ellipsis_width=ellipsis_width,
                    )
                )

                # Explicit blank lines after the clamp still occupy slots.
                # Ordinary separators before clipped content do not create an
                # additional blank line.
                for later_records, _ in wrapped[line_limit:]:
                    if not self._trim_trailing_space_records(later_records):
                        lines.append(
                            {"text": "", "width": 0.0, "ellipsis": False}
                        )
                return tuple(lines)

            return tuple(self._line_dict(records) for records, _ in wrapped)

    def cache_key(
        self,
        text: str,
        *,
        font_id: str,
        size: float,
        max_width: float,
        max_lines: int = 0,
        features=(),
    ) -> str:
        if not isinstance(text, str):
            raise _invalid_request("text must be a string")
        if not _valid_font_id(font_id):
            raise _invalid_request("font_id must be a non-empty string")
        size_value = _positive_float(size, "size")
        width_value = _positive_float(max_width, "max_width")
        line_limit = _non_negative_int(max_lines, "max_lines")
        feature_tuple = _normalize_features(features)
        payload = [
            SNAPSHOT_SCHEMA,
            text,
            font_id,
            size_value,
            width_value,
            line_limit,
            list(feature_tuple),
        ]
        encoded = json.dumps(
            payload, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8")
        return "text-layout-v1:" + hashlib.sha256(encoded).hexdigest()

    def layout(
        self,
        text: str,
        *,
        font_id: str,
        size: float = 16.0,
        max_width,
        max_lines: int = 0,
        features=(),
    ) -> dict:
        if not isinstance(text, str):
            raise _invalid_request("text must be a string")
        size_value = _positive_float(size, "size")
        width_value = _positive_float(max_width, "max_width")
        line_limit = _non_negative_int(max_lines, "max_lines")
        feature_tuple = _normalize_features(features)
        key = self.cache_key(
            text,
            font_id=font_id,
            size=size_value,
            max_width=width_value,
            max_lines=line_limit,
            features=feature_tuple,
        )

        with self._lock:
            self._require_font_locked(font_id)
            cached = self._cache.get(key)
            if cached is not None:
                self._cache.move_to_end(key)
                self._cache_hits += 1
                result = copy.deepcopy(cached)
                result["cached"] = True
                return result

            lines = self.break_lines(
                text,
                font_id=font_id,
                size=size_value,
                max_width=width_value,
                max_lines=line_limit,
            )
            result = {
                "text": text,
                "font_id": font_id,
                "size": size_value,
                "max_width": width_value,
                "max_lines": line_limit,
                "features": feature_tuple,
                "lines": lines,
                "width": max(
                    (line["width"] for line in lines), default=0.0
                ),
                "cache_key": key,
                "cached": False,
            }

            self._layouts += 1
            stored = copy.deepcopy(result)
            stored["cached"] = False
            self._cache[key] = stored
            self._cache.move_to_end(key)
            while len(self._cache) > self.max_cache_entries:
                self._cache.popitem(last=False)
            return result

    def _invalidate_font_locked(
        self, font_id: str | None, *, count_stat: bool
    ) -> int:
        if font_id is None:
            removed = len(self._cache)
            self._cache.clear()
        else:
            affected_fonts = {font_id}
            for candidate_id in self._fonts:
                if font_id in self._font_chain_locked(candidate_id):
                    affected_fonts.add(candidate_id)
            keys = [
                key
                for key, value in self._cache.items()
                if value.get("font_id") in affected_fonts
            ]
            removed = len(keys)
            for key in keys:
                del self._cache[key]
        if count_stat:
            self._cache_invalidations += removed
        return removed

    def invalidate_cache(self, font_id: str | None = None) -> int:
        with self._lock:
            if font_id is not None:
                self._require_font_locked(font_id)
            return self._invalidate_font_locked(font_id, count_stat=True)

    def fonts(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(sorted(self._fonts))

    def stats(self) -> dict:
        with self._lock:
            return {
                "fonts": len(self._fonts),
                "font_versions": self._font_versions,
                "layouts": self._layouts,
                "cache_hits": self._cache_hits,
                "cache_invalidations": self._cache_invalidations,
            }

    def snapshot(self) -> dict:
        with self._lock:
            fonts = {}
            for font_id, font in self._fonts.items():
                font_snapshot = copy.deepcopy(font)
                font_snapshot["history"] = copy.deepcopy(
                    self._history.get(font_id, [])
                )
                fonts[font_id] = font_snapshot
            state = {
                "schema": SNAPSHOT_SCHEMA,
                "fonts": fonts,
                "cache": copy.deepcopy(self._cache),
                "stats": self.stats(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        try:
            parsed = self._parse_snapshot(state)
        except TextShapeError:
            raise
        except Exception as exc:
            raise _snapshot_invalid("snapshot structure is invalid") from exc
        with self._lock:
            (
                fonts,
                history,
                cache,
                font_versions,
                layouts,
                cache_hits,
                cache_invalidations,
            ) = parsed
            self._fonts = fonts
            self._history = history
            self._cache = cache
            self._font_versions = font_versions
            self._layouts = layouts
            self._cache_hits = cache_hits
            self._cache_invalidations = cache_invalidations
            while len(self._cache) > self.max_cache_entries:
                self._cache.popitem(last=False)

    def _parse_snapshot(self, state: object):
        if not isinstance(state, Mapping):
            raise _snapshot_invalid("snapshot must be a mapping")
        if set(state.keys()) != {"schema", "fonts", "cache", "stats"}:
            raise _snapshot_invalid("snapshot has invalid top-level keys")
        if state.get("schema") != SNAPSHOT_SCHEMA:
            raise _snapshot_invalid("unsupported snapshot schema")

        try:
            frozen = copy.deepcopy(state)
        except Exception as exc:
            raise _snapshot_invalid("snapshot is not detachable") from exc

        raw_fonts = frozen["fonts"]
        if not isinstance(raw_fonts, Mapping):
            raise _snapshot_invalid("fonts must be a mapping")

        fonts: dict[str, dict] = {}
        history: dict[str, list[dict]] = {}
        for font_id, raw_font in raw_fonts.items():
            font_id_value, font_record, font_history = (
                self._parse_font_snapshot(font_id, raw_font)
            )
            fonts[font_id_value] = font_record
            history[font_id_value] = font_history

        for font_record in list(fonts.values()) + [
            item for items in history.values() for item in items
        ]:
            for fallback_id in font_record["fallbacks"]:
                if fallback_id not in fonts:
                    raise _snapshot_invalid(
                        f"unknown fallback font {fallback_id!r}"
                    )

        raw_cache = frozen["cache"]
        if not isinstance(raw_cache, Mapping):
            raise _snapshot_invalid("cache must be a mapping")

        cache: OrderedDict[str, dict] = OrderedDict()
        for cache_key, raw_result in raw_cache.items():
            if not isinstance(cache_key, str):
                raise _snapshot_invalid("cache keys must be strings")
            result = self._parse_cached_result(cache_key, raw_result)
            if result["font_id"] not in fonts:
                raise _snapshot_invalid("cache references an unknown font")
            cache[cache_key] = result

        raw_stats = frozen["stats"]
        if not isinstance(raw_stats, Mapping):
            raise _snapshot_invalid("stats must be a mapping")
        stats_values = []
        for key in (
            "fonts",
            "font_versions",
            "layouts",
            "cache_hits",
            "cache_invalidations",
        ):
            value = raw_stats.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise _snapshot_invalid(
                    f"stats.{key} must be a non-negative integer"
                )
            stats_values.append(value)

        if stats_values[0] != len(fonts):
            raise _snapshot_invalid("stats.fonts does not match fonts")

        return (
            fonts,
            history,
            cache,
            stats_values[1],
            stats_values[2],
            stats_values[3],
            stats_values[4],
        )

    def _parse_font_snapshot(
        self, raw_font_id: object, raw_font: object
    ) -> tuple[str, dict, list[dict]]:
        if not _valid_font_id(raw_font_id):
            raise _snapshot_invalid("font id must be a non-empty string")
        if not isinstance(raw_font, Mapping):
            raise _snapshot_invalid(f"font {raw_font_id!r} must be a mapping")
        if "font_id" in raw_font and raw_font["font_id"] != raw_font_id:
            raise _snapshot_invalid("font_id mismatch")

        version = raw_font.get("version")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise _snapshot_invalid("font version must be a positive integer")

        try:
            glyphs = self._validate_glyphs(raw_font.get("glyphs"))
            fallbacks = self._validate_fallback_argument(
                raw_font.get("fallbacks", ())
            )
        except TextShapeError as exc:
            raise _snapshot_invalid(exc.detail or exc.code) from exc

        record = {
            "font_id": raw_font_id,
            "version": version,
            "glyphs": glyphs,
            "fallbacks": fallbacks,
        }

        raw_history = raw_font.get("history", ())
        if not isinstance(raw_history, (list, tuple)):
            raise _snapshot_invalid("font history must be a list")
        history: list[dict] = []
        for raw_item in raw_history:
            _, item, _ = self._parse_font_snapshot(raw_font_id, raw_item)
            history.append(item)

        return raw_font_id, record, history

    def _parse_cached_result(
        self, expected_key: str, raw_result: object
    ) -> dict:
        if not isinstance(raw_result, Mapping):
            raise _snapshot_invalid("cached layout must be a mapping")

        text = raw_result.get("text")
        font_id = raw_result.get("font_id")
        if not isinstance(text, str) or not _valid_font_id(font_id):
            raise _snapshot_invalid("cached layout identity is invalid")

        try:
            size = _positive_float(raw_result.get("size"), "size")
            max_width = _positive_float(
                raw_result.get("max_width"), "max_width"
            )
            max_lines = _non_negative_int(
                raw_result.get("max_lines"), "max_lines"
            )
            features = _normalize_features(raw_result.get("features", ()))
        except TextShapeError as exc:
            raise _snapshot_invalid(exc.detail or exc.code) from exc

        raw_lines = raw_result.get("lines")
        if not isinstance(raw_lines, (list, tuple)):
            raise _snapshot_invalid("cached lines must be a list")

        lines: list[dict] = []
        width = 0.0
        for raw_line in raw_lines:
            if not isinstance(raw_line, Mapping):
                raise _snapshot_invalid("cached line must be a mapping")
            if set(raw_line.keys()) != {"text", "width", "ellipsis"}:
                raise _snapshot_invalid("cached line has invalid keys")
            line_text = raw_line.get("text")
            line_width = raw_line.get("width")
            ellipsis = raw_line.get("ellipsis")
            if not isinstance(line_text, str):
                raise _snapshot_invalid("cached line text must be a string")
            if (
                isinstance(line_width, bool)
                or not isinstance(line_width, numbers.Real)
                or not math.isfinite(float(line_width))
                or float(line_width) < 0.0
            ):
                raise _snapshot_invalid(
                    "cached line width must be non-negative"
                )
            if not isinstance(ellipsis, bool):
                raise _snapshot_invalid(
                    "cached ellipsis flag must be boolean"
                )
            line = {
                "text": line_text,
                "width": float(line_width),
                "ellipsis": ellipsis,
            }
            lines.append(line)
            width = max(width, line["width"])

        cache_key = raw_result.get("cache_key")
        if not isinstance(cache_key, str) or cache_key != expected_key:
            raise _snapshot_invalid("cached layout key mismatch")

        expected_cache_key = self.cache_key(
            text,
            font_id=font_id,
            size=size,
            max_width=max_width,
            max_lines=max_lines,
            features=features,
        )
        if cache_key != expected_cache_key:
            raise _snapshot_invalid(
                "cached layout parameters do not match key"
            )

        result_width = raw_result.get("width", width)
        if (
            isinstance(result_width, bool)
            or not isinstance(result_width, numbers.Real)
            or not math.isfinite(float(result_width))
            or float(result_width) < 0.0
        ):
            raise _snapshot_invalid("cached layout width must be non-negative")

        return {
            "text": text,
            "font_id": font_id,
            "size": size,
            "max_width": max_width,
            "max_lines": max_lines,
            "features": features,
            "lines": tuple(lines),
            "width": float(result_width),
            "cache_key": cache_key,
            "cached": False,
        }
