"""Text run shaper: font fallback chains, glyph runs, line breaking and ellipsis."""

from __future__ import annotations

import threading

__all__ = [
    "TextShapeError",
    "TextRunShaper",
    "ELLIPSIS",
]

ELLIPSIS = "\u2026"


class TextShapeError(ValueError):
    """Raised when a shaping or layout request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class TextRunShaper:
    """Shape styled text into glyph runs and lay it out into lines."""

    def __init__(self, *, max_runs: int = 64,
                 max_cache_entries: int = 128) -> None:
        self.max_runs = max_runs
        self.max_cache_entries = max_cache_entries
        self._lock = threading.RLock()

    def register_font(self, font_id: str, *, glyphs, version: int = 1,
                      fallbacks=()) -> int:
        raise NotImplementedError

    def rollback_font(self, font_id: str) -> int:
        raise NotImplementedError

    def font_info(self, font_id: str) -> dict:
        raise NotImplementedError

    def resolve_fallback(self, font_id: str, text: str) -> dict:
        raise NotImplementedError

    def shape_run(self, text: str, *, font_id: str, size: float = 16.0,
                  features=()) -> dict:
        raise NotImplementedError

    def break_lines(self, text: str, *, font_id: str, size: float = 16.0,
                    max_width: float, max_lines: int = 0) -> tuple[dict, ...]:
        raise NotImplementedError

    def layout(self, text: str, *, font_id: str, size: float = 16.0,
               max_width: float, max_lines: int = 0,
               features=()) -> dict:
        raise NotImplementedError

    def cache_key(self, text: str, *, font_id: str, size: float,
                  max_width: float, max_lines: int = 0,
                  features=()) -> str:
        raise NotImplementedError

    def invalidate_cache(self, font_id: str | None = None) -> int:
        raise NotImplementedError

    def fonts(self) -> tuple[str, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
