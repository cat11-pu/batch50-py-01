"""Lightmap bake scheduling: page slot allocation, priority dispatch, resumable progress."""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "LightmapError",
    "PageAllocation",
    "LightmapBakeScheduler",
    "SLOT_TEXELS",
    "JOB_STATUSES",
]

SLOT_TEXELS = 512
JOB_STATUSES = ("queued", "running", "done", "canceled", "failed")


class LightmapError(ValueError):
    """Raised when a lightmap bake scheduling request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class PageAllocation:
    """One job's placement: page index plus the slots it owns on that page."""

    page: int
    slots: tuple[int, ...]
    slot_texels: int = SLOT_TEXELS


class LightmapBakeScheduler:
    """Allocate lightmap pages, dispatch bake jobs, and track per-page progress."""

    def __init__(self, *, page_slots: int = 4, max_pages: int = 8,
                 max_workers: int = 2) -> None:
        self.page_slots = page_slots
        self.max_pages = max_pages
        self.max_workers = max_workers
        self._lock = threading.RLock()

    def submit_job(self, object_id: str, *, texel_density, bounds,
                   priority: int = 0) -> str:
        raise NotImplementedError

    def allocate_page(self, job_id: str) -> PageAllocation:
        raise NotImplementedError

    def start_job(self, job_id: str, *, worker: str) -> None:
        raise NotImplementedError

    def dispatch(self, worker: str) -> str | None:
        raise NotImplementedError

    def report_progress(self, job_id: str, *, page_index: int, progress,
                        digest=None) -> None:
        raise NotImplementedError

    def cancel_job(self, job_id: str) -> bool:
        raise NotImplementedError

    def resume(self, job_id: str) -> None:
        raise NotImplementedError

    def fail_job(self, job_id: str, *, reason: str) -> None:
        raise NotImplementedError

    def release_worker(self, worker: str) -> None:
        raise NotImplementedError

    def job_state(self, job_id: str) -> dict:
        raise NotImplementedError

    def pages_of(self, object_id: str) -> tuple[PageAllocation, ...]:
        raise NotImplementedError

    def pending_jobs(self) -> tuple[str, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
