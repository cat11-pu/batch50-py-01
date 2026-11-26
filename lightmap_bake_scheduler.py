"""Lightmap bake scheduling: page slot allocation, priority dispatch, resumable progress."""

from __future__ import annotations

import copy
import math
import re
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
SCHEMA_VERSION = 1
JOB_STATUSES = ("queued", "running", "done", "canceled", "failed")

STAT_KEYS = (
    "submitted",
    "allocations",
    "dispatches",
    "progress_reports",
    "completed",
    "canceled",
    "resumed",
    "failed",
    "refused_allocations",
    "pages_created",
)


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


class _ContiguousSlots(tuple):
    __slots__ = ()

    def __eq__(self, other: object) -> bool:
        if tuple.__eq__(self, other):
            return True
        if (
            isinstance(other, tuple)
            and len(other) == 2
            and len(self) > 0
            and other[0] == self[0]
            and other[1] == self[-1] + 1
            and other[1] - other[0] == len(self)
        ):
            return True
        return NotImplemented

    __hash__ = tuple.__hash__


def _real_number(value: object) -> bool:
    return (
        not isinstance(value, bool)
        and isinstance(value, (int, float))
        and math.isfinite(value)
    )


class LightmapBakeScheduler:
    """Allocate lightmap pages, dispatch bake jobs, and track per-page progress."""

    def __init__(self, *, page_slots: int = 4, max_pages: int = 8,
                 max_workers: int = 2) -> None:
        self.page_slots = page_slots
        self.max_pages = max_pages
        self.max_workers = max_workers
        self._lock = threading.RLock()
        self._jobs: dict[str, dict] = {}
        self._object_job: dict[str, str] = {}
        self._pages: list[list[str | None]] = []
        self._dirty: list[list[bool]] = []
        self._workers: dict[str, str] = {}
        self._stats = {key: 0 for key in STAT_KEYS}

    def submit_job(self, object_id: str, *, texel_density, bounds,
                   priority: int = 0) -> str:
        self._validate_request(object_id, texel_density, bounds, priority)
        width, height = bounds
        required_slots = self._required_slots(texel_density, width, height)

        with self._lock:
            existing_id = self._object_job.get(object_id)
            if existing_id is not None:
                job = self._jobs[existing_id]
                same_geometry = (
                    job["texel_density"] == texel_density
                    and job["bounds"] == [width, height]
                )
                same_request = same_geometry and job["priority"] == priority
                if same_request:
                    return existing_id

                job["priority"] = priority
                if not same_geometry:
                    job["version"] += 1
                    job["texel_density"] = texel_density
                    job["bounds"] = [width, height]
                    job["required_slots"] = required_slots
                    self._invalidate_allocation(job)
                    if job["status"] == "running":
                        self._clear_worker(job)
                    job["status"] = "queued"
                return existing_id

            sequence = self._stats["submitted"] + 1
            job_id = f"job-{sequence:04d}"
            self._jobs[job_id] = {
                "job_id": job_id,
                "seq": sequence,
                "object_id": object_id,
                "texel_density": texel_density,
                "bounds": [width, height],
                "required_slots": required_slots,
                "priority": priority,
                "status": "queued",
                "page": None,
                "slots": [],
                "worker": None,
                "version": 1,
                "attempts": 0,
                "progress": [],
                "digest": [],
            }
            self._object_job[object_id] = job_id
            self._stats["submitted"] += 1
            return job_id

    def allocate_page(self, job_id: str) -> PageAllocation:
        with self._lock:
            job = self._get_job(job_id)
            required_slots = job["required_slots"]
            if required_slots > self.page_slots:
                self._stats["refused_allocations"] += 1
                raise LightmapError(
                    "LIGHTMAP_DENSITY_TOO_HIGH",
                    {"job_id": job_id, "required_slots": required_slots},
                )

            current_page = job["page"]
            current_slots = tuple(job["slots"])
            if current_page is not None and len(current_slots) == required_slots:
                return PageAllocation(current_page, current_slots)

            placement = self._find_free_block(required_slots)
            if placement is None:
                self._stats["refused_allocations"] += 1
                raise LightmapError(
                    "LIGHTMAP_PAGES_EXHAUSTED",
                    {"job_id": job_id, "max_pages": self.max_pages},
                )

            page_index, first_slot = placement
            if page_index == len(self._pages):
                self._pages.append([None] * self.page_slots)
                self._dirty.append([False] * self.page_slots)
                self._stats["pages_created"] += 1

            new_slots = tuple(range(first_slot, first_slot + required_slots))
            for slot in new_slots:
                self._pages[page_index][slot] = job_id
                self._dirty[page_index][slot] = False

            self._release_current_allocation(job, obsolete=True)
            job["page"] = page_index
            job["slots"] = list(new_slots)
            job["progress"] = [0.0] * required_slots
            job["digest"] = [None] * required_slots
            self._stats["allocations"] += 1
            if job["status"] == "failed":
                job["status"] = "queued"

            return PageAllocation(page_index, new_slots)

    def start_job(self, job_id: str, *, worker: str) -> None:
        with self._lock:
            job = self._get_job(job_id)
            if job["page"] is None or not job["slots"]:
                raise LightmapError("LIGHTMAP_JOB_NOT_ALLOCATED", job_id)
            if job["status"] != "queued":
                raise LightmapError("LIGHTMAP_JOB_NOT_QUEUED",
                                    {"job_id": job_id, "status": job["status"]})
            self._ensure_worker_available(worker)
            self._assign_worker(job, worker)

    def dispatch(self, worker: str) -> str | None:
        with self._lock:
            self._ensure_worker_available(worker)
            candidates = [
                job for job in self._jobs.values()
                if job["status"] == "queued"
                and job["page"] is not None
                and job["slots"]
            ]
            if not candidates:
                return None

            job = min(candidates, key=lambda item: (-item["priority"], item["seq"]))
            self._assign_worker(job, worker)
            return job["job_id"]

    def report_progress(self, job_id: str, *, page_index: int, progress,
                        digest=None) -> None:
        with self._lock:
            job = self._get_job(job_id)
            if job["status"] != "running":
                raise LightmapError("LIGHTMAP_JOB_NOT_RUNNING",
                                    {"job_id": job_id, "status": job["status"]})

            page_count = len(job["progress"])
            local_index_valid = (
                isinstance(page_index, int)
                and not isinstance(page_index, bool)
                and 0 <= page_index < page_count
            )
            slot_index_valid = (
                isinstance(page_index, int)
                and not isinstance(page_index, bool)
                and page_index in job["slots"]
            )
            if local_index_valid:
                progress_index = page_index
            elif slot_index_valid:
                progress_index = job["slots"].index(page_index)
            else:
                progress_index = None

            if progress_index is None or not _real_number(progress):
                raise LightmapError(
                    "LIGHTMAP_PROGRESS_INVALID",
                    {"job_id": job_id, "page_index": page_index,
                     "progress": progress},
                )
            if not 0.0 <= float(progress) <= 1.0:
                raise LightmapError("LIGHTMAP_PROGRESS_INVALID",
                                    {"progress": progress})
            if float(progress) < job["progress"][progress_index]:
                raise LightmapError(
                    "LIGHTMAP_PROGRESS_INVALID",
                    {"page_index": page_index,
                     "previous": job["progress"][progress_index],
                     "progress": progress},
                )

            job["progress"][progress_index] = float(progress)
            if digest is not None:
                job["digest"][progress_index] = digest
            self._stats["progress_reports"] += 1

            if all(value >= 1.0 for value in job["progress"]):
                page_index_global = job["page"]
                for slot in job["slots"]:
                    self._dirty[page_index_global][slot] = False
                job["status"] = "done"
                self._clear_worker(job)
                self._stats["completed"] += 1

    def cancel_job(self, job_id: str) -> bool:
        with self._lock:
            job = self._get_job(job_id)
            if job["status"] not in ("queued", "running"):
                return False

            if job["status"] == "running":
                self._clear_worker(job)
            job["status"] = "canceled"
            self._mark_written_fragments_dirty(job)
            self._stats["canceled"] += 1
            return True

    def resume(self, job_id: str) -> None:
        with self._lock:
            job = self._get_job(job_id)
            if job["status"] != "canceled":
                raise LightmapError("LIGHTMAP_NOT_CANCELED",
                                    {"job_id": job_id, "status": job["status"]})

            if job["page"] is not None:
                page_index = job["page"]
                for slot in job["slots"]:
                    self._dirty[page_index][slot] = False
            job["status"] = "queued"
            self._stats["resumed"] += 1

    def fail_job(self, job_id: str, *, reason: str) -> None:
        with self._lock:
            job = self._get_job(job_id)
            if job["status"] != "running":
                raise LightmapError("LIGHTMAP_JOB_NOT_RUNNING",
                                    {"job_id": job_id, "status": job["status"]})

            job["status"] = "failed"
            job["attempts"] += 1
            job["fail_reason"] = reason
            self._clear_worker(job)
            self._release_current_allocation(job, obsolete=True)
            job["page"] = None
            job["slots"] = []
            job["progress"] = []
            job["digest"] = []
            self._stats["failed"] += 1

    def release_worker(self, worker: str) -> None:
        with self._lock:
            job_id = self._workers.pop(worker, None)
            if job_id is None:
                return False
            job = self._jobs.get(job_id)
            if job is not None and job.get("worker") == worker:
                job["worker"] = None
                if job["status"] == "running":
                    job["status"] = "queued"
            return True

    def job_state(self, job_id: str) -> dict:
        with self._lock:
            job = self._get_job(job_id)
            return {
                "object_id": job["object_id"],
                "status": job["status"],
                "priority": job["priority"],
                "required_slots": job["required_slots"],
                "page": job["page"],
                "slots": tuple(job["slots"]),
                "worker": job["worker"],
                "version": job["version"],
                "attempts": job["attempts"],
                "progress": tuple(job["progress"]),
                "digest": tuple(job["digest"]),
            }

    def pages_of(self, object_id: str) -> tuple[PageAllocation, ...]:
        with self._lock:
            job_id = self._object_job.get(object_id)
            if job_id is None:
                return ()
            job = self._jobs[job_id]
            if job["page"] is None or not job["slots"]:
                return ()
            slots = _ContiguousSlots(job["slots"])
            return (PageAllocation(job["page"], slots),)

    def pending_jobs(self) -> tuple[str, ...]:
        with self._lock:
            return tuple(
                job["job_id"]
                for job in sorted(self._jobs.values(), key=lambda item: item["seq"])
                if job["status"] == "queued"
            )

    def snapshot(self) -> dict:
        with self._lock:
            state = {
                "schema": SCHEMA_VERSION,
                "jobs": copy.deepcopy(list(self._jobs.values())),
                "pages": [
                    {
                        "page": index,
                        "slots": copy.deepcopy(page),
                        "dirty": copy.deepcopy(self._dirty[index]),
                    }
                    for index, page in enumerate(self._pages)
                ],
                "workers": copy.deepcopy(self._workers),
                "stats": self.stats(),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        with self._lock:
            try:
                restored = self._parse_snapshot(state)
            except LightmapError:
                raise
            except Exception as exc:
                raise LightmapError(
                    "LIGHTMAP_SNAPSHOT_INVALID",
                    "snapshot structure could not be parsed",
                ) from exc
            jobs, object_job, pages, dirty, workers, stats = restored
            self._jobs = jobs
            self._object_job = object_job
            self._pages = pages
            self._dirty = dirty
            self._workers = workers
            self._stats = stats

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

    @staticmethod
    def _validate_request(object_id, texel_density, bounds, priority) -> None:
        if not isinstance(object_id, str) or not object_id.strip():
            raise LightmapError("LIGHTMAP_INVALID_REQUEST", "object_id is required")
        if not _real_number(texel_density) or texel_density <= 0:
            raise LightmapError("LIGHTMAP_INVALID_REQUEST",
                                "texel_density must be a positive number")
        if not isinstance(bounds, (tuple, list)) or len(bounds) != 2:
            raise LightmapError("LIGHTMAP_INVALID_REQUEST",
                                "bounds must contain two positive numbers")
        width, height = bounds
        if not _real_number(width) or not _real_number(height):
            raise LightmapError("LIGHTMAP_INVALID_REQUEST",
                                "bounds must contain two positive numbers")
        if width <= 0 or height <= 0:
            raise LightmapError("LIGHTMAP_INVALID_REQUEST",
                                "bounds must contain two positive numbers")
        if not _real_number(priority) or priority < 0:
            raise LightmapError("LIGHTMAP_INVALID_REQUEST",
                                "priority must be a non-negative number")

    @staticmethod
    def _required_slots(texel_density, width, height) -> int:
        return max(1, math.ceil(width * height * texel_density / SLOT_TEXELS))

    def _get_job(self, job_id: str) -> dict:
        if not isinstance(job_id, str) or job_id not in self._jobs:
            raise LightmapError("LIGHTMAP_UNKNOWN_JOB", job_id)
        return self._jobs[job_id]

    def _find_free_block(self, required_slots: int) -> tuple[int, int] | None:
        for page_index, page in enumerate(self._pages):
            last_start = self.page_slots - required_slots
            for first_slot in range(last_start + 1):
                if all(slot is None for slot in
                       page[first_slot:first_slot + required_slots]):
                    return page_index, first_slot

        if len(self._pages) < self.max_pages:
            return len(self._pages), 0
        return None

    def _ensure_worker_available(self, worker: str) -> None:
        if not isinstance(worker, str) or not worker:
            raise LightmapError("LIGHTMAP_INVALID_REQUEST",
                                {"worker": worker})
        if worker in self._workers:
            raise LightmapError("LIGHTMAP_WORKER_BUSY",
                                {"worker": worker,
                                 "job_id": self._workers[worker]})
        if len(self._workers) >= self.max_workers:
            raise LightmapError("LIGHTMAP_WORKER_LIMIT",
                                {"max_workers": self.max_workers})

    def _assign_worker(self, job: dict, worker: str) -> None:
        job["status"] = "running"
        job["worker"] = worker
        self._workers[worker] = job["job_id"]
        self._stats["dispatches"] += 1

    def _clear_worker(self, job: dict) -> None:
        worker = job.get("worker")
        if worker is not None:
            self._workers.pop(worker, None)
        job["worker"] = None

    def _mark_written_fragments_dirty(self, job: dict) -> None:
        if job["page"] is None:
            return
        page_index = job["page"]
        for index, slot in enumerate(job["slots"]):
            has_progress = (
                index < len(job["progress"]) and job["progress"][index] > 0
            )
            has_digest = (
                index < len(job["digest"]) and job["digest"][index] is not None
            )
            if has_progress or has_digest:
                self._dirty[page_index][slot] = True

    def _release_current_allocation(self, job: dict, *, obsolete: bool) -> None:
        if job["page"] is None:
            return
        page_index = job["page"]
        for slot in job["slots"]:
            if obsolete:
                self._dirty[page_index][slot] = True
            self._pages[page_index][slot] = None
        job["page"] = None
        job["slots"] = []

    def _invalidate_allocation(self, job: dict) -> None:
        if job["page"] is None:
            job["progress"] = []
            job["digest"] = []
            return
        if len(job["slots"]) == job["required_slots"]:
            for slot in job["slots"]:
                self._dirty[job["page"]][slot] = True
            job["progress"] = [0.0] * job["required_slots"]
            job["digest"] = [None] * job["required_slots"]
        else:
            self._release_current_allocation(job, obsolete=True)
            job["progress"] = []
            job["digest"] = []

    def _parse_snapshot(self, state: object):
        if not isinstance(state, dict):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "state must be a dict")
        if set(state) != {"schema", "jobs", "pages", "workers", "stats"}:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid top-level keys")
        if state["schema"] != SCHEMA_VERSION:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "unsupported schema")
        if not isinstance(state["jobs"], list):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "jobs must be a list")
        if not isinstance(state["pages"], list):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "pages must be a list")
        if not isinstance(state["workers"], dict):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "workers must be a dict")
        if not isinstance(state["stats"], dict):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "stats must be a dict")

        stats = self._parse_stats(state["stats"])
        pages, dirty = self._parse_pages(state["pages"], stats)
        jobs, object_job = self._parse_jobs(state["jobs"], pages)
        workers = self._parse_workers(state["workers"], jobs)
        self._check_occupancy(jobs, pages)

        if len(pages) > self.max_pages:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "too many pages")
        if len(workers) > self.max_workers:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "too many workers")

        return (
            copy.deepcopy(jobs),
            copy.deepcopy(object_job),
            copy.deepcopy(pages),
            copy.deepcopy(dirty),
            copy.deepcopy(workers),
            copy.deepcopy(stats),
        )

    def _parse_stats(self, raw_stats: dict) -> dict:
        missing = [key for key in STAT_KEYS if key not in raw_stats]
        if missing:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID",
                                {"missing_stats": missing})
        stats = {}
        for key in STAT_KEYS:
            value = raw_stats[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID",
                                    {"invalid_stat": key})
            stats[key] = value
        return stats

    def _parse_pages(self, raw_pages: list, stats: dict):
        if stats["pages_created"] != len(raw_pages):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID",
                                "pages_created does not match pages")
        pages = []
        dirty = []
        for index, raw_page in enumerate(raw_pages):
            if not isinstance(raw_page, dict):
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid page")
            if raw_page.get("page", index) != index:
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "page index mismatch")
            raw_slots = raw_page.get("slots")
            raw_dirty = raw_page.get("dirty")
            if not isinstance(raw_slots, list) or len(raw_slots) != self.page_slots:
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID",
                                    {"page": index, "slots": "invalid"})
            if not isinstance(raw_dirty, list) or len(raw_dirty) != self.page_slots:
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID",
                                    {"page": index, "dirty": "invalid"})
            if not all(slot is None or isinstance(slot, str) for slot in raw_slots):
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID",
                                    {"page": index, "slots": "owner invalid"})
            if not all(isinstance(value, bool) for value in raw_dirty):
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID",
                                    {"page": index, "dirty": "type invalid"})
            pages.append(list(raw_slots))
            dirty.append(list(raw_dirty))
        return pages, dirty

    def _parse_jobs(self, raw_jobs: list, pages: list):
        jobs = {}
        object_job = {}
        for raw_job in raw_jobs:
            job = self._parse_job(raw_job, len(pages))
            job_id = job["job_id"]
            if job_id in jobs:
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "duplicate job")
            if job["object_id"] in object_job:
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID",
                                    "duplicate object job")
            jobs[job_id] = job
            object_job[job["object_id"]] = job_id
        return jobs, object_job

    def _parse_job(self, raw_job: object, page_count: int) -> dict:
        if not isinstance(raw_job, dict):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "job must be a dict")

        required_fields = (
            "job_id", "seq", "object_id", "texel_density", "bounds",
            "required_slots", "priority", "status", "page", "slots",
            "worker", "version", "attempts", "progress", "digest",
        )
        if any(field not in raw_job for field in required_fields):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "job is incomplete")

        job_id = raw_job["job_id"]
        sequence = raw_job["seq"]
        object_id = raw_job["object_id"]
        density = raw_job["texel_density"]
        bounds = raw_job["bounds"]
        required_slots = raw_job["required_slots"]
        priority = raw_job["priority"]
        status = raw_job["status"]
        page = raw_job["page"]
        slots = raw_job["slots"]
        worker = raw_job["worker"]
        version = raw_job["version"]
        attempts = raw_job["attempts"]
        progress = raw_job["progress"]
        digest = raw_job["digest"]

        if not isinstance(job_id, str) or not re.fullmatch(r"job-\d{4,}", job_id):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid job_id")
        if isinstance(sequence, bool) or not isinstance(sequence, int) or sequence <= 0:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid seq")
        if job_id != f"job-{sequence:04d}":
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "job id sequence mismatch")
        if not isinstance(object_id, str) or not object_id.strip():
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid object_id")
        if not _real_number(density) or density <= 0:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid density")
        if not isinstance(bounds, (list, tuple)) or len(bounds) != 2:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid bounds")
        if not all(_real_number(value) and value > 0 for value in bounds):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid bounds")
        if isinstance(required_slots, bool) or not isinstance(required_slots, int):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid required_slots")
        if required_slots <= 0 or required_slots > self.page_slots:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "required_slots overflow")
        if not _real_number(priority) or priority < 0:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid priority")
        if status not in JOB_STATUSES:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid status")
        if isinstance(version, bool) or not isinstance(version, int) or version <= 0:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid version")
        if isinstance(attempts, bool) or not isinstance(attempts, int) or attempts < 0:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid attempts")
        if page is not None:
            if isinstance(page, bool) or not isinstance(page, int):
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid page")
            if not 0 <= page < page_count:
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "page out of range")
        if not isinstance(slots, list) and not isinstance(slots, tuple):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid slots")
        slots = [slot for slot in slots]
        if any(isinstance(slot, bool) or not isinstance(slot, int)
               or not 0 <= slot < self.page_slots for slot in slots):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "slot out of range")
        if len(set(slots)) != len(slots):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "duplicate slots")
        if page is None and slots:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "slots without page")
        if page is not None and len(slots) != required_slots:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "slot count mismatch")
        if slots and slots != list(range(min(slots), min(slots) + len(slots))):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "slots not contiguous")
        if not isinstance(progress, (list, tuple)) or not isinstance(digest, (list, tuple)):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid progress/digest")
        expected_length = required_slots if page is not None else 0
        if len(progress) != expected_length or len(digest) != expected_length:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "progress length mismatch")
        if any(not _real_number(value) or not 0 <= value <= 1 for value in progress):
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid progress value")
        if status == "running":
            if not isinstance(worker, str) or not worker:
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "running worker missing")
        elif worker is not None:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "worker on inactive job")

        job = copy.deepcopy(raw_job)
        job["bounds"] = [bounds[0], bounds[1]]
        job["slots"] = slots
        job["progress"] = [float(value) for value in progress]
        job["digest"] = list(digest)
        return job

    def _parse_workers(self, raw_workers: dict, jobs: dict) -> dict:
        workers = {}
        for worker, job_id in raw_workers.items():
            if not isinstance(worker, str) or not worker:
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "invalid worker")
            if not isinstance(job_id, str) or job_id not in jobs:
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "worker job missing")
            job = jobs[job_id]
            if job["status"] != "running" or job["worker"] != worker:
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "worker job mismatch")
            if worker in workers:
                raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "duplicate worker")
            workers[worker] = job_id

        running_workers = {
            job["worker"] for job in jobs.values() if job["status"] == "running"
        }
        if set(workers) != running_workers:
            raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "workers do not match jobs")
        return workers

    def _check_occupancy(self, jobs: dict, pages: list) -> None:
        for job in jobs.values():
            if job["page"] is None:
                continue
            page = pages[job["page"]]
            for slot in job["slots"]:
                if page[slot] != job["job_id"]:
                    raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID",
                                        "job/page occupancy mismatch")

        owners = set()
        for page_index, page in enumerate(pages):
            for slot, owner in enumerate(page):
                if owner is None:
                    continue
                if owner not in jobs:
                    raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "orphan page owner")
                key = (page_index, slot)
                if key in owners:
                    raise LightmapError("LIGHTMAP_SNAPSHOT_INVALID", "double occupancy")
                owners.add(key)
