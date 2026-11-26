"""Lightmap bake queue with shelf atlas packing and dirty region merging."""

from __future__ import annotations

import threading


class BakeError(ValueError):
    """Raised when a bake queue operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class LightmapBakeQueue:
    """Queue offline bake tasks, lease them to workers and pack atlas pages."""

    MAX_QUEUED = 64

    def __init__(self, *, page_size=(1024, 1024), max_queued: int = 64) -> None:
        if (not isinstance(page_size, (tuple, list)) or len(page_size) != 2
                or any(not isinstance(v, int) or isinstance(v, bool) or v <= 0
                       for v in page_size)):
            raise BakeError("BAKE_INVALID_ARGUMENT", page_size)
        if not isinstance(max_queued, int) or isinstance(max_queued, bool) or max_queued < 1:
            raise BakeError("BAKE_INVALID_ARGUMENT", max_queued)
        self.page_size = (int(page_size[0]), int(page_size[1]))
        self.max_queued = max_queued
        self._lock = threading.RLock()

    def submit(self, scene, region, *, priority=0, size):
        raise NotImplementedError

    def cancel(self, task_id):
        raise NotImplementedError

    def claim(self, worker_id):
        raise NotImplementedError

    def complete(self, task_id, *, digest):
        raise NotImplementedError

    def pack_atlas(self):
        raise NotImplementedError

    def dirty_mark(self, scene, region):
        raise NotImplementedError

    def merge_dirty(self, scene):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
