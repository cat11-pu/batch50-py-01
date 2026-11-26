"""Scene graph dirty propagation with double-buffered commit and rollback."""

from __future__ import annotations

import threading


class SceneGraphError(ValueError):
    """Raised when a scene graph operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class SceneGraphDirtySync:
    """Track local transforms, propagate dirty marks and publish committed worlds."""

    def __init__(self, *, max_nodes: int = 256) -> None:
        if not isinstance(max_nodes, int) or isinstance(max_nodes, bool) or max_nodes < 1:
            raise SceneGraphError("SG_INVALID_ARGUMENT", max_nodes)
        self.max_nodes = max_nodes
        self._lock = threading.RLock()

    def attach(self, node_id, *, parent=None, local=(0, 0, 0)):
        raise NotImplementedError

    def set_local(self, node_id, *, local):
        raise NotImplementedError

    def detach(self, node_id):
        raise NotImplementedError

    def mark_dirty(self, node_id):
        raise NotImplementedError

    def update_world(self):
        raise NotImplementedError

    def commit(self):
        raise NotImplementedError

    def query_world(self, node_id):
        raise NotImplementedError

    def rollback(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
