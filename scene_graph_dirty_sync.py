"""Scene graph dirty propagation with double-buffered commit and rollback."""

from __future__ import annotations

import copy
import threading
from types import MappingProxyType


class SceneGraphError(ValueError):
    """Raised when a scene graph operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class SceneGraphDirtySync:
    """Track local transforms, propagate dirty marks and publish committed worlds."""

    VERSION = 1
    STAT_KEYS = (
        "nodes",
        "attached",
        "detached",
        "dirty_marks",
        "recomputed",
        "commits",
        "rollbacks",
    )

    def __init__(self, *, max_nodes: int = 256) -> None:
        if not isinstance(max_nodes, int) or isinstance(max_nodes, bool) or max_nodes < 1:
            raise SceneGraphError("SG_INVALID_ARGUMENT", max_nodes)
        self.max_nodes = max_nodes
        self._lock = threading.RLock()
        self._nodes: dict[str, dict] = {}
        self._active: set[str] = set()
        self._seq = 0
        self._pending: dict[str, tuple[float, float, float]] = {}
        self._committed: dict[str, tuple[float, float, float]] = {}
        self._published_frame = MappingProxyType(
            {"generation": 0, "worlds": MappingProxyType({})}
        )
        self._dirty: set[str] = set()
        self._modified: set[str] = set()
        self._generation = 0
        self._rollback_available = False
        self._stats = {
            "attached": 0,
            "detached": 0,
            "dirty_marks": 0,
            "recomputed": 0,
            "commits": 0,
            "rollbacks": 0,
        }

    @staticmethod
    def _valid_node_id(node_id) -> bool:
        return isinstance(node_id, str) and bool(node_id)

    @staticmethod
    def _normalize_local(local, *, snapshot: bool = False):
        if not isinstance(local, tuple) and not (snapshot and isinstance(local, list)):
            raise SceneGraphError(
                "SG_SNAPSHOT_INVALID" if snapshot else "SG_INVALID_ARGUMENT", local
            )
        if len(local) != 3:
            code = "SG_SNAPSHOT_INVALID" if snapshot else "SG_INVALID_ARGUMENT"
            raise SceneGraphError(code, local)
        values = []
        for value in local:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                code = "SG_SNAPSHOT_INVALID" if snapshot else "SG_INVALID_ARGUMENT"
                raise SceneGraphError(code, local)
            values.append(float(value))
        return tuple(values)

    def _require_active_node(self, node_id) -> dict:
        record = self._nodes.get(node_id) if self._valid_node_id(node_id) else None
        if record is None or not record["active"]:
            raise SceneGraphError("SG_UNKNOWN", node_id)
        return record

    def _mark_subtree(self, node_id: str) -> int:
        if node_id in self._dirty:
            return 0

        added = 0
        stack = [node_id]
        while stack:
            current_id = stack.pop()
            if current_id in self._dirty:
                continue

            self._dirty.add(current_id)
            self._modified.add(current_id)
            added += 1

            record = self._nodes[current_id]
            for child_id in reversed(record["children"]):
                if child_id in self._active:
                    stack.append(child_id)
        return added

    def _note_mutation_after_commit(self) -> None:
        if self._generation > 0:
            self._rollback_available = True

    def attach(self, node_id, *, parent=None, local=(0, 0, 0)):
        if not self._valid_node_id(node_id):
            raise SceneGraphError("SG_INVALID_ARGUMENT", node_id)
        normalized_local = self._normalize_local(local)

        with self._lock:
            if node_id in self._nodes:
                raise SceneGraphError("SG_DUPLICATE", node_id)

            parent_record = None
            if parent is not None:
                parent_record = (
                    self._nodes.get(parent) if self._valid_node_id(parent) else None
                )
                if parent_record is None or not parent_record["active"]:
                    raise SceneGraphError("SG_UNKNOWN", parent)

            if len(self._active) >= self.max_nodes:
                raise SceneGraphError("SG_CAPACITY_EXCEEDED", self.max_nodes)

            self._seq += 1
            depth = 0 if parent_record is None else parent_record["depth"] + 1
            record = {
                "parent": parent,
                "local": normalized_local,
                "children": [],
                "seq": self._seq,
                "depth": depth,
                "active": True,
                "committed_known": False,
                "committed_active": False,
                "committed_local": None,
            }
            self._nodes[node_id] = record
            self._active.add(node_id)
            if parent_record is not None:
                parent_record["children"].append(node_id)

            self._dirty.add(node_id)
            self._modified.add(node_id)
            self._stats["attached"] += 1
            self._note_mutation_after_commit()

            return {
                "node_id": node_id,
                "parent": parent,
                "local": normalized_local,
                "attached": True,
            }

    def set_local(self, node_id, *, local):
        normalized_local = self._normalize_local(local)
        with self._lock:
            record = self._require_active_node(node_id)
            record["local"] = normalized_local
            added = self._mark_subtree(node_id)
            self._stats["dirty_marks"] += added
            self._note_mutation_after_commit()
            return {
                "node_id": node_id,
                "local": normalized_local,
                "dirty": added,
            }

    def detach(self, node_id):
        with self._lock:
            self._require_active_node(node_id)

            removed = []
            stack = [(node_id, False)]
            while stack:
                current_id, expanded = stack.pop()
                current = self._nodes[current_id]
                if expanded:
                    removed.append(current_id)
                    continue

                stack.append((current_id, True))
                for child_id in reversed(current["children"]):
                    if child_id in self._active:
                        stack.append((child_id, False))

            for removed_id in removed:
                record = self._nodes[removed_id]
                record["active"] = False
                self._active.discard(removed_id)
                self._dirty.discard(removed_id)
                self._pending.pop(removed_id, None)

            self._stats["detached"] += len(removed)
            self._note_mutation_after_commit()
            return removed

    def mark_dirty(self, node_id):
        with self._lock:
            self._require_active_node(node_id)
            added = self._mark_subtree(node_id)
            self._stats["dirty_marks"] += added
            self._note_mutation_after_commit()
            return added

    def update_world(self):
        with self._lock:
            if not self._dirty:
                return {"recomputed": 0, "remaining": 0}

            compute_ids = set(self._dirty)
            for dirty_id in tuple(self._dirty):
                current = self._nodes[dirty_id]["parent"]
                while current is not None:
                    if current in self._active and current not in self._pending:
                        compute_ids.add(current)
                    current = self._nodes[current]["parent"]

            ordered_ids = sorted(
                compute_ids,
                key=lambda item: (
                    self._nodes[item]["depth"],
                    self._nodes[item]["seq"],
                ),
            )

            recomputed = 0
            for node_id in ordered_ids:
                record = self._nodes[node_id]
                parent_id = record["parent"]
                if parent_id is None:
                    parent_world = (0.0, 0.0, 0.0)
                else:
                    parent_world = self._pending[parent_id]

                local = record["local"]
                self._pending[node_id] = (
                    float(local[0]) + float(parent_world[0]),
                    float(local[1]) + float(parent_world[1]),
                    float(local[2]) + float(parent_world[2]),
                )
                self._dirty.discard(node_id)
                recomputed += 1

            self._stats["recomputed"] += recomputed
            return {"recomputed": recomputed, "remaining": len(self._dirty)}

    def commit(self):
        with self._lock:
            if self._dirty:
                raise SceneGraphError("SG_DIRTY_PENDING", sorted(self._dirty))

            missing_pending = sorted(
                node_id for node_id in self._active if node_id not in self._pending
            )
            if missing_pending:
                self._dirty.update(missing_pending)
                raise SceneGraphError("SG_DIRTY_PENDING", missing_pending)

            next_generation = self._generation + 1
            next_worlds = dict(self._committed)
            frame_worlds = {}
            for node_id in self._active:
                world = tuple(self._pending[node_id])
                next_worlds[node_id] = world
                frame_worlds[node_id] = world

            next_frame = MappingProxyType(
                {
                    "generation": next_generation,
                    "worlds": MappingProxyType(frame_worlds),
                }
            )

            self._generation = next_generation
            self._committed = next_worlds
            for node_id, record in self._nodes.items():
                record["committed_known"] = True
                if record["active"]:
                    record["committed_active"] = True
                    record["committed_local"] = record["local"]
                else:
                    record["committed_active"] = False

            self._modified.clear()
            self._rollback_available = True
            self._stats["commits"] += 1
            self._published_frame = next_frame

            return {"generation": next_generation, "nodes": len(self._active)}

    def query_world(self, node_id):
        with self._lock:
            record = self._nodes.get(node_id) if self._valid_node_id(node_id) else None
            if record is None:
                raise SceneGraphError("SG_UNKNOWN", node_id)

            if node_id not in self._committed:
                raise SceneGraphError("SG_NO_COMMIT", node_id)
            return tuple(self._committed[node_id])

    def rollback(self):
        with self._lock:
            if self._generation <= 0 or not self._rollback_available:
                raise SceneGraphError("SG_NO_ROLLBACK", self._generation)

            marked_ids = set(self._modified)
            removed = sum(
                1 for record in self._nodes.values() if not record["committed_known"]
            )

            restored = 0
            for node_id, record in self._nodes.items():
                if not record["committed_known"] or not record["committed_active"]:
                    continue
                if (
                    not record["active"]
                    or record["local"] != record["committed_local"]
                    or node_id in marked_ids
                ):
                    restored += 1

            restored_nodes = {}
            restored_active = set()
            for node_id, record in self._nodes.items():
                if not record["committed_known"]:
                    continue

                restored_record = copy.deepcopy(record)
                if record["committed_active"]:
                    restored_record["active"] = True
                    restored_record["local"] = record["committed_local"]
                    restored_active.add(node_id)
                else:
                    restored_record["active"] = False
                restored_nodes[node_id] = restored_record

            self._nodes = restored_nodes
            self._active = restored_active
            self._pending = {
                node_id: tuple(world)
                for node_id, world in self._committed.items()
                if node_id in restored_active
            }
            self._dirty = {
                node_id for node_id in marked_ids if node_id in restored_active
            }
            self._rollback_available = False
            self._stats["rollbacks"] += 1

            return {
                "generation": self._generation,
                "restored": restored,
                "removed": removed,
            }

    def snapshot(self):
        with self._lock:
            return {
                "version": self.VERSION,
                "generation": self._generation,
                "nodes": copy.deepcopy(self._nodes),
                "pending": copy.deepcopy(self._pending),
                "committed": copy.deepcopy(self._committed),
                "dirty": copy.deepcopy(self._dirty),
                "modified": copy.deepcopy(self._modified),
                "stats": self.stats(),
            }

    def restore(self, state):
        with self._lock:
            try:
                candidate = self._parse_snapshot(state)
            except SceneGraphError:
                raise
            except Exception as exc:
                raise SceneGraphError("SG_SNAPSHOT_INVALID", state) from exc

            self._generation = candidate["generation"]
            self._nodes = candidate["nodes"]
            self._active = candidate["active"]
            self._seq = max(
                (record["seq"] for record in candidate["nodes"].values()),
                default=0,
            )
            self._pending = candidate["pending"]
            self._committed = candidate["committed"]
            self._dirty = candidate["dirty"]
            self._modified = candidate["modified"]
            self._stats = candidate["stats"]
            self._rollback_available = candidate["generation"] > 0
            frame_worlds = {
                node_id: candidate["committed"][node_id]
                for node_id, record in candidate["nodes"].items()
                if record["committed_active"] and node_id in candidate["committed"]
            }
            self._published_frame = MappingProxyType(
                {
                    "generation": candidate["generation"],
                    "worlds": MappingProxyType(frame_worlds),
                }
            )

    def stats(self):
        with self._lock:
            return {
                "nodes": len(self._active),
                "attached": self._stats["attached"],
                "detached": self._stats["detached"],
                "dirty_marks": self._stats["dirty_marks"],
                "recomputed": self._stats["recomputed"],
                "commits": self._stats["commits"],
                "rollbacks": self._stats["rollbacks"],
            }

    def _parse_snapshot(self, state):
        if not isinstance(state, dict):
            raise SceneGraphError("SG_SNAPSHOT_INVALID", type(state).__name__)

        required = (
            "version",
            "generation",
            "nodes",
            "pending",
            "committed",
            "dirty",
            "modified",
            "stats",
        )
        if any(key not in state for key in required):
            raise SceneGraphError("SG_SNAPSHOT_INVALID", "missing key")

        version = state["version"]
        if isinstance(version, bool) or not isinstance(version, int):
            raise SceneGraphError("SG_SNAPSHOT_INVALID", "version")
        if version != self.VERSION:
            raise SceneGraphError("SG_SNAPSHOT_INVALID", version)

        generation = state["generation"]
        if (
            isinstance(generation, bool)
            or not isinstance(generation, int)
            or generation < 0
        ):
            raise SceneGraphError("SG_SNAPSHOT_INVALID", generation)

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict):
            raise SceneGraphError("SG_SNAPSHOT_INVALID", "stats")
        stats = {}
        for key in self.STAT_KEYS:
            if key not in raw_stats:
                raise SceneGraphError("SG_SNAPSHOT_INVALID", f"stats.{key}")
            value = raw_stats[key]
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise SceneGraphError("SG_SNAPSHOT_INVALID", f"stats.{key}")
            stats[key] = value

        raw_nodes = state["nodes"]
        if isinstance(raw_nodes, dict):
            raw_items = list(raw_nodes.items())
        elif isinstance(raw_nodes, (list, tuple)):
            raw_items = []
            for index, raw_record in enumerate(raw_nodes):
                if not isinstance(raw_record, dict):
                    raise SceneGraphError("SG_SNAPSHOT_INVALID", "nodes[]")
                node_id = raw_record.get("node_id", raw_record.get("id"))
                if node_id is None:
                    raise SceneGraphError("SG_SNAPSHOT_INVALID", f"nodes[{index}]")
                raw_items.append((node_id, raw_record))
        else:
            raise SceneGraphError("SG_SNAPSHOT_INVALID", "nodes")

        nodes = {}
        order = []
        for index, (node_id, raw_record) in enumerate(raw_items):
            if not self._valid_node_id(node_id) or node_id in nodes:
                raise SceneGraphError("SG_SNAPSHOT_INVALID", node_id)
            if not isinstance(raw_record, dict):
                raise SceneGraphError("SG_SNAPSHOT_INVALID", node_id)

            parent = raw_record.get("parent")
            if parent is not None and not self._valid_node_id(parent):
                raise SceneGraphError("SG_SNAPSHOT_INVALID", f"{node_id}.parent")

            local = self._normalize_local(raw_record.get("local"), snapshot=True)

            active = raw_record.get("active", True)
            if not isinstance(active, bool):
                raise SceneGraphError("SG_SNAPSHOT_INVALID", f"{node_id}.active")

            seq = raw_record.get("seq", index + 1)
            if isinstance(seq, bool) or not isinstance(seq, int) or seq < 0:
                raise SceneGraphError("SG_SNAPSHOT_INVALID", f"{node_id}.seq")

            committed_known = raw_record.get("committed_known", generation > 0)
            if not isinstance(committed_known, bool):
                raise SceneGraphError(
                    "SG_SNAPSHOT_INVALID", f"{node_id}.committed_known"
                )

            committed_active = raw_record.get("committed_active", active)
            if not isinstance(committed_active, bool):
                raise SceneGraphError(
                    "SG_SNAPSHOT_INVALID", f"{node_id}.committed_active"
                )
            if not committed_known:
                committed_active = False

            raw_committed_local = raw_record.get("committed_local", local)
            if raw_committed_local is None:
                committed_local = None
            else:
                committed_local = self._normalize_local(
                    raw_committed_local, snapshot=True
                )
            if committed_active and committed_local is None:
                committed_local = local

            nodes[node_id] = {
                "parent": parent,
                "local": local,
                "children": [],
                "seq": seq,
                "depth": 0,
                "active": active,
                "committed_known": committed_known,
                "committed_active": committed_active,
                "committed_local": committed_local,
            }
            order.append(node_id)

        active = {node_id for node_id in order if nodes[node_id]["active"]}
        if len(active) > self.max_nodes or stats["nodes"] != len(active):
            raise SceneGraphError("SG_SNAPSHOT_INVALID", "node count")

        depths = {}
        for start_id in order:
            if start_id in depths:
                continue
            path = []
            positions = {}
            current_id = start_id
            while current_id is not None and current_id not in depths:
                if current_id in positions:
                    raise SceneGraphError("SG_SNAPSHOT_INVALID", "cycle")
                if current_id not in nodes:
                    raise SceneGraphError("SG_SNAPSHOT_INVALID", current_id)
                positions[current_id] = len(path)
                path.append(current_id)
                current_id = nodes[current_id]["parent"]

            if current_id is not None and current_id not in nodes:
                raise SceneGraphError("SG_SNAPSHOT_INVALID", current_id)

            for node_id in reversed(path):
                parent_id = nodes[node_id]["parent"]
                if parent_id is None:
                    depth = 0
                else:
                    depth = depths[parent_id] + 1
                depths[node_id] = depth

        for node_id in order:
            record = nodes[node_id]
            record["depth"] = depths[node_id]
            parent_id = record["parent"]
            if parent_id is not None:
                nodes[parent_id]["children"].append(node_id)

        pending = {}
        raw_pending = state["pending"]
        if not isinstance(raw_pending, dict):
            raise SceneGraphError("SG_SNAPSHOT_INVALID", "pending")
        for node_id, world in raw_pending.items():
            if not self._valid_node_id(node_id) or node_id not in active:
                raise SceneGraphError("SG_SNAPSHOT_INVALID", f"pending.{node_id}")
            pending[node_id] = self._normalize_local(world, snapshot=True)

        committed = {}
        raw_committed = state["committed"]
        if not isinstance(raw_committed, dict):
            raise SceneGraphError("SG_SNAPSHOT_INVALID", "committed")
        for node_id, world in raw_committed.items():
            if not self._valid_node_id(node_id) or node_id not in nodes:
                raise SceneGraphError("SG_SNAPSHOT_INVALID", f"committed.{node_id}")
            committed[node_id] = self._normalize_local(world, snapshot=True)

        def parse_id_set(value, *, active_only: bool):
            if not isinstance(value, (set, frozenset, list, tuple)):
                raise SceneGraphError("SG_SNAPSHOT_INVALID", "id set")
            result = set()
            for node_id in value:
                allowed = active if active_only else nodes.keys()
                if not self._valid_node_id(node_id) or node_id not in allowed:
                    raise SceneGraphError("SG_SNAPSHOT_INVALID", node_id)
                result.add(node_id)
            return result

        dirty = parse_id_set(state["dirty"], active_only=True)
        modified = parse_id_set(state["modified"], active_only=False)
        modified.update(dirty)

        return {
            "generation": generation,
            "nodes": nodes,
            "active": active,
            "pending": pending,
            "committed": committed,
            "dirty": dirty,
            "modified": modified,
            "stats": {key: stats[key] for key in self.STAT_KEYS},
        }
