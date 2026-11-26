"""Destruction support graph: durability, reachability, collapse, and loot."""

from __future__ import annotations

import copy
import threading
from collections import deque


GRAPH_INVALID_REQUEST = "GRAPH_INVALID_REQUEST"
GRAPH_STRUCTURE_EXISTS = "GRAPH_STRUCTURE_EXISTS"
GRAPH_CAPACITY_EXCEEDED = "GRAPH_CAPACITY_EXCEEDED"
GRAPH_COMPONENT_GONE = "GRAPH_COMPONENT_GONE"
GRAPH_STRUCTURE_UNKNOWN = "GRAPH_STRUCTURE_UNKNOWN"
GRAPH_COMPONENT_UNKNOWN = "GRAPH_COMPONENT_UNKNOWN"
GRAPH_SNAPSHOT_INVALID = "GRAPH_SNAPSHOT_INVALID"

_SNAPSHOT_VERSION = 1
_STAT_KEYS = (
    "registered",
    "damaged",
    "collapsed",
    "destroyed",
    "repaired",
    "loot",
    "resets",
)


class GraphError(ValueError):
    """Raised when a destruction operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


def _positive_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and value > 0


def _sorted_identifiers(values):
    identifiers = list(values)
    try:
        return sorted(identifiers)
    except TypeError:
        return sorted(
            identifiers,
            key=lambda value: (type(value).__name__, str(value)),
        )


class DestructionSupportGraph:
    """Model breakable structures as components plus support edges."""

    def __init__(
        self,
        *,
        max_components: int = 256,
        max_collapse: int = 32,
        default_durability: int = 100,
        secondary_damage: int = 15,
    ) -> None:
        self.max_components = max_components
        self.max_collapse = max_collapse
        self.default_durability = default_durability
        self.secondary_damage = secondary_damage
        self._lock = threading.RLock()
        self._structures: dict = {}
        self._stats = {key: 0 for key in _STAT_KEYS}

    def register_structure(
        self,
        structure_id: str,
        components,
        edges,
        *,
        region=None,
    ) -> dict:
        structure_key = self._structure_identifier(structure_id)

        with self._lock:
            if structure_key in self._structures:
                raise GraphError(
                    GRAPH_STRUCTURE_EXISTS,
                    {"structure": structure_key},
                )

            try:
                component_inputs = list(components)
            except TypeError as exc:
                raise GraphError(
                    GRAPH_INVALID_REQUEST,
                    "components must be a sequence",
                ) from exc

            if len(component_inputs) > self.max_components:
                raise GraphError(
                    GRAPH_CAPACITY_EXCEEDED,
                    {
                        "structure": structure_key,
                        "components": len(component_inputs),
                        "max_components": self.max_components,
                    },
                )

            if not component_inputs:
                raise GraphError(GRAPH_INVALID_REQUEST, "components must not be empty")

            component_order = []
            component_states = {}

            for component in component_inputs:
                if not isinstance(component, dict) or "component" not in component:
                    raise GraphError(
                        GRAPH_INVALID_REQUEST,
                        "every component requires a component field",
                    )

                component_id = component["component"]
                try:
                    hash(component_id)
                except TypeError as exc:
                    raise GraphError(
                        GRAPH_INVALID_REQUEST,
                        "component id must be hashable",
                    ) from exc

                if component_id in component_states:
                    raise GraphError(
                        GRAPH_INVALID_REQUEST,
                        {"duplicate_component": component_id},
                    )

                durability = component.get(
                    "durability",
                    self.default_durability,
                )
                if not _positive_int(durability):
                    raise GraphError(
                        GRAPH_INVALID_REQUEST,
                        {"component": component_id, "durability": durability},
                    )

                view = copy.deepcopy(component)
                view["durability"] = durability
                view["max_durability"] = durability
                view["destroyed"] = False

                component_states[component_id] = {
                    "view": view,
                    "collapsed": False,
                }
                component_order.append(component_id)

            try:
                edge_inputs = list(edges)
            except TypeError as exc:
                raise GraphError(
                    GRAPH_INVALID_REQUEST,
                    "edges must be a sequence",
                ) from exc

            parsed_edges = []
            neighbor_sets = {component_id: set() for component_id in component_order}

            for edge in edge_inputs:
                if isinstance(edge, (str, bytes)):
                    raise GraphError(GRAPH_INVALID_REQUEST, "edge must be a pair")
                try:
                    endpoints = tuple(edge)
                except TypeError as exc:
                    raise GraphError(
                        GRAPH_INVALID_REQUEST,
                        "edge must contain two component ids",
                    ) from exc

                if len(endpoints) != 2:
                    raise GraphError(
                        GRAPH_INVALID_REQUEST,
                        "edge must contain exactly two component ids",
                    )

                source_id, target_id = endpoints
                if source_id == target_id:
                    raise GraphError(GRAPH_INVALID_REQUEST, "self loops are invalid")
                try:
                    source_unknown = source_id not in component_states
                    target_unknown = target_id not in component_states
                except TypeError as exc:
                    raise GraphError(
                        GRAPH_INVALID_REQUEST,
                        {"edge": repr(edge)},
                    ) from exc
                if source_unknown or target_unknown:
                    raise GraphError(
                        GRAPH_INVALID_REQUEST,
                        {"edge": [source_id, target_id]},
                    )

                parsed_edges.append([source_id, target_id])
                neighbor_sets[source_id].add(target_id)
                neighbor_sets[target_id].add(source_id)

            has_ground = any(
                component_states[component_id]["view"].get("grounded")
                for component_id in component_order
            )
            if not has_ground:
                raise GraphError(
                    GRAPH_INVALID_REQUEST,
                    "structure requires at least one grounded component",
                )

            structure = {
                "structure": structure_key,
                "region": region,
                "edge_count": len(parsed_edges),
                "component_order": component_order,
                "components": component_states,
                "edges": parsed_edges,
                "neighbors": {
                    component_id: _sorted_identifiers(
                        neighbor_sets[component_id]
                    )
                    for component_id in component_order
                },
                "loot": [],
                "initial_states": copy.deepcopy(component_states),
            }
            self._structures[structure_key] = structure
            self._stats["registered"] += 1

            return {
                "structure": structure_key,
                "components": len(component_order),
                "edges": len(parsed_edges),
                "region": region,
            }

    def apply_damage(
        self,
        structure_id: str,
        component_id: str,
        amount: int,
    ) -> dict:
        if not _positive_int(amount):
            raise GraphError(GRAPH_INVALID_REQUEST, {"amount": amount})

        with self._lock:
            structure_key, structure = self._structure_for_operation(structure_id)
            component_state = self._component_state(structure, component_id)
            view = component_state["view"]

            if view["destroyed"]:
                raise GraphError(
                    GRAPH_COMPONENT_GONE,
                    {"structure": structure_key, "component": component_id},
                )

            self._stats["damaged"] += 1
            view["durability"] = max(0, view["durability"] - amount)
            destroyed = view["durability"] == 0
            if destroyed:
                self._destroy_component(component_state)

            return {
                "structure": structure_key,
                "component": component_id,
                "durability": view["durability"],
                "destroyed": destroyed,
            }

    def evaluate_support(self, structure_id: str) -> list:
        with self._lock:
            _, structure = self._structure_for_operation(structure_id)
            grounded = self._grounded_reachable(structure)
            unstable = [
                component_id
                for component_id in structure["component_order"]
                if not structure["components"][component_id]["view"]["destroyed"]
                and component_id not in grounded
            ]
            return _sorted_identifiers(unstable)

    def collapse_region(self, structure_id: str, component_id: str) -> dict:
        with self._lock:
            structure_key, structure = self._structure_for_operation(structure_id)
            target_state = self._component_state(structure, component_id)
            target_view = target_state["view"]

            if target_view["destroyed"]:
                raise GraphError(
                    GRAPH_COMPONENT_GONE,
                    {"structure": structure_key, "component": component_id},
                )

            self._destroy_component(target_state)
            candidate_ids = self._collapse_candidates(structure, component_id)
            limit = self.max_collapse if _positive_int(self.max_collapse) else 0
            collapsed_ids = candidate_ids[:limit]
            pending = len(candidate_ids) - len(collapsed_ids)

            collapsed = []
            loot = []
            damaged = {}
            secondary_destroyed = set()

            for collapsed_id in collapsed_ids:
                collapsed_state = structure["components"][collapsed_id]
                collapsed_view = collapsed_state["view"]

                if not collapsed_view["destroyed"]:
                    self._destroy_component(collapsed_state)
                collapsed_state["collapsed"] = True
                collapsed.append(collapsed_id)
                self._stats["collapsed"] += 1

                material = collapsed_view.get("material")
                if material is None:
                    material = "unknown"
                loot_row = {
                    "item": f"{material}-rubble",
                    "material": material,
                    "quantity": 1,
                    "from": collapsed_id,
                }
                loot.append(loot_row)
                structure["loot"].append(loot_row)
                self._stats["loot"] += 1

                if not _positive_int(self.secondary_damage):
                    continue

                neighbor_ids = structure["neighbors"].get(collapsed_id, [])
                for neighbor_id in _sorted_identifiers(neighbor_ids):
                    neighbor_state = structure["components"][neighbor_id]
                    neighbor_view = neighbor_state["view"]
                    if neighbor_view["destroyed"]:
                        continue

                    neighbor_view["durability"] = max(
                        0,
                        neighbor_view["durability"] - self.secondary_damage,
                    )
                    damaged[neighbor_id] = neighbor_view["durability"]
                    if neighbor_view["durability"] == 0:
                        if self._destroy_component(neighbor_state):
                            secondary_destroyed.add(neighbor_id)

            return {
                "structure": structure_key,
                "collapsed": collapsed,
                "pending": pending,
                "secondary_destroyed": _sorted_identifiers(secondary_destroyed),
                "damaged": damaged,
                "loot": loot,
            }

    def settle_loot(self, structure_id: str) -> list:
        with self._lock:
            _, structure = self._structure_for_operation(structure_id)
            pending = structure["loot"]
            structure["loot"] = []
            return copy.deepcopy(pending)

    def repair(self, structure_id: str, component_id: str) -> dict:
        with self._lock:
            structure_key, structure = self._structure_for_operation(structure_id)
            component_state = self._component_state(structure, component_id)
            view = component_state["view"]

            if view["destroyed"]:
                raise GraphError(
                    GRAPH_COMPONENT_GONE,
                    {"structure": structure_key, "component": component_id},
                )

            view["durability"] = view["max_durability"]
            self._stats["repaired"] += 1

            return {
                "structure": structure_key,
                "component": component_id,
                "durability": view["durability"],
            }

    def reset(self, structure_id=None) -> int:
        with self._lock:
            if structure_id is None:
                component_count = 0
                for structure_key in list(self._structures):
                    component_count += self._reset_structure(structure_key)
                self._stats["resets"] += 1
                return component_count

            structure_key = self._structure_identifier(structure_id)
            if structure_key not in self._structures:
                raise GraphError(
                    GRAPH_STRUCTURE_UNKNOWN,
                    {"structure": structure_key},
                )

            component_count = self._reset_structure(structure_key)
            self._stats["resets"] += 1
            return component_count

    def component_of(self, structure_id: str, component_id: str) -> dict:
        with self._lock:
            _, structure = self._structure_for_operation(structure_id)
            component_state = self._component_state(structure, component_id)
            return copy.deepcopy(component_state["view"])

    def durability_of(self, structure_id: str, component_id: str) -> int:
        with self._lock:
            _, structure = self._structure_for_operation(structure_id)
            component_state = self._component_state(structure, component_id)
            return component_state["view"]["durability"]

    def pending_loot(self, structure_id: str) -> list:
        with self._lock:
            _, structure = self._structure_for_operation(structure_id)
            return copy.deepcopy(structure["loot"])

    def structures(self) -> list:
        with self._lock:
            return list(self._structures)

    def snapshot(self) -> dict:
        with self._lock:
            return copy.deepcopy(
                {
                    "version": _SNAPSHOT_VERSION,
                    "structures": self._structures,
                    "stats": self._stats,
                }
            )

    def restore(self, state: dict) -> None:
        if not isinstance(state, dict):
            raise GraphError(GRAPH_SNAPSHOT_INVALID, "snapshot must be a dict")

        with self._lock:
            try:
                self._validate_snapshot(state)
            except GraphError:
                raise
            except Exception as exc:
                raise GraphError(
                    GRAPH_SNAPSHOT_INVALID,
                    "malformed snapshot",
                ) from exc
            try:
                restored = copy.deepcopy(state)
            except Exception as exc:
                raise GraphError(
                    GRAPH_SNAPSHOT_INVALID,
                    "snapshot is not copyable",
                ) from exc

            self._structures = restored["structures"]
            self._stats = restored["stats"]

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)

    def _structure_identifier(self, structure_id: object) -> str:
        if not isinstance(structure_id, str):
            raise GraphError(GRAPH_INVALID_REQUEST, "structure id must be a string")
        structure_key = structure_id.strip()
        if not structure_key:
            raise GraphError(GRAPH_INVALID_REQUEST, "structure id must not be blank")
        return structure_key

    def _structure_for_operation(self, structure_id: object):
        structure_key = self._structure_identifier(structure_id)
        try:
            return structure_key, self._structures[structure_key]
        except KeyError as exc:
            raise GraphError(
                GRAPH_STRUCTURE_UNKNOWN,
                {"structure": structure_key},
            ) from exc

    @staticmethod
    def _component_state(structure: dict, component_id: object) -> dict:
        components = structure["components"]
        try:
            return components[component_id]
        except KeyError as exc:
            raise GraphError(
                GRAPH_COMPONENT_UNKNOWN,
                {"component": component_id},
            ) from exc
        except TypeError as exc:
            raise GraphError(
                GRAPH_COMPONENT_UNKNOWN,
                {"component": repr(component_id)},
            ) from exc

    def _destroy_component(self, component_state: dict) -> bool:
        view = component_state["view"]
        if view["destroyed"]:
            return False
        view["destroyed"] = True
        view["durability"] = 0
        self._stats["destroyed"] += 1
        return True

    def _grounded_reachable(self, structure: dict) -> set:
        reachable = set()
        queue = deque()

        for component_id in structure["component_order"]:
            view = structure["components"][component_id]["view"]
            if not view["destroyed"] and view.get("grounded"):
                reachable.add(component_id)
                queue.append(component_id)

        while queue:
            component_id = queue.popleft()
            for neighbor_id in structure["neighbors"].get(component_id, []):
                neighbor_state = structure["components"].get(neighbor_id)
                if neighbor_state is None:
                    continue
                neighbor_view = neighbor_state["view"]
                if neighbor_view["destroyed"] or neighbor_id in reachable:
                    continue
                reachable.add(neighbor_id)
                queue.append(neighbor_id)

        return reachable

    def _collapse_candidates(self, structure: dict, target_id: object) -> list:
        reachable = self._grounded_reachable(structure)
        failed_ids = _sorted_identifiers(
            component_id
            for component_id in structure["component_order"]
            if component_id not in reachable
            and not structure["components"][component_id]["collapsed"]
        )

        additional = [
            component_id
            for component_id in failed_ids
            if component_id != target_id
        ]
        return [target_id, *additional]

    def _reset_structure(self, structure_key: str) -> int:
        structure = self._structures[structure_key]
        structure["components"] = copy.deepcopy(structure["initial_states"])
        structure["loot"] = []
        return len(structure["component_order"])

    def _validate_snapshot(self, state: dict) -> None:
        if set(state) != {"version", "structures", "stats"}:
            raise GraphError(GRAPH_SNAPSHOT_INVALID, "invalid snapshot keys")

        version = state["version"]
        if type(version) is not int or version != _SNAPSHOT_VERSION:
            raise GraphError(GRAPH_SNAPSHOT_INVALID, "unsupported snapshot version")

        structures = state["structures"]
        if not isinstance(structures, dict):
            raise GraphError(GRAPH_SNAPSHOT_INVALID, "structures must be a dict")

        stats = state["stats"]
        if not isinstance(stats, dict) or set(stats) != set(_STAT_KEYS):
            raise GraphError(GRAPH_SNAPSHOT_INVALID, "invalid stats snapshot")

        for key in _STAT_KEYS:
            value = stats[key]
            if type(value) is not int or value < 0:
                raise GraphError(GRAPH_SNAPSHOT_INVALID, {"stat": key})

        for structure_id, structure in structures.items():
            if not isinstance(structure_id, str) or not structure_id.strip():
                raise GraphError(GRAPH_SNAPSHOT_INVALID, "invalid structure id")
            self._validate_structure_snapshot(structure_id, structure)

    def _validate_structure_snapshot(
        self,
        structure_id: str,
        structure: object,
    ) -> None:
        if not isinstance(structure, dict):
            raise GraphError(
                GRAPH_SNAPSHOT_INVALID,
                {"structure": structure_id},
            )

        required_keys = {
            "component_order",
            "components",
            "neighbors",
            "loot",
            "initial_states",
        }
        if not required_keys.issubset(structure):
            raise GraphError(
                GRAPH_SNAPSHOT_INVALID,
                {"structure": structure_id, "missing": "structure fields"},
            )

        order = structure["component_order"]
        components = structure["components"]
        if not isinstance(order, list) or not isinstance(components, dict):
            raise GraphError(GRAPH_SNAPSHOT_INVALID, {"structure": structure_id})

        try:
            if len(order) != len(set(order)) or set(order) != set(components):
                raise GraphError(
                    GRAPH_SNAPSHOT_INVALID,
                    {"structure": structure_id, "component_order": True},
                )
        except TypeError as exc:
            raise GraphError(
                GRAPH_SNAPSHOT_INVALID,
                {"structure": structure_id, "component_order": True},
            ) from exc

        for component_id in order:
            self._validate_component_snapshot(
                structure_id,
                component_id,
                components[component_id],
            )

        initial_states = structure["initial_states"]
        if not isinstance(initial_states, dict):
            raise GraphError(GRAPH_SNAPSHOT_INVALID, {"structure": structure_id})
        try:
            if set(initial_states) != set(components):
                raise GraphError(GRAPH_SNAPSHOT_INVALID, {"structure": structure_id})
        except TypeError as exc:
            raise GraphError(
                GRAPH_SNAPSHOT_INVALID,
                {"structure": structure_id},
            ) from exc
        for component_id, component_state in initial_states.items():
            self._validate_component_snapshot(
                structure_id,
                component_id,
                component_state,
                initial=True,
            )

        neighbors = structure["neighbors"]
        if not isinstance(neighbors, dict):
            raise GraphError(GRAPH_SNAPSHOT_INVALID, {"structure": structure_id})
        for component_id, neighbor_ids in neighbors.items():
            if component_id not in components or not isinstance(neighbor_ids, list):
                raise GraphError(GRAPH_SNAPSHOT_INVALID, {"structure": structure_id})
            for neighbor_id in neighbor_ids:
                if neighbor_id not in components:
                    raise GraphError(
                        GRAPH_SNAPSHOT_INVALID,
                        {"structure": structure_id, "neighbor": repr(neighbor_id)},
                    )

        loot = structure["loot"]
        if not isinstance(loot, list):
            raise GraphError(GRAPH_SNAPSHOT_INVALID, {"structure": structure_id})
        for row in loot:
            if not isinstance(row, dict):
                raise GraphError(GRAPH_SNAPSHOT_INVALID, {"structure": structure_id})
            if not {"item", "material", "quantity", "from"}.issubset(row):
                raise GraphError(GRAPH_SNAPSHOT_INVALID, {"structure": structure_id})
            if row["from"] not in components or type(row["quantity"]) is not int:
                raise GraphError(GRAPH_SNAPSHOT_INVALID, {"structure": structure_id})

    def _validate_component_snapshot(
        self,
        structure_id: str,
        component_id: object,
        component_state: object,
        *,
        initial: bool = False,
    ) -> None:
        if not isinstance(component_state, dict):
            raise GraphError(
                GRAPH_SNAPSHOT_INVALID,
                {"structure": structure_id, "component": repr(component_id)},
            )

        view = component_state.get("view")
        collapsed = component_state.get("collapsed")
        if not isinstance(view, dict) or type(collapsed) is not bool:
            raise GraphError(
                GRAPH_SNAPSHOT_INVALID,
                {"structure": structure_id, "component": repr(component_id)},
            )

        durability = view.get("durability")
        max_durability = view.get("max_durability")
        destroyed = view.get("destroyed")
        if (
            type(durability) is not int
            or durability < 0
            or type(max_durability) is not int
            or max_durability <= 0
            or type(destroyed) is not bool
        ):
            raise GraphError(
                GRAPH_SNAPSHOT_INVALID,
                {"structure": structure_id, "component": repr(component_id)},
            )

        if initial and (destroyed or collapsed or durability != max_durability):
            raise GraphError(
                GRAPH_SNAPSHOT_INVALID,
                {"structure": structure_id, "component": repr(component_id)},
            )
