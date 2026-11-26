"""Destruction support graph: component durability, support reachability, collapse."""

from __future__ import annotations

import threading


class GraphError(ValueError):
    """Raised when a destruction operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class DestructionSupportGraph:
    """Model breakable structures as components plus support edges."""

    def __init__(self, *, max_components: int = 256, max_collapse: int = 32,
                 default_durability: int = 100,
                 secondary_damage: int = 15) -> None:
        self.max_components = max_components
        self.max_collapse = max_collapse
        self.default_durability = default_durability
        self.secondary_damage = secondary_damage
        self._lock = threading.RLock()

    def register_structure(self, structure_id: str, components, edges, *,
                           region=None) -> dict:
        raise NotImplementedError

    def apply_damage(self, structure_id: str, component_id: str,
                     amount: int) -> dict:
        raise NotImplementedError

    def evaluate_support(self, structure_id: str) -> list:
        raise NotImplementedError

    def collapse_region(self, structure_id: str, component_id: str) -> dict:
        raise NotImplementedError

    def settle_loot(self, structure_id: str) -> list:
        raise NotImplementedError

    def repair(self, structure_id: str, component_id: str) -> dict:
        raise NotImplementedError

    def reset(self, structure_id=None) -> int:
        raise NotImplementedError

    def component_of(self, structure_id: str, component_id: str) -> dict:
        raise NotImplementedError

    def durability_of(self, structure_id: str, component_id: str) -> int:
        raise NotImplementedError

    def pending_loot(self, structure_id: str) -> list:
        raise NotImplementedError

    def structures(self) -> list:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
