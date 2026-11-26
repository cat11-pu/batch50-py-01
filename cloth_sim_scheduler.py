"""Cloth substep scheduling with fixed timestep and snapshot continuity."""

from __future__ import annotations

import threading


class ClothError(ValueError):
    """Raised when a cloth scheduling operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class ClothSimScheduler:
    """Allocate a per-frame substep budget across several cloth instances."""

    MAX_SUBSTEPS = 64
    NEAR_DISTANCE = 2.0
    MID_DISTANCE = 6.0

    def __init__(self, *, fixed_step: float = 1.0 / 120.0,
                 substep_budget: int = 8, damping: float = 2.0) -> None:
        if not isinstance(fixed_step, (int, float)) or fixed_step <= 0:
            raise ClothError("CLOTH_INVALID_ARGUMENT", fixed_step)
        if not isinstance(substep_budget, int) or isinstance(substep_budget, bool):
            raise ClothError("CLOTH_INVALID_ARGUMENT", substep_budget)
        if substep_budget < 1 or substep_budget > self.MAX_SUBSTEPS:
            raise ClothError("CLOTH_INVALID_ARGUMENT", substep_budget)
        if not isinstance(damping, (int, float)) or damping < 0:
            raise ClothError("CLOTH_INVALID_ARGUMENT", damping)
        self.fixed_step = float(fixed_step)
        self.substep_budget = substep_budget
        self.damping = float(damping)
        self._lock = threading.RLock()

    def register(self, cloth_id, *, vertices, pinned=(), rest=None,
                 distance=1.0, visible=True):
        raise NotImplementedError

    def unregister(self, cloth_id):
        raise NotImplementedError

    def set_budget(self, substeps):
        raise NotImplementedError

    def step(self, dt):
        raise NotImplementedError

    def state_of(self, cloth_id):
        raise NotImplementedError

    def positions_of(self, cloth_id):
        raise NotImplementedError

    def detach(self, cloth_id):
        raise NotImplementedError

    def collision_batch(self):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
