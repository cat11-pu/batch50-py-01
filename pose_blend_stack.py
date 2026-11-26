"""Pose blend stack: ordered animation layers, masks, normalized overlay blending."""

from __future__ import annotations

import threading

__all__ = [
    "PoseError",
    "PoseBlendStack",
    "IDENTITY",
]

IDENTITY = (0.0, 0.0, 0.0, 1.0)


class PoseError(ValueError):
    """Raised when a pose stack request is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class PoseBlendStack:
    """Stack animation layers and evaluate one blended pose per bone."""

    def __init__(self, *, max_layers: int = 8, max_history: int = 8,
                 max_mask_bones: int = 64) -> None:
        self.max_layers = max_layers
        self.max_history = max_history
        self.max_mask_bones = max_mask_bones
        self._lock = threading.RLock()

    def add_layer(self, layer_id: str, *, mode: str = "override",
                  weight: float = 1.0, mask=None) -> None:
        raise NotImplementedError

    def set_weight(self, layer_id: str, weight: float) -> None:
        raise NotImplementedError

    def set_mask(self, layer_id: str, mask) -> None:
        raise NotImplementedError

    def push_pose(self, layer_id: str, pose) -> None:
        raise NotImplementedError

    def evaluate(self) -> dict:
        raise NotImplementedError

    def remove_layer(self, layer_id: str) -> None:
        raise NotImplementedError

    def layer_state(self, layer_id: str) -> dict:
        raise NotImplementedError

    def layers(self) -> tuple[str, ...]:
        raise NotImplementedError

    def set_limits(self, bone: str, low, high) -> None:
        raise NotImplementedError

    def history(self) -> tuple[dict, ...]:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
