"""Animation blend tree with weight normalization, sync groups and layer masks."""

from __future__ import annotations

import threading


class BlendError(ValueError):
    """Raised when an animation blend operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class AnimationBlendTree:
    """Blend layered animation clips per bone with normalized weights."""

    def __init__(self, *, default_pose=None) -> None:
        if default_pose is not None:
            if not isinstance(default_pose, dict):
                raise BlendError("BLEND_INVALID_ARGUMENT", default_pose)
            for bone, value in default_pose.items():
                if not isinstance(bone, str) or not bone:
                    raise BlendError("BLEND_INVALID_ARGUMENT", bone)
                if not isinstance(value, (int, float)) or isinstance(value, bool):
                    raise BlendError("BLEND_INVALID_ARGUMENT", value)
        self.default_pose = dict(default_pose or {})
        self._lock = threading.RLock()

    def add_clip(self, clip_id, *, layer=0, length=1.0, weight=1.0,
                 phase=0.0, bones=None):
        raise NotImplementedError

    def remove_clip(self, clip_id):
        raise NotImplementedError

    def set_weight(self, clip_id, weight):
        raise NotImplementedError

    def set_phase(self, clip_id, phase):
        raise NotImplementedError

    def join_sync_group(self, group, clip_id):
        raise NotImplementedError

    def evaluate(self, time):
        raise NotImplementedError

    def set_layer_mask(self, layer, bones):
        raise NotImplementedError

    def pose_of(self, clip_id, time):
        raise NotImplementedError

    def snapshot(self):
        raise NotImplementedError

    def restore(self, state):
        raise NotImplementedError

    def stats(self):
        raise NotImplementedError
