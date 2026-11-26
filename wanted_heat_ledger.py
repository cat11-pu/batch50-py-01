"""Wanted heat ledger: per-region heat, witness testimony, decay, bounty settlement."""

from __future__ import annotations

import threading


class WantedError(ValueError):
    """Raised when a wanted operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class WantedHeatLedger:
    """Track player heat per jurisdiction, witness lists, decay and bounty."""

    def __init__(self, *, heat_cap: int = 1000, bounty_cap: int = 50000,
                 heat_per_bounty: int = 10, bounty_unit: int = 100,
                 bounty_per_witness: int = 50, decay_interval: int = 60,
                 decay_step: int = 10, clear_cooldown: int = 120,
                 fine_per_heat: int = 5, max_regions: int = 16) -> None:
        self.heat_cap = heat_cap
        self.bounty_cap = bounty_cap
        self.heat_per_bounty = heat_per_bounty
        self.bounty_unit = bounty_unit
        self.bounty_per_witness = bounty_per_witness
        self.decay_interval = decay_interval
        self.decay_step = decay_step
        self.clear_cooldown = clear_cooldown
        self.fine_per_heat = fine_per_heat
        self.max_regions = max_regions
        self._lock = threading.RLock()

    def add_heat(self, player: str, region: str, amount: int, *, now=None) -> dict:
        raise NotImplementedError

    def witness(self, player: str, region: str, witness_id: str, *,
                now=None) -> dict:
        raise NotImplementedError

    def decay(self, player: str, *, now=None) -> int:
        raise NotImplementedError

    def heat(self, player: str, region=None) -> int:
        raise NotImplementedError

    def bounty(self, player: str) -> dict:
        raise NotImplementedError

    def claim_bounty(self, player: str, region: str, claimant: str, *,
                     now=None) -> dict:
        raise NotImplementedError

    def clear(self, player: str, region: str, *, now=None,
              payment: int = 0) -> dict:
        raise NotImplementedError

    def records(self, player: str) -> list:
        raise NotImplementedError

    def list_wanted(self, *, min_heat: int = 1) -> list:
        raise NotImplementedError

    def extradite(self, player: str, source: str, target: str) -> dict:
        raise NotImplementedError

    def snapshot(self) -> dict:
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        raise NotImplementedError

    def stats(self) -> dict:
        raise NotImplementedError
