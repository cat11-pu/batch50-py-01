"""Deck and zone manager for a two-player card game.

Tracks every card instance across the deck, hand, discard pile, exile and
battlefield, keeps the in-zone position of each card and derives shuffle
orders from the match seed plus a shuffle sequence number so that a match
can be replayed move for move.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass

__all__ = [
    "DeckError",
    "CardView",
    "DeckZoneManager",
]

ZONES = ("deck", "hand", "discard", "exile", "battlefield")


class DeckError(ValueError):
    """Raised when a zone operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class CardView:
    """Where one card instance currently sits."""

    card_id: str
    zone: str
    index: int
    visible: bool


class DeckZoneManager:
    """Move card instances between zones with deterministic shuffles."""

    def __init__(self, *, seed: int = 0, hand_limit: int = 8) -> None:
        self.seed = seed
        self.hand_limit = hand_limit
        self._lock = threading.RLock()

    def load_deck(self, cards) -> dict:
        """Load the starting deck in the given order."""
        raise NotImplementedError

    def draw(self, count: int = 1) -> tuple[str, ...]:
        """Move *count* cards from the top of the deck into the hand."""
        raise NotImplementedError

    def discard(self, card_id: str) -> CardView:
        """Move a card from the hand to the top of the discard pile."""
        raise NotImplementedError

    def exile(self, card_id: str) -> CardView:
        """Remove a card from the hand or the deck into exile."""
        raise NotImplementedError

    def deploy(self, card_id: str) -> CardView:
        """Move a card from the hand onto the battlefield."""
        raise NotImplementedError

    def shuffle(self, *, reason: str = "manual") -> dict:
        """Reorder the deck using the match seed and the next shuffle sequence."""
        raise NotImplementedError

    def mulligan(self, card_ids) -> dict:
        """Return cards to the deck, reshuffle and draw the same number back."""
        raise NotImplementedError

    def reveal_top(self) -> str:
        """Reveal the top card of the deck to both players."""
        raise NotImplementedError

    def zone_of(self, card_id: str) -> str:
        """Return the zone holding *card_id*."""
        raise NotImplementedError

    def cards_in(self, zone: str) -> tuple[str, ...]:
        """Return the card ids of *zone* in their in-zone order."""
        raise NotImplementedError

    def deck_top(self, count: int = 1) -> tuple[str, ...]:
        """Return the next cards that would be drawn, without moving them."""
        raise NotImplementedError

    def describe(self, card_id: str) -> CardView:
        """Return zone, in-zone index and visibility for one card."""
        raise NotImplementedError

    def snapshot(self) -> dict:
        """Return a detached copy of zones, shuffle sequence and counters."""
        raise NotImplementedError

    def restore(self, state: dict) -> None:
        """Load a snapshot after validating its structure."""
        raise NotImplementedError

    def stats(self) -> dict:
        """Return cumulative counters for draws, moves and refusals."""
        raise NotImplementedError
