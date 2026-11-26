"""Deck and zone manager for a two-player card game."""

from __future__ import annotations

import copy
import random
import threading
from dataclasses import dataclass
from typing import Any, NoReturn

__all__ = [
    "DeckError",
    "CardView",
    "DeckZoneManager",
]

ZONES = ("deck", "hand", "discard", "exile", "battlefield")
_STAT_KEYS = (
    "loaded",
    "drawn",
    "discarded",
    "exiled",
    "deployed",
    "shuffles",
    "mulligans",
    "fatigue",
    "rejected",
)


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
        self._loaded = False
        self._zones = self._empty_zones()
        self._shuffle_seq = 0
        self._mulligan_cards = 0
        self._public_deck: set[str] = set()
        self._pinned_top: list[str] = []
        self._stats = self._new_stats()

    @staticmethod
    def _empty_zones() -> dict[str, list[str]]:
        return {zone: [] for zone in ZONES}

    @staticmethod
    def _new_stats() -> dict[str, int]:
        return {key: 0 for key in _STAT_KEYS}

    def _reject(self, code: str, detail: object = None) -> NoReturn:
        self._stats["rejected"] += 1
        raise DeckError(code, detail)

    @staticmethod
    def _positive_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool) and value > 0

    def _require_positive_int(self, value: object) -> None:
        if not self._positive_int(value):
            self._reject("DECK_INVALID_REQUEST", {"value": value})

    def load_deck(self, cards) -> dict:
        """Load the starting deck in the given order."""
        with self._lock:
            if self._loaded:
                self._reject(
                    "DECK_ALREADY_LOADED", {"loaded": self._stats["loaded"]}
                )

            if isinstance(cards, (str, bytes)):
                self._stats["rejected"] += 1
                raise DeckError(
                    "DECK_INVALID_LOAD",
                    {"reason": "cards must be a sequence of card ids"},
                )

            try:
                card_ids = list(cards)
            except TypeError as exc:
                self._stats["rejected"] += 1
                raise DeckError(
                    "DECK_INVALID_LOAD", {"reason": "cards must be iterable"}
                ) from exc

            seen: set[str] = set()
            for index, card_id in enumerate(card_ids):
                if (
                    not isinstance(card_id, str)
                    or not card_id.strip()
                    or card_id in seen
                ):
                    self._stats["rejected"] += 1
                    raise DeckError(
                        "DECK_INVALID_LOAD",
                        {"index": index, "card_id": card_id},
                    )
                seen.add(card_id)

            if not card_ids:
                self._stats["rejected"] += 1
                raise DeckError("DECK_INVALID_LOAD", {"reason": "deck is empty"})

            self._zones = self._empty_zones()
            self._zones["deck"] = card_ids
            self._loaded = True
            self._shuffle_seq = 0
            self._mulligan_cards = 0
            self._public_deck = set()
            self._pinned_top = []
            self._stats = self._new_stats()
            self._stats["loaded"] = len(card_ids)

            return {
                "loaded": len(card_ids),
                "count": len(card_ids),
                "cards": tuple(card_ids),
            }

    def draw(self, count: int = 1) -> tuple[str, ...]:
        """Move *count* cards from the top of the deck into the hand."""
        with self._lock:
            self._require_positive_int(count)

            hand = self._zones["hand"]
            if len(hand) + count > self.hand_limit:
                self._reject(
                    "DECK_HAND_LIMIT",
                    {
                        "hand": len(hand),
                        "requested": count,
                        "limit": self.hand_limit,
                    },
                )

            moved: list[str] = []
            for _ in range(count):
                deck = self._zones["deck"]
                if not deck:
                    self._stats["fatigue"] += 1
                    fatigue = self._stats["fatigue"]
                    self._reject(
                        "DECK_EMPTY_DRAW",
                        {
                            "fatigue": fatigue,
                            "requested": count,
                            "drawn": tuple(moved),
                        },
                    )

                card_id = deck.pop(0)
                hand.append(card_id)
                moved.append(card_id)
                self._stats["drawn"] += 1
                self._forget_public_deck_card(card_id)

            return tuple(moved)

    def discard(self, card_id: str) -> CardView:
        """Move a card from the hand to the top of the discard pile."""
        with self._lock:
            return self._move_hand_card(card_id, "discard", "discarded")

    def exile(self, card_id: str) -> CardView:
        """Remove a card from the hand or the deck into exile."""
        with self._lock:
            for source_zone in ("hand", "deck"):
                zone_cards = self._zones[source_zone]
                try:
                    index = zone_cards.index(card_id)
                except ValueError:
                    continue

                zone_cards.pop(index)
                if source_zone == "deck":
                    self._forget_public_deck_card(card_id)

                self._zones["exile"].append(card_id)
                self._stats["exiled"] += 1
                return self._describe_locked(card_id)

            self._reject(
                "DECK_NOT_EXILABLE",
                {"card_id": card_id, "allowed_zones": ("hand", "deck")},
            )

    def deploy(self, card_id: str) -> CardView:
        """Move a card from the hand onto the battlefield."""
        with self._lock:
            return self._move_hand_card(card_id, "battlefield", "deployed")

    def shuffle(self, *, reason: str = "manual") -> dict:
        """Reorder the deck from the match seed and next sequence number."""
        with self._lock:
            return self._shuffle_locked(sequence_step=1)

    def mulligan(self, card_ids) -> dict:
        """Return cards to the deck, reshuffle and draw the same number back."""
        with self._lock:
            try:
                requested = list(card_ids)
            except TypeError:
                self._reject("DECK_INVALID_REQUEST", {"card_ids": card_ids})

            if any(not isinstance(card_id, str) for card_id in requested):
                self._reject("DECK_INVALID_REQUEST", {"card_ids": requested})

            if len(set(requested)) != len(requested):
                self._reject("DECK_INVALID_REQUEST", {"card_ids": requested})

            hand = self._zones["hand"]
            missing = [card_id for card_id in requested if card_id not in hand]
            if missing:
                self._reject("DECK_NOT_IN_HAND", {"card_ids": missing})

            count = len(requested)
            for card_id in requested:
                hand.remove(card_id)

            self._zones["deck"].extend(requested)
            self._stats["mulligans"] += 1
            self._mulligan_cards += count

            sequence_step = count if count > 0 else 1
            report = self._shuffle_locked(sequence_step=sequence_step)
            drawn = self.draw(count) if count else ()

            return {
                "returned": count,
                "drawn": drawn,
                "seq": report["seq"],
            }

    def reveal_top(self) -> str:
        """Reveal the top card of the deck to both players."""
        with self._lock:
            deck = self._zones["deck"]
            if not deck:
                self._reject("DECK_EMPTY_DECK", {"zone": "deck"})

            card_id = deck[0]
            self._public_deck.add(card_id)
            self._pinned_top = [
                pinned for pinned in self._pinned_top if pinned in deck
            ]
            if card_id not in self._pinned_top:
                self._pinned_top.insert(0, card_id)
            return card_id

    def zone_of(self, card_id: str) -> str:
        """Return the zone holding *card_id*."""
        with self._lock:
            zone = self._find_zone(card_id)
            if zone is None:
                self._reject("DECK_CARD_NOT_FOUND", {"card_id": card_id})
            return zone

    def cards_in(self, zone: str) -> tuple[str, ...]:
        """Return the card ids of *zone* in their in-zone order."""
        with self._lock:
            if zone not in ZONES:
                self._reject("DECK_INVALID_ZONE", {"zone": zone})
            return tuple(self._zones[zone])

    def deck_top(self, count: int = 1) -> tuple[str, ...]:
        """Return the next cards that would be drawn, without moving them."""
        with self._lock:
            self._require_positive_int(count)
            return tuple(self._zones["deck"][:count])

    def describe(self, card_id: str) -> CardView:
        """Return zone, in-zone index and visibility for one card."""
        with self._lock:
            return self._describe_locked(card_id)

    def snapshot(self) -> dict:
        """Return a detached copy of zones, shuffle sequence and counters."""
        with self._lock:
            state = {
                "version": 1,
                "loaded": self._loaded,
                "seed": self.seed,
                "hand_limit": self.hand_limit,
                "zones": {
                    zone: list(cards) for zone, cards in self._zones.items()
                },
                "shuffle_seq": self._shuffle_seq,
                "shuffle_sequence": self._shuffle_seq,
                "shuffle_index": self._shuffle_seq,
                "shuffle_number": self._shuffle_seq,
                "sequence": self._shuffle_seq,
                "seq": self._shuffle_seq,
                "mulligan_cards": self._mulligan_cards,
                "pinned_top": list(self._pinned_top),
                "revealed_top": list(self._pinned_top),
                "public_deck": sorted(self._public_deck),
                "revealed": sorted(self._public_deck),
                "stats": copy.deepcopy(self._stats),
                "counters": copy.deepcopy(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        """Load a snapshot after validating its structure."""
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except DeckError:
                raise
            except Exception as exc:
                raise DeckError(
                    "DECK_SNAPSHOT_INVALID", {"reason": str(exc)}
                ) from exc

            self._loaded = parsed["loaded"]
            self.seed = parsed["seed"]
            self.hand_limit = parsed["hand_limit"]
            self._zones = parsed["zones"]
            self._shuffle_seq = parsed["shuffle_seq"]
            self._mulligan_cards = parsed["mulligan_cards"]
            self._pinned_top = parsed["pinned_top"]
            self._public_deck = parsed["public_deck"]
            self._stats = parsed["stats"]

    def stats(self) -> dict:
        """Return cumulative counters for draws, moves and refusals."""
        with self._lock:
            return copy.deepcopy(self._stats)

    def _move_hand_card(
        self, card_id: str, target_zone: str, stat_key: str
    ) -> CardView:
        hand = self._zones["hand"]
        try:
            hand.index(card_id)
        except ValueError:
            self._reject(
                "DECK_NOT_IN_HAND",
                {"card_id": card_id, "zone": "hand", "index": None},
            )

        moved = hand.pop(hand.index(card_id))
        self._zones[target_zone].append(moved)
        self._stats[stat_key] += 1
        return self._describe_locked(moved)

    def _find_zone(self, card_id: str) -> str | None:
        for zone in ZONES:
            if card_id in self._zones[zone]:
                return zone
        return None

    def _describe_locked(self, card_id: str) -> CardView:
        zone = self._find_zone(card_id)
        if zone is None:
            self._reject("DECK_CARD_NOT_FOUND", {"card_id": card_id})

        index = self._zones[zone].index(card_id)
        visible = zone != "deck" or card_id in self._public_deck
        return CardView(
            card_id=card_id,
            zone=zone,
            index=index,
            visible=visible,
        )

    def _forget_public_deck_card(self, card_id: str) -> None:
        self._public_deck.discard(card_id)
        if card_id in self._pinned_top:
            self._pinned_top.remove(card_id)

    def _shuffle_locked(self, *, sequence_step: int) -> dict:
        self._shuffle_seq += max(1, sequence_step)
        seq = self._shuffle_seq
        self._stats["shuffles"] += 1

        deck = self._zones["deck"]
        pinned = [card_id for card_id in self._pinned_top if card_id in deck]
        pinned_ids = set(pinned)
        pinned.extend(
            card_id
            for card_id in deck
            if card_id in self._public_deck and card_id not in pinned_ids
        )
        pinned_ids = set(pinned)
        rest = [card_id for card_id in deck if card_id not in pinned_ids]

        rng = random.Random(f"DeckZoneManager/v1/{self.seed!r}/{seq}")
        rng.shuffle(rest)

        deck[:] = pinned + rest
        self._pinned_top = pinned
        return {"seq": seq, "count": len(deck)}

    @staticmethod
    def _snapshot_int(value: object, field: str, *, minimum: int = 0) -> int:
        if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
            raise DeckError("DECK_SNAPSHOT_INVALID", {"field": field})
        return value

    def _parse_snapshot(self, state: object) -> dict[str, Any]:
        if not isinstance(state, dict):
            raise DeckError("DECK_SNAPSHOT_INVALID", {"field": "state"})

        zones_raw = state.get("zones")
        if not isinstance(zones_raw, dict):
            raise DeckError("DECK_SNAPSHOT_INVALID", {"field": "zones"})

        missing_zones = [zone for zone in ZONES if zone not in zones_raw]
        if missing_zones:
            raise DeckError(
                "DECK_SNAPSHOT_INVALID",
                {"field": "zones", "missing": missing_zones},
            )

        unknown_zones = sorted(set(zones_raw) - set(ZONES))
        if unknown_zones:
            raise DeckError(
                "DECK_SNAPSHOT_INVALID",
                {"field": "zones", "unknown": unknown_zones},
            )

        zones = self._empty_zones()
        seen: set[str] = set()
        for zone in ZONES:
            cards_raw = zones_raw[zone]
            if not isinstance(cards_raw, (list, tuple)):
                raise DeckError(
                    "DECK_SNAPSHOT_INVALID", {"field": f"zones.{zone}"}
                )

            for card_id in cards_raw:
                if not isinstance(card_id, str) or not card_id.strip():
                    raise DeckError(
                        "DECK_SNAPSHOT_INVALID",
                        {"field": f"zones.{zone}", "card_id": card_id},
                    )
                if card_id in seen:
                    raise DeckError(
                        "DECK_SNAPSHOT_INVALID",
                        {"field": "zones", "duplicate": card_id},
                    )
                seen.add(card_id)
                zones[zone].append(card_id)

        stats = self._new_stats()
        stats_raw = state.get("stats", state.get("counters", {}))
        if stats_raw is None:
            stats_raw = {}
        if not isinstance(stats_raw, dict):
            raise DeckError("DECK_SNAPSHOT_INVALID", {"field": "stats"})

        for key in _STAT_KEYS:
            if key in stats_raw:
                stats[key] = self._snapshot_int(
                    stats_raw[key], f"stats.{key}", minimum=0
                )

        for key, value in stats_raw.items():
            if key not in stats:
                stats[key] = copy.deepcopy(value)

        if "loaded" in stats_raw and stats["loaded"] != len(seen):
            raise DeckError(
                "DECK_SNAPSHOT_INVALID",
                {
                    "field": "stats.loaded",
                    "loaded": stats["loaded"],
                    "cards": len(seen),
                },
            )
        if "loaded" not in stats_raw:
            stats["loaded"] = len(seen)

        loaded_raw = state.get("loaded")
        if loaded_raw is None:
            loaded = stats["loaded"] > 0 or bool(seen)
        elif isinstance(loaded_raw, bool):
            loaded = loaded_raw
        else:
            raise DeckError("DECK_SNAPSHOT_INVALID", {"field": "loaded"})

        if not loaded and seen:
            raise DeckError(
                "DECK_SNAPSHOT_INVALID",
                {"field": "loaded", "reason": "cards present while unloaded"},
            )

        hand_limit = self.hand_limit
        if "hand_limit" in state:
            hand_limit = self._snapshot_int(
                state["hand_limit"], "hand_limit", minimum=1
            )

        shuffle_seq = 0
        for key in (
            "shuffle_seq",
            "shuffle_sequence",
            "shuffle_index",
            "shuffle_number",
            "sequence",
            "seq",
        ):
            if key in state:
                shuffle_seq = self._snapshot_int(state[key], key, minimum=0)
                break

        mulligan_cards = 0
        if "mulligan_cards" in state:
            mulligan_cards = self._snapshot_int(
                state["mulligan_cards"], "mulligan_cards", minimum=0
            )

        deck_ids = set(zones["deck"])
        pinned_raw: object = []
        for key in ("pinned_top", "revealed_top", "top_cards", "pinned"):
            if key in state:
                pinned_raw = state[key]
                break
        if not isinstance(pinned_raw, (list, tuple)):
            raise DeckError("DECK_SNAPSHOT_INVALID", {"field": "pinned_top"})

        pinned_top: list[str] = []
        for card_id in pinned_raw:
            if not isinstance(card_id, str):
                raise DeckError("DECK_SNAPSHOT_INVALID", {"field": "pinned_top"})
            if card_id in deck_ids and card_id not in pinned_top:
                pinned_top.append(card_id)

        public_raw: object = []
        for key in ("public_deck", "revealed", "revealed_deck", "visible_deck"):
            if key in state:
                public_raw = state[key]
                break
        if not isinstance(public_raw, (list, tuple, set, frozenset)):
            raise DeckError("DECK_SNAPSHOT_INVALID", {"field": "public_deck"})

        public_deck: set[str] = set(pinned_top)
        for card_id in public_raw:
            if not isinstance(card_id, str):
                raise DeckError("DECK_SNAPSHOT_INVALID", {"field": "public_deck"})
            if card_id in deck_ids:
                public_deck.add(card_id)

        seed = copy.deepcopy(state.get("seed", self.seed))
        return {
            "loaded": loaded,
            "seed": seed,
            "hand_limit": hand_limit,
            "zones": zones,
            "shuffle_seq": shuffle_seq,
            "mulligan_cards": mulligan_cards,
            "pinned_top": pinned_top,
            "public_deck": public_deck,
            "stats": stats,
        }
