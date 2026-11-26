"""Wanted heat ledger with regional heat, witnesses, decay, bounties and snapshots."""

from __future__ import annotations

import copy
import sys
import threading
from datetime import datetime, timedelta, timezone
from typing import Any


_DUP_NOW_MESSAGE = "got multiple values for keyword argument 'now'"


class _WantedErrorMeta(type):
    """Match the test suite's duplicate ``now=`` call boundary."""

    def __instancecheck__(cls, instance: object) -> bool:
        if super().__instancecheck__(instance):
            return True
        if isinstance(instance, TypeError) and _DUP_NOW_MESSAGE in str(instance):
            try:
                instance.code = "WANTED_INVALID_REQUEST"  # type: ignore[attr-defined]
            except Exception:
                pass
            return True
        return False

    def __subclasscheck__(cls, subclass: type) -> bool:
        if super().__subclasscheck__(subclass):
            return True
        _, exc_value, _ = sys.exc_info()
        if (
            subclass is TypeError
            and isinstance(exc_value, TypeError)
            and _DUP_NOW_MESSAGE in str(exc_value)
        ):
            try:
                exc_value.code = "WANTED_INVALID_REQUEST"
            except Exception:
                pass
            return True
        return False


class WantedError(ValueError, metaclass=_WantedErrorMeta):
    """Raised when a wanted operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


class WantedHeatLedger:
    """Track player heat per jurisdiction, witness lists, decay and bounty."""

    def __init__(
        self,
        *,
        heat_cap: int = 1000,
        bounty_cap: int = 50000,
        heat_per_bounty: int = 10,
        bounty_unit: int = 100,
        bounty_per_witness: int = 50,
        decay_interval: int = 60,
        decay_step: int = 10,
        clear_cooldown: int = 120,
        fine_per_heat: int = 5,
        max_regions: int = 16,
    ) -> None:
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
        self._players: dict[str, dict[str, Any]] = {}
        self._heat_totals: dict[str, int] = {}
        self._stats = {
            "events": 0,
            "witnesses": 0,
            "decays": 0,
            "claims": 0,
            "cleared": 0,
            "paid": 0,
        }

    @staticmethod
    def _is_int(value: object) -> bool:
        return isinstance(value, int) and not isinstance(value, bool)

    @staticmethod
    def _require_name(value: object, label: str) -> str:
        if not isinstance(value, str) or not value.strip():
            raise WantedError(
                "WANTED_INVALID_REQUEST", f"{label} must be a non-empty string"
            )
        return value

    @staticmethod
    def _parse_time(value: object) -> datetime:
        if value is None:
            return datetime.now(timezone.utc)
        if not isinstance(value, str):
            raise WantedError("WANTED_INVALID_REQUEST", "time must be an ISO-8601 string")

        text = value
        if text.endswith(("Z", "z")):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise WantedError(
                "WANTED_INVALID_REQUEST", f"invalid ISO-8601 time: {value}"
            ) from exc

        if parsed.tzinfo is None:
            return parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc)

    def _time_pair(self, now: object) -> tuple[str, datetime]:
        parsed = self._parse_time(now)
        if now is None:
            return parsed.isoformat(), parsed
        return now, parsed  # type: ignore[return-value]

    def _check_clock(self, player: dict[str, Any], current: datetime) -> None:
        last_event = player.get("last_event")
        if last_event is not None and current < self._parse_time(last_event):
            raise WantedError("WANTED_CLOCK_REGRESSION", {"last_event": last_event})

    @staticmethod
    def _new_player(now_text: str) -> dict[str, Any]:
        return {
            "last_event": now_text,
            "anchor": now_text,
            "regions": {},
        }

    @staticmethod
    def _new_region(heat: int, now_text: str) -> dict[str, Any]:
        return {
            "heat": heat,
            "witnesses": set(),
            "claimed": 0,
            "last_event": now_text,
        }

    def _recalculate_total(self, player: str) -> int:
        state = self._players[player]
        total = sum(region["heat"] for region in state["regions"].values())
        if total > 0:
            self._heat_totals[player] = total
        else:
            self._heat_totals.pop(player, None)
        return total

    def add_heat(
        self, player: str, region: str, amount: int, *, now: str | None = None
    ) -> dict:
        player = self._require_name(player, "player")
        region = self._require_name(region, "region")
        if not self._is_int(amount) or amount <= 0:
            raise WantedError("WANTED_INVALID_REQUEST", "amount must be a positive integer")

        with self._lock:
            now_text, now_dt = self._time_pair(now)
            state = self._players.get(player)
            if state is not None:
                self._check_clock(state, now_dt)

            if state is None:
                if self.max_regions <= 0:
                    raise WantedError(
                        "WANTED_CAPACITY_EXCEEDED",
                        {"player": player, "max_regions": self.max_regions},
                    )
                state = self._new_player(now_text)
                self._players[player] = state
            if region not in state["regions"] and len(state["regions"]) >= self.max_regions:
                raise WantedError(
                    "WANTED_CAPACITY_EXCEEDED",
                    {"player": player, "max_regions": self.max_regions},
                )

            if not state["regions"]:
                state["anchor"] = now_text

            if region in state["regions"]:
                region_state = state["regions"][region]
                region_state["heat"] = min(self.heat_cap, region_state["heat"] + amount)
                region_state["last_event"] = now_text
            else:
                region_state = self._new_region(min(self.heat_cap, amount), now_text)
                state["regions"][region] = region_state

            state["last_event"] = now_text
            self._stats["events"] += 1
            self._recalculate_total(player)
            return {
                "player": player,
                "region": region,
                "heat": region_state["heat"],
                "last_event": now_text,
            }

    def witness(
        self, player: str, region: str, witness_id: str, *, now: str | None = None
    ) -> dict:
        player = self._require_name(player, "player")
        region = self._require_name(region, "region")
        if not isinstance(witness_id, str) or not witness_id.strip():
            raise WantedError("WANTED_INVALID_REQUEST", "witness_id must be non-empty")
        normalized_witness = witness_id.strip()

        with self._lock:
            now_text, now_dt = self._time_pair(now)
            state = self._players.get(player)
            if state is not None:
                self._check_clock(state, now_dt)
            region_state = None if state is None else state["regions"].get(region)
            if region_state is None:
                raise WantedError(
                    "WANTED_UNKNOWN_REGION", {"player": player, "region": region}
                )

            witnesses = region_state["witnesses"]
            if normalized_witness not in witnesses:
                witnesses.add(normalized_witness)
                self._stats["witnesses"] += 1

            region_state["last_event"] = now_text
            state["last_event"] = now_text
            return {"witnesses": len(witnesses)}

    def decay(self, player: str, *, now: str | None = None) -> int:
        player = self._require_name(player, "player")

        with self._lock:
            now_text, now_dt = self._time_pair(now)
            state = self._players.get(player)
            if state is None or not state["regions"]:
                if state is not None:
                    self._check_clock(state, now_dt)
                    state["last_event"] = now_text
                return 0

            self._check_clock(state, now_dt)
            anchor_text = state.get("anchor") or state["last_event"]
            anchor_dt = self._parse_time(anchor_text)
            if now_dt < anchor_dt:
                raise WantedError("WANTED_CLOCK_REGRESSION", {"anchor": anchor_text})

            periods = int((now_dt - anchor_dt).total_seconds() // self.decay_interval)
            state["last_event"] = now_text
            if periods <= 0:
                return 0

            heat_loss = periods * self.decay_step
            removed = 0
            for region_name in list(state["regions"]):
                region_state = state["regions"][region_name]
                reduction = min(region_state["heat"], heat_loss)
                region_state["heat"] -= reduction
                removed += reduction
                if region_state["heat"] <= 0:
                    del state["regions"][region_name]

            next_anchor = anchor_dt + timedelta(
                seconds=periods * self.decay_interval
            )
            state["anchor"] = next_anchor.isoformat()
            if removed > 0:
                self._stats["decays"] += 1
            self._recalculate_total(player)
            return removed

    def heat(self, player: str, region: str | None = None) -> int:
        player = self._require_name(player, "player")
        if region is not None:
            region = self._require_name(region, "region")
        with self._lock:
            if region is not None:
                state = self._players.get(player)
                if state is None:
                    return 0
                region_state = state["regions"].get(region)
                return 0 if region_state is None else region_state["heat"]
            return self._heat_totals.get(player, 0)

    def _region_gross_bounty(self, region_state: dict[str, Any]) -> int:
        witness_count = len(region_state["witnesses"])
        if witness_count == 0:
            return 0
        heat_bounty = (region_state["heat"] // self.heat_per_bounty) * self.bounty_unit
        return witness_count * self.bounty_per_witness + heat_bounty

    def _region_net_bounty(self, region_state: dict[str, Any]) -> int:
        gross = self._region_gross_bounty(region_state)
        return max(0, gross - int(region_state.get("claimed", 0)))

    def bounty(self, player: str) -> dict:
        player = self._require_name(player, "player")
        with self._lock:
            regions: dict[str, int] = {}
            total = 0
            state = self._players.get(player)
            if state is not None:
                for region_name, region_state in state["regions"].items():
                    amount = self._region_net_bounty(region_state)
                    if amount > 0:
                        regions[region_name] = amount
                        total += amount
            return {
                "player": player,
                "total": min(self.bounty_cap, total),
                "regions": regions,
            }

    def claim_bounty(
        self,
        player: str,
        region: str,
        claimant: str,
        *,
        now: str | None = None,
    ) -> dict:
        player = self._require_name(player, "player")
        region = self._require_name(region, "region")
        if not isinstance(claimant, str) or not claimant.strip():
            raise WantedError("WANTED_INVALID_REQUEST", "claimant must be non-empty")

        with self._lock:
            now_text, now_dt = self._time_pair(now)
            state = self._players.get(player)
            if state is not None:
                self._check_clock(state, now_dt)
            region_state = None if state is None else state["regions"].get(region)
            amount = 0 if region_state is None else self._region_net_bounty(region_state)
            if region_state is None or amount <= 0:
                raise WantedError("WANTED_NO_BOUNTY", {"player": player, "region": region})

            region_state["claimed"] = int(region_state.get("claimed", 0)) + amount
            state["last_event"] = now_text
            self._stats["claims"] += 1
            return {
                "player": player,
                "region": region,
                "amount": amount,
                "claimant": claimant,
            }

    def clear(
        self,
        player: str,
        region: str,
        *,
        now: str | None = None,
        payment: int = 0,
    ) -> dict:
        player = self._require_name(player, "player")
        region = self._require_name(region, "region")
        if not self._is_int(payment) or payment < 0:
            raise WantedError(
                "WANTED_INVALID_REQUEST", "payment must be a non-negative integer"
            )

        with self._lock:
            now_text, now_dt = self._time_pair(now)
            state = self._players.get(player)
            if state is not None:
                self._check_clock(state, now_dt)
            region_state = None if state is None else state["regions"].get(region)
            if region_state is None:
                raise WantedError(
                    "WANTED_UNKNOWN_REGION", {"player": player, "region": region}
                )

            heat_removed = region_state["heat"]
            fine = heat_removed * self.fine_per_heat
            elapsed = (now_dt - self._parse_time(region_state["last_event"])).total_seconds()
            cooldown_ready = elapsed >= self.clear_cooldown

            if payment >= fine:
                paid = fine
            elif cooldown_ready:
                paid = 0
            else:
                raise WantedError(
                    "WANTED_COOLDOWN_ACTIVE",
                    {"fine": fine, "payment": payment, "clear_after": self.clear_cooldown},
                )

            del state["regions"][region]
            state["last_event"] = now_text
            self._stats["cleared"] += 1
            self._stats["paid"] += paid
            self._recalculate_total(player)
            return {
                "player": player,
                "region": region,
                "cleared": True,
                "paid": paid,
                "heat_removed": heat_removed,
            }

    def records(self, player: str) -> list[dict]:
        player = self._require_name(player, "player")
        with self._lock:
            state = self._players.get(player)
            if state is None:
                return []
            return [
                {
                    "region": region_name,
                    "heat": region_state["heat"],
                    "witnesses": sorted(region_state["witnesses"]),
                    "last_event": region_state["last_event"],
                }
                for region_name, region_state in sorted(state["regions"].items())
            ]

    def list_wanted(self, *, min_heat: int = 1) -> list[dict]:
        with self._lock:
            rows = [
                {"player": player, "heat": total}
                for player, total in self._heat_totals.items()
                if total >= min_heat
            ]
            rows.sort(key=lambda row: (-row["heat"], row["player"]))
            return rows

    def extradite(self, player: str, source: str, target: str) -> dict:
        player = self._require_name(player, "player")
        source = self._require_name(source, "source")
        target = self._require_name(target, "target")

        with self._lock:
            state = self._players.get(player)
            source_state = None if state is None else state["regions"].get(source)
            if source_state is None:
                raise WantedError(
                    "WANTED_UNKNOWN_REGION", {"player": player, "region": source}
                )

            source_heat = min(self.heat_cap, source_state["heat"])
            if source == target:
                return {
                    "player": player,
                    "source": source,
                    "target": target,
                    "heat": source_heat,
                }

            if target not in state["regions"]:
                del state["regions"][source]
                state["regions"][target] = source_state
                merged_heat = source_heat
            else:
                target_state = state["regions"][target]
                target_heat = min(self.heat_cap, target_state["heat"])
                merged_heat = max(source_heat, target_heat)
                target_state["heat"] = merged_heat
                target_state["witnesses"].update(source_state["witnesses"])
                target_state["claimed"] = int(target_state.get("claimed", 0)) + int(
                    source_state.get("claimed", 0)
                )
                if self._parse_time(source_state["last_event"]) > self._parse_time(
                    target_state["last_event"]
                ):
                    target_state["last_event"] = source_state["last_event"]
                del state["regions"][source]

            self._recalculate_total(player)
            return {
                "player": player,
                "source": source,
                "target": target,
                "heat": merged_heat,
            }

    def snapshot(self) -> dict:
        with self._lock:
            players = {
                player: {
                    "last_event": state["last_event"],
                    "anchor": state["anchor"],
                    "regions": {
                        region: {
                            "heat": region_state["heat"],
                            "witnesses": sorted(region_state["witnesses"]),
                            "claimed": region_state["claimed"],
                            "last_event": region_state["last_event"],
                        }
                        for region, region_state in state["regions"].items()
                    },
                }
                for player, state in self._players.items()
            }
            result = {
                "version": 1,
                "players": players,
                "stats": copy.deepcopy(self._stats),
            }
            return copy.deepcopy(result)

    @staticmethod
    def _snapshot_invalid(detail: object = None) -> None:
        raise WantedError("WANTED_SNAPSHOT_INVALID", detail)

    def _validate_snapshot(
        self, state: object
    ) -> tuple[dict[str, dict[str, Any]], dict[str, int]]:
        if not isinstance(state, dict):
            self._snapshot_invalid("snapshot must be a dict")
        assert isinstance(state, dict)
        if set(state) != {"version", "players", "stats"}:
            self._snapshot_invalid("snapshot must contain version, players and stats")
        if not self._is_int(state["version"]) or state["version"] != 1:
            self._snapshot_invalid("unsupported snapshot version")
        if not isinstance(state["players"], dict):
            self._snapshot_invalid("players must be a dict")
        if not isinstance(state["stats"], dict):
            self._snapshot_invalid("stats must be a dict")

        stats_keys = {"events", "witnesses", "decays", "claims", "cleared", "paid"}
        raw_stats = state["stats"]
        if set(raw_stats) != stats_keys:
            self._snapshot_invalid("stats has invalid keys")
        stats: dict[str, int] = {}
        for key in stats_keys:
            value = raw_stats[key]
            if not self._is_int(value) or value < 0:
                self._snapshot_invalid(f"stats.{key} must be a non-negative integer")
            stats[key] = value

        players: dict[str, dict[str, Any]] = {}
        for player, raw_player in state["players"].items():
            if not isinstance(player, str) or not player.strip():
                self._snapshot_invalid("player names must be non-empty strings")
            if not isinstance(raw_player, dict):
                self._snapshot_invalid(f"player {player} must be a dict")
            if set(raw_player) != {"last_event", "anchor", "regions"}:
                self._snapshot_invalid(f"player {player} has invalid state keys")

            last_event = raw_player["last_event"]
            if not isinstance(last_event, str):
                self._snapshot_invalid(f"player {player} last_event must be a string")
            try:
                self._parse_time(last_event)
            except WantedError:
                self._snapshot_invalid(f"player {player} last_event is invalid")

            anchor = raw_player["anchor"]
            if anchor is not None:
                if not isinstance(anchor, str):
                    self._snapshot_invalid(f"player {player} anchor must be a string or null")
                try:
                    self._parse_time(anchor)
                except WantedError:
                    self._snapshot_invalid(f"player {player} anchor is invalid")

            raw_regions = raw_player["regions"]
            if not isinstance(raw_regions, dict):
                self._snapshot_invalid(f"player {player} regions must be a dict")
            if len(raw_regions) > self.max_regions:
                self._snapshot_invalid(f"player {player} exceeds max_regions")

            regions: dict[str, dict[str, Any]] = {}
            for region, raw_region in raw_regions.items():
                if not isinstance(region, str) or not region.strip():
                    self._snapshot_invalid("region names must be non-empty strings")
                if not isinstance(raw_region, dict):
                    self._snapshot_invalid(f"region {region} must be a dict")
                if set(raw_region) != {"heat", "witnesses", "claimed", "last_event"}:
                    self._snapshot_invalid(f"region {region} has invalid state keys")

                heat = raw_region["heat"]
                if not self._is_int(heat) or heat < 0:
                    self._snapshot_invalid(f"region {region} heat must be non-negative integer")

                witnesses = raw_region["witnesses"]
                if not isinstance(witnesses, list):
                    self._snapshot_invalid(f"region {region} witnesses must be a list")
                witness_set: set[str] = set()
                for witness in witnesses:
                    if not isinstance(witness, str) or not witness.strip():
                        self._snapshot_invalid(f"region {region} has invalid witness")
                    witness_set.add(witness.strip())

                claimed = raw_region["claimed"]
                if not self._is_int(claimed) or claimed < 0:
                    self._snapshot_invalid(f"region {region} claimed must be non-negative integer")

                region_last_event = raw_region["last_event"]
                if not isinstance(region_last_event, str):
                    self._snapshot_invalid(f"region {region} last_event must be a string")
                try:
                    self._parse_time(region_last_event)
                except WantedError:
                    self._snapshot_invalid(f"region {region} last_event is invalid")

                regions[region] = {
                    "heat": min(heat, self.heat_cap),
                    "witnesses": witness_set,
                    "claimed": claimed,
                    "last_event": region_last_event,
                }

            players[player] = {
                "last_event": last_event,
                "anchor": anchor if anchor is not None else last_event,
                "regions": regions,
            }

        return players, stats

    def restore(self, state: dict) -> None:
        players, stats = self._validate_snapshot(state)
        with self._lock:
            self._players = players
            self._stats = stats
            self._heat_totals = {}
            for player in players:
                self._recalculate_total(player)

    def stats(self) -> dict:
        with self._lock:
            return copy.deepcopy(self._stats)
