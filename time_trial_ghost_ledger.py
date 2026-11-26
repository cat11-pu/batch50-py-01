"""Time trial ledger: checkpoint order, splits, ghosts and leaderboard.

One active run at a time per ledger records the checkpoint it expects
next, the cumulative time at each checkpoint and a sampling of the ghost
recording.  Finished laps are submitted with their checkpoint mask and the
leaderboard keeps only the fastest legal lap per player and track.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any

__all__ = [
    "TrialError",
    "LapRecord",
    "TimeTrialLedger",
]


class TrialError(ValueError):
    """Raised when a run or submission is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class LapRecord:
    """One finished lap as stored by the ledger."""

    lap_id: str
    player: str
    track_id: str
    total_ms: int
    splits_ms: tuple[int, ...]
    checkpoint_mask: int
    valid: bool
    finished_seq: int


class TimeTrialLedger:
    """Validate checkpoint order and keep the ghost and leaderboard data."""

    def __init__(self, *, checkpoint_count: int = 8, max_samples: int = 64,
                 max_laps_per_player: int = 5) -> None:
        for name, value in (
            ("checkpoint_count", checkpoint_count),
            ("max_samples", max_samples),
            ("max_laps_per_player", max_laps_per_player),
        ):
            if not _is_int(value) or value < 1:
                raise ValueError(f"{name} must be a positive integer")

        self.checkpoint_count = checkpoint_count
        self.max_samples = max_samples
        self.max_laps_per_player = max_laps_per_player
        self._lock = threading.RLock()
        self._active: dict[str, Any] | None = None
        self._laps: dict[str, LapRecord] = {}
        self._ghosts: dict[str, tuple[tuple[int, int], ...]] = {}
        self._board: dict[str, dict[str, str]] = {}
        self._stats = {
            "runs_started": 0,
            "laps_finished": 0,
            "submitted": 0,
            "rejected": 0,
            "invalidated": 0,
        }
        self._next_lap_seq = 1

    @property
    def _full_mask(self) -> int:
        return (1 << self.checkpoint_count) - 1

    def start_run(self, player: str, track_id: str = "default",
                  start_ms: int = 0) -> dict:
        """Open a new run for *player* on *track_id*."""
        with self._lock:
            if self._active is not None:
                raise TrialError("TRIAL_RUN_ACTIVE", self._run_view(self._active))
            if not isinstance(player, str) or not player:
                raise TrialError("TRIAL_INVALID_REQUEST", "player must be a string")
            if not isinstance(track_id, str) or not track_id:
                raise TrialError("TRIAL_INVALID_REQUEST", "track_id must be a string")
            if not _is_int(start_ms):
                raise TrialError("TRIAL_INVALID_REQUEST", "start_ms must be an integer")

            self._active = {
                "player": player,
                "track_id": track_id,
                "start_ms": start_ms,
                "latest_at_ms": start_ms,
                "last_total_ms": 0,
                "next_index": 0,
                "mask": 0,
                "splits_ms": [],
                "invalid": False,
                "invalid_reason": None,
                "backtracked": False,
                "backtrack_at": None,
                "ghost_samples": [(0, 0)],
            }
            self._stats["runs_started"] += 1
            return self._run_view(self._active)

    def checkpoint(self, index: int, at_ms: int) -> dict:
        """Record passing checkpoint *index* at *at_ms*."""
        with self._lock:
            run = self._active
            if run is None:
                raise TrialError("TRIAL_NO_ACTIVE_RUN")
            if run["invalid"]:
                raise TrialError("TRIAL_RUN_INVALID", run["invalid_reason"])
            if not _is_int(index) or not 0 <= index < self.checkpoint_count:
                raise TrialError(
                    "TRIAL_INVALID_REQUEST",
                    {
                        "index": index,
                        "checkpoint_count": self.checkpoint_count,
                    },
                )
            if not _is_int(at_ms):
                raise TrialError("TRIAL_INVALID_REQUEST", "at_ms must be an integer")
            if at_ms < run["start_ms"] or at_ms < run["latest_at_ms"]:
                raise TrialError("TRIAL_INVALID_REQUEST", "at_ms is not monotonic")

            total_ms = at_ms - run["start_ms"]
            run["latest_at_ms"] = at_ms

            if index > run["next_index"]:
                self._invalidate_run(run, "shortcut")
                raise TrialError(
                    "TRIAL_SHORTCUT",
                    {
                        "expected_index": run["next_index"],
                        "actual_index": index,
                    },
                )

            if index == run["next_index"]:
                if run["backtracked"]:
                    self._invalidate_run(run, "backtracking")
                    return self._checkpoint_view(run, index, None, total_ms, False)

                split_ms = total_ms - run["last_total_ms"]
                if split_ms < 0:
                    raise TrialError("TRIAL_INVALID_REQUEST", "at_ms precedes split time")
                run["splits_ms"].append(split_ms)
                run["last_total_ms"] = total_ms
                run["mask"] |= 1 << index
                run["next_index"] += 1
                self._append_sample(run, total_ms, index + 1)
                return self._checkpoint_view(run, index, split_ms, total_ms, False)

            if index == run["next_index"] - 1:
                # A second edge event for the current checkpoint is harmless,
                # but it must not rewrite the split or advance the mask.
                if run["backtracked"] and index > run["backtrack_at"]:
                    self._invalidate_run(run, "backtracking")
                return self._checkpoint_view(run, index, None, total_ms, True)

            if not run["backtracked"]:
                run["backtracked"] = True
                run["backtrack_at"] = index
            elif index > run["backtrack_at"]:
                self._invalidate_run(run, "backtracking")
            return self._checkpoint_view(run, index, None, total_ms, True)

    def finish_run(self, at_ms: int) -> LapRecord:
        """Close the active run and return the finished lap."""
        with self._lock:
            run = self._active
            if run is None:
                raise TrialError("TRIAL_NO_ACTIVE_RUN")
            if run["invalid"]:
                self._active = None
                raise TrialError("TRIAL_RUN_INVALID", run["invalid_reason"])
            if run["backtracked"]:
                self._invalidate_run(run, "backtracking")
                self._active = None
                raise TrialError("TRIAL_RUN_INVALID", run["invalid_reason"])
            if not _is_int(at_ms):
                raise TrialError("TRIAL_INVALID_REQUEST", "at_ms must be an integer")
            if at_ms < run["start_ms"]:
                raise TrialError("TRIAL_INVALID_REQUEST", "at_ms precedes run start")

            if run["mask"] != self._full_mask:
                raise TrialError(
                    "TRIAL_INCOMPLETE",
                    {
                        "mask": run["mask"],
                        "expected_mask": self._full_mask,
                        "missing_indices": tuple(
                            index
                            for index in range(self.checkpoint_count)
                            if not run["mask"] & (1 << index)
                        ),
                    },
                )

            total_ms = at_ms - run["start_ms"]
            raw_samples = [
                sample
                for sample in run["ghost_samples"]
                if sample[0] <= total_ms
            ]
            if not raw_samples:
                raw_samples.append((0, 0))
            if raw_samples and raw_samples[-1][0] == total_ms:
                raw_samples[-1] = (total_ms, self.checkpoint_count)
            else:
                raw_samples.append((total_ms, self.checkpoint_count))
            samples = self._compress_samples(raw_samples, self.max_samples)

            finished_seq = self._next_lap_seq
            lap_id = f"lap-{finished_seq}"
            lap = LapRecord(
                lap_id=lap_id,
                player=run["player"],
                track_id=run["track_id"],
                total_ms=total_ms,
                splits_ms=tuple(run["splits_ms"]),
                checkpoint_mask=run["mask"],
                valid=True,
                finished_seq=finished_seq,
            )

            self._next_lap_seq += 1
            self._laps[lap_id] = lap
            self._ghosts[lap_id] = samples
            self._active = None
            self._stats["laps_finished"] += 1
            return lap

    def validate(self, lap_id: str) -> dict:
        """Report whether a stored lap is legal."""
        with self._lock:
            lap = self._laps.get(lap_id) if isinstance(lap_id, str) else None
            if lap is None:
                return {
                    "lap_id": lap_id,
                    "valid": False,
                    "reasons": ("unknown_lap",),
                }

            reasons: list[str] = []
            if not lap.valid:
                reasons.append("marked_invalid")
            if lap.checkpoint_mask != self._full_mask:
                reasons.append("mask_mismatch")
            if len(lap.splits_ms) != self.checkpoint_count:
                reasons.append("split_count_mismatch")
            if not _is_int(lap.total_ms) or lap.total_ms < 0:
                reasons.append("invalid_total")
            samples = self._ghosts.get(lap.lap_id, ())
            if not samples or samples[-1][0] != lap.total_ms:
                reasons.append("ghost_duration_mismatch")

            return {
                "lap_id": lap.lap_id,
                "player": lap.player,
                "track_id": lap.track_id,
                "total_ms": lap.total_ms,
                "checkpoint_mask": lap.checkpoint_mask,
                "expected_mask": self._full_mask,
                "valid": not reasons,
                "reasons": tuple(reasons),
            }

    def submit(self, lap) -> dict:
        """Submit a lap to the leaderboard of its track."""
        with self._lock:
            if not isinstance(lap, LapRecord):
                self._stats["rejected"] += 1
                raise TrialError("TRIAL_INVALID_REQUEST", "lap must be a LapRecord")

            if not _is_int(lap.checkpoint_mask) or lap.checkpoint_mask != self._full_mask:
                self._stats["rejected"] += 1
                raise TrialError(
                    "TRIAL_MASK_MISMATCH",
                    {
                        "mask": lap.checkpoint_mask,
                        "expected_mask": self._full_mask,
                    },
                )
            if not lap.valid:
                self._stats["rejected"] += 1
                raise TrialError("TRIAL_RUN_INVALID", "lap is not legal")
            if (
                not isinstance(lap.player, str)
                or not isinstance(lap.track_id, str)
                or not _is_int(lap.total_ms)
                or lap.total_ms < 0
                or len(lap.splits_ms) != self.checkpoint_count
                or not _is_int(lap.finished_seq)
            ):
                self._stats["rejected"] += 1
                raise TrialError("TRIAL_INVALID_REQUEST", "malformed lap")

            canonical = self._laps.get(lap.lap_id)
            if canonical is not None and canonical != lap:
                self._stats["rejected"] += 1
                raise TrialError(
                    "TRIAL_INVALID_REQUEST",
                    "submitted lap differs from the stored lap",
                )
            if canonical is None:
                canonical = lap
                self._laps[lap.lap_id] = lap
                self._ghosts[lap.lap_id] = (
                    (0, 0),
                    (lap.total_ms, self.checkpoint_count),
                )

            player_board = self._board.setdefault(canonical.track_id, {})
            existing_id = player_board.get(canonical.player)
            if existing_id == canonical.lap_id:
                self._stats["rejected"] += 1
                return self._submission_result(canonical, False, "already_submitted")

            existing = self._laps.get(existing_id) if existing_id is not None else None
            if existing is not None and canonical.total_ms >= existing.total_ms:
                self._stats["rejected"] += 1
                return self._submission_result(canonical, False, "not_faster")

            player_board[canonical.player] = canonical.lap_id
            self._stats["submitted"] += 1
            rank = self._rank(canonical.track_id, canonical.lap_id)
            return self._submission_result(canonical, True, None, rank)

    def ghost_samples(self, lap_id: str,
                      max_samples: int | None = None) -> tuple[tuple[int, int], ...]:
        """Return the compressed ghost samples of a stored lap."""
        with self._lock:
            if max_samples is not None and (
                not _is_int(max_samples) or max_samples < 1
            ):
                raise TrialError("TRIAL_INVALID_REQUEST", "max_samples must be positive")
            samples = self._ghosts.get(lap_id)
            if samples is None:
                return ()
            limit = self.max_samples if max_samples is None else max_samples
            return self._compress_samples(samples, limit)

    def leaderboard(self, track_id: str | None = None,
                    limit: int = 10) -> tuple[dict, ...]:
        """Return the fastest legal laps of a track."""
        with self._lock:
            if not _is_int(limit) or limit < 0:
                raise TrialError("TRIAL_INVALID_REQUEST", "limit must be non-negative")
            track_ids = (
                [track_id]
                if track_id is not None
                else list(self._board)
            )
            entries = []
            for current_track in track_ids:
                for player, lap_id in self._board.get(current_track, {}).items():
                    lap = self._laps.get(lap_id)
                    if (
                        lap is None
                        or not lap.valid
                        or lap.checkpoint_mask != self._full_mask
                    ):
                        continue
                    entries.append(lap)
            entries.sort(
                key=lambda lap: (
                    lap.total_ms,
                    lap.finished_seq,
                    lap.track_id,
                    lap.player,
                    lap.lap_id,
                )
            )
            return tuple(
                self._lap_entry(lap, rank)
                for rank, lap in enumerate(entries[:limit], start=1)
            )

    def elapsed_ms(self) -> int:
        """Return the running time of the active run."""
        with self._lock:
            if self._active is None:
                return 0
            return self._active["latest_at_ms"] - self._active["start_ms"]

    def checkpoint_mask(self) -> int:
        """Return the checkpoint bitmask of the active run."""
        with self._lock:
            return 0 if self._active is None else self._active["mask"]

    def current_run(self) -> dict | None:
        """Return a description of the active run, or ``None``."""
        with self._lock:
            if self._active is None:
                return None
            return self._run_view(self._active)

    def best_of(self, player: str) -> dict | None:
        """Return the fastest submitted lap of *player*."""
        with self._lock:
            best: LapRecord | None = None
            for track, players in self._board.items():
                lap_id = players.get(player)
                if lap_id is None:
                    continue
                lap = self._laps.get(lap_id)
                if (
                    lap is None
                    or not lap.valid
                    or lap.checkpoint_mask != self._full_mask
                ):
                    continue
                if best is None or (
                    lap.total_ms,
                    lap.finished_seq,
                    lap.track_id,
                    lap.lap_id,
                ) < (
                    best.total_ms,
                    best.finished_seq,
                    best.track_id,
                    best.lap_id,
                ):
                    best = lap
            if best is None:
                return None
            return self._lap_entry(best, self._rank(best.track_id, best.lap_id))

    def snapshot(self) -> dict:
        """Return a detached copy of the active run, laps and counters."""
        with self._lock:
            laps = []
            for lap_id, lap in self._laps.items():
                laps.append(
                    {
                        "lap_id": lap.lap_id,
                        "player": lap.player,
                        "track_id": lap.track_id,
                        "total_ms": lap.total_ms,
                        "splits_ms": list(lap.splits_ms),
                        "checkpoint_mask": lap.checkpoint_mask,
                        "valid": lap.valid,
                        "finished_seq": lap.finished_seq,
                        "ghost_samples": [
                            [at_ms, value]
                            for at_ms, value in self._ghosts.get(lap_id, ())
                        ],
                    }
                )
            return {
                "version": 1,
                "config": {
                    "checkpoint_count": self.checkpoint_count,
                    "max_samples": self.max_samples,
                    "max_laps_per_player": self.max_laps_per_player,
                },
                "run": None if self._active is None else self._run_snapshot(self._active),
                "laps": laps,
                "board": {
                    track: dict(players)
                    for track, players in self._board.items()
                },
                "stats": dict(self._stats),
                "next_lap_seq": self._next_lap_seq,
            }

    def restore(self, state: dict) -> None:
        """Load a snapshot after validating its structure."""
        with self._lock:
            try:
                parsed = self._parse_snapshot(state)
            except TrialError:
                raise
            except (KeyError, TypeError, ValueError, IndexError) as exc:
                raise TrialError("TRIAL_SNAPSHOT_INVALID", str(exc)) from exc

            (
                checkpoint_count,
                max_samples,
                max_laps_per_player,
                active,
                laps,
                ghosts,
                board,
                stats,
                next_lap_seq,
            ) = parsed
            self.checkpoint_count = checkpoint_count
            self.max_samples = max_samples
            self.max_laps_per_player = max_laps_per_player
            self._active = active
            self._laps = laps
            self._ghosts = ghosts
            self._board = board
            self._stats = stats
            self._next_lap_seq = next_lap_seq

    def stats(self) -> dict:
        """Return cumulative counters for runs, laps and submissions."""
        with self._lock:
            return dict(self._stats)

    def _invalidate_run(self, run: dict[str, Any], reason: str) -> None:
        if not run["invalid"]:
            run["invalid"] = True
            run["invalid_reason"] = reason
            self._stats["invalidated"] += 1

    def _run_view(self, run: dict[str, Any]) -> dict:
        return {
            "player": run["player"],
            "track_id": run["track_id"],
            "start_ms": run["start_ms"],
            "elapsed_ms": run["latest_at_ms"] - run["start_ms"],
            "mask": run["mask"],
            "next_index": run["next_index"],
            "splits_ms": tuple(run["splits_ms"]),
            "invalid": run["invalid"],
            "invalid_reason": run["invalid_reason"],
        }

    def _checkpoint_view(
        self,
        run: dict[str, Any],
        index: int,
        split_ms: int | None,
        total_ms: int,
        duplicate: bool,
    ) -> dict:
        view = self._run_view(run)
        view.update(
            {
                "index": index,
                "split_ms": split_ms,
                "total_ms": total_ms,
                "duplicate": duplicate,
            }
        )
        return view

    @staticmethod
    def _append_sample(run: dict[str, Any], at_ms: int, value: int) -> None:
        samples = run["ghost_samples"]
        if samples and samples[-1][0] == at_ms:
            samples[-1] = (at_ms, value)
        else:
            samples.append((at_ms, value))

    @staticmethod
    def _compress_samples(
        samples: Any,
        limit: int,
    ) -> tuple[tuple[int, int], ...]:
        normalized = tuple((int(at_ms), int(value)) for at_ms, value in samples)
        if not normalized:
            return ()
        if limit <= 0:
            return ()
        if len(normalized) <= limit:
            return normalized
        if limit == 1:
            return (normalized[0], normalized[-1])

        last_index = len(normalized) - 1
        positions = [
            round(position * last_index / (limit - 1))
            for position in range(limit)
        ]
        positions[0] = 0
        positions[-1] = last_index
        return tuple(normalized[index] for index in positions)

    def _submission_result(
        self,
        lap: LapRecord,
        accepted: bool,
        reason: str | None,
        rank: int | None = None,
    ) -> dict:
        return {
            "accepted": accepted,
            "rank": rank,
            "lap_id": lap.lap_id,
            "player": lap.player,
            "track_id": lap.track_id,
            "total_ms": lap.total_ms,
            "reason": reason,
        }

    def _rank(self, track_id: str, lap_id: str) -> int | None:
        entries = []
        for player, player_lap_id in self._board.get(track_id, {}).items():
            lap = self._laps.get(player_lap_id)
            if (
                lap is not None
                and lap.valid
                and lap.checkpoint_mask == self._full_mask
            ):
                entries.append(lap)
        entries.sort(
            key=lambda item: (
                item.total_ms,
                item.finished_seq,
                item.player,
                item.lap_id,
            )
        )
        for rank, lap in enumerate(entries, start=1):
            if lap.lap_id == lap_id:
                return rank
        return None

    @staticmethod
    def _lap_entry(lap: LapRecord, rank: int) -> dict:
        return {
            "rank": rank,
            "lap_id": lap.lap_id,
            "player": lap.player,
            "track_id": lap.track_id,
            "total_ms": lap.total_ms,
            "splits_ms": tuple(lap.splits_ms),
            "checkpoint_mask": lap.checkpoint_mask,
            "valid": lap.valid,
            "finished_seq": lap.finished_seq,
        }

    @staticmethod
    def _run_snapshot(run: dict[str, Any]) -> dict:
        return {
            "player": run["player"],
            "track_id": run["track_id"],
            "start_ms": run["start_ms"],
            "latest_at_ms": run["latest_at_ms"],
            "last_total_ms": run["last_total_ms"],
            "next_index": run["next_index"],
            "mask": run["mask"],
            "splits_ms": list(run["splits_ms"]),
            "invalid": run["invalid"],
            "invalid_reason": run["invalid_reason"],
            "backtracked": run["backtracked"],
            "backtrack_at": run["backtrack_at"],
            "ghost_samples": [
                [at_ms, value]
                for at_ms, value in run["ghost_samples"]
            ],
        }

    def _parse_snapshot(self, state: Any) -> tuple:
        if not isinstance(state, dict):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "state must be a dict")
        if not _is_int(state.get("version")) or state.get("version") != 1:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "unsupported version")
        for key in ("run", "laps", "board", "stats"):
            if key not in state:
                raise TrialError("TRIAL_SNAPSHOT_INVALID", f"missing {key}")

        raw_config = state.get("config", {})
        if not isinstance(raw_config, dict):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "config must be a dict")
        checkpoint_count = raw_config.get("checkpoint_count", self.checkpoint_count)
        max_samples = raw_config.get("max_samples", self.max_samples)
        max_laps = raw_config.get(
            "max_laps_per_player",
            self.max_laps_per_player,
        )
        for name, value in (
            ("checkpoint_count", checkpoint_count),
            ("max_samples", max_samples),
            ("max_laps_per_player", max_laps),
        ):
            if not _is_int(value) or value < 1:
                raise TrialError(
                    "TRIAL_SNAPSHOT_INVALID",
                    f"invalid {name}",
                )
        full_mask = (1 << checkpoint_count) - 1

        raw_run = state["run"]
        active = None if raw_run is None else self._parse_run(raw_run, checkpoint_count)

        raw_laps = state["laps"]
        if not isinstance(raw_laps, list):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "laps must be a list")
        laps: dict[str, LapRecord] = {}
        ghosts: dict[str, tuple[tuple[int, int], ...]] = {}
        highest_seq = 0
        for raw_lap in raw_laps:
            lap, samples = self._parse_lap(raw_lap, checkpoint_count, full_mask)
            if lap.lap_id in laps:
                raise TrialError("TRIAL_SNAPSHOT_INVALID", "duplicate lap_id")
            laps[lap.lap_id] = lap
            ghosts[lap.lap_id] = samples
            highest_seq = max(highest_seq, lap.finished_seq)

        raw_board = state["board"]
        if not isinstance(raw_board, dict):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "board must be a dict")
        board: dict[str, dict[str, str]] = {}
        for track, players in raw_board.items():
            if not isinstance(track, str) or not isinstance(players, dict):
                raise TrialError("TRIAL_SNAPSHOT_INVALID", "malformed track board")
            current = board.setdefault(track, {})
            for player, lap_id in players.items():
                if not isinstance(player, str) or not isinstance(lap_id, str):
                    raise TrialError("TRIAL_SNAPSHOT_INVALID", "malformed board entry")
                lap = laps.get(lap_id)
                if (
                    lap is None
                    or lap.player != player
                    or lap.track_id != track
                    or not lap.valid
                    or lap.checkpoint_mask != full_mask
                ):
                    raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid board lap")
                current[player] = lap_id

        raw_stats = state["stats"]
        if not isinstance(raw_stats, dict):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "stats must be a dict")
        stats = {}
        for key in (
            "runs_started",
            "laps_finished",
            "submitted",
            "rejected",
            "invalidated",
        ):
            value = raw_stats.get(key)
            if not _is_int(value) or value < 0:
                raise TrialError("TRIAL_SNAPSHOT_INVALID", f"invalid stat {key}")
            stats[key] = value

        next_lap_seq = state.get("next_lap_seq", highest_seq + 1)
        if not _is_int(next_lap_seq) or next_lap_seq <= highest_seq:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid next_lap_seq")

        return (
            checkpoint_count,
            max_samples,
            max_laps,
            active,
            laps,
            ghosts,
            board,
            stats,
            next_lap_seq,
        )

    def _parse_run(self, raw_run: Any, checkpoint_count: int) -> dict[str, Any]:
        if not isinstance(raw_run, dict):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "run must be a dict or null")
        required = (
            "player",
            "track_id",
            "start_ms",
            "latest_at_ms",
            "last_total_ms",
            "next_index",
            "mask",
            "splits_ms",
            "invalid",
            "invalid_reason",
            "backtracked",
            "backtrack_at",
            "ghost_samples",
        )
        for key in required:
            if key not in raw_run:
                raise TrialError("TRIAL_SNAPSHOT_INVALID", f"run missing {key}")

        player = raw_run["player"]
        track_id = raw_run["track_id"]
        start_ms = raw_run["start_ms"]
        latest_at_ms = raw_run["latest_at_ms"]
        last_total_ms = raw_run["last_total_ms"]
        next_index = raw_run["next_index"]
        mask = raw_run["mask"]
        splits = raw_run["splits_ms"]
        invalid = raw_run["invalid"]
        invalid_reason = raw_run["invalid_reason"]
        backtracked = raw_run["backtracked"]
        backtrack_at = raw_run["backtrack_at"]
        samples = raw_run["ghost_samples"]

        if not isinstance(player, str) or not isinstance(track_id, str):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid run identity")
        if not _is_int(start_ms) or not _is_int(latest_at_ms):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid run time")
        if latest_at_ms < start_ms:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "run time is negative")
        if not _is_int(next_index) or not 0 <= next_index <= checkpoint_count:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid next_index")
        expected_mask = (1 << next_index) - 1
        if not _is_int(mask) or mask != expected_mask:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid run mask")
        if not isinstance(splits, list) or len(splits) != next_index:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid run splits")
        if any(not _is_int(split) or split < 0 for split in splits):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid split")
        if sum(splits) != last_total_ms:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "split total mismatch")
        if last_total_ms < 0 or last_total_ms > latest_at_ms - start_ms:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid run elapsed time")
        if not isinstance(invalid, bool) or not isinstance(backtracked, bool):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid run flags")
        if invalid and not isinstance(invalid_reason, str):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "missing run reason")
        if not invalid and invalid_reason is not None:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid run reason")
        if backtracked:
            if backtrack_at is None or (
                not _is_int(backtrack_at) or not 0 <= backtrack_at < next_index
            ):
                raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid backtrack index")
        elif backtrack_at is not None:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "unexpected backtrack index")
        parsed_samples = self._parse_samples(
            samples,
            maximum_ms=latest_at_ms - start_ms,
        )
        return {
            "player": player,
            "track_id": track_id,
            "start_ms": start_ms,
            "latest_at_ms": latest_at_ms,
            "last_total_ms": last_total_ms,
            "next_index": next_index,
            "mask": mask,
            "splits_ms": list(splits),
            "invalid": invalid,
            "invalid_reason": invalid_reason,
            "backtracked": backtracked,
            "backtrack_at": backtrack_at,
            "ghost_samples": list(parsed_samples),
        }

    def _parse_lap(
        self,
        raw_lap: Any,
        checkpoint_count: int,
        full_mask: int,
    ) -> tuple[LapRecord, tuple[tuple[int, int], ...]]:
        if not isinstance(raw_lap, dict):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "lap must be a dict")
        for key in (
            "lap_id",
            "player",
            "track_id",
            "total_ms",
            "splits_ms",
            "checkpoint_mask",
            "valid",
            "finished_seq",
            "ghost_samples",
        ):
            if key not in raw_lap:
                raise TrialError("TRIAL_SNAPSHOT_INVALID", f"lap missing {key}")

        lap_id = raw_lap["lap_id"]
        player = raw_lap["player"]
        track_id = raw_lap["track_id"]
        total_ms = raw_lap["total_ms"]
        splits = raw_lap["splits_ms"]
        checkpoint_mask = raw_lap["checkpoint_mask"]
        valid = raw_lap["valid"]
        finished_seq = raw_lap["finished_seq"]
        samples = raw_lap["ghost_samples"]

        if not isinstance(lap_id, str) or not isinstance(player, str):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid lap identity")
        if not isinstance(track_id, str):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid lap track")
        if not _is_int(total_ms) or total_ms < 0:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid lap time")
        if not isinstance(splits, list) or len(splits) != checkpoint_count:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid lap splits")
        if any(not _is_int(split) or split < 0 for split in splits):
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid lap split")
        if not _is_int(checkpoint_mask) or not 0 <= checkpoint_mask <= full_mask:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid lap mask")
        if not isinstance(valid, bool) or not _is_int(finished_seq) or finished_seq < 0:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "invalid lap flags")
        if valid and checkpoint_mask != full_mask:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "valid lap has incomplete mask")

        parsed_samples = self._parse_samples(samples, maximum_ms=total_ms)
        if not parsed_samples or parsed_samples[-1][0] != total_ms:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "lap ghost duration mismatch")

        lap = LapRecord(
            lap_id=lap_id,
            player=player,
            track_id=track_id,
            total_ms=total_ms,
            splits_ms=tuple(splits),
            checkpoint_mask=checkpoint_mask,
            valid=valid,
            finished_seq=finished_seq,
        )
        return lap, parsed_samples

    @staticmethod
    def _parse_samples(
        raw_samples: Any,
        *,
        maximum_ms: int,
    ) -> tuple[tuple[int, int], ...]:
        if not isinstance(raw_samples, list) or not raw_samples:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "ghost samples must be a list")
        samples = []
        previous_at = -1
        for raw_sample in raw_samples:
            if (
                not isinstance(raw_sample, (list, tuple))
                or len(raw_sample) != 2
                or not _is_int(raw_sample[0])
                or not _is_int(raw_sample[1])
            ):
                raise TrialError("TRIAL_SNAPSHOT_INVALID", "malformed ghost sample")
            at_ms, value = raw_sample
            if at_ms < previous_at or at_ms < 0 or at_ms > maximum_ms:
                raise TrialError("TRIAL_SNAPSHOT_INVALID", "ghost sample order")
            samples.append((at_ms, value))
            previous_at = at_ms
        if samples[0][0] != 0:
            raise TrialError("TRIAL_SNAPSHOT_INVALID", "ghost must start at zero")
        return tuple(samples)


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)
