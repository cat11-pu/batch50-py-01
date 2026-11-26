"""Rhythm chart judge: timing windows, holds and calibration offset.

The judge holds one chart, converts raw input timestamps with the player
calibration offset and grades taps and holds into perfect, great or miss
while tracking combo and accuracy.
"""

from __future__ import annotations

import copy
import math
import threading
from collections.abc import Mapping
from dataclasses import dataclass
from numbers import Real

__all__ = [
    "RhythmError",
    "NoteState",
    "RhythmChartJudge",
]


class RhythmError(ValueError):
    """Raised when a chart or input operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class NoteState:
    """Judgement state of one chart note."""

    note_id: str
    status: str
    judgement: str | None
    delta_ms: int | None


@dataclass
class _Note:
    note_id: object
    time_ms: Real
    lane: int
    kind: str
    duration_ms: Real | None
    end_ms: Real
    index: int = 0
    status: str = "pending"
    head_judgement: str | None = None
    head_delta_ms: Real | None = None
    tail_judgement: str | None = None
    tail_delta_ms: Real | None = None
    broken: bool = False


_GRADES = {"perfect", "great", "miss"}


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return (
        isinstance(value, Real)
        and not isinstance(value, bool)
        and math.isfinite(float(value))
    )


class RhythmChartJudge:
    """Grade chart notes against timestamped press and release input."""

    def __init__(self, *, perfect_ms: int = 40, great_ms: int = 80) -> None:
        if not _is_number(perfect_ms) or perfect_ms < 0:
            raise RhythmError("RHYTHM_CONFIG_INVALID", perfect_ms)
        if not _is_number(great_ms) or great_ms < perfect_ms:
            raise RhythmError("RHYTHM_CONFIG_INVALID", great_ms)
        self.perfect_ms = perfect_ms
        self.great_ms = great_ms
        self._lock = threading.RLock()
        self._notes: list[_Note] = []
        self._by_id: dict[object, _Note] = {}
        self._offset_ms: Real = 0
        self._combo = 0
        self._max_combo = 0
        self._paused = False
        self._stats = {
            "presses": 0,
            "ticks": 0,
            "ignored": 0,
            "calibrations": 0,
        }

    def _validate_chart(self, notes) -> list[_Note]:
        if isinstance(notes, (str, bytes, Mapping)) or notes is None:
            raise RhythmError("RHYTHM_CHART_INVALID", "chart must be a sequence")
        try:
            raw_notes = list(notes)
        except TypeError as exc:
            raise RhythmError("RHYTHM_CHART_INVALID", "chart must be a sequence") from exc
        if len(raw_notes) < 2:
            raise RhythmError("RHYTHM_CHART_INVALID", "chart needs at least two notes")

        parsed: list[_Note] = []
        seen_ids: set[object] = set()
        last_time: Real | None = None

        for index, raw in enumerate(raw_notes):
            if not isinstance(raw, Mapping):
                raise RhythmError("RHYTHM_CHART_INVALID", index)
            for key in ("note_id", "time_ms", "lane", "kind"):
                if key not in raw:
                    raise RhythmError("RHYTHM_CHART_INVALID", f"missing {key}")

            note_id = raw["note_id"]
            try:
                hash(note_id)
            except TypeError as exc:
                raise RhythmError("RHYTHM_CHART_INVALID", "unhashable note_id") from exc
            if note_id is None:
                raise RhythmError("RHYTHM_CHART_INVALID", "note_id is required")
            if note_id in seen_ids:
                raise RhythmError("RHYTHM_CHART_INVALID", f"duplicate note_id {note_id!r}")
            seen_ids.add(note_id)

            time_ms = raw["time_ms"]
            if not _is_number(time_ms):
                raise RhythmError("RHYTHM_CHART_INVALID", f"invalid time for {note_id!r}")
            if last_time is not None and time_ms < last_time:
                raise RhythmError("RHYTHM_CHART_INVALID", "notes are not sorted")
            last_time = time_ms

            lane = raw["lane"]
            if not _is_int(lane) or lane < 0:
                raise RhythmError("RHYTHM_CHART_INVALID", f"invalid lane for {note_id!r}")

            kind = raw["kind"]
            if kind not in ("tap", "hold"):
                raise RhythmError("RHYTHM_CHART_INVALID", f"invalid kind for {note_id!r}")

            duration_ms = None
            end_ms = time_ms
            if kind == "hold":
                duration_ms = raw.get("duration_ms")
                if not _is_number(duration_ms) or duration_ms <= 0:
                    raise RhythmError(
                        "RHYTHM_CHART_INVALID",
                        f"invalid hold duration for {note_id!r}",
                    )
                end_ms = time_ms + duration_ms

            parsed.append(
                _Note(
                    note_id=note_id,
                    time_ms=time_ms,
                    lane=lane,
                    kind=kind,
                    duration_ms=duration_ms,
                    end_ms=end_ms,
                    index=index,
                )
            )

        return parsed

    def _install_chart(self, notes: list[_Note]) -> None:
        self._notes = notes
        self._by_id = {note.note_id: note for note in notes}
        self._combo = 0
        self._max_combo = 0

    def load_chart(self, notes) -> dict:
        """Load the note list in chart order."""
        with self._lock:
            parsed = self._validate_chart(notes)
            self._install_chart(parsed)
            return {
                "notes": len(self._notes),
                "judged": 0,
                "combo": 0,
                "max_combo": 0,
                "offset_ms": self._offset_ms,
            }

    def calibrate(self, offset_ms: int) -> dict:
        """Apply the player timing offset used for every later input."""
        if not _is_number(offset_ms):
            raise RhythmError("RHYTHM_INPUT_INVALID", offset_ms)
        with self._lock:
            self._offset_ms = offset_ms
            self._stats["calibrations"] += 1
            return {"offset_ms": self._offset_ms}

    def _effective_time(self, time_ms: Real) -> Real:
        return time_ms - self._offset_ms

    def _grade(self, delta_ms: Real) -> str | None:
        distance = abs(delta_ms)
        if distance <= self.perfect_ms:
            return "perfect"
        if distance <= self.great_ms:
            return "great"
        return None

    def _increase_combo(self) -> None:
        self._combo += 1
        if self._combo > self._max_combo:
            self._max_combo = self._combo

    def press(self, time_ms: int, lane: int) -> dict:
        """Grade a press against the earliest matching pending note."""
        if not _is_number(time_ms) or not _is_int(lane) or lane < 0:
            raise RhythmError("RHYTHM_INPUT_INVALID", (time_ms, lane))
        with self._lock:
            if self._paused:
                raise RhythmError("RHYTHM_PAUSED", "judge is paused")
            self._stats["presses"] += 1
            effective = self._effective_time(time_ms)
            candidates: list[tuple[Real, Real, int, _Note, str]] = []
            for note in self._notes:
                if note.lane != lane or note.status != "pending":
                    continue
                delta = effective - note.time_ms
                grade = self._grade(delta)
                if grade is not None:
                    candidates.append((abs(delta), note.time_ms, note.index, note, grade))

            if not candidates:
                self._stats["ignored"] += 1
                return {
                    "judgement": "none",
                    "note_id": None,
                    "delta_ms": None,
                    "combo": self._combo,
                }

            _, target, _, note, grade = min(
                candidates,
                key=lambda item: (item[0], item[1], item[2]),
            )
            delta = effective - target
            note.head_judgement = grade
            note.head_delta_ms = delta
            note.status = "holding" if note.kind == "hold" else "judged"
            self._increase_combo()
            return {
                "judgement": grade,
                "note_id": note.note_id,
                "delta_ms": delta,
                "combo": self._combo,
                "status": note.status,
            }

    def release(self, time_ms: int, lane: int) -> dict:
        """Grade the tail of a hold currently being held in *lane*."""
        if not _is_number(time_ms) or not _is_int(lane) or lane < 0:
            raise RhythmError("RHYTHM_INPUT_INVALID", (time_ms, lane))
        with self._lock:
            if self._paused:
                raise RhythmError("RHYTHM_PAUSED", "judge is paused")
            effective = self._effective_time(time_ms)
            held = [
                note
                for note in self._notes
                if note.lane == lane and note.status == "holding"
            ]
            if not held:
                self._stats["ignored"] += 1
                return {
                    "judgement": "none",
                    "note_id": None,
                    "delta_ms": None,
                    "combo": self._combo,
                    "broken": False,
                }

            note = min(held, key=lambda item: (item.end_ms, item.index))
            delta = effective - note.end_ms
            grade = self._grade(delta)
            note.tail_delta_ms = delta
            note.status = "judged"
            if grade is None:
                note.tail_judgement = "miss"
                note.broken = True
                self._combo = 0
                broken = True
            else:
                note.tail_judgement = grade
                note.broken = False
                self._increase_combo()
                broken = False

            return {
                "judgement": note.tail_judgement,
                "note_id": note.note_id,
                "delta_ms": delta,
                "combo": self._combo,
                "broken": broken,
            }

    def tick(self, time_ms: int) -> tuple[str, ...]:
        """Miss every note whose window has passed at *time_ms*."""
        if not _is_number(time_ms):
            raise RhythmError("RHYTHM_INPUT_INVALID", time_ms)
        with self._lock:
            self._stats["ticks"] += 1
            if self._paused:
                return ()

            effective = self._effective_time(time_ms)
            overdue: list[tuple[Real, int, _Note]] = []
            for note in self._notes:
                if note.status == "pending":
                    target = note.time_ms
                elif note.status == "holding":
                    target = note.end_ms
                else:
                    continue
                if effective - target > self.great_ms:
                    overdue.append((target, note.index, note))

            overdue.sort(key=lambda item: (item[0], item[1]))
            missed: list[str] = []
            for _, _, note in overdue:
                if note.status == "pending":
                    note.head_judgement = "miss"
                    note.head_delta_ms = None
                elif note.status == "holding":
                    note.tail_judgement = "miss"
                    note.tail_delta_ms = None
                    note.broken = True
                else:
                    continue
                note.status = "judged"
                self._combo = 0
                missed.append(note.note_id)
            return tuple(missed)

    def pause(self) -> None:
        """Freeze judgement until :meth:`resume`."""
        with self._lock:
            self._paused = True

    def resume(self) -> None:
        """Leave the paused state."""
        with self._lock:
            self._paused = False

    def _aggregate_state(self, note: _Note) -> tuple[str | None, Real | None]:
        if note.kind == "hold" and note.status == "judged" and note.tail_judgement:
            return note.tail_judgement, note.tail_delta_ms
        return note.head_judgement, note.head_delta_ms

    def judge(self, note_id: str) -> NoteState:
        """Return the judgement state of one note."""
        with self._lock:
            note = self._by_id.get(note_id)
            if note is None:
                raise RhythmError("RHYTHM_NOTE_UNKNOWN", note_id)
            judgement, delta = self._aggregate_state(note)
            return NoteState(
                note_id=note.note_id,
                status=note.status,
                judgement=judgement,
                delta_ms=delta,
            )

    def combo(self) -> int:
        """Return the current combo."""
        with self._lock:
            return self._combo

    def max_combo(self) -> int:
        """Return the highest combo reached in this run."""
        with self._lock:
            return self._max_combo

    def _counts(self) -> tuple[int, int, int]:
        perfect = great = miss = 0
        for note in self._notes:
            judgements = [note.head_judgement]
            if note.kind == "hold" and note.tail_judgement is not None:
                judgements.append(note.tail_judgement)
            for judgement in judgements:
                if judgement == "perfect":
                    perfect += 1
                elif judgement == "great":
                    great += 1
                elif judgement == "miss":
                    miss += 1
        return perfect, great, miss

    def accuracy(self) -> float:
        """Return the weighted accuracy in percent."""
        with self._lock:
            perfect, great, miss = self._counts()
            judged = perfect + great + miss
            if judged == 0:
                return 0.0
            return round((100 * perfect + 60 * great) / judged, 2)

    def results(self) -> dict:
        """Return per-grade counts plus combo and note totals."""
        with self._lock:
            perfect, great, miss = self._counts()
            judged = perfect + great + miss
            pending = sum(1 for note in self._notes if note.status == "pending")
            holding = sum(1 for note in self._notes if note.status == "holding")
            accuracy = (
                round((100 * perfect + 60 * great) / judged, 2) if judged else 0.0
            )
            return {
                "notes": len(self._notes),
                "judged": judged,
                "perfect": perfect,
                "great": great,
                "miss": miss,
                "pending": pending,
                "holding": holding,
                "combo": self._combo,
                "max_combo": self._max_combo,
                "accuracy": accuracy,
            }

    def snapshot(self) -> dict:
        """Return a detached copy of chart, states, combo and counters."""
        with self._lock:
            chart = []
            states = {}
            for note in self._notes:
                entry = {
                    "note_id": note.note_id,
                    "time_ms": note.time_ms,
                    "lane": note.lane,
                    "kind": note.kind,
                }
                if note.kind == "hold":
                    entry["duration_ms"] = note.duration_ms
                chart.append(entry)

                judgement, delta = self._aggregate_state(note)
                states[note.note_id] = {
                    "note_id": note.note_id,
                    "status": note.status,
                    "judgement": judgement,
                    "delta_ms": delta,
                    "head_judgement": note.head_judgement,
                    "head_delta_ms": note.head_delta_ms,
                    "tail_judgement": note.tail_judgement,
                    "tail_delta_ms": note.tail_delta_ms,
                    "broken": note.broken,
                }

            payload = {
                "chart": chart,
                "states": states,
                "offset_ms": self._offset_ms,
                "paused": self._paused,
                "combo": self._combo,
                "max_combo": self._max_combo,
                "stats": dict(self._stats),
            }
            return copy.deepcopy(payload)

    def _state_value(
        self,
        entry: Mapping,
        key: str,
        *,
        default: object = None,
    ) -> object:
        if key in entry:
            return entry[key]
        return default

    def _parse_snapshot(self, state) -> tuple[
        list[_Note],
        dict[object, _Note],
        Real,
        bool,
        int,
        int,
        dict[str, int],
    ]:
        if not isinstance(state, Mapping):
            raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "snapshot must be a mapping")
        for key in ("chart", "states", "offset_ms", "combo", "max_combo", "stats"):
            if key not in state:
                raise RhythmError("RHYTHM_SNAPSHOT_INVALID", f"missing {key}")

        try:
            notes = self._validate_chart(state["chart"])
        except RhythmError as exc:
            raise RhythmError("RHYTHM_SNAPSHOT_INVALID", exc.detail) from exc
        except Exception as exc:  # noqa: BLE001 - normalized into a snapshot error
            raise RhythmError("RHYTHM_SNAPSHOT_INVALID", str(exc)) from exc

        raw_states = state["states"]
        if not isinstance(raw_states, Mapping):
            raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "states must be a mapping")
        expected_ids = {note.note_id for note in notes}
        try:
            actual_ids = set(raw_states)
        except TypeError as exc:
            raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "invalid state keys") from exc
        if actual_ids != expected_ids:
            raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "states do not match chart")

        for note in notes:
            entry = raw_states[note.note_id]
            if not isinstance(entry, Mapping):
                raise RhythmError("RHYTHM_SNAPSHOT_INVALID", note.note_id)
            if entry.get("note_id") != note.note_id:
                raise RhythmError("RHYTHM_SNAPSHOT_INVALID", note.note_id)
            status = entry.get("status")
            if status not in ("pending", "holding", "judged"):
                raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "invalid status")

            head = self._state_value(entry, "head_judgement")
            tail = self._state_value(entry, "tail_judgement")
            head_delta = self._state_value(entry, "head_delta_ms")
            tail_delta = self._state_value(entry, "tail_delta_ms")
            broken = self._state_value(entry, "broken", default=False)

            if head is not None and head not in _GRADES:
                raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "invalid head judgement")
            if tail is not None and tail not in _GRADES:
                raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "invalid tail judgement")
            if head_delta is not None and not _is_number(head_delta):
                raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "invalid head delta")
            if tail_delta is not None and not _is_number(tail_delta):
                raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "invalid tail delta")
            if not isinstance(broken, bool):
                raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "invalid broken flag")

            if status == "pending":
                if head is not None or tail is not None:
                    raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "pending has judgement")
            elif status == "holding":
                if note.kind != "hold" or head not in ("perfect", "great") or tail is not None:
                    raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "invalid holding state")
            else:
                if head is None:
                    raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "judged note has no head")
                if note.kind == "tap":
                    if tail is not None:
                        raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "tap has tail")
                elif head in ("perfect", "great") and tail is None:
                    raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "hold tail missing")

            note.status = status
            note.head_judgement = head
            note.head_delta_ms = head_delta
            note.tail_judgement = tail
            note.tail_delta_ms = tail_delta
            note.broken = broken

        offset_ms = state["offset_ms"]
        if not _is_number(offset_ms):
            raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "invalid offset")

        combo = state["combo"]
        max_combo = state["max_combo"]
        if not _is_int(combo) or combo < 0:
            raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "invalid combo")
        if not _is_int(max_combo) or max_combo < combo:
            raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "invalid max combo")

        paused = state.get("paused", False)
        if not isinstance(paused, bool):
            raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "invalid paused flag")

        raw_stats = state["stats"]
        if not isinstance(raw_stats, Mapping):
            raise RhythmError("RHYTHM_SNAPSHOT_INVALID", "stats must be a mapping")
        stats: dict[str, int] = {}
        for key in ("presses", "ticks", "ignored", "calibrations"):
            value = raw_stats.get(key, 0)
            if not _is_int(value) or value < 0:
                raise RhythmError("RHYTHM_SNAPSHOT_INVALID", f"invalid stat {key}")
            stats[key] = value

        by_id = {note.note_id: note for note in notes}
        return notes, by_id, offset_ms, paused, combo, max_combo, stats

    def restore(self, state: dict) -> None:
        """Load a snapshot after validating its structure."""
        with self._lock:
            (
                notes,
                by_id,
                offset_ms,
                paused,
                combo,
                max_combo,
                stats,
            ) = self._parse_snapshot(state)
            self._notes = notes
            self._by_id = by_id
            self._offset_ms = offset_ms
            self._paused = paused
            self._combo = combo
            self._max_combo = max_combo
            self._stats = stats

    def stats(self) -> dict:
        """Return cumulative counters for input and tick calls."""
        with self._lock:
            return dict(self._stats)
