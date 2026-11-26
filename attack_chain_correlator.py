"""Attack chain correlator: keyed aggregation, watermark, reorder window, stale close."""

from __future__ import annotations

import copy
import threading
from dataclasses import dataclass
from datetime import datetime, timedelta


class ChainError(ValueError):
    """Raised when a correlator operation is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


STAGES = (
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "exfiltration",
    "impact",
)
_STAGE_INDEX = {name: index for index, name in enumerate(STAGES)}

STATE_OPEN = "open"
STATE_CLOSED = "closed"

_SNAPSHOT_VERSION = 1
_SNAPSHOT_KEYS = frozenset(
    {"version", "chains", "events", "watermark", "stats"})
_STAT_KEYS = frozenset({"ingested", "opened", "isolated", "closed"})
_CHAIN_KEYS = frozenset({
    "chain_id", "src", "dst", "stage", "stages", "events", "state",
    "isolated", "opened_at", "last_event_at", "closed_at", "close_reason",
})


def _parse_ts(value: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ChainError("CHAIN_BAD_REQUEST",
                         "ts must be a non-empty ISO 8601 string")
    try:
        return datetime.fromisoformat(value)
    except ValueError as exc:
        raise ChainError("CHAIN_BAD_REQUEST",
                         f"invalid timestamp: {value!r}") from exc


def _is_non_empty_str(value: object) -> bool:
    return isinstance(value, str) and bool(value.strip())


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


@dataclass(frozen=True)
class Chain:
    chain_id: str
    src: str
    dst: str
    stage: str
    stages: tuple
    events: int
    state: str
    isolated: bool
    opened_at: str
    last_event_at: str
    closed_at: str | None
    close_reason: str | None


class AttackChainCorrelator:
    """Correlate stage-tagged events into chains keyed by source and target."""

    def __init__(self, *, reorder_window: int = 120,
                 silence_timeout: int = 600) -> None:
        self.reorder_window = reorder_window
        self.silence_timeout = silence_timeout
        self._lock = threading.RLock()
        self._chains: dict[str, dict] = {}
        self._events: dict[str, str] = {}
        self._open_by_key: dict[tuple[str, str], str] = {}
        self._watermark: str | None = None
        self._chain_seq = 0
        self._stats = {
            "ingested": 0,
            "opened": 0,
            "isolated": 0,
            "closed": 0,
        }

    def ingest(self, event_id: str, *, src: str, dst: str, stage: str,
               ts: str) -> dict:
        with self._lock:
            for name, value in (("event_id", event_id),
                                ("src", src), ("dst", dst)):
                if not _is_non_empty_str(value):
                    raise ChainError(
                        "CHAIN_BAD_REQUEST",
                        f"{name} must be a non-empty string")
            if not isinstance(stage, str) or stage not in _STAGE_INDEX:
                raise ChainError("CHAIN_BAD_STAGE",
                                 f"unknown stage: {stage!r}")
            event_time = _parse_ts(ts)
            if event_id in self._events:
                raise ChainError("CHAIN_DUPLICATE_EVENT", event_id)

            watermark_dt = (_parse_ts(self._watermark)
                            if self._watermark is not None else None)
            too_late = (
                watermark_dt is not None
                and event_time
                < watermark_dt - timedelta(seconds=self.reorder_window)
            )

            self._stats["ingested"] += 1

            if too_late:
                chain_id = self._open_chain(src, dst, stage, ts,
                                            isolated=True)
                self._events[event_id] = chain_id
                self._stats["isolated"] += 1
                return {
                    "event_id": event_id,
                    "chain_id": chain_id,
                    "stage": stage,
                    "attached": False,
                    "isolated": True,
                }

            chain_id = self._open_by_key.get((src, dst))
            if chain_id is None:
                chain_id = self._open_chain(src, dst, stage, ts,
                                            isolated=False)
                self._events[event_id] = chain_id
                return {
                    "event_id": event_id,
                    "chain_id": chain_id,
                    "stage": stage,
                    "attached": False,
                    "isolated": False,
                }

            record = self._chains[chain_id]
            record["events"] += 1
            if _STAGE_INDEX[stage] > _STAGE_INDEX[record["stage"]]:
                record["stage"] = stage
                record["stages"] = record["stages"] + (stage,)
            if event_time > _parse_ts(record["last_event_at"]):
                record["last_event_at"] = ts
            self._events[event_id] = chain_id
            return {
                "event_id": event_id,
                "chain_id": chain_id,
                "stage": record["stage"],
                "attached": True,
                "isolated": False,
            }

    def advance_watermark(self, *, ts: str) -> str:
        with self._lock:
            new_time = _parse_ts(ts)
            if self._watermark is not None:
                current_time = _parse_ts(self._watermark)
                if new_time < current_time:
                    raise ChainError("CHAIN_WATERMARK_REGRESSION", ts)
            self._watermark = ts
            return self._watermark

    def watermark(self) -> str | None:
        with self._lock:
            return self._watermark

    def close_stale(self, *, now: str) -> tuple:
        with self._lock:
            now_time = _parse_ts(now)
            closing = []
            for chain_id, record in self._chains.items():
                if record["state"] != STATE_OPEN:
                    continue
                deadline = (_parse_ts(record["last_event_at"])
                            + timedelta(seconds=self.silence_timeout))
                if deadline <= now_time:
                    closing.append(chain_id)
            closing.sort()
            for chain_id in closing:
                self._close(self._chains[chain_id], now, "silence_timeout")
            return tuple(closing)

    def close_chain(self, chain_id: str, *, reason: str, now: str) -> Chain:
        with self._lock:
            record = self._chains.get(chain_id)
            if record is None:
                raise ChainError("CHAIN_UNKNOWN_CHAIN", chain_id)
            if record["state"] == STATE_CLOSED:
                raise ChainError("CHAIN_ALREADY_CLOSED", chain_id)
            self._close(record, now, reason)
            return self._to_chain(record)

    def chain_of(self, chain_id: str) -> Chain:
        with self._lock:
            record = self._chains.get(chain_id)
            if record is None:
                raise ChainError("CHAIN_UNKNOWN_CHAIN", chain_id)
            return self._to_chain(record)

    def chains(self, *, state: str | None = None) -> list:
        with self._lock:
            rows = [
                self._to_chain(record)
                for record in self._chains.values()
                if state is None or record["state"] == state
            ]
            rows.sort(key=lambda chain: chain.chain_id)
            return rows

    def chain_for_event(self, event_id: str) -> str:
        with self._lock:
            chain_id = self._events.get(event_id)
            if chain_id is None:
                raise ChainError("CHAIN_UNKNOWN_EVENT", event_id)
            return chain_id

    def stages(self) -> tuple:
        return STAGES

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "version": _SNAPSHOT_VERSION,
                "chains": copy.deepcopy(self._chains),
                "events": copy.deepcopy(self._events),
                "watermark": self._watermark,
                "stats": copy.deepcopy(self._stats),
            }

    def restore(self, state: dict) -> None:
        with self._lock:
            chains, events, watermark, stats, max_seq = \
                self._validate_snapshot(state)
            self._chains = chains
            self._events = events
            self._watermark = watermark
            self._stats = stats
            self._open_by_key = {}
            for chain_id, record in chains.items():
                if (record["state"] == STATE_OPEN
                        and not record["isolated"]):
                    self._open_by_key[(record["src"], record["dst"])] = \
                        chain_id
            if max_seq > self._chain_seq:
                self._chain_seq = max_seq

    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)

    def _new_chain_id(self) -> str:
        self._chain_seq += 1
        return f"chain-{self._chain_seq:04d}"

    def _open_chain(self, src: str, dst: str, stage: str, ts: str,
                    *, isolated: bool) -> str:
        chain_id = self._new_chain_id()
        self._chains[chain_id] = {
            "chain_id": chain_id,
            "src": src,
            "dst": dst,
            "stage": stage,
            "stages": (stage,),
            "events": 1,
            "state": STATE_OPEN,
            "isolated": isolated,
            "opened_at": ts,
            "last_event_at": ts,
            "closed_at": None,
            "close_reason": None,
        }
        self._stats["opened"] += 1
        if not isolated:
            self._open_by_key[(src, dst)] = chain_id
        return chain_id

    def _close(self, record: dict, now: str, reason: str) -> None:
        record["state"] = STATE_CLOSED
        record["closed_at"] = now
        record["close_reason"] = reason
        key = (record["src"], record["dst"])
        if self._open_by_key.get(key) == record["chain_id"]:
            self._open_by_key.pop(key)
        self._stats["closed"] += 1

    @staticmethod
    def _to_chain(record: dict) -> Chain:
        return Chain(
            chain_id=record["chain_id"],
            src=record["src"],
            dst=record["dst"],
            stage=record["stage"],
            stages=record["stages"],
            events=record["events"],
            state=record["state"],
            isolated=record["isolated"],
            opened_at=record["opened_at"],
            last_event_at=record["last_event_at"],
            closed_at=record["closed_at"],
            close_reason=record["close_reason"],
        )

    @staticmethod
    def _validate_snapshot(state: object) -> tuple:
        invalid = ChainError("CHAIN_SNAPSHOT_INVALID", "malformed snapshot")

        def check_ts(value: object) -> None:
            if not _is_non_empty_str(value):
                raise invalid
            try:
                datetime.fromisoformat(value)
            except ValueError as exc:
                raise invalid from exc

        if not isinstance(state, dict) \
                or frozenset(state.keys()) != _SNAPSHOT_KEYS:
            raise invalid
        if state["version"] != _SNAPSHOT_VERSION:
            raise invalid
        raw_chains = state["chains"]
        raw_events = state["events"]
        raw_watermark = state["watermark"]
        raw_stats = state["stats"]
        if not isinstance(raw_chains, dict) \
                or not isinstance(raw_events, dict) \
                or not isinstance(raw_stats, dict):
            raise invalid
        if frozenset(raw_stats.keys()) != _STAT_KEYS:
            raise invalid
        if not all(_is_int(value) and value >= 0
                   for value in raw_stats.values()):
            raise invalid
        if raw_watermark is not None:
            check_ts(raw_watermark)

        chains: dict[str, dict] = {}
        max_seq = 0
        for chain_id, record in raw_chains.items():
            if not _is_non_empty_str(chain_id) \
                    or not isinstance(record, dict) \
                    or frozenset(record.keys()) != _CHAIN_KEYS:
                raise invalid
            if record["chain_id"] != chain_id \
                    or not _is_non_empty_str(record["src"]) \
                    or not _is_non_empty_str(record["dst"]):
                raise invalid
            if record["stage"] not in _STAGE_INDEX:
                raise invalid
            raw_stages = record["stages"]
            if not isinstance(raw_stages, (list, tuple)) or not raw_stages \
                    or not all(name in _STAGE_INDEX for name in raw_stages):
                raise invalid
            stages = tuple(raw_stages)
            indices = [_STAGE_INDEX[name] for name in stages]
            if any(prev >= curr for prev, curr in zip(indices, indices[1:])):
                raise invalid
            if record["stage"] != stages[-1]:
                raise invalid
            if not _is_int(record["events"]) or record["events"] < 1:
                raise invalid
            if record["state"] not in (STATE_OPEN, STATE_CLOSED) \
                    or not isinstance(record["isolated"], bool):
                raise invalid
            if not _is_non_empty_str(record["opened_at"]) \
                    or not _is_non_empty_str(record["last_event_at"]):
                raise invalid
            check_ts(record["opened_at"])
            check_ts(record["last_event_at"])
            closed_at = record["closed_at"]
            close_reason = record["close_reason"]
            if closed_at is not None:
                check_ts(closed_at)
            if close_reason is not None \
                    and not _is_non_empty_str(close_reason):
                raise invalid
            if record["state"] == STATE_CLOSED:
                if closed_at is None or close_reason is None:
                    raise invalid
            elif closed_at is not None or close_reason is not None:
                raise invalid
            normalized = dict(record)
            normalized["stages"] = stages
            chains[chain_id] = normalized
            if chain_id.startswith("chain-"):
                try:
                    max_seq = max(max_seq, int(chain_id[len("chain-"):]))
                except ValueError:
                    pass

        events: dict[str, str] = {}
        for event_id, mapped_chain in raw_events.items():
            if not _is_non_empty_str(event_id) \
                    or not _is_non_empty_str(mapped_chain) \
                    or mapped_chain not in chains:
                raise invalid
            events[event_id] = mapped_chain

        return copy.deepcopy(chains), events, raw_watermark, \
            dict(raw_stats), max_seq
