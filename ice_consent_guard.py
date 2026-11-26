"""ICE candidate-pair governance: nomination, role conflict and consent freshness."""

from __future__ import annotations

import copy
import threading
from dataclasses import asdict, dataclass, fields


class IceError(ValueError):
    """Raised when candidate, nomination or consent handling is refused."""

    def __init__(self, code: str, detail: object = None) -> None:
        super().__init__(code)
        self.code = code
        self.detail = detail


@dataclass(frozen=True)
class Candidate:
    key: str
    foundation: str
    component: str
    transport: str
    address: str
    port: int
    priority: int
    side: str


@dataclass(frozen=True)
class PairReport:
    pair_id: str
    state: str
    priority: int
    nominated: bool
    consent_until: int | None


@dataclass(frozen=True)
class NominationReport:
    pair_id: str
    state: str
    nominated: bool
    role: str


@dataclass(frozen=True)
class ConsentReport:
    pair_id: str
    state: str
    failures: int
    consent_until: int | None
    selected: str | None


@dataclass(frozen=True)
class Selection:
    pair_id: str
    state: str
    consent_until: int


@dataclass
class _PairState:
    pair_id: str
    seq: int
    local_foundation: str
    remote_foundation: str
    local_key: str
    remote_key: str
    local_priority: int
    remote_priority: int
    priority: int
    state: str = "waiting"
    nominated: bool = False
    failures: int = 0
    consent_until: int | None = None
    reselect_anchor: bool = False


_STAT_KEYS = (
    "candidates_added",
    "candidates_replaced",
    "pairs_created",
    "checks",
    "valid",
    "failed",
    "nominations",
    "consents",
    "reselects",
)
_ROLES = ("controlling", "controlled")
_PAIR_STATES = ("waiting", "in-progress", "valid", "failed", "invalid")
_CANDIDATE_FIELDS = {item.name for item in fields(Candidate)}
_PAIR_FIELDS = {item.name for item in fields(_PairState)}
_SNAPSHOT_FIELDS = {"version", "candidates", "pairs", "role", "selection", "counters"}
_REQUIRED_CANDIDATE_FIELDS = (
    "foundation",
    "component",
    "transport",
    "address",
    "port",
    "priority",
)


def _plain_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _parse_candidate(raw: object, side: str) -> Candidate:
    if not isinstance(raw, dict):
        raise IceError("ICE_INVALID_REQUEST", {"reason": "candidate_not_object"})

    missing = [name for name in _REQUIRED_CANDIDATE_FIELDS if name not in raw]
    if missing:
        raise IceError("ICE_INVALID_REQUEST", {"missing": missing})

    foundation = raw["foundation"]
    component = raw["component"]
    transport = raw["transport"]
    address = raw["address"]
    if not all(isinstance(value, str) and value for value in
               (foundation, component, transport, address)):
        raise IceError("ICE_INVALID_REQUEST", {"reason": "invalid_text_field"})

    port = raw["port"]
    if isinstance(port, bool) or not isinstance(port, int) or not 0 <= port <= 65535:
        raise IceError("ICE_INVALID_REQUEST", {"field": "port"})

    priority = raw["priority"]
    if not _plain_int(priority):
        raise IceError("ICE_INVALID_REQUEST", {"field": "priority"})

    key = f"{transport}://{address}:{port}"
    return Candidate(
        key=key,
        foundation=foundation,
        component=component,
        transport=transport,
        address=address,
        port=port,
        priority=priority,
        side=side,
    )


class IceConsentGuard:
    """Govern candidate pairs, nominations and consent timers for one session."""

    def __init__(self, *, max_candidates: int = 16, max_pairs: int = 32,
                 consent_ttl: int = 6, max_consent_failures: int = 2,
                 role: str = "controlling", clock=None) -> None:
        if role not in _ROLES:
            raise IceError("ICE_INVALID_ROLE", {"role": role})
        self.max_candidates = max_candidates
        self.max_pairs = max_pairs
        self.consent_ttl = consent_ttl
        self.max_consent_failures = max_consent_failures
        self._clock = clock
        self._lock = threading.RLock()
        self._reset_state(role)

    def _reset_state(self, role: str) -> None:
        self._role = role
        self._candidates = {"local": {}, "remote": {}}
        self._pairs = {}
        self._pair_seq = 0
        self._nominated_id: str | None = None
        self._selected_id: str | None = None
        self._reselect_pending = False
        self._last_now = 0
        self._stats = {key: 0 for key in _STAT_KEYS}

    def _current_now_locked(self, now: int | None) -> int:
        if now is not None:
            if not _plain_int(now):
                raise IceError("ICE_INVALID_REQUEST", {"field": "now"})
            return now
        if self._clock is not None:
            now = self._clock()
            if not _plain_int(now):
                raise IceError("ICE_INVALID_REQUEST", {"field": "now"})
            return now
        return self._last_now

    def _commit_now_locked(self, now: int) -> None:
        self._last_now = now

    def add_candidates(self, candidates, side: str | None = None,
                       now: int | None = None) -> tuple[Candidate, ...]:
        if side not in ("local", "remote"):
            raise IceError("ICE_INVALID_REQUEST", {"field": "side"})
        try:
            raw_candidates = list(candidates)
        except TypeError as exc:
            raise IceError("ICE_INVALID_REQUEST",
                           {"field": "candidates"}) from exc

        parsed = [_parse_candidate(raw, side) for raw in raw_candidates]

        with self._lock:
            current_now = self._current_now_locked(now)
            winners: dict[str, Candidate] = {}
            foundation_order: list[str] = []
            for candidate in parsed:
                if candidate.foundation not in winners:
                    foundation_order.append(candidate.foundation)
                    winners[candidate.foundation] = candidate
                    continue
                if candidate.priority > winners[candidate.foundation].priority:
                    winners[candidate.foundation] = candidate

            plan: list[tuple[Candidate, str, str | None]] = []
            added_count = 0
            for foundation in foundation_order:
                candidate = winners[foundation]
                old_candidate = self._candidates[side].get(foundation)
                if old_candidate is not None:
                    if candidate.priority <= old_candidate.priority:
                        continue
                    action = "replace"
                    old_key = old_candidate.key
                else:
                    action = "add"
                    added_count += 1
                    old_key = None

                plan.append((candidate, action, old_key))

            final_candidate_count = len(self._candidates[side]) + added_count
            if final_candidate_count > self.max_candidates:
                raise IceError("ICE_CANDIDATE_LIMIT",
                               {"side": side, "limit": self.max_candidates})

            opposite_side = "remote" if side == "local" else "local"
            opposite = list(self._candidates[opposite_side].values())
            existing_endpoints = {
                (pair.local_foundation, pair.local_key,
                 pair.remote_foundation, pair.remote_key)
                for pair in self._pairs.values()
            }
            new_pair_count = 0
            for candidate, _, old_key in plan:
                for other in opposite:
                    if side == "local":
                        endpoint = (candidate.foundation, candidate.key,
                                   other.foundation, other.key)
                    else:
                        endpoint = (other.foundation, other.key,
                                    candidate.foundation, candidate.key)
                    if endpoint not in existing_endpoints:
                        new_pair_count += 1
                        existing_endpoints.add(endpoint)

            if len(self._pairs) + new_pair_count > self.max_pairs:
                raise IceError("ICE_PAIR_LIMIT",
                               {"limit": self.max_pairs,
                                "requested": new_pair_count})

            reports: list[Candidate] = []
            for candidate, action, old_key in plan:
                if action == "add":
                    self._stats["candidates_added"] += 1
                else:
                    self._stats["candidates_replaced"] += 1
                    if old_key is not None and old_key != candidate.key:
                        self._cascade_candidate_key_locked(old_key)
                    elif old_key == candidate.key:
                        self._refresh_pair_priorities_locked(candidate)

                self._candidates[side][candidate.foundation] = candidate
                reports.append(candidate)

            if side == "local":
                for candidate, _, _ in plan:
                    for remote in list(self._candidates["remote"].values()):
                        self._create_pair_locked(candidate, remote)
            else:
                for local in list(self._candidates["local"].values()):
                    for candidate, _, _ in plan:
                        self._create_pair_locked(local, candidate)
            self._commit_now_locked(current_now)
            return tuple(reports)

    def resolve_role(self, local_role: str, local_tie_breaker: int,
                     remote_role: str, remote_tie_breaker: int) -> str:
        if local_role not in _ROLES or remote_role not in _ROLES:
            raise IceError("ICE_INVALID_ROLE",
                           {"local_role": local_role,
                            "remote_role": remote_role})
        if not _plain_int(local_tie_breaker) or not _plain_int(remote_tie_breaker):
            raise IceError("ICE_INVALID_REQUEST", {"field": "tie_breaker"})

        with self._lock:
            if local_role == "controlling" and remote_role == "controlling":
                if local_tie_breaker > remote_tie_breaker:
                    self._role = "controlling"
                else:
                    self._role = "controlled"
            else:
                self._role = local_role
            return self._role

    def check_pair(self, pair_id: str, responded: bool = True,
                   failed: bool = False,
                   now: int | None = None) -> PairReport:
        with self._lock:
            current_now = self._current_now_locked(now)
            pair = self._pairs.get(pair_id)
            if pair is None:
                raise IceError("ICE_UNKNOWN_PAIR", {"pair_id": pair_id})

            self._stats["checks"] += 1
            if not self._candidates_present_locked(pair):
                pair.state = "invalid"
                pair.consent_until = None
                pair.nominated = False
                if self._nominated_id == pair_id:
                    self._nominated_id = None
                self._clear_active_choice_locked(pair)
            elif failed:
                pair.state = "failed"
                pair.consent_until = None
                pair.failures = 0
                self._stats["failed"] += 1
                self._clear_active_choice_locked(pair)
            elif responded:
                pair.state = "valid"
                pair.failures = 0
                pair.consent_until = current_now + self.consent_ttl
                pair.reselect_anchor = False
                self._stats["valid"] += 1
            else:
                pair.state = "in-progress"

            self._commit_now_locked(current_now)
            return self._pair_report(pair)

    def nominate(self, pair_id: str, replace: bool = False,
                 now: int | None = None) -> NominationReport:
        with self._lock:
            current_now = self._current_now_locked(now)
            if self._role != "controlling":
                raise IceError("NOMINATION_FORBIDDEN", {"role": self._role})

            pair = self._pairs.get(pair_id)
            if pair is None:
                raise IceError("ICE_UNKNOWN_PAIR", {"pair_id": pair_id})
            if pair.state != "valid" or not self._candidates_present_locked(pair):
                raise IceError("ICE_PAIR_NOT_VALID", {"pair_id": pair_id})

            if (self._nominated_id is not None
                    and self._nominated_id != pair_id and not replace):
                raise IceError("NOMINATION_CONFLICT",
                               {"nominated": self._nominated_id,
                                "requested": pair_id})

            if self._nominated_id != pair_id:
                for existing in self._pairs.values():
                    if existing.pair_id == self._nominated_id:
                        existing.nominated = False
                self._nominated_id = pair_id

            pair.nominated = True
            self._stats["nominations"] += 1
            self._commit_now_locked(current_now)
            return NominationReport(pair.pair_id, pair.state, True, self._role)

    def consent(self, pair_id: str, ok: bool,
                now: int | None = None) -> ConsentReport:
        with self._lock:
            current_now = self._current_now_locked(now)
            pair = self._pairs.get(pair_id)
            if pair is None:
                raise IceError("ICE_UNKNOWN_PAIR", {"pair_id": pair_id})
            if pair.state != "valid" or not self._candidates_present_locked(pair):
                raise IceError("ICE_PAIR_NOT_VALID", {"pair_id": pair_id})

            self._stats["consents"] += 1
            if ok:
                pair.failures = 0
                pair.consent_until = current_now + self.consent_ttl
            else:
                pair.failures += 1
                if pair.failures >= self.max_consent_failures:
                    pair.state = "invalid"
                    pair.consent_until = None
                    self._clear_active_choice_locked(pair)

            selected = self._read_selected_locked(current_now)
            self._commit_now_locked(current_now)
            return ConsentReport(
                pair.pair_id,
                pair.state,
                pair.failures,
                pair.consent_until,
                selected,
            )

    def select(self, now: int | None = None) -> Selection:
        with self._lock:
            current_now = self._current_now_locked(now)
            current = self._pairs.get(self._selected_id or "")
            if self._pair_usable_locked(current, current_now):
                return Selection(current.pair_id, current.state,
                                 current.consent_until)

            if self._selected_id is not None:
                self._clear_active_choice_locked(current)

            best = self._best_pair_locked(current_now)
            if best is None:
                self._commit_now_locked(current_now)
                raise IceError("NO_VALID_PAIR", {"now": current_now})

            if self._reselect_pending:
                self._stats["reselects"] += 1
            self._selected_id = best.pair_id
            self._reselect_pending = False
            for pair in self._pairs.values():
                pair.reselect_anchor = False
            self._commit_now_locked(current_now)
            return Selection(best.pair_id, best.state, best.consent_until)

    def remove_candidate(self, key: str) -> int:
        with self._lock:
            current_now = self._current_now_locked(None)
            removed = 0
            for side in ("local", "remote"):
                foundations = [
                    foundation
                    for foundation, candidate in self._candidates[side].items()
                    if candidate.key == key
                ]
                for foundation in foundations:
                    self._candidates[side].pop(foundation, None)
                    removed += 1

            if removed:
                self._cascade_candidate_key_locked(key)
                self._commit_now_locked(current_now)
            return removed

    def pairs(self) -> tuple[PairReport, ...]:
        with self._lock:
            ordered = sorted(self._pairs.values(),
                             key=lambda pair: (-pair.priority, pair.seq))
            return tuple(self._pair_report(pair) for pair in ordered)

    def status(self) -> dict:
        with self._lock:
            current_now = self._current_now_locked(None)
            selected = self._read_selected_locked(current_now)
            self._commit_now_locked(current_now)
            return {
                "role": self._role,
                "selected": selected,
                "candidates": sum(len(items) for items in self._candidates.values()),
                "pairs": len(self._pairs),
                "valid": sum(pair.state == "valid" for pair in self._pairs.values()),
                "nominated": self._nominated_id,
            }

    def snapshot(self) -> dict:
        with self._lock:
            current_now = self._current_now_locked(None)
            self._read_selected_locked(current_now)
            self._commit_now_locked(current_now)
            state = {
                "version": 1,
                "candidates": [
                    asdict(candidate)
                    for side in ("local", "remote")
                    for candidate in self._candidates[side].values()
                ],
                "pairs": [
                    asdict(pair)
                    for pair in self._pairs.values()
                ],
                "role": self._role,
                "selection": self._selected_id,
                "counters": copy.deepcopy(self._stats),
            }
            return copy.deepcopy(state)

    def restore(self, state: dict) -> None:
        candidates, pairs, role, selection, counters, nominated_id, \
            reselect_pending = self._validate_snapshot(state)
        with self._lock:
            self._role = role
            self._candidates = candidates
            self._pairs = pairs
            max_seq = max((pair.seq for pair in pairs.values()), default=0)
            id_seq = 0
            for pair_id in pairs:
                if pair_id.startswith("p-"):
                    try:
                        id_seq = max(id_seq, int(pair_id[2:]))
                    except ValueError:
                        pass
            self._pair_seq = max(max_seq, id_seq)
            self._nominated_id = nominated_id
            self._selected_id = selection
            self._reselect_pending = reselect_pending
            self._last_now = 0
            self._stats = dict(counters)

    def stats(self) -> dict:
        with self._lock:
            return {key: self._stats[key] for key in _STAT_KEYS}

    def _create_pair_locked(self, local: Candidate, remote: Candidate) -> _PairState:
        pair_endpoint = (local.foundation, local.key,
                         remote.foundation, remote.key)
        for pair in self._pairs.values():
            existing_endpoint = (
                pair.local_foundation,
                pair.local_key,
                pair.remote_foundation,
                pair.remote_key,
            )
            if existing_endpoint == pair_endpoint:
                return pair

        self._pair_seq += 1
        priority = local.priority * 1000 + remote.priority
        pair_id = f"p-{self._pair_seq}"
        pair = _PairState(
            pair_id=pair_id,
            seq=self._pair_seq,
            local_foundation=local.foundation,
            remote_foundation=remote.foundation,
            local_key=local.key,
            remote_key=remote.key,
            local_priority=local.priority,
            remote_priority=remote.priority,
            priority=priority,
        )
        self._pairs[pair_id] = pair
        self._stats["pairs_created"] += 1
        return pair

    def _refresh_pair_priorities_locked(self, candidate: Candidate) -> None:
        for pair in self._pairs.values():
            if (candidate.side == "local"
                    and pair.local_foundation == candidate.foundation
                    and pair.local_key == candidate.key):
                pair.local_priority = candidate.priority
            elif (candidate.side == "remote"
                    and pair.remote_foundation == candidate.foundation
                    and pair.remote_key == candidate.key):
                pair.remote_priority = candidate.priority
            else:
                continue
            pair.priority = pair.local_priority * 1000 + pair.remote_priority

    def _cascade_candidate_key_locked(self, key: str) -> None:
        for pair in self._pairs.values():
            if pair.local_key != key and pair.remote_key != key:
                continue
            pair.state = "invalid"
            pair.consent_until = None
            pair.nominated = False
            if self._nominated_id == pair.pair_id:
                self._nominated_id = None
            self._clear_active_choice_locked(pair)

    def _clear_active_choice_locked(self, pair: _PairState | None) -> None:
        if self._selected_id is None:
            return
        if pair is not None and pair.pair_id != self._selected_id:
            return
        anchor = pair if pair is not None else self._pairs.get(self._selected_id)
        self._selected_id = None
        self._reselect_pending = True
        if anchor is not None:
            anchor.reselect_anchor = True

    def _candidates_present_locked(self, pair: _PairState) -> bool:
        local = self._candidates["local"].get(pair.local_foundation)
        remote = self._candidates["remote"].get(pair.remote_foundation)
        return (
            local is not None
            and local.key == pair.local_key
            and remote is not None
            and remote.key == pair.remote_key
        )

    def _pair_usable_locked(self, pair: _PairState | None, now: int) -> bool:
        return (
            pair is not None
            and pair.state == "valid"
            and pair.consent_until is not None
            and pair.consent_until > now
            and self._candidates_present_locked(pair)
        )

    def _read_selected_locked(self, now: int) -> str | None:
        pair = self._pairs.get(self._selected_id or "")
        if self._pair_usable_locked(pair, now):
            return self._selected_id
        if self._selected_id is not None:
            self._clear_active_choice_locked(pair)
        return None

    def _best_pair_locked(self, now: int) -> _PairState | None:
        usable = [pair for pair in self._pairs.values()
                  if self._pair_usable_locked(pair, now)]
        if not usable:
            return None
        return sorted(usable, key=lambda pair: (-pair.priority, pair.seq))[0]

    def _pair_report(self, pair: _PairState) -> PairReport:
        return PairReport(
            pair.pair_id,
            pair.state,
            pair.priority,
            pair.nominated,
            pair.consent_until,
        )

    def _validate_snapshot(self, state: object):
        def invalid(detail: object = None) -> IceError:
            return IceError("ICE_SNAPSHOT_INVALID", detail)

        if not isinstance(state, dict) or set(state) != _SNAPSHOT_FIELDS:
            raise invalid({"reason": "top_level"})
        if not _plain_int(state["version"]) or state["version"] != 1:
            raise invalid({"field": "version"})
        if state["role"] not in _ROLES:
            raise invalid({"field": "role"})
        if not isinstance(state["candidates"], list):
            raise invalid({"field": "candidates"})
        if not isinstance(state["pairs"], list):
            raise invalid({"field": "pairs"})
        if state["selection"] is not None and not isinstance(state["selection"], str):
            raise invalid({"field": "selection"})
        if not isinstance(state["counters"], dict) \
                or set(state["counters"]) != set(_STAT_KEYS):
            raise invalid({"field": "counters"})
        for key in _STAT_KEYS:
            if not _plain_int(state["counters"][key]) or state["counters"][key] < 0:
                raise invalid({"field": f"counters.{key}"})

        candidates = {"local": {}, "remote": {}}
        for raw_candidate in state["candidates"]:
            if not isinstance(raw_candidate, dict) \
                    or set(raw_candidate) != _CANDIDATE_FIELDS:
                raise invalid({"field": "candidate"})
            side = raw_candidate.get("side")
            if side not in ("local", "remote"):
                raise invalid({"field": "candidate.side"})
            try:
                candidate = _parse_candidate(raw_candidate, side)
            except IceError as exc:
                raise invalid({"field": "candidate.structure"}) from exc
            if raw_candidate.get("key") != candidate.key:
                raise invalid({"field": "candidate.key"})
            if candidate.foundation in candidates[side]:
                raise invalid({"field": "candidate.foundation_duplicate"})
            candidates[side][candidate.foundation] = candidate

        pairs = {}
        endpoints = set()
        nominated_id = None
        reselect_pending = False
        for raw_pair in state["pairs"]:
            if not isinstance(raw_pair, dict) \
                    or set(raw_pair) != _PAIR_FIELDS:
                raise invalid({"field": "pair"})
            pair_id = raw_pair["pair_id"]
            seq = raw_pair["seq"]
            local_foundation = raw_pair["local_foundation"]
            remote_foundation = raw_pair["remote_foundation"]
            local_key = raw_pair["local_key"]
            remote_key = raw_pair["remote_key"]
            if not isinstance(pair_id, str) or pair_id in pairs:
                raise invalid({"field": "pair.pair_id"})
            if not _plain_int(seq) or seq <= 0:
                raise invalid({"field": "pair.seq"})
            if not isinstance(local_foundation, str) \
                    or not isinstance(remote_foundation, str):
                raise invalid({"field": "pair.foundation"})
            if not isinstance(local_key, str) or not isinstance(remote_key, str):
                raise invalid({"field": "pair.endpoints"})
            endpoint = (local_foundation, local_key,
                        remote_foundation, remote_key)
            if endpoint in endpoints:
                raise invalid({"field": "pair.endpoint_duplicate"})
            if not all(_plain_int(raw_pair[name]) for name in
                       ("local_priority", "remote_priority", "priority", "failures")):
                raise invalid({"field": "pair.priority"})
            if raw_pair["priority"] != (raw_pair["local_priority"]
                                        * 1000 + raw_pair["remote_priority"]):
                raise invalid({"field": "pair.priority_value"})
            consent_until = raw_pair["consent_until"]
            if consent_until is not None and not _plain_int(consent_until):
                raise invalid({"field": "pair.consent_until"})
            if raw_pair["state"] not in _PAIR_STATES:
                raise invalid({"field": "pair.state"})
            if raw_pair["state"] == "valid":
                local_candidate = candidates["local"].get(local_foundation)
                remote_candidate = candidates["remote"].get(remote_foundation)
                if (local_candidate is None
                        or local_candidate.key != local_key
                        or remote_candidate is None
                        or remote_candidate.key != remote_key
                        or consent_until is None):
                    raise invalid({"field": "pair.valid_endpoints"})
            if not isinstance(raw_pair["nominated"], bool):
                raise invalid({"field": "pair.nominated"})
            if not isinstance(raw_pair["reselect_anchor"], bool):
                raise invalid({"field": "pair.reselect_anchor"})
            if raw_pair["failures"] < 0:
                raise invalid({"field": "pair.failures"})

            pair = _PairState(**raw_pair)
            pairs[pair_id] = pair
            endpoints.add(endpoint)
            if pair.nominated:
                if nominated_id is not None:
                    raise invalid({"field": "pair.nominated_conflict"})
                nominated_id = pair_id
            if pair.reselect_anchor:
                reselect_pending = True

        selection = state["selection"]
        if selection is not None:
            selected_pair = pairs.get(selection)
            if selected_pair is None:
                raise invalid({"field": "selection"})
            selected_local = candidates["local"].get(
                selected_pair.local_foundation)
            selected_remote = candidates["remote"].get(
                selected_pair.remote_foundation)
            if selected_pair.state != "valid" \
                    or selected_pair.consent_until is None \
                    or selected_local is None \
                    or selected_local.key != selected_pair.local_key \
                    or selected_remote is None \
                    or selected_remote.key != selected_pair.remote_key:
                raise invalid({"field": "selection_not_active"})

        counters = copy.deepcopy(state["counters"])
        return (
            candidates,
            pairs,
            state["role"],
            selection,
            counters,
            nominated_id,
            reselect_pending,
        )
